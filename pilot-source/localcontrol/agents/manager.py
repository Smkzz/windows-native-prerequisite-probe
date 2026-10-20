"""DelegationManager: owns agent lifecycle, provider sessions and the
delegation intent queue. All public entry points are synchronous and
thread-safe; the facade calls them via asyncio.to_thread.

The manager is the ONLY writer for agent rows/events. The in-child shim may
only enqueue intents on its own sqlite connection; the manager drains and
re-validates them under full policy.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from ..errors import ControlError, require
from ..nextlib.core import Rejected, digest, ident, need, safe_relative
from . import state as st
from .codex_adapter import (DENY_APPROVAL, DENY_ELICITATION, DENY_LEGACY, DENY_TOOL_CALL,
                            DeniedByPolicy, ProviderError, Session,
                            PROTOCOL_NOTE, SUPPORTED_CODEX, discover_executable)
from .codex_home import build_home, child_env, read_provider_table
from .profiles import Profile, load_profiles
from .store import AgentStore, MAX_TASK_BYTES

AGENT_ID_RE = re.compile(r'^agt-[0-9a-f]{16}$')
CLIENT_NAME = 'localcontrol-delegation'

LIMIT_KEYS = frozenset({'max_concurrent', 'max_records', 'max_children', 'max_depth',
                        'spawn_per_minute', 'startup_timeout_s', 'max_events_per_agent',
                        'max_result_bytes', 'workspace_scan_files', 'workspace_scan_bytes',
                        'reattach_budget_s'})
DEFAULT_LIMITS = {'max_concurrent': 4, 'max_records': 512, 'max_children': 4, 'max_depth': 2,
                  'spawn_per_minute': 12, 'startup_timeout_s': 60, 'max_events_per_agent': 4096,
                  'max_result_bytes': 262144, 'workspace_scan_files': 4096,
                  'workspace_scan_bytes': 8 * 1024 * 1024, 'reattach_budget_s': 120}
PROVIDER_KEYS = frozenset({'enabled', 'executable', 'executable_sha256', 'min_version',
                           'model_provider', 'model', 'model_catalog', 'auth_codex_home',
                           'windows_sandbox', 'models_allow', 'efforts_allow'})
MAX_INPUT_BYTES = 32768
AWAITABLE = st.TERMINAL | {st.IDLE}

def _clip(value, max_bytes: int):
    """Truncate a string to a UTF-8 byte bound for durable-column safety."""
    if not isinstance(value, str):
        return value
    data = value.encode('utf-8')
    if len(data) <= max_bytes:
        return value
    return data[:max_bytes].decode('utf-8', 'replace')


DEVELOPER_PREAMBLE = (
    'You are a delegated sub-agent managed by LocalControl. Operate only inside your '
    'assigned working directory. Do not read, write, or execute anything outside it. '
    'Do not create network connections. When a delegation tool server named '
    '"localcontrol" is available, use ONLY its lc_agent_* tools to create or control '
    'other agents; never spawn agents by other means. If you need permissions beyond '
    'your sandbox, finish the turn and report what is blocked instead of escalating.')


class _Live:
    """In-memory provider-session bookkeeping for one agent generation."""
    __slots__ = ('generation', 'session', 'thread_id', 'turn_id', 'cancel_requested',
                 'last_event_ns', 'token_usage', 'final_texts', 'files_changed',
                 'setup_done', 'turn_started_ns', 'starting')

    def __init__(self, generation: int):
        self.generation = generation
        self.session = None
        self.thread_id = None
        self.turn_id = None
        self.cancel_requested = False
        self.last_event_ns = time.time_ns()
        self.token_usage = None
        self.final_texts = []
        self.files_changed = set()
        self.setup_done = threading.Event()
        self.turn_started_ns = 0
        self.starting = True


class DelegationManager:
    def __init__(self, policy, principal: str, options: dict, *, next_api=None):
        self.policy, self.principal = policy, principal
        self.next = next_api
        need(isinstance(options, dict) and options.get('enabled') is True, 'V110_CONFIG')
        need(set(options) <= {'enabled', 'providers', 'profiles', 'limits', 'default_profile',
                              'auto_reattach'}, 'V110_CONFIG')
        self.limits = dict(DEFAULT_LIMITS)
        for key, value in (options.get('limits') or {}).items():
            need(key in LIMIT_KEYS and type(value) is int and value >= 1, 'V110_CONFIG')
            self.limits[key] = value
        auto_reattach = options.get('auto_reattach', True)
        need(type(auto_reattach) is bool, 'V110_CONFIG')
        self._auto_reattach_enabled = auto_reattach
        self.profiles = load_profiles(options.get('profiles'))
        self.default_profile = options.get('default_profile', 'read_only')
        need(self.default_profile in self.profiles, 'V110_CONFIG')
        providers = options.get('providers') or {}
        need(set(providers) <= {'codex'}, 'V110_CONFIG')
        self.codex_cfg = self._codex_config(providers.get('codex') or {})
        self.store = AgentStore(policy.state_dir, 'runtime-' + uuid.uuid4().hex[:16])
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.live: dict[str, _Live] = {}
        self._live_generation = 0
        self._spawn_times = deque(maxlen=256)
        self._closed = False
        self._exe_info = None
        self._models_cache = None
        self._models_ns = 0
        self.recovered = self.store.recover()
        self._watchdog = threading.Thread(target=self._supervise, daemon=True,
                                          name='lc-delegation-watchdog')
        self._intents = threading.Thread(target=self._intent_loop, daemon=True,
                                         name='lc-delegation-intents')
        self._watchdog.start()
        self._intents.start()
        if self._auto_reattach_enabled:
            threading.Thread(target=self._auto_reattach, daemon=True,
                             name='lc-delegation-reattach').start()

    # ---------- config ----------

    def _codex_config(self, cfg: dict) -> dict:
        need(isinstance(cfg, dict) and set(cfg) <= PROVIDER_KEYS, 'V110_CONFIG')
        need(cfg.get('enabled') is True, 'V110_CONFIG')
        auth_home = cfg.get('auth_codex_home') or str(Path.home() / '.codex')
        provider = cfg.get('model_provider', 'openai')
        for name, value in (('models_allow', cfg.get('models_allow')),
                            ('efforts_allow', cfg.get('efforts_allow'))):
            need(value is None or (isinstance(value, list) and 1 <= len(value) <= 64
                                   and all(isinstance(m, str) and 0 < len(m) <= 128
                                           for m in value)), 'V110_CONFIG')
        pin = cfg.get('executable_sha256')
        need(pin is None or (isinstance(pin, str)
                             and re.fullmatch(r'[0-9a-fA-F]{64}', pin)), 'V110_CONFIG')
        min_ver = cfg.get('min_version')
        if min_ver is not None:
            need(isinstance(min_ver, str) and
                 re.fullmatch(r'\d+\.\d+\.\d+', min_ver), 'V110_CONFIG')
            min_ver = tuple(int(x) for x in min_ver.split('.'))
        return {'executable': cfg.get('executable'), 'min_version': min_ver,
                'executable_sha256': pin.lower() if pin else None,
                'model_provider': provider, 'model': cfg.get('model'),
                'model_catalog': cfg.get('model_catalog'), 'auth_home': auth_home,
                'windows_sandbox': cfg.get('windows_sandbox', 'elevated'),
                'models_allow': cfg.get('models_allow'),
                'efforts_allow': cfg.get('efforts_allow')}

    def exe_info(self) -> dict:
        if self._exe_info is None:
            info = discover_executable(self.codex_cfg['executable'])
            floor = max(SUPPORTED_CODEX, self.codex_cfg['min_version'] or (0, 0, 0))
            require(info['version_tuple'] >= floor, 'PROVIDER_UNSUPPORTED',
                    f'codex {info["version"]} is below the supported floor '
                    f'{".".join(str(x) for x in floor)}')
            pin = self.codex_cfg.get('executable_sha256')
            if pin is not None:
                require(info.get('sha256') == pin, 'PROVIDER_UNSUPPORTED',
                        'codex executable sha256 does not match the configured pin')
            self._exe_info = info
        return self._exe_info

    # ---------- public API (all called via to_thread) ----------

    def spawn(self, scope: str, project: str, args: dict) -> dict:
        """Admit and synchronously start an agent. Returns once the provider
        turn is running or startup failed (the durable row always exists)."""
        self._open()
        task = args['task']
        need(isinstance(task, str) and 0 < len(task.encode('utf-8')) <= MAX_TASK_BYTES,
             'INVALID_TASK')
        parent = args.get('_parent')            # internal: set only for shim intents
        profile = args.get('_profile')          # internal: resolved Profile for children
        if profile is None:
            name = args.get('profile') or self.default_profile
            need(name in self.profiles, 'INVALID_PROFILE')
            profile = self.profiles[name]
        need(self.codex_cfg['models_allow'] is None or not args.get('model')
             or args['model'] in self.codex_cfg['models_allow'], 'MODEL_DENIED')
        need(self.codex_cfg['efforts_allow'] is None or not args.get('effort')
             or args['effort'] in self.codex_cfg['efforts_allow'], 'EFFORT_DENIED')
        schema = args.get('output_schema')
        need(schema is None or (isinstance(schema, dict) and
                                len(json.dumps(schema)) <= 16384), 'INVALID_OUTPUT_SCHEMA')
        dedupe_key = args.get('dedupe_key')
        need(dedupe_key is None or (isinstance(dedupe_key, str)
                                    and 1 <= len(dedupe_key) <= 128), 'INVALID_DEDUPE_KEY')
        for name in ('model', 'effort'):
            value = args.get(name)
            need(value is None or (isinstance(value, str) and 0 < len(value) <= 128),
                 'INVALID_ARGUMENT')
        depth = (parent['depth'] + 1) if parent else 0
        lineage = (parent['lineage'] + [parent['agent_id']]) if parent else []
        agent_id = 'agt-' + uuid.uuid4().hex[:16]

        with self.lock:
            if parent is not None:
                # Re-read the parent inside the admission lock: state/limits
                # may have changed since the intent was enqueued.
                fresh = self.store.get(parent['agent_id'])
                need(fresh['state'] in st.LIVE, 'DELEGATION_REVOKED')
                plimits = fresh['limits'] or {}
                need(plimits.get('can_delegate'), 'DELEGATION_DENIED')
                need(depth <= min(plimits.get('max_depth', 0),
                                  self.limits['max_depth']), 'DEPTH_LIMIT')
                children = self.store.list(parent=parent['agent_id'], limit=256)
                need(len(children) < min(plimits.get('max_children', 0),
                                         self.limits['max_children']), 'CHILD_LIMIT')
            self._admit(parent, profile)
            # Create the managed worktree only after every admission check has
            # passed: on denial there is nothing to undo. `git worktree add`
            # runs under the admission lock — spawns are already serialized
            # here and this is not a hot path.
            runtime_bound = self._runtime_bound(profile, args)
            workspace = self._resolve_workspace(project, args, agent_id, parent)
            token = secrets.token_hex(32) if profile.can_delegate else None
            record = {'agent_id': agent_id, 'scope': scope, 'project': project, 'task': task,
                      'task_sha256': digest(task), 'profile': profile.name, 'provider': 'codex',
                      'model': args.get('model') or self.codex_cfg['model'],
                      'effort': args.get('effort'), 'workspace_mode': workspace['mode'],
                      'workspace_root': workspace['root'],
                      'workspace_managed': workspace['managed'],
                      'worktree_ref': workspace.get('ref'), 'depth': depth,
                      'parent_agent_id': parent['agent_id'] if parent else None,
                      'lineage': lineage, 'dedupe_key': dedupe_key,
                      'request_id': args.get('request_id'), 'output_schema': schema,
                      # Raw SHA-256 of the token bytes — the shim hashes the env
                      # value identically; do NOT use digest() (it JSON-quotes).
                      'delegation_token_sha256': hashlib.sha256(token.encode()).hexdigest()
                      if token else None,
                      'limits': {'max_runtime_s': runtime_bound,
                                 'stall_timeout_s': profile.stall_timeout_s,
                                 'idle_retain_s': profile.idle_retain_s,
                                 'max_turns': profile.max_turns,
                                 'max_children': profile.max_children,
                                 'max_depth': profile.max_depth,
                                 'can_delegate': profile.can_delegate,
                                 'delegate_profile': profile.delegate_profile,
                                 'writable_roots_mode': profile.writable_roots_mode},
                      'provider_state': {'sandbox': profile.codex_sandbox,
                                         'network': profile.network,
                                         'requires_os_sandbox': profile.requires_os_sandbox,
                                         'writable_roots_mode': profile.writable_roots_mode},
                      'policy_binding': self._policy_binding(project)}
            try:
                self.store.create(record)
                # Claim the slot inside the admission lock: the row is counted
                # as live immediately, so concurrent spawns cannot over-admit.
                self.store.transition(agent_id, {st.QUEUED}, st.STARTING,
                                      'spawn.starting', {'provider': 'codex'})
            except Rejected as error:
                self._undo_workspace(workspace)
                if error.code == 'DEDUPE_CONFLICT':
                    existing = error.existing
                    return {'agent_id': existing['agent_id'], 'state': existing['state'],
                            'deduped': True, 'project': existing['project'],
                            'note': 'existing agent returned for dedupe_key'}
                raise
        try:
            self._spawn_pipeline(agent_id, token)
        except BaseException as error:
            # A managed worktree created for this spawn must not leak: the
            # pipeline owns it only after session startup succeeds.
            self._undo_workspace(workspace)
            code = getattr(error, 'code', 'PROVIDER_ERROR')
            raise ControlError(code, 'Agent spawn failed',
                               {'agent_id': agent_id, 'detail': str(getattr(error, 'message', error))[:256]})
        stored = self.wait(scope, project, agent_id, args.get('wait_ms', 0)) \
            if args.get('wait_ms') else self._summary(self.store.get(agent_id))
        return dict(stored) | {'spawned': True}

    def send(self, scope: str, project: str, args: dict) -> dict:
        self._open()
        agent = self._own(scope, args['agent_id'], write=True)
        text = args['input']
        need(isinstance(text, str) and 0 < len(text.encode('utf-8')) <= MAX_INPUT_BYTES,
             'INVALID_INPUT')
        if agent['state'] in {st.INTERRUPTED, st.FAILED}:
            raise Rejected('RESUME_REQUIRED', {'state': agent['state']})
        if agent['state'] not in {st.RUNNING, st.WAITING_INTERNAL, st.IDLE, st.COMPLETED}:
            raise Rejected('STATE_MISMATCH', {'state': agent['state']})
        live = self.live.get(agent['agent_id'])
        if agent['state'] in {st.RUNNING, st.WAITING_INTERNAL} and (
                live is None or live.session is None or not live.session.alive()):
            # durable state says a turn is active but we own no live session:
            # the provider process was lost; require an explicit resume
            self.store.transition(agent['agent_id'], {agent['state']}, st.INTERRUPTED,
                                  'send.stale_session', {}, active_process=0,
                                  active_turn_id=None)
            self._wake()
            raise Rejected('RESUME_REQUIRED')
        turn_id = None
        if agent['state'] in {st.RUNNING, st.WAITING_INTERNAL} and live.turn_id:
            try:
                live.session.request('turn/steer', {
                    'threadId': live.thread_id, 'expectedTurnId': live.turn_id,
                    'input': [{'type': 'text', 'text': text}]}, timeout=30)
                turn_id = live.turn_id
                self.store.update_fields(agent['agent_id'], 'send.steered',
                                         {'input_sha256': digest(text)})
            except ProviderError:
                pass  # turn ended between check and steer; fall through to a new turn
        if turn_id is None:
            need(agent['turns_completed'] + 1 <= agent['limits'].get('max_turns', 8),
                 'TURN_LIMIT')
            if agent['state'] in {st.IDLE, st.COMPLETED}:
                if agent['state'] == st.COMPLETED:
                    with self.lock:
                        self._admit(None, None)  # reviving claims a slot
                agent = self._set_state(agent, st.STARTING, 'send.reviving', {})
            try:
                session = self._ensure_session(agent)
                live = self.live[agent['agent_id']]
                turn = self._turn_start(session, live, agent, text,
                                        args.get('output_schema'))
                live.turn_id = turn['turn']['id']
                live.turn_started_ns = time.time_ns()
            except BaseException:
                removed = self._pop_live(agent['agent_id'], live)
                if removed is not None and removed.session is not None:
                    removed.session.kill()
                if agent['state'] == st.STARTING:
                    try:
                        self.store.transition(agent['agent_id'], {st.STARTING}, st.FAILED,
                                              'send.failed', {})
                    except Rejected:
                        pass
                self._wake()
                raise
            self._set_state(agent, st.RUNNING, 'turn.started',
                            {'turn_id': live.turn_id}, active_turn_id=live.turn_id)
        if args.get('wait_ms'):
            return {'sent': True, 'turn_id': turn_id,
                    'agent': self.wait(scope, project, agent['agent_id'], args['wait_ms'])}
        return {'sent': True, 'turn_id': turn_id}

    def cancel(self, scope: str, project: str, args: dict) -> dict:
        self._open()
        agent = self._own(scope, args['agent_id'])
        reason = args.get('reason')
        need(reason is None or (isinstance(reason, str) and len(reason) <= 512),
             'INVALID_ARGUMENT')
        if agent['state'] == st.CANCELLED:
            return {'agent_id': agent['agent_id'], 'state': st.CANCELLED, 'already': True}
        need(not agent['archived'], 'AGENT_ARCHIVED')
        if agent['state'] not in st.LIVE | {st.INTERRUPTED, st.FAILED, st.COMPLETED}:
            raise Rejected('STATE_MISMATCH', {'state': agent['state']})
        live = self._pop_live(agent['agent_id'])
        if live is not None:
            live.cancel_requested = True
            if live.session is not None and live.turn_id and live.session.alive():
                try:
                    live.session.request('turn/interrupt', {'threadId': live.thread_id,
                                                            'turnId': live.turn_id}, timeout=10)
                except Exception:
                    pass
            if live.session is not None:
                live.session.kill()
        # session.kill() fires on_exit, which may have already moved the row to
        # interrupted — accept either pre-cancel state here.
        stored = self.store.transition(
            agent['agent_id'], {agent['state'], st.INTERRUPTED}, st.CANCELLED, 'cancelled',
            {'reason': reason}, active_process=0, active_turn_id=None,
            delegation_token_sha256=None, delegation_pid=None)
        self._wake()
        return self._summary(stored)

    def resume(self, scope: str, project: str, args: dict) -> dict:
        self._open()
        agent = self._own(scope, args['agent_id'], write=True)
        if agent['state'] not in {st.INTERRUPTED, st.FAILED}:
            raise Rejected('STATE_MISMATCH', {'state': agent['state']})
        text = args.get('input')
        need(text is None or (isinstance(text, str) and
                              0 < len(text.encode('utf-8')) <= MAX_INPUT_BYTES), 'INVALID_INPUT')
        output_schema = args.get('output_schema')
        need(output_schema is None or (isinstance(output_schema, dict) and
                                       len(json.dumps(output_schema)) <= 16384),
             'INVALID_OUTPUT_SCHEMA')
        stored = self._resume_agent(agent, text, output_schema)
        if args.get('wait_ms'):
            return dict(self.wait(scope, project, agent['agent_id'], args['wait_ms'])) \
                | {'resumed': True}
        return dict(self._summary(stored)) | {'resumed': True}

    def _resume_agent(self, agent: dict, text: str | None, output_schema) -> dict:
        """Shared resume core: claims a provider slot, reattaches the durable
        thread, then either starts a new turn (input) or settles IDLE.
        Unrecoverable threads diagnose to ORPHANED; everything else falls
        back to the pre-resume state."""
        with self.lock:
            self._admit(None, None)   # resuming claims a provider session slot
        stored = self.store.transition(agent['agent_id'], {agent['state']}, st.RECOVERING,
                                       'resume.requested', {'has_input': text is not None},
                                       recovery_attempts=agent['recovery_attempts'] + 1)
        live = None
        try:
            session = self._ensure_session(stored)
            live = self.live[agent['agent_id']]
            if text:
                need(agent['turns_completed'] + 1 <= agent['limits'].get('max_turns', 8),
                     'TURN_LIMIT')
                turn = self._turn_start(session, live, stored, text, output_schema)
                live.turn_id = turn['turn']['id']
                live.turn_started_ns = time.time_ns()
                stored = self._set_state(stored, st.RUNNING, 'turn.started',
                                         {'turn_id': live.turn_id, 'resumed': True},
                                         active_turn_id=live.turn_id)
            else:
                stored = self._set_state(stored, st.IDLE, 'resume.attached',
                                         {'thread_id': live.thread_id})
        except BaseException as error:
            removed = self._pop_live(agent['agent_id'], live) if live is not None else None
            if removed is not None and removed.session is not None:
                removed.session.kill()
            message = str(getattr(error, 'message', error)).lower()
            # A provider thread that no longer exists is unrecoverable: the
            # record becomes orphaned rather than resumable-forever. A rollout
            # that exists but is empty/corrupt (process killed before the first
            # write) is equally unrecoverable — the provider can enumerate the
            # thread yet cannot read session metadata for it.
            unrecoverable = ('no rollout found' in message
                             or 'thread not found' in message
                             or 'failed to read session metadata' in message
                             or ('rollout' in message and 'empty' in message))
            fallback = st.ORPHANED if unrecoverable else \
                (st.INTERRUPTED if agent['state'] == st.INTERRUPTED else st.FAILED)
            try:
                # The spawned session's kill() may already have routed this
                # agent through _on_exit (process.lost) back to INTERRUPTED —
                # accept both source states so an unrecoverable thread still
                # diagnoses to ORPHANED.
                self.store.transition(agent['agent_id'],
                                      {st.RECOVERING, st.INTERRUPTED}, fallback,
                                      'resume.failed',
                                      {'code': getattr(error, 'code', 'PROVIDER_ERROR')},
                                      active_process=0, delegation_pid=None)
            except Rejected:
                pass
            self._wake()
            raise
        self._wake()
        return stored

    def _auto_reattach(self) -> None:
        """Bounded continuation for agents interrupted by *this* restart.

        Only agents that recover() just transitioned are considered — older
        INTERRUPTED rows already had their chance and stay operator-owned.
        Reattach is input-free (never starts a turn): it restores the durable
        provider thread to IDLE so authorized work is steerable again without
        a manual agent_resume.

        Only agents interrupted from a settled state (IDLE/WAITING_INTERNAL)
        are reattached. Agents interrupted mid-turn (RUNNING/STARTING/
        COMPLETING/RECOVERING) have ambiguous provider-side effects and stay
        INTERRUPTED for reconcile-then-resume (agent_resume). A missing
        profile (capability revoked while down) or absent thread_id likewise
        leaves the agent INTERRUPTED for operator action; a provider-side
        missing thread diagnoses to ORPHANED via the normal resume path.
        Slot pressure backs off and retries once."""
        budget = time.monotonic() + self.limits['reattach_budget_s']
        for item in self.recovered:
            if self._closed or time.monotonic() > budget:
                return
            if item.get('from_state') not in (st.IDLE, st.WAITING_INTERNAL):
                continue  # in-flight effects are ambiguous — operator reconciles
            try:
                record = self.store.get(item['agent_id'])
            except Exception:
                continue
            if record is None or record['state'] != st.INTERRUPTED:
                continue  # operator or watchdog already acted on it
            if record['profile'] not in self.profiles:
                continue  # capability revoked while down — operator decision
            if not (record.get('provider_state') or {}).get('thread_id'):
                continue  # nothing durable to reattach
            try:
                self._resume_agent(record, None, None)
            except Rejected as err:
                if err.code not in ('BUSY', 'RATE_LIMIT'):
                    continue
                time.sleep(15)
                if self._closed:
                    return
                try:
                    fresh = self.store.get(item['agent_id'])
                    if fresh is not None and fresh['state'] == st.INTERRUPTED:
                        self._resume_agent(fresh, None, None)
                except Exception:
                    pass  # stays INTERRUPTED — operator-visible
            except Exception:
                pass  # resume path already recorded the fallback state

    def fork(self, scope: str, project: str, args: dict) -> dict:
        self._open()
        agent = self._own(scope, args['agent_id'], write=True)
        # Fork re-grants authority (a fresh delegation token when the profile
        # allows it), so terminal/revoked parents can never be forked.
        if agent['state'] not in {st.RUNNING, st.WAITING_INTERNAL, st.IDLE,
                                st.COMPLETED, st.INTERRUPTED, st.FAILED}:
            raise Rejected('STATE_MISMATCH', {'state': agent['state']})
        thread_id = (agent.get('provider_state') or {}).get('thread_id')
        if not thread_id:
            raise Rejected('FORK_UNAVAILABLE')
        task = args.get('task')
        need(task is None or (isinstance(task, str) and
                              0 < len(task.encode('utf-8')) <= MAX_TASK_BYTES), 'INVALID_TASK')
        session = self._ensure_session(agent)
        resp = session.request('thread/fork', {'threadId': thread_id}, timeout=30)
        new_thread = (resp.get('thread') or {}).get('id')
        if not (isinstance(new_thread, str) and new_thread):
            raise Rejected('PROVIDER_CONTRACT', {'detail': 'thread/fork returned no thread id'})
        child_id = 'agt-' + uuid.uuid4().hex[:16]
        child_limits = dict(agent['limits'])
        # A fork inherits delegation rights from the parent's authority
        # snapshot and receives its own token — never the parent's token.
        can_delegate = bool(child_limits.get('can_delegate'))
        token = secrets.token_hex(32) if can_delegate else None
        with self.lock:
            self._admit(agent, None)
            record = {'agent_id': child_id, 'scope': scope, 'project': agent['project'],
                      'task': task or agent['task'], 'task_sha256': digest(task or agent['task']),
                      'profile': agent['profile'], 'provider': 'codex',
                      'model': agent['model'], 'effort': agent['effort'],
                      'workspace_mode': agent['workspace_mode'],
                      'workspace_root': agent['workspace_root'], 'workspace_managed': False,
                      'depth': agent['depth'], 'parent_agent_id': agent['agent_id'],
                      'lineage': agent['lineage'] + [agent['agent_id']],
                      'dedupe_key': None, 'request_id': args.get('request_id'),
                      'output_schema': agent.get('output_schema'),
                      'delegation_token_sha256': hashlib.sha256(token.encode()).hexdigest()
                      if token else None,
                      'limits': child_limits,
                      'provider_state': dict(agent.get('provider_state') or {},
                                             thread_id=new_thread, forked=True),
                      'policy_binding': agent.get('policy_binding')}
            stored = self.store.create(record)
        if task:
            stored = self._set_state(stored, st.STARTING, 'fork.starting',
                                   {'from': agent['agent_id']})
            live = self._install_live(child_id, new_thread)
            try:
                session2 = self._spawn_session(stored, live, token=token, thread_id=new_thread)
                if not self._bind_live_session(child_id, live, session2):
                    session2.kill()
                    raise ControlError('PROVIDER_REPLACED',
                                       'Provider session was superseded during startup')
                turn = self._turn_start(session2, live, stored, task,
                                        stored.get('output_schema'))
                live.turn_id = turn['turn']['id']
                live.turn_started_ns = time.time_ns()
                stored = self._set_state(stored, st.RUNNING, 'turn.started',
                                         {'turn_id': live.turn_id, 'forked': True},
                                         active_turn_id=live.turn_id)
            except BaseException:
                removed = self._pop_live(child_id, live)
                if removed is not None and removed.session is not None:
                    removed.session.kill()
                try:
                    self.store.transition(child_id, {st.STARTING}, st.FAILED,
                                          'fork.failed', {}, active_process=0)
                except Rejected:
                    pass
                self._wake()
                raise
        else:
            stored = self._set_state(stored, st.IDLE, 'forked.ready',
                                     {'thread_id': new_thread})
        if args.get('wait_ms'):
            return dict(self.wait(scope, project, child_id, args['wait_ms'])) \
                | {'forked_from': agent['agent_id'], 'thread_id': new_thread}
        return dict(self._summary(stored)) | {'forked_from': agent['agent_id'],
                                              'thread_id': new_thread}

    def status(self, scope: str, project: str, args: dict) -> dict:
        agent = self._own(scope, args['agent_id'])
        data = self._summary(agent, detail=True)
        include = args.get('include') or []
        need(isinstance(include, list) and len(include) <= 4
             and set(include) <= {'events', 'result', 'provider'}, 'INVALID_INCLUDE')
        if 'result' in include:
            data['result'] = agent.get('result')
        if 'events' in include:
            data['events_tail'] = self.store.events(agent['agent_id'], limit=16,
                                                    tail=True)['events']
        if 'provider' in include:
            data['provider_detail'] = agent.get('provider_state')
        return data

    def wait(self, scope: str, project: str, agent_id: str, wait_ms: int) -> dict:
        need(type(wait_ms) is int and 0 <= wait_ms <= 3600000, 'INVALID_WAIT')
        deadline = time.monotonic() + wait_ms / 1000
        while True:
            record = self._own(scope, agent_id)
            if record['state'] in AWAITABLE or time.monotonic() >= deadline:
                return self._summary(record)
            with self.cond:
                self.cond.wait(min(0.5, max(0.05, deadline - time.monotonic())))

    def result(self, scope: str, project: str, args: dict) -> dict:
        agent = self._own(scope, args['agent_id'])
        data = self._summary(agent, detail=True)
        data['result'] = agent.get('result')
        data['files_changed'] = agent.get('files_changed') or []
        data['token_usage'] = agent.get('token_usage')
        return data

    def events(self, scope: str, project: str, args: dict) -> dict:
        agent = self._own(scope, args['agent_id'])
        return self.store.events(agent['agent_id'], after_seq=args.get('cursor', 0),
                                 limit=args.get('limit', 64))

    def list_agents(self, scope: str, project: str, args: dict) -> dict:
        state = args.get('state')
        need(state is None or state in st.STATES, 'INVALID_STATE')
        scoped = project if project not in ('', '*') else None
        rows = self.store.list(project=scoped, state=state, limit=args.get('limit', 64),
                               include_archived=args.get('include_archived') is True)
        # Scope isolation: a project-scoped list must never reveal agents owned
        # by another principal, and catalog listings stay inside this principal.
        if scoped is None:
            rows = [r for r in rows if r['scope'].startswith(self.principal + ':')]
        else:
            rows = [r for r in rows if r['scope'] == scope]
        return {'agents': [self._summary(r) for r in rows],
                'stats': self.store.stats() if scoped is None else None}

    def capabilities(self) -> dict:
        info = error = None
        try:
            info = self.exe_info()
        except ControlError as e:
            error = e.code
        models = models_error = None
        if info is not None:
            try:
                models = self._models()
            except ControlError as e:
                models_error = e.code
        return {
            'providers': {'codex': {
                'available': info is not None,
                'unavailable_reason': error,
                'executable': info['path'] if info else None,
                'executable_sha256': info['sha256'] if info else None,
                'version': info['version'] if info else None,
                'supported_floor': '.'.join(str(x) for x in SUPPORTED_CODEX),
                'protocol': PROTOCOL_NOTE,
                'model_provider': self.codex_cfg['model_provider'],
                'default_model': self.codex_cfg['model'],
                'models': models,
                'models_error': models_error,
                'auth_mode': 'delegated-codex-home-hardlink',
                'features': {'steer': True, 'interrupt': True, 'resume': True, 'fork': True,
                             'output_schema': True, 'sandbox_modes': ['read_only', 'workspace_write'],
                             'approval_policy': 'never',
                             'os_sandbox': 'windows-elevated'}}},
            'profiles': {name: {'codex_sandbox': p.codex_sandbox, 'network': p.network,
                                'can_delegate': p.can_delegate, 'max_runtime_s': p.max_runtime_s,
                                'max_turns': p.max_turns, 'max_children': p.max_children,
                                'max_depth': p.max_depth,
                                'requires_os_sandbox': p.requires_os_sandbox,
                                'description': p.description}
                         for name, p in sorted(self.profiles.items())},
            'limits': dict(self.limits),
            'states': sorted(st.STATES),
            'delegation': {'via': 'lc_agent_* MCP tools inside delegate-capable profiles',
                           'token_binding': 'token + provider process ancestry'},
            'recovery': {'daemon_restart': 'agents interrupted by the restart auto-reattach '
                                           'durable provider threads (reattach only — no '
                                           'turn is restarted); agents interrupted earlier, '
                                           'missing threads, or on removed profiles stay '
                                           'interrupted for agent_resume/operator action',
                         'auto_resume': 'reattach_only'}}

    def cleanup(self, scope: str, project: str, args: dict) -> dict:
        self._open()
        confirm = args.get('confirm')
        need(confirm in (None, 'delete_artifacts'), 'INVALID_ARGUMENT')
        if args.get('all_terminal') is True:
            rows = self.store.list(project=project if project not in ('', '*') else None,
                                   include_archived=True)
            targets = [r for r in rows if r['state'] in st.TERMINAL and not r['archived']
                       and (r['scope'] == scope or
                            (project in ('', '*') and r['scope'].startswith(self.principal + ':')))]
        else:
            agent = self._own(scope, args['agent_id'])
            if agent['state'] not in st.TERMINAL:
                raise Rejected('STATE_MISMATCH', {'state': agent['state']})
            targets = [agent]
        cleaned = []
        for record in targets:
            artifacts = self._delete_artifacts(record) if confirm == 'delete_artifacts' else []
            self.store.update_fields(record['agent_id'], 'archived',
                                     {'artifacts_removed': artifacts}, archived=1)
            cleaned.append({'agent_id': record['agent_id'], 'artifacts_removed': artifacts})
        return {'cleaned': cleaned, 'count': len(cleaned)}

    # ---------- spawn pipeline ----------

    def _spawn_pipeline(self, agent_id: str, token: str | None) -> None:
        stored = self.store.get(agent_id)   # already STARTING (claimed under lock)
        live = self._install_live(agent_id)
        try:
            session = self._spawn_session(stored, live, token=token)
            if not self._bind_live_session(agent_id, live, session):
                session.kill()
                raise ControlError('PROVIDER_REPLACED',
                                   'Provider session was superseded during startup')
            turn = self._turn_start(session, live, stored, stored['task'],
                                    stored.get('output_schema'))
            live.turn_id = turn['turn']['id']
            live.turn_started_ns = time.time_ns()
            self._set_state(stored, st.RUNNING, 'turn.started',
                            {'turn_id': live.turn_id}, active_turn_id=live.turn_id)
        except BaseException as error:
            code = getattr(error, 'code', 'PROVIDER_ERROR')
            removed = self._pop_live(agent_id, live)
            if removed is not None and removed.session is not None:
                removed.session.kill()
            try:
                self.store.transition(agent_id, {st.STARTING}, st.FAILED,
                                      'spawn.failed', {'code': code}, active_process=0)
            except Rejected:
                pass
            self._wake()
            raise

    def _spawn_session(self, record: dict, live: _Live, token: str | None = None,
                       thread_id: str | None = None) -> Session:
        """Build home (first time), spawn process, handshake, sandbox readiness,
        thread start/resume. Session is NOT yet in self.live when returned."""
        agent_id = record['agent_id']
        exe = self.exe_info()
        pin = self.codex_cfg.get('executable_sha256')
        if pin is not None:
            # The discovered binary may have been swapped since first use:
            # re-hash at every spawn when the operator pins an identity.
            actual = hashlib.sha256(Path(exe['path']).read_bytes()).hexdigest()
            require(actual == pin, 'PROVIDER_UNSUPPORTED',
                    'codex executable sha256 changed since discovery')
        provider = dict(record.get('provider_state') or {})
        agent_dir = self.policy.state_dir / 'v110' / 'agents' / agent_id
        home = agent_dir / 'codex-home'
        deadline = time.monotonic() + self.limits['startup_timeout_s']

        if not (home / 'config.toml').exists() or not (home / 'auth.json').exists():
            if token is None and record['delegation_token_sha256']:
                # Lazily built home (e.g. an idle fork's first send): the
                # original token plaintext is gone by design, so issue a fresh
                # token and rotate the stored hash atomically.
                token = secrets.token_hex(32)
                self.store.update_fields(
                    agent_id, 'delegation.rotated', {},
                    delegation_token_sha256=hashlib.sha256(token.encode()).hexdigest())
            shim = self._shim_spec(agent_id, token) if token else None
            provider_table = read_provider_table(
                Path(self.codex_cfg['auth_home']) / 'config.toml',
                self.codex_cfg['model_provider'])
            build_home(home, auth_source=Path(self.codex_cfg['auth_home']) / 'auth.json',
                       provider_table=provider_table, model=record.get('model'),
                       model_provider=self.codex_cfg['model_provider'],
                       sandbox_mode=provider.get('sandbox', 'read_only'),
                       model_catalog=self.codex_cfg['model_catalog'],
                       windows_sandbox=self.codex_cfg['windows_sandbox'], shim=shim)

        env = child_env()
        env['CODEX_HOME'] = str(home)
        workspace = Path(record['workspace_root'])
        # Re-validate the stored workspace at session start: the admission-time
        # check ran earlier and a mutable path may have been swapped since.
        spec = self.policy.projects.get(record['project'])
        resolved = workspace.resolve()
        if record.get('workspace_managed'):
            # Managed worktrees live under the state dir by design, outside the
            # project root: verify the exact recorded location, not a project-
            # relative envelope. Outside-root is expected here, not a breach.
            expected = (self.policy.state_dir / 'v110' / 'worktrees' / agent_id).resolve()
            need(spec is not None and resolved == workspace and resolved == expected
                 and resolved.is_dir(), 'WORKSPACE_GONE')
        else:
            envelope = spec.root.resolve() if spec is not None else None
            parent_id = record.get('parent_agent_id')
            if parent_id:
                # A child/fork of a managed-worktree parent is admitted under
                # the parent's worktree as its envelope (see _resolve_workspace)
                # — it legitimately lives outside the project spec root.
                try:
                    parent = self.store.get(parent_id)
                except Exception:
                    parent = None
                if parent is not None and parent.get('workspace_managed') \
                        and parent.get('workspace_root'):
                    envelope = Path(parent['workspace_root']).resolve()
            need(spec is not None and resolved == workspace
                 and envelope is not None
                 and resolved.is_relative_to(envelope)
                 and resolved.is_dir(), 'WORKSPACE_GONE')
        generation = live.generation
        session = Session(
            agent_id, exe['path'], home, workspace, env,
            on_event=lambda m, a=agent_id, g=generation: self._on_event(a, g, m),
            on_exit=lambda rc, a=agent_id, g=generation: self._on_exit(a, g, rc),
            on_request=lambda m, p, a=agent_id, g=generation: self._on_request(a, g, m, p))
        session.start()
        try:
            hello = session.handshake(CLIENT_NAME, timeout=max(5, deadline - time.monotonic()))
            provider.update({'exe_path': exe['path'], 'exe_sha256': exe['sha256'],
                             'codex_version': exe['version'], 'protocol': PROTOCOL_NOTE,
                             'user_agent': hello.get('userAgent'), 'codex_home': str(home),
                             'session_pid': session.pid, 'auth_mode': 'hardlink',
                             'model_provider': self.codex_cfg['model_provider']})
            # Bind provider ancestry BEFORE thread/start: the delegation shim
            # may come up during thread start and must already see its pid.
            with self.lock:
                require(self.live.get(agent_id) is live, 'PROVIDER_REPLACED',
                        'Provider session was superseded during startup')
                if record['delegation_token_sha256']:
                    self.store.update_fields(agent_id, 'session.binding',
                                             {'pid': session.pid},
                                             delegation_pid=session.pid,
                                             delegation_exe=exe['path'],
                                             provider_json=provider)
            if provider.get('requires_os_sandbox'):
                self._ensure_sandbox(session, live, deadline)
            if thread_id is None:
                thread = session.request('thread/start', {
                    'cwd': record['workspace_root'],
                    'sandbox': {'read_only': 'read-only',
                                'workspace_write': 'workspace-write',
                                'danger_full_access': 'danger-full-access'}[
                                    provider.get('sandbox', 'read_only')],
                    'approvalPolicy': 'never', 'approvalsReviewer': 'user',
                    'model': record.get('model'),
                    'modelProvider': self.codex_cfg['model_provider'],
                    'ephemeral': False,
                    'developerInstructions': DEVELOPER_PREAMBLE},
                    timeout=max(5, deadline - time.monotonic()))
                thread_id = thread['thread']['id']
            else:
                resumed = session.request('thread/resume', {'threadId': thread_id},
                                          timeout=max(5, deadline - time.monotonic()))
            provider['thread_id'] = thread_id
            provider['session_pid'] = session.pid
            with self.lock:
                require(self.live.get(agent_id) is live, 'PROVIDER_REPLACED',
                        'Provider session was superseded during startup')
                live.thread_id = thread_id
                self.store.update_fields(agent_id, 'session.started',
                                         {'thread_id': thread_id, 'pid': session.pid},
                                         provider_json=provider, active_process=1)
        except BaseException:
            session.kill()
            raise
        return session

    def _ensure_sandbox(self, session: Session, live: _Live, deadline: float) -> None:
        try:
            ready = session.request('windowsSandbox/readiness',
                                    timeout=max(5, deadline - time.monotonic()))
        except ControlError:
            raise ControlError('SANDBOX_UNAVAILABLE',
                               'windowsSandbox/readiness unsupported by this app-server')
        status = (ready or {}).get('status')
        if status in ('notConfigured', 'updateRequired'):
            session.request('windowsSandbox/setupStart',
                            {'mode': self.codex_cfg['windows_sandbox']},
                            timeout=max(5, deadline - time.monotonic()))
            live.setup_done.wait(max(5, deadline - time.monotonic()))
            ready = session.request('windowsSandbox/readiness',
                                    timeout=max(5, deadline - time.monotonic()))
            status = (ready or {}).get('status')
        if status != 'ready':
            raise ControlError('SANDBOX_UNAVAILABLE',
                               'Windows sandbox not ready for this profile',
                               {'status': status})

    def _turn_start(self, session: Session, live: _Live, record: dict,
                    text: str, output_schema) -> dict:
        self._require_current_live(record['agent_id'], live)
        provider = record.get('provider_state') or {}
        sandbox = {'type': 'readOnly'}
        if provider.get('sandbox') == 'workspace_write':
            sandbox = {'type': 'workspaceWrite',
                       'writableRoots': [record['workspace_root']]
                       if provider.get('writable_roots_mode', 'workspace') == 'workspace' else [],
                       'networkAccess': bool(provider.get('network'))}
        elif provider.get('sandbox') == 'danger_full_access':
            sandbox = {'type': 'dangerFullAccess'}
        params = {'threadId': live.thread_id,
                  'input': [{'type': 'text', 'text': text}],
                  'sandboxPolicy': sandbox, 'approvalPolicy': 'never',
                  'cwd': record['workspace_root']}
        if record.get('model'):
            params['model'] = record['model']
        if record.get('effort'):
            params['effort'] = record['effort']
        if output_schema is not None:
            params['outputSchema'] = output_schema
        return session.request('turn/start', params,
                               timeout=self.limits['startup_timeout_s'])

    def _shim_spec(self, agent_id: str, token: str) -> dict:
        import sys
        package_parent = str(Path(__file__).resolve().parent.parent.parent)
        return {'command': sys.executable,
                'args': ['-m', 'localcontrol.agents.shim',
                         '--state-dir', str(self.policy.state_dir)],
                'token': token, 'agent_id': agent_id, 'pythonpath': package_parent}

    # ---------- provider event handling ----------

    def _on_event(self, agent_id: str, generation: int, msg: dict) -> None:
        with self.lock:
            live = self.live.get(agent_id)
            if live is None or live.generation != generation:
                return
            self._on_event_current(agent_id, live, msg)

    def _on_event_current(self, agent_id: str, live: _Live, msg: dict) -> None:
        live.last_event_ns = time.time_ns()
        method = msg.get('method') or ''
        params = msg.get('params') or {}
        try:
            if method == 'windowsSandbox/setupCompleted':
                if live is not None:
                    live.setup_done.set()
            elif method == 'turn/started':
                turn = params.get('turn') or {}
                if live is not None and turn.get('id'):
                    live.turn_id = turn['id']
                    live.turn_started_ns = time.time_ns()
            elif method == 'turn/completed':
                self._turn_completed(agent_id, live, params.get('turn') or {})
            elif method == 'item/completed':
                self._item_completed(agent_id, live, params.get('item') or {})
            elif method == 'thread/tokenUsage/updated':
                if live is not None:
                    live.token_usage = (params.get('tokenUsage') or {}).get('total')
            elif method == 'error':
                info = params.get('codexErrorInfo')
                kind = next(iter(info), info) if isinstance(info, dict) else info
                retry = bool(params.get('willRetry'))
                self._note(agent_id, 'provider.error',
                           {'codex_error': kind, 'will_retry': retry,
                            'message': str(params.get('message'))[:256]},
                           status_detail_json={'provider_error': kind,
                                               'retrying': retry})
            elif method == 'warning':
                self._note(agent_id, 'provider.warning',
                           {'message': str(params.get('message'))[:256]})
            elif method == 'serverRequest/resolved':
                self._note(agent_id, 'provider.requestResolved',
                           {'request_id': params.get('requestId')})
            elif method == 'mcpServer/startupStatus/updated':
                self._note(agent_id, 'provider.mcpStartup',
                           {'server': str(params.get('server'))[:128],
                            'status': str(params.get('status'))[:64]})
            elif method == 'turn/diff/updated':
                diff = params.get('diff') or ''
                if live is not None:
                    for match in re.findall(r'^\+\+\+ b/(.+)$', diff, re.M)[:64]:
                        live.files_changed.add(match)
        except (Rejected, ControlError):
            pass
        except Exception:
            pass

    def _item_completed(self, agent_id: str, live: _Live, item: dict) -> None:
        itype = item.get('type')
        if itype == 'agentMessage' and live is not None:
            text = item.get('text') or ''
            if item.get('phase') == 'final_answer' and text:
                live.final_texts.append(text)
            elif text and not live.final_texts:
                live.final_texts.append(text)
        elif itype == 'fileChange':
            changes = item.get('changes') or {}
            paths = list(changes)[:64]
            if live is not None:
                live.files_changed.update(paths)
            self._note(agent_id, 'item.fileChange', {'paths': paths[:16]})
        elif itype == 'commandExecution':
            self._note(agent_id, 'item.command',
                       {'command': str(item.get('command'))[:384],
                        'exit_code': item.get('exitCode')})
        elif itype == 'mcpToolCall':
            self._note(agent_id, 'item.mcpTool',
                       {'tool': str(item.get('tool'))[:128],
                        'server': str(item.get('server'))[:128]})

    def _turn_completed(self, agent_id: str, live: _Live, turn: dict) -> None:
        if self.live.get(agent_id) is not live:
            return
        record = self.store.maybe_get(agent_id)
        if record is None or record['state'] in st.TERMINAL:
            return
        if live is not None and live.turn_id and turn.get('id') and turn['id'] != live.turn_id:
            return  # completion for a previous turn; keep current state
        usage = live.token_usage if live else None
        finals = list(live.final_texts) if live else []
        if not finals:
            for item in turn.get('items') or []:
                if isinstance(item, dict) and item.get('type') == 'agentMessage' \
                        and item.get('text'):
                    finals.append(item['text'])
        files = sorted(live.files_changed)[:256] if live else []
        updates = {'token_usage_json': usage, 'files_changed_json': files,
                   'active_turn_id': None,
                   'turns_completed': record['turns_completed'] + 1}
        if live is not None:
            live.turn_id = None
            live.final_texts = []
            live.files_changed = set()
        status = turn.get('status')
        if status == 'completed':
            final = finals[-1] if finals else None
            schema_ok = None
            if record.get('output_schema') is not None and isinstance(final, str):
                try:
                    schema_ok = isinstance(json.loads(final), (dict, list))
                except ValueError:
                    schema_ok = False
            result = {'final': _clip(final, min(self.limits['max_result_bytes'], 32768)),
                      'finals': [_clip(f, 8192) for f in finals[-4:]],
                      'turn_id': turn.get('id'),
                      'duration_ms': turn.get('durationMs'), 'ended_at_ns': time.time_ns(),
                      'schema_valid': schema_ok,
                      'schema_validation': 'json-parse' if schema_ok is not None
                                           else 'not-requested'}
            self._set_state(record, st.COMPLETING, 'turn.completed',
                            {'turn_id': turn.get('id'), 'status': status}, **updates)
            try:
                self._set_state(self.store.get(agent_id), st.IDLE, 'agent.idle',
                                {'turns_completed': record['turns_completed'] + 1},
                                result_json=result)
            except Rejected:
                # The column budget is a hard bound; never strand the agent in
                # completing — persist a truncated marker instead.
                self._set_state(self.store.get(agent_id), st.IDLE, 'agent.idle',
                                {'turns_completed': record['turns_completed'] + 1},
                                result_json={'final': None, 'truncated': True,
                                             'turn_id': turn.get('id'),
                                             'ended_at_ns': time.time_ns(),
                                             'schema_valid': None,
                                             'schema_validation': 'not-requested'})
        elif status in ('failed', 'interrupted'):
            detail = {'turn_status': status, 'turn_id': turn.get('id'),
                      'error': (turn.get('error') or {}).get('message'),
                      'codex_error': (turn.get('error') or {}).get('codexErrorInfo')}
            to = st.CANCELLED if (status == 'interrupted' and live and live.cancel_requested) \
                else (st.INTERRUPTED if status == 'interrupted' else st.FAILED)
            self._set_state(record, to, 'turn.ended', detail, status_detail_json=detail,
                            **updates)
        else:
            self._set_state(record, st.FAILED, 'turn.ended',
                            {'turn_status': status or 'unknown'}, **updates)
        self._wake()

    def _on_request(self, agent_id: str, generation: int, method: str, params: dict) -> dict:
        with self.lock:
            live = self.live.get(agent_id)
            if live is None or live.generation != generation:
                raise DeniedByPolicy('stale provider session')
            return self._on_request_current(agent_id, method, params)

    def _on_request_current(self, agent_id: str, method: str, params: dict) -> dict:
        """Policy table for server->client requests. Runs on the session's
        dispatch thread; bounded and never caller-blocking."""
        if method == 'account/chatgptAuthTokens/refresh':
            return self._auth_refresh()
        if method in ('item/commandExecution/requestApproval',
                      'item/fileChange/requestApproval'):
            self._denial(agent_id, method, params)
            return DENY_APPROVAL
        if method in ('applyPatchApproval', 'execCommandApproval'):
            self._denial(agent_id, method, params)
            return DENY_LEGACY
        if method == 'item/permissions/requestApproval':
            self._denial(agent_id, method, params)
            raise DeniedByPolicy('permission escalation requests are denied by policy')
        if method == 'item/tool/requestUserInput':
            answers = {q.get('id'): {'answers': []}
                       for q in (params.get('questions') or [])
                       if isinstance(q, dict) and q.get('id')}
            self._denial(agent_id, method, {'questions': len(answers)})
            return {'answers': answers}
        if method == 'item/tool/call':
            self._denial(agent_id, method, {'tool': params.get('tool')})
            return DENY_TOOL_CALL
        if method == 'mcpServer/elicitation/request':
            self._denial(agent_id, method, {'server': params.get('serverName')})
            return DENY_ELICITATION
        self._denial(agent_id, method or 'unknown',
                     params if isinstance(params, dict) else {})
        raise DeniedByPolicy(f'{method} is not supported by the delegation client')

    def _denial(self, agent_id: str, method: str, params: dict) -> None:
        record = self.store.maybe_get(agent_id)
        detail = {'method': method,
                  'command': str((params or {}).get('command'))[:256],
                  'tool': (params or {}).get('tool')}
        self._note(agent_id, 'provider.requestDenied', detail,
                   tool_denials=(record['tool_denials'] + 1) if record else 1)

    def _auth_refresh(self) -> dict:
        """Answer chatgptAuthTokens/refresh from the operator's live auth.json.
        Tokens are read per request and returned to the provider — never
        persisted or logged by LocalControl."""
        try:
            data = json.loads((Path(self.codex_cfg['auth_home']) / 'auth.json')
                              .read_text(encoding='utf-8'))
        except (OSError, ValueError):
            raise DeniedByPolicy('operator codex auth unavailable')
        tokens = data.get('tokens') or {}
        if not tokens.get('access_token') or not tokens.get('account_id'):
            raise DeniedByPolicy('operator codex auth has no chatgpt tokens')
        return {'accessToken': tokens['access_token'],
                'chatgptAccountId': tokens['account_id'], 'chatgptPlanType': None}

    def _on_exit(self, agent_id: str, generation: int, returncode) -> None:
        session = None
        with self.cond:
            live = self.live.get(agent_id)
            if live is None or live.generation != generation:
                return
            self.live.pop(agent_id, None)
            live.starting = False
            self.cond.notify_all()
            session = live.session

            record = self.store.maybe_get(agent_id)
            if record is None or record['state'] in st.TERMINAL | {st.COMPLETING, st.IDLE}:
                # Still unbind the dead pid — a recycled pid must not satisfy the
                # shim's ancestry check for a parked/finished agent.
                if record is not None and record.get('delegation_pid'):
                    try:
                        self.store.update_fields(agent_id, '', {}, delegation_pid=None)
                    except Rejected:
                        pass
            elif not live.cancel_requested:
                try:
                    self.store.transition(agent_id, {record['state']}, st.INTERRUPTED,
                                          'process.lost', {'returncode': returncode},
                                          active_process=0, active_turn_id=None,
                                          delegation_pid=None)
                except Rejected:
                    try:
                        self.store.update_fields(
                            agent_id, 'process.lost', {'returncode': returncode},
                            active_process=0)
                    except Rejected:
                        pass
            self.cond.notify_all()

        if session is not None:
            session.kill()
        self._wake()

    # ---------- supervision ----------

    def _supervise(self) -> None:
        while not self._closed:
            try:
                self._tick()
            except Exception:
                pass
            time.sleep(1.0)

    def _tick(self) -> None:
        now = time.time_ns()
        for agent_id, live in list(self.live.items()):
            record = self.store.maybe_get(agent_id)
            if record is None:
                continue
            state = record['state']
            limits = record['limits'] or {}
            if state in st.TERMINAL or state == st.INTERRUPTED:
                # A live entry must never outlive its row's authority: a dead
                # or revoked agent's provider process is reaped here.
                removed = self._pop_live(agent_id, live)
                if removed is None:
                    continue
                if removed.session is not None:
                    removed.session.kill()
                continue
            if state in (st.RUNNING, st.WAITING_INTERNAL) and live.turn_started_ns:
                if (now - live.turn_started_ns) / 1e9 > limits.get('max_runtime_s', 1800):
                    self._kill_turn(agent_id, 'runtime_exceeded')
                    continue
                if (now - live.last_event_ns) / 1e9 > limits.get('stall_timeout_s', 300):
                    self._kill_turn(agent_id, 'stalled_no_progress')
                    continue
            if state == st.IDLE and (now - live.last_event_ns) / 1e9 > limits.get('idle_retain_s', 300):
                removed = self._pop_live(agent_id, live)
                if removed is None:
                    continue
                session = removed.session
                if session is not None:
                    session.kill()
                try:
                    self.store.transition(agent_id, {st.IDLE}, st.COMPLETED,
                                          'agent.parked', {'reason': 'idle_retention'},
                                          active_process=0, delegation_pid=None)
                except Rejected:
                    pass
                self._wake()

    def _intent_loop(self) -> None:
        """Intent execution runs on its own thread: a delegated child spawn
        (process start + handshake + thread/start) can take tens of seconds and
        must never stall the stall/runtime watchdog."""
        while not self._closed:
            try:
                self._drain_intents()
            except Exception:
                pass
            time.sleep(0.5)

    def _kill_turn(self, agent_id: str, reason: str) -> None:
        live = self.live.get(agent_id)
        if live is None:
            return
        removed = self._pop_live(agent_id, live)
        if removed is None:
            return
        if removed.session is not None and removed.turn_id and removed.session.alive():
            try:
                removed.session.request('turn/interrupt', {'threadId': removed.thread_id,
                                                           'turnId': removed.turn_id}, timeout=10)
            except Exception:
                pass
        if removed.session is not None:
            removed.session.kill()
        try:
            self.store.transition(agent_id, st.LIVE - {st.QUEUED}, st.FAILED,
                                  'agent.terminated', {'reason': reason},
                                  active_process=0, active_turn_id=None,
                                  delegation_pid=None)
        except Rejected:
            pass
        self._wake()

    # ---------- delegation intents ----------

    def _drain_intents(self) -> None:
        for intent in self.store.dequeue_intents(16):
            try:
                parent = self.store.token_lookup(intent['token_sha256'])
                if parent is not None and parent['state'] == st.INTERRUPTED:
                    # Parent lost its provider session and may reattach or be
                    # resumed; an interruption must not consume the intent.
                    self.store.requeue_intent(intent['intent_id'])
                    continue
                self.store.finish_intent(intent['intent_id'], True,
                                         self._execute_intent(intent))
            except (ControlError, Rejected) as error:
                self.store.finish_intent(intent['intent_id'], False,
                                         {'code': getattr(error, 'code', 'INTENT_FAILED')})
            except Exception:
                self.store.finish_intent(intent['intent_id'], False,
                                         {'code': 'INTERNAL_ERROR'})

    def _execute_intent(self, intent: dict) -> dict:
        parent = self.store.token_lookup(intent['token_sha256'])
        need(parent is not None, 'DELEGATION_DENIED')
        need(parent['agent_id'] == intent['parent_agent_id'], 'DELEGATION_DENIED')
        need(parent['state'] not in (st.CANCELLED, st.ORPHANED), 'DELEGATION_REVOKED')
        limits = parent['limits'] or {}
        need(limits.get('can_delegate'), 'DELEGATION_DENIED')
        payload = json.loads(intent['payload_json'])
        op = intent['op']
        if op == 'spawn':
            task = payload.get('task')
            need(isinstance(task, str) and 0 < len(task.encode('utf-8')) <= MAX_TASK_BYTES,
                 'INVALID_TASK')
            child = self._child_profile(parent, payload.get('profile'))
            spec = {'task': task, 'model': payload.get('model'), 'effort': payload.get('effort'),
                    'output_schema': payload.get('output_schema'),
                    'workspace_mode': payload.get('workspace_mode', 'existing'),
                    'workspace_path': payload.get('workspace_path'),
                    # Deterministic key: an intent re-queued after a crash
                    # dedupes to the child it already created, never re-runs.
                    'dedupe_key': f"intent:{parent['agent_id']}:{intent['request_key']}",
                    'request_id': intent['request_key'],
                    '_parent': parent, '_profile': child}
            result = self.spawn(parent['scope'], parent['project'], spec)
            self.store.update_fields(parent['agent_id'], 'delegation.spawned',
                                     {'child': result['agent_id'],
                                      'request_key': intent['request_key']})
            return {'agent_id': result['agent_id'], 'state': result['state']}
        if op in ('send', 'cancel'):
            agent_id = payload.get('agent_id')
            ident(agent_id)
            target = self.store.maybe_get(agent_id)
            need(target is not None and parent['agent_id'] in target['lineage'],
                 'DELEGATION_SCOPE')
            if op == 'send':
                return self.send(parent['scope'], target['project'],
                                 {'agent_id': agent_id, 'input': payload.get('input'),
                                  'wait_ms': 0})
            return self.cancel(parent['scope'], target['project'],
                               {'agent_id': agent_id, 'reason': 'delegated cancel'})
        raise Rejected('INVALID_INTENT_OP')

    def _child_profile(self, parent: dict, requested: str | None) -> Profile:
        """Resolve the profile a child may run under. A delegated child may only
        claim the parent's own profile or the parent's configured
        delegate_profile — never an arbitrary named profile."""
        limits = parent['limits'] or {}
        allowed = {parent['profile'], limits.get('delegate_profile')} - {None}
        if requested is not None:
            need(requested in self.profiles and requested in allowed, 'PROFILE_DENIED')
            return self.profiles[requested]
        delegate = limits.get('delegate_profile')
        if delegate and delegate in self.profiles:
            return self.profiles[delegate]
        return self.profiles.get(parent['profile'], self.profiles[self.default_profile])

    # ---------- workspace ----------

    def _resolve_workspace(self, project: str, args: dict, agent_id: str,
                           parent: dict | None = None) -> dict:
        mode = args.get('workspace_mode', 'existing')
        need(mode in st.WORKSPACE_MODES, 'INVALID_WORKSPACE_MODE')
        spec = self.policy.projects[project]
        if parent is not None:
            # Delegated children inherit the parent's effective workspace as
            # their authority envelope. The project enrollment root is never
            # a fallback, and managed worktrees (which live outside the
            # envelope) cannot be requested through delegation.
            need(mode == 'existing', 'WORKSPACE_DENIED')
            envelope = Path(parent['workspace_root']).resolve()
            rel = args.get('workspace_path')
            if rel in (None, '', '.'):
                root = envelope
            else:
                root = self.policy.path(project, safe_relative(rel),
                                        directory=True).resolve()
                need(root.is_relative_to(envelope), 'WORKSPACE_DENIED')
            require(root.is_dir(), 'NOT_FOUND', 'Workspace directory does not exist')
            return {'mode': 'existing', 'root': str(root), 'managed': False}
        if mode == 'existing':
            rel = args.get('workspace_path')
            if rel in (None, '', '.'):
                root = spec.root
            else:
                root = self.policy.path(project, safe_relative(rel), directory=True)
            require(root.is_dir(), 'NOT_FOUND', 'Workspace directory does not exist')
            # Store the canonical path: session start re-verifies it unchanged.
            return {'mode': mode, 'root': str(root.resolve()), 'managed': False}
        require((spec.root / '.git').exists(), 'WORKTREE_UNAVAILABLE',
                'Project root is not a git worktree')
        import shutil
        git = shutil.which('git')
        require(git is not None, 'WORKTREE_UNAVAILABLE', 'git is not available')
        base_ref = args.get('base_ref') or 'HEAD'
        need(isinstance(base_ref, str) and '..' not in base_ref
             and not base_ref.startswith(('-', '/'))
             and re.fullmatch(r'[0-9a-f]{40}|[A-Za-z0-9_.][A-Za-z0-9_./-]{0,63}', base_ref),
             'INVALID_BASE_REF')
        wt_dir = self.policy.state_dir / 'v110' / 'worktrees' / agent_id
        wt_dir.parent.mkdir(parents=True, exist_ok=True)
        out = subprocess.run([git, '-C', str(spec.root), 'worktree', 'add', '--detach',
                              str(wt_dir), base_ref], capture_output=True, timeout=120)
        if out.returncode != 0:
            raise ControlError('WORKTREE_FAILED', 'git worktree add failed',
                               {'stderr': out.stderr.decode('utf-8', 'replace')[-400:]})
        return {'mode': mode, 'root': str(wt_dir.resolve()), 'managed': True,
                'ref': base_ref, 'git_root': str(spec.root)}

    def _undo_workspace(self, workspace: dict) -> None:
        if workspace.get('managed') and workspace.get('root'):
            import shutil
            # `git worktree remove` also drops the .git/worktrees admin entry;
            # plain rmtree would leave stale metadata behind.
            git = shutil.which('git')
            try:
                if git is not None and workspace.get('git_root'):
                    subprocess.run([git, '-C', workspace['git_root'], 'worktree', 'remove',
                                    '--force', workspace['root']],
                                   capture_output=True, timeout=60)
                if Path(workspace['root']).exists():
                    shutil.rmtree(workspace['root'])
            except (OSError, subprocess.SubprocessError):
                pass

    def _delete_artifacts(self, record: dict) -> list[str]:
        removed = []
        if record.get('workspace_managed') and record.get('workspace_root'):
            import shutil
            git = shutil.which('git')
            spec = self.policy.projects.get(record['project'])
            if git and spec is not None:
                out = subprocess.run([git, '-C', str(spec.root), 'worktree', 'remove', '--force',
                                      record['workspace_root']], capture_output=True, timeout=60)
                if out.returncode == 0:
                    removed.append(record['workspace_root'])
        agent_dir = self.policy.state_dir / 'v110' / 'agents' / record['agent_id']
        if agent_dir.is_dir():
            import shutil
            try:
                shutil.rmtree(agent_dir)
                removed.append(str(agent_dir))
            except OSError:
                pass
        return removed

    # ---------- helpers ----------

    def _open(self) -> None:
        need(not self._closed, 'SHUTTING_DOWN')

    def _own(self, scope: str, agent_id: str, write: bool = False) -> dict:
        ident(agent_id)
        need(AGENT_ID_RE.match(agent_id) is not None, 'INVALID_AGENT_ID')
        record = self.store.get(agent_id)
        need(record['scope'] == scope, 'AGENT_NOT_FOUND')
        if write:
            need(not record['archived'], 'AGENT_ARCHIVED')
        return record

    def _set_state(self, record: dict, to: str, kind: str, payload: dict, **updates) -> dict:
        return self.store.transition(record['agent_id'], {record['state']}, to, kind,
                                     payload, **updates)

    def _note(self, agent_id: str, kind: str, payload: dict, **updates) -> None:
        """Column update + event for high-frequency provider traffic. Column
        writes always apply; the chained event is emitted only while the
        agent is under its per-agent event budget (lifecycle transitions are
        emitted unconditionally elsewhere — they are structurally bounded)."""
        record = self.store.maybe_get(agent_id)
        if record is None:
            return
        emit = record['events_seen'] < self.limits['max_events_per_agent']
        try:
            self.store.update_fields(agent_id, kind if emit else '', payload, **updates)
        except Rejected:
            pass

    def _install_live(self, agent_id: str, thread_id: str | None = None) -> _Live:
        with self.cond:
            self._live_generation += 1
            live = _Live(self._live_generation)
            live.thread_id = thread_id
            self.live[agent_id] = live
            self.cond.notify_all()
            return live

    def _bind_live_session(self, agent_id: str, live: _Live, session: Session) -> bool:
        with self.cond:
            if self.live.get(agent_id) is not live:
                return False
            live.session = session
            live.starting = False
            self.cond.notify_all()
            return True

    def _pop_live(self, agent_id: str, expected: _Live | None = None) -> _Live | None:
        with self.cond:
            current = self.live.get(agent_id)
            if expected is not None and current is not expected:
                return None
            live = self.live.pop(agent_id, None)
            if live is not None:
                live.starting = False
                self.cond.notify_all()
            return live

    def _require_current_live(self, agent_id: str, live: _Live) -> None:
        with self.lock:
            require(self.live.get(agent_id) is live, 'PROVIDER_REPLACED',
                    'Provider session was superseded by a newer generation')

    def _admit(self, parent: dict | None, profile: Profile | None) -> None:
        # Every row in a LIVE state holds a concurrency slot — including
        # queued, since create+STARTING now commit under this same lock.
        live = self.store.live_agents()
        if len(live) >= self.limits['max_concurrent']:
            raise Rejected('BUSY', {'max_concurrent': self.limits['max_concurrent']})
        now = time.monotonic()
        while self._spawn_times and now - self._spawn_times[0] > 60:
            self._spawn_times.popleft()
        need(len(self._spawn_times) < self.limits['spawn_per_minute'], 'RATE_LIMIT')
        self._spawn_times.append(now)
        need(self.store.stats()['total'] < self.limits['max_records'], 'AGENT_CAPACITY')

    def _ensure_session(self, record: dict) -> Session:
        agent_id = record['agent_id']
        deadline = time.monotonic() + self.limits['startup_timeout_s']
        while True:
            with self.cond:
                current = self.live.get(agent_id)
                if current is not None and current.session is not None                         and current.session.alive():
                    return current.session
                if current is not None and current.starting:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ControlError('PROVIDER_START_TIMEOUT',
                                           'Timed out waiting for provider session startup')
                    self.cond.wait(min(0.25, remaining))
                    continue
                live = self._install_live(
                    agent_id, (record.get('provider_state') or {}).get('thread_id'))
                break

        try:
            session = self._spawn_session(record, live, thread_id=live.thread_id)
            if not self._bind_live_session(agent_id, live, session):
                session.kill()
                raise ControlError('PROVIDER_REPLACED',
                                   'Provider session was superseded during startup')
            return session
        except BaseException:
            removed = self._pop_live(agent_id, live)
            if removed is not None and removed.session is not None:
                removed.session.kill()
            raise

    def _runtime_bound(self, profile: Profile, args: dict) -> int:
        requested = args.get('timeout_s')
        if requested is not None:
            need(type(requested) is int and 30 <= requested <= profile.max_runtime_s,
                 'INVALID_TIMEOUT')
        return requested or profile.max_runtime_s

    def _policy_binding(self, project: str) -> str:
        try:
            if self.next is not None:
                return self.next.context(project).binding
        except Exception:
            pass
        return digest({'project': project, 'root': str(self.policy.projects[project].root)})

    def _models(self) -> list[dict]:
        if self._models_cache is not None and time.time_ns() - self._models_ns < 300e9:
            return self._models_cache
        exe = self.exe_info()
        scratch = self.policy.state_dir / 'v110' / 'model-probe-home'
        provider_table = read_provider_table(
            Path(self.codex_cfg['auth_home']) / 'config.toml', self.codex_cfg['model_provider'])
        build_home(scratch, auth_source=Path(self.codex_cfg['auth_home']) / 'auth.json',
                   provider_table=provider_table, model=self.codex_cfg['model'],
                   model_provider=self.codex_cfg['model_provider'],
                   sandbox_mode='read_only', model_catalog=self.codex_cfg['model_catalog'],
                   windows_sandbox=self.codex_cfg['windows_sandbox'], shim=None)
        env = child_env()
        env['CODEX_HOME'] = str(scratch)

        def deny(method, params):
            if method == 'account/chatgptAuthTokens/refresh':
                return self._auth_refresh()
            raise DeniedByPolicy(method)

        session = Session('model-probe', exe['path'], scratch, self.policy.state_dir, env,
                          on_event=lambda m: None, on_exit=lambda rc: None, on_request=deny)
        try:
            session.start()
            session.handshake(CLIENT_NAME, timeout=20)
            result = session.request('model/list', {'includeHidden': False, 'limit': 64},
                                     timeout=30)
            models = [{'id': m.get('id'), 'name': m.get('name'),
                       'default': m.get('isDefault'),
                       'efforts': [e.get('reasoningEffort') if isinstance(e, dict) else e
                                   for e in (m.get('supportedReasoningEfforts') or [])]}
                      for m in (result.get('data') or [])[:64]]
            self._models_cache = models
            self._models_ns = time.time_ns()
            return models
        finally:
            session.kill()

    def _summary(self, record: dict, detail: bool = False) -> dict:
        provider = record.get('provider_state') or {}
        data = {'agent_id': record['agent_id'], 'project': record['project'],
                'state': record['state'], 'revision': record['revision'],
                'profile': record['profile'], 'provider': record['provider'],
                'model': record.get('model'), 'depth': record['depth'],
                'parent_agent_id': record.get('parent_agent_id'),
                'created_ns': record['created_ns'], 'updated_ns': record['updated_ns'],
                'terminal_ns': record.get('terminal_ns'),
                'workspace': {'mode': record['workspace_mode'],
                              'root': record['workspace_root'],
                              'managed': bool(record.get('workspace_managed'))},
                'turns_completed': record['turns_completed'],
                'tool_denials': record['tool_denials'],
                'thread_id': provider.get('thread_id'),
                'active_turn_id': record.get('active_turn_id'),
                'has_result': record.get('result') is not None,
                'status_detail': record.get('status_detail') or {}}
        if detail:
            data.update({'task_sha256': record['task_sha256'],
                         'lineage': record.get('lineage'),
                         'dedupe_key': record.get('dedupe_key'),
                         'limits': record.get('limits'),
                         'files_changed': record.get('files_changed'),
                         'token_usage': record.get('token_usage'),
                         'can_delegate': bool(record.get('delegation_token_sha256'))})
        return data

    def _wake(self) -> None:
        with self.cond:
            self.cond.notify_all()

    def health(self) -> dict:
        stats = self.store.stats()
        return {'agents_active': sum(stats['agents_by_state'].get(s, 0) for s in st.LIVE),
                'agents_by_state': stats['agents_by_state'],
                'queued_intents': stats['queued_intents'],
                'agent_chain_ok': stats['chain']['ok'],
                'recovered_at_startup': len(self.recovered),
                'live_sessions': len(self.live)}

    def close(self) -> None:
        self._closed = True
        with self.lock:
            sessions = [(aid, live) for aid, live in self.live.items()
                        if live.session is not None]
        for agent_id, live in sessions:
            removed = self._pop_live(agent_id, live)
            if removed is None:
                continue
            removed.session.kill()
            record = self.store.maybe_get(agent_id)
            if record is not None and record['state'] in st.LIVE - {st.QUEUED}:
                try:
                    self.store.transition(agent_id, {record['state']}, st.INTERRUPTED,
                                          'daemon.shutdown', {}, active_process=0,
                                          active_turn_id=None)
                except Rejected:
                    pass
        self._wake()
        self.store.close()
