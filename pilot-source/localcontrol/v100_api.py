"""LocalControl v1.0 mission runtime API: missions, schedules, verification, recovery.

The model may propose work; it is not the authority, not the resource governor
and not the completion authority. Every mission binds an immutable snapshot of
operator authority and budgets, and completion requires the independent
deterministic verifier.
"""
from __future__ import annotations

import asyncio
import json
import stat
import time
import uuid
from pathlib import Path

from .nextlib.core import Rejected, digest, ident, integer, need, packed, safe_relative
from .v080 import identity as identity_mod
from .v100 import backup as backup_mod
from .v100 import migrate as migrate_mod
from .v100 import telemetry as telemetry_mod
from .v100 import verifier as verifier_mod
from .v100.missions import (ACTIVE_STATES, BUDGET_KEYS, DEFAULT_BUDGETS, NON_TERMINAL,
                            OPTIONAL_BUDGETS, TERMINAL, MissionStore)
from .v100.scheduler import DurableScheduler

VERSION = '1.0.2'
MAX_INCLUDE = 8
INCLUDE_OPTIONS = frozenset({'evidence', 'verification', 'runs', 'jobs', 'budget', 'identity', 'notes'})
OPTION_KEYS = frozenset({'enabled', 'scheduler_interval_s', 'budget_caps', 'telemetry'})
TELEMETRY_OPTION_KEYS = frozenset({'enabled', 'interval_s', 'max_samples'})
DEFAULT_INTERVAL_S = 5
MAX_INTERVAL_S = 300
V100_FIELDS = {
    'mission_begin': {'objective', 'ttl_s', 'watch_paths', 'success_contract', 'budgets', 'request_id',
                      'trust_origin', 'resource_keys', 'dedupe_key', 'supersedes_mission_id', 'supersedes',
                      'supersedes_token', 'takeover'},
    'mission_status': {'mission_id', 'state', 'limit', 'include', 'max_response_bytes'},
    'mission_checkpoint': {'mission_id', 'token', 'expected_revision', 'notes', 'evidence', 'state', 'ttl_s',
                           'request_id', 'generation', 'fence_token'},
    'mission_resume': {'mission_id', 'token', 'accept_divergence', 'ttl_s', 'takeover', 'generation',
                       'fence_token', 'request_id'},
    'mission_finish': {'mission_id', 'token', 'summary', 'generation', 'fence_token', 'request_id'},
    'mission_cancel': {'mission_id', 'token', 'reason', 'abandon', 'takeover', 'request_id',
                       'generation', 'fence_token'},
    'mission_schedule': {'action', 'schedule_id', 'objective', 'ttl_s', 'watch_paths', 'success_contract',
                         'budgets', 'delay_s', 'run_at_ns', 'recur_s', 'depends_on', 'max_attempts',
                         'backoff_base_s', 'backoff_max_s', 'deadline_s', 'grace_s', 'state', 'limit',
                         'reason', 'resource_keys', 'dedupe_key', 'supersedes_mission_id', 'supersedes',
                         'request_id'},
    'state_backup': {'action', 'label', 'backup_id', 'limit'},
    'state_restore': {'action', 'backup_id', 'confirm'},
}
MUTATING_TOOLS = frozenset({'mission_begin', 'mission_checkpoint', 'mission_resume', 'mission_finish',
                            'mission_cancel'})


class V100API:
    def __init__(self, policy, principal: str, next_api, config_path: Path, options: dict, *,
                 run_command=None, worker_probe=None, transaction_probe=None, move_probe=None,
                 telemetry_probe=None):
        need(isinstance(options, dict) and set(options) <= OPTION_KEYS, 'V100_CONFIG')
        need(options.get('enabled') is True, 'V100_CONFIG')
        ident(principal)
        self.policy, self.principal, self.next = policy, principal, next_api
        self.config_path = Path(config_path)
        interval = options.get('scheduler_interval_s', DEFAULT_INTERVAL_S)
        need(type(interval) is int and 1 <= interval <= MAX_INTERVAL_S, 'V100_CONFIG')
        self.interval_s = interval
        caps = options.get('budget_caps', {})
        need(isinstance(caps, dict) and set(caps) <= set(DEFAULT_BUDGETS), 'V100_CONFIG')
        self.budget_caps = {**DEFAULT_BUDGETS, **{k: v for k, v in caps.items()}}
        for key, value in self.budget_caps.items():
            need(type(value) is int and value >= 1, 'V100_CONFIG')
        self.run_command = run_command
        self.worker_probe = worker_probe
        self.transaction_probe = transaction_probe
        self.move_probe = move_probe
        self.state_dir = policy.state_dir
        self.backup_root = self.state_dir / 'v100' / 'backups'
        self.migration = migrate_mod.initialize(self.state_dir)
        self.store = MissionStore(self.state_dir, 'runtime-' + uuid.uuid4().hex[:16])
        self.scheduler = DurableScheduler(self.store)
        self.recovered = self.store.recover()
        self.started_ns = time.time_ns()
        self._scheduler_stop = None
        self.last_scheduler_error = None
        self.recovery_reconciled = self.store.reconcile_recovering(
            identity_probe=self._identity_probe, policy_probe=self._policy_probe,
            worker_probe=self.worker_probe, transaction_probe=self.transaction_probe,
            move_probe=self.move_probe)
        telemetry = options.get('telemetry') or {}
        need(isinstance(telemetry, dict) and set(telemetry) <= TELEMETRY_OPTION_KEYS,
             'V100_CONFIG')
        self.telemetry = None
        if telemetry.get('enabled', True):
            self.telemetry = telemetry_mod.TelemetrySampler(
                self.state_dir, interval_s=telemetry.get('interval_s', 60),
                max_samples=telemetry.get('max_samples', 1440),
                collect=lambda: self._telemetry_collect(telemetry_probe))
            self.telemetry.start()

    def _telemetry_collect(self, host_probe) -> dict:
        """One bounded derived-telemetry sample. Every source is isolated so a
        failing probe degrades that field to 'unknown', never kills sampling."""
        stats = self.store.stats()
        payload = {
            'v100_version': VERSION,
            'runtime_instance': self.store.runtime_instance,
            'missions_by_state': stats['by_state'],
            'mission_events': stats['events'],
            'mission_chain_entries': stats['chain'].get('entries'),
            'recovery_pending': stats['recovery']['pending'],
            'recovery_awaiting_owner': stats['recovery']['awaiting_owner'],
            'scheduler_error': self.last_scheduler_error is not None,
            'fences_active': stats['fences'].get('ACTIVE', 0),
        }
        if host_probe is not None:
            try:
                probe = host_probe()
                if isinstance(probe, dict):
                    payload.update(probe)
            except Exception:
                payload['host_probe'] = 'unknown'
        return payload

    def close(self) -> None:
        if self.telemetry is not None:
            self.telemetry.close()
        self.store.close()

    def wire(self, run_command) -> None:
        self.run_command = run_command

    def _identity_probe(self, mission: dict) -> dict:
        with self.store.lock:
            raw = self.store.db.execute(
                'SELECT workspace_identity_json,policy_snapshot_json FROM missions WHERE mission_id=?',
                (mission['mission_id'],)).fetchone()
        if raw is None:
            return {'classification': 'missing'}
        saved = json.loads(raw['workspace_identity_json'])
        snapshot = json.loads(raw['policy_snapshot_json'])
        current = identity_mod.build_identity(self.policy, mission['project'],
                                               snapshot.get('watch_paths', []))
        return identity_mod.classify(saved, current)

    def _policy_probe(self, mission: dict) -> dict:
        return {'classification': 'same' if
                self.next.context(mission['project']).binding == mission['policy_binding']
                else 'changed'}

    # ---------- helpers ----------

    def _snapshot(self, project: str, watch_paths: list[str]) -> dict:
        context = self.next.context(project)
        spec = self.policy.projects[project]
        return {'binding': context.binding, 'project': project, 'root': str(spec.root),
                'workspace_root': str(spec.root),
                'writable': context.writable, 'exec_mode': context.execution_mode,
                'security_sandbox': context.security_sandbox,
                'exclusive_workspace': context.exclusive_workspace,
                'allowed_tools': sorted(context.allowed_tools),
                'recipes': sorted(getattr(self.policy, 'recipes', {}) or {}),
                'max_file_bytes': getattr(self.policy, 'max_file_bytes', None),
                'max_wait_ms': getattr(self.policy, 'max_wait_ms', None),
                'max_timeout_ms': getattr(self.policy, 'max_timeout_ms', None),
                'watch_paths': list(watch_paths)}

    def _limits(self, requested: dict | None) -> dict:
        need(requested is None or isinstance(requested, dict), 'INVALID_BUDGETS')
        need(not (requested or {}) or set(requested) <= set(BUDGET_KEYS), 'INVALID_BUDGETS')
        merged = {}
        for key, hard in self.budget_caps.items():
            value = (requested or {}).get(key, min(hard, DEFAULT_BUDGETS[key]))
            need(type(value) is int and 1 <= value <= hard, 'INVALID_BUDGETS')
            merged[key] = value
        for key, hard in OPTIONAL_BUDGETS.items():
            value = (requested or {}).get(key)
            need(value is None or (type(value) is int and 1 <= value <= hard), 'INVALID_BUDGETS')
            merged[key] = value
        if merged['max_deadline_ms'] is not None and 'max_wall_ms' not in (requested or {}):
            # Declared deadline supersedes the default legacy elapsed wall cap;
            # an explicit max_wall_ms still applies alongside the deadline.
            merged['max_wall_ms'] = None
        return merged

    def _validate_watch(self, watch_paths) -> list[str]:
        need(watch_paths is None or (isinstance(watch_paths, list) and len(watch_paths) <= 32), 'INVALID_WATCH_PATHS')
        return [safe_relative(p) for p in (watch_paths or [])]

    def _mission(self, mission_id: str) -> dict:
        ident(mission_id)
        return self.store.get(mission_id)

    # ---------- budget hooks used by the facade ----------

    def precheck(self, project: str, tool: str, mission_id: str, *,
                 generation: int | None = None, fence_token: str | None = None) -> dict:
        mission = self.store.get(mission_id, notes=False)
        need(mission['project'] == project, 'MISSION_PROJECT_MISMATCH')
        need(mission['state'] in {'READY', 'RUNNING', 'WAITING'}, 'MISSION_NOT_ACTIVE')
        self.store.assert_generation(mission_id, generation, fence_token)
        budget = self.store.budget_state(mission_id)
        limits = budget['budgets']
        if tool == 'exec':
            need(budget['jobs'] < limits['max_jobs'], 'BUDGET_JOBS')
        if tool in ('transaction_plan', 'transaction_apply'):
            need(budget['transactions'] < limits['max_transactions'], 'BUDGET_TRANSACTIONS')
        elapsed_ms = int((time.time_ns() - mission['created_ns']) / 1_000_000)
        need(elapsed_ms <= self._elapsed_cap_ms(limits), 'BUDGET_WALL')
        if limits.get('max_active_ms') is not None:
            active_ns = mission['active_ns'] or 0
            if mission['state'] in ACTIVE_STATES and mission['state_since_ns']:
                active_ns += max(0, time.time_ns() - mission['state_since_ns'])
            need(active_ns // 1_000_000 <= limits['max_active_ms'], 'BUDGET_ACTIVE')
        self.store.charge_tool_call(mission_id, max_calls=limits['max_tool_calls'])
        return mission

    def note_job(self, project: str, mission_id: str, job_id: str, output_bytes: int = 0) -> None:
        mission = self.store.get(mission_id, notes=False)
        need(mission['project'] == project, 'MISSION_PROJECT_MISMATCH')
        self.store.bind(mission_id, job_id=job_id, output_bytes=output_bytes)

    def note_transaction(self, project: str, mission_id: str, transaction_id: str) -> None:
        mission = self.store.get(mission_id, notes=False)
        need(mission['project'] == project, 'MISSION_PROJECT_MISMATCH')
        self.store.bind(mission_id, transaction_id=transaction_id)

    def note_output(self, project: str, mission_id: str, output_bytes: int) -> None:
        mission = self.store.get(mission_id, notes=False)
        need(mission['project'] == project, 'MISSION_PROJECT_MISMATCH')
        self.store.bind(mission_id, output_bytes=max(0, min(int(output_bytes), 1 << 30)))

    def _elapsed_cap_ms(self, limits: dict) -> int:
        # Every declared elapsed bound applies; an explicit max_wall_ms caps
        # alongside a declared deadline rather than being replaced by it.
        caps = [v for v in (limits.get('max_deadline_ms'), limits.get('max_wall_ms'))
                if v is not None]
        return min(caps)

    def job_limits(self, mission_id: str) -> dict:
        mission = self.store.get(mission_id, notes=False)
        limits = mission['budgets']
        cap = self._elapsed_cap_ms(limits)
        remaining = max(1, cap - int((time.time_ns() - mission['created_ns']) / 1_000_000))
        return {'memory_bytes': limits['max_job_memory_bytes'],
                'max_processes': limits['max_job_processes'],
                'cpu_ms': limits['max_job_cpu_ms'],
                'max_timeout_ms': min(cap, remaining)}

    def remaining_wall_ms(self, mission_id: str) -> int:
        mission = self.store.get(mission_id, notes=False)
        cap = self._elapsed_cap_ms(mission['budgets'])
        return cap - int((time.time_ns() - mission['created_ns']) / 1_000_000)

    # ---------- tool handlers ----------

    async def call(self, tool: str, project, args: dict):
        return await asyncio.to_thread(self._call_sync, tool, project, args)

    def _call_sync(self, tool: str, project, args: dict):
        scoped = project if project not in ('', '*') else None
        handlers = {
            'mission_begin': lambda: self.mission_begin(project, args),
            'mission_status': lambda: self.mission_status(scoped, args),
            'mission_checkpoint': lambda: self.mission_checkpoint(project, args),
            'mission_resume': lambda: self.mission_resume(project, args),
            'mission_finish': lambda: self.mission_finish(project, args),
            'mission_cancel': lambda: self.mission_cancel(project, args),
            'mission_schedule': lambda: self.mission_schedule(scoped, args),
            'state_backup': lambda: self.state_backup(scoped, args),
            'state_restore': lambda: self.state_restore(scoped, args),
        }
        handler = handlers.get(tool)
        need(handler is not None, 'INVALID_ARGUMENT')
        return handler()

    def mission_begin(self, project: str, args: dict) -> dict:
        objective = args.get('objective')
        request_id = args.get('request_id')
        need(isinstance(request_id, str) and request_id, 'INVALID_REQUEST_ID')
        watch = self._validate_watch(args.get('watch_paths'))
        contract = verifier_mod.validate_contract(args.get('success_contract') or {})
        budgets = self._limits(args.get('budgets'))
        ttl = args.get('ttl_s', 3600)
        need(type(ttl) is int and 30 <= ttl <= 86400, 'INVALID_TTL')
        trust_origin = args.get('trust_origin', 'model')
        snapshot = self._snapshot(project, watch)
        identity = identity_mod.build_identity(self.policy, project, watch)
        result = self.store.begin(project=project, objective=objective, workspace_root=str(self.policy.projects[project].root),
                                  workspace_identity=identity, policy_binding=snapshot['binding'],
                                  policy_snapshot=snapshot, success_contract=contract, budgets=budgets,
                                  ttl_s=ttl, request_id=request_id, trust_origin=trust_origin,
                                  resource_keys=args.get('resource_keys'),
                                  dedupe_key=args.get('dedupe_key'),
                                  supersedes_mission_id=args.get('supersedes_mission_id',
                                                                  args.get('supersedes')),
                                  supersedes_token=args.get('supersedes_token'),
                                  takeover=args.get('takeover') is True)
        result['workspace_identity_sha256'] = identity.get('digest')
        result['budget_caps'] = self.budget_caps
        return result

    def mission_status(self, project: str | None, args: dict) -> dict:
        include = args.get('include') or []
        need(isinstance(include, list) and len(include) <= MAX_INCLUDE and set(include) <= INCLUDE_OPTIONS,
             'INVALID_INCLUDE')
        mission_id = args.get('mission_id')
        if mission_id:
            mission = self._mission(mission_id)
            out = {k: v for k, v in mission.items() if k not in ('evidence', 'policy_snapshot', 'workspace_identity')}
            if 'evidence' in include:
                out['evidence'] = mission['evidence']
            if 'verification' in include:
                out['verification'] = mission['verification']
            if 'identity' in include:
                out['workspace_identity'] = mission['workspace_identity']
                out['policy_snapshot'] = mission['policy_snapshot']
            out['chain_ok'] = self.store.chain_status().get('ok')
            return out
        state = args.get('state')
        if state is not None and state not in (NON_TERMINAL | TERMINAL):
            raise Rejected('INVALID_STATE')
        return {'missions': self.store.list_missions(project=project, state=state, limit=args.get('limit', 50)),
                'schedules': self.scheduler.list(project=project, limit=min(args.get('limit', 50), 50)),
                'stats': self.store.stats()}

    def mission_checkpoint(self, project: str, args: dict) -> dict:
        mission_id = args.get('mission_id')
        need(isinstance(mission_id, str) and mission_id, 'INVALID_MISSION_ID')
        token = args.get('token')
        request_id = args.get('request_id')
        need(isinstance(request_id, str) and request_id, 'INVALID_REQUEST_ID')
        scope = 'mission:' + mission_id
        input_sha = digest({'tool': 'mission_checkpoint', 'mission': mission_id, 'project': project,
                            'notes': args.get('notes'), 'evidence': args.get('evidence'),
                            'state': args.get('state'), 'expected_revision': args.get('expected_revision'),
                            'ttl_s': args.get('ttl_s'), 'generation': args.get('generation'),
                            'fence_token': args.get('fence_token')})
        ttl = args.get('ttl_s', 3600)
        need(type(ttl) is int and 30 <= ttl <= 86400, 'INVALID_TTL')
        mission = self._mission(mission_id)
        need(mission['project'] == project, 'MISSION_PROJECT_MISMATCH')
        replayed = self.store.request_replay(scope, request_id, 'mission_checkpoint', input_sha)
        if replayed is not None:
            return {**replayed, 'replayed': True}
        result = self.store.checkpoint(mission_id, token=token, expected_revision=args.get('expected_revision'),
                                       notes=args.get('notes'), evidence=args.get('evidence'),
                                       state=args.get('state'), ttl_s=ttl,
                                       generation=args.get('generation'),
                                       fence_token=args.get('fence_token'))
        result['mission_id'] = mission_id
        with self.store.lock:
            self.store._record_request(scope, request_id, 'mission_checkpoint', mission_id, input_sha, result)
            self.store.db.commit()
        return result

    def mission_resume(self, project: str, args: dict) -> dict:
        mission_id = args.get('mission_id')
        need(isinstance(mission_id, str) and mission_id, 'INVALID_MISSION_ID')
        request_id = args.get('request_id')
        need(isinstance(request_id, str) and request_id, 'INVALID_REQUEST_ID')
        scope = 'mission:' + mission_id
        input_sha = digest({'tool': 'mission_resume', 'mission': mission_id, 'project': project,
                            'accept_divergence': args.get('accept_divergence'), 'ttl_s': args.get('ttl_s'),
                            'takeover': args.get('takeover'), 'generation': args.get('generation'),
                            'fence_token': args.get('fence_token')})
        ttl = args.get('ttl_s', 3600)
        need(type(ttl) is int and 30 <= ttl <= 86400, 'INVALID_TTL')
        mission = self._mission(mission_id)
        need(mission['project'] == project, 'MISSION_PROJECT_MISMATCH')
        replayed = self.store.request_replay(scope, request_id, 'mission_resume', input_sha)
        if replayed is not None:
            return {**replayed, 'replayed': True}
        need(mission['state'] in ('RECOVERING', 'WAITING', 'BLOCKED'), 'STATE_MISMATCH')
        need(self.next.context(project).binding == mission['policy_binding'], 'AUTHORITY_CHANGED')
        current = identity_mod.build_identity(self.policy, project, mission['policy_snapshot'].get('watch_paths', []))
        classification = identity_mod.classify(mission['workspace_identity'], current)
        accepted = args.get('accept_divergence')
        if classification['classification'] != 'same':
            need(isinstance(accepted, str) and accepted == classification['classification'], 'DIVERGENCE_NOT_ACCEPTED')
        result = self.store.resume(
            mission_id, expect=mission['state'], ttl_s=ttl, token=args.get('token'),
            allow_stale=(mission['state'] == 'RECOVERING' or args.get('takeover') is True),
            takeover=(args.get('takeover') is True),
            generation=args.get('generation'), fence_token=args.get('fence_token'),
            classification=classification['classification'],
            differences=classification['differences'],
            workspace_identity=current)
        with self.store.lock:
            self.store._record_request(scope, request_id, 'mission_resume', mission_id, input_sha, result)
            self.store.db.commit()
        return result

    def mission_finish(self, project: str, args: dict) -> dict:
        mission_id = args.get('mission_id')
        need(isinstance(mission_id, str) and mission_id, 'INVALID_MISSION_ID')
        request_id = args.get('request_id')
        need(isinstance(request_id, str) and request_id, 'INVALID_REQUEST_ID')
        summary = args.get('summary')
        need(summary is None or (isinstance(summary, str) and len(summary) <= 2048), 'INVALID_SUMMARY')
        token = args.get('token')
        need(isinstance(token, str) and token, 'MISSION_TOKEN_INVALID')
        scope = 'mission:' + mission_id
        input_sha = digest({'tool': 'mission_finish', 'mission': mission_id, 'project': project,
                            'summary': summary})
        mission = self._mission(mission_id)
        need(mission['project'] == project, 'MISSION_PROJECT_MISMATCH')
        replayed = self.store.request_replay(scope, request_id, 'mission_finish', input_sha)
        if replayed is not None:
            return {**replayed, 'replayed': True}
        need(mission['state'] in ('RUNNING', 'WAITING', 'BLOCKED'), 'STATE_MISMATCH')
        verifying = self.store.transition(mission_id, mission['state'], 'VERIFYING', 'verification_requested',
                                           {'summary': summary}, token=args.get('token'),
                                           generation=args.get('generation'),
                                           fence_token=args.get('fence_token'))
        need(self.run_command is not None, 'VERIFIER_UNAVAILABLE')
        current_identity = identity_mod.build_identity(self.policy, project,
                                                       mission['policy_snapshot'].get('watch_paths', []))
        current_binding = self.next.context(project).binding

        def read_sha(rel: str):
            # Tri-state: True = hashed, False = genuinely absent, None = error
            # (denied path, vanished mid-check, unreadable). Gates must treat
            # None as fail-closed, never as absent.
            try:
                path = self.policy.path(project, rel)
            except Exception:
                return None, None, None
            try:
                st = path.stat()
            except FileNotFoundError:
                return False, None, None
            except OSError:
                return None, None, None
            if not stat.S_ISREG(st.st_mode):
                # A non-regular object (directory, fifo, symlink-to-dir) at
                # the path is inconclusive, not absent: a forbidden-files
                # gate must not pass on '.git/' being a directory.
                return None, None, None
            try:
                import hashlib
                h = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1 << 20), b''):
                        h.update(chunk)
                return True, h.hexdigest(), st.st_size
            except OSError:
                return None, None, None

        def run_command(spec: dict) -> dict:
            budget = self.store.budget_state(mission_id)
            if budget['jobs'] >= mission['budgets']['max_jobs']:
                return {'ok': False, 'error': 'BUDGET_JOBS'}
            return self.run_command(project, spec)

        record = verifier_mod.measure(mission=mission, chain_ok=self.store.verify_chain().get('ok', False),
                                      current_identity=current_identity, current_binding=current_binding,
                                      read_sha=read_sha, run_command=run_command,
                                      budget_state=self.store.budget_state(mission_id))
        final = self.store.commit_verification(mission_id, verdict=record['ok'], verification=record,
                                               detail='verification gates failed' if not record['ok'] else None)
        result = {'mission_id': mission_id, 'state': final['state'], 'revision': final['revision'],
                  'verified': record['ok'], 'verification': record,
                  'terminal': final['state'] in TERMINAL}
        with self.store.lock:
            self.store._record_request(scope, request_id, 'mission_finish', mission_id, input_sha, result)
            self.store.db.commit()
        return result

    def mission_cancel(self, project: str, args: dict) -> dict:
        mission_id = args.get('mission_id')
        need(isinstance(mission_id, str) and mission_id, 'INVALID_MISSION_ID')
        mission = self._mission(mission_id)
        need(mission['project'] == project, 'MISSION_PROJECT_MISMATCH')
        takeover = args.get('takeover') is True
        result = self.store.cancel(mission_id, token=args.get('token'), reason=args.get('reason', 'cancelled'),
                                   abandon=args.get('abandon') is True, allow_stale=takeover,
                                   generation=args.get('generation'), fence_token=args.get('fence_token'))
        return {k: result[k] for k in ('mission_id', 'state', 'revision', 'terminal_ns', 'last_error')}

    def mission_schedule(self, project: str, args: dict) -> dict:
        action = args.get('action', 'create')
        need(action in ('create', 'list', 'status', 'cancel'), 'INVALID_ACTION')
        if action == 'list':
            state = args.get('state')
            if state is not None:
                need(state in ('ACTIVE', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED', 'EXPIRED'), 'INVALID_STATE')
            return {'schedules': self.scheduler.list(project=project, state=state, limit=args.get('limit', 50))}
        if action == 'status':
            schedule_id = args.get('schedule_id')
            need(isinstance(schedule_id, str) and schedule_id, 'INVALID_SCHEDULE_ID')
            return self.scheduler.get(schedule_id)
        if action == 'cancel':
            schedule_id = args.get('schedule_id')
            need(isinstance(schedule_id, str) and schedule_id, 'INVALID_SCHEDULE_ID')
            return self.scheduler.cancel(schedule_id, reason=args.get('reason', 'cancelled'))
        objective = args.get('objective')
        request_id = args.get('request_id')
        need(isinstance(request_id, str) and request_id, 'INVALID_REQUEST_ID')
        watch = self._validate_watch(args.get('watch_paths'))
        contract = verifier_mod.validate_contract(args.get('success_contract') or {})
        budgets = self._limits(args.get('budgets'))
        snapshot = self._snapshot(project, watch)
        snapshot['workspace_identity'] = identity_mod.build_identity(self.policy, project, watch)
        deadline_s = args.get('deadline_s')
        deadline_ns = None
        if deadline_s is not None:
            need(type(deadline_s) is int and deadline_s > 0, 'INVALID_DEADLINE')
            deadline_ns = time.time_ns() + deadline_s * 1_000_000_000
        return self.scheduler.create(
            project=project, objective=objective, snapshot=snapshot, contract=contract, budgets=budgets,
            ttl_s=args.get('ttl_s', 3600), watch_paths=watch, run_at_ns=args.get('run_at_ns'),
            delay_s=args.get('delay_s'), recur_s=args.get('recur_s'), depends_on=args.get('depends_on'),
            max_attempts=args.get('max_attempts', 3), backoff_base_s=args.get('backoff_base_s', 30),
            backoff_max_s=args.get('backoff_max_s', 900), deadline_ns=deadline_ns,
            grace_s=args.get('grace_s', 300), request_id=request_id, state='ACTIVE',
            resource_keys=args.get('resource_keys'),
            dedupe_key=args.get('dedupe_key'),
            supersedes_mission_id=args.get('supersedes_mission_id', args.get('supersedes')))

    @staticmethod
    def _backup_id(value) -> str:
        need(isinstance(value, str) and 0 < len(value) <= 128 and '..' not in value
             and all(c.isalnum() or c in '._-' for c in value), 'INVALID_BACKUP_ID')
        return value

    def state_backup(self, project: str | None, args: dict) -> dict:
        action = args.get('action', 'create')
        need(action in ('create', 'list', 'verify', 'pending'), 'INVALID_ACTION')
        if action == 'pending':
            return backup_mod.pending_status(self.state_dir)
        if action == 'list':
            return {'backups': backup_mod.list_backups(self.backup_root, limit=args.get('limit', 20))}
        if action == 'create':
            label = args.get('label', 'manual')
            need(isinstance(label, str) and 0 < len(label) <= 128, 'INVALID_LABEL')
            receipt = backup_mod.create(self.state_dir, self.backup_root, label=label,
                                        metadata={'principal': self.principal, 'policy_binding':
                                                  self.next.context(next(iter(self.policy.projects))).binding})
            return {'ok': receipt['ok'], 'backup_id': receipt['backup_id'], 'file_count': receipt['file_count'],
                    'manifest_sha256': receipt['manifest_sha256'], 'verified_ns': receipt['verified_ns'],
                    'backup_dir': receipt['backup_dir']}
        backup_id = args.get('backup_id')
        backup_id = self._backup_id(backup_id)
        backup_dir = self.backup_root / ('backup-' + backup_id)
        need(backup_dir.is_dir(), 'BACKUP_NOT_FOUND')
        receipt = backup_mod.verify(backup_dir)
        return {'ok': receipt['ok'], 'backup_id': receipt['backup_id'], 'file_count': receipt['file_count'],
                'manifest_sha256': receipt['manifest_sha256'], 'files': receipt['files']}

    def state_restore(self, project: str | None, args: dict) -> dict:
        action = args.get('action', 'stage')
        need(action in ('stage', 'status', 'receipt'), 'INVALID_ACTION')
        if action == 'status':
            return backup_mod.pending_status(self.state_dir)
        if action == 'receipt':
            receipt = backup_mod.restore_receipt(self.state_dir)
            return receipt or {'ok': None, 'note': 'no restore has been applied'}
        backup_id = self._backup_id(args.get('backup_id'))
        confirm = args.get('confirm')
        need(isinstance(confirm, str) and confirm, 'RESTORE_CONFIRM_REQUIRED')
        backup_dir = self.backup_root / ('backup-' + backup_id)
        need(backup_dir.is_dir(), 'BACKUP_NOT_FOUND')
        return backup_mod.stage_restore(self.state_dir, backup_dir, confirm=confirm)

    # ---------- scheduler ----------

    def scheduler_tick(self) -> dict:
        try:
            self.recovery_reconciled = self.store.reconcile_recovering(
                identity_probe=self._identity_probe, policy_probe=self._policy_probe,
                worker_probe=self.worker_probe, transaction_probe=self.transaction_probe,
                move_probe=self.move_probe)
            result = self.scheduler.tick()
            result['recovery'] = self.recovery_reconciled
            self.last_scheduler_error = None
            return result
        except Exception as exc:
            self.last_scheduler_error = f'{type(exc).__name__}'
            raise

    async def scheduler_loop(self, stop_event: asyncio.Event | None = None) -> None:
        while True:
            await asyncio.sleep(self.interval_s)
            if stop_event is not None and stop_event.is_set():
                return
            try:
                self.scheduler_tick()
            except Exception:
                continue

    def health(self) -> dict:
        stats = self.store.stats()
        migration = self.migration
        backups = backup_mod.list_backups(self.backup_root, limit=1)
        telemetry = self.telemetry.status() if self.telemetry is not None else {
            'state': 'disabled', 'samples': 0}
        return {'version': VERSION, 'missions': stats['missions'], 'missions_by_state': stats['by_state'],
                'mission_events': stats['events'], 'mission_chain_ok': stats['chain']['ok'],
                'recovered_at_startup': len(self.recovered), 'recovery_reconciled': self.recovery_reconciled,
                'recovery': stats.get('recovery'), 'fences': stats.get('fences'),
                'scheduler_error': self.last_scheduler_error,
                'backup_readiness': {'migration_backup_id': migration.get('pre_migration_backup_id'),
                                     'latest_verified': bool(backups and backups[0].get('ok') is True)},
                'migration': {'from': migration.get('from_version'), 'to': migration.get('to_version'),
                              'ok': migration.get('ok'), 'idempotent': migration.get('idempotent')},
                'restore': backup_mod.pending_status(self.state_dir),
                'telemetry': telemetry}



