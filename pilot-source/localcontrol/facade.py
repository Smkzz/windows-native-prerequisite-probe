from __future__ import annotations
import asyncio
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
from . import __version__ as SERVER_VERSION
from . import protocol
from .errors import ControlError, require
from .jobs import JobManager
from .next_api import NextAPI, EXPOSED_TOOLS, EXTENSION_VERSION
from .nextlib.core import Rejected, packed
from .policy import Policy
from . import shells
from .store import Store, digest
from .v060.core import Rejected as V060Rejected
from .v060_api import V060API, V060_FIELDS, MUTATING_TOOLS as V060_MUTATING_TOOLS, VERSION as V060_VERSION
from .v080_api import V080API, V080_FIELDS, MUTATING_TOOLS as V080_MUTATING_TOOLS, VERSION as V080_VERSION
from .v100_api import V100API, V100_FIELDS, MUTATING_TOOLS as V100_MUTATING_TOOLS, VERSION as V100_VERSION
from .v110_api import V110API, V110_FIELDS, MUTATING_TOOLS as V110_MUTATING_TOOLS, VERSION as V110_VERSION
from .v120_api import V120API, V120_FIELDS, MUTATING_TOOLS as V120_MUTATING_TOOLS, VERSION as V120_VERSION

MUTATIONS = frozenset({'exec', 'job_input', 'job_stop', 'archive_terminal_jobs',
                       'file_write', 'file_patch', 'file_delete'})
BOOTSTRAP_TOOL = 'localcontrol_context'
TRANSACTION_TOOLS = frozenset({'transaction_plan', 'transaction_apply', 'transaction_status',
                               'transaction_reconcile', 'transaction_rollback'})
TRANSACTION_FILE_MUTATIONS = frozenset({'transaction_apply', 'transaction_reconcile', 'transaction_rollback'})
# Omitted project -> catalog/global scope. These tools are safe before a client
# knows any project identifier and remain explicit-scope when one is supplied.
GLOBAL_DEFAULT_TOOLS = frozenset({'system_info', 'workspace_catalog', 'collection_inventory',
                                  'project_discovery_candidates', 'health_status', 'usage_summary',
                                  'maintenance_begin', 'maintenance_end', 'project_move_plan',
                                  'project_move_apply', 'project_move_status', 'project_move_reconcile',
                                  'project_move_rollback', 'telemetry_summary', 'mission_status',
                                  'state_backup', 'state_restore',
                                  'agent_list', 'agent_capabilities'})
FIELDS = {
 'localcontrol_context': {'include', 'max_response_bytes'},
 'system_info': set(),
 'file_read': {'path','offset','length'},
 'file_write': {'path','content','expected_sha256','request_id'},
 'file_patch': {'path','old','new','expected_count','expected_sha256','request_id','dry_run'},
 'file_delete': {'path','expected_sha256','request_id'},
 'file_search': {'path','query','max_files','max_matches'},
 'file_list': {'path','limit'},
 'exec': {'argv','recipe','wait_ms','timeout_ms','request_id','mission_id','generation','fence_token'},
 'job_read': {'job_id','wait_ms','view'},
 'job_input': {'job_id','text','eof','request_id'},
 'job_stop': {'job_id','request_id'},
 'archive_terminal_jobs': {'request_id'},
 'process_list': set(),
 'capabilities': {'client_observed'},
 'read_batch': {'requests','max_response_bytes'},
 'job_delta': {'job_id','cursor','max_bytes','wait_ms'},
 'efficiency_metrics': set(),
 'task_begin': {'task','paths'},
 'task_create_file': {'task','op','path','content'},
 'task_handoff': {'task','limit','after_sequence','snapshot_max_sequence','max_response_bytes','include'},
 'task_checkpoint': {'task','expected_revision','notes'},
}
# Static short hints for the codes an agent most often needs to recover from.
ERROR_HINTS = {
 'PROJECT_REQUIRED': 'Call localcontrol_context, then pass an authorized project name.',
 'UNKNOWN_PROJECT': 'Call localcontrol_context to list authorized projects.',
 'CATALOG_SCOPE_REQUIRED': 'This is a global tool: omit project or call localcontrol_context first.',
 'CONFLICT': 'Re-read the file and retry with the currently observed sha256.',
 'NOT_FOUND': 'Check file_list or read_batch stat before reading or editing this path.',
 'FILE_LIMIT': 'Use a smaller bounded range or split the change into bounded transactions.',
 'INVALID_PATH': 'Use a project-relative path without dot-dot or absolute segments.',
 'PRECONDITION_REQUIRED': 'Supply the sha256 observed from file_read or read_batch.',
 'MAINTENANCE_ACTIVE': 'A maintenance lease is active; retry after maintenance_end.',
 'UNRESOLVED_MOVE': 'Reconcile the unresolved move before mutating this scope.',
 'STALE_PLAN': 'Re-plan; the guarded state changed since planning.',
 'INDETERMINATE': 'Inspect durable state first; do not blindly retry the side effect.',
 'TRANSACTION_ROLLED_BACK': 'No files changed; inspect details.failed_code and re-plan.',
 'TRANSACTION_INDETERMINATE': 'Call transaction_reconcile; operator review may be required.',
 'TRANSACTION_NEEDS_RECONCILE': 'Call transaction_reconcile to resolve durable state.',
 'DRIFT_DETECTED': 'Files changed after apply; inspect transaction_status before repair.',
 'ALREADY_APPLIED': 'The transaction already committed; inspect transaction_status.',
 'IDEMPOTENCY_CONFLICT': 'A request ID was reused with different input; use a fresh request ID.',
 'JOB_CAPACITY': 'Only active and retained terminal records count; retry after safe terminal reclamation or inspect the bounded capacity details.',
 'QUEUE_FULL': 'Execution backpressure queue is full; wait for queued work to drain before retrying.',
 'JOB_NOT_RUNNING': 'The job is queued or starting; use job_read until status becomes running before sending stdin.',
 'OUTPUT_REPLACED': 'Job output was restarted; drop the cursor and use job_read view=summary.',
 'INVALID_CURSOR': 'Cursors are scoped and expiring; re-read state to obtain a fresh cursor.',
 'TASK_CLOSED': 'The task is no longer active; begin a new task.',
 'AGENT_NOT_FOUND': 'Check agent_list for agents owned by this project scope.',
 'STATE_MISMATCH': 'Inspect agent_status; agents only accept operations valid for their state.',
 'RESUME_REQUIRED': 'The provider session was lost; call agent_resume before sending input.',
 'BUSY': 'Concurrent agent limit reached; wait or cancel an active agent.',
 'RATE_LIMIT': 'Spawn rate limit reached; retry after a minute.',
 'DEPTH_LIMIT': 'Delegation depth cap reached for this lineage.',
 'CHILD_LIMIT': 'This agent already has the maximum number of children.',
 'TURN_LIMIT': 'This agent has used its per-life turn budget.',
 'PROFILE_DENIED': 'A delegated child may only claim the parent profile or its delegate_profile.',
 'DEDUPE_CONFLICT': 'dedupe_key already exists; use agent_status/agent_result on the returned agent.',
 'PROVIDER_UNAVAILABLE': 'No usable codex executable found; see agent_capabilities.',
 'PROVIDER_UNSUPPORTED': 'Installed codex is below the supported floor; upgrade the provider.',
 'SANDBOX_UNAVAILABLE': 'The required OS sandbox is not ready; check windowsSandbox readiness.',
 'PYTHON_LAUNCHER_UNSUPPORTED': 'Use capabilities(project=...) or localcontrol_context to get the manifest-bound AppContainer Python executable.',
 'DELEGATION_DENIED': 'This agent has no delegation rights or its token was revoked.',
 'DELEGATION_SCOPE': 'Agents may only control agents inside their own delegation subtree.',
 'AUTHORITY_CHANGED': 'Operator policy changed since the record was bound; reconcile first.',
}


class Facade:
    def __init__(self, policy: Policy, backend, principal: str = 'local-owner', *,
                 v060_options: dict | None = None, v080_options: dict | None = None,
                 v100_options: dict | None = None, v110_options: dict | None = None,
                 v120_options: dict | None = None, config_path: Path | None = None):
        self.policy, self.backend = policy, backend
        self.principal = principal  # Operator/transport identity, never a tool argument.
        self.fields = {name:set(value) for name,value in FIELDS.items()}
        self.store = Store(policy.state_dir, policy.max_requests, policy.max_audit_rows,
                           audit_reserve_margin=policy.audit_reserve_margin)
        try:
            self.jobs = JobManager(policy, self.store)
            # Resolved once at startup: a bad shell pin is a boot-time config
            # failure, never a per-call surprise.
            self._exec_surface = shells.surface(policy)
        except BaseException:
            self.store.close()
            raise
        self.locks = {k: asyncio.Lock() for k in policy.projects}
        self.mutation_gate = asyncio.Lock()
        self._inside_mutation_gate = ContextVar('localcontrol_inside_mutation_gate', default=False)
        self._internal_depth = ContextVar('localcontrol_internal_depth', default=0)
        self._metrics_lock = threading.RLock()
        self._metrics = {'calls': 0, 'errors': 0, 'bytes': 0, 'by_tool': {}, 'since_ns': time.time_ns()}
        self.v060 = None
        self.v080 = None
        self.v100 = None
        self.v110 = None
        self.v120 = None
        try:
            self.next = NextAPI(policy, self.principal, self._call_base)
            if v060_options is not None:
                require(config_path is not None, 'V060_CONFIG', 'v0.6 requires the operator config path')
                protected=tuple(str(x) for x in (getattr(backend,'node',None),getattr(backend,'entry',None)) if x)
                self.v060 = V060API(policy, self.principal, self.next, config_path, v060_options,
                                    active_jobs=self.store.jobs, current_health=self._current_health,
                                    protected_paths=protected)
                self.fields.update({name:set(value) for name,value in V060_FIELDS.items()})
                self.next.environment = self._environment_snapshot
            if v080_options is not None:
                require(config_path is not None, 'V080_CONFIG', 'v0.8 requires the operator config path')
                self.v080 = V080API(policy, self.principal, self.next, config_path, v080_options)
                self.fields.update({name:set(value) for name,value in V080_FIELDS.items()})
            if v100_options is not None:
                require(self.v080 is not None, 'V100_CONFIG', 'v1.0 requires the v0.8 supervision family')
                require(config_path is not None, 'V100_CONFIG', 'v1.0 requires the operator config path')
                self.v100 = V100API(policy, self.principal, self.next, config_path, v100_options,
                                    run_command=self._v100_run_command,
                                    worker_probe=self._v100_worker_probe,
                                    transaction_probe=self._v100_transaction_probe,
                                    move_probe=self._v100_move_probe,
                                    telemetry_probe=self._telemetry_probe)
                self.fields.update({name:set(value) for name,value in V100_FIELDS.items()})
            if v110_options is not None:
                require(self.v100 is not None, 'V110_CONFIG', 'v1.1 requires the v1.0 autonomy family')
                require(config_path is not None, 'V110_CONFIG', 'v1.1 requires the operator config path')
                self.v110 = V110API(policy, self.principal, self.next, config_path, v110_options)
                self.fields.update({name:set(value) for name,value in V110_FIELDS.items()})
            if v120_options is not None:
                require(self.v060 is not None, 'V120_CONFIG', 'v1.2 requires the v0.6 signed registry')
                require(config_path is not None, 'V120_CONFIG', 'v1.2 requires the operator config path')
                self.v120 = V120API(policy, self.principal, config_path, v120_options,
                                    registry_store=self.v060.registry,
                                    registry_key=self.v060.registry.codec.key,
                                    admission=self.jobs)
                self.fields.update({name:set(value) for name,value in V120_FIELDS.items()})
        except BaseException:
            if self.v060 is not None:
                self.v060.close()
            if self.v080 is not None:
                self.v080.close()
            if self.v100 is not None:
                self.v100.close()
            if self.v110 is not None:
                self.v110.close()
            if self.v120 is not None:
                self.v120.close()
            if hasattr(self,'next'):
                self.next.close()
            self.jobs.close()
            self.store.close()
            raise

    def _current_health(self) -> dict:
        jobs = self.store.jobs()
        running = [j for j in jobs if j.get('status') in {'starting', 'running'}]
        queued = [j for j in jobs if j.get('status') == 'queued']
        ages = [int(j.get('elapsed_ms', 0) / 1000) for j in running
                if isinstance(j.get('elapsed_ms'), (int, float))]
        health = {
            'server_version': SERVER_VERSION,
            'ownership_recovery': self.jobs.ownership_status(),
            'tool_count': len(self.fields),
            'audit_chain_ok': self.store.verify(),
            'security_sandbox': self.policy.exec_mode == 'appcontainer',
            'network_listener': False,
            'owned_jobs_running': len(running),
            'owned_jobs_queued': len(queued),
            'oldest_owned_job_seconds': max(ages, default=0),
            'runtime_count': 'supervisor_telemetry_required',
            'admission': self.jobs.admission_status(),
            'store_capacity': self.store.capacity_snapshot(),
        }
        if self.v080 is not None:
            with self._metrics_lock:
                health['telemetry_failures'] = self._metrics.get('telemetry_failures', 0)
            health['telemetry_integrity'] = self.v080.telemetry.integrity()
            health['runs_interrupted_at_startup'] = len(self.v080.startup.get('interrupted', []))
        v100 = getattr(self, 'v100', None)
        if v100 is not None:
            info = v100.health()
            health['missions_active'] = sum(info['missions_by_state'].get(s, 0)
                                            for s in ('READY', 'RUNNING', 'WAITING', 'BLOCKED', 'VERIFYING', 'RECOVERING'))
            health['mission_chain_ok'] = info['mission_chain_ok']
            health['scheduler_error'] = info['scheduler_error']
            health['missions_recovered_at_startup'] = info['recovered_at_startup']
            health['mission_recovery'] = info.get('recovery')
            health['mission_fences'] = info.get('fences')
            health['mission_telemetry'] = info.get('telemetry')
            first_project = next(iter(self.policy.projects), None)
            if first_project is not None:
                extra = set(V060_FIELDS) | set(V080_FIELDS) | set(V100_FIELDS)
                if getattr(self, 'v110', None) is not None:
                    extra |= set(V110_FIELDS)
                if getattr(self, 'v120', None) is not None:
                    extra |= set(V120_FIELDS)
                parity = self.next.capability_report(
                    self.next.context(first_project), self.fields, SERVER_VERSION, None,
                    extra_enabled=extra,
                    extension_version=self._extension_version())
                health['capability_parity'] = {
                    'registered_count': parity['registered_count'],
                    'enabled_count': parity['enabled_count'],
                    'catalog_revision': parity['catalog_revision'],
                    'client_visibility': parity['client_visibility'],
                    'refresh_required': parity['refresh_required'],
                }
        v110 = getattr(self, 'v110', None)
        if v110 is not None:
            info = v110.health()
            health['agents_active'] = info['agents_active']
            health['agents_by_state'] = info['agents_by_state']
            health['agent_chain_ok'] = info['agent_chain_ok']
            health['agents_recovered_at_startup'] = info['recovered_at_startup']
            health['queued_delegation_intents'] = info['queued_intents']
        return health

    def _v100_worker_probe(self, mission: dict) -> dict:
        wanted = set(mission.get('jobs') or [])
        if not wanted:
            return {'live': False, 'owned': True, 'worker_ids': [], 'unresolved': False}
        live, unresolved = [], []
        for job in self.store.jobs():
            jid = job.get('job_id') or job.get('id')
            if jid not in wanted:
                continue
            # Overlay retained in-memory cleanup faults as well as restart ambiguity.
            observed = self.jobs.read(job['scope'], jid, 0)
            status = observed.get('status')
            if status in {'ownership_unresolved', 'stopping', 'finalizing'}:
                unresolved.append(jid)
            elif status in {'queued', 'starting', 'running'}:
                live.append(jid)
        return {'live': bool(live), 'owned': True, 'worker_ids': live + unresolved,
                'unresolved': bool(unresolved), 'unresolved_worker_ids': unresolved}

    def _v100_transaction_probe(self, mission: dict) -> dict:
        if self.v060 is None or not mission.get('transactions'):
            return {'unresolved': False, 'state': 'NONE'}
        wanted = set(mission.get('transactions') or [])
        unresolved = [row for row in self.v060.transactions.journal.unresolved()
                      if row.get('plan_id') in wanted]
        return {'unresolved': bool(unresolved), 'state': 'UNRESOLVED' if unresolved else 'NONE',
                'items': unresolved[:8]}

    def _v100_move_probe(self, mission: dict) -> dict:
        if self.v060 is None:
            return {'unresolved': False, 'state': 'NONE'}
        wanted = set(mission.get('transactions') or [])
        unresolved = [row for row in self.v060.journal.unresolved()
                      if row.get('plan_id') in wanted]
        return {'unresolved': bool(unresolved), 'state': 'UNRESOLVED' if unresolved else 'NONE',
                'items': unresolved[:8]}

    def _v100_run_command(self, project: str, spec: dict) -> dict:
        cancelling = False
        try:
            argv = self.policy.command(project, spec.get('argv'), spec.get('recipe'))
            timeout = spec.get('timeout_ms', 300000)
            scope = self.principal + ':v100-verifier:' + project
            jid = self.jobs.start(scope, project, argv, timeout,
                                  cwd=spec.get('working_directory'), scratch=True)
            deadline = time.monotonic() + timeout / 1000
            wait = min(self.policy.max_wait_ms, timeout)
            record = self.jobs.read(scope, jid, max(1, wait))
            while (record.get('status') in ('queued', 'starting', 'running') and time.monotonic() < deadline):
                wait = min(self.policy.max_wait_ms, max(1, int((deadline - time.monotonic()) * 1000)))
                record = self.jobs.read(scope, jid, wait)
            if record.get('status') in {'queued', 'starting', 'running'}:
                # A verifier deadline includes admission wait. Do not leave
                # its owned command queued to execute after a terminal verdict.
                cancelling = True
                self.jobs.stop(scope, jid)
                record = self.jobs.read(scope, jid, 0)
                if record.get('status') in {'queued', 'starting', 'running'}:
                    raise ControlError('VERIFIER_CANCELLATION_PENDING',
                                       'Owned verifier cancellation is not yet confirmed')
                return {'ok': False, 'timed_out': True, 'job_id': jid,
                        'status': record.get('status'), 'returncode': record.get('returncode')}
            return {'ok': record.get('status') in ('completed', 'failed'), 'returncode': record.get('returncode'),
                    'job_id': record.get('job_id'), 'status': record.get('status'),
                    'timed_out': record.get('status') == 'timed_out',
                    'output_bytes': (record.get('stdout_bytes') or 0) + (record.get('stderr_bytes') or 0),
                    'cwd': record.get('cwd'), 'scratch': record.get('scratch'),
                    'execution': ('sandbox' if record.get('security_sandbox') else 'host')}
        except ControlError as error:
            if cancelling:
                # Propagate an indeterminate cancellation through measure so
                # mission_finish cannot commit a terminal verification verdict.
                raise ControlError('VERIFIER_CANCELLATION_PENDING',
                                   'Owned verifier cancellation requires reconciliation') from None
            return {'ok': False, 'error': error.code}
        except (Rejected, V060Rejected) as error:
            return {'ok': False, 'error': error.code}

    async def scheduler_loop(self):
        if self.v100 is not None:
            await self.v100.scheduler_loop()

    async def _call_base(self, tool: str, project: str, args: dict) -> dict:
        token = self._internal_depth.set(self._internal_depth.get() + 1)
        try:
            return await self.call(tool, project, args)
        finally:
            self._internal_depth.reset(token)

    async def call(self, tool: str, project: str, args: dict) -> dict:
        base_mutation = tool in MUTATIONS and not (tool == 'file_patch' and isinstance(args,dict) and args.get('dry_run') is True)
        delegated_mutation = tool == 'task_create_file'
        v060_mutation = self.v060 is not None and tool in V060_MUTATING_TOOLS
        v080_mutation = self.v080 is not None and tool in V080_MUTATING_TOOLS
        gated = ((self.v060 is not None and (base_mutation or delegated_mutation or v060_mutation))
                 or (self.v080 is not None and v080_mutation))
        if gated and not self._inside_mutation_gate.get():
            async with self.mutation_gate:
                token=self._inside_mutation_gate.set(True)
                try:
                    return await self._call_impl(tool,project,args)
                finally:
                    self._inside_mutation_gate.reset(token)
        return await self._call_impl(tool,project,args)

    def _record_metric(self, tool: str, result: dict):
        try:
            size = len(json.dumps(result, ensure_ascii=True))
        except (TypeError, ValueError):
            size = 0
        with self._metrics_lock:
            self._metrics['calls'] += 1
            self._metrics['bytes'] += size
            self._metrics['by_tool'][tool] = self._metrics['by_tool'].get(tool, 0) + 1
            if not (isinstance(result, dict) and result.get('ok') is True):
                self._metrics['errors'] += 1

    def _telemetry_probe(self) -> dict:
        """Bounded host/runtime fields for derived telemetry. Cheap only:
        no whole-history scans, no job stdout materialization."""
        import shutil
        state_dir = self.policy.state_dir
        disk = shutil.disk_usage(state_dir)
        state_bytes, entries, truncated = 0, 0, False
        for root, dirs, files in os.walk(state_dir):
            for name in files:
                entries += 1
                if entries > 20000:
                    truncated = True
                    break
                try:
                    state_bytes += (Path(root) / name).stat().st_size
                except OSError:
                    pass
            if truncated:
                break
        wal = state_dir / 'localcontrol.db-wal'
        mission_wal = state_dir / 'v100' / 'missions.db-wal'
        payload = {
            'server_version': SERVER_VERSION,
            'exec_mode': self.policy.exec_mode,
            'tool_count': len(self.fields),
            'jobs': self.store.job_status_counts(),
            'admission': self.jobs.admission_status(),
            'disk_free_bytes': disk.free,
            'state_dir_bytes': state_bytes,
            'state_dir_walk_truncated': truncated,
            'audit': self.store.audit_capacity_snapshot(),
            'store_wal_bytes': wal.stat().st_size if wal.exists() else 0,
            'mission_wal_bytes': mission_wal.stat().st_size if mission_wal.exists() else 0,
            'process_cpu_s': round(sum(os.times()[:2]), 1),
        }
        with self._metrics_lock:
            payload['telemetry_failures'] = self._metrics.get('telemetry_failures', 0)
        if self.v110 is not None:
            try:
                info = self.v110.health()
                payload['agents_active'] = info['agents_active']
                payload['queued_delegation_intents'] = info['queued_intents']
            except Exception:
                payload['agents'] = 'unknown'
        return payload

    def _local_metrics(self) -> dict:
        with self._metrics_lock:
            return {'tool_calls_total': self._metrics['calls'], 'tool_errors_total': self._metrics['errors'],
                    'tool_response_bytes_total': self._metrics['bytes'],
                    'calls_by_tool': dict(sorted(self._metrics['by_tool'].items())),
                    'since_ns': self._metrics['since_ns'], 'model_tokens': None,
                    'scope': 'process lifetime; includes internal broker calls; never persisted or inferred'}

    def _project_choices(self) -> dict:
        return {'valid_projects': [{'name': name, 'writable': spec.writable}
                                   for name, spec in sorted(self.policy.projects.items())],
                'next_action': {'tool': BOOTSTRAP_TOOL}}

    def _extension_version(self) -> str:
        if getattr(self, "v120", None) is not None:
            return V120_VERSION
        if getattr(self, "v110", None) is not None:
            return V110_VERSION
        if getattr(self, "v100", None) is not None:
            return V100_VERSION
        if getattr(self, "v080", None) is not None:
            return V080_VERSION
        if getattr(self, "v060", None) is not None:
            return V060_VERSION
        return EXTENSION_VERSION

    def _resolve_project(self, tool: str, project) -> str:
        if project is None or project == '':
            if tool in GLOBAL_DEFAULT_TOOLS:
                return '*'
            if len(self.policy.projects) == 1:
                return next(iter(self.policy.projects))
            raise ControlError('PROJECT_REQUIRED', 'Project is required for this operation', self._project_choices())
        require(isinstance(project, str), 'INVALID_ARGUMENT', 'project must be a string')
        return project

    def _error_details(self, code: str, project: str) -> dict | None:
        if code in ('PROJECT_REQUIRED', 'UNKNOWN_PROJECT'):
            return self._project_choices()
        if code == 'CATALOG_SCOPE_REQUIRED':
            return {'global_scope_selector': '*', 'next_action': {'tool': BOOTSTRAP_TOOL}}
        return None

    @staticmethod
    def _bounded(details: dict, limit: int = 4096) -> dict:
        try:
            if len(packed(details)) <= limit:
                return details
        except (TypeError, ValueError):
            return {'note': 'details unavailable'}
        return {'note': 'details truncated', 'keys': sorted(details)[:16]} if isinstance(details, dict) else {}

    def _job_summary(self, record: dict) -> dict:
        keep = ('job_id','project','status','returncode','elapsed_ms','queued_ms','queued_ns',
                'queue_position','queued_reason','started_ns','timeout_ms','last_output_ns',
                'silent_ms','stdout_bytes','stderr_bytes','stdout_truncated','stderr_truncated','stdin_bytes',
                'containment','security_sandbox','isolation','cpu_user_ns','cpu_kernel_ns','cpu_ms',
                'peak_memory_bytes','memory_bytes','disk_bytes',
                'active_processes','resource_limit_state')
        summary = {key: record.get(key) for key in keep if key in record}
        for key in ('archived', 'archived_ns', 'archive_reason', 'record_sha256'):
            if key in record:
                summary[key] = record[key]
        summary['output_captured_bytes'] = (record.get('stdout_bytes') or 0) + (record.get('stderr_bytes') or 0)
        summary['next_action'] = ({'tool': 'job_delta', 'args': {'job_id': record.get('job_id')}}
                                  if record.get('status') in {'queued', 'starting', 'running'} or summary['output_captured_bytes']
                                  else None)
        summary['ownership'] = 'localcontrol_owned_only'
        return summary

    def _environment_snapshot(self, context, task: str) -> dict:
        project = context.project
        jobs = [{'job_id': j.get('id'), 'status': j.get('status'),
                 'elapsed_ms': j.get('elapsed_ms'), 'returncode': j.get('returncode')}
                for j in self.store.jobs()
                if j.get('project') == project and j.get('status') in {'queued', 'starting', 'running', 'interrupted',
                                                                      'capture_incomplete', 'timed_out'}]
        environment = {'project': project, 'task': task, 'owned_jobs': jobs[:32],
                       'leases': [], 'unresolved_moves': [], 'unresolved_transactions': [],
                       'workspace': None, 'usage': None,
                       'recommended_next': [{'tool': 'job_read', 'args': {'job_id': j['job_id'], 'view': 'summary'}}
                                            for j in jobs[:4]] or [{'tool': 'process_list'}]}
        if self.v060 is not None:
            try:
                catalog = self.v060.workspace_catalog()
                environment['leases'] = [{'lease_id': l.get('lease_id'), 'scopes': l.get('scopes'),
                                          'purpose': l.get('purpose'), 'expires_ns': l.get('expires_ns')}
                                         for l in catalog.get('active_leases', [])][:16]
                environment['unresolved_moves'] = catalog.get('unresolved_moves', [])[:16]
                environment['unresolved_transactions'] = self.v060.transactions.journal.unresolved()[:16]
                for workspace in catalog.get('workspaces', []):
                    if workspace.get('name') == project:
                        environment['workspace'] = workspace
                        break
                if task:
                    usage = self.v060.usage.summary(project, task)
                    environment['usage'] = {'events': usage.get('events'), 'tokens': usage.get('tokens'),
                                            'estimated_cost': None}
            except (ControlError, Rejected, V060Rejected):
                environment['environment_warning'] = 'PARTIAL_ENVIRONMENT'
        return environment

    def _context_data(self, include, max_response_bytes) -> dict:
        sections = set(include or [])
        require(sections <= {'operations', 'run', 'telemetry', 'mission'}, 'INVALID_ARGUMENT',
                'include supports: operations, run, telemetry, mission')
        require(not (sections & {'run', 'telemetry'}) or self.v080 is not None, 'INVALID_ARGUMENT',
                'run/telemetry sections require v0.8')
        require('mission' not in sections or self.v100 is not None, 'INVALID_ARGUMENT',
                'mission section requires v1.0')
        require(type(max_response_bytes) is int and 4096 <= max_response_bytes <= 131072,
                'INVALID_ARGUMENT', 'max_response_bytes must be 4096..131072')
        single = len(self.policy.projects) == 1
        projects = [{'name': name, 'writable': spec.writable, 'execution_mode': self.policy.exec_mode,
                     'security_sandbox': self.policy.exec_mode == 'appcontainer',
                     'execution_class': self._exec_surface['execution_class'],
                     'python': self._exec_surface['python_by_project'][name], 'is_default': single}
                    for name, spec in sorted(self.policy.projects.items())]
        groups = {group: [name for name in names if name in self.fields]
                  for group, names in protocol.TOOL_GROUPS.items()}
        groups = {group: names for group, names in groups.items() if names}
        workflows = {name: value for name, value in protocol.WORKFLOWS.items()
                     if (name != 'supervision' or self.v080 is not None)
                     and (name != 'delegation' or self.v110 is not None)}
        data = {
            'protocol_version': protocol.PROTOCOL_VERSION, 'schema_version': protocol.SCHEMA_VERSION,
            'server_version': SERVER_VERSION,
            'extension_version': self._extension_version(),
            'tool_count': len(self.fields), 'tool_groups': groups, 'projects': projects,
            'default_project': projects[0]['name'] if single else None,
            'execution_mode': self.policy.exec_mode,
            'execution_class': self._exec_surface['execution_class'],
            'powershell': self._exec_surface['powershell'],
            'python_by_project': self._exec_surface['python_by_project'],
            'security_sandbox': self.policy.exec_mode == 'appcontainer',
            'network_listener': False, 'audit_chain_ok': self.store.verify(),
             'health': self._current_health(),
             'state_schema': ({'version': 2, 'migration': self.v100.migration.get('to_version'),
                              'migration_ok': self.v100.migration.get('ok'),
                              'recovery_model': 'autonomy-closure'}
                             if self.v100 is not None else {'version': protocol.SCHEMA_VERSION}),
            'features': {'owned_jobs': True, 'change_aware_reads': True, 'task_ownership': True,
                         'appcontainer': self.policy.exec_mode == 'appcontainer',
                         'recipe_execution': bool(self.policy.recipes),
                         'v060_maintenance': self.v060 is not None,
                         'transactions': self.v060 is not None,
                         'durable_telemetry': self.v080 is not None,
                         'supervision': self.v080 is not None,
                         'workspace_identity': self.v080 is not None,
                         'missions': self.v100 is not None,
                         'scheduler': self.v100 is not None,
                          'resource_governor': self.v100 is not None,
                          'completion_verifier': self.v100 is not None,
                          'backup_restore': self.v100 is not None,
                          'terminal_job_reclamation': True,
                         'archived_job_lookup': True,
                         'protocol_metadata': True,
                         'truthful_capability_parity': True,
                         'fail_closed_recovery': self.v100 is not None,
                         'agent_delegation': self.v110 is not None,
                         'task_preflight': self.v120 is not None,
                         'autonomous_project_powershell': self._exec_surface['powershell']['autonomous'],
                         'autonomous_project_python': any(
                             item['autonomous'] for item in self._exec_surface['python_by_project'].values())},
            'workflows': workflows,
            'recommended_next': ([{'tool': 'capabilities', 'args': {'project': projects[0]['name']}}]
                                 if projects else []) + [{'tool': 'health_status'}],
            'arguments_model': {'project': 'optional when exactly one project exists; global tools default to *'},
        }
        if self.v060 is not None:
            catalog = self.v060.workspace_catalog()
            data['registry'] = {'revision': catalog['revision'], 'sha256': catalog['registry_sha256'],
                                'operator_only': True}
            data['scopes'] = {'workspaces': catalog['workspaces'], 'collections': catalog['collections']}
            data['health']['active_leases'] = len(catalog['active_leases'])
            data['health']['unresolved_moves'] = len(catalog['unresolved_moves'])
            data['health']['unresolved_transactions'] = len(self.v060.transactions.journal.unresolved())
        if self.v080 is not None and (sections & {'run', 'telemetry'}):
            data.update(self.v080.context_sections(None, sections))
        if self.v100 is not None and 'mission' in sections:
            data['mission'] = self.v100.health()
        if 'operations' in sections:
            data['operations'] = {name: spec for name, spec in protocol.OPERATIONS.items() if name in self.fields}
        require(len(packed(data)) <= max_response_bytes, 'RESPONSE_LIMIT',
                'Context exceeds max_response_bytes; request a smaller section set')
        return data

    async def _call_impl(self, tool: str, project, args: dict) -> dict:
        start_ns = time.time_ns()
        result = await self._dispatch(tool, project, args)
        self._record_metric(tool, result)
        self._record_telemetry(tool, project, args, result, start_ns)
        return result

    def _record_telemetry(self, tool: str, project, args: dict, result: dict, start_ns: int):
        if self.v080 is None or self._internal_depth.get() > 0:
            return
        try:
            end_ns = time.time_ns()
            status = 'replayed' if result.get('replayed') is True else ('ok' if result.get('ok') is True else 'error')
            error_code = None if result.get('ok') is True else (result.get('error') or {}).get('code')
            self.v080.note_operation(
                tool=tool, start_ns=start_ns, end_ns=end_ns,
                project=project if isinstance(project, str) and project not in ('', '*') else '',
                origin='client', status=status, error_code=error_code,
                request_bytes=len(packed(args)) if isinstance(args, dict) else 0,
                response_bytes=len(json.dumps(result, ensure_ascii=True)),
                args=args if isinstance(args, dict) else {}, result=result)
        except Exception:
            # A telemetry fault never changes the tool outcome; it is surfaced as
            # degraded health instead of being hidden.
            with self._metrics_lock:
                self._metrics['telemetry_failures'] = self._metrics.get('telemetry_failures', 0) + 1

    async def _dispatch(self, tool: str, project, args: dict) -> dict:
        reserved = False
        scope = ''
        request_id = args.get('request_id') if isinstance(args, dict) else None
        try:
            require(tool in self.fields and isinstance(args, dict) and not set(args) - self.fields[tool],
                    'INVALID_ARGUMENT', 'Unknown tool or argument')
            if tool == BOOTSTRAP_TOOL:
                return {'ok': True, 'data': self._context_data(args.get('include'),
                                                               args.get('max_response_bytes', 65536))}
            project = self._resolve_project(tool, project)
            catalog = tool == 'system_info' and project == '*'
            v060_tool = self.v060 is not None and tool in V060_FIELDS
            v080_tool = self.v080 is not None and tool in V080_FIELDS
            v100_tool = self.v100 is not None and tool in V100_FIELDS
            v110_tool = self.v110 is not None and tool in V110_FIELDS
            v120_tool = self.v120 is not None and tool in V120_FIELDS
            mission_id = args.get('mission_id') if isinstance(args, dict) else None
            if mission_id:
                require(self.v100 is not None, 'V100_REQUIRED', 'Mission-scoped calls require v1.0')
                require(isinstance(mission_id, str), 'INVALID_MISSION_ID', 'mission_id must be a string')
                if not v100_tool:
                    self.v100.precheck(project, tool, mission_id,
                                       generation=args.get('generation'),
                                       fence_token=args.get('fence_token'))
            require(catalog or v060_tool or v080_tool or v100_tool or v110_tool or v120_tool
                    or project in self.policy.projects,
                    'UNKNOWN_PROJECT', 'Project is not configured')
            scope = self.principal + ':v120-task' if v120_tool else self.principal + (':v060-catalog' if v060_tool and project == '*' else
                                      (':v080-catalog' if v080_tool and project in ('', '*') else
                                       (':v100-catalog' if v100_tool and project in ('', '*') else
                                        (':v110-catalog' if v110_tool and project in ('', '*') else
                                         (':project-catalog' if catalog else ':' + project)))))
            extension = tool in EXPOSED_TOOLS or v060_tool or v080_tool or v100_tool or v110_tool or v120_tool
            mutation = tool in MUTATIONS and not (tool == 'file_patch' and args.get('dry_run') is True)
            v060_mutation = self.v060 is not None and tool in V060_MUTATING_TOOLS
            v080_mutation = self.v080 is not None and tool in V080_MUTATING_TOOLS
            v100_mutation = self.v100 is not None and tool in V100_MUTATING_TOOLS
            v110_mutation = self.v110 is not None and tool in V110_MUTATING_TOOLS
            v120_mutation = self.v120 is not None and tool in V120_MUTATING_TOOLS
            if self.v060 is not None and (mutation or tool == 'task_create_file'):
                self.v060.guard_base_mutation(project)
            if self.v060 is not None and tool in TRANSACTION_FILE_MUTATIONS:
                require(project in self.policy.projects, 'UNKNOWN_PROJECT', 'Project is not configured')
                self.v060.guard_base_mutation(project)
            if mutation or v060_mutation or v080_mutation or v100_mutation or v110_mutation or v120_mutation:
                old = self.store.reserve(scope, request_id, digest({'tool': tool, 'args': args}))
                if old is not None:
                    # Job creation replay returns the SAME job's current state, never starts another.
                    if tool == 'exec' and old.get('data', {}).get('job_id'):
                        # Admission can be durable even when later request finish fails.
                        # Preserve its result class and return current owned state.
                        try:
                            old = {**old, 'data': self.jobs.read(scope, old['data']['job_id'], 0)}
                        except ControlError as error:
                            if error.code != 'UNKNOWN_JOB':
                                raise
                            # Initial admission may have failed before its row
                            # existed. The request identity survives; never replay.
                            bound = old['data']['job_id']
                            old = {'ok': False, 'error': {'code': 'JOB_RECEIPT_UNAVAILABLE',
                                'message': 'Bound job receipt unavailable; reconcile instead of replay',
                                'details': {'job_id': bound}}, 'data': {'job_id': bound}}
                    return {**old, 'replayed': True}
                reserved = True
            elif extension:
                self.store.audit('extension_intent', {'scope':scope, 'tool':tool, 'input_sha256':digest(args)})
            else:
                self.store.audit('read_intent', {'scope':scope, 'tool':tool, 'input_sha256':digest(args)})
            if catalog:
                single = len(self.policy.projects) == 1
                data = {'version':SERVER_VERSION,
                        'extension_version': self._extension_version(),
                        'protocol_version':protocol.PROTOCOL_VERSION,
                        'tool_count':len(self.fields),
                        'projects':[{'name':name,'writable':spec.writable}
                                    for name,spec in sorted(self.policy.projects.items())],
                        'count':len(self.policy.projects),
                        'default_project':next(iter(self.policy.projects)) if single else None,
                        'bootstrap_tool':BOOTSTRAP_TOOL if BOOTSTRAP_TOOL in self.fields else None,
                        'tools_by_group':{group:[name for name in names if name in self.fields]
                                          for group,names in protocol.TOOL_GROUPS.items()},
                        'execution_mode':self.policy.exec_mode,
                         'execution_class':self._exec_surface['execution_class'],
                         'powershell':self._exec_surface['powershell'],
                         'python_by_project':self._exec_surface['python_by_project'],
                         'security_sandbox':self.policy.exec_mode == 'appcontainer',
                         'network_listener':False,
                         'v060_maintenance':self.v060 is not None,
                         'v080_supervision':self.v080 is not None,
                         'v110_delegation':self.v110 is not None,
                         'v120_preflight':self.v120 is not None,
                         'state_schema_version':protocol.SCHEMA_VERSION,
                         'selector':'*'}
            elif v060_tool:
                data = await self.v060.call(tool,project,args)
            elif v080_tool:
                if tool == 'telemetry_summary':
                    data = self.v080.telemetry_summary(project, args)
                elif tool == 'run_begin':
                    data = self.v080.run_begin(project, args)
                elif tool == 'run_heartbeat':
                    data = self.v080.run_heartbeat(project, args)
                elif tool == 'run_status':
                    data = self.v080.run_status(project, args)
                elif tool == 'run_finish':
                    data = self.v080.run_finish(project, args)
                else:
                    raise Rejected('INVALID_ARGUMENT')
            elif v100_tool:
                data = await self.v100.call(tool, project, args)
            elif v110_tool:
                data = await self.v110.call(tool, project, args)
            elif v120_tool:
                data = await asyncio.to_thread(self.v120.call, tool, project, args)
            elif tool == 'capabilities':
                extra = set()
                if self.v060 is not None:
                    extra.update(V060_FIELDS)
                if self.v080 is not None:
                    extra.update(V080_FIELDS)
                if self.v100 is not None:
                    extra.update(V100_FIELDS)
                if self.v110 is not None:
                    extra.update(V110_FIELDS)
                if self.v120 is not None:
                    extra.update(V120_FIELDS)
                if self.v060 is not None or self.v080 is not None or self.v100 is not None \
                        or self.v110 is not None or self.v120 is not None:
                    c=self.next.context(project)
                    data=self.next.capability_report(c,self.fields,SERVER_VERSION,args.get('client_observed'),
                                                     extra_enabled=extra,
                                                     extension_version=self._extension_version())
                else:
                    data=await self.next.call(tool, project, args, self.fields, SERVER_VERSION)
                data['protocol_version']=protocol.PROTOCOL_VERSION
                if self.v100 is not None:
                    data['state_schema_version'] = 2
                    data['migration_origin'] = self.v100.migration.get('migration_origin')
                data['execution_class']=self._exec_surface['execution_class']
                data['powershell']=self._exec_surface['powershell']
                data['python']=self._exec_surface['python_by_project'].get(project)
                data['features']={'owned_jobs':True,'change_aware_reads':True,'task_ownership':True,
                                  'v060_maintenance':self.v060 is not None,
                                  'transactions':self.v060 is not None,
                                  'durable_telemetry':self.v080 is not None,
                                  'supervision':self.v080 is not None,
                                  'workspace_identity':self.v080 is not None,
                                  'missions':self.v100 is not None,
                                  'scheduler':self.v100 is not None,
                                   'resource_governor':self.v100 is not None,
                                   'completion_verifier':self.v100 is not None,
                                   'backup_restore':self.v100 is not None,
                                   'terminal_job_reclamation':True,
                                   'archived_job_lookup':True,
                                   'protocol_metadata':True,
                                   'agent_delegation':self.v110 is not None,
                                   'task_preflight':self.v120 is not None,
                                   'autonomous_project_powershell':self._exec_surface['powershell']['autonomous'],
                                   'autonomous_project_python':bool(
                                       (self._exec_surface['python_by_project'].get(project) or {}).get('autonomous'))}
            elif tool == 'efficiency_metrics':
                data = await self.next.call(tool, project, args, self.fields, SERVER_VERSION)
                data = {**data, 'localcontrol': self._local_metrics()}
            elif tool in EXPOSED_TOOLS:
                data = await self.next.call(tool, project, args, self.fields, SERVER_VERSION)
            elif tool.startswith('file_'):
                if tool in {'file_read', 'file_search', 'file_list'}:
                    # Do not make independent reads wait behind project-wide
                    # mutations. file_read validates a before/after hash;
                    # search and listing are observational and may race writes.
                    data = await self._file(tool, project, args)
                else:
                    # Preserve serial mutations and their SHA guards.
                    async with self.locks[project]:
                        data = await self._file(tool, project, args)
            elif tool == 'exec':
                wait = args.get('wait_ms', min(25000, self.policy.max_wait_ms))
                require(type(wait) is int and 0 <= wait <= self.policy.max_wait_ms, 'INVALID_WAIT', 'Invalid synchronous wait')
                argv = self.policy.command(project, args.get('argv'), args.get('recipe'))
                job_limits = None
                job_timeout = args.get('timeout_ms', self.policy.max_timeout_ms)
                if mission_id:
                    job_limits = self.v100.job_limits(mission_id)
                    job_timeout = min(job_timeout, max(1, job_limits.pop('max_timeout_ms', job_timeout)))
                    require(self.v100.remaining_wall_ms(mission_id) > 0, 'BUDGET_WALL', 'Mission wall budget exhausted')
                jid = self.jobs.start(scope, project, argv, job_timeout, limits=job_limits,
                                      request_id=request_id)
                if mission_id:
                    self.v100.note_job(project, mission_id, jid)
                # Persist binding BEFORE waiting, making disconnect/retry non-duplicating.
                running = {'ok':True, 'data':self.jobs.read(scope,jid)}
                self.store.finish(scope, request_id, running)
                data = await asyncio.to_thread(self.jobs.read, scope, jid, wait)
            elif tool == 'job_read':
                view = args.get('view', 'full')
                require(view in {'full','summary'}, 'INVALID_ARGUMENT', 'view must be full or summary')
                record = await asyncio.to_thread(self.jobs.read, scope, args['job_id'], args.get('wait_ms',0))
                data = record if view == 'full' else self._job_summary(record)
            elif tool == 'job_input':
                require(type(args.get('eof',False)) is bool, 'INVALID_ARGUMENT', 'eof must be boolean')
                data = self.jobs.input(scope,args['job_id'],args.get('text',''),args.get('eof',False))
            elif tool == 'job_stop':
                data = await asyncio.to_thread(self.jobs.stop,scope,args['job_id'])
            elif tool == 'archive_terminal_jobs':
                data = await asyncio.to_thread(self.jobs.archive_terminal_jobs, scope)
            elif tool == 'process_list':
                data = {'jobs':[{k:v for k,v in j.items() if k not in {'stdout','stderr','scope'}}
                                for j in self.store.jobs(scope=scope)], 'scope':'owned_jobs_only'}
            else:
                data = {'version':SERVER_VERSION, 'extension_version': self._extension_version(),
                        'protocol_version':protocol.PROTOCOL_VERSION,
                        'tool_count':len(self.fields), 'project':project,
                        'writable':self.policy.projects[project].writable,
                        'execution_mode':self.policy.exec_mode,
                        'execution_class':self._exec_surface['execution_class'],
                        'powershell':self._exec_surface['powershell'],
                        'python':self._exec_surface['python_by_project'].get(project),
                        'security_sandbox':self.policy.exec_mode == 'appcontainer',
                        'backend':'winfs-mcp', 'network_listener':False,
                        'protected_process_control':'job handles only; no foreign PID stop tool',
                        'audit_chain_ok':self.store.verify()}
            result = {'ok':True,'data':data}
        except (Rejected,V060Rejected) as e:
            error = {'code':e.code,'message':e.code}
            details = getattr(e, 'details', None)
            if not details:
                details = self._error_details(e.code, project)
            if details:
                error['details'] = self._bounded(details)
            hint = ERROR_HINTS.get(e.code)
            if hint:
                error['hint'] = hint
            result = {'ok':False,'error':error}
        except ControlError as e:
            error = {'code':e.code,'message':str(e)}
            details = getattr(e, 'details', None) or self._error_details(e.code, project)
            if details:
                error['details'] = self._bounded(details)
            hint = ERROR_HINTS.get(e.code)
            if hint:
                error['hint'] = hint
            result = {'ok':False,'error':error}
        except (KeyError, TypeError, ValueError):
            if os.environ.get('LOCALCONTROL_DEBUG_ERRORS') == '1':
                raise
            result = {'ok':False,'error':{'code':'INVALID_ARGUMENT','message':'Missing or malformed argument'}}
        except Exception:
            result = {'ok':False,'error':{'code':'INTERNAL_ERROR','message':'Operation failed; inspect local logs before retrying'}}
        if reserved and tool == 'exec' and not result.get('ok'):
            # Preserve the admitted identity through note_job/read/finish failures.
            bound_jid = locals().get('jid') or result.get('error', {}).get('details', {}).get('job_id')
            if bound_jid:
                result['data'] = {'job_id': bound_jid}
                result['error'].setdefault('details', {})['job_id'] = bound_jid
        if reserved:
            # A store failure is intentionally not hidden as a successful operation.
            self.store.finish(scope, request_id, result)
        try:
            mid = locals().get('mission_id')
            proj = locals().get('project')
            if (isinstance(mid, str) and isinstance(proj, str) and proj not in ('', '*')
                    and result.get('ok') is True and self.v100 is not None and tool not in V100_FIELDS):
                if tool in ('transaction_plan', 'transaction_apply'):
                    data = result.get('data') or {}
                    plan_id = data.get('plan_id')
                    if isinstance(plan_id, str):
                        self.v100.note_transaction(proj, mid, plan_id)
                else:
                    self.v100.note_output(proj, mid, min(len(json.dumps(result, ensure_ascii=True)), 1 << 20))
        except Exception:
            pass
        return result

    def _hash(self, p: Path) -> str | None:
        if not p.exists():
            return None
        require(p.is_file() and p.stat().st_size <= self.policy.max_file_bytes, 'FILE_LIMIT', 'File exceeds bounded-operation limit')
        with p.open('rb') as stream:
            content=stream.read(self.policy.max_file_bytes+1)
        require(len(content)<=self.policy.max_file_bytes,'FILE_LIMIT','File grew beyond operation limit')
        return hashlib.sha256(content).hexdigest()

    async def _file(self, tool: str, project: str, a: dict):
        p = self.policy.path(project, a.get('path',''), write=tool in {'file_write','file_patch','file_delete'},
                             directory=tool in {'file_search','file_list'})
        if tool == 'file_list':
            limit = a.get('limit',100)
            require(type(limit) is int and 1 <= limit <= 500, 'INVALID_ARGUMENT', 'Invalid list limit')
            value = await self.backend.call(project,'list',{'path':str(p),'max_depth':1})
            safe = []
            for row in value['entries']:
                try:
                    relative = str(Path(row['path']).relative_to(self.policy.projects[project].root))
                    self.policy.path(project,relative, directory=row['is_dir'])
                    safe.append({**row,'path':relative})
                except (ControlError, ValueError):
                    continue
            return {'entries':safe[:limit], 'truncated':len(safe)>limit}
        if tool == 'file_search':
            # Literal search only. No user-regex ReDoS or multi-line content returned
            # from protected files. Upstream handles actual reads and listings.
            query = a.get('query','')
            max_files, max_matches = a.get('max_files',100), a.get('max_matches',50)
            require(isinstance(query,str) and 0 < len(query) <= 256, 'INVALID_ARGUMENT','Bounded literal query required')
            require(type(max_files) is int and 1 <= max_files <= 200 and type(max_matches) is int and 1 <= max_matches <= 200,
                    'INVALID_ARGUMENT','Invalid search limits')
            matches, scanned, omitted = [],0,0
            queue = [p]; deadline=time.monotonic()+10
            while queue and scanned < max_files and len(matches)<max_matches and time.monotonic()<deadline:
                directory=queue.pop()
                listing=await self.backend.call(project,'list',{'path':str(directory),'max_depth':1})
                for row in listing['entries']:
                    if scanned>=max_files or len(matches)>=max_matches or time.monotonic()>=deadline:
                        omitted+=1; break
                    try:
                        rel=str(Path(row['path']).relative_to(self.policy.projects[project].root))
                        checked=self.policy.path(project,rel,directory=row['is_dir'])
                        if row['is_dir']:
                            if len(queue)<200: queue.append(checked)
                            else: omitted+=1
                            continue
                        if row.get('size',0)>self.policy.max_file_bytes:
                            omitted+=1; continue
                        scanned+=1
                        response=await self.backend.call(project,'read',{'path':str(checked),'max_bytes':self.policy.max_file_bytes})
                        for number,line in enumerate(response['content'].splitlines(),1):
                            if query.casefold() in line.casefold():
                                matches.append({'path':rel,'line':number,'text':line[:500]})
                                if len(matches)>=max_matches: break
                    except ControlError:
                        omitted+=1
            return {'matches':matches,'files_scanned':scanned,'skipped':omitted,
                    'truncated':bool(queue or omitted or len(matches)>=max_matches or scanned>=max_files), 'literal':True}
        if tool == 'file_delete' and p.exists():
            require(p.is_file(),'NOT_FILE','Delete target must be a regular file')
        before=self._hash(p)
        if tool=='file_read':
            require(before is not None,'NOT_FOUND','File does not exist')
            offset,length=a.get('offset',0),a.get('length',200)
            require(type(offset) is int and offset>=0 and type(length) is int and 1<=length<=2000,'INVALID_ARGUMENT','Invalid line range')
            # Upstream ranged reads normalize CRLF. Fetch bounded raw UTF-8 and
            # slice here without changing line endings or the final newline.
            data=await self.backend.call(project,'read',{'path':str(p),'max_bytes':self.policy.max_file_bytes})
            require(self._hash(p)==before,'CONCURRENT_CHANGE','File changed during read')
            lines=data['content'].splitlines(keepends=True)
            content=''.join(lines[offset:offset+length])
            return {'content':content,'lines_returned':len(lines[offset:offset+length]),
                    'bytes_returned':len(content.encode('utf-8')),
                    'truncated':bool(data.get('truncated') or offset+length<len(lines)),
                    'sha256':before,'path':a['path']}
        expected=a.get('expected_sha256')
        if tool == 'file_delete':
            require(isinstance(expected,str) and bool(re.fullmatch('[0-9a-f]{64}',expected)),
                    'PRECONDITION_REQUIRED','Supply the observed SHA-256 before deleting')
            require(before is not None,'NOT_FOUND','Delete target must exist')
            require(expected==before,'CONFLICT','File changed; read it again before deleting')
            require(self._hash(p)==expected,'CONCURRENT_CHANGE','File changed during delete')
            p.unlink()
            return {'deleted':True,'previous_sha256':before,'sha256':None,'path':a['path']}
        require(expected=='absent' or (isinstance(expected,str) and bool(re.fullmatch('[0-9a-f]{64}',expected))),
                'PRECONDITION_REQUIRED','Supply observed SHA-256, or absent to create')
        require((expected=='absent' and before is None) or expected==before,'CONFLICT','File changed; read it again before editing')
        if tool=='file_write':
            text=a['content']
            require(isinstance(text,str) and len(text.encode('utf-8'))<=self.policy.max_file_bytes,'FILE_LIMIT','Content limit exceeded')
            require(not text.startswith('\ufeff') and '\0' not in text,'INVALID_TEXT','Use UTF-8 text without BOM or NUL')
            data=await self.backend.call(project,'write',{'path':str(p),'content':text,'overwrite':before is not None,'mkdirParents':False})
        else:
            require(before is not None,'NOT_FOUND','Patch target must exist')
            old,new,count=a['old'],a['new'],a.get('expected_count',1)
            require(isinstance(old,str) and bool(old) and isinstance(new,str) and type(count) is int and 1<=count<=10000,
                    'INVALID_ARGUMENT','Invalid patch')
            require(len(old.encode())+len(new.encode())<=self.policy.max_file_bytes and not new.startswith('\ufeff') and '\0' not in new,
                    'FILE_LIMIT','Patch text limit exceeded')
            require(type(a.get('dry_run',False)) is bool,'INVALID_ARGUMENT','dry_run must be boolean')
            # Bound resulting file size before delegating atomic patch logic.
            size=p.stat().st_size + count*(len(new.encode())-len(old.encode()))
            require(size<=self.policy.max_file_bytes,'FILE_LIMIT','Patched file would be too large')
            data=await self.backend.call(project,'edit_file',{'path':str(p),'edits':[{'old_str':old,'new_str':new,'expected_count':count}],
                                                            'dry_run':a.get('dry_run',False),'with_diff':False})
        return {**data,'sha256':self._hash(p),'path':a['path']}

    def close(self):
        # Both execution owners drain before any shared dependency is closed.
        # SHUTDOWN_PENDING preserves the complete facade for operator retry.
        if self.v120 is not None:
            self.v120.close()
        self.jobs.close()
        if self.v060 is not None:
            self.v060.close()
        if self.v080 is not None:
            self.v080.close()
        if getattr(self, 'v100', None) is not None:
            self.v100.close()
        if getattr(self, 'v110', None) is not None:
            self.v110.close()
        self.next.close()
        self.store.close()

