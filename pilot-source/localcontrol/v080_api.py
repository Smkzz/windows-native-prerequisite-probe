"""LocalControl v0.8 durable telemetry, supervised runs and workspace identity.

Authority stays with the operator policy: projects come from ``Policy`` only,
monitoring paths are policy-checked, Git reads are bounded and never write, and
no new host process or network authority is introduced. Run state is durable
and tamper-evident; completion requires an explicit, owned transition.
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

from .errors import require
from .nextlib.core import Rejected, ident, need, packed
from .v080 import identity as identity_mod
from .v080.runs import RunStore
from .v080.telemetry import TelemetryStore, VIEWS

VERSION = '0.8.0-rc.1'
V080_FIELDS = {
    'telemetry_summary': {'view', 'run_id', 'tool', 'since_ns', 'after_sequence', 'limit', 'max_response_bytes'},
    'run_begin': {'objective', 'run_id', 'continuation_id', 'ttl_s', 'watch_paths', 'accept_divergence',
                  'takeover', 'token', 'request_id'},
    'run_heartbeat': {'run_id', 'token', 'notes', 'ttl_s', 'request_id'},
    'run_status': {'run_id', 'include', 'max_response_bytes'},
    'run_finish': {'run_id', 'token', 'state', 'summary', 'request_id'},
}
MUTATING_TOOLS = frozenset({'run_begin', 'run_heartbeat', 'run_finish'})
CATEGORIES = {
    'localcontrol_context': 'bootstrap', 'system_info': 'discovery', 'capabilities': 'discovery',
    'workspace_catalog': 'discovery', 'collection_inventory': 'discovery',
    'project_discovery_candidates': 'discovery', 'health_status': 'discovery',
    'file_read': 'read', 'file_list': 'read', 'file_search': 'read', 'read_batch': 'read',
    'file_write': 'write', 'file_patch': 'write', 'file_delete': 'write',
    'exec': 'execution', 'job_read': 'execution', 'job_delta': 'execution', 'job_input': 'execution',
    'job_stop': 'execution', 'archive_terminal_jobs': 'execution', 'process_list': 'execution',
    'task_begin': 'task', 'task_create_file': 'task', 'task_checkpoint': 'task', 'task_handoff': 'task',
    'task_cleanup_plan': 'task', 'task_cleanup_apply': 'task',
    'maintenance_begin': 'maintenance', 'maintenance_end': 'maintenance',
    'project_move_plan': 'maintenance', 'project_move_apply': 'maintenance', 'project_move_status': 'maintenance',
    'project_move_reconcile': 'maintenance', 'project_move_rollback': 'maintenance',
    'transaction_plan': 'transaction', 'transaction_apply': 'transaction', 'transaction_status': 'transaction',
    'transaction_reconcile': 'transaction', 'transaction_rollback': 'transaction',
    'usage_summary': 'telemetry', 'efficiency_metrics': 'telemetry', 'telemetry_summary': 'telemetry',
    'run_begin': 'supervision', 'run_heartbeat': 'supervision', 'run_status': 'supervision',
    'run_finish': 'supervision',
    'mission_begin': 'mission', 'mission_status': 'mission', 'mission_checkpoint': 'mission',
    'mission_resume': 'mission', 'mission_finish': 'mission', 'mission_cancel': 'mission',
    'mission_schedule': 'mission', 'state_backup': 'recovery', 'state_restore': 'recovery',
}


def category_of(tool: str) -> str:
    return CATEGORIES.get(tool, 'unknown')


def operation_details(tool: str, args: dict, result: dict) -> dict:
    """Bounded, non-secret per-operation detail extracted from request/response."""
    details = {}
    data = result.get('data') if isinstance(result, dict) else None
    if not isinstance(data, dict):
        return details
    if tool in {'file_write', 'file_patch', 'file_delete'}:
        details['files_affected'] = [str(args.get('path'))[:256]]
        if isinstance(data.get('sha256'), str):
            details['sha256'] = data['sha256']
    elif tool == 'read_batch':
        details['items'] = len(data.get('items', [])) if isinstance(data.get('items'), list) else None
    elif tool in {'exec', 'job_read', 'job_delta', 'job_input', 'job_stop'}:
        details['job_id'] = str(data.get('job_id') or args.get('job_id') or '')[:128]
        if isinstance(data.get('status'), str):
            details['job_status'] = data['status']
        if isinstance(data.get('isolation'), str):
            details['isolation'] = data['isolation']
        for key in ('cpu_user_ns', 'peak_memory_bytes'):
            if isinstance(data.get(key), int):
                details[key] = data[key]
    elif tool == 'archive_terminal_jobs':
        for key in ('examined', 'eligible', 'archived', 'retained', 'active_untouched'):
            if isinstance(data.get(key), int):
                details[key] = data[key]
        details['archive_schema'] = data.get('archive_schema')
    elif tool.startswith('transaction_'):
        details['plan_id'] = str(data.get('plan_id') or args.get('plan_id') or '')[:128]
        if isinstance(data.get('state'), str):
            details['transaction_state'] = data['state']
        if isinstance(data.get('operations'), int):
            details['operations'] = data['operations']
    elif tool in {'maintenance_begin', 'maintenance_end'}:
        details['lease_id'] = str(data.get('lease_id') or args.get('lease_id') or '')[:128]
    elif tool.startswith('project_move_'):
        details['plan_id'] = str(data.get('plan_id') or args.get('plan_id') or '')[:128]
    elif tool in {'task_begin', 'task_create_file', 'task_checkpoint', 'task_handoff', 'task_cleanup_plan',
                  'task_cleanup_apply'}:
        details['task'] = str(data.get('task') or args.get('task') or '')[:128]
    elif tool == 'run_begin':
        details['run_id'] = str(data.get('run_id') or '')[:128]
        details['run_state'] = data.get('state')
    return details


class V080API:
    def __init__(self, policy, principal: str, next_api, config_path: Path, options: dict):
        need(isinstance(options, dict) and set(options) == {'enabled'} and options.get('enabled') is True,
             'V080_CONFIG')
        self.policy, self.principal, self.next = policy, ident(principal), next_api
        self.config_path = config_path
        self.state = policy.state_dir / 'v080'
        self.state.mkdir(parents=True, exist_ok=True)
        self.epoch = uuid.uuid4().hex
        self.telemetry = TelemetryStore(self.state / 'telemetry.sqlite')
        self.runs = RunStore(self.state)
        self.startup = self.runs.startup(self.epoch)

    # ---- helpers --------------------------------------------------------
    def _context(self, project: str):
        return self.next.context(project)

    def _project(self, project: str) -> str:
        need(isinstance(project, str) and project in self.policy.projects, 'UNKNOWN_PROJECT')
        return project

    def _resolve_run_project(self, project: str, run_id: str) -> str:
        if project and project != '*':
            self._project(project)
            return project
        row = self.runs.status(run_id=run_id)
        need(row.get('run') is not None, 'UNKNOWN_RUN')
        resolved = row['run']['project']
        self._project(resolved)
        return resolved

    def active_run_id(self, project: str) -> str | None:
        if project in self.policy.projects:
            return self.runs.active_run(project)
        return None

    def note_operation(self, *, tool: str, start_ns: int, end_ns: int, project: str, origin: str,
                       status: str, error_code: str | None, request_bytes: int, response_bytes: int,
                       args: dict, result: dict):
        run_id = None
        continuation_id = None
        task = args.get('task') if isinstance(args, dict) else None
        if project in self.policy.projects:
            run_id = self.runs.active_run(project)
            if run_id and tool in {'run_begin', 'run_heartbeat', 'run_status', 'run_finish'}:
                run_id = None  # run tools are accounted by their own durable events
        details = operation_details(tool, args if isinstance(args, dict) else {}, result)
        if run_id:
            details['run_id'] = run_id
        self.telemetry.record(tool=tool, category=category_of(tool), start_ns=start_ns, end_ns=end_ns,
                              project=project if project in self.policy.projects else '',
                              origin=origin, run_id=run_id, continuation_id=continuation_id,
                              task=str(task)[:128] if task else None, status=status, error_code=error_code,
                              request_bytes=request_bytes, response_bytes=response_bytes, details=details)

    # ---- telemetry ------------------------------------------------------
    def telemetry_summary(self, project: str, args: dict) -> dict:
        view = args.get('view', 'summary')
        need(view in VIEWS, 'INVALID_ARGUMENT')
        scope = None if project in ('*', '', None) else self._project(project)
        max_bytes = args.get('max_response_bytes', 65536)
        if view == 'summary':
            return self.telemetry.summary(project=scope, run_id=args.get('run_id'), tool=args.get('tool'),
                                          since_ns=args.get('since_ns'), max_response_bytes=max_bytes)
        if view == 'delta':
            need('after_sequence' in args, 'INVALID_ARGUMENT')
            return self.telemetry.delta(after_sequence=args['after_sequence'], project=scope,
                                        max_response_bytes=max_bytes)
        return self.telemetry.operations(project=scope, run_id=args.get('run_id'), tool=args.get('tool'),
                                         since_sequence=args.get('after_sequence', 0),
                                         limit=args.get('limit', 200), max_response_bytes=max_bytes)

    # ---- supervised runs ------------------------------------------------
    def run_begin(self, project: str, args: dict) -> dict:
        project = self._project(project)
        run_id = args.get('run_id')
        if run_id is not None:
            ident(run_id)
        ttl_s = args.get('ttl_s', 300)
        watch_paths = args.get('watch_paths') or []
        need(isinstance(watch_paths, list) and all(isinstance(p, str) for p in watch_paths),
             'INVALID_WATCH_PATHS')
        accept = args.get('accept_divergence')
        takeover = args.get('takeover', False)
        need(type(takeover) is bool, 'INVALID_ARGUMENT')
        current = identity_mod.build_identity(self.policy, project, watch_paths)
        classification = None
        if run_id is not None:
            stored = self.runs.identity_of(run_id)
            classification = identity_mod.classify(stored, current)
            if accept is not None:
                need(isinstance(accept, str), 'INVALID_ARGUMENT')
        result = self.runs.begin_or_resume(
            project=project, context=self._context(project), identity=current, classification=classification,
            objective=args.get('objective'), run_id=run_id, continuation_id=args.get('continuation_id'),
            ttl_s=ttl_s, accept_divergence=accept, takeover=takeover, epoch=self.epoch,
            token=args.get('token'))
        result['identity'] = {'digest': current['digest'], 'root': current['root'],
                              'git_present': bool(current['git'].get('present')),
                              'commit': current['git'].get('head'),
                              'branch': current['git'].get('branch'),
                              'detached': current['git'].get('detached'),
                              'dirty': current['git'].get('dirty')}
        if classification:
            result['divergence'] = classification
        return result

    def run_heartbeat(self, project: str, args: dict) -> dict:
        run_id = args['run_id']
        ident(run_id)
        project = self._resolve_run_project(project, run_id)
        return self.runs.heartbeat(run_id=run_id, project=project, context=self._context(project),
                                   token=args['token'], notes=args.get('notes'),
                                   ttl_s=args.get('ttl_s', 300), epoch=self.epoch)

    def run_status(self, project: str, args: dict) -> dict:
        run_id = args.get('run_id')
        if run_id is not None:
            ident(run_id)
        scope = None if project in ('', '*', None) else self._project(project)
        include = args.get('include') or []
        need(isinstance(include, list) and set(include) <= {'telemetry'}, 'INVALID_ARGUMENT')
        max_bytes = args.get('max_response_bytes', 65536)
        status = self.runs.status(project=scope, run_id=run_id)
        if 'telemetry' in include:
            run_row = status.get('run') or {}
            status['telemetry'] = self.telemetry.summary(project=run_row.get('project'), run_id=run_row.get('run_id'),
                                                         max_response_bytes=max_bytes)
        need(len(packed(status)) <= max_bytes, 'RESPONSE_LIMIT')
        return status

    def run_finish(self, project: str, args: dict) -> dict:
        run_id = args['run_id']
        ident(run_id)
        project = self._resolve_run_project(project, run_id)
        return self.runs.finish(run_id=run_id, project=project, context=self._context(project),
                                token=args['token'], state=args['state'], summary=args.get('summary'),
                                epoch=self.epoch)

    def context_sections(self, project: str, sections: set) -> dict:
        out = {}
        scope = project if project in self.policy.projects else None
        if 'run' in sections:
            out['active_run'] = self.runs.status(project=scope).get('run')
        if 'telemetry' in sections:
            out['telemetry'] = self.telemetry.summary(project=scope, max_response_bytes=8192)
        return out

    def close(self):
        for store in (self.telemetry, self.runs):
            try:
                store.close()
            except Exception:
                pass

