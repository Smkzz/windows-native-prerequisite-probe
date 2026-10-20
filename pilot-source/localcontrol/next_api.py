from __future__ import annotations
import os
from pathlib import Path
import stat
from typing import Mapping

from .errors import require
from .nextlib.core import BASE_TOOLS, Context, Rejected, Signer, digest, ident, need
from .nextlib.ledger import Ledger
from .nextlib.reads import ReadService
from .nextlib.tasks import TaskService

EXTENSION_VERSION = '1.1.1'
EXPOSED_TOOLS = frozenset({
    'capabilities', 'read_batch', 'job_delta', 'efficiency_metrics',
    'task_begin', 'task_create_file', 'task_handoff', 'task_checkpoint',
})
READONLY_EXTENSION_TOOLS = frozenset({'capabilities','read_batch','job_delta','efficiency_metrics','task_handoff'})
STATE_EXTENSION_TOOLS = frozenset({'task_begin','task_create_file','task_checkpoint'})


def _regular_unlinked(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            not (getattr(info, 'st_file_attributes', 0) & 0x400))


def _load_cursor_key(state_dir: Path) -> bytes:
    """Persistent local integrity key. The operator-owned state directory is the trust boundary."""
    path = state_dir / 'next_cursor_key.bin'
    if path.exists() or path.is_symlink():
        require(_regular_unlinked(path), 'UNSAFE_STATE_PATH', 'Cursor key path is linked or non-regular')
        data = path.read_bytes()
        require(len(data) == 32, 'STATE_CORRUPT', 'Cursor key has an unexpected size')
        return data
    data = os.urandom(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags, 0o600)
    try:
        written = os.write(fd, data)
        require(written == len(data), 'STATE_WRITE_FAILED', 'Cursor key write was incomplete')
        os.fsync(fd)
    finally:
        os.close(fd)
    require(_regular_unlinked(path), 'UNSAFE_STATE_PATH', 'Cursor key path changed during creation')
    return data


class NextAPI:
    """Adapter from the v0.4.2 broker authority to the reviewed lab.2 reliability services.

    This layer never accepts principal/writable/sandbox authority from tool arguments and never
    performs direct filesystem deletion or process creation. Project mutations are routed back
    through the original Facade callback.
    """
    def __init__(self, policy, principal: str, caller):
        self.policy = policy
        self.principal = ident(principal)
        self.caller = caller
        # Store already provisions state_dir before this adapter is constructed.
        require(policy.state_dir.is_dir(), 'STATE_PARENT_MISSING', 'State directory is missing')
        key = _load_cursor_key(policy.state_dir)
        self.signer = Signer(key)
        self.ledger = Ledger(policy.state_dir / 'next_tasks.sqlite',
                             max_tasks=min(1000, max(1, policy.max_requests // 10)),
                             max_operations=policy.max_requests)
        self.reads = ReadService(caller, self.signer, principal=self.principal)
        self.tasks = TaskService(caller, self.ledger, self.signer, principal=self.principal)

    def context(self, project: str) -> Context:
        spec = self.policy.projects[project]
        revision = digest({
            'root': str(spec.root), 'writable': spec.writable,
            'execution_mode': self.policy.exec_mode,
            'max_file_bytes': self.policy.max_file_bytes,
            'max_wait_ms': self.policy.max_wait_ms,
            'max_timeout_ms': self.policy.max_timeout_ms,
            'max_active_jobs': self.policy.max_active_jobs,
            'max_queued_jobs': self.policy.max_queued_jobs,
            'min_free_memory_bytes': self.policy.min_free_memory_bytes,
            'max_ephemeral_port_fraction': self.policy.max_ephemeral_port_fraction,
            'ephemeral_port_start': self.policy.ephemeral_port_start,
            'ephemeral_port_count': self.policy.ephemeral_port_count,
            'pressure_sample_interval_ms': self.policy.pressure_sample_interval_ms,
            'max_job_records': self.policy.max_job_records,
            'terminal_retention': self.policy.terminal_retention,
            'base_tools': sorted(BASE_TOOLS),
        })
        return Context(principal=self.principal, project=project, policy_revision=revision,
                       allowed_tools=BASE_TOOLS, writable=spec.writable,
                       security_sandbox=self.policy.exec_mode == 'appcontainer',
                       execution_mode=self.policy.exec_mode, exclusive_workspace=False)

    @staticmethod
    def _can(context: Context, tool: str) -> bool:
        try:
            context.authorize(tool)
            return True
        except Rejected:
            return False

    def capability_report(self, context: Context, registry: Mapping[str, object],
                          server_version: str, client_observed: list[str] | None,
                          *, extra_enabled=(), extension_version: str | None = None) -> dict:
        context.authorize('system_info')
        registered = sorted(registry)
        registry_shape = {name: sorted(value) if isinstance(value, (set, frozenset)) else value
                          for name, value in registry.items()}
        base_enabled = sorted(t for t in BASE_TOOLS if t in registry and self._can(context, t))
        extension_enabled = ['capabilities']
        if self._can(context, 'file_read'):
            extension_enabled += ['read_batch', 'efficiency_metrics', 'task_handoff']
        if self._can(context, 'job_read'):
            extension_enabled += ['job_delta']
        if self._can(context, 'file_write'):
            extension_enabled += ['task_begin', 'task_create_file', 'task_checkpoint']
        enabled = sorted(set(base_enabled + extension_enabled + list(extra_enabled)))
        result = {
            'server_version': server_version,
            'extension_version': extension_version or EXTENSION_VERSION,
            'registered': registered,
            'enabled': enabled,
            'registered_count': len(registered),
            'enabled_count': len(enabled),
            'schema_sha256': digest(registry_shape),
            'catalog_revision': digest({'server_version': server_version,
                                        'extension_version': extension_version or EXTENSION_VERSION,
                                        'schema_sha256': digest(registry_shape)})[:32],
            'legacy_identifiers': {'protocol_version': '1.0',
                                   'tool_names_stable': True,
                                   'previous_extension_versions': ['1.0.1', '0.8.0-rc.1']},
            'policy_binding': context.binding,
            'client_visibility': 'unknown',
            'client_observed': False,
            'degraded_mode': False,
            'refresh_required': False,
            'client_observation_is_attestation': False,
            'security_sandbox_reported': context.security_sandbox,
            'execution_mode': context.execution_mode,
            'task_cleanup_apply_exposed': 'task_cleanup_apply' in enabled,
            'usage_import_exposed': False,
            'notes': (['cleanup apply requires a server-verified maintenance lease'] if 'task_cleanup_apply' in enabled else ['cleanup apply awaits operator exclusive-workspace binding']) +
                     ['usage ingestion remains operator-only; MCP exposes summaries only'],
        }
        if client_observed is not None:
            if not isinstance(client_observed, list) or len(client_observed) > 128:
                raise Rejected('INVALID_ARGUMENT')
            for name in client_observed:
                ident(name)
            if len(set(client_observed)) != len(client_observed):
                raise Rejected('INVALID_ARGUMENT')
            observed = set(client_observed)
            expected = set(enabled)
            result.update(client_visibility='matches' if observed == expected else 'mismatch',
                          client_observed=True,
                          degraded_mode=observed != expected,
                          refresh_required=observed != expected,
                          client_reported=sorted(observed),
                          missing_from_client=sorted(expected-observed),
                          unexpected_at_client=sorted(observed-expected))
        return result

    async def call(self, tool: str, project: str, args: dict, registry: Mapping[str, object],
                   server_version: str):
        c = self.context(project)
        if tool == 'capabilities':
            return self.capability_report(c, registry, server_version, args.get('client_observed'))
        if tool == 'read_batch':
            return await self.reads.read_batch(c, args['requests'], args.get('max_response_bytes', 65536))
        if tool == 'job_delta':
            return await self.reads.job_delta(c, args['job_id'], args.get('cursor'),
                                              args.get('max_bytes',16384), args.get('wait_ms',0))
        if tool == 'efficiency_metrics':
            c.authorize('file_read')
            return self.reads.metrics()
        if tool == 'task_begin':
            return self.ledger.begin_task(c, args['task'], args['paths'])
        if tool == 'task_create_file':
            result = await self.tasks.create_file(c, args['task'], args['op'], args['path'], args['content'])
            if result.get('ok') is not True:
                raise Rejected(result.get('error',{}).get('code','BACKEND_ERROR'))
            data = dict(result.get('data',{}))
            for key in ('backend_request_id','replayed'):
                if key in result:
                    data[key] = result[key]
            return data
        if tool == 'task_handoff':
            result = self.ledger.handoff(c, args['task'], limit=args.get('limit',50),
                                         after_sequence=args.get('after_sequence',0),
                                         snapshot_max_sequence=args.get('snapshot_max_sequence'),
                                         max_response_bytes=args.get('max_response_bytes',65536))
            include = args.get('include')
            if include is not None:
                need(isinstance(include, list) and len(include) <= 4 and
                     all(isinstance(name, str) for name in include), 'INVALID_ARGUMENT')
                need(set(include) <= {'environment'}, 'INVALID_ARGUMENT')
                if 'environment' in include:
                    provider = getattr(self, 'environment', None)
                    need(provider is not None, 'ENVIRONMENT_UNAVAILABLE')
                    result = {**result, 'environment': provider(c, args['task']),
                              'environment_is_observed_state_not_goal_completion': True}
            return result
        if tool == 'task_checkpoint':
            return self.ledger.checkpoint(c, args['task'], args['expected_revision'], args['notes'])
        raise Rejected('INVALID_ARGUMENT')

    def close(self):
        self.ledger.close()




