"""Static, machine-readable protocol metadata. Data only: no I/O, no secrets.

Agents should not need large external instructions. This module describes tool
categories, per-operation lifecycle requirements (request IDs, SHA guards,
leases, plans) and the multi-step workflows that connect them. The metadata is
bounded and safe for any authenticated MCP client; it never contains paths,
credentials or policy values beyond the fixed tool names.
"""
from __future__ import annotations

PROTOCOL_VERSION = '1.0'
SCHEMA_VERSION = 2

# Every registered tool appears in exactly one category.
TOOL_GROUPS = {
    'bootstrap': ('localcontrol_context',),
    'discovery': ('system_info', 'capabilities', 'workspace_catalog', 'collection_inventory',
                  'project_discovery_candidates', 'health_status', 'usage_summary'),
    'files': ('file_read', 'file_list', 'file_search', 'read_batch',
              'file_write', 'file_patch', 'file_delete'),
    'execution': ('exec', 'job_read', 'job_delta', 'job_input', 'job_stop', 'archive_terminal_jobs', 'process_list'),
    'tasks': ('task_begin', 'task_create_file', 'task_checkpoint', 'task_handoff',
              'task_cleanup_plan', 'task_cleanup_apply'),
    'maintenance': ('maintenance_begin', 'maintenance_end', 'project_move_plan', 'project_move_apply',
                    'project_move_status', 'project_move_reconcile', 'project_move_rollback'),
    'transactions': ('transaction_plan', 'transaction_apply', 'transaction_status',
                     'transaction_reconcile', 'transaction_rollback'),
    'supervision': ('run_begin', 'run_heartbeat', 'run_status', 'run_finish'),
    'missions': ('mission_begin', 'mission_checkpoint', 'mission_resume', 'mission_finish', 'mission_cancel',
                 'mission_schedule', 'mission_status'),
    'agents': ('agent_spawn', 'agent_send', 'agent_status', 'agent_result', 'agent_events',
               'agent_list', 'agent_cancel', 'agent_resume', 'agent_fork', 'agent_cleanup',
               'agent_capabilities'),
    'recovery': ('state_backup', 'state_restore'),
    'telemetry': ('efficiency_metrics', 'telemetry_summary'),
}

_R = 'safe_retry'

# scope: bootstrap|project|global; mutating: durable or project mutation;
# request_id: required|optional|none; sha_guard: required|conditional|none;
# recovery: safe_retry|reconcile|rollback|operator.
OPERATIONS = {
    'localcontrol_context':      {'scope': 'bootstrap', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': []},
    'system_info':               {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': ['localcontrol_context']},
    'capabilities':              {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': ['localcontrol_context']},
    'file_read':                 {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['sha256'], 'consumes': [], 'depends_on': []},
    'file_list':                 {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': []},
    'file_search':               {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': []},
    'read_batch':                {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['sha256'], 'consumes': ['previous'], 'depends_on': []},
    'file_write':                {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'required', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['sha256'], 'consumes': ['sha256'], 'depends_on': ['file_read']},
    'file_patch':                {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'required', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['sha256'], 'consumes': ['sha256'], 'depends_on': ['file_read']},
    'file_delete':               {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'required', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['sha256'], 'depends_on': ['file_read']},
    'exec':                      {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': ['execution_enabled'], 'produces': ['job_id'], 'consumes': ['generation', 'fence_token'], 'depends_on': []},
    'job_read':                  {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['job_id'], 'depends_on': ['exec']},
    'job_delta':                 {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['cursor'], 'consumes': ['job_id', 'cursor'], 'depends_on': ['exec']},
    'job_input':                 {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['job_id'], 'depends_on': ['exec']},
    'job_stop':                  {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['job_id'], 'depends_on': ['exec']},
    'archive_terminal_jobs':     {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['archived_job_ids'], 'consumes': [], 'depends_on': ['exec']},
    'process_list':              {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': []},
    'efficiency_metrics':        {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': []},
    'task_begin':                {'scope': 'project', 'mutating': True, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['task'], 'consumes': [], 'depends_on': []},
    'task_create_file':          {'scope': 'project', 'mutating': True, 'request_id': 'none', 'sha_guard': 'conditional', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['task_begin'], 'produces': ['sha256'], 'consumes': ['task', 'op'], 'depends_on': ['task_begin']},
    'task_checkpoint':           {'scope': 'project', 'mutating': True, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': False, 'recovery': _R, 'requires': ['task_begin'], 'produces': ['revision'], 'consumes': ['revision'], 'depends_on': ['task_begin']},
    'task_handoff':              {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': ['task_begin'], 'produces': [], 'consumes': ['task'], 'depends_on': ['task_begin']},
    'task_cleanup_plan':         {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': ['lease'], 'produces': ['plan'], 'consumes': ['task'], 'depends_on': ['maintenance_begin', 'task_begin']},
    'task_cleanup_apply':        {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'conditional', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['lease'], 'produces': [], 'consumes': ['plan', 'lease_id'], 'depends_on': ['task_cleanup_plan']},
    'workspace_catalog':         {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': ['localcontrol_context']},
    'collection_inventory':      {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['collection'], 'depends_on': ['workspace_catalog']},
    'project_discovery_candidates': {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': ['workspace_catalog']},
    'maintenance_begin':         {'scope': 'global', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['lease_id'], 'consumes': ['scopes'], 'depends_on': ['workspace_catalog']},
    'maintenance_end':           {'scope': 'global', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['lease_id'], 'depends_on': ['maintenance_begin']},
    'project_move_plan':         {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': ['lease'], 'produces': ['plan_id', 'plan'], 'consumes': ['lease_id'], 'depends_on': ['maintenance_begin']},
    'project_move_apply':        {'scope': 'global', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['lease'], 'produces': ['plan_id'], 'consumes': ['plan', 'lease_id'], 'depends_on': ['project_move_plan']},
    'project_move_status':       {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['plan_id'], 'depends_on': ['project_move_plan']},
    'project_move_reconcile':    {'scope': 'global', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['lease'], 'produces': [], 'consumes': ['plan_id'], 'depends_on': ['project_move_status']},
    'project_move_rollback':     {'scope': 'global', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'rollback', 'requires': ['lease'], 'produces': [], 'consumes': ['plan_id'], 'depends_on': ['project_move_status']},
    'transaction_plan':          {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'conditional', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['plan_id', 'plan'], 'consumes': ['sha256', 'generation', 'fence_token'], 'depends_on': ['file_read']},
    'transaction_apply':         {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'conditional', 'idempotent': True, 'recovery': 'reconcile', 'requires': [], 'produces': ['sha256'], 'consumes': ['plan', 'generation', 'fence_token'], 'depends_on': ['transaction_plan']},
    'transaction_status':        {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['plan_id'], 'depends_on': ['transaction_plan']},
    'transaction_reconcile':     {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': [], 'produces': [], 'consumes': ['plan_id', 'strategy'], 'depends_on': ['transaction_status']},
    'transaction_rollback':      {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'rollback', 'requires': [], 'produces': [], 'consumes': ['plan_id'], 'depends_on': ['transaction_status']},
    'usage_summary':             {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['task'], 'depends_on': []},
    'health_status':             {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': []},
    'telemetry_summary':         {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['sequence'], 'consumes': ['after_sequence'], 'depends_on': []},
    'run_begin':                 {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['workspace_identity'], 'produces': ['run_id', 'token'], 'consumes': ['run_id', 'accept_divergence'], 'depends_on': []},
    'run_heartbeat':             {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': ['run_token'], 'produces': ['token'], 'consumes': ['run_id', 'token'], 'depends_on': ['run_begin']},
    'run_status':                {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['run_id'], 'depends_on': ['run_begin']},
    'run_finish':                {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['run_token'], 'produces': [], 'consumes': ['run_id', 'token'], 'depends_on': ['run_begin']},
    'mission_begin':             {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['workspace_identity'], 'produces': ['mission_id', 'token'], 'consumes': [], 'depends_on': []},
    'mission_status':            {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['mission_id'], 'depends_on': ['mission_begin']},
    'mission_checkpoint':        {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': ['mission_token'], 'produces': ['revision', 'token'], 'consumes': ['mission_id', 'token', 'expected_revision'], 'depends_on': ['mission_begin']},
    'mission_resume':            {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['workspace_identity'], 'produces': ['token'], 'consumes': ['mission_id', 'accept_divergence'], 'depends_on': ['mission_begin']},
    'mission_finish':            {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['mission_token'], 'produces': ['verification'], 'consumes': ['mission_id', 'token'], 'depends_on': ['mission_begin']},
    'mission_cancel':            {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': ['mission_token'], 'produces': [], 'consumes': ['mission_id', 'token'], 'depends_on': ['mission_begin']},
    'mission_schedule':          {'scope': 'global', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['schedule_id'], 'consumes': ['depends_on'], 'depends_on': []},
    'state_backup':              {'scope': 'global', 'mutating': True, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': False, 'recovery': _R, 'requires': [], 'produces': ['backup_id'], 'consumes': [], 'depends_on': []},
    'state_restore':             {'scope': 'global', 'mutating': True, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['backup'], 'produces': ['restore'], 'consumes': ['backup_id'], 'depends_on': ['state_backup']},
    'agent_capabilities':        {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['profiles', 'provider_status'], 'consumes': [], 'depends_on': ['localcontrol_context']},
    'agent_spawn':               {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': ['v110_enabled'], 'produces': ['agent_id'], 'consumes': ['dedupe_key'], 'depends_on': ['agent_capabilities']},
    'agent_send':                {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['turn_id'], 'consumes': ['agent_id'], 'depends_on': ['agent_spawn']},
    'agent_status':              {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['state'], 'consumes': ['agent_id'], 'depends_on': ['agent_spawn']},
    'agent_result':              {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['result'], 'consumes': ['agent_id'], 'depends_on': ['agent_spawn']},
    'agent_events':              {'scope': 'project', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': ['cursor'], 'consumes': ['agent_id', 'cursor'], 'depends_on': ['agent_spawn']},
    'agent_list':                {'scope': 'global', 'mutating': False, 'request_id': 'none', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': [], 'depends_on': ['agent_spawn']},
    'agent_cancel':              {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['agent_id'], 'depends_on': ['agent_spawn']},
    'agent_resume':              {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': [], 'produces': [], 'consumes': ['agent_id'], 'depends_on': ['agent_status']},
    'agent_fork':                {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': 'reconcile', 'requires': [], 'produces': ['agent_id', 'thread_id'], 'consumes': ['agent_id'], 'depends_on': ['agent_spawn']},
    'agent_cleanup':             {'scope': 'project', 'mutating': True, 'request_id': 'required', 'sha_guard': 'none', 'idempotent': True, 'recovery': _R, 'requires': [], 'produces': [], 'consumes': ['agent_id'], 'depends_on': ['agent_status']},
}

WORKFLOWS = {
    'bootstrap': {'steps': ['localcontrol_context', 'capabilities'], 'note': 'optional arguments; projects are discovered, never guessed'},
    'move': {'plan': 'project_move_plan', 'apply': 'project_move_apply', 'inspect': 'project_move_status',
             'recover': 'project_move_reconcile', 'reverse': 'project_move_rollback',
             'requires_lease': True, 'lease': 'maintenance_begin'},
    'cleanup': {'plan': 'task_cleanup_plan', 'apply': 'task_cleanup_apply',
                'requires_lease': True, 'lease': 'maintenance_begin'},
    'transaction': {'plan': 'transaction_plan', 'apply': 'transaction_apply', 'inspect': 'transaction_status',
                    'recover': 'transaction_reconcile', 'reverse': 'transaction_rollback',
                    'requires_lease': False, 'all_or_nothing': 'compensated'},
    'continuation': {'begin': 'task_begin', 'checkpoint': 'task_checkpoint',
                     'resume': 'task_handoff', 'environment': "task_handoff include=['environment']"},
    'execution': {'start': 'exec', 'observe': 'job_read', 'delta': 'job_delta',
                  'input': 'job_input', 'stop': 'job_stop', 'reclaim': 'archive_terminal_jobs'},
    'supervision': {'begin': 'run_begin', 'heartbeat': 'run_heartbeat', 'status': 'run_status',
                    'finish': 'run_finish', 'telemetry': 'telemetry_summary',
                    'resume': 'run_begin run_id=<id> with accept_divergence when classified differently',
                    'bootstrap': "localcontrol_context include=['run','telemetry']"},
    'delegation': {'spawn': 'agent_spawn', 'steer': 'agent_send', 'observe': 'agent_status',
                   'wait': 'agent_status wait_ms=<ms>', 'collect': 'agent_result',
                   'events': 'agent_events', 'stop': 'agent_cancel',
                   'recover': 'agent_resume (interrupted/failed only)',
                   'fork': 'agent_fork', 'retire': 'agent_cleanup',
                   'discover': 'agent_capabilities, agent_list',
                   'recursion': 'delegate-capable children use only lc_agent_* tools via the '
                                'LocalControl-owned delegation shim'},
}


def validate_protocol(tool_names) -> dict:
    """Fail closed if metadata and the registered surface drift apart.

    A configuration may enable a subset of the documented surface (for example
    v0.6 without v0.8), so registered names must be covered by the metadata
    rather than equal to it.
    """
    names = set(tool_names)
    grouped = [name for group in TOOL_GROUPS.values() for name in group]
    if len(grouped) != len(set(grouped)):
        raise ValueError('PROTOCOL_GROUP_DUPLICATE')
    if set(grouped) != set(OPERATIONS):
        raise ValueError('PROTOCOL_OPERATION_DRIFT')
    if not names <= set(OPERATIONS):
        raise ValueError('PROTOCOL_CATALOG_DRIFT')
    return {'protocol_version': PROTOCOL_VERSION, 'schema_version': SCHEMA_VERSION,
            'groups': {name: list(members) for name, members in TOOL_GROUPS.items()},
            'operations': {name: dict(spec) for name, spec in OPERATIONS.items()}}

