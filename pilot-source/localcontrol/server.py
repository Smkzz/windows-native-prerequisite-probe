"""MCP stdio integration, using the official SDK rather than a new protocol stack."""
from __future__ import annotations
import argparse
import asyncio
import json
from pathlib import Path
import sys
from . import __version__
from .errors import require
from .policy import Policy, no_links
from .backend import WinfsBackend
from .facade import Facade
from .v120_api import V120_SCHEMAS

S={'type':'string'}
I={'type':'integer'}
B={'type':'boolean'}
A={'type':'array','items':S}
SCHEMAS={
 'localcontrol_context': ('Zero-knowledge bootstrap. Call this first: returns authorized projects/scopes, tool groups, features, workflows and health. No arguments needed; project is never guessed.',
                 {'include':A,'max_response_bytes':I},[]),
 'system_info': ('Inspect enabled capabilities and safety mode. Omit project for the global catalog.',
                 {},[]),
 'file_read': ('Read bounded UTF-8 lines and a SHA-256 for future edits.',{'path':S,'offset':I,'length':I},['path']),
 'file_write': ('Create or replace one file atomically. Requires an observed SHA-256 or absent, and a unique request ID.',
                 {'path':S,'content':S,'expected_sha256':S,'request_id':S},['path','content','expected_sha256','request_id']),
 'file_patch': ('Exact occurrence-checked patch with optimistic concurrency. dry_run returns without mutation.',
                 {'path':S,'old':S,'new':S,'expected_count':I,'expected_sha256':S,'request_id':S,'dry_run':B},['path','old','new','expected_sha256','request_id']),
 'file_delete': ('Delete one regular file inside a writable project. Requires its observed SHA-256 and a unique request ID. Never deletes directories.',
                 {'path':S,'expected_sha256':S,'request_id':S},['path','expected_sha256','request_id']),
 'file_list': ('List safe direct children. No credential/control directories or reparse targets.',{'path':S,'limit':I},[]),
 'file_search': ('Bounded literal text search, skipping protected and linked files.',
                 {'path':S,'query':S,'max_files':I,'max_matches':I},['query']),
 'exec': ('Start one owned job. In the project_sandbox class (exec_mode=appcontainer) arbitrary absolute-path argv - including the governed PowerShell executable - runs autonomously inside the enrolled workspace with no per-command approval; never elevated. This ownership candidate supports Windows AppContainer execution only; recipes and trusted_local configurations are rejected at startup. Waits for short jobs.',
           {'argv':{'type':'array','items':S},'recipe':S,'wait_ms':I,'timeout_ms':I,'request_id':S,'mission_id':S},['request_id']),
 'job_read': ('Read an owned job result, optionally long-polling for completion. view=summary skips captured output and returns structured state only (use job_delta for output).',
               {'job_id':S,'wait_ms':I,'view':S},['job_id']),
 'job_input': ('Queue bounded stdin to an owned interactive job. Delivery to application is not acknowledged.',
                {'job_id':S,'text':S,'eof':B,'request_id':S},['job_id','request_id']),
  'job_stop': ('Stop only a job created by this server and scope. Never accepts a PID or process name.',
                {'job_id':S,'request_id':S},['job_id','request_id']),
  'archive_terminal_jobs': ('Archive only older terminal job receipts for this project scope into durable LocalControl history. Active jobs and recent terminal receipts are retained; safe to repeat.',
                            {'request_id':S},['request_id']),
  'process_list': ('List this scope\'s job receipts, not the host process table.',{},[]),
 'capabilities': ('Report registered, enabled and client-observed capabilities.',
                   {'client_observed':{'type':'array','items':S}},[]),
 'read_batch': ('Read up to 32 bounded text ranges or SHA-256 observations (stat=true) with change-aware response suppression.',
                 {'requests':{'type':'array','items':{'type':'object'}},'max_response_bytes':I},['requests']),
 'job_delta': ('Read only newly captured output from one owned job.',
                {'job_id':S,'cursor':S,'max_bytes':I,'wait_ms':I},['job_id']),
 'efficiency_metrics': ('Report LocalControl broker/read call and byte counters; never invents model tokens.',{},[]),
 'task_begin': ('Create an exact-path task ownership ledger entry.',
                 {'task':S,'paths':{'type':'array','items':S}},['task','paths']),
 'task_create_file': ('Create one task-authorized file through the original guarded file_write broker.',
                       {'task':S,'op':S,'path':S,'content':S},['task','op','path','content']),
 'task_handoff': ('Return bounded durable task state for safe continuation. include=["environment"] adds observed jobs, leases, unresolved moves/transactions and usage.',
                   {'task':S,'limit':I,'after_sequence':I,'snapshot_max_sequence':I,'max_response_bytes':I,'include':A},['task']),
 'task_checkpoint': ('Advance durable task notes with an expected revision guard. Notes accept objective, phase, decisions, completed, blocked_checks, blockers, next_action, vcs, inferences, untested.',
                      {'task':S,'expected_revision':I,'notes':{'type':'object'}},['task','expected_revision','notes']),
}
V060_SCHEMAS={
 'workspace_catalog': ('Show the signed operator-authorized workspace and maintenance-collection catalog.',{},[]),
 'collection_inventory': ('List bounded metadata for direct children of one authorized collection; never reads arbitrary file contents.',
                          {'collection':S,'limit':I},['collection']),
 'project_discovery_candidates': ('Read bounded sanitized candidates from the operator-owned metadata-only discovery report.',{'limit':I},[]),
 'maintenance_begin': ('Acquire an expiring LocalControl-only mutation lease across authorized scopes. Refuses active owned jobs.',
                       {'scopes':{'type':'array','items':S},'purpose':S,'ttl_s':I,'request_id':S},['scopes','purpose','request_id']),
 'maintenance_end': ('Release a matching maintenance lease; replay-safe.',
                     {'lease_id':S,'scope':S,'request_id':S},['lease_id','scope','request_id']),
 'project_move_plan': ('Build an expiring signed same-volume directory-move plan after bounded dependency and reparse risk scanning.',
                       {'source_scope':S,'source_relative':S,'collection':S,'destination_relative':S,'lease_id':S,'ttl_s':I},
                       ['source_scope','collection','destination_relative','lease_id']),
 'project_move_apply': ('Apply one exact signed same-volume move under its lease. Warning codes must be acknowledged exactly.',
                        {'plan':S,'lease_id':S,'acknowledged_warnings':{'type':'array','items':S},'request_id':S},
                        ['plan','lease_id','request_id']),
 'project_move_status': ('Read durable state for one move plan without mutating it.',{'plan_id':S},['plan_id']),
 'project_move_reconcile': ('Reconcile an interrupted move from durable journal plus Windows filesystem identity; never blindly retries rename.',
                            {'plan_id':S,'lease_id':S,'request_id':S},['plan_id','lease_id','request_id']),
 'project_move_rollback': ('Rollback only when destination identity and full tree fingerprint prove it is the original source.',
                           {'plan_id':S,'lease_id':S,'request_id':S},['plan_id','lease_id','request_id']),
 'task_cleanup_plan': ('Plan cleanup of task-owned files under a verified maintenance lease.',
                       {'task':S,'lease_id':S,'max_files':I},['task','lease_id']),
 'task_cleanup_apply': ('Apply the guarded task-owned cleanup plan under the verified lease. Never deletes directories.',
                        {'plan':S,'lease_id':S,'request_id':S},['plan','lease_id','request_id']),
 'usage_summary': ('Read durable normalized token usage imported only by trusted local adapters, grouped by task/model/stage.',
                   {'task':S},[]),
 'health_status': ('Read current LocalControl health plus durable trusted supervisor telemetry.',{'since_ns':I},[]),
 'transaction_plan': ('Preflight and journal a bounded multi-file transaction (create/replace/patch/delete) with exact SHA guards; returns a signed plan token.',
                      {'operations':{'type':'array','items':{'type':'object'}},'ttl_s':I,'mission_id':S},['operations']),
 'transaction_apply': ('Apply one signed transaction plan. All operations commit or the applied prefix is compensated; partial application is never reported as success.',
                        {'plan':S,'request_id':S,'mission_id':S},['plan','request_id']),
 'transaction_status': ('Read durable transaction state, observed file states and recovery hint.',{'plan_id':S},['plan_id']),
 'transaction_reconcile': ('Resolve an interrupted or indeterminate transaction from the durable journal and observed file state. strategy=rollback (default) compensates; strategy=forward completes remaining operations under their exact guards.',
                           {'plan_id':S,'request_id':S,'strategy':S},['plan_id','request_id']),
 'transaction_rollback': ('Reverse an applied transaction only when current file state still matches the applied result.',
                          {'plan_id':S,'request_id':S},['plan_id','request_id']),
}
V080_SCHEMAS={
 'telemetry_summary': ('Read durable per-operation telemetry (summary, delta since a sequence, or bounded records). Totals survive restarts; unknown model-token fields stay null.',
                       {'view':S,'run_id':S,'tool':S,'since_ns':I,'after_sequence':I,'limit':I,'max_response_bytes':I},[]),
 'run_begin': ('Create or explicitly resume a supervised run bound to the workspace identity. Resume classifies divergence and requires accept_divergence when it is not \'same\'.',
               {'objective':S,'run_id':S,'continuation_id':S,'ttl_s':I,'watch_paths':A,
                'accept_divergence':S,'takeover':B,'token':S,'request_id':S},['request_id']),
 'run_heartbeat': ('Renew the run lease with an owned token and optionally merge bounded progress notes.',
                   {'run_id':S,'token':S,'notes':{'type':'object'},'ttl_s':I,'request_id':S},
                   ['run_id','token','request_id']),
 'run_status': ('Read bounded supervised-run state, tamper-evident history and optional telemetry for the run.',
                {'run_id':S,'include':A,'max_response_bytes':I},[]),
 'run_finish': ('Explicitly finish an owned run. Completion is never inferred; interrupted runs must be resumed before finishing.',
                {'run_id':S,'token':S,'state':S,'summary':S,'request_id':S},
                ['run_id','token','state','request_id']),
}


V100_SCHEMAS={
 'mission_begin': ('Create a durable mission bound to the workspace identity, an immutable authority snapshot and explicit resource budgets. Completion is never granted by the caller; only the independent verifier may mark it SUCCEEDED.',
                   {'objective':S,'ttl_s':I,'watch_paths':A,'success_contract':{'type':'object'},
                    'budgets':{'type':'object'},'request_id':S,'trust_origin':S},['objective','request_id']),
 'mission_status': ('Read mission state, evidence, verification and schedules. Omit mission_id to list missions and schedules.',
                    {'mission_id':S,'state':S,'limit':I,'include':A,'max_response_bytes':I},[]),
 'mission_checkpoint': ('Advance mission notes/evidence and lease with an owned token and optional expected revision guard.',
                        {'mission_id':S,'token':S,'expected_revision':I,'notes':{'type':'object'},
                         'evidence':{'type':'array','items':{'type':'object'}},'state':S,'ttl_s':I,'request_id':S},
                        ['mission_id','token','request_id']),
 'mission_resume': ('Resume an interrupted or waiting mission after re-classifying workspace identity. Non-same divergence must be explicitly accepted.',
                    {'mission_id':S,'token':S,'accept_divergence':S,'ttl_s':I,'request_id':S},
                    ['mission_id','request_id']),
 'mission_finish': ('Request completion. Moves the mission to VERIFYING; the deterministic verifier evaluates the success contract and only it can commit SUCCEEDED.',
                    {'mission_id':S,'token':S,'summary':S,'request_id':S},
                    ['mission_id','token','request_id']),
 'mission_cancel': ('Cancel an owned mission (or abandon it with takeover when the lease is stale).',
                    {'mission_id':S,'token':S,'reason':S,'abandon':B,'takeover':B,'request_id':S},
                    ['mission_id','request_id']),
 'mission_schedule': ('Create, list, inspect or cancel durable schedules for queued, delayed, recurring, dependency-bound and retried missions.',
                      {'action':S,'schedule_id':S,'objective':S,'ttl_s':I,'watch_paths':A,
                       'success_contract':{'type':'object'},'budgets':{'type':'object'},'delay_s':I,'run_at_ns':I,
                       'recur_s':I,'depends_on':S,'max_attempts':I,'backoff_base_s':I,'backoff_max_s':I,
                       'deadline_s':I,'grace_s':I,'state':S,'limit':I,'reason':S,'request_id':S},[]),
 'state_backup': ('Create, list, verify or inspect verified backups of authoritative LocalControl state.',
                  {'action':S,'label':S,'backup_id':S,'limit':I},[]),
 'state_restore': ('Stage a verified restore of authoritative state. The staged restore is applied idempotently at the next LocalControl start, before any store opens.',
                   {'action':S,'backup_id':S,'confirm':S},[]),
}

V110_SCHEMAS={
 'agent_spawn': ('Create and start a delegated provider sub-agent bound to this project. Authority (workspace, sandbox profile, budgets, lineage) is bound server-side; dedupe_key returns the same agent for safe retries.',
                  {'task':S,'profile':S,'model':S,'effort':S,'workspace_mode':S,'workspace_path':S,
                   'base_ref':S,'dedupe_key':S,'output_schema':{'type':'object'},'timeout_s':I,
                   'wait_ms':I,'request_id':S},['task','request_id']),
 'agent_send': ('Steer a running agent\'s active turn, or start a new turn on an idle/completed agent.',
                 {'agent_id':S,'input':S,'output_schema':{'type':'object'},'wait_ms':I,'request_id':S},
                 ['agent_id','input','request_id']),
 'agent_status': ('Read an agent\'s durable state; wait_ms long-polls until a result-bearing state. include may add events, result, provider detail.',
                   {'agent_id':S,'include':A,'wait_ms':I},['agent_id']),
 'agent_result': ('Read an agent\'s final result, files changed and token usage; wait_ms long-polls until the turn resolves.',
                   {'agent_id':S,'wait_ms':I},['agent_id']),
 'agent_events': ('Read the tamper-evident lifecycle event log for an agent, paged by cursor.',
                   {'agent_id':S,'cursor':I,'limit':I},['agent_id']),
 'agent_list': ('List agents for this project scope (or all project scopes when project is omitted).',
                 {'state':S,'limit':I,'include_archived':B},[]),
 'agent_cancel': ('Cancel an agent: interrupts the active provider turn, tears down its owned process tree and revokes its delegation token.',
                   {'agent_id':S,'reason':S,'request_id':S},['agent_id','request_id']),
 'agent_resume': ('Recover an interrupted or failed agent: respawns the provider session and reattaches its durable thread, optionally starting a new turn.',
                   {'agent_id':S,'input':S,'output_schema':{'type':'object'},'wait_ms':I,'request_id':S},
                   ['agent_id','request_id']),
 'agent_fork': ('Fork an agent\'s provider thread into a new agent sharing history; optionally start it on a new task.',
                 {'agent_id':S,'task':S,'wait_ms':I,'request_id':S},['agent_id','request_id']),
 'agent_cleanup': ('Archive terminal agent records; confirm=delete_artifacts also removes managed worktrees and delegated homes.',
                    {'agent_id':S,'all_terminal':B,'confirm':S,'request_id':S},['request_id']),
 'agent_capabilities': ('Report delegation providers, permission profiles, limits, recovery semantics and protocol details.',{},[]),
}


def make_tools(v060_enabled: bool = False, v080_enabled: bool = False, v100_enabled: bool = False,
               v110_enabled: bool = False, v120_enabled: bool = False):
    from mcp import types
    readonly={'localcontrol_context','system_info','file_read','file_list','file_search','job_read','process_list',
              'capabilities','read_batch','job_delta','efficiency_metrics','task_handoff',
              'workspace_catalog','collection_inventory','project_discovery_candidates','project_move_plan',
              'project_move_status','task_cleanup_plan','usage_summary','health_status',
              'transaction_plan','transaction_status','telemetry_summary','run_status','mission_status',
              'agent_status','agent_result','agent_events','agent_list','agent_capabilities',
              'task_scope_info','task_worker_observe'}
    destructive={'task_worker_launch','task_worker_stop','task_worker_recover','task_worker_cleanup','file_write','file_patch','file_delete','exec','job_input','job_stop','archive_terminal_jobs','task_create_file',
                 'project_move_apply','project_move_reconcile','project_move_rollback','task_cleanup_apply',
                 'transaction_apply','transaction_reconcile','transaction_rollback',
                 'run_begin','run_heartbeat','run_finish',
                 'mission_begin','mission_checkpoint','mission_resume','mission_finish','mission_cancel',
                 'mission_schedule','state_backup','state_restore',
                 'agent_spawn','agent_send','agent_cancel','agent_resume','agent_fork','agent_cleanup'}
    idempotent=readonly|{'task_worker_launch','task_worker_stop','task_worker_recover','task_worker_cleanup','exec','file_write','file_patch','file_delete','job_input','job_stop','archive_terminal_jobs','task_begin','task_create_file',
                         'maintenance_begin','maintenance_end','project_move_apply','project_move_reconcile','project_move_rollback',
                         'task_cleanup_apply','transaction_plan','transaction_apply','transaction_reconcile','transaction_rollback',
                         'run_begin','run_heartbeat','run_finish',
                         'mission_begin','mission_checkpoint','mission_resume','mission_finish','mission_cancel',
                         'mission_schedule','state_restore',
                         'agent_spawn','agent_send','agent_cancel','agent_resume','agent_fork','agent_cleanup'}
    idempotent.add('resource_preflight')
    destructive.add('resource_preflight')
    catalog={**SCHEMAS,
             **(V060_SCHEMAS if v060_enabled else {}),
             **(V080_SCHEMAS if v080_enabled else {}),
             **(V100_SCHEMAS if v100_enabled else {}),
             **(V110_SCHEMAS if v110_enabled else {}),
             **(V120_SCHEMAS if v120_enabled else {})}
    tools=[]
    for name,(description,properties,required) in catalog.items():
        props={'project':S,**properties}
        tools.append(types.Tool(name=name,description=description,
             inputSchema={'type':'object','properties':props,'required':list(required),'additionalProperties':False},
             annotations=types.ToolAnnotations(readOnlyHint=name in readonly,
               destructiveHint=name in destructive,
               idempotentHint=name in idempotent,
               openWorldHint=name in {'exec','job_input'})))
    return tools


def require_host_execution_acknowledged(exec_mode: str, acknowledged: bool) -> None:
    """Tier B boundary: trusted_host execution exists only behind an explicit
    operator acknowledgement at server start. The project_sandbox class never
    consults this; nothing in a tool call can promote a job to trusted host."""
    require(exec_mode != 'trusted_local' or acknowledged,
            'HOST_EXEC_NOT_ACKNOWLEDGED',
            'Trusted execution needs --acknowledge-host-execution; not a sandbox')


async def serve(config_path: Path, acknowledge_host_execution: bool = False):
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
    from mcp import types
    no_links(config_path)
    raw=json.loads(config_path.read_text(encoding='utf-8'))
    keys=set(raw);require({'policy','winfs'} <= keys <= {'policy','winfs','v060','v080','v100','v110','v120'},'INVALID_CONFIG','Expected policy/winfs and optional v060/v080/v100/v110/v120 settings')
    v060_enabled='v060' in raw
    v080_enabled='v080' in raw
    v100_enabled='v100' in raw
    v110_enabled='v110' in raw
    v120_enabled='v120' in raw
    require(not v080_enabled or v060_enabled,'INVALID_CONFIG','v0.8 requires the v0.6 maintenance family')
    require(not v100_enabled or v080_enabled,'INVALID_CONFIG','v1.0 requires the v0.8 supervision family')
    require(not v110_enabled or v100_enabled,'INVALID_CONFIG','v1.1 requires the v1.0 autonomy family')
    require(not v120_enabled or v060_enabled,'INVALID_CONFIG','v1.2 requires the v0.6 signed registry family')
    require(not v120_enabled or raw.get('v120') == {'enabled': True},'INVALID_CONFIG','v1.2 options must be exactly {enabled: true}')
    if v100_enabled:
        from .v100 import backup as backup_mod
        applied=backup_mod.apply_pending_restore(Path(raw['policy']['state_dir']))
        if applied.get('applied'):
            print(f"applied staged restore {applied.get('backup_id')} ({len(applied.get('files', []))} files)",file=sys.stderr)
    else:
        applied={'applied': False}
    policy=Policy.from_dict(raw['policy'])
    require(not any(config_path.resolve().is_relative_to(p.root) for p in policy.projects.values()),
            'INVALID_CONFIG','Operator config must be outside projects')
    require_host_execution_acknowledged(policy.exec_mode, acknowledge_host_execution)
    if policy.exec_mode=='trusted_local':
        print('WARNING: trusted-local host execution is NOT an OS security sandbox. Do not expose via a remote relay.',file=sys.stderr)
    policy.state_dir.mkdir(parents=True,exist_ok=True)
    backend=WinfsBackend(policy,raw['winfs']['node'],raw['winfs']['entry'])
    facade=Facade(policy,backend,v060_options=raw.get('v060'),v080_options=raw.get('v080'),
                  v100_options=raw.get('v100'),v110_options=raw.get('v110'),
                  v120_options=raw.get('v120'),
                  config_path=config_path if (v060_enabled or v080_enabled or v100_enabled
                                              or v110_enabled or v120_enabled) else None)
    server=Server('LocalControl',version=__version__)
    @server.list_tools()
    async def tools():
        return make_tools(v060_enabled, v080_enabled, v100_enabled, v110_enabled, v120_enabled)
    @server.call_tool()
    async def call(name: str, arguments: dict):
        project=arguments.pop('project', '')
        result=await facade.call(name,project,arguments)
        return types.CallToolResult(content=[types.TextContent(type='text',text=json.dumps(result,ensure_ascii=True))],
                                    structuredContent=result,isError=not result['ok'])
    scheduler_task=None
    if v100_enabled:
        scheduler_task=asyncio.create_task(facade.scheduler_loop())
    try:
        async with backend.connected():
            async with stdio_server() as (read,write):
                await server.run(read,write,server.create_initialization_options())
    finally:
        if scheduler_task is not None:
            scheduler_task.cancel()
        facade.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--acknowledge-host-execution',action='store_true')
    args=parser.parse_args()
    try:
        asyncio.run(serve(args.config.resolve(),args.acknowledge_host_execution))
    except KeyboardInterrupt:
        pass

if __name__=='__main__':
    main()


