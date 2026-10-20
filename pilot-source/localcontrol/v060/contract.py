"""Proposed v0.6 MCP surface. Operator-only registry mutation is intentionally absent."""
from __future__ import annotations
from .core import need

BASE_V050=frozenset({
 'system_info','file_read','file_write','file_patch','file_delete','file_search','file_list','exec','job_read','job_input','job_stop','process_list',
  'capabilities','read_batch','job_delta','efficiency_metrics','task_begin','task_create_file','task_handoff','task_checkpoint','archive_terminal_jobs'})

V060_ADDITIONS={
 'workspace_catalog': {'read_only':True,'scope':'catalog','purpose':'Show operator-authorized project and collection roots; no secrets or worker manifests.'},
 'collection_inventory': {'read_only':True,'scope':'collection','purpose':'Bounded metadata/project-marker inventory. Never returns arbitrary file contents.'},
 'project_discovery_candidates': {'read_only':True,'scope':'catalog','purpose':'Read sanitized candidates produced by the pinned metadata-only host discovery adapter; never triggers arbitrary path reads.'},
 'maintenance_begin': {'read_only':False,'scope':'project_or_collection','purpose':'Acquire LocalControl-owned expiring mutation lease.'},
 'maintenance_end': {'read_only':False,'scope':'project_or_collection','purpose':'Release matching maintenance lease.'},
 'project_move_plan': {'read_only':True,'scope':'collection','purpose':'Create expiring signed same-volume relocation plan after risk scan.'},
 'project_move_apply': {'read_only':False,'scope':'collection','purpose':'Apply exact signed move under matching lease and registry revision.'},
 'project_move_status': {'read_only':True,'scope':'collection','purpose':'Read durable journal / reconciliation state.'},
 'project_move_reconcile': {'read_only':False,'scope':'collection','purpose':'Resolve an interrupted MOVED state using filesystem identity; never blindly repeats rename.'},
 'project_move_rollback': {'read_only':False,'scope':'collection','purpose':'Rollback only when destination identity proves it is the original source.'},
 'task_cleanup_plan': {'read_only':True,'scope':'project','purpose':'Existing v0.5 cleanup planner, promoted to MCP.'},
 'task_cleanup_apply': {'read_only':False,'scope':'project','purpose':'Existing guarded cleanup apply, enabled only under server-verified maintenance lease.'},
 'usage_summary': {'read_only':True,'scope':'project','purpose':'Durable imported usage distribution from trusted local adapters only.'},
 'health_status': {'read_only':True,'scope':'catalog','purpose':'Bounded soak/recovery/audit/sandbox health summary from trusted local supervisor telemetry.'},
}

V070_ADDITIONS={
 'localcontrol_context': {'read_only':True,'scope':'bootstrap','purpose':'Zero-argument bootstrap: authorized projects/scopes, features, workflows and health; no path guessing.'},
 'transaction_plan': {'read_only':True,'scope':'project','purpose':'Preflight and journal a bounded multi-file transaction with exact SHA guards; returns a signed plan.'},
 'transaction_apply': {'read_only':False,'scope':'project','purpose':'Apply a signed plan; all-or-compensated with durable journal. Partial application is never success.'},
 'transaction_status': {'read_only':True,'scope':'project','purpose':'Durable transaction state, observed file states and recovery hint.'},
 'transaction_reconcile': {'read_only':False,'scope':'project','purpose':'Resolve interrupted/indeterminate transactions from journal plus observed state; never blindly retries.'},
 'transaction_rollback': {'read_only':False,'scope':'project','purpose':'Reverse an applied transaction only when current state still matches the applied result.'},
}

V080_ADDITIONS={
 'telemetry_summary': {'read_only':True,'scope':'catalog','purpose':'Durable per-operation telemetry: summary, delta since a sequence, or bounded records. Survives restarts; model tokens stay null unless authoritative.'},
 'run_begin': {'read_only':False,'scope':'project','purpose':'Create or explicitly resume a supervised run bound to workspace identity evidence.'},
 'run_heartbeat': {'read_only':False,'scope':'project','purpose':'Renew the run lease with an owned token and bounded progress notes.'},
 'run_status': {'read_only':True,'scope':'project','purpose':'Bounded supervised-run state, tamper-evident history and optional run telemetry.'},
 'run_finish': {'read_only':False,'scope':'project','purpose':'Explicit terminal transition for an owned run; completion is never inferred.'},
}

OPERATOR_ONLY=frozenset({
 'workspace_add','workspace_remove','collection_add','collection_remove','worker_profile_provision','worker_profile_revoke',
 'usage_import','health_sample_import','registry_publish'})

FORBIDDEN_MAINTENANCE=frozenset({'exec','job_input'})

def validate_contract()->dict:
    public=set(BASE_V050)|set(V060_ADDITIONS)|set(V070_ADDITIONS)|set(V080_ADDITIONS)
    need(not (public & set(OPERATOR_ONLY)),'CONTROL_PLANE_EXPOSED')
    need(all(name not in V060_ADDITIONS and name not in V070_ADDITIONS and name not in V080_ADDITIONS
             for name in ('workspace_add','collection_add','usage_import')),'CONTROL_PLANE_EXPOSED')
    need(len(public)==46,'TOOL_CONTRACT_DRIFT')
    return {'v050_tools':len(BASE_V050),'v060_additions':len(V060_ADDITIONS),'v070_additions':len(V070_ADDITIONS),
            'v080_additions':len(V080_ADDITIONS),
            'v060_total':len(BASE_V050|set(V060_ADDITIONS)),'total':len(public),
            'operator_only_count':len(OPERATOR_ONLY),'control_plane_exposed':False}
