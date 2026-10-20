"""LocalControl v1.0 public surface: mission runtime and recovery tools."""
from __future__ import annotations

from ..nextlib.core import need
from ..v060.contract import BASE_V050, OPERATOR_ONLY, V060_ADDITIONS, V070_ADDITIONS, V080_ADDITIONS

V100_ADDITIONS = {
    'mission_begin': {'read_only': False, 'scope': 'project',
                      'purpose': 'Create a durable mission bound to workspace identity, an immutable authority snapshot and budgets.'},
    'mission_status': {'read_only': True, 'scope': 'catalog',
                       'purpose': 'Bounded mission state, evidence, verification and schedules.'},
    'mission_checkpoint': {'read_only': False, 'scope': 'project',
                           'purpose': 'Owned-token checkpoint with revision guard and trust-classified evidence.'},
    'mission_resume': {'read_only': False, 'scope': 'project',
                       'purpose': 'Resume after recovery with workspace re-classification and explicit divergence acceptance.'},
    'mission_finish': {'read_only': False, 'scope': 'project',
                       'purpose': 'Request completion; only the independent verifier may commit SUCCEEDED.'},
    'mission_cancel': {'read_only': False, 'scope': 'project',
                       'purpose': 'Cancel an owned mission; takeover only when the lease is stale.'},
    'mission_schedule': {'read_only': False, 'scope': 'catalog',
                         'purpose': 'Queued, delayed, recurring, dependency-bound and retried durable schedules.'},
    'state_backup': {'read_only': False, 'scope': 'catalog',
                     'purpose': 'Create, list and verify hashed backups of authoritative state.'},
    'state_restore': {'read_only': False, 'scope': 'catalog',
                      'purpose': 'Stage a verified restore applied idempotently at the next start.'},
}


def validate_contract_v100() -> dict:
    public = (set(BASE_V050) | set(V060_ADDITIONS) | set(V070_ADDITIONS) | set(V080_ADDITIONS)
              | set(V100_ADDITIONS))
    need(not (public & set(OPERATOR_ONLY)), 'CONTROL_PLANE_EXPOSED')
    need(len(public) == 55, 'TOOL_CONTRACT_DRIFT')
    return {'v050_tools': len(BASE_V050), 'v060_additions': len(V060_ADDITIONS),
            'v070_additions': len(V070_ADDITIONS), 'v080_additions': len(V080_ADDITIONS),
            'v100_additions': len(V100_ADDITIONS), 'total': len(public),
            'operator_only_count': len(OPERATOR_ONLY), 'control_plane_exposed': False}
