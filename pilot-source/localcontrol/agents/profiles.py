"""Permission profiles for delegated agents.

A profile is the ONLY way a caller selects provider permissions: parents pick a
name; the operator owns the definitions. Callers can never supply raw sandbox
flags, writable roots, network access, or approval policies — those resolve
server-side from the profile. `danger_full_access` exists only for explicit
operator-configured profiles and is never part of a bundled default.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..nextlib.core import Rejected, need

CODEX_SANDBOXES = frozenset({'read_only', 'workspace_write', 'danger_full_access'})
PROFILE_KEYS = frozenset({
    'codex_sandbox', 'writable_roots_mode', 'network', 'can_delegate', 'delegate_profile',
    'requires_os_sandbox', 'max_runtime_s', 'max_turns', 'max_children', 'max_depth',
    'stall_timeout_s', 'idle_retain_s', 'description',
})


@dataclass(frozen=True)
class Profile:
    name: str
    codex_sandbox: str                 # read_only | workspace_write | danger_full_access
    writable_roots_mode: str           # none | workspace
    network: bool                      # provider network capability inside sandboxed exec
    can_delegate: bool                 # child gets the LocalControl delegation shim
    delegate_profile: str | None       # profile granted to children (None -> self minus delegation)
    requires_os_sandbox: bool          # windowsSandbox/readiness must be 'ready'
    max_runtime_s: int                 # hard per-turn ceiling
    max_turns: int                     # total turns over the agent's life
    max_children: int
    max_depth: int                     # lineage depth ceiling for descendants
    stall_timeout_s: int               # no provider progress -> interrupt
    idle_retain_s: int                 # warm session keepalive after a turn ends
    description: str = ''

    @property
    def confined_write(self) -> bool:
        return self.codex_sandbox == 'workspace_write'


DEFAULT_PROFILES = {
    'read_only': {
        'codex_sandbox': 'read_only', 'writable_roots_mode': 'none', 'network': False,
        'can_delegate': False, 'requires_os_sandbox': True, 'max_runtime_s': 900,
        'max_turns': 4, 'max_children': 0, 'max_depth': 0, 'stall_timeout_s': 300,
        'idle_retain_s': 300,
        'description': 'Read-only analysis agent. No writes, no delegation, OS-sandboxed.'},
    'workspace_write': {
        'codex_sandbox': 'workspace_write', 'writable_roots_mode': 'workspace', 'network': False,
        'can_delegate': False, 'requires_os_sandbox': True, 'max_runtime_s': 1800,
        'max_turns': 8, 'max_children': 0, 'max_depth': 0, 'stall_timeout_s': 600,
        'idle_retain_s': 300,
        'description': 'Autonomous coding agent confined to its assigned workspace.'},
    'project_autonomous': {
        'codex_sandbox': 'workspace_write', 'writable_roots_mode': 'workspace', 'network': False,
        'can_delegate': True, 'requires_os_sandbox': True, 'max_runtime_s': 3600,
        'max_turns': 16, 'max_children': 4, 'max_depth': 2, 'stall_timeout_s': 900,
        'idle_retain_s': 600,
        'description': 'Workspace-confined agent allowed bounded recursive delegation '
                       'through LocalControl.'},
}


def _int(value, lo: int, hi: int, code: str) -> int:
    need(type(value) is int and lo <= value <= hi, code)
    return value


def _bool(value, code: str) -> bool:
    need(type(value) is bool, code)
    return value


def _build(name: str, spec: dict) -> Profile:
    need(isinstance(spec, dict) and set(spec) <= PROFILE_KEYS, 'PROFILE_CONFIG')
    sandbox = spec.get('codex_sandbox', 'read_only')
    need(sandbox in CODEX_SANDBOXES, 'PROFILE_CONFIG')
    roots_mode = spec.get('writable_roots_mode', 'workspace' if sandbox != 'read_only' else 'none')
    need(roots_mode in ('none', 'workspace'), 'PROFILE_CONFIG')
    need(not (sandbox == 'read_only' and roots_mode == 'workspace'), 'PROFILE_CONFIG')
    can_delegate = _bool(spec.get('can_delegate', False), 'PROFILE_CONFIG')
    delegate_profile = spec.get('delegate_profile')
    need(delegate_profile is None or isinstance(delegate_profile, str) and 0 < len(delegate_profile) <= 64,
         'PROFILE_CONFIG')
    return Profile(
        name=name,
        codex_sandbox=sandbox,
        writable_roots_mode=roots_mode,
        network=_bool(spec.get('network', False), 'PROFILE_CONFIG'),
        can_delegate=can_delegate,
        delegate_profile=delegate_profile,
        requires_os_sandbox=_bool(spec.get('requires_os_sandbox', True), 'PROFILE_CONFIG'),
        max_runtime_s=_int(spec.get('max_runtime_s', 900), 30, 86400, 'PROFILE_CONFIG'),
        max_turns=_int(spec.get('max_turns', 4), 1, 256, 'PROFILE_CONFIG'),
        max_children=_int(spec.get('max_children', 4 if can_delegate else 0), 0, 32, 'PROFILE_CONFIG'),
        max_depth=_int(spec.get('max_depth', 2 if can_delegate else 0), 0, 8, 'PROFILE_CONFIG'),
        stall_timeout_s=_int(spec.get('stall_timeout_s', 300), 30, 7200, 'PROFILE_CONFIG'),
        idle_retain_s=_int(spec.get('idle_retain_s', 300), 0, 7200, 'PROFILE_CONFIG'),
        description=spec.get('description', '')[:256],
    )


def load_profiles(configured: dict | None) -> dict[str, Profile]:
    """Merge operator-configured profiles over the bundled defaults.
    Operator profiles are validated exactly like bundled ones; a profile that
    lowers requires_os_sandbox is legal but surfaced truthfully."""
    specs = dict(DEFAULT_PROFILES)
    if configured:
        need(isinstance(configured, dict) and len(configured) <= 16, 'PROFILE_CONFIG')
        for name, spec in configured.items():
            need(isinstance(name, str) and 0 < len(name) <= 64
                 and name.replace('_', '').replace('-', '').isalnum(), 'PROFILE_CONFIG')
            merged = {**specs.get(name, {}), **(spec or {})}
            specs[name] = merged
    profiles = {name: _build(name, spec) for name, spec in specs.items()}
    # delegate_profile references must resolve
    for profile in profiles.values():
        if profile.delegate_profile is not None:
            need(profile.delegate_profile in profiles, 'PROFILE_CONFIG')
    return profiles

