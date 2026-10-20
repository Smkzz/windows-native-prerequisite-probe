"""Agent lifecycle states. Terminal states never transition again.

An agent is a durable record plus an optional live provider session.
States describe the *agent*, not the provider process:

    queued      admitted, waiting for a spawn slot
    starting    provider session/thread/turn setup in flight
    running     a provider turn is in progress
    waiting_internal  turn in progress but blocked on an internal exchange
                      the server already answered under policy
    completing  provider reported completion; result persistence in flight
    idle        no active turn; warm provider session retained for follow-ups
    completed   work finished; provider session released; durable + resumable
    failed      provider turn/spawn failed; durable; resumable when a thread id exists
    cancelled   explicit cancellation; terminal
    interrupted daemon restart or provider process loss while work was active
    recovering  a resume/reconciliation attempt is in flight
    orphaned    provider thread unrecoverable or authority changed; terminal
"""
from __future__ import annotations

QUEUED = 'queued'
STARTING = 'starting'
RUNNING = 'running'
WAITING_INTERNAL = 'waiting_internal'
COMPLETING = 'completing'
IDLE = 'idle'
COMPLETED = 'completed'
FAILED = 'failed'
CANCELLED = 'cancelled'
INTERRUPTED = 'interrupted'
RECOVERING = 'recovering'
ORPHANED = 'orphaned'

LIVE = frozenset({QUEUED, STARTING, RUNNING, WAITING_INTERNAL, COMPLETING, IDLE, RECOVERING})
TERMINAL = frozenset({COMPLETED, FAILED, CANCELLED, ORPHANED})
RESUMABLE = frozenset({INTERRUPTED, FAILED, IDLE, COMPLETED})
STATES = LIVE | TERMINAL | {INTERRUPTED}

TRANSITIONS = {
    QUEUED: {STARTING, IDLE, CANCELLED, INTERRUPTED},
    STARTING: {RUNNING, IDLE, COMPLETING, FAILED, CANCELLED, INTERRUPTED},
    RUNNING: {WAITING_INTERNAL, COMPLETING, IDLE, FAILED, CANCELLED, INTERRUPTED, RECOVERING},
    WAITING_INTERNAL: {RUNNING, COMPLETING, IDLE, FAILED, CANCELLED, INTERRUPTED, RECOVERING},
    COMPLETING: {IDLE, COMPLETED, FAILED, CANCELLED, INTERRUPTED},
    IDLE: {STARTING, COMPLETED, CANCELLED, INTERRUPTED},
    COMPLETED: {STARTING, CANCELLED},
    FAILED: {RECOVERING, CANCELLED, ORPHANED},
    CANCELLED: set(),
    INTERRUPTED: {RECOVERING, CANCELLED, ORPHANED},
    RECOVERING: {RUNNING, IDLE, COMPLETED, FAILED, INTERRUPTED, ORPHANED, CANCELLED},
    ORPHANED: set(),
}

PROVIDERS = frozenset({'codex'})
WORKSPACE_MODES = frozenset({'existing', 'isolated_worktree'})
