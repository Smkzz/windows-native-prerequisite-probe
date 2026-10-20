"""LocalControl agent delegation plane (v1.1.0).

Provider-neutral delegated sub-agent lifecycle: durable records, bounded
concurrency and recursion, provider sessions owned by this daemon only.
The Codex backend speaks the official `codex app-server` JSONL protocol;
no browser, clipboard, UI or credential automation exists anywhere here.
"""
from . import state  # noqa: F401
from .store import AgentStore  # noqa: F401
from .profiles import Profile, load_profiles  # noqa: F401
from .manager import DelegationManager  # noqa: F401
