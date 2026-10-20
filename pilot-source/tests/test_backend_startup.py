import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
import mcp
from mcp.client import stdio as stdio_module

from localcontrol.backend import ALLOWED, WinfsBackend
from localcontrol.errors import ControlError


def make_backend(tmp_path):
    root = tmp_path / "project"
    state = tmp_path / "state"
    root.mkdir()
    state.mkdir()
    node = tmp_path / "node.exe"
    entry = tmp_path / "winfs.js"
    node.touch()
    entry.touch()
    policy = SimpleNamespace(
        projects={"probe": SimpleNamespace(root=root)},
        state_dir=state,
        max_file_bytes=4096,
    )
    return WinfsBackend(policy, str(node), str(entry))


def install_fake_upstream(monkeypatch, counts, initialize, tool_names=ALLOWED):
    class FakeSession:
        def __init__(self, *_streams, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            counts["sessions_closed"] += 1

        async def initialize(self):
            counts["initializes"] += 1
            result = initialize(counts["initializes"])
            if asyncio.iscoroutine(result):
                await result

        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in tool_names])

    @asynccontextmanager
    async def fake_stdio(_params, errlog):
        counts["children_started"] += 1
        try:
            yield (object(), object())
        finally:
            counts["children_closed"] += 1

    monkeypatch.setattr(mcp, "ClientSession", FakeSession)
    monkeypatch.setattr(stdio_module, "stdio_client", fake_stdio)


def test_upstream_initialize_timeout_retries_with_fresh_child(tmp_path, monkeypatch):
    counts = {"children_started": 0, "children_closed": 0, "initializes": 0, "sessions_closed": 0}

    def fail_first(attempt):
        if attempt == 1:
            raise TimeoutError("transient initialize timeout")

    install_fake_upstream(monkeypatch, counts, fail_first)
    backend = make_backend(tmp_path)

    async def run():
        async with backend.connected():
            assert set(backend.sessions) == {"probe"}

    asyncio.run(run())
    assert counts == {"children_started": 2, "children_closed": 2,
                      "initializes": 2, "sessions_closed": 2}


def test_upstream_contract_mismatch_fails_without_retry(tmp_path, monkeypatch):
    counts = {"children_started": 0, "children_closed": 0, "initializes": 0, "sessions_closed": 0}
    install_fake_upstream(monkeypatch, counts, lambda _attempt: None, tool_names=())
    backend = make_backend(tmp_path)

    async def run():
        async with backend.connected():
            pass

    with pytest.raises(ControlError, match="Upstream tool contract changed") as exc:
        asyncio.run(run())
    assert exc.value.code == "BACKEND_CONTRACT"
    assert counts == {"children_started": 1, "children_closed": 1,
                      "initializes": 1, "sessions_closed": 1}


def test_upstream_startup_retry_budget_is_bounded_and_cleans_children(tmp_path, monkeypatch):
    counts = {"children_started": 0, "children_closed": 0, "initializes": 0, "sessions_closed": 0}

    def always_fail(_attempt):
        raise TimeoutError("persistent initialize timeout")

    install_fake_upstream(monkeypatch, counts, always_fail)
    backend = make_backend(tmp_path)

    async def run():
        async with backend.connected():
            pass

    with pytest.raises(TimeoutError, match="persistent initialize timeout"):
        asyncio.run(run())
    assert counts == {"children_started": 3, "children_closed": 3,
                      "initializes": 3, "sessions_closed": 3}

def test_cancellation_during_startup_cleans_child_without_retry(tmp_path, monkeypatch):
    counts = {"children_started": 0, "children_closed": 0, "initializes": 0, "sessions_closed": 0}
    backend = make_backend(tmp_path)

    async def run():
        entered_initialize = asyncio.Event()

        async def block_initialize(_attempt):
            entered_initialize.set()
            await asyncio.Event().wait()

        install_fake_upstream(monkeypatch, counts, block_initialize)

        async def connect():
            async with backend.connected():
                pass

        task = asyncio.create_task(connect())
        await asyncio.wait_for(entered_initialize.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert counts == {"children_started": 1, "children_closed": 1,
                      "initializes": 1, "sessions_closed": 1}
