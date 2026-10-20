"""The only production file backend is upstream winfs-mcp, via the official SDK.

One private upstream per project. Never forwards client roots/list responses or
allows clients to select upstream tools. No upstream shell/process tools exposed.
"""
from __future__ import annotations
import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
import logging
from pathlib import Path
import json
import os
from .errors import ControlError, require
from .policy import Policy, no_links

ALLOWED = frozenset({'read', 'write', 'edit_file', 'list', 'stat'})
STARTUP_BACKOFF_S = (0.5, 1.0)
STARTUP_ATTEMPTS = 1 + len(STARTUP_BACKOFF_S)
logger = logging.getLogger(__name__)


class WinfsBackend:
    def __init__(self, policy: Policy, node: str, entry: str):
        self.policy, self.node, self.entry = policy, node, entry
        self.sessions = {}
        for value in (node, entry):
            p = Path(value)
            require(p.is_absolute() and p.is_file(), 'BACKEND_CONFIG', 'Explicit upstream runtime paths required')
            require(not any(p.is_relative_to(x.root) for x in policy.projects.values()), 'BACKEND_CONFIG', 'Upstream runtime must be outside project roots')
        self.stack = AsyncExitStack()

    @asynccontextmanager
    async def connected(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        from datetime import timedelta
        # Lifecycle enter/exit stays in the same async task.
        async with self.stack:
            for name, project in self.policy.projects.items():
                cfg_path = self.policy.state_dir / f'winfs-{name}.json'
                no_links(cfg_path)
                cfg = {'allowedRoots': [str(project.root)], 'defaultTimeoutMs': 10000,
                       'maxTimeoutMs': 15000, 'readMaxBytes': self.policy.max_file_bytes,
                       'auditLogPath': str(self.policy.state_dir / f'winfs-{name}-audit.jsonl')}
                cfg_path.write_text(json.dumps(cfg), encoding='utf-8')
                env = {k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','COMSPEC','PATH','PATHEXT','TEMP','TMP','LOCALAPPDATA'}}
                params = StdioServerParameters(command=self.node,
                                               args=[self.entry, '--config', str(cfg_path)], env=env)
                session = None
                # Discard a failed stdio session and launch a fresh child on retry.
                for attempt in range(1, STARTUP_ATTEMPTS + 1):
                    attempt_stack = AsyncExitStack()
                    await attempt_stack.__aenter__()
                    try:
                        stderr = attempt_stack.enter_context(
                            open(self.policy.state_dir / f'winfs-{name}-stderr.log', 'ab'))
                        streams = await attempt_stack.enter_async_context(
                            stdio_client(params, errlog=stderr))
                        candidate = await attempt_stack.enter_async_context(
                            ClientSession(*streams, read_timeout_seconds=timedelta(seconds=20)))
                        await candidate.initialize()
                        tools = await candidate.list_tools()
                        require(ALLOWED <= {t.name for t in tools.tools}, 'BACKEND_CONTRACT',
                                'Upstream tool contract changed')
                    except ControlError:
                        await attempt_stack.aclose()
                        raise
                    except Exception as exc:
                        await attempt_stack.aclose()
                        if attempt == STARTUP_ATTEMPTS:
                            raise
                        logger.warning(
                            'Upstream MCP startup failed for project %s on attempt %d/%d (%s); retrying',
                            name, attempt, STARTUP_ATTEMPTS, type(exc).__name__)
                        await asyncio.sleep(STARTUP_BACKOFF_S[attempt - 1])
                        continue
                    except BaseException:
                        await attempt_stack.aclose()
                        raise
                    self.stack.push_async_callback(attempt_stack.aclose)
                    session = candidate
                    break
                require(session is not None, 'BACKEND_UNAVAILABLE',
                        'Upstream MCP startup did not produce a session')
                self.sessions[name] = session
            yield self

    async def call(self, project: str, tool: str, args: dict) -> dict:
        require(tool in ALLOWED, 'BACKEND_TOOL_DENIED', 'Tool is not exposed by the facade')
        result = await self.sessions[project].call_tool(tool, args)
        text = '\n'.join(getattr(c, 'text', '') for c in result.content)
        if result.isError:
            try:
                error = json.loads(text)
                code = error.get('code', 'BACKEND_ERROR')
            except (ValueError, AttributeError):
                code = 'BACKEND_ERROR'
            # Don't propagate upstream snippets containing file/credential contents.
            raise ControlError(str(code), 'Upstream operation failed; no automatic retry')
        if result.structuredContent is not None:
            return result.structuredContent
        try:
            parsed = json.loads(text)
            require(isinstance(parsed, dict), 'BACKEND_CONTRACT', 'Malformed backend response')
            return parsed
        except ValueError:
            raise ControlError('BACKEND_CONTRACT', 'Malformed backend response')
