"""LocalControl v1.1 agent-delegation API.

A parent harness creates and supervises independent provider-backed
sub-agents. The model selects a permission PROFILE by name; all authority
(root, sandbox, provider, budgets, lineage) is bound server-side and is
never accepted from tool arguments. Delegated children may only recurse
through the LocalControl-owned delegation shim — provider-native agent
facilities are disabled in every delegated CODEX_HOME.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from .agents.manager import DelegationManager
from .nextlib.core import Rejected, ident, need

VERSION = '1.1.1'
OPTION_KEYS = frozenset({'enabled', 'providers', 'profiles', 'limits', 'default_profile',
                         'auto_reattach'})
MAX_INCLUDE = 4
V110_FIELDS = {
    'agent_spawn': {'task', 'profile', 'model', 'effort', 'workspace_mode', 'workspace_path',
                    'base_ref', 'dedupe_key', 'output_schema', 'timeout_s', 'wait_ms',
                    'request_id'},
    'agent_send': {'agent_id', 'input', 'output_schema', 'wait_ms', 'request_id'},
    'agent_status': {'agent_id', 'include', 'wait_ms'},
    'agent_result': {'agent_id', 'wait_ms'},
    'agent_events': {'agent_id', 'cursor', 'limit'},
    'agent_list': {'state', 'limit', 'include_archived'},
    'agent_cancel': {'agent_id', 'reason', 'request_id'},
    'agent_resume': {'agent_id', 'input', 'output_schema', 'wait_ms', 'request_id'},
    'agent_fork': {'agent_id', 'task', 'wait_ms', 'request_id'},
    'agent_cleanup': {'agent_id', 'all_terminal', 'confirm', 'request_id'},
    'agent_capabilities': set(),
}
MUTATING_TOOLS = frozenset({'agent_spawn', 'agent_send', 'agent_cancel', 'agent_resume',
                            'agent_fork', 'agent_cleanup'})


class V110API:
    def __init__(self, policy, principal: str, next_api, config_path: Path, options: dict):
        need(isinstance(options, dict) and set(options) <= OPTION_KEYS, 'V110_CONFIG')
        ident(principal)
        self.policy, self.principal, self.next = policy, principal, next_api
        self.config_path = Path(config_path)
        self.manager = DelegationManager(policy, principal, options, next_api=next_api)
        self.started_ns = time.time_ns()

    def close(self) -> None:
        self.manager.close()

    # ---------- tool handlers ----------

    async def call(self, tool: str, project, args: dict):
        return await asyncio.to_thread(self._call_sync, tool, project, args)

    def _call_sync(self, tool: str, project, args: dict):
        if tool in MUTATING_TOOLS:
            request_id = args.get('request_id')
            if not (isinstance(request_id, str) and request_id):
                raise Rejected('INVALID_REQUEST_ID')
        if tool == 'agent_capabilities':
            return self.manager.capabilities()
        if tool == 'agent_list':
            return self.manager.list_agents(self._scope(project), project, args)
        # every other tool is project-bound: '*' is never an agent home
        need(isinstance(project, str) and project in self.policy.projects, 'PROJECT_REQUIRED')
        scope = self._scope(project)
        handlers = {
            'agent_spawn': self.manager.spawn,
            'agent_send': self.manager.send,
            'agent_status': self.manager.status,
            'agent_result': self.manager.result,
            'agent_events': self.manager.events,
            'agent_cancel': self.manager.cancel,
            'agent_resume': self.manager.resume,
            'agent_fork': self.manager.fork,
            'agent_cleanup': self.manager.cleanup,
        }
        handler = handlers.get(tool)
        need(handler is not None, 'INVALID_ARGUMENT')
        if tool in ('agent_status', 'agent_result') and args.get('wait_ms'):
            agent = self.manager.wait(scope, project, args['agent_id'], args['wait_ms'])
            data = self.manager.status(scope, project,
                                       {'agent_id': args['agent_id'],
                                        'include': args.get('include')}) \
                if tool == 'agent_status' else self.manager.result(
                    scope, project, {'agent_id': args['agent_id']})
            data['waited'] = agent
            return data
        return handler(scope, project, args)

    def _scope(self, project) -> str:
        return self.principal + (':v110-catalog' if project in ('', '*') else ':' + project)

    def health(self) -> dict:
        info = self.manager.health()
        info['version'] = VERSION
        info['provider'] = 'codex'
        info['provider_available'] = self.manager._exe_info is not None
        return info
