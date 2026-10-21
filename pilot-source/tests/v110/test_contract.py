"""v1.1 public tool contract: 66 tools, additive over v1.0, protocol parity."""
from __future__ import annotations

import unittest

from localcontrol import protocol
from localcontrol.server import make_tools
from localcontrol.v110_api import V110_FIELDS


class ContractV110Tests(unittest.TestCase):
    def test_registered_names_match_documented_surface(self):
        names = {tool.name for tool in make_tools(True, True, True, True)}
        self.assertEqual(names, set(protocol.OPERATIONS))
        self.assertEqual(len(names), 66)
        without_v110 = {tool.name for tool in make_tools(True, True, True)}
        self.assertEqual(len(without_v110), 55)
        self.assertTrue(without_v110 < names)

    def test_metadata_covers_agent_group(self):
        names = {tool.name for tool in make_tools(True, True, True, True)}
        report = protocol.validate_protocol(names)
        self.assertIn('agents', report['groups'])
        self.assertEqual(len(report['operations']), 66)
        self.assertEqual(set(report['operations']), names)

    def test_fields_schemas_match(self):
        tools = {tool.name: tool for tool in make_tools(True, True, True, True)}
        for name in V110_FIELDS:
            schema = tools[name].inputSchema
            self.assertEqual(schema['type'], 'object', name)
            self.assertFalse(schema['additionalProperties'], name)
            self.assertIn('project', schema['properties'], name)
            self.assertEqual(set(schema['properties']) - {'project'}, set(V110_FIELDS[name]), name)

    def test_agent_tool_annotations(self):
        tools = {tool.name: tool for tool in make_tools(True, True, True, True)}
        for name in ('agent_status', 'agent_result', 'agent_events', 'agent_list',
                     'agent_capabilities'):
            self.assertTrue(tools[name].annotations.readOnlyHint, name)
            self.assertFalse(tools[name].annotations.destructiveHint, name)
        for name in ('agent_spawn', 'agent_send', 'agent_cancel', 'agent_resume',
                     'agent_fork', 'agent_cleanup'):
            self.assertTrue(tools[name].annotations.destructiveHint, name)
            self.assertTrue(tools[name].annotations.idempotentHint, name)
        self.assertEqual(tools['agent_spawn'].inputSchema['required'], ['task', 'request_id'])
        self.assertEqual(tools['agent_resume'].inputSchema['required'], ['agent_id', 'request_id'])

    def test_agent_spawn_never_accepts_raw_permissions(self):
        schema = {tool.name: tool for tool in make_tools(True, True, True, True)}['agent_spawn'].inputSchema
        forbidden = {'sandbox', 'writable_roots', 'network', 'approval_policy',
                     'permissions', 'executable', 'env'}
        self.assertFalse(forbidden & set(schema['properties']), schema['properties'])


if __name__ == '__main__':
    unittest.main()
