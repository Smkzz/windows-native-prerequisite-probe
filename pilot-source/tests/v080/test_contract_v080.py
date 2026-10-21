"""v0.8 public tool contract: 46 tools, additive over v0.7, operator-only hidden."""
from __future__ import annotations

import unittest

from localcontrol import protocol
from localcontrol.server import make_tools
from localcontrol.v060.contract import BASE_V050, OPERATOR_ONLY, V060_ADDITIONS, V080_ADDITIONS, validate_contract


class ContractTests(unittest.TestCase):
    def test_contract_totals_and_operator_separation(self):
        report = validate_contract()
        self.assertEqual(report['total'], 46)
        self.assertEqual(report['v080_additions'], len(V080_ADDITIONS))
        self.assertTrue(report['control_plane_exposed'] is False)
        public = set(BASE_V050) | set(V060_ADDITIONS) | set(V080_ADDITIONS) | {'workspace_catalog'}
        self.assertTrue(set(V080_ADDITIONS) <= public)
        self.assertFalse(set(V080_ADDITIONS) & set(OPERATOR_ONLY))

    def test_registered_names_match_documented_surface(self):
        names = {tool.name for tool in make_tools(True, True)}
        self.assertTrue(names <= set(protocol.OPERATIONS))
        self.assertEqual(len(names), 46)
        base = {tool.name for tool in make_tools(False, False)}
        self.assertEqual(len(base), 22)
        v060_only = {tool.name for tool in make_tools(True, False)}
        self.assertEqual(len(v060_only), 41)
        self.assertTrue(v060_only < names)

    def test_new_tools_are_annotated(self):
        tools = {tool.name: tool for tool in make_tools(True, True)}
        for name in ('telemetry_summary', 'run_status'):
            self.assertTrue(tools[name].annotations.readOnlyHint, name)
            self.assertFalse(tools[name].annotations.destructiveHint, name)
        for name in ('run_begin', 'run_heartbeat', 'run_finish'):
            self.assertTrue(tools[name].annotations.destructiveHint, name)
            self.assertTrue(tools[name].annotations.idempotentHint, name)
        self.assertEqual(tools['run_begin'].inputSchema['required'], ['request_id'])
        self.assertIn('project', tools['run_begin'].inputSchema['properties'])


if __name__ == '__main__':
    unittest.main()
