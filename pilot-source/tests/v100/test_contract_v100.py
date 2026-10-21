"""v1.0 public tool contract: 55 tools, additive over v0.8, operator-only hidden."""
from __future__ import annotations

import unittest

from localcontrol import protocol
from localcontrol.server import make_tools
from localcontrol.v100.contract import V100_ADDITIONS, validate_contract_v100


class ContractV100Tests(unittest.TestCase):
    def test_contract_totals_and_operator_separation(self):
        report = validate_contract_v100()
        self.assertEqual(report['total'], 55)
        self.assertEqual(report['v100_additions'], len(V100_ADDITIONS))
        self.assertFalse(report['control_plane_exposed'])

    def test_registered_names_match_documented_surface(self):
        names = {tool.name for tool in make_tools(True, True, True)}
        self.assertLessEqual(names, set(protocol.OPERATIONS))
        names_v110 = {tool.name for tool in make_tools(True, True, True, True)}
        self.assertEqual(names_v110, set(protocol.OPERATIONS))
        self.assertEqual(len(names), 55)
        without_v100 = {tool.name for tool in make_tools(True, True)}
        self.assertEqual(len(without_v100), 46)
        self.assertTrue(without_v100 < names)

    def test_metadata_covers_groups(self):
        report = protocol.validate_protocol({tool.name for tool in make_tools(True, True, True)})
        self.assertIn('missions', report['groups'])
        self.assertIn('recovery', report['groups'])
        # OPERATIONS documents the full surface incl. optional later families;
        # registration is allowed to enable a subset of it.
        self.assertEqual(len(report['operations']), len(protocol.OPERATIONS))

    def test_new_tools_are_annotated_and_bounded(self):
        tools = {tool.name: tool for tool in make_tools(True, True, True)}
        self.assertTrue(tools['mission_status'].annotations.readOnlyHint)
        self.assertFalse(tools['mission_status'].annotations.destructiveHint)
        for name in ('mission_begin', 'mission_checkpoint', 'mission_resume', 'mission_finish',
                     'mission_cancel', 'mission_schedule', 'state_backup', 'state_restore'):
            self.assertTrue(tools[name].annotations.destructiveHint, name)
        for name in ('mission_begin', 'mission_checkpoint', 'mission_resume', 'mission_finish', 'mission_cancel'):
            self.assertTrue(tools[name].annotations.idempotentHint, name)
        self.assertFalse(tools['state_backup'].annotations.idempotentHint)
        self.assertEqual(tools['mission_begin'].inputSchema['required'], ['objective', 'request_id'])
        self.assertEqual(tools['mission_finish'].inputSchema['required'],
                         ['mission_id', 'token', 'request_id'])
        for name in V100_ADDITIONS:
            schema = tools[name].inputSchema
            self.assertEqual(schema['type'], 'object', name)
            self.assertFalse(schema['additionalProperties'], name)
            self.assertIn('project', schema['properties'], name)


if __name__ == '__main__':
    unittest.main()
