"""P1/P2/P6: zero-knowledge bootstrap, self-describing protocol, error ergonomics."""
from __future__ import annotations

from pathlib import Path

from localcontrol import protocol
from localcontrol.policy import Project
from localcontrol.server import make_tools
from tests.v070.fixture import V070Case


class BootstrapTests(V070Case):
    def test_context_requires_no_arguments(self):
        result = self.call('localcontrol_context', '')
        self.assertTrue(result['ok'], result)
        data = result['data']
        self.assertEqual(data['protocol_version'], protocol.PROTOCOL_VERSION)
        self.assertEqual([p['name'] for p in data['projects']], ['pilot'])
        self.assertEqual(data['default_project'], 'pilot')
        self.assertTrue(all(p['is_default'] for p in data['projects']))
        self.assertEqual(data['scopes']['collections'][0]['name'], 'projects')
        self.assertEqual(data['scopes']['workspaces'][0]['name'], 'pilot')
        self.assertEqual(data['registry']['revision'], 1)
        self.assertTrue(data['features']['transactions'])
        self.assertEqual(set(data['workflows']), {'bootstrap', 'move', 'cleanup', 'transaction', 'continuation', 'execution'})
        self.assertEqual(data['recommended_next'][0]['tool'], 'capabilities')
        self.assertNotIn('operations', data)

    def test_context_operations_section_is_complete_and_bounded(self):
        result = self.call('localcontrol_context', '', include=['operations'])
        self.assertTrue(result['ok'], result)
        operations = result['data']['operations']
        names = {tool.name for tool in make_tools(True)}
        self.assertEqual(set(operations), names)
        for spec in operations.values():
            self.assertEqual(set(spec), {'scope', 'mutating', 'request_id', 'sha_guard', 'idempotent',
                                         'recovery', 'requires', 'produces', 'consumes', 'depends_on'})

    def test_context_rejects_unknown_sections_and_oversize(self):
        self.assert_error('INVALID_ARGUMENT', self.call('localcontrol_context', '', include=['everything']))
        self.assert_error('RESPONSE_LIMIT', self.call('localcontrol_context', '',
                                                      include=['operations'], max_response_bytes=4096))

    def test_system_info_without_project_is_catalog(self):
        result = self.call('system_info', '')
        self.assertTrue(result['ok'], result)
        data = result['data']
        self.assertEqual(data['selector'], '*')
        self.assertEqual(data['bootstrap_tool'], 'localcontrol_context')
        self.assertEqual(data['tool_count'], 41)
        self.assertEqual(data['protocol_version'], protocol.PROTOCOL_VERSION)
        self.assertEqual(set(data['tools_by_group']), set(protocol.TOOL_GROUPS))

    def test_global_tool_without_project_uses_global_scope(self):
        result = self.call('workspace_catalog', '')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['revision'], 1)

    def test_project_tool_without_project_selects_only_project(self):
        self.seed('a.txt', 'hello\n')
        result = self.call('file_read', '', path='a.txt')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['content'], 'hello\n')

    def test_multi_project_without_project_is_actionable(self):
        second = self.root / 'second'
        second.mkdir()
        self.facade.policy.projects['second'] = Project(second, True)
        self.facade.locks['second'] = __import__('asyncio').Lock()
        error = self.assert_error('PROJECT_REQUIRED', self.call('file_read', '', path='a.txt'))
        self.assertEqual([p['name'] for p in error['details']['valid_projects']], ['pilot', 'second'])
        self.assertEqual(error['details']['next_action']['tool'], 'localcontrol_context')
        self.assertIn('localcontrol_context', error['hint'])
        # Global tools stay argument-light in the same configuration.
        self.assertTrue(self.call('health_status', '')['ok'])

    def test_unknown_project_error_carries_choices(self):
        error = self.assert_error('UNKNOWN_PROJECT', self.call('file_read', 'nope', path='a.txt'))
        self.assertEqual(error['details']['valid_projects'][0]['name'], 'pilot')

    def test_conflict_error_has_recovery_hint(self):
        self.seed('a.txt', 'one\n')
        error = self.assert_error('CONFLICT', self.call('file_write', path='a.txt', content='two\n',
                                                        expected_sha256='0' * 64, request_id='conflict-0001'))
        self.assertIn('sha256', error['hint'])

    def test_catalog_scope_error_is_actionable(self):
        error = self.assert_error('CATALOG_SCOPE_REQUIRED',
                                  self.call('workspace_catalog', 'pilot'))
        self.assertEqual(error['details']['global_scope_selector'], '*')
        self.assertEqual(error['details']['next_action']['tool'], 'localcontrol_context')

    def test_protocol_metadata_has_no_drift(self):
        names = {tool.name for tool in make_tools(True)}
        summary = protocol.validate_protocol(names)
        self.assertEqual(summary['protocol_version'], protocol.PROTOCOL_VERSION)
        # Every dependency of an enabled tool points at an enabled tool.
        for name in names:
            for dependency in protocol.OPERATIONS[name]['depends_on']:
                self.assertIn(dependency, names, name)

    def test_protocol_metadata_never_contains_paths(self):
        for name, spec in protocol.OPERATIONS.items():
            self.assertNotIn('C:', str(spec), name)
            self.assertNotIn('\\\\', str(spec), name)

    def test_context_never_leaks_control_plane_paths(self):
        result = self.call('localcontrol_context', '')
        text = str(result['data'])
        self.assertNotIn(str(self.state), text)
        self.assertNotIn(str(self.config), text)
        self.assertNotIn('runtime-key', text)


class BootstrapWithoutV060Tests(V070Case):
    v060 = False

    def test_bootstrap_works_without_maintenance_family(self):
        result = self.call('localcontrol_context', '')
        self.assertTrue(result['ok'], result)
        self.assertFalse(result['data']['features']['v060_maintenance'])
        self.assertFalse(result['data']['features']['transactions'])
        self.assertNotIn('registry', result['data'])
        self.assertEqual(result['data']['tool_count'], 22)
