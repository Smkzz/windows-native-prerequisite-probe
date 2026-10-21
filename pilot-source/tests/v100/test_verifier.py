"""Independent completion verifier: gates, identity blocking, budgets, false success."""
from __future__ import annotations

import copy
import json

from localcontrol.v080 import identity as identity_mod
from localcontrol.v100 import verifier as verifier_mod
from tests.v100.fixture import V100Case


class VerifierTests(V100Case):
    def _mission_row(self, mission_id: str) -> dict:
        return self.facade.v100.store.get(mission_id)

    def test_command_gate_success_and_failure(self):
        mission = self.begin_mission(contract={'commands': [{'argv': ['probe'], 'expect_returncode': 0}]})
        row = self._mission_row(mission['mission_id'])
        calls = []

        def runner(spec):
            calls.append(spec)
            return {'ok': True, 'returncode': 0, 'job_id': 'job-1', 'output_bytes': 3}

        record = verifier_mod.measure(mission=row, chain_ok=True,
                                      current_identity=identity_mod.build_identity(self.facade.policy, 'pilot'),
                                      current_binding=row['policy_binding'], read_sha=lambda rel: (False, None, None),
                                      run_command=runner, budget_state=self.facade.v100.store.budget_state(mission['mission_id']))
        self.assertTrue(record['ok'], record)
        self.assertEqual(len(calls), 1)
        failed = verifier_mod.measure(mission=row, chain_ok=True,
                                      current_identity=identity_mod.build_identity(self.facade.policy, 'pilot'),
                                      current_binding=row['policy_binding'], read_sha=lambda rel: (False, None, None),
                                      run_command=lambda spec: {'ok': True, 'returncode': 7, 'job_id': 'job-2'},
                                      budget_state=self.facade.v100.store.budget_state(mission['mission_id']))
        self.assertFalse(failed['ok'])
        self.assertFalse(next(g for g in failed['gates'] if g['name'] == 'command_0')['ok'])

    def test_finish_uses_command_gate(self):
        self.facade.v100.run_command = lambda project, spec: {'ok': True, 'returncode': 0, 'job_id': 'job-x',
                                                             'output_bytes': 0}
        mission = self.begin_mission(contract={'commands': [{'recipe': 'noop', 'expect_returncode': 0}]})
        result = self.finish_mission(mission['mission_id'], mission['token'])
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'SUCCEEDED')

    def test_chain_failure_blocks_success(self):
        mission = self.begin_mission()
        row = self._mission_row(mission['mission_id'])
        record = verifier_mod.measure(mission=row, chain_ok=False,
                                      current_identity=identity_mod.build_identity(self.facade.policy, 'pilot'),
                                      current_binding=row['policy_binding'], read_sha=lambda rel: (False, None, None),
                                      run_command=lambda spec: {}, budget_state=self.facade.v100.store.budget_state(mission['mission_id']))
        self.assertFalse(record['ok'])
        self.assertFalse(next(g for g in record['gates'] if g['name'] == 'mission_chain')['ok'])

    def test_budget_overflow_blocks_success(self):
        mission = self.begin_mission(budgets={'max_jobs': 1})
        row = self._mission_row(mission['mission_id'])
        record = verifier_mod.measure(mission=row, chain_ok=True,
                                      current_identity=identity_mod.build_identity(self.facade.policy, 'pilot'),
                                      current_binding=row['policy_binding'], read_sha=lambda rel: (False, None, None),
                                      run_command=lambda spec: {},
                                      budget_state={'budgets': row['budgets'], 'jobs': 5, 'transactions': 0,
                                                    'tool_calls': 0, 'output_bytes': 0})
        self.assertFalse(record['ok'])
        self.assertFalse(next(g for g in record['gates'] if g['name'] == 'budget')['ok'])

    def test_replaced_root_blocks_success(self):
        mission = self.begin_mission()
        row = self._mission_row(mission['mission_id'])
        current = copy.deepcopy(row['workspace_identity'])
        current['root_id']['file_id'] = int(current['root_id'].get('file_id') or 0) + 1
        current['digest'] = 'changed'
        record = verifier_mod.measure(mission=row, chain_ok=True, current_identity=current,
                                      current_binding=row['policy_binding'], read_sha=lambda rel: (False, None, None),
                                      run_command=lambda spec: {},
                                      budget_state=self.facade.v100.store.budget_state(mission['mission_id']))
        self.assertFalse(record['ok'])
        gate = next(g for g in record['gates'] if g['name'] == 'workspace_identity')
        self.assertFalse(gate['ok'])
        self.assertIn('root_replaced', gate['detail']['blocking'])

    def test_file_evolution_does_not_block(self):
        mission = self.begin_mission()
        self.seed('progress.txt', 'work in progress\n', request_id='seed-progress-0001')
        row = self._mission_row(mission['mission_id'])
        record = verifier_mod.measure(mission=row, chain_ok=True,
                                      current_identity=identity_mod.build_identity(self.facade.policy, 'pilot'),
                                      current_binding=row['policy_binding'], read_sha=lambda rel: (False, None, None),
                                      run_command=lambda spec: {},
                                      budget_state=self.facade.v100.store.budget_state(mission['mission_id']))
        self.assertTrue(record['ok'], record)

    def test_contract_validation_rejects_bad_shapes(self):
        bad = self.call('mission_begin', objective='bad contract', request_id='mission-begin-bad-0001',
                        success_contract={'required_files': [{'path': '../escape'}]})
        self.assert_error('INVALID_PATH', bad)
        unknown = self.call('mission_begin', objective='bad contract', request_id='mission-begin-bad-0002',
                            success_contract={'unknown_key': []})
        self.assert_error('INVALID_CONTRACT', unknown)
        bad_command = self.call('mission_begin', objective='bad contract', request_id='mission-begin-bad-0003',
                                success_contract={'commands': [{'argv': []}]})
        self.assert_error('INVALID_CONTRACT', bad_command)

    def test_verification_digest_is_stable_record(self):
        mission = self.begin_mission()
        result = self.finish_mission(mission['mission_id'], mission['token'])
        record = result['data']['verification']
        self.assertEqual(record['verifier'], 'deterministic-v1')
        self.assertIn('digest', record)
        self.assertEqual(len(record['gates']), len({g['name'] for g in record['gates']}))


class ContractSchemaV2(V100Case):
    """C-D3: versioned verifier contracts with scoped working directories."""

    def _mission_row(self, mission_id: str) -> dict:
        return self.facade.v100.store.get(mission_id)

    def _measure(self, mission_id: str, runner) -> dict:
        row = self._mission_row(mission_id)
        return verifier_mod.measure(
            mission=row, chain_ok=True,
            current_identity=identity_mod.build_identity(self.facade.policy, 'pilot'),
            current_binding=row['policy_binding'],
            read_sha=lambda rel: (False, None, None), run_command=runner,
            budget_state=self.facade.v100.store.budget_state(mission_id))

    def test_schema2_working_directory_accepted(self):
        mission = self.begin_mission(contract={
            'schema': 2,
            'commands': [{'argv': ['probe'], 'working_directory': 'work/sub'}]})
        seen = []

        def runner(spec):
            seen.append(spec)
            return {'ok': True, 'returncode': 0, 'job_id': 'j-1', 'cwd': 'resolved/work/sub',
                    'scratch': True, 'execution': 'sandbox'}

        record = self._measure(mission['mission_id'], runner)
        self.assertTrue(record['ok'], record)
        self.assertEqual(seen[0]['working_directory'], 'work/sub')
        gate = next(g for g in record['gates'] if g['name'] == 'command_0')
        self.assertEqual(gate['detail']['working_directory'], 'work/sub')
        self.assertEqual(gate['detail']['cwd'], 'resolved/work/sub')
        self.assertEqual(gate['detail']['execution'], 'sandbox')

    def test_working_directory_rejected_without_schema2(self):
        result = self.call('mission_begin', objective='v1 wd', request_id='mission-begin-v1wd01',
                           success_contract={'commands': [{'argv': ['p'], 'working_directory': 'x'}]})
        self.assert_error('INVALID_CONTRACT', result)

    def test_unknown_schema_rejected(self):
        result = self.call('mission_begin', objective='bad schema', request_id='mission-begin-v9-01',
                           success_contract={'schema': 9, 'commands': [{'argv': ['p']}]})
        self.assert_error('INVALID_CONTRACT', result)

    def test_working_directory_traversal_rejected(self):
        result = self.call('mission_begin', objective='wd traversal', request_id='mission-begin-wdtrv',
                           success_contract={'schema': 2, 'commands': [
                               {'argv': ['p'], 'working_directory': '../escape'}]})
        self.assert_error('INVALID_PATH', result)

    def test_working_directory_protected_rejected(self):
        result = self.call('mission_begin', objective='wd protected', request_id='mission-begin-wdgit',
                           success_contract={'schema': 2, 'commands': [
                               {'argv': ['p'], 'working_directory': '.git/hooks'}]})
        self.assert_error('PROTECTED_PATH', result)

    def test_working_directory_absolute_rejected(self):
        result = self.call('mission_begin', objective='wd absolute', request_id='mission-begin-wdabs',
                           success_contract={'schema': 2, 'commands': [
                               {'argv': ['p'], 'working_directory': 'C:/Windows'}]})
        self.assert_error('INVALID_PATH', result)

    def test_schema1_contract_unchanged(self):
        clean = verifier_mod.validate_contract({'commands': [{'argv': ['p']}]})
        self.assertEqual(clean['schema'], 1)
        self.assertNotIn('working_directory', clean['commands'][0])


class ForbiddenFileGateTests(V100Case):
    """L-1: forbidden_files must fail closed when read_sha is inconclusive."""

    def _mission_row(self, mission_id: str) -> dict:
        return self.facade.v100.store.get(mission_id)

    def _measure(self, mission, read_sha):
        row = self._mission_row(mission['mission_id'])
        return verifier_mod.measure(
            mission=row, chain_ok=True,
            current_identity=identity_mod.build_identity(self.facade.policy, 'pilot'),
            current_binding=row['policy_binding'], read_sha=read_sha,
            run_command=lambda spec: {'ok': True, 'returncode': 0, 'job_id': 'j',
                                      'output_bytes': 0},
            budget_state=self.facade.v100.store.budget_state(mission['mission_id']))

    def test_forbidden_file_present_fails(self):
        mission = self.begin_mission(contract={'forbidden_files': ['leak.txt']})
        record = self._measure(mission, lambda rel: (True, 'sha', 5))
        self.assertFalse(record['ok'])
        gate = next(g for g in record['gates'] if g['name'] == 'forbidden_file:leak.txt')
        self.assertFalse(gate['ok'])

    def test_forbidden_file_absent_passes(self):
        mission = self.begin_mission(contract={'forbidden_files': ['leak.txt']})
        record = self._measure(mission, lambda rel: (False, None, None))
        self.assertTrue(record['ok'], record)

    def test_forbidden_file_read_error_fails_closed(self):
        mission = self.begin_mission(contract={'forbidden_files': ['leak.txt']})
        record = self._measure(mission, lambda rel: (None, None, None))
        self.assertFalse(record['ok'])
        gate = next(g for g in record['gates'] if g['name'] == 'forbidden_file:leak.txt')
        self.assertFalse(gate['ok'])
        self.assertEqual(gate['detail'].get('error'), 'read_inconclusive')

    def test_required_file_read_error_fails_closed(self):
        mission = self.begin_mission(
            contract={'required_files': [{'path': 'need.txt'}]})
        record = self._measure(mission, lambda rel: (None, None, None))
        self.assertFalse(record['ok'])

    def test_forbidden_directory_does_not_pass_gate(self):
        """End-to-end through the production read_sha: a *directory* (or any
        non-regular object) at a forbidden path is inconclusive, not absent —
        a contract forbidding '.git' must not pass because '.git/' is a dir."""
        (self.project / 'secrets.dir').mkdir()
        mission = self.begin_mission(contract={'forbidden_files': ['secrets.dir']})
        result = self.finish_mission(mission['mission_id'], mission['token'],
                                     request_id='forbidden-dir-01')
        self.assertTrue(result['ok'], result)
        self.assertFalse(result['data']['verified'])
        gate = next(g for g in result['data']['verification']['gates']
                    if g['name'] == 'forbidden_file:secrets.dir')
        self.assertFalse(gate['ok'])
        self.assertEqual(gate['detail'].get('error'), 'read_inconclusive')
