"""Mission runtime: state machine, idempotency, tokens, recovery, budgets, authority."""
from __future__ import annotations

import json
import time

from localcontrol.v100.missions import MissionStore
from tests.v100.fixture import V100Case


class MissionRuntimeTests(V100Case):
    def test_begin_is_idempotent_by_request_id(self):
        first = self.begin_mission(objective='idempotent mission')
        replay = self.call('mission_begin', objective='idempotent mission', request_id='mission-begin-0001',
                           success_contract={}, budgets={})
        self.assertTrue(replay['ok'], replay)
        self.assertTrue(replay.get('replayed'))
        self.assertEqual(replay['data']['mission_id'], first['mission_id'])
        conflict = self.call('mission_begin', objective='different objective', request_id='mission-begin-0001')
        self.assert_error('IDEMPOTENCY_CONFLICT', conflict)

    def test_checkpoint_rotates_token_and_guards_revision(self):
        mission = self.begin_mission()
        first = self.checkpoint(mission['mission_id'], mission['token'], notes={'phase': 'start'})
        self.assertTrue(first['ok'], first)
        self.assertNotEqual(first['data']['token'], mission['token'])
        stale = self.checkpoint(mission['mission_id'], mission['token'], request_id='mission-checkpoint-0002')
        self.assert_error('MISSION_TOKEN_INVALID', stale)
        stale_revision = self.checkpoint(mission['mission_id'], first['data']['token'],
                                         request_id='mission-checkpoint-0003', expected_revision=99)
        self.assert_error('STALE_REVISION', stale_revision)

    def test_finish_runs_verifier_and_marks_succeeded(self):
        mission = self.begin_mission(contract={'required_files': [{'path': 'deliverable.txt'}]})
        self.seed('deliverable.txt', 'verified content\n', request_id='seed-deliverable-0001')
        result = self.finish_mission(mission['mission_id'], mission['token'])
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['data']['verified'], result)
        self.assertEqual(result['data']['state'], 'SUCCEEDED')
        status = self.mission(mission['mission_id'], include=['verification'])
        self.assertEqual(status['state'], 'SUCCEEDED')
        self.assertEqual(status['terminal_result'], 'SUCCEEDED')
        self.assertTrue(status['verification']['ok'])
        again = self.finish_mission(mission['mission_id'], mission['token'], request_id='mission-finish-0002')
        self.assert_error('STATE_MISMATCH', again)

    def test_failed_verification_produces_failed_never_succeeded(self):
        mission = self.begin_mission(contract={'required_files': [{'path': 'missing.txt'}]})
        result = self.finish_mission(mission['mission_id'], mission['token'])
        self.assertTrue(result['ok'], result)
        self.assertFalse(result['data']['verified'])
        self.assertEqual(result['data']['state'], 'FAILED')
        gates = {g['name']: g['ok'] for g in result['data']['verification']['gates']}
        self.assertFalse(gates['required_file:missing.txt'])
        self.assertTrue(gates['workspace_identity'])

    def test_required_file_sha_mismatch_fails(self):
        mission = self.begin_mission(contract={'required_files': [{'path': 'artifact.txt',
                                                                   'sha256': '0' * 64}]})
        self.seed('artifact.txt', 'content\n', request_id='seed-artifact-0001')
        result = self.finish_mission(mission['mission_id'], mission['token'])
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'FAILED')

    def test_forbidden_file_fails(self):
        self.seed('secret.txt', 'nope\n', request_id='seed-secret-0001')
        mission = self.begin_mission(contract={'forbidden_files': ['secret.txt']})
        result = self.finish_mission(mission['mission_id'], mission['token'])
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'FAILED')

    def test_cancel_is_terminal_and_token_guarded(self):
        mission = self.begin_mission()
        bad = self.call('mission_cancel', mission_id=mission['mission_id'], token='wrong',
                        reason='stop', request_id='mission-cancel-0001')
        self.assert_error('MISSION_TOKEN_INVALID', bad)
        good = self.call('mission_cancel', mission_id=mission['mission_id'], token=mission['token'],
                         reason='operator stop', request_id='mission-cancel-0002')
        self.assertTrue(good['ok'], good)
        self.assertEqual(good['data']['state'], 'CANCELLED')
        finish = self.finish_mission(mission['mission_id'], mission['token'], request_id='mission-finish-0003')
        self.assert_error('STATE_MISMATCH', finish)

    def test_runtime_loss_marks_recovering_not_terminal(self):
        mission = self.begin_mission()
        other = MissionStore(self.state, 'runtime-foreign-0001')
        try:
            recovered = other.recover()
            self.assertTrue(any(item['mission_id'] == mission['mission_id'] for item in recovered))
            status = self.mission(mission['mission_id'])
            self.assertEqual(status['state'], 'RECOVERING')
            self.assertIsNone(status['terminal_result'])
            chain = other.verify_chain()
            self.assertTrue(chain['ok'])
        finally:
            other.close()

    def test_resume_after_recovery(self):
        mission = self.begin_mission()
        other = MissionStore(self.state, 'runtime-foreign-0002')
        other.recover()
        other.close()
        resume = self.call('mission_resume', mission_id=mission['mission_id'], token=mission['token'],
                           request_id='mission-resume-0001')
        self.assertTrue(resume['ok'], resume)
        self.assertEqual(resume['data']['state'], 'RUNNING')
        self.assertEqual(resume['data']['classification'], 'same')
        finish = self.finish_mission(mission['mission_id'], resume['data']['token'],
                                     request_id='mission-finish-0004')
        self.assertTrue(finish['ok'], finish)
        self.assertEqual(finish['data']['state'], 'SUCCEEDED')

    def test_resume_requires_divergence_acceptance(self):
        mission = self.begin_mission()
        self.seed('changes.txt', 'new file\n', request_id='seed-changes-0001')
        other = MissionStore(self.state, 'runtime-foreign-0003')
        other.recover()
        other.close()
        refused = self.call('mission_resume', mission_id=mission['mission_id'], token=mission['token'],
                            request_id='mission-resume-0002')
        self.assert_error('DIVERGENCE_NOT_ACCEPTED', refused)
        accepted = self.call('mission_resume', mission_id=mission['mission_id'], token=mission['token'],
                             accept_divergence='files_changed', request_id='mission-resume-0003')
        self.assertTrue(accepted['ok'], accepted)
        self.assertNotEqual(accepted['data']['classification'], 'same')

    def _restart_and_reconcile(self, runtime: str, **kwargs):
        store = MissionStore(self.state, runtime)
        try:
            store.recover()
            return store.reconcile_recovering(
                identity_probe=self.facade.v100._identity_probe,
                policy_probe=self.facade.v100._policy_probe,
                worker_probe=self.facade.v100.worker_probe,
                transaction_probe=self.facade.v100.transaction_probe,
                move_probe=self.facade.v100.move_probe, **kwargs)
        finally:
            store.close()

    def test_accepted_divergence_is_durable_across_restart(self):
        mission = self.begin_mission()
        self.seed('changes.txt', 'new file\n', request_id='seed-changes-0001')
        self._restart_and_reconcile('runtime-foreign-0004')
        self.assertEqual(self.mission(mission['mission_id'])['state'], 'BLOCKED')
        resumed = self.call('mission_resume', mission_id=mission['mission_id'], token=mission['token'],
                            accept_divergence='files_changed', request_id='mission-resume-accept-0001')
        self.assertTrue(resumed['ok'], resumed)
        self.assertEqual(resumed['data']['classification'], 'files_changed')
        self._restart_and_reconcile('runtime-foreign-0005')
        status = self.mission(mission['mission_id'])
        self.assertNotEqual(status['state'], 'BLOCKED', status)
        self.assertEqual(status['recovery']['action'], 'WAIT_FRESH_LEASE', status)
        self._restart_and_reconcile('runtime-foreign-0006',
                                    now_ns=int(status['lease_expires_ns']) + 1)
        # C-D1: reclaim holds the mission for owner acquisition instead of
        # running it under an unreachable scheduler credential.
        held = self.mission(mission['mission_id'])
        self.assertEqual(held['state'], 'RECOVERING')
        self.assertEqual(held['recovery']['action'], 'AWAIT_OWNER_RESUME')
        reacquired = self.call('mission_resume', mission_id=mission['mission_id'],
                               token=resumed['data']['token'],
                               request_id='mission-resume-accept-0002')
        self.assertTrue(reacquired['ok'], reacquired)
        self.assertEqual(self.mission(mission['mission_id'])['state'], 'RUNNING')
        self.seed('more.txt', 'more\n', request_id='seed-more-0001')
        self._restart_and_reconcile('runtime-foreign-0007')
        self.assertEqual(self.mission(mission['mission_id'])['state'], 'BLOCKED')

    def test_budget_tool_calls_enforced(self):
        mission = self.begin_mission(budgets={'max_tool_calls': 2})
        v100 = self.facade.v100
        v100.precheck('pilot', 'exec', mission['mission_id'])
        v100.precheck('pilot', 'exec', mission['mission_id'])
        with self.assertRaises(Exception) as raised:
            v100.precheck('pilot', 'exec', mission['mission_id'])
        self.assertEqual(getattr(raised.exception, 'code', None), 'BUDGET_TOOL_CALLS')

    def test_budget_jobs_enforced_through_note_binding(self):
        mission = self.begin_mission(budgets={'max_jobs': 1})
        v100 = self.facade.v100
        v100.precheck('pilot', 'exec', mission['mission_id'])
        v100.note_job('pilot', mission['mission_id'], 'job-0000000000000001')
        with self.assertRaises(Exception) as raised:
            v100.precheck('pilot', 'exec', mission['mission_id'])
        self.assertEqual(getattr(raised.exception, 'code', None), 'BUDGET_JOBS')

    def test_mission_project_mismatch_rejected(self):
        mission = self.begin_mission()
        with self.assertRaises(Exception) as raised:
            self.facade.v100.precheck('other', 'exec', mission['mission_id'])
        self.assertEqual(getattr(raised.exception, 'code', None), 'MISSION_PROJECT_MISMATCH')

    def test_authority_snapshot_is_immutable(self):
        mission = self.begin_mission()
        status = self.mission(mission['mission_id'], include=['identity'])
        snapshot = status['policy_snapshot']
        self.assertEqual(snapshot['exec_mode'], 'appcontainer')
        self.assertEqual(mission['policy_binding'], status['policy_binding'])
        self.assertEqual(snapshot['binding'], mission['policy_binding'])
        self.assertFalse(snapshot['writable'] is None)

    def test_evidence_trust_escalation_rejected(self):
        mission = self.begin_mission()
        forged = self.checkpoint(mission['mission_id'], mission['token'],
                                 evidence=[{'kind': 'test', 'ref': 'x', 'trust': 'operator'}])
        self.assert_error('TRUST_CLASS_RESERVED', forged)

    def test_mission_status_lists_and_schedules(self):
        mission = self.begin_mission()
        listing = self.call('mission_status')
        self.assertTrue(listing['ok'], listing)
        self.assertIn(mission['mission_id'], [m['mission_id'] for m in listing['data']['missions']])
        self.assertIn('schedules', listing['data'])
        self.assertIn('chain', listing['data']['stats'])

    def _force_recovering(self, mission, runtime='runtime-foreign-probe'):
        other = MissionStore(self.state, runtime)
        try:
            other.recover()
        finally:
            other.close()

    def _reconcile_with(self, probes, **kwargs):
        store = MissionStore(self.state, 'runtime-foreign-reconcile')
        try:
            merged = {
                'identity_probe': self.facade.v100._identity_probe,
                'policy_probe': self.facade.v100._policy_probe,
                'worker_probe': self.facade.v100.worker_probe,
                'transaction_probe': self.facade.v100.transaction_probe,
                'move_probe': self.facade.v100.move_probe,
            }
            merged.update(probes)
            return store.reconcile_recovering(**merged, **kwargs)
        finally:
            store.close()

    def test_probe_exception_preserves_typed_diagnostic(self):
        mission = self.begin_mission()
        self._force_recovering(mission)

        def boom(_mission):
            raise RuntimeError('disk gone while reading watch path')

        receipts = self._reconcile_with({'identity_probe': boom})
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]['state'], 'RECOVERING')
        self.assertEqual(receipts[0]['reason'], 'recovery_probe_exception')
        status = self.mission(mission['mission_id'])
        self.assertEqual(status['state'], 'RECOVERING')
        self.assertEqual(status['recovery']['reason'], 'recovery_probe_exception')
        self.assertEqual(status['recovery']['action'], 'RETRY_RECOVERY')
        self.assertEqual(status['recovery']['attempts'], 1)
        self.assertEqual(status['last_error'],
                         'probe_identity:RuntimeError: disk gone while reading watch path')

    def test_probe_exception_opens_circuit_with_diagnostics(self):
        mission = self.begin_mission()
        self._force_recovering(mission)

        def boom(_mission):
            raise OSError(13, 'Permission denied')

        for i in range(6):
            self._reconcile_with({'identity_probe': boom}, now_ns=time.time_ns() + i * 10**13)
        status = self.mission(mission['mission_id'])
        self.assertEqual(status['state'], 'BLOCKED')
        self.assertEqual(status['recovery']['reason'], 'recovery_circuit_open')
        self.assertEqual(status['recovery']['action'], 'OPERATOR_REVIEW')
        self.assertEqual(status['recovery']['attempts'], 6)
        self.assertTrue(status['last_error'].startswith('probe_identity:PermissionError'),
                        status['last_error'])

    def test_probe_exception_diagnostic_is_bounded(self):
        mission = self.begin_mission()
        self._force_recovering(mission)

        def boom(_mission):
            raise ValueError('x' * 5000 + '\nsecret\x00path')

        self._reconcile_with({'worker_probe': boom})
        status = self.mission(mission['mission_id'])
        self.assertTrue(status['last_error'].startswith('probe_worker:ValueError'),
                        status['last_error'])
        self.assertLessEqual(len(status['last_error']), 220)
        self.assertNotIn('\n', status['last_error'])
        self.assertNotIn('\x00', status['last_error'])

    def test_lifecycle_signals_are_not_swallowed(self):
        mission = self.begin_mission()
        self._force_recovering(mission)

        def interrupt(_mission):
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self._reconcile_with({'identity_probe': interrupt})
        status = self.mission(mission['mission_id'])
        self.assertEqual(status['state'], 'RECOVERING')
        self.assertEqual(status['recovery']['attempts'], 0)
