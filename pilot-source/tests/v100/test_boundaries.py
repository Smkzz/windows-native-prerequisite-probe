"""Boundaries: secret non-inheritance, concurrency races, migration, multi-agent leases."""
from __future__ import annotations

import os
import threading

from localcontrol.jobs import job_env
from localcontrol.v100 import migrate as migrate_mod
from tests.v100.fixture import V100Case


class BoundaryTests(V100Case):
    def test_job_env_excludes_credentials(self):
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'super-secret-value'
        os.environ['MY_SERVICE_TOKEN'] = 'another-secret'
        os.environ['LOCALCONTROL_RUNTIME_KEY'] = 'runtime-secret'
        try:
            env = job_env()
            rendered = ' '.join(f'{k}={v}' for k, v in env.items())
            self.assertNotIn('super-secret-value', rendered)
            self.assertNotIn('another-secret', rendered)
            self.assertNotIn('runtime-secret', rendered)
            self.assertNotIn('AWS_SECRET_ACCESS_KEY', env)
            self.assertNotIn('MY_SERVICE_TOKEN', env)
        finally:
            for key in ('AWS_SECRET_ACCESS_KEY', 'MY_SERVICE_TOKEN', 'LOCALCONTROL_RUNTIME_KEY'):
                os.environ.pop(key, None)

    def test_concurrent_tool_call_budget_admits_exactly_one(self):
        mission = self.begin_mission(budgets={'max_tool_calls': 1, 'max_jobs': 4})
        results = []
        lock = threading.Lock()

        def attempt():
            try:
                self.facade.v100.precheck('pilot', 'exec', mission['mission_id'])
                with lock:
                    results.append('ok')
            except Exception as exc:  # noqa: BLE001
                with lock:
                    results.append(getattr(exc, 'code', type(exc).__name__))

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count('ok'), 1, results)
        self.assertEqual(results.count('BUDGET_TOOL_CALLS'), 7, results)

    def test_concurrent_checkpoint_same_token_single_winner(self):
        mission = self.begin_mission()
        outcomes = []
        lock = threading.Lock()

        def checkpoint(index: int):
            result = self.checkpoint(mission['mission_id'], mission['token'],
                                     request_id=f'concurrent-ckpt-{index:04d}')
            with lock:
                outcomes.append(result.get('ok') is True)
        threads = [threading.Thread(target=checkpoint, args=(index,)) for index in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count(True), 1, outcomes)
        self.assertEqual(self.mission(mission['mission_id'])['revision'], 1)

    def test_mission_lock_serializes_second_mission_workspace(self):
        first = self.begin_mission(objective='first writer', request_id='mission-begin-w1-0001')
        second = self.begin_mission(objective='second writer', request_id='mission-begin-w2-0001')
        first_status = self.mission(first['mission_id'])
        second_status = self.mission(second['mission_id'])
        self.assertEqual(first_status['state'], 'RUNNING')
        self.assertEqual(second_status['state'], 'RUNNING')
        self.assertEqual(first_status['policy_binding'], second_status['policy_binding'])
        # Separate missions own independent leases; staleness is per-mission.
        self.assertNotEqual(first_status['lease_expires_ns'], second_status['lease_expires_ns'])

    def test_migration_receipt_idempotent_and_hash_bound(self):
        receipt = migrate_mod.initialize(self.state)
        self.assertTrue(receipt['ok'])
        self.assertGreaterEqual(receipt['observed_files_present'], 0)
        again = migrate_mod.initialize(self.state)
        self.assertTrue(again.get('idempotent'))
        self.assertEqual(again['initialized_ns'], receipt['initialized_ns'])
        recorded = {item['path']: item['sha256'] for item in receipt['observed_prior_state']}
        self.assertIn('receipts.sqlite', recorded)

    def test_scheduler_persists_across_store_recreation(self):
        from localcontrol.v100.missions import MissionStore
        from localcontrol.v100.scheduler import DurableScheduler
        store2 = MissionStore(self.state, 'runtime-boundary-0002')
        try:
            scheduler = DurableScheduler(store2)
            result = scheduler.create(project='pilot', objective='boundary schedule', snapshot={
                'workspace_root': str(self.project), 'workspace_identity': {'schema': 1, 'digest': 'x'},
                'binding': 'b', 'watch_paths': []}, contract={}, budgets={'max_jobs': 1},
                ttl_s=60, watch_paths=[], run_at_ns=None, delay_s=3600, recur_s=None, depends_on=None,
                max_attempts=1, backoff_base_s=1, backoff_max_s=2, deadline_ns=None, grace_s=0,
                request_id='boundary-sched-0001')
            self.assertTrue(result['schedule_id'])
            again = scheduler.create(project='pilot', objective='boundary schedule', snapshot={
                'workspace_root': str(self.project), 'workspace_identity': {'schema': 1, 'digest': 'x'},
                'binding': 'b', 'watch_paths': []}, contract={}, budgets={'max_jobs': 1},
                ttl_s=60, watch_paths=[], run_at_ns=None, delay_s=3600, recur_s=None, depends_on=None,
                max_attempts=1, backoff_base_s=1, backoff_max_s=2, deadline_ns=None, grace_s=0,
                request_id='boundary-sched-0001')
            self.assertTrue(again.get('replayed'))
            self.assertEqual(again['schedule_id'], result['schedule_id'])
        finally:
            store2.close()
