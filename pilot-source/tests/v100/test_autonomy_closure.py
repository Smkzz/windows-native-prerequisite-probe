"""Focused v1.0.2 autonomy-closure qualification tests."""
from __future__ import annotations

import tempfile
import unittest
import sqlite3
from pathlib import Path

from localcontrol.nextlib.core import Rejected, digest
from localcontrol.v060.health import HealthBook
from localcontrol.v100 import migrate as migrate_mod
from localcontrol.v100.missions import MissionStore
from localcontrol.v100.scheduler import DurableScheduler
from tests.v100.fixture import V100Case


class AutonomyClosureTests(V100Case):
    def test_resource_fence_conflict_and_explicit_supersession(self):
        first = self.begin_mission(objective='first writer', resource_keys=['Repo:Main'])
        conflict = self.call('mission_begin', objective='other writer', request_id='fence-conflict-0001',
                             resource_keys=['repo:main'], success_contract={}, budgets={})
        self.assert_error('RESOURCE_CONFLICT', conflict)
        replacement = self.call(
            'mission_begin', objective='replacement writer', request_id='fence-replace-0001',
            resource_keys=['repo:main'], supersedes_mission_id=first['mission_id'],
            supersedes_token=first['token'],
            success_contract={}, budgets={})
        self.assertTrue(replacement['ok'], replacement)
        self.assertEqual(replacement['data']['generation'], first['generation'] + 1)
        self.assertEqual(self.mission(first['mission_id'])['state'], 'ABANDONED')
        self.assertEqual(self.mission(replacement['data']['mission_id'])['resource_keys'], ['repo:main'])

    def test_dedupe_same_intent_replays_and_different_intent_fails_closed(self):
        first = self.begin_mission(objective='deduplicated', request_id='dedupe-create-0001',
                                   dedupe_key='work-item-17')
        replay = self.call('mission_begin', objective='deduplicated', request_id='dedupe-create-0002',
                           dedupe_key='work-item-17', success_contract={}, budgets={})
        self.assertTrue(replay['ok'], replay)
        self.assertTrue(replay['data'].get('dedupe_replayed'))
        self.assertEqual(replay['data']['mission_id'], first['mission_id'])
        conflict = self.call('mission_begin', objective='changed intent', request_id='dedupe-create-0003',
                             dedupe_key='work-item-17', success_contract={}, budgets={})
        self.assert_error('MISSION_DEDUPE_CONFLICT', conflict)

    def test_generation_and_fence_are_checked_on_checkpoint(self):
        mission = self.begin_mission()
        stale_generation = self.call(
            'mission_checkpoint', mission_id=mission['mission_id'], token=mission['token'],
            generation=mission['generation'] + 1, fence_token=mission['fence_token'],
            request_id='generation-stale-0001')
        self.assert_error('STALE_GENERATION', stale_generation)
        stale_fence = self.call(
            'mission_checkpoint', mission_id=mission['mission_id'], token=mission['token'],
            generation=mission['generation'], fence_token='stale-fence-token',
            request_id='fence-stale-0001')
        self.assert_error('STALE_FENCE', stale_fence)

    def _begin_at(self, store, state, ttl_s=30, request_id='recovery-begin-0001'):
        return store.begin(
            project='pilot', objective='recoverable', workspace_root=str(state),
            workspace_identity={'schema': 1, 'digest': 'identity'},
            policy_binding='binding', policy_snapshot={'watch_paths': []},
            success_contract={}, budgets={'max_jobs': 1}, ttl_s=ttl_s,
            request_id=request_id, resource_keys=['repo:recover'])

    def _probes(self, **overrides):
        probes = {'identity_probe': lambda _: {'classification': 'same'},
                  'policy_probe': lambda _: {'classification': 'same'},
                  'worker_probe': lambda _: {'live': False, 'owned': True}}
        probes.update(overrides)
        return probes

    def test_expired_recovery_holds_for_owner_acquisition_not_zombie_ownership(self):
        """C-D1: reclaim must never mint an unreachable credential. The mission
        stays RECOVERING/AWAIT_OWNER_RESUME anchored to the last delivered
        token; that owner reacquires and the generation rotates at handoff."""
        with tempfile.TemporaryDirectory(prefix='lc-c1-recovery-') as temp:
            state = Path(temp)
            first = MissionStore(state, 'runtime-first')
            created = self._begin_at(first, state)
            second = MissionStore(state, 'runtime-second')
            try:
                second.recover()
                receipts = second.reconcile_recovering(
                    now_ns=created['created_ns'] + 31 * 1_000_000_000, **self._probes())
                self.assertEqual(receipts[0]['state'], 'RECOVERING')
                self.assertTrue(receipts[0]['awaiting_owner'])
                current = second.get(created['mission_id'])
                # No unreachable owned state: still RECOVERING, lease expired,
                # generation and owner anchor unchanged, no new fence minted.
                self.assertEqual(current['state'], 'RECOVERING')
                self.assertEqual(current['recovery']['action'], 'AWAIT_OWNER_RESUME')
                self.assertEqual(current['generation'], created['generation'])
                with second.lock:
                    raw = second.db.execute('SELECT runtime_instance FROM missions WHERE mission_id=?', (created['mission_id'],)).fetchone()
                self.assertIsNone(raw['runtime_instance'])
                self.assertLessEqual(current['lease_expires_ns'] or 0,
                                     created['created_ns'] + 31 * 1_000_000_000)
                # The claimant anchor is still the delivered token: a foreign
                # credential cannot acquire the mission.
                with self.assertRaises(Rejected) as denied:
                    second.resume(created['mission_id'], token='foreign-token',
                                  expect='RECOVERING', ttl_s=60, allow_stale=True)
                self.assertEqual(denied.exception.code, 'MISSION_TOKEN_INVALID')
                # The delivered owner reacquires: atomic handoff mints and
                # returns fresh credentials only now.
                acquired = second.resume(
                    created['mission_id'], token=created['token'],
                    expect='RECOVERING', ttl_s=60, allow_stale=True)
                self.assertEqual(acquired['state'], 'RUNNING')
                self.assertEqual(acquired['generation'], created['generation'] + 1)
                self.assertNotEqual(acquired['token'], created['token'])
                after = second.get(created['mission_id'])
                self.assertEqual(after['state'], 'RUNNING')
                # The anchor rotated on acquisition: the old token is dead.
                with self.assertRaises(Rejected):
                    second.checkpoint(
                        created['mission_id'], token=created['token'],
                        expected_revision=None, notes=None, evidence=None,
                        state=None, ttl_s=60)
            finally:
                second.close()
                first.close()

    def test_repeated_reclamation_is_stable_and_still_claimable(self):
        with tempfile.TemporaryDirectory(prefix='lc-c1-rereclaim-') as temp:
            state = Path(temp)
            first = MissionStore(state, 'runtime-first')
            created = self._begin_at(first, state)
            second = MissionStore(state, 'runtime-second')
            try:
                second.recover()
                future = created['created_ns'] + 31 * 1_000_000_000
                second.reconcile_recovering(now_ns=future, **self._probes())
                # Reconcile again: an awaiting-owner mission is quiescent —
                # nothing rotates, nothing reclaims twice.
                receipts = second.reconcile_recovering(
                    now_ns=future + 1_000_000_000, **self._probes())
                self.assertEqual(receipts, [])
                current = second.get(created['mission_id'])
                self.assertEqual(current['recovery']['action'], 'AWAIT_OWNER_RESUME')
                self.assertEqual(current['generation'], created['generation'])
                acquired = second.resume(
                    created['mission_id'], token=created['token'],
                    expect='RECOVERING', ttl_s=60, allow_stale=True)
                self.assertEqual(acquired['state'], 'RUNNING')
            finally:
                second.close()
                first.close()

    def test_reclaim_then_cancel_with_anchor_or_takeover(self):
        with tempfile.TemporaryDirectory(prefix='lc-c1-cancel-') as temp:
            state = Path(temp)
            first = MissionStore(state, 'runtime-first')
            created = self._begin_at(first, state)
            second = MissionStore(state, 'runtime-second')
            try:
                second.recover()
                second.reconcile_recovering(
                    now_ns=created['created_ns'] + 31 * 1_000_000_000, **self._probes())
                # Anchor holder may still cancel a held mission.
                out = second.cancel(created['mission_id'], token=created['token'],
                                    reason='owner cancels', abandon=False,
                                    allow_stale=False)
                self.assertEqual(out['state'], 'CANCELLED')
            finally:
                second.close()
                first.close()

    def test_reclaim_takeover_by_operator_without_anchor(self):
        with tempfile.TemporaryDirectory(prefix='lc-c1-takeover-') as temp:
            state = Path(temp)
            first = MissionStore(state, 'runtime-first')
            created = self._begin_at(first, state)
            second = MissionStore(state, 'runtime-second')
            try:
                second.recover()
                second.reconcile_recovering(
                    now_ns=created['created_ns'] + 31 * 1_000_000_000, **self._probes())
                # Explicit takeover is the authorized escape when the anchor
                # credential is unavailable (e.g. pre-fix unreachable owner).
                acquired = second.resume(
                    created['mission_id'], token='not-the-owner',
                    expect='RECOVERING', ttl_s=60, allow_stale=True, takeover=True)
                self.assertEqual(acquired['state'], 'RUNNING')
            finally:
                second.close()
                first.close()

    def test_concurrent_acquire_exactly_one_owner(self):
        with tempfile.TemporaryDirectory(prefix='lc-c1-race-') as temp:
            state = Path(temp)
            first = MissionStore(state, 'runtime-first')
            created = self._begin_at(first, state)
            second = MissionStore(state, 'runtime-second')
            try:
                second.recover()
                second.reconcile_recovering(
                    now_ns=created['created_ns'] + 31 * 1_000_000_000, **self._probes())
                first_resume = second.resume(
                    created['mission_id'], token=created['token'],
                    expect='RECOVERING', ttl_s=60, allow_stale=True)
                self.assertEqual(first_resume['state'], 'RUNNING')
                # A racing second acquire sees RUNNING, not RECOVERING: no
                # duplicate ownership, no double execution.
                with self.assertRaises(Rejected) as denied:
                    second.resume(created['mission_id'], token=created['token'],
                                  expect='RECOVERING', ttl_s=60, allow_stale=True)
                self.assertEqual(denied.exception.code, 'STATE_MISMATCH')
            finally:
                second.close()
                first.close()

    def test_expired_lease_running_mission_is_swept_to_recovering(self):
        """Lease expiry — not only process restart — returns an owned mission
        to the recoverable path (repairs pre-fix RUNNING zombies)."""
        with tempfile.TemporaryDirectory(prefix='lc-c1-sweep-') as temp:
            state = Path(temp)
            store = MissionStore(state, 'runtime-live')
            created = self._begin_at(store, state, request_id='sweep-begin-0001')
            try:
                receipts = store.reconcile_recovering(
                    now_ns=created['created_ns'] + 31 * 1_000_000_000, **self._probes())
                swept = [r for r in receipts if r['mission_id'] == created['mission_id']]
                self.assertTrue(swept and swept[0]['reason'] == 'lease_expired', receipts)
                current = store.get(created['mission_id'])
                self.assertEqual(current['state'], 'RECOVERING')
                # Reconcile then holds it for the owner.
                store.reconcile_recovering(
                    now_ns=created['created_ns'] + 32 * 1_000_000_000, **self._probes())
                current = store.get(created['mission_id'])
                self.assertEqual(current['recovery']['action'], 'AWAIT_OWNER_RESUME')
            finally:
                store.close()

    def test_expired_lease_recovery_row_never_accepts_foreign_claim(self):
        """C-D1 review follow-up: the strict anchor check must cover every
        expired-lease recovery row, not only AWAIT_OWNER_RESUME — a mission
        mid-reconcile (RECONCILE_LEASE) has an expired lease too, and the
        blanket allow_stale bypass must not let a foreign token claim it."""
        with tempfile.TemporaryDirectory(prefix='lc-c1-midreconcile-') as temp:
            state = Path(temp)
            store = MissionStore(state, 'runtime-live')
            created = self._begin_at(store, state, request_id='midrec-0001')
            try:
                with store.lock:
                    store.db.execute(
                        "UPDATE missions SET state='RECOVERING',"
                        "recovery_action='RECONCILE_LEASE',lease_expires_ns=? "
                        "WHERE mission_id=?",
                        (created['created_ns'], created['mission_id']))
                    store.db.commit()
                with self.assertRaises(Rejected) as denied:
                    store.resume(created['mission_id'], token='foreign-token',
                                 expect='RECOVERING', ttl_s=60, allow_stale=True)
                self.assertEqual(denied.exception.code, 'MISSION_TOKEN_INVALID')
                acquired = store.resume(
                    created['mission_id'], token=created['token'],
                    expect='RECOVERING', ttl_s=60, allow_stale=True)
                self.assertEqual(acquired['state'], 'RUNNING')
            finally:
                store.close()

    def test_unresolved_transaction_blocks_recovery(self):
        with tempfile.TemporaryDirectory(prefix='lc-v102-recovery-block-') as temp:
            state = Path(temp)
            first = MissionStore(state, 'runtime-first')
            created = first.begin(
                project='pilot', objective='indeterminate', workspace_root=str(state),
                workspace_identity={'schema': 1, 'digest': 'identity'},
                policy_binding='binding', policy_snapshot={'watch_paths': []},
                success_contract={}, budgets={'max_jobs': 1}, ttl_s=30,
                request_id='recovery-block-0001')
            second = MissionStore(state, 'runtime-second')
            try:
                second.recover()
                receipts = second.reconcile_recovering(
                    identity_probe=lambda _: {'classification': 'same'},
                    policy_probe=lambda _: {'classification': 'same'},
                    transaction_probe=lambda _: {'unresolved': True, 'state': 'INDETERMINATE'},
                    now_ns=created['created_ns'] + 31 * 1_000_000_000)
                self.assertEqual(receipts[0]['state'], 'BLOCKED')
                self.assertEqual(second.get(created['mission_id'])['state'], 'BLOCKED')
            finally:
                second.close()
                first.close()

    def test_migration_interruption_resumes_and_is_idempotent(self):
        with tempfile.TemporaryDirectory(prefix='lc-v102-migration-') as temp:
            state = Path(temp)
            with self.assertRaises(Rejected) as raised:
                migrate_mod.initialize(state, fail_at='after_backup')
            self.assertEqual(raised.exception.code, 'MIGRATION_INTERRUPTED')
            self.assertTrue((state / 'v100' / migrate_mod.PENDING_NAME).is_file())
            receipt = migrate_mod.initialize(state)
            self.assertTrue(receipt['ok'])
            self.assertEqual(receipt['to_version'], '1.0.2')
            again = migrate_mod.initialize(state)
            self.assertTrue(again['idempotent'])

    def test_migration_after_columns_rolls_back_before_retry(self):
        with tempfile.TemporaryDirectory(prefix='lc-v102-migration-rollback-') as temp:
            state = Path(temp)
            v100 = state / 'v100'
            v100.mkdir()
            conn = sqlite3.connect(v100 / 'missions.sqlite')
            conn.executescript(
                'CREATE TABLE missions(mission_id TEXT PRIMARY KEY, project TEXT NOT NULL, '
                'state TEXT NOT NULL);'
                'CREATE TABLE schedules(schedule_id TEXT PRIMARY KEY);'
                'CREATE TABLE mission_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);'
            )
            conn.commit()
            conn.close()
            with self.assertRaises(Rejected) as raised:
                migrate_mod.initialize(state, fail_at='after_columns')
            self.assertEqual(raised.exception.code, 'MIGRATION_INTERRUPTED')
            conn = sqlite3.connect(v100 / 'missions.sqlite')
            columns = {row[1] for row in conn.execute('PRAGMA table_info(missions)')}
            conn.close()
            self.assertNotIn('generation', columns)
            receipt = migrate_mod.initialize(state)
            self.assertTrue(receipt['ok'])

    def test_capability_report_is_truthful_about_client_observation(self):
        result = self.call('capabilities')
        self.assertTrue(result['ok'], result)
        data = result['data']
        self.assertEqual(data['registered_count'], len(data['registered']))
        self.assertEqual(data['enabled_count'], len(data['enabled']))
        self.assertFalse(data['client_observed'])
        self.assertEqual(data['client_visibility'], 'unknown')
        mismatch = self.call('capabilities', client_observed=[])
        self.assertEqual(mismatch['data']['client_visibility'], 'mismatch')
        self.assertTrue(mismatch['data']['refresh_required'])

    def test_scheduler_relinks_preexisting_dispatch_after_claim_timeout(self):
        with tempfile.TemporaryDirectory(prefix='lc-v102-scheduler-') as temp:
            state = Path(temp)
            store = MissionStore(state, 'runtime-scheduler')
            scheduler = DurableScheduler(store, now_ns=lambda: 100_000_000_000)
            created = scheduler.create(
                project='pilot', objective='crash replay',
                snapshot={'workspace_root': str(state), 'workspace_identity': {'schema': 1, 'digest': 'x'},
                          'binding': 'binding', 'watch_paths': []},
                contract={}, budgets={'max_jobs': 1}, ttl_s=60, watch_paths=[],
                run_at_ns=1, delay_s=None, recur_s=None, depends_on=None,
                max_attempts=1, backoff_base_s=1, backoff_max_s=2, deadline_ns=None,
                grace_s=0, request_id='dispatch-crash-0001', resource_keys=['repo:replay'])
            dispatch_id = f"dispatch-{created['schedule_id']}-1"
            mission_id = 'mission-' + digest(
                {'schedule_id': created['schedule_id'], 'attempt': 1})[:16]
            try:
                store.begin(
                    project='pilot', objective='crash replay', workspace_root=str(state),
                    workspace_identity={'schema': 1, 'digest': 'x'},
                    policy_binding='binding',
                    policy_snapshot={'workspace_root': str(state), 'workspace_identity': {'schema': 1, 'digest': 'x'},
                                     'binding': 'binding', 'watch_paths': []},
                    success_contract={}, budgets={'max_jobs': 1}, ttl_s=60,
                    request_id=f"sched-{created['schedule_id']}-1", mission_id=mission_id,
                    schedule_id=created['schedule_id'], resource_keys=['repo:replay'],
                    dedupe_key=None, dispatch_id=dispatch_id, trust_origin='policy')
                with store.lock:
                    store.db.execute(
                        'UPDATE schedules SET dispatch_id=?,dispatch_claim_ns=?,run_at_ns=1 WHERE schedule_id=?',
                        (dispatch_id, 1, created['schedule_id']))
                    store.db.commit()
                result = scheduler.tick()
                self.assertEqual(result['actions'][0]['action'], 'dispatched')
                status = scheduler.get(created['schedule_id'])
                self.assertEqual(status['attempts'], 1)
                self.assertEqual(status['mission_id'], mission_id)
            finally:
                store.close()


class HealthStateTests(unittest.TestCase):
    def test_empty_health_is_unknown_not_unhealthy(self):
        self.assertEqual(HealthBook().summary()['state'], 'unknown-no-samples')
