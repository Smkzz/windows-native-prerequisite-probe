"""C-D4: durable active/suspended/elapsed/deadline budget accounting."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from localcontrol.v100.missions import MissionStore
from localcontrol.v080 import identity as identity_mod
from localcontrol.v100 import verifier as verifier_mod
from tests.v100.fixture import V100Case


class StoreTimeAccounting(V100Case):
    """Deterministic accumulators through a controllable store clock."""

    def _store(self, tmp: str, state: str = 'RUNNING'):
        tick = {'now': 1_000_000_000_000}
        store = MissionStore(Path(tmp), 'runtime-clock', clock_ns=lambda: tick['now'])
        mission = store.begin(
            project='pilot', objective='accounted', workspace_root=tmp,
            workspace_identity={'schema': 1, 'digest': 'identity'},
            policy_binding='binding', policy_snapshot={'watch_paths': []},
            success_contract={}, budgets={'max_jobs': 4}, ttl_s=86400,
            request_id='budget-begin-0001', state=state)
        return tick, store, mission

    def test_active_and_suspended_accumulate_by_state(self):
        with tempfile.TemporaryDirectory(prefix='lc-c4-acct-') as tmp:
            tick, store, mission = self._store(tmp)
            try:
                mid = mission['mission_id']
                token = mission['token']
                tick['now'] += 10 * 1_000_000_000            # 10s RUNNING
                store.transition(mid, 'RUNNING', 'WAITING', 'pause', {}, token=token)
                tick['now'] += 5 * 1_000_000_000             # 5s suspended
                store.transition(mid, 'WAITING', 'RUNNING', 'resume', {}, token=token,
                                 allow_stale=True)
                tick['now'] += 10 * 1_000_000_000            # 10s RUNNING
                store.transition(mid, 'RUNNING', 'RECOVERING', 'lost', {}, token=token)
                tick['now'] += 20 * 1_000_000_000            # 20s interrupted
                store.transition(mid, 'RECOVERING', 'RUNNING', 'reacquire', {}, token=token,
                                 allow_stale=True)
                tick['now'] += 5 * 1_000_000_000             # 5s RUNNING
                store.transition(mid, 'RUNNING', 'CANCELLED', 'done', {}, token=token)
                row = store.get(mid)
                self.assertEqual(row['active_ns'], 25 * 1_000_000_000)
                self.assertEqual(row['suspended_ns'], 25 * 1_000_000_000)
                self.assertEqual(row['ready_ns'], 0)
                self.assertEqual(row['time_accounting'], 'full')
            finally:
                store.close()

    def test_ready_time_and_first_running_recorded(self):
        with tempfile.TemporaryDirectory(prefix='lc-c4-ready-') as tmp:
            tick, store, mission = self._store(tmp, state='READY')
            try:
                created = mission['created_ns']
                mid = mission['mission_id']
                tick['now'] += 7 * 1_000_000_000              # 7s queued in READY
                store.transition(mid, 'READY', 'RUNNING', 'admit', {})
                row = store.get(mid)
                self.assertEqual(row['ready_ns'], 7 * 1_000_000_000)
                self.assertEqual(row['first_running_ns'], created + 7 * 1_000_000_000)
            finally:
                store.close()

    def test_legacy_rows_report_partial_basis(self):
        with tempfile.TemporaryDirectory(prefix='lc-c4-legacy-') as tmp:
            tick, store, mission = self._store(tmp)
            try:
                mid = mission['mission_id']
                with store.lock:
                    store.db.execute('UPDATE missions SET state_since_ns=NULL,'
                                     'time_accounting=NULL WHERE mission_id=?', (mid,))
                    store.db.commit()
                row = store.get(mid)
                self.assertEqual(row['time_accounting'], 'partial')
                # A later transition must not fabricate a split of pre-C.1 time.
                tick['now'] += 60 * 1_000_000_000
                store.transition(mid, 'RUNNING', 'WAITING', 'pause', {},
                                 token=mission['token'])
                row = store.get(mid)
                self.assertEqual(row['active_ns'], 0)
                self.assertIsNotNone(row['state_since_ns'])
            finally:
                store.close()


class BudgetSemantics(V100Case):
    """API-level budget declarations and enforcement."""

    def test_deadline_supersedes_default_wall(self):
        mission = self.begin_mission(
            budgets={'max_deadline_ms': 24 * 3600 * 1000, 'max_active_ms': 3600 * 1000})
        budgets = mission['budgets']
        self.assertEqual(budgets['max_deadline_ms'], 24 * 3600 * 1000)
        self.assertEqual(budgets['max_active_ms'], 3600 * 1000)
        # Declared deadline supersedes the default 8h elapsed wall cap.
        self.assertIsNone(budgets['max_wall_ms'])
        row = self.facade.v100.store.get(mission['mission_id'])
        self.assertIsNone(row['budgets']['max_wall_ms'])

    def test_explicit_wall_caps_alongside_deadline(self):
        mission = self.begin_mission(
            budgets={'max_deadline_ms': 24 * 3600 * 1000, 'max_wall_ms': 3600 * 1000})
        budgets = mission['budgets']
        self.assertEqual(budgets['max_wall_ms'], 3600 * 1000)
        self.assertEqual(self.facade.v100._elapsed_cap_ms(budgets), 3600 * 1000)

    def test_legacy_wall_semantics_unchanged(self):
        mission = self.begin_mission(budgets={'max_wall_ms': 3600 * 1000})
        budgets = mission['budgets']
        self.assertEqual(budgets['max_wall_ms'], 3600 * 1000)
        self.assertIsNone(budgets['max_deadline_ms'])
        self.assertEqual(self.facade.v100._elapsed_cap_ms(budgets), 3600 * 1000)

    def test_unknown_budget_key_rejected(self):
        result = self.call('mission_begin', objective='bad budget', request_id='budget-bad-0001',
                           success_contract={}, budgets={'max_unbounded': 1})
        self.assert_error('INVALID_BUDGETS', result)

    def test_elapsed_deadline_enforced(self):
        mission = self.begin_mission(budgets={'max_deadline_ms': 50})
        import time
        time.sleep(0.08)
        result = self.call('exec', argv=[], request_id='deadline-exec-0001',
                           mission_id=mission['mission_id'])
        self.assert_error('BUDGET_WALL', result)

    def test_active_budget_enforced_fail_closed(self):
        mission = self.begin_mission(budgets={'max_active_ms': 1})
        with self.facade.v100.store.lock:
            self.facade.v100.store.db.execute(
                'UPDATE missions SET active_ns=? WHERE mission_id=?',
                (60 * 1_000_000_000, mission['mission_id']))
            self.facade.v100.store.db.commit()
        result = self.call('exec', argv=[], request_id='active-exec-0001',
                           mission_id=mission['mission_id'])
        self.assert_error('BUDGET_ACTIVE', result)


class VerifierBudgetGate(V100Case):
    """measure() reports every category with numerator/limit semantics."""

    def _measure(self, mission_id: str) -> dict:
        row = self.facade.v100.store.get(mission_id)
        return verifier_mod.measure(
            mission=row, chain_ok=True,
            current_identity=identity_mod.build_identity(self.facade.policy, 'pilot'),
            current_binding=row['policy_binding'],
            read_sha=lambda rel: (False, None, None), run_command=lambda spec: {},
            budget_state=self.facade.v100.store.budget_state(mission_id))

    def test_gate_reports_all_categories(self):
        mission = self.begin_mission(
            budgets={'max_deadline_ms': 24 * 3600 * 1000, 'max_active_ms': 3600 * 1000})
        record = self._measure(mission['mission_id'])
        detail = next(g for g in record['gates'] if g['name'] == 'budget')['detail']
        for key in ('wall_ms', 'active_ms', 'suspended_ms', 'ready_ms', 'deadline_ms'):
            self.assertIn(key, detail)
            self.assertIn('used', detail[key])
            self.assertIn('limit', detail[key])
        self.assertIn('queue_ms', detail)
        self.assertIn('accounted_ms', detail)
        self.assertEqual(detail['accounting_basis'], 'full')
        # The wall cap is superseded (reported, not enforced) under a deadline.
        self.assertIsNone(detail['wall_ms']['limit'])
        self.assertEqual(detail['deadline_ms']['limit'], 24 * 3600 * 1000)
        self.assertTrue(record['ok'], record)

    def test_active_overflow_fails_gate(self):
        mission = self.begin_mission(budgets={'max_active_ms': 1})
        with self.facade.v100.store.lock:
            self.facade.v100.store.db.execute(
                'UPDATE missions SET active_ns=? WHERE mission_id=?',
                (60 * 1_000_000_000, mission['mission_id']))
            self.facade.v100.store.db.commit()
        record = self._measure(mission['mission_id'])
        gate = next(g for g in record['gates'] if g['name'] == 'budget')
        self.assertFalse(gate['ok'])
        self.assertFalse(record['ok'])

    def test_deadline_overflow_fails_gate(self):
        mission = self.begin_mission(budgets={'max_deadline_ms': 50})
        import time
        time.sleep(0.08)
        record = self._measure(mission['mission_id'])
        gate = next(g for g in record['gates'] if g['name'] == 'budget')
        self.assertFalse(gate['ok'])
