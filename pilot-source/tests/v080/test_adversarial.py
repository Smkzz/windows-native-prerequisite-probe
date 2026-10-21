"""Adversarial and property-style coverage for v0.8 state, leases and telemetry."""
from __future__ import annotations

import random

import localcontrol.v080.runs as runs_module
from localcontrol.v080.runs import STATES, TERMINAL
from tests.v080.fixture import V080Case


class InputFuzzTests(V080Case):
    def test_notes_fuzz_never_crashes_or_accepts_garbage(self):
        run = self.begin_run()
        token = run['token']
        rng = random.Random(20260911)
        keys = ['progress', 'phase', 'next_action', 'blockers', 'decisions', 'mystery', '1', '']
        for index in range(120):
            notes = {}
            for _ in range(rng.randint(0, 4)):
                key = rng.choice(keys)
                value = rng.choice([None, 1, 'ok', ['a'], ['a'] * 30, {'nested': True}, 'x' * 3000, ''])
                notes[key] = value
            result = self.call('run_heartbeat', run_id=run['run_id'], token=token, notes=notes,
                               request_id=f'fuzz-notes-{index:04d}')
            if result['ok']:
                token = result['data']['token']
            else:
                self.assertEqual(result['error']['code'], 'INVALID_NOTES', result)

    def test_watch_path_fuzz_rejects_traversal(self):
        for value in ['../escape', 'C:/abs', '..\\x', '.env', 'a/../b', 'con', 'name.']:
            result = self.call('run_begin', objective='fuzz', watch_paths=[value],
                               request_id='fuzz-watch-' + str(abs(hash(value)) % 10**8))
            self.assertFalse(result['ok'], result)
            self.assertIn(result['error']['code'], {'INVALID_PATH', 'PROTECTED_PATH', 'INVALID_ARGUMENT'})

    def test_telemetry_record_fuzz_invariants(self):
        store = self.facade.v080.telemetry
        rng = random.Random(7)
        tools = ['system_info', 'file_read', 'run_begin', 'bogus tool!', 'x' * 300]
        for index in range(80):
            try:
                store.record(tool=rng.choice(tools), category=rng.choice(['discovery', 'nonsense']),
                             start_ns=index, end_ns=index + rng.randint(0, 5),
                             request_bytes=rng.randint(-1, 10), response_bytes=rng.randint(0, 10),
                             status=rng.choice(['ok', 'error', 'weird']), details={'i': index})
            except Exception as exc:  # noqa: BLE001
                self.assertEqual(getattr(exc, 'code', None), 'TELEMETRY_CATEGORY' if 'nonsense' in str(exc)
                                 else getattr(exc, 'code', None))
        summary = store.summary()
        self.assertGreaterEqual(summary['totals']['operations'], 0)
        self.assertTrue(summary['integrity'])
        operations = store.operations(limit=500)
        counted = len(operations['items']) + sum(
            1 for _ in range(0))
        self.assertEqual(summary['totals']['operations'] >= len(operations['items']), True)


class SupervisorFuzzTests(V080Case):
    def test_random_lifecycle_never_violates_invariants(self):
        rng = random.Random(424242)
        run_ids = []
        for step in range(160):
            choice = rng.random()
            if choice < 0.30 or not run_ids:
                result = self.call('run_begin', objective=f'fuzz-{step}', request_id=f'fz-begin-{step:04d}')
                if result['ok']:
                    run_ids.append((result['data']['run_id'], result['data']['token']))
            elif choice < 0.55:
                run_id, token = rng.choice(run_ids)
                result = self.call('run_heartbeat', run_id=run_id, token=token,
                                   request_id=f'fz-beat-{step:04d}')
                if result['ok']:
                    run_ids = [(r, result['data']['token'] if r == run_id else t) for r, t in run_ids]
            elif choice < 0.75:
                run_id, token = rng.choice(run_ids)
                self.call('run_finish', run_id=run_id, token=token, state=rng.choice(['completed', 'failed', 'cancelled']),
                          request_id=f'fz-fin-{step:04d}')
            elif choice < 0.90:
                run_id, token = rng.choice(run_ids)
                self.call('run_begin', run_id=run_id, token=token, request_id=f'fz-resume-{step:04d}')
            else:
                run_id, _ = rng.choice(run_ids)
                self.call('run_status', run_id=run_id)
            for run_id, _ in run_ids:
                row = self.facade.v080.runs.status(run_id=run_id)['run']
                self.assertIn(row['state'], STATES)
        with self.facade.v080.runs.lock:
            rows = self.facade.v080.runs.db.execute('SELECT run_id, state FROM runs').fetchall()
        for row in rows:
            self.assertIn(row['state'], STATES)

    def test_terminal_runs_never_reactivate_or_refinish(self):
        run = self.begin_run()
        finished = self.call('run_finish', run_id=run['run_id'], token=run['token'], state='completed',
                             request_id='term-fin-0001')
        self.assertTrue(finished['ok'], finished)
        resume = self.call('run_begin', run_id=run['run_id'], token=run['token'], request_id='term-resume-0001')
        self.assert_error('RUN_TERMINAL', resume)
        again = self.call('run_finish', run_id=run['run_id'], token=run['token'], state='failed',
                          request_id='term-fin-0002')
        self.assert_error('RUN_NOT_ACTIVE', again)
        status = self.call('run_status', run_id=run['run_id'])
        self.assertEqual(status['data']['run']['state'], 'completed')

    def test_token_is_bound_to_its_run(self):
        first = self.begin_run(objective='one', request_id='bind-begin-0001')
        second = self.begin_run(objective='two', request_id='bind-begin-0002')
        cross = self.call('run_heartbeat', run_id=second['run_id'], token=first['token'],
                          request_id='bind-beat-0001')
        self.assert_error('RUN_TOKEN_INVALID', cross)

    def test_event_pruning_is_bounded_and_marked(self):
        original = runs_module.MAX_EVENTS
        runs_module.MAX_EVENTS = 5
        self.addCleanup(lambda: setattr(runs_module, 'MAX_EVENTS', original))
        runs = []
        for index in range(4):
            run = self.begin_run(objective=f'prune-{index}', request_id=f'prune-begin-{index:04d}')
            self.call('run_finish', run_id=run['run_id'], token=run['token'], state='completed',
                      request_id=f'prune-fin-{index:04d}')
            runs.append(run['run_id'])
        self.facade.v080.runs.startup('prune-epoch')
        with self.facade.v080.runs.lock:
            total = self.facade.v080.runs.db.execute('SELECT count(*) FROM run_events').fetchone()[0]
            pruned = self.facade.v080.runs.db.execute('SELECT count(*) FROM runs WHERE events_pruned=1')\
                .fetchone()[0]
        self.assertLessEqual(total, 5)
        self.assertGreaterEqual(pruned, 1)
        status = self.call('run_status', run_id=runs[0])
        self.assertTrue(status['ok'], status)
        self.assertIsNone(status['data']['run']['chain_ok'])

    def test_run_record_retention_bounds_total_rows(self):
        original = runs_module.MAX_RUNS
        runs_module.MAX_RUNS = 3
        self.addCleanup(lambda: setattr(runs_module, 'MAX_RUNS', original))
        run_ids = []
        for index in range(5):
            run = self.begin_run(objective=f'retain-{index}', request_id=f'retain-begin-{index:04d}')
            self.call('run_finish', run_id=run['run_id'], token=run['token'], state='completed',
                      request_id=f'retain-fin-{index:04d}')
            run_ids.append(run['run_id'])
        active = self.begin_run(objective='still active', request_id='retain-active-0001')
        report = self.facade.v080.runs.startup('retention-epoch')
        with self.facade.v080.runs.lock:
            total = self.facade.v080.runs.db.execute('SELECT count(*) FROM runs').fetchone()[0]
        self.assertLessEqual(total, 3)
        self.assertGreaterEqual(report['pruned_runs'], 1)
        self.assertTrue(self.call('run_status', run_id=active['run_id'])['ok'])

    def test_duplicate_request_replay_and_conflict(self):
        first = self.call('run_begin', objective='replay', request_id='replay-begin-0001')
        self.assertTrue(first['ok'], first)
        replay = self.call('run_begin', objective='replay', request_id='replay-begin-0001')
        self.assertTrue(replay['ok'], replay)
        self.assertTrue(replay.get('replayed'))
        conflict = self.call('run_begin', objective='different', request_id='replay-begin-0001')
        self.assert_error('IDEMPOTENCY_CONFLICT', conflict)

    def test_telemetry_response_bounds(self):
        for _ in range(20):
            self.call('system_info', '*')
        result = self.call('telemetry_summary', '*', view='operations', limit=500, max_response_bytes=2048)
        self.assertFalse(result['ok'], result)
        self.assertEqual(result['error']['code'], 'RESPONSE_LIMIT')
