"""Admission-reserve and essential-lane tests for the receipts store.

The reserve invariant: every reserved-but-unfinished request and every
nonterminal job owes the audit ledger a bounded number of mandatory records.
Routine admissions are denied before that space is consumed, so completion,
cancellation and maintenance records remain writable under capacity pressure.
Rotation behavior itself is covered in test_core.py.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from localcontrol.errors import ControlError
from localcontrol.store import (Store, canonical, digest,
                                AUDIT_ROWS_PER_RESERVED_REQUEST,
                                AUDIT_ESSENTIAL_OVERFLOW)


def _chain_fill(store: Store, n: int, kind: str = 'bulk') -> int:
    """Append n chain-valid rows directly (test fixture, not a product path)."""
    with store.transaction():
        row = store.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else '0' * 64
        for i in range(n):
            payload = canonical({'time_ns': i + 1, 'kind': kind, 'metadata': {'i': i}})
            hashed = hashlib.sha256((prev + payload).encode()).hexdigest()
            store.db.execute('INSERT INTO audit(payload,prev,hash) VALUES(?,?,?)',
                             (payload, prev, hashed))
            prev = hashed
    return n


def _rows(store: Store) -> int:
    return store.db.execute('SELECT count(*) FROM audit').fetchone()[0]


class AuditReserveCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _store(self, name: str, **kw) -> Store:
        store = Store(self.root / name, **kw)
        # Rotation is qualified separately; the reserve is measured without it.
        store._ensure_audit_headroom = lambda reason: None
        return store

    def test_routine_admission_denied_but_finish_essential(self):
        store = self._store('deny-admission', max_audit_rows=60, audit_reserve_margin=10)
        try:
            admitted = []
            for i in range(64):
                try:
                    store.reserve('s', 'req-%08d' % i, digest({'i': i}))
                    admitted.append(i)
                except ControlError as err:
                    self.assertEqual(err.code, 'AUDIT_CAPACITY')
                    break
            # The new request's INSERT lands before its audit row, so its own
            # reserve is already owed: count=i, owed=20*(i+1)+10 -> 21i+31<=60.
            self.assertEqual(len(admitted), 2)
            for i in admitted:
                store.finish('s', 'req-%08d' % i, {'ok': True})
            self.assertTrue(store.verify())
        finally:
            store.close()

    def test_finish_allowed_at_row_cap(self):
        store = self._store('finish-at-cap', max_audit_rows=30, audit_reserve_margin=4)
        try:
            store.reserve('s', 'req-00000001', digest({'a': 1}))
            _chain_fill(store, 29 - _rows(store))  # finish takes the final row
            self.assertEqual(_rows(store), 29)
            store.finish('s', 'req-00000001', {'ok': False})
            self.assertEqual(_rows(store), 30)
            with self.assertRaises(ControlError) as ctx:
                store.reserve('s', 'req-00000002', digest({'a': 2}))
            self.assertEqual(ctx.exception.code, 'AUDIT_CAPACITY')
            self.assertTrue(store.verify())
        finally:
            store.close()

    def test_essential_overflow_is_bounded(self):
        store = self._store('bounded-overflow', max_audit_rows=30, audit_reserve_margin=4)
        try:
            _chain_fill(store, 30)
            for i in range(AUDIT_ESSENTIAL_OVERFLOW + 2):
                try:
                    store.audit_essential('job_finished', {'i': i})
                except ControlError as err:
                    self.assertEqual(err.code, 'AUDIT_CAPACITY')
                    break
            self.assertEqual(_rows(store), 30 + AUDIT_ESSENTIAL_OVERFLOW)
            self.assertTrue(store.verify())
        finally:
            store.close()

    def test_reclamation_uses_essential_lane(self):
        store = self._store('reclaim-essential', max_audit_rows=40, audit_reserve_margin=4)
        try:
            with store.transaction():
                for i in range(6):
                    store.db.execute(
                        'INSERT INTO jobs VALUES(?,?,?)',
                        ('job-%d' % i, 's', canonical({'job_id': 'job-%d' % i,
                                                       'status': 'completed',
                                                       'started_ns': i + 1})))
            _chain_fill(store, 40 - _rows(store))
            result = store.reclaim_terminal_jobs('s', keep_recent=1, reason='test')
            self.assertEqual(result['archived'], 5)
            self.assertTrue(store.verify())
        finally:
            store.close()

    def test_capacity_snapshot_reports_reserve(self):
        store = self._store('snapshot', max_audit_rows=200, audit_reserve_margin=16)
        try:
            store.reserve('s', 'req-00000001', digest({'a': 1}))
            snap = store.audit_capacity_snapshot()
            self.assertEqual(snap['max_rows'], 200)
            self.assertEqual(snap['reserved_owed_rows'],
                             1 * AUDIT_ROWS_PER_RESERVED_REQUEST + 16)
            self.assertIn('rotation_trigger_rows', snap)
            self.assertIn('est_days_to_trigger', snap)
            cap = store.capacity_snapshot()
            self.assertEqual(cap['requests']['pending_reserved'], 1)
            self.assertIn('jobs', cap)
        finally:
            store.close()

    def test_rotation_backoff_is_bounded(self):
        store = Store(self.root / 'backoff', max_audit_rows=20)
        try:
            for i in range(17):
                store.audit('probe', {'i': i})
            (self.root / 'backoff' / 'audit-archive').write_text('not-a-directory',
                                                               encoding='utf-8')
            with self.assertRaises(FileExistsError):
                store.audit('trigger_broken_rotation', {})
            # In backoff: routine calls fail fast with the recorded error.
            with self.assertRaises(ControlError) as ctx:
                store.audit('probe_during_backoff', {})
            self.assertEqual(ctx.exception.code, 'AUDIT_ROTATION_BACKOFF')
            # Essential lane still records while rotation is broken.
            store.audit_essential('job_finished', {'job_id': 'j', 'status': 'completed'})
            self.assertTrue(store.verify())
        finally:
            store.close()

    def test_recovery_clears_rotation_failure(self):
        store = Store(self.root / 'recovery', max_audit_rows=20)
        try:
            for i in range(17):
                store.audit('probe', {'i': i})
            (self.root / 'recovery' / 'audit-archive').write_text('x',
                                                              encoding='utf-8')
            with self.assertRaises(FileExistsError):
                store.audit('boom', {})
            self.assertIsNotNone(store._rotation_failure)
            # Operator removes the block; backoff expiry lets the next routine
            # write retry rotation, which clears the degraded state.
            (self.root / 'recovery' / 'audit-archive').unlink()
            store._rotation_backoff_until_ns = 0  # simulate backoff expiry
            store.audit('post_recovery', {})
            self.assertIsNone(store._rotation_failure)
            self.assertIsNotNone(store._last_rotation_error)
            self.assertTrue(store.verify())
        finally:
            store.close()

    def test_external_rotation_cancels_backoff(self):
        store = Store(self.root / 'ext-recovery', max_audit_rows=20)
        try:
            for i in range(17):
                store.audit('probe', {'i': i})
            (self.root / 'ext-recovery' / 'audit-archive').write_text('x',
                                                                  encoding='utf-8')
            with self.assertRaises(FileExistsError):
                store.audit('boom', {})
            # Operator repairs the cause AND rotates externally while backoff
            # is still active; headroom recovery must cancel the backoff.
            (self.root / 'ext-recovery' / 'audit-archive').unlink()
            store._rotate_audit_locked('operator external rotation')
            store.audit('post_external', {})
            self.assertIsNone(store._rotation_failure)
            self.assertEqual(store._rotation_backoff_until_ns, 0)
            self.assertTrue(store.verify())
        finally:
            store.close()

    def test_corruption_remains_fail_closed_through_backoff(self):
        store = Store(self.root / 'corrupt-backoff', max_audit_rows=20)
        try:
            for i in range(17):
                store.audit('probe', {'i': i})
            with store.transaction():
                store.db.execute(
                    "UPDATE audit SET payload=replace(payload,'probe','tampered')"
                    " WHERE seq=3")
            with self.assertRaises(ControlError) as ctx:
                store.audit('trigger_rotation', {})
            self.assertEqual(ctx.exception.code, 'AUDIT_CORRUPT')
            self.assertEqual(store._rotation_failure['code'], 'AUDIT_CORRUPT')
            # During backoff the corruption code must still surface; the
            # essential lane must not append to a chain that failed verify.
            with self.assertRaises(ControlError) as ctx2:
                store.audit_essential('job_finished',
                                      {'job_id': 'j', 'status': 'completed'})
            self.assertEqual(ctx2.exception.code, 'AUDIT_CORRUPT')
            with self.assertRaises(ControlError) as ctx3:
                store.audit('routine_during_backoff', {})
            self.assertEqual(ctx3.exception.code, 'AUDIT_CORRUPT')
        finally:
            store.close()

    def test_owed_cache_does_not_survive_rollback(self):
        # A denied reserve rolls back its INSERT; the owed cache must not keep
        # the post-mutation value (phantom debt would deny later admissions,
        # phantom headroom would over-admit).
        store = self._store('cache-rollback', max_audit_rows=10, audit_reserve_margin=2)
        try:
            with self.assertRaises(ControlError) as ctx:
                store.reserve('s', 'req-00000001', digest({'a': 1}))
            self.assertEqual(ctx.exception.code, 'AUDIT_CAPACITY')
            self.assertIsNone(store._owed_cache)
            # Rebuilt from authoritative state: no pending request survives.
            self.assertEqual(store._owed_reserve_locked(), 2)
            # And a request that fits does commit and leaves no stale debt.
            store2 = self._store('cache-ok', max_audit_rows=100, audit_reserve_margin=2)
            try:
                store2.reserve('s', 'req-00000001', digest({'a': 1}))
                store2.finish('s', 'req-00000001', {'ok': True})
                self.assertEqual(store2._owed_reserve_locked(), 2)
            finally:
                store2.close()
        finally:
            store.close()

    def test_busy_checkpoint_does_not_open_backoff(self):
        # Rotation contention (WAL reader blocks the checkpoint) surfaces as
        # AUDIT_ROTATION_BUSY — transient, not a failure. It must not record a
        # failure or open the 60s routine-admission backoff, and the next call
        # must retry rotation immediately.
        store = Store(self.root / 'busy', max_audit_rows=20)
        real_rotate = store._rotate_audit_locked
        calls = []
        try:
            for i in range(17):
                store.audit('probe', {'i': i})

            def busy(reason):
                calls.append(reason)
                raise ControlError('AUDIT_ROTATION_BUSY', 'checkpoint busy')
            store._rotate_audit_locked = busy
            with self.assertRaises(ControlError) as ctx:
                store.audit('trigger_busy_rotation', {})
            self.assertEqual(ctx.exception.code, 'AUDIT_ROTATION_BUSY')
            self.assertIsNone(store._rotation_failure)
            self.assertEqual(store._rotation_backoff_until_ns, 0)
            # Essential lane treats BUSY as degradable too.
            store.audit_essential('job_finished', {'job_id': 'j', 'status': 'completed'})
            self.assertIsNone(store._rotation_failure)
            # Contention gone: the next routine write rotates normally.
            store._rotate_audit_locked = real_rotate
            store.audit('post_contention', {})
            self.assertIsNone(store._rotation_failure)
            self.assertTrue(store.verify())
        finally:
            store._rotate_audit_locked = real_rotate
            store.close()

    def test_unknown_rotation_failure_fails_closed(self):
        # A recorded failure whose code is not a known-transient (e.g.
        # sqlite3.DatabaseError) must surface as AUDIT_ROTATION_FATAL during
        # backoff on BOTH lanes — essential writes must not degrade onto a
        # chain whose rotation just failed for an unclassified reason.
        store = Store(self.root / 'fatal', max_audit_rows=20)
        try:
            for i in range(17):
                store.audit('probe', {'i': i})
            import time as _t
            store._rotation_failure = {'time_ns': _t.time_ns(),
                                       'code': 'DatabaseError',
                                       'message': 'database disk image is malformed'}
            store._rotation_backoff_until_ns = _t.time_ns() + 60_000_000_000
            for call in (lambda: store.audit('x', {}),
                         lambda: store.audit_essential('job_finished', {'job_id': 'j'})):
                with self.assertRaises(ControlError) as ctx:
                    call()
                self.assertEqual(ctx.exception.code, 'AUDIT_ROTATION_FATAL')
            # And the transient whitelist still degrades on the essential lane.
            store._rotation_failure['code'] = 'FileExistsError'
            store.audit_essential('job_finished', {'job_id': 'j', 'status': 'completed'})
            self.assertTrue(store.verify())
        finally:
            store.close()

    def test_stale_rotation_failure_clears_in_snapshot(self):
        store = Store(self.root / 'stale-signal', max_audit_rows=20)
        try:
            for i in range(17):
                store.audit('probe', {'i': i})
            (self.root / 'stale-signal' / 'audit-archive').write_text('x',
                                                                    encoding='utf-8')
            with self.assertRaises(FileExistsError):
                store.audit('boom', {})
            self.assertIsNotNone(store._rotation_failure)
            (self.root / 'stale-signal' / 'audit-archive').unlink()
            store._rotate_audit_locked('operator external rotation')
            snap = store.audit_capacity_snapshot()
            self.assertIsNone(snap['rotation_failure'])
            self.assertFalse(snap['rotation_backoff_active'])
            self.assertIsNotNone(snap['last_rotation_error'])
        finally:
            store.close()

    def test_external_script_rotates_live_store(self):
        store = Store(self.root / 'script-rotate', max_audit_rows=20)
        script = Path(__file__).resolve().parent.parent / 'scripts' / 'audit_rotate.py'
        try:
            _chain_fill(store, 19)  # fixture write: bypasses auto-rotation
            self.assertEqual(_rows(store), 19)
            proc = subprocess.run(
                [sys.executable, str(script),
                 '--db', str(self.root / 'script-rotate' / 'receipts.sqlite'),
                 '--rotate', '--max-rows', '20', '--reason', 'test'],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            result = json.loads(proc.stdout)
            self.assertTrue(result['rotated'], result)
            self.assertEqual(result['archived_rows'], 19)
            archive = Path(result['archive_file'])
            self.assertTrue(archive.is_file())
            # The open store observes a valid post-rotation chain and keeps
            # writing onto the new genesis without a restart.
            self.assertTrue(store.verify())
            store.audit('post_rotation', {'ok': True})
            self.assertTrue(store.verify())
            self.assertEqual(_rows(store), 2)
        finally:
            store.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
