"""C.1 Q3 hardening: deterministic multi-claimant ownership races.

Two MissionStore instances on the same SQLite file (WAL) race resume/cancel
against a recoverable mission. Store locks are per-instance, so the only
thing serializing claimants is BEGIN IMMEDIATE + the state-guarded UPDATE —
the same contention path a second daemon or concurrent tool calls would hit.
The point is not ordering (either claimant may win) but the invariant:
exactly one effective owner, the loser gets a correct rejection, and no
committed work becomes unreachable or double-owned.
"""
from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from localcontrol.nextlib.core import Rejected
from localcontrol.v100.missions import MissionStore


def _probes():
    return {'identity_probe': lambda _: {'classification': 'same'},
            'policy_probe': lambda _: {'classification': 'same'},
            'worker_probe': lambda _: {'live': False, 'owned': True}}


def _begin_at(store, state: Path, request_id: str = 'race-begin-0001', ttl_s: int = 30):
    return store.begin(
        project='pilot', objective='ownership race probe',
        workspace_root=str(state),
        workspace_identity={'schema': 1, 'digest': 'identity'},
        policy_binding='binding', policy_snapshot={'watch_paths': []},
        success_contract={}, budgets={'max_jobs': 1}, ttl_s=ttl_s,
        request_id=request_id, resource_keys=['repo:race'])


def _await_owner(store, created):
    """Drive a store into RECOVERING/AWAIT_OWNER_RESUME via restart+reconcile."""
    future = created['created_ns'] + 31 * 1_000_000_000
    store.recover()
    store.reconcile_recovering(now_ns=future, **_probes())
    row = store.get(created['mission_id'])
    assert row['state'] == 'RECOVERING' and \
        row['recovery']['action'] == 'AWAIT_OWNER_RESUME'


def _race(fn_a, fn_b):
    """Run two callables with a start barrier; return (result, raised) pairs."""
    barrier = threading.Barrier(2)
    out = [None, None]
    err = [None, None]

    def run(i, fn):
        barrier.wait(timeout=10)
        try:
            out[i] = fn()
        except BaseException as exc:  # noqa: BLE001 — capture, then classify
            err[i] = exc

    t_a = threading.Thread(target=run, args=(0, fn_a))
    t_b = threading.Thread(target=run, args=(1, fn_b))
    t_a.start(); t_b.start(); t_a.join(30); t_b.join(30)
    assert not t_a.is_alive() and not t_b.is_alive()
    return out, err


def _resume(store, mid, token, takeover=False):
    return store.resume(mid, token=token, expect='RECOVERING', ttl_s=60,
                        allow_stale=True, takeover=takeover)


class OwnershipRaceCase(unittest.TestCase):
    """Exact-invariant races: precisely one winner or an honest rejection."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lc-c1-race-')
        self.state = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _stores(self):
        a = MissionStore(self.state, 'runtime-a')
        b = MissionStore(self.state, 'runtime-b')
        return a, b

    def _winner_loser(self, out, err):
        """Exactly one side produced a result; the other raised."""
        winners = [r for r in out if r is not None]
        losers = [e for e in err if e is not None]
        self.assertEqual(len(winners) + len(losers), 2, (out, err))
        return winners, losers

    def test_two_anchor_claimants_exactly_one_owner(self):
        first, second = self._stores()
        try:
            created = _begin_at(first, self.state)
            _await_owner(second, created)
            mid = created['mission_id']
            out, err = _race(lambda: _resume(first, mid, created['token']),
                             lambda: _resume(second, mid, created['token']))
            winners, losers = self._winner_loser(out, err)
            self.assertEqual(len(winners), 1, (out, err))
            self.assertEqual(len(losers), 1)
            self.assertEqual(winners[0]['state'], 'RUNNING')
            self.assertIsInstance(losers[0], Exception)
            row = second.get(mid)
            self.assertEqual(row['state'], 'RUNNING')
            self.assertEqual(row['generation'], created['generation'] + 1)
            # Loser holds only the superseded anchor — every post-handoff
            # action with it must fail.
            with self.assertRaises(Rejected) as denied:
                second.checkpoint(mid, token=created['token'],
                                  expected_revision=None, notes=None,
                                  evidence=None, state=None, ttl_s=60)
            self.assertEqual(denied.exception.code, 'MISSION_TOKEN_INVALID')
            # Winner's delivered credential is live: lease renew succeeds
            # and rotates the owner anchor to the renewed token.
            renewed = second.heartbeat_lease(mid, token=winners[0]['token'],
                                             ttl_s=60, expect='RUNNING')
            self.assertTrue(isinstance(renewed, str) and renewed)
        finally:
            first.close(); second.close()

    def test_anchor_resume_vs_takeover_single_owner(self):
        first, second = self._stores()
        try:
            created = _begin_at(first, self.state, request_id='race-takeover-0001')
            _await_owner(second, created)
            mid = created['mission_id']
            out, err = _race(lambda: _resume(first, mid, created['token']),
                             lambda: _resume(second, mid, 'operator-token',
                                             takeover=True))
            winners, losers = self._winner_loser(out, err)
            self.assertEqual(len(winners), 1, (out, err))
            row = first.get(mid)
            self.assertEqual(row['state'], 'RUNNING')
            self.assertEqual(row['generation'], created['generation'] + 1)
            # Whichever side lost cannot act through its credential.
            with self.assertRaises(Rejected):
                first.heartbeat_lease(mid, token='operator-token',
                                      ttl_s=60, expect='RUNNING')
        finally:
            first.close(); second.close()

    def test_resume_vs_cancel_exactly_one_outcome(self):
        first, second = self._stores()
        try:
            created = _begin_at(first, self.state, request_id='race-cancel-0001')
            _await_owner(second, created)
            mid = created['mission_id']
            out, err = _race(
                lambda: _resume(first, mid, created['token']),
                lambda: second.cancel(mid, token=created['token'],
                                      reason='racing cancel', abandon=False,
                                      allow_stale=False))
            winners, losers = self._winner_loser(out, err)
            self.assertEqual(len(winners), 1, (out, err))
            row = second.get(mid)
            self.assertIn(row['state'], ('RUNNING', 'CANCELLED'))
            # If cancel won, mission is durably terminal: replay must not
            # resurrect it. If resume won, the winner owns it solely.
            if row['state'] == 'CANCELLED':
                with self.assertRaises(Rejected):
                    _resume(first, mid, created['token'])
            else:
                with self.assertRaises(Rejected):
                    second.cancel(mid, token=created['token'],
                                  reason='late cancel', abandon=False,
                                  allow_stale=False)
        finally:
            first.close(); second.close()

    def test_reclaim_vs_resume_never_unreachable_creds(self):
        """Reclaim racing resume must not mint a scheduler-only credential."""
        first, second = self._stores()
        try:
            created = _begin_at(first, self.state)
            mid = created['mission_id']
            # Mid-reconcile state: expired lease, RECONCILE_LEASE action.
            second.recover()
            with second.lock:
                second.db.execute(
                    "UPDATE missions SET recovery_action='RECONCILE_LEASE' "
                    "WHERE mission_id=?", (mid,))
                second.db.commit()
            out, err = _race(
                lambda: _resume(first, mid, created['token']),
                lambda: second.reconcile_recovering(
                    now_ns=created['created_ns'] + 31 * 1_000_000_000,
                    **_probes()))
            row = first.get(mid)
            if out[0] is not None:
                # Resume won: fresh delivered credentials, RUNNING.
                self.assertEqual(row['state'], 'RUNNING')
                self.assertEqual(row['generation'], created['generation'] + 1)
            else:
                # Reclaim won first: still claimable under the same anchor —
                # never a minted-but-undelivered credential.
                self.assertEqual(row['state'], 'RECOVERING')
                self.assertIsInstance(err[0], Exception)
                retry = _resume(first, mid, created['token'])
                self.assertEqual(retry['state'], 'RUNNING')
        finally:
            first.close(); second.close()

    def test_replay_after_response_loss_is_safe_rejection(self):
        """Caller loses the resume response; replay must not double-own."""
        first, second = self._stores()
        try:
            created = _begin_at(first, self.state, request_id='race-replay-0001')
            _await_owner(second, created)
            mid = created['mission_id']
            won = _resume(first, mid, created['token'])
            self.assertEqual(won['state'], 'RUNNING')
            with self.assertRaises(Rejected) as denied:
                _resume(first, mid, created['token'])
            self.assertEqual(denied.exception.code, 'STATE_MISMATCH')
            row = first.get(mid)
            self.assertEqual(row['state'], 'RUNNING')
            self.assertEqual(row['generation'], created['generation'] + 1)
        finally:
            first.close(); second.close()

    def test_winner_crash_recovers_via_legitimate_protocol(self):
        """The winner's lease lapses; the next claimant uses the new anchor —
        never the superseded one — or explicit takeover."""
        first, second = self._stores()
        try:
            created = _begin_at(first, self.state, request_id='race-crash-0001')
            _await_owner(second, created)
            mid = created['mission_id']
            won = _resume(first, mid, created['token'])
            first.close()  # winner's runtime dies holding the lease
            # Winner's lease expires; sweep → reconcile → AWAIT on new anchor.
            expiry = created['created_ns'] + 200 * 1_000_000_000
            second.reconcile_recovering(now_ns=expiry, **_probes())
            row = second.get(mid)
            self.assertEqual(row['state'], 'RECOVERING')
            # Superseded anchor is dead even for the recovery path.
            with self.assertRaises(Rejected) as denied:
                _resume(second, mid, created['token'])
            self.assertEqual(denied.exception.code, 'MISSION_TOKEN_INVALID')
            # The winner's delivered token (the anchor now) still claims.
            reclaimed = _resume(second, mid, won['token'])
            self.assertEqual(reclaimed['state'], 'RUNNING')
            self.assertEqual(reclaimed['generation'], created['generation'] + 2)
        finally:
            second.close()

    def test_foreign_claimants_cannot_race_in(self):
        first, second = self._stores()
        try:
            created = _begin_at(first, self.state, request_id='race-foreign-0001')
            _await_owner(second, created)
            mid = created['mission_id']
            out, err = _race(
                lambda: _resume(first, mid, 'foreign-a'),
                lambda: _resume(second, mid, 'foreign-b'))
            self.assertIsNone(out[0]); self.assertIsNone(out[1])
            for e in err:
                self.assertIsInstance(e, Rejected)
                self.assertEqual(e.code, 'MISSION_TOKEN_INVALID')
            row = first.get(mid)
            self.assertEqual(row['state'], 'RECOVERING')
            self.assertEqual(row['recovery']['action'], 'AWAIT_OWNER_RESUME')
        finally:
            first.close(); second.close()

    def test_stale_generation_rejected_after_handoff(self):
        first, second = self._stores()
        try:
            created = _begin_at(first, self.state, request_id='race-stalegen-0001')
            _await_owner(second, created)
            mid = created['mission_id']
            won = _resume(first, mid, created['token'])
            # A claimant acting on the old generation+anchor is refused.
            with self.assertRaises(Rejected) as denied:
                first.heartbeat_lease(mid, token=created['token'], ttl_s=60,
                                      expect='RUNNING')
            self.assertEqual(denied.exception.code, 'MISSION_TOKEN_INVALID')
            with self.assertRaises(Rejected) as denied2:
                first.cancel(mid, token=created['token'], reason='stale',
                             abandon=False, allow_stale=False,
                             generation=created['generation'])
            self.assertIn(denied2.exception.code,
                          {'MISSION_TOKEN_INVALID', 'STALE_GENERATION'})
            # Winner unaffected; both store views agree on the rotated anchor.
            self.assertEqual(first.get(mid)['state'], 'RUNNING')
            with first.lock:
                row = first.db.execute(
                    'SELECT owner_token_sha256,generation FROM missions '
                    'WHERE mission_id=?', (mid,)).fetchone()
            self.assertEqual(row['generation'], created['generation'] + 1)
            self.assertNotEqual(won['token'], created['token'])
        finally:
            first.close(); second.close()


if __name__ == '__main__':
    unittest.main()
