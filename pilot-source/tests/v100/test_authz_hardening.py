"""C.1 security-hardening regressions.

Pins the independent-review findings: unauthenticated finish, credential-less
supersession, checkpoint-as-stealth-resume, credential-bearing replay caches,
expired-lease sweep oscillation, and unlocked request recording.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from localcontrol.nextlib.core import Rejected
from localcontrol.v100.missions import MissionStore
from tests.v100.fixture import V100Case


def _probes():
    return {'identity_probe': lambda _: {'classification': 'same'},
        'policy_probe': lambda _: {'classification': 'same'},
        'worker_probe': lambda _: {'live': False, 'owned': True}}


def _store(state_dir: Path) -> MissionStore:
    return MissionStore(state_dir, 'runtime-test')


def _begin(store: MissionStore, state_dir: Path, request_id: str, ttl_s: int = 300):
    return store.begin(
        project='pilot', objective='authz probe', workspace_root=str(state_dir),
        workspace_identity={'schema': 1, 'digest': 'identity'},
        policy_binding='binding', policy_snapshot={'watch_paths': []},
        success_contract={}, budgets={'max_jobs': 1}, ttl_s=ttl_s,
        request_id=request_id)


def _recovering(store: MissionStore, created):
    future = created['created_ns'] + 301 * 1_000_000_000
    store.recover()
    store.reconcile_recovering(now_ns=future, **_probes())
    row = store.get(created['mission_id'])
    assert row['state'] == 'RECOVERING'
    return row


class FinishAuthorizationTests(V100Case):
    v100 = True

    def test_finish_without_token_is_rejected(self):
        mission = self.begin_mission()
        result = self.call('mission_finish', mission_id=mission['mission_id'],
                   request_id='finish-no-token-01')
        self.assertFalse(result['ok'])
        self.assertEqual(result['error']['code'], 'MISSION_TOKEN_INVALID')
        self.assertEqual(self.mission(mission['mission_id'])['state'], 'RUNNING')

    def test_finish_without_token_cannot_verify(self):
        mission = self.begin_mission()
        result = self.call('mission_finish', mission_id=mission['mission_id'],
                   request_id='finish-no-token-02')
        self.assertFalse(result['ok'])
        self.assertEqual(result['error']['code'], 'MISSION_TOKEN_INVALID')
        # Even a passing contract must never commit without the owner token.
        self.assertNotIn(self.mission(mission['mission_id'])['state'],
                 ('VERIFYING', 'SUCCEEDED', 'FAILED'))


class SupersedeAuthorizationTests(V100Case):
    v100 = True

    def test_supersede_requires_predecessor_credential_or_takeover(self):
        victim = self.begin_mission(request_id='supersede-victim-01')
        denied = self.call('mission_begin', objective='hostile supersede',
                   request_id='supersede-denied-01',
                   supersedes_mission_id=victim['mission_id'])
        self.assertFalse(denied['ok'])
        self.assertEqual(denied['error']['code'], 'MISSION_TOKEN_INVALID')
        self.assertEqual(self.mission(victim['mission_id'])['state'], 'RUNNING')

        owned = self.call('mission_begin', objective='owner supersede',
                  request_id='supersede-owned-01',
                  supersedes_mission_id=victim['mission_id'],
                  supersedes_token=victim['token'])
        self.assertTrue(owned['ok'], owned)
        self.assertEqual(self.mission(victim['mission_id'])['state'], 'ABANDONED')

    def test_supersede_takeover_is_lease_gated(self):
        # Takeover is the operator escape, as on resume/cancel: it is honored
        # only once the predecessor's lease has actually lapsed. A live mission
        # must never be superseded by a bare takeover flag.
        victim = self.begin_mission(request_id='supersede-victim-02')
        denied = self.call('mission_begin', objective='live-lease takeover',
                  request_id='supersede-takeover-01',
                  supersedes_mission_id=victim['mission_id'],
                  takeover=True)
        self.assertFalse(denied['ok'])
        self.assertEqual(denied['error']['code'], 'MISSION_TOKEN_INVALID')
        self.assertEqual(self.mission(victim['mission_id'])['state'], 'RUNNING')
        # Once the lease lapses the same takeover is the legitimate operator
        # escape for collecting abandoned work.
        store = self.facade.v100.store
        with store.lock:
            store.db.execute('UPDATE missions SET lease_expires_ns=? WHERE mission_id=?',
                             (0, victim['mission_id']))
            store.db.commit()
        owned = self.call('mission_begin', objective='expired-lease takeover',
                  request_id='supersede-takeover-02',
                  supersedes_mission_id=victim['mission_id'],
                  takeover=True)
        self.assertTrue(owned['ok'], owned)
        self.assertEqual(self.mission(victim['mission_id'])['state'], 'ABANDONED')

    def test_supersede_fences_pass_only_to_authorized_successor(self):
        victim = self.begin_mission(request_id='supersede-victim-03',
                        resource_keys=['repo:guarded'])
        denied = self.call('mission_begin', objective='fence theft',
                   request_id='supersede-fences-01',
                   resource_keys=['repo:guarded'],
                   supersedes_mission_id=victim['mission_id'])
        self.assertFalse(denied['ok'])
        self.assertEqual(denied['error']['code'], 'MISSION_TOKEN_INVALID')
        owned = self.call('mission_begin', objective='legit fence handoff',
                  request_id='supersede-fences-02',
                  resource_keys=['repo:guarded'],
                  supersedes_mission_id=victim['mission_id'],
                  supersedes_token=victim['token'])
        self.assertTrue(owned['ok'], owned)
        self.assertEqual(owned['data']['resource_keys'], ['repo:guarded'])


class ReplayCredentialTests(V100Case):
    v100 = True

    def test_replayed_begin_response_does_not_reissue_token(self):
        args = {'objective': 'replayable begin', 'request_id': 'replay-begin-01',
            'success_contract': {}, 'budgets': {}}
        first = self.call('mission_begin', **args)
        self.assertTrue(first['ok'], first)
        self.assertIn('token', first['data'])
        second = self.call('mission_begin', **args)
        self.assertTrue(second['ok'], second)
        self.assertTrue(second.get('replayed'))
        self.assertEqual(second['data']['mission_id'], first['data']['mission_id'])
        self.assertNotIn('token', second['data'])
        self.assertNotIn('fence_token', second['data'])

    def test_replayed_checkpoint_response_does_not_reissue_token(self):
        mission = self.begin_mission(request_id='replay-begin-02')
        args = {'mission_id': mission['mission_id'], 'token': mission['token'],
            'request_id': 'replay-cp-01', 'notes': {'k': 'v'}}
        first = self.call('mission_checkpoint', **args)
        self.assertTrue(first['ok'], first)
        self.assertIn('token', first['data'])
        second = self.call('mission_checkpoint', **args)
        self.assertTrue(second['ok'], second)
        self.assertTrue(second.get('replayed'))
        self.assertNotIn('token', second['data'])

    def test_checkpoint_rejects_foreign_project(self):
        mission = self.begin_mission(request_id='replay-begin-03')
        result = self.call('mission_checkpoint', project='nonexistent',
                   mission_id=mission['mission_id'],
                   token=mission['token'], request_id='cp-xproject-01')
        self.assertFalse(result['ok'])
        self.assertIn(result['error']['code'],
              ('UNKNOWN_PROJECT', 'MISSION_PROJECT_MISMATCH'))


class StoreBackedCase(unittest.TestCase):
    def _mkstore(self, tmp: Path, runtime: str = 'runtime-test') -> MissionStore:
        store = MissionStore(tmp, runtime)
        self.addCleanup(store.close)
        return store

    def _tmpdir(self) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix='lc-authz-'))
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        return tmp


class CheckpointBoundaryTests(StoreBackedCase):
    """Store-level: checkpoint must not bypass resume gates or mint
    credentials around generation/fence rotation."""

    def _recovering_mission(self, store, tmp):
        created = _begin(store, tmp, 'authz-begin-01')
        return created, _recovering(store, created)

    def test_checkpoint_rejected_on_recovering(self):
        tmp = self._tmpdir()
        store = self._mkstore(tmp)
        created, _ = self._recovering_mission(store, tmp)
        with self.assertRaises(Rejected) as ctx:
            store.checkpoint(created['mission_id'], token=created['token'],
                     expected_revision=None, notes=None, evidence=None,
                     state='RUNNING', ttl_s=300)
        self.assertEqual(ctx.exception.code, 'STATE_MISMATCH')
        self.assertEqual(store.get(created['mission_id'])['state'], 'RECOVERING')

    def test_checkpoint_cannot_leave_blocked(self):
        tmp = self._tmpdir()
        store = self._mkstore(tmp)
        created = _begin(store, tmp, 'authz-begin-02')
        # Drive to BLOCKED via transition (internal path), then prove the
        # checkpoint surface cannot drive it back to RUNNING.
        store.transition(created['mission_id'], 'RUNNING', 'BLOCKED',
                 'operator_block', {}, token=created['token'])
        row = store.get(created['mission_id'])
        self.assertEqual(row['state'], 'BLOCKED')
        with self.assertRaises(Rejected) as ctx:
            store.checkpoint(created['mission_id'], token=created['token'],
                     expected_revision=None, notes=None, evidence=None,
                     state='RUNNING', ttl_s=300)
        self.assertEqual(ctx.exception.code, 'ILLEGAL_TRANSITION')
        # Notes-only checkpoint on BLOCKED stays legal.
        ok = store.checkpoint(created['mission_id'], token=created['token'],
                      expected_revision=None, notes={'still': 'held'},
                      evidence=None, state=None, ttl_s=300)
        self.assertEqual(ok['state'], 'BLOCKED')
        self.assertEqual(store.get(created['mission_id'])['state'], 'BLOCKED')

    def test_checkpoint_ttl_is_bounded(self):
        tmp = self._tmpdir()
        store = self._mkstore(tmp)
        created = _begin(store, tmp, 'authz-begin-03')
        with self.assertRaises(Rejected) as ctx:
            store.checkpoint(created['mission_id'], token=created['token'],
                     expected_revision=None, notes=None, evidence=None,
                     state=None, ttl_s=10 ** 9)
        self.assertEqual(ctx.exception.code, 'INVALID_TTL')
        row = store.get(created['mission_id'])
        self.assertLess(row['lease_expires_ns'], created['created_ns'] + 86401 * 1_000_000_000)

    def test_checkpoint_race_cannot_resurrect_terminal(self):
        """The UPDATE carries AND state=? so a concurrent terminal transition
        committed between check and write cannot be overwritten."""
        tmp = self._tmpdir()
        store_a = self._mkstore(tmp, 'runtime-a')
        store_b = self._mkstore(tmp, 'runtime-b')
        created = _begin(store_a, tmp, 'authz-begin-04')
        # Read-then-write interleaving across store instances: cancel via B
        # first, then checkpoint via A must hit STATE_MISMATCH up front.
        store_b.cancel(created['mission_id'], token=created['token'],
                   reason='cancelled', abandon=False, allow_stale=False)
        with self.assertRaises(Rejected) as ctx:
            store_a.checkpoint(created['mission_id'], token=created['token'],
                       expected_revision=None, notes=None, evidence=None,
                       state='RUNNING', ttl_s=300)
        self.assertEqual(ctx.exception.code, 'STATE_MISMATCH')
        self.assertEqual(store_a.get(created['mission_id'])['state'], 'CANCELLED')


class SweepOscillationTests(StoreBackedCase):
    def test_expired_blocked_mission_is_not_re_swept(self):
        """BLOCKED is owner-gated and quiescent: the sweep must not churn it
        through RECOVERING every tick."""
        tmp = self._tmpdir()
        store = self._mkstore(tmp)
        created = _begin(store, tmp, 'authz-begin-05', ttl_s=30)
        store.transition(created['mission_id'], 'RUNNING', 'BLOCKED',
                 'operator_block', {}, token=created['token'])
        future = created['created_ns'] + 301 * 1_000_000_000
        receipts = store.reconcile_recovering(now_ns=future, **_probes())
        self.assertEqual(receipts, [])
        row = store.get(created['mission_id'])
        self.assertEqual(row['state'], 'BLOCKED')

    def test_expired_running_mission_still_sweeps(self):
        tmp = self._tmpdir()
        store = self._mkstore(tmp)
        created = _begin(store, tmp, 'authz-begin-06', ttl_s=30)
        future = created['created_ns'] + 301 * 1_000_000_000
        receipts = store.reconcile_recovering(now_ns=future, **_probes())
        self.assertTrue(any(r['mission_id'] == created['mission_id']
                    and r['reason'] == 'lease_expired' for r in receipts),
                receipts)


if __name__ == '__main__':
    unittest.main()
