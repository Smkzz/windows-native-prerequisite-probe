"""v1.1 durable store: schema, transitions, event chain, recovery, intents."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from localcontrol.agents import state as st
from localcontrol.agents.store import AgentStore
from localcontrol.nextlib.core import Rejected


def record(agent_id: str, scope: str = 'local-owner:pilot', project: str = 'pilot',
           **overrides) -> dict:
    base = {'agent_id': agent_id, 'scope': scope, 'project': project, 'task': 't',
            'task_sha256': 'x' * 64, 'profile': 'read_only', 'provider': 'codex',
            'workspace_mode': 'existing', 'workspace_root': 'C:/pilot',
            'depth': 0, 'limits': {'max_turns': 4},
            'provider_state': {'sandbox': 'read_only'}}
    base.update(overrides)
    return base


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lc110-store-')
        self.store = AgentStore(Path(self.tmp.name), 'runtime-test01')

    def tearDown(self):
        if self.store is not None:
            self.store.close()
        self.tmp.cleanup()

    def test_create_transition_and_events(self):
        self.store.create(record('agt-0000000000000001'))
        stored = self.store.transition('agt-0000000000000001', {st.QUEUED}, st.STARTING,
                                       'spawn.starting', {})
        self.assertEqual(stored['state'], st.STARTING)
        stored = self.store.transition('agt-0000000000000001', {st.STARTING}, st.RUNNING,
                                       'turn.started', {'turn_id': 't1'}, active_turn_id='t1')
        self.assertEqual(stored['active_turn_id'], 't1')
        events = self.store.events('agt-0000000000000001')
        self.assertEqual([e['kind'] for e in events['events']],
                         ['spawn.accepted', 'spawn.starting', 'turn.started'])
        self.assertTrue(self.store.verify_chain()['ok'])

    def test_invalid_transition_rejected(self):
        self.store.create(record('agt-0000000000000002'))
        with self.assertRaises(Rejected) as ctx:
            self.store.transition('agt-0000000000000002', {st.QUEUED}, st.RUNNING, 'bad', {})
        self.assertEqual(ctx.exception.code, 'STATE_MISMATCH')
        with self.assertRaises(Rejected) as ctx:
            self.store.transition('agt-0000000000000002', {st.RUNNING}, st.RUNNING, 'bad', {})
        self.assertEqual(ctx.exception.code, 'STATE_MISMATCH')

    def test_dedupe_scoped_to_scope(self):
        self.store.create(record('agt-0000000000000003', dedupe_key='k1'))
        with self.assertRaises(Rejected) as ctx:
            self.store.create(record('agt-0000000000000004', dedupe_key='k1'))
        self.assertEqual(ctx.exception.code, 'DEDUPE_CONFLICT')
        self.assertEqual(ctx.exception.existing['agent_id'], 'agt-0000000000000003')
        # a different scope may reuse the same dedupe key without collision
        other = self.store.create(record('agt-0000000000000005', dedupe_key='k1',
                                         scope='other-owner:pilot'))
        self.assertEqual(other['agent_id'], 'agt-0000000000000005')

    def test_events_seen_counts_chained_events(self):
        self.store.create(record('agt-0000000000000006'))
        self.store.update_fields('agt-0000000000000006', 'provider.warning', {'m': 'x'})
        stored = self.store.get('agt-0000000000000006')
        self.assertEqual(stored['events_seen'], 2)

    def test_recover_interrupts_all_live_including_recovering(self):
        self.store.create(record('agt-0000000000000007'))
        self.store.transition('agt-0000000000000007', {st.QUEUED}, st.STARTING, 's', {})
        self.store.create(record('agt-0000000000000008'))
        self.store.transition('agt-0000000000000008', {st.QUEUED}, st.STARTING, 's', {})
        self.store.transition('agt-0000000000000008', {st.STARTING}, st.RUNNING, 'r', {})
        self.store.transition('agt-0000000000000008', {st.RUNNING}, st.INTERRUPTED, 'i', {})
        self.store.transition('agt-0000000000000008', {st.INTERRUPTED}, st.RECOVERING, 'rc', {})
        recovered = self.store.recover()
        self.assertEqual({r['agent_id'] for r in recovered},
                         {'agt-0000000000000007', 'agt-0000000000000008'})
        for aid in ('agt-0000000000000007', 'agt-0000000000000008'):
            self.assertEqual(self.store.get(aid)['state'], st.INTERRUPTED)
        self.assertTrue(self.store.verify_chain()['ok'])

    def test_recover_requeues_running_intents(self):
        intent = self.store.enqueue_intent('t' * 64, 'agt-0000000000000009',
                                           'request-key-1', 'spawn', {'task': 'x'})
        claimed = self.store.dequeue_intents(4)
        self.assertEqual(claimed[0]['intent_id'], intent['intent_id'])
        stored = self.store.poll_intent(intent['intent_id'], timeout_s=0.2)
        self.assertEqual(stored['status'], 'running')
        self.store.recover()
        again = self.store.dequeue_intents(4)
        self.assertEqual(again[0]['intent_id'], intent['intent_id'])

    def test_intent_idempotent_enqueue_and_finish(self):
        first = self.store.enqueue_intent('a' * 64, 'agt-0000000000000010',
                                          'rk-dup-0001', 'send', {'agent_id': 'x', 'input': 'y'})
        second = self.store.enqueue_intent('a' * 64, 'agt-0000000000000010',
                                           'rk-dup-0001', 'send', {'agent_id': 'x', 'input': 'y'})
        self.assertEqual(first['intent_id'], second['intent_id'])
        claimed = self.store.dequeue_intents(4)
        self.store.finish_intent(claimed[0]['intent_id'], True, {'ok': True})
        done = self.store.poll_intent(claimed[0]['intent_id'], timeout_s=1)
        self.assertEqual(done['status'], 'done')

    def test_corrupt_chain_fails_closed(self):
        self.store.create(record('agt-0000000000000011'))
        self.store.db.execute("UPDATE agent_events SET payload_json='{}' WHERE seq=1")
        self.store.db.commit()
        self.assertFalse(self.store.verify_chain()['ok'])
        self.store.close()
        self.store.close()
        self.store = None
        with self.assertRaises(Rejected) as ctx:
            AgentStore(Path(self.tmp.name), 'runtime-test02')
        self.assertEqual(ctx.exception.code, 'AGENT_CHAIN_CORRUPT')

    def test_transition_updates_whitelist(self):
        self.store.create(record('agt-0000000000000012'))
        with self.assertRaises(Rejected):
            self.store.transition('agt-0000000000000012', {st.QUEUED}, st.STARTING, 's', {},
                                  task='mutate')
        with self.assertRaises(Rejected):
            self.store.update_fields('agt-0000000000000012', 'k', {}, scope='x')


if __name__ == '__main__':
    unittest.main()
