"""v0.8 forward-completion reconciliation (evidence-driven transaction improvement)."""
from __future__ import annotations

from tests.v080.fixture import V080Case


class TransactionForwardTests(V080Case):
    def plan_creates(self, count: int):
        operations = [{'op': 'create', 'path': f'fwd-{index}.txt', 'content': f'content-{index}\n'}
                      for index in range(count)]
        result = self.call('transaction_plan', operations=operations)
        self.assertTrue(result['ok'], result)
        return result['data']

    def simulate_partial(self, plan: dict, landed: int):
        """Land the first `landed` creates and move the journal to APPLYING."""
        for op in plan['operations'][:landed]:
            (self.project / op['path']).write_bytes(f"content-{op['index']}\n".encode('utf-8'))
        self.facade.v060.transaction_journal.transition(plan['plan_id'], 'PLANNED', 'APPLYING',
                                                        evidence={'crash': 'simulated'})

    def test_forward_completes_remaining_operations(self):
        plan = self.plan_creates(4)
        self.simulate_partial(plan, 2)
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], strategy='forward',
                           request_id='fwd-rec-0001')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'APPLIED')
        self.assertEqual(result['data']['already_landed'], [0, 1])
        self.assertEqual(result['data']['completed'], 2)
        for index in range(4):
            self.assertEqual((self.project / f'fwd-{index}.txt').read_text(encoding='utf-8'),
                             f'content-{index}\n')
        again = self.call('transaction_reconcile', plan_id=plan['plan_id'], strategy='forward',
                          request_id='fwd-rec-0002')
        self.assertTrue(again['ok'], again)
        self.assertFalse(again['data']['changed'])

    def test_forward_refuses_unprovable_state(self):
        plan = self.plan_creates(4)
        self.simulate_partial(plan, 2)
        (self.project / 'fwd-2.txt').write_bytes(b'external\n')
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], strategy='forward',
                           request_id='fwd-rec-0003')
        self.assert_error('TRANSACTION_INDETERMINATE', result)
        status = self.call('transaction_status', plan_id=plan['plan_id'])
        self.assertEqual(status['data']['state'], 'INDETERMINATE')
        self.assertTrue(status['data']['needs_reconciliation'])
        # The unprovable target is never overwritten and the landed prefix is not
        # silently discarded either: the state is explicitly flagged for review.
        self.assertEqual((self.project / 'fwd-2.txt').read_bytes(), b'external\n')
        self.assertTrue((self.project / 'fwd-0.txt').exists())
        self.assertTrue((self.project / 'fwd-1.txt').exists())

    def test_forward_completes_when_remaining_state_is_provable(self):
        plan = self.plan_creates(4)
        self.simulate_partial(plan, 2)
        (self.project / 'fwd-2.txt').write_bytes(b'external\n')
        (self.project / 'fwd-2.txt').unlink()
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], strategy='forward',
                           request_id='fwd-rec-0009')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'APPLIED')
        self.assertEqual(result['data']['completed'], 2)
        for index in range(4):
            self.assertEqual((self.project / f'fwd-{index}.txt').read_text(encoding='utf-8'),
                             f'content-{index}\n')

    def test_forward_from_indeterminate_state(self):
        plan = self.plan_creates(3)
        self.simulate_partial(plan, 1)
        self.facade.v060.transaction_journal.transition(plan['plan_id'], 'APPLYING', 'INDETERMINATE',
                                                        evidence={'reason': 'ambiguous'})
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], strategy='forward',
                           request_id='fwd-rec-0004')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'APPLIED')
        for index in range(3):
            self.assertTrue((self.project / f'fwd-{index}.txt').exists())

    def test_forward_refuses_non_prefix_state(self):
        plan = self.plan_creates(3)
        (self.project / 'fwd-0.txt').write_bytes(b'content-0\n')
        (self.project / 'fwd-2.txt').write_bytes(b'content-2\n')
        self.facade.v060.transaction_journal.transition(plan['plan_id'], 'PLANNED', 'APPLYING',
                                                        evidence={'crash': 'simulated'})
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], strategy='forward',
                           request_id='fwd-rec-0005')
        self.assert_error('TRANSACTION_INDETERMINATE', result)
        state = self.call('transaction_status', plan_id=plan['plan_id'])['data']['state']
        self.assertEqual(state, 'INDETERMINATE')

    def test_default_strategy_remains_rollback(self):
        plan = self.plan_creates(3)
        self.simulate_partial(plan, 2)
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], request_id='fwd-rec-0006')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'ROLLED_BACK')
        for index in range(3):
            self.assertFalse((self.project / f'fwd-{index}.txt').exists())

    def test_forward_rejects_invalid_strategy(self):
        plan = self.plan_creates(1)
        self.assert_error('INVALID_ARGUMENT', self.call('transaction_reconcile', plan_id=plan['plan_id'],
                                                        strategy='sideways', request_id='fwd-rec-0007'))

    def test_forward_patch_remaining_operation(self):
        seeded = self.seed('patch-me.txt', 'alpha beta\n')
        plan = self.call('transaction_plan', operations=[
            {'op': 'patch', 'path': 'patch-me.txt', 'old': 'beta', 'new': 'gamma',
             'expected_sha256': seeded['data']['sha256']}])
        self.assertTrue(plan['ok'], plan)
        plan = plan['data']
        self.facade.v060.transaction_journal.transition(plan['plan_id'], 'PLANNED', 'APPLYING',
                                                        evidence={'crash': 'simulated'})
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], strategy='forward',
                           request_id='fwd-rec-0008')
        self.assertTrue(result['ok'], result)
        self.assertEqual((self.project / 'patch-me.txt').read_text(encoding='utf-8'), 'alpha gamma\n')
