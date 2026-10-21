"""P3/P9/P10: bounded multi-file transactions, compensation and recovery."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from localcontrol.v060.transactions import TransactionJournal
from tests.v070.fixture import V070Case


class TransactionBasics(V070Case):
    def test_create_replace_patch_delete_in_one_transaction(self):
        first = self.seed('a.txt', 'one two\n')
        self.seed('b.txt', 'keep\n')
        self.seed('d.txt', 'patch me\n')
        plan = self.plan([
            {'op': 'replace', 'path': 'a.txt', 'content': 'replaced\n',
             'expected_sha256': first['data']['sha256']},
            {'op': 'patch', 'path': 'd.txt', 'old': 'patch', 'new': 'patched',
             'expected_sha256': self.read_sha('d.txt')},
            {'op': 'create', 'path': 'c.txt', 'content': 'new\n'},
            {'op': 'delete', 'path': 'b.txt', 'expected_sha256': self.read_sha('b.txt')},
        ])
        self.assertEqual(plan['state'], 'PLANNED')
        self.assertEqual(len(plan['operations']), 4)
        applied = self.apply(plan)
        self.assertTrue(applied['ok'], applied)
        self.assertEqual(applied['data']['state'], 'APPLIED')
        self.assertEqual(self.read_text('a.txt'), 'replaced\n')
        self.assertEqual(self.read_text('d.txt'), 'patched me\n')
        self.assertEqual(self.read_text('c.txt'), 'new\n')
        self.assertFalse((self.project / 'b.txt').exists())
        status = self.call('transaction_status', plan_id=plan['plan_id'])
        self.assertEqual(status['data']['state'], 'APPLIED')
        self.assertFalse(status['data']['needs_reconciliation'])

    def read_sha(self, relative: str) -> str:
        result = self.call('read_batch', requests=[{'path': relative, 'stat': True}])
        self.assertTrue(result['ok'], result)
        return result['data']['items'][0]['sha256']

    def test_duplicate_path_rejected(self):
        self.seed('a.txt', 'x\n')
        error = self.assert_error('DUPLICATE_PATH', self.call('transaction_plan', operations=[
            {'op': 'delete', 'path': 'a.txt', 'expected_sha256': self.read_sha('a.txt')},
            {'op': 'replace', 'path': 'A.TXT', 'content': 'y\n', 'expected_sha256': self.read_sha('a.txt')},
        ]))
        self.assertEqual(error['code'], 'DUPLICATE_PATH')

    def test_stale_sha_conflict(self):
        seeded = self.seed('a.txt', 'one\n')
        error = self.assert_error('CONFLICT', self.call('transaction_plan', operations=[
            {'op': 'replace', 'path': 'a.txt', 'content': 'two\n', 'expected_sha256': '0' * 64}]))
        self.assertEqual(error['code'], 'CONFLICT')
        self.assertEqual(error['details']['observed_sha256'], seeded['data']['sha256'])

    def test_irrelevant_operation_keys_rejected(self):
        self.seed('a.txt', 'x\n')
        self.assert_error('INVALID_OPERATIONS', self.call('transaction_plan', operations=[
            {'op': 'delete', 'path': 'a.txt', 'expected_sha256': self.read_sha('a.txt'), 'content': 'no'}]))
        self.assert_error('INVALID_OPERATIONS', self.call('transaction_plan', operations=[
            {'op': 'create', 'path': 'b.txt', 'content': 'x', 'old': 'no'}]))

    def test_create_requires_absence(self):
        self.seed('a.txt', 'exists\n')
        self.assert_error('CONFLICT', self.call('transaction_plan', operations=[
            {'op': 'create', 'path': 'a.txt', 'content': 'other\n'}]))

    def test_patch_count_mismatch(self):
        self.seed('a.txt', 'one one\n')
        self.assert_error('CONFLICT', self.call('transaction_plan', operations=[
            {'op': 'patch', 'path': 'a.txt', 'old': 'one', 'new': 'two', 'expected_count': 1,
             'expected_sha256': self.read_sha('a.txt')}]))

    def test_precondition_required_without_sha(self):
        self.seed('a.txt', 'x\n')
        self.assert_error('PRECONDITION_REQUIRED', self.call('transaction_plan', operations=[
            {'op': 'delete', 'path': 'a.txt'}]))

    def test_path_escape_rejected(self):
        self.assert_error('INVALID_PATH', self.call('transaction_plan', operations=[
            {'op': 'create', 'path': '..\\escape.txt', 'content': 'x'}]))
        self.assert_error('INVALID_PATH', self.call('transaction_plan', operations=[
            {'op': 'create', 'path': 'C:/absolute.txt', 'content': 'x'}]))

    def test_operation_and_size_bounds(self):
        too_many = [{'op': 'create', 'path': f'f{i}.txt', 'content': 'x'} for i in range(33)]
        self.assert_error('INVALID_OPERATIONS', self.call('transaction_plan', operations=too_many))
        big = 'x' * (self.facade.policy.max_file_bytes + 1)
        self.assert_error('FILE_LIMIT', self.call('transaction_plan', operations=[
            {'op': 'create', 'path': 'big.txt', 'content': big}]))

    def test_transaction_requires_writable_and_sandbox(self):
        self.facade.policy.projects['pilot'] = type(self.facade.policy.projects['pilot'])(
            self.facade.policy.projects['pilot'].root, False)
        self.assert_error('READ_ONLY', self.call('transaction_plan', operations=[
            {'op': 'create', 'path': 'a.txt', 'content': 'x'}]))


class TransactionAtomicity(V070Case):
    def test_same_request_id_replays_result(self):
        plan = self.plan([{'op': 'create', 'path': 'a.txt', 'content': 'x\n'}])
        first = self.call('transaction_apply', plan=plan['plan'], request_id='tx-apply-replay')
        self.assertTrue(first['ok'], first)
        second = self.call('transaction_apply', plan=plan['plan'], request_id='tx-apply-replay')
        self.assertTrue(second['ok'], second)
        self.assertTrue(second.get('replayed'))

    def test_fresh_request_id_on_applied_plan_is_rejected(self):
        plan = self.plan([{'op': 'create', 'path': 'a.txt', 'content': 'x\n'}])
        self.apply(plan, request_id='tx-apply-first1')
        again = self.call('transaction_apply', plan=plan['plan'], request_id='tx-apply-second')
        self.assert_error('ALREADY_APPLIED', again)

    def test_no_effect_failure_rolls_back_prefix(self):
        plan = self.plan([
            {'op': 'create', 'path': 'a.txt', 'content': 'new\n'},
            {'op': 'create', 'path': 'b.txt', 'content': 'clash\n'},
        ])
        # An external writer creates the second target after planning so the
        # broker guards it at apply time; the landed prefix must be reversed.
        (self.project / 'b.txt').write_bytes(b'external\n')
        failed = self.call('transaction_apply', plan=plan['plan'], request_id='tx-apply-fail1')
        error = self.assert_error('TRANSACTION_ROLLED_BACK', failed)
        self.assertEqual(error['details']['state'], 'ROLLED_BACK')
        self.assertFalse((self.project / 'a.txt').exists())
        status = self.call('transaction_status', plan_id=plan['plan_id'])
        self.assertEqual(status['data']['state'], 'ROLLED_BACK')

    def test_conflict_between_plan_and_apply_rolls_back(self):
        self.seed('a.txt', 'one\n')
        plan = self.plan([
            {'op': 'create', 'path': 'new.txt', 'content': 'n\n'},
            {'op': 'replace', 'path': 'a.txt', 'content': 'two\n', 'expected_sha256': self.read_sha('a.txt')},
        ])
        # External writer changes the guarded file after planning.
        (self.project / 'a.txt').write_text('tampered\n', encoding='utf-8')
        failed = self.call('transaction_apply', plan=plan['plan'], request_id='tx-apply-drift')
        error = self.assert_error('TRANSACTION_ROLLED_BACK', failed)
        self.assertEqual(error['details']['restored'], [0])
        self.assertFalse((self.project / 'new.txt').exists())
        self.assertEqual(self.read_text('a.txt'), 'tampered\n')

    def test_rollback_restores_all_pre_images(self):
        self.seed('a.txt', 'alpha\n')
        sha = self.read_sha('a.txt')
        plan = self.plan([
            {'op': 'replace', 'path': 'a.txt', 'content': 'beta\n', 'expected_sha256': sha},
            {'op': 'create', 'path': 'b.txt', 'content': 'bee\n'},
        ])
        self.assertTrue(self.apply(plan, request_id='tx-apply-rb0001')['ok'])
        rolled = self.call('transaction_rollback', plan_id=plan['plan_id'], request_id='tx-roll-0001')
        self.assertTrue(rolled['ok'], rolled)
        self.assertEqual(rolled['data']['state'], 'ROLLED_BACK')
        self.assertTrue(rolled['data']['verified_pre_state'])
        self.assertEqual(self.read_text('a.txt'), 'alpha\n')
        self.assertFalse((self.project / 'b.txt').exists())

    def test_rollback_refuses_on_drift(self):
        self.seed('a.txt', 'alpha\n')
        plan = self.plan([{'op': 'replace', 'path': 'a.txt', 'content': 'beta\n',
                           'expected_sha256': self.read_sha('a.txt')}])
        self.assertTrue(self.apply(plan, request_id='tx-apply-drift2')['ok'])
        (self.project / 'a.txt').write_text('someone else\n', encoding='utf-8')
        self.assert_error('DRIFT_DETECTED', self.call('transaction_rollback', plan_id=plan['plan_id'],
                                                       request_id='tx-roll-0002'))

    def test_rollback_before_apply_is_noop(self):
        plan = self.plan([{'op': 'create', 'path': 'a.txt', 'content': 'x'}])
        result = self.call('transaction_rollback', plan_id=plan['plan_id'], request_id='tx-roll-0003')
        self.assertTrue(result['ok'], result)
        self.assertFalse(result['data']['changed'])

    def test_plan_replay_is_idempotent(self):
        self.seed('a.txt', 'one\n')
        payload = [{'op': 'replace', 'path': 'a.txt', 'content': 'two\n',
                    'expected_sha256': self.read_sha('a.txt')}]
        first = self.plan(payload)
        second = self.plan(payload)
        self.assertEqual(first['plan_id'], second['plan_id'])
        self.assertTrue(second['replayed'])


class TransactionSecurity(V070Case):
    def test_tampered_token_rejected(self):
        plan = self.plan([{'op': 'create', 'path': 'a.txt', 'content': 'x'}])
        token = plan['plan']
        self.assert_error('INVALID_CURSOR', self.call('transaction_apply', plan=token[:-3] + 'aaa',
                                                      request_id='tx-apply-tamper'))

    def test_token_is_project_bound(self):
        import asyncio
        from localcontrol.policy import Project
        from localcontrol.v060.registry import Collection, RegistryCodec, RegistrySnapshot, Workspace
        self.seed('a.txt', 'x\n')
        plan = self.plan([{'op': 'create', 'path': 'b.txt', 'content': 'y\n'}])
        second = self.root / 'second'
        second.mkdir()
        self.facade.policy.projects['second'] = Project(second, True)
        self.facade.locks['second'] = asyncio.Lock()
        regkey = (self.vstate / 'registry-key.bin').read_bytes()
        snapshot = RegistrySnapshot(2, (Workspace('pilot', str(self.project), True, True, False),
                                        Workspace('second', str(second), True, True, False)),
                                    (Collection('projects', str(self.collection), True),))
        (self.vstate / 'workspace-registry.json').write_bytes(RegistryCodec(regkey).encode(snapshot))
        # The plan token was signed under the pilot context; another project must not accept it.
        self.assert_error('STALE_CURSOR',
                          self.call('transaction_apply', project='second', plan=plan['plan'],
                                    request_id='tx-apply-other1'))
        self.assert_error('UNKNOWN_PROJECT',
                          self.call('transaction_apply', project='ghost', plan=plan['plan'],
                                    request_id='tx-apply-ghost1'))

    def test_unknown_plan_status_and_reconcile(self):
        self.assert_error('UNKNOWN_PLAN', self.call('transaction_status', plan_id='f' * 64))
        self.assert_error('UNKNOWN_PLAN', self.call('transaction_reconcile', plan_id='f' * 64,
                                                    request_id='tx-rec-0001'))

    def test_apply_requires_request_id(self):
        plan = self.plan([{'op': 'create', 'path': 'a.txt', 'content': 'x'}])
        self.assert_error('INVALID_REQUEST_ID', self.call('transaction_apply', plan=plan['plan']))

    def test_non_utf8_file_is_refused_not_weakened(self):
        import hashlib
        target = self.project / 'binary.bin'
        target.write_bytes(b'\xff\xfe\x00\x01')
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        result = self.call('transaction_plan', operations=[
            {'op': 'delete', 'path': 'binary.bin', 'expected_sha256': digest}])
        self.assert_error('TRANSACTION_REQUIRES_TEXT', result)

    def test_protected_path_rejected(self):
        self.assert_error('PROTECTED_PATH', self.call('transaction_plan', operations=[
            {'op': 'create', 'path': '.env', 'content': 'secret'}]))

    def test_history_does_not_echo_pre_images(self):
        self.seed('a.txt', 'top-secret-value\n')
        plan = self.plan([{'op': 'replace', 'path': 'a.txt', 'content': 'clean\n',
                           'expected_sha256': self.read_sha('a.txt')}])
        status = self.call('transaction_status', plan_id=plan['plan_id'])
        self.assertNotIn('top-secret-value', str(status))
        events = self.call('transaction_status', plan_id=plan['plan_id'])['data']['events']
        self.assertNotIn('top-secret-value', str(events))


class TransactionRecovery(V070Case):
    def journal(self) -> TransactionJournal:
        return self.facade.v060.transaction_journal

    def test_reconcile_completes_rollback_for_landed_prefix(self):
        self.seed('a.txt', 'one\n')
        plan = self.plan([
            {'op': 'replace', 'path': 'a.txt', 'content': 'two\n', 'expected_sha256': self.read_sha('a.txt')},
            {'op': 'create', 'path': 'b.txt', 'content': 'bee\n'},
            {'op': 'create', 'path': 'c.txt', 'content': 'cee\n'},
        ])
        self.journal().transition(plan['plan_id'], 'PLANNED', 'APPLYING', evidence={'crash': 'simulated'})
        (self.project / 'a.txt').write_bytes(b'two\n')  # op 0 landed
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], request_id='tx-rec-prefix')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'ROLLED_BACK')
        self.assertEqual(result['data']['restored'], [0])
        self.assertEqual(self.read_text('a.txt'), 'one\n')
        self.assertFalse((self.project / 'b.txt').exists())

    def test_reconcile_marks_all_landed_as_applied(self):
        plan = self.plan([
            {'op': 'create', 'path': 'a.txt', 'content': 'one\n'},
            {'op': 'create', 'path': 'b.txt', 'content': 'two\n'},
        ])
        self.journal().transition(plan['plan_id'], 'PLANNED', 'APPLYING', evidence={'crash': 'simulated'})
        (self.project / 'a.txt').write_bytes(b'one\n')
        (self.project / 'b.txt').write_bytes(b'two\n')
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], request_id='tx-rec-applied')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'APPLIED')
        self.assertTrue(result['data']['committed'])

    def test_reconcile_resumes_compensation_from_indeterminate(self):
        plan = self.plan([
            {'op': 'create', 'path': 'a.txt', 'content': 'one\n'},
            {'op': 'create', 'path': 'b.txt', 'content': 'two\n'},
            {'op': 'create', 'path': 'c.txt', 'content': 'three\n'},
        ])
        journal = self.journal()
        journal.transition(plan['plan_id'], 'PLANNED', 'APPLYING', evidence={'crash': 'simulated'})
        journal.transition(plan['plan_id'], 'APPLYING', 'INDETERMINATE', evidence={'reason': 'ambiguous'})
        (self.project / 'a.txt').write_bytes(b'one\n')
        (self.project / 'b.txt').write_bytes(b'two\n')
        result = self.call('transaction_reconcile', plan_id=plan['plan_id'], request_id='tx-rec-resume')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'ROLLED_BACK')
        self.assertFalse((self.project / 'a.txt').exists())
        self.assertFalse((self.project / 'b.txt').exists())
        self.assertEqual(journal.get(plan['plan_id'])['state'], 'ROLLED_BACK')

    def test_reconcile_indeterminate_for_unknown_content(self):
        plan = self.plan([{'op': 'create', 'path': 'a.txt', 'content': 'one\n'}])
        self.journal().transition(plan['plan_id'], 'PLANNED', 'APPLYING', evidence={'crash': 'simulated'})
        (self.project / 'a.txt').write_text('something else\n', encoding='utf-8')
        error = self.assert_error('TRANSACTION_INDETERMINATE',
                                  self.call('transaction_reconcile', plan_id=plan['plan_id'],
                                            request_id='tx-rec-other1'))
        self.assertTrue(error['details']['requires_operator_review'])
        self.assertEqual(self.journal().get(plan['plan_id'])['state'], 'INDETERMINATE')

    def test_journal_survives_reopen(self):
        plan = self.plan([{'op': 'create', 'path': 'a.txt', 'content': 'x\n'}])
        path = self.vstate / 'transaction-journal.sqlite'
        self.facade.v060.transaction_journal.close()
        reopened = TransactionJournal(path)
        try:
            self.assertEqual(reopened.get(plan['plan_id'])['state'], 'PLANNED')
        finally:
            reopened.close()

    def test_tampered_journal_plan_is_rejected_at_apply(self):
        import json as jsonlib
        plan = self.plan([{'op': 'create', 'path': 'a.txt', 'content': 'x\n'}])
        journal = self.facade.v060.transaction_journal
        row = journal.get(plan['plan_id'])
        body = dict(row['plan'])
        body['operations'] = [dict(body['operations'][0], content='evil\n')]
        with journal.lock:
            journal.db.execute('BEGIN IMMEDIATE')
            journal.db.execute('UPDATE transactions SET plan=? WHERE plan_id=?',
                               (jsonlib.dumps(body, sort_keys=True, separators=(',', ':')), plan['plan_id']))
            journal.db.execute('COMMIT')
        self.assert_error('PLAN_DIGEST_MISMATCH',
                          self.call('transaction_apply', plan=plan['plan'], request_id='tx-apply-tamper2'))

    def test_corrupt_journal_fails_closed(self):
        path = self.root / 'corrupt-journal.sqlite'
        path.write_bytes(b'not a database at all')
        with self.assertRaises(Exception) as raised:
            TransactionJournal(path)
        self.assertEqual(getattr(raised.exception, 'code', None), 'JOURNAL_CORRUPT')

    def test_status_reports_recovery_hint_for_interrupted(self):
        plan = self.plan([{'op': 'create', 'path': 'a.txt', 'content': 'x\n'}])
        self.journal().transition(plan['plan_id'], 'PLANNED', 'APPLYING', evidence={'crash': 'simulated'})
        status = self.call('transaction_status', plan_id=plan['plan_id'])
        self.assertTrue(status['data']['needs_reconciliation'])
        self.assertEqual(status['data']['recovery'], 'transaction_reconcile')
