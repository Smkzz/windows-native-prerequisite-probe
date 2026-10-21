import asyncio
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from localcontrol import __version__ as SERVER_VERSION
from localcontrol.facade import Facade, FIELDS
from localcontrol.policy import Policy, Project
from tests.fake_backend import FakeBackend


class NextIntegrationCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='localcontrol-next-test-')
        self.root = Path(self.tmp.name).resolve()
        self.project = self.root / 'workspace'; self.project.mkdir()
        self.runtime = self.root / 'runtime'; self.runtime.mkdir()
        self.state = self.root / 'state'
        self.manifest = self.root / 'worker.json'
        self.manifest.write_text(json.dumps({
            'workspace': str(self.project), 'network_capabilities': [],
            'profile_name': 'LocalControl.Test', 'runtime': str(self.runtime),
        }), encoding='utf-8')
        self.backend = FakeBackend()
        self.policy = Policy({'test': Project(self.project, True)}, self.state,
                             exec_mode='appcontainer', workers={'test': {'manifest': str(self.manifest)}})
        self.f = Facade(self.policy, self.backend)

    def tearDown(self):
        self.f.close(); self.tmp.cleanup()

    def call(self, tool, **args):
        return asyncio.run(self.f.call(tool, 'test', args))

    def assert_error(self, code, result):
        self.assertFalse(result['ok'], result)
        self.assertEqual(result['error']['code'], code, result)

    def test_server_identity_and_extension_registry(self):
        r = self.call('system_info')
        self.assertTrue(r['ok'], r)
        self.assertEqual(r['data']['version'], SERVER_VERSION)
        self.assertEqual(r['data']['extension_version'], SERVER_VERSION)
        self.assertEqual(r['data']['tool_count'], 22)
        self.assertEqual(len(FIELDS), 22)

    def test_capabilities_and_client_visibility(self):
        r = self.call('capabilities')
        self.assertTrue(r['ok'], r)
        d = r['data']
        self.assertEqual(d['server_version'], SERVER_VERSION)
        self.assertIn('read_batch', d['enabled'])
        self.assertIn('task_create_file', d['enabled'])
        self.assertFalse(d['task_cleanup_apply_exposed'])
        self.assertFalse(d['usage_import_exposed'])
        self.assertEqual(d['protocol_version'], '1.0')
        observed = d['enabled'][:-1]
        mismatch = self.call('capabilities', client_observed=observed)
        self.assertEqual(mismatch['data']['client_visibility'], 'mismatch')
        self.assertEqual(len(mismatch['data']['missing_from_client']), 1)

    def test_change_aware_batch_read(self):
        text = ('abcdefghij' * 150) + '\n'
        p = self.project / 'large.txt'; p.write_bytes(text.encode('utf-8'))
        first = self.call('read_batch', requests=[{'path':'large.txt','offset':0,'length':10}])
        self.assertTrue(first['ok'], first)
        row = first['data']['items'][0]
        self.assertEqual(row['content'], text)
        self.assertIn('previous', row)
        second = self.call('read_batch', requests=[{'path':'large.txt','offset':0,'length':10,'previous':row['previous']}])
        self.assertTrue(second['ok'], second)
        row2 = second['data']['items'][0]
        self.assertTrue(row2['unchanged'])
        self.assertNotIn('content', row2)

    def test_small_batch_read_avoids_expensive_cursor(self):
        (self.project/'tiny.txt').write_text('x\n', encoding='utf-8')
        r = self.call('read_batch', requests=[{'path':'tiny.txt'}])
        row = r['data']['items'][0]
        self.assertEqual(row['change_tracking'], 'omitted_for_small_read')
        self.assertNotIn('previous', row)

    def test_task_create_replay_and_handoff(self):
        begin = self.call('task_begin', task='task-alpha', paths=['owned.txt'])
        self.assertTrue(begin['ok'], begin)
        create = self.call('task_create_file', task='task-alpha', op='op-create-1', path='owned.txt', content='owned\n')
        self.assertTrue(create['ok'], create)
        n = len(self.backend.calls)
        replay = self.call('task_create_file', task='task-alpha', op='op-create-1', path='owned.txt', content='owned\n')
        self.assertTrue(replay['ok'], replay)
        self.assertTrue(replay['data']['replayed'])
        self.assertEqual(len(self.backend.calls), n)
        self.assertEqual((self.project/'owned.txt').read_text(encoding='utf-8'), 'owned\n')
        handoff = self.call('task_handoff', task='task-alpha')
        self.assertTrue(handoff['ok'], handoff)
        self.assertEqual(handoff['data']['owned_files'][0]['path'], 'owned.txt')
        self.assertFalse(handoff['data']['unknown_requires_reconciliation'])

    def test_task_does_not_adopt_preexisting_file(self):
        (self.project/'pre.txt').write_text('original', encoding='utf-8')
        self.assertTrue(self.call('task_begin', task='task-pre', paths=['pre.txt'])['ok'])
        r = self.call('task_create_file', task='task-pre', op='op-pre-1', path='pre.txt', content='replacement')
        self.assert_error('CONFLICT', r)
        self.assertEqual((self.project/'pre.txt').read_text(encoding='utf-8'), 'original')

    def test_checkpoint_revision_guard(self):
        self.call('task_begin', task='task-cp', paths=['a.txt'])
        one = self.call('task_checkpoint', task='task-cp', expected_revision=0,
                        notes={'inferences':['build succeeded'], 'untested':['packaging']})
        self.assertEqual(one['data']['revision'], 1)
        stale = self.call('task_checkpoint', task='task-cp', expected_revision=0,
                          notes={'inferences':[], 'untested':[]})
        self.assert_error('CONFLICT', stale)
        h = self.call('task_handoff', task='task-cp')
        self.assertEqual(h['data']['revision'], 1)
        self.assertEqual(h['data']['agent_notes']['untested'], ['packaging'])

    def test_unknown_job_delta_stays_owned_scope(self):
        r = self.call('job_delta', job_id='missing-job')
        self.assert_error('UNKNOWN_JOB', r)

    def test_efficiency_metrics_do_not_invent_tokens(self):
        r = self.call('efficiency_metrics')
        self.assertTrue(r['ok'], r)
        self.assertIsNone(r['data']['model_tokens'])
        self.assertIn('not inferred', r['data']['token_accounting'])

    def test_readonly_project_denies_task_state_mutation(self):
        self.f.close()
        readonly = Policy({'test': Project(self.project, False)}, self.state,
                          exec_mode='appcontainer', workers={'test': {'manifest': str(self.manifest)}})
        self.f = Facade(readonly, self.backend)
        r = self.call('task_begin', task='task-ro', paths=['x.txt'])
        self.assert_error('READ_ONLY', r)


if __name__ == '__main__':
    unittest.main()
