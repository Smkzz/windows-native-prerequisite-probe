"""P5: durable, minimal task continuation state."""
from __future__ import annotations

from tests.v070.fixture import V070Case


class Continuation(V070Case):
    def begin(self, task: str = 'resume-task', paths=('a.txt',)):
        result = self.call('task_begin', task=task, paths=list(paths))
        self.assertTrue(result['ok'], result)

    def test_checkpoint_accepts_structured_manifest(self):
        self.begin()
        result = self.call('task_checkpoint', task='resume-task', expected_revision=0, notes={
            'objective': 'Finish the migration',
            'phase': 'implementation',
            'decisions': ['use transactions for multi-file edits'],
            'completed': ['wrote a.txt'],
            'blocked_checks': ['release build not run'],
            'blockers': [],
            'next_action': 'apply transaction and run tests',
            'vcs': {'kind': 'git', 'worktree': 'C:/w', 'commit': 'abc123'},
            'inferences': ['tests likely green'],
            'untested': ['packaging'],
        })
        self.assertTrue(result['ok'], result)
        handoff = self.call('task_handoff', task='resume-task')
        self.assertTrue(handoff['ok'], handoff)
        notes = handoff['data']['agent_notes']
        self.assertEqual(notes['objective'], 'Finish the migration')
        self.assertEqual(notes['next_action'], 'apply transaction and run tests')
        self.assertEqual(notes['vcs']['commit'], 'abc123')

    def test_legacy_checkpoint_shape_still_accepted(self):
        self.begin('legacy-task')
        result = self.call('task_checkpoint', task='legacy-task', expected_revision=0,
                           notes={'inferences': [], 'untested': ['x']})
        self.assertTrue(result['ok'], result)

    def test_checkpoint_rejects_unknown_and_malformed_notes(self):
        self.begin('bad-task')
        self.assert_error('INVALID_ARGUMENT', self.call('task_checkpoint', task='bad-task',
                                                        expected_revision=0, notes={'mystery': []}))
        self.assert_error('INVALID_ARGUMENT', self.call('task_checkpoint', task='bad-task',
                                                        expected_revision=0, notes={'decisions': 'not-a-list'}))
        self.assert_error('INVALID_ARGUMENT', self.call('task_checkpoint', task='bad-task',
                                                        expected_revision=0, notes={}))

    def test_handoff_environment_is_one_call_resume_state(self):
        self.seed('a.txt', 'hello\n')
        self.begin(paths=('a.txt', 'b.txt'))
        created = self.call('task_create_file', task='resume-task', op='create-b-1',
                            path='b.txt', content='bee\n')
        self.assertTrue(created['ok'], created)
        handoff = self.call('task_handoff', task='resume-task', include=['environment'])
        self.assertTrue(handoff['ok'], handoff)
        data = handoff['data']
        environment = data['environment']
        self.assertTrue(data['environment_is_observed_state_not_goal_completion'])
        for key in ('owned_jobs', 'leases', 'unresolved_moves', 'unresolved_transactions',
                    'workspace', 'usage', 'recommended_next'):
            self.assertIn(key, environment)
        self.assertEqual(environment['workspace']['name'], 'pilot')
        self.assertEqual(data['authorized_exact_paths'], ['a.txt', 'b.txt'])
        self.assertEqual(data['owned_files'][0]['path'], 'b.txt')
        self.assertNotIn(str(self.state), str(environment))

    def test_handoff_rejects_unknown_include(self):
        self.begin('include-task')
        self.assert_error('INVALID_ARGUMENT', self.call('task_handoff', task='include-task',
                                                        include=['everything']))
        self.assert_error('INVALID_ARGUMENT', self.call('task_handoff', task='include-task',
                                                        include='environment'))

    def test_environment_usage_is_bounded(self):
        self.begin('usage-task')
        handoff = self.call('task_handoff', task='usage-task', include=['environment'])
        self.assertIsNone(self.call('task_handoff', task='usage-task')['data'].get('environment'))
        self.assertEqual(handoff['data']['environment']['usage']['estimated_cost'], None)
