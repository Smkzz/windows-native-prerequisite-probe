"""Workspace identity evidence and divergence classification."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from localcontrol.v080 import identity as ident
from tests.v080.fixture import V080Case


def git_available() -> bool:
    return shutil.which('git') is not None


def git(root: Path, *args: str):
    return subprocess.run(['git', '-C', str(root), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30, shell=False)


def init_repo(root: Path):
    git(root, 'init', '-q')
    git(root, 'config', 'user.email', 'test@example.invalid')
    git(root, 'config', 'user.name', 'Test')
    (root / 'tracked.txt').write_text('one\n', encoding='utf-8')
    git(root, 'add', 'tracked.txt')
    git(root, 'commit', '-q', '-m', 'initial')
    return root


class IdentityClassificationTests(V080Case):
    def policy(self):
        policy = self.facade.policy
        return policy

    def current(self, watch=None):
        return ident.build_identity(self.policy(), 'pilot', watch)

    def test_same_and_missing_and_replaced(self):
        first = self.current()
        self.assertEqual(ident.classify(first, self.current())['classification'], 'same')
        stored = self.current()
        shutil.rmtree(self.project)
        missing = self.current()
        self.assertEqual(ident.classify(stored, missing)['classification'], 'missing')
        self.project.mkdir()
        replaced = self.current()
        self.assertEqual(ident.classify(stored, replaced)['classification'], 'replaced')

    def test_tree_and_watch_divergence_no_git(self):
        seeded = self.seed('watched.txt', 'original\n')
        stored = self.current(['watched.txt'])
        self.seed('new-child.txt', 'child\n')
        tree_changed = ident.classify(stored, self.current(['watched.txt']))
        self.assertEqual(tree_changed['classification'], 'files_changed')
        replaced = self.call('file_write', path='watched.txt', content='changed\n',
                             expected_sha256=seeded['data']['sha256'], request_id='ident-change-0001')
        self.assertTrue(replaced['ok'], replaced)
        watched_changed = ident.classify(stored, self.current(['watched.txt']))
        self.assertEqual(watched_changed['classification'], 'files_changed')
        self.assertTrue(any(d.startswith('watched_file_changed:') for d in watched_changed['differences']))
        self.assertTrue(watched_changed['requires_acceptance'])

    def test_synthetic_git_classifications(self):
        base = self.current()
        stored = dict(base)
        stored['git'] = {'present': True, 'repo_root': str(self.project), 'head': 'a' * 40,
                         'branch': 'main', 'detached': False, 'dirty': False, 'dirty_count': 0, 'dirty_sample': []}
        variants = {
            'branch_changed': {'branch': 'feature'},
            'dirty_changed': {'dirty': True, 'dirty_count': 1, 'dirty_sample': ['x.txt']},
        }
        for expected, patch in variants.items():
            current = dict(base)
            git_record = dict(stored['git'])
            git_record.update(patch)
            current['git'] = git_record
            result = ident.classify(stored, current)
            self.assertEqual(result['classification'], expected, result)
            self.assertTrue(result['requires_acceptance'], result)
        current = dict(base)
        current['git'] = dict(stored['git'], repo_root=str(self.root / 'other'))
        self.assertEqual(ident.classify(stored, current)['classification'], 'different_repo')
        current = dict(base)
        current['git'] = {'present': False}
        self.assertEqual(ident.classify(stored, current)['classification'], 'different_repo')

    def test_git_repository_lifecycle(self):
        if not git_available():
            self.skipTest('git unavailable')
        init_repo(self.project)
        clean = self.current()
        branch = clean['git']['branch']
        self.assertTrue(clean['git']['present'])
        self.assertTrue(clean['git']['head'])
        self.assertFalse(clean['git']['dirty'])
        self.assertEqual(ident.classify(clean, self.current())['classification'], 'same')
        (self.project / 'tracked.txt').write_text('two\n', encoding='utf-8')
        self.assertEqual(ident.classify(clean, self.current())['classification'], 'dirty_changed')
        (self.project / 'tracked.txt').write_text('one\n', encoding='utf-8')
        self.assertEqual(ident.classify(clean, self.current())['classification'], 'same')
        git(self.project, 'checkout', '-q', '-b', 'feature/one')
        self.assertEqual(ident.classify(clean, self.current())['classification'], 'branch_changed')
        (self.project / 'tracked.txt').write_text('three\n', encoding='utf-8')
        git(self.project, 'add', 'tracked.txt')
        git(self.project, 'commit', '-q', '-m', 'second')
        self.assertEqual(ident.classify(clean, self.current())['classification'], 'advanced')
        git(self.project, 'checkout', '-q', '-')
        self.assertEqual(self.current()['git']['branch'], branch)
        self.assertEqual(ident.classify(clean, self.current())['classification'], 'same')
        git(self.project, 'checkout', '-q', '--detach', 'HEAD')
        self.assertEqual(ident.classify(clean, self.current())['classification'], 'branch_changed')

    def test_classify_rejects_invalid_records(self):
        with self.assertRaises(Exception) as raised:
            ident.classify({'schema': 1}, self.current())
        self.assertEqual(getattr(raised.exception, 'code', None), 'INVALID_IDENTITY')

    def test_tampered_identity_record_refused_on_resume(self):
        run = self.begin_run()
        with self.facade.v080.runs.lock:
            with self.facade.v080.runs._tx():
                self.facade.v080.runs.db.execute("UPDATE runs SET identity='[]' WHERE run_id=?",
                                                 (run['run_id'],))
        refused = self.call('run_begin', run_id=run['run_id'], request_id='ident-tamper-0001')
        self.assert_error('RUN_STATE_TAMPERED', refused)
