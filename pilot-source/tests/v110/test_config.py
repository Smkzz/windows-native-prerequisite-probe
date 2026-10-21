"""v1.1 config validation and profile resolution rules."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from localcontrol.agents.manager import DelegationManager
from localcontrol.agents.profiles import load_profiles
from localcontrol.errors import ControlError
from localcontrol.nextlib.core import Rejected
from localcontrol.policy import Policy, Project


def _policy(root: Path) -> Policy:
    root = root.resolve()
    project = root / 'project'
    project.mkdir(exist_ok=True)
    state = root / 'state'
    state.mkdir(exist_ok=True)
    return Policy({'pilot': Project(project.resolve(), True)}, state,
                  exec_mode='trusted_local')


def _options(**overrides) -> dict:
    base = {'enabled': True, 'providers': {'codex': {'enabled': True}}}
    base.update(overrides)
    return base


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lc110-cfg-')
        self.root = Path(self.tmp.name)
        self._managers = []

    def tearDown(self):
        for mgr in self._managers:
            mgr.close()
        self.tmp.cleanup()

    def manager(self, options) -> DelegationManager:
        mgr = DelegationManager(_policy(self.root), 'local-owner', options)
        self._managers.append(mgr)
        return mgr

    def test_enabled_shape(self):
        mgr = self.manager(_options())
        self.assertIn('read_only', mgr.profiles)
        self.assertEqual(mgr.default_profile, 'read_only')

    def test_rejects_disabled_or_malformed(self):
        with self.assertRaises(Rejected):
            DelegationManager(_policy(self.root), 'local-owner', {'enabled': False})
        with self.assertRaises(Rejected):
            DelegationManager(_policy(self.root), 'local-owner',
                              _options(unknown_key=1))
        with self.assertRaises(Rejected):
            DelegationManager(_policy(self.root), 'local-owner',
                              _options(providers={'other': {'enabled': True}}))
        with self.assertRaises(Rejected):
            DelegationManager(_policy(self.root), 'local-owner',
                              _options(providers={'codex': {'enabled': True, 'surprise': 1}}))
        with self.assertRaises(Rejected):
            DelegationManager(_policy(self.root), 'local-owner',
                              _options(limits={'max_concurrent': 'lots'}))
        with self.assertRaises(Rejected):
            DelegationManager(_policy(self.root), 'local-owner',
                              _options(default_profile='missing'))

    def test_limits_merge_and_bound(self):
        mgr = self.manager(_options(limits={'max_concurrent': 2}))
        self.assertEqual(mgr.limits['max_concurrent'], 2)
        self.assertEqual(mgr.limits['max_depth'], 2)

    def test_profile_overrides_merge_with_defaults(self):
        profiles = load_profiles({'read_only': {'max_turns': 2}})
        self.assertEqual(profiles['read_only'].max_turns, 2)
        self.assertEqual(profiles['read_only'].codex_sandbox, 'read_only')
        self.assertIn('workspace_write', profiles)

    def test_profile_validation_failures(self):
        for bad in ({'codex_sandbox': 'bogus'},
                    {'can_delegate': 'yes'},
                    {'max_turns': 0},
                    {'delegate_profile': 'does_not_exist'},
                    {'not_a_key': 1}):
            with self.assertRaises(Rejected, msg=str(bad)):
                load_profiles({'custom_profile': bad})
        with self.assertRaises(Rejected):
            load_profiles({'read_only': {'codex_sandbox': 'read_only',
                                         'writable_roots_mode': 'workspace'}})

    def test_auto_reattach_option(self):
        mgr = self.manager(_options())
        self.assertTrue(mgr._auto_reattach_enabled)          # default on
        mgr = self.manager(_options(auto_reattach=False))
        self.assertFalse(mgr._auto_reattach_enabled)
        with self.assertRaises(Rejected):
            DelegationManager(_policy(self.root), 'local-owner',
                              _options(auto_reattach='yes'))

    def test_default_profiles_never_expose_danger(self):
        profiles = load_profiles(None)
        for name, profile in profiles.items():
            self.assertNotEqual(profile.codex_sandbox, 'danger_full_access', name)
            self.assertFalse(profile.network, name)
        self.assertFalse(profiles['read_only'].can_delegate)
        self.assertTrue(profiles['project_autonomous'].can_delegate)


if __name__ == '__main__':
    unittest.main()
