"""Shared v0.7 test fixture: an AppContainer-shaped facade with a fake backend."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from localcontrol.facade import Facade
from localcontrol.policy import Policy, Project
from localcontrol.v060.registry import Collection, RegistryCodec, RegistrySnapshot, Workspace
from tests.fake_backend import FakeBackend


class V070Case(unittest.TestCase):
    exec_mode = 'appcontainer'
    v060 = True
    v080 = False
    v100 = False
    v110 = False

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lc070-test-')
        self.root = Path(self.tmp.name).resolve()
        self.project = self.root / 'project'
        self.collection = self.root / 'collection'
        self.state = self.root / 'state'
        self.vstate = self.state / 'v060'
        for path in (self.project, self.collection, self.vstate, self.root / 'runtime'):
            path.mkdir(parents=True)
        self.config = self.root / 'localcontrol.json'
        self.config.write_text('{}', encoding='utf-8')
        self.manifest = self.root / 'worker.json'
        self.manifest.write_text(json.dumps({
            'workspace': str(self.project), 'network_capabilities': [],
            'profile_name': 'LocalControl.Test', 'runtime': str(self.root / 'runtime'),
        }), encoding='utf-8')
        if self.v060:
            regkey, movekey = os.urandom(32), os.urandom(32)
            (self.vstate / 'registry-key.bin').write_bytes(regkey)
            (self.vstate / 'move-key.bin').write_bytes(movekey)
            snapshot = RegistrySnapshot(1, (Workspace('pilot', str(self.project), True, True, False),),
                                        (Collection('projects', str(self.collection), True),))
            (self.vstate / 'workspace-registry.json').write_bytes(RegistryCodec(regkey).encode(snapshot))
        workers = {'pilot': {'manifest': str(self.manifest)}} if self.exec_mode == 'appcontainer' else {}
        policy = Policy({'pilot': Project(self.project, True)}, self.state, exec_mode=self.exec_mode,
                        workers=workers)
        self.backend = FakeBackend()
        options = {'enabled': True, 'allowed_usage_adapters': ['test']} if self.v060 else None
        v080_options = {'enabled': True} if self.v080 else None
        v100_options = {'enabled': True} if self.v100 else None
        v110_options = {'enabled': True, 'providers': {'codex': {'enabled': True}}} \
            if self.v110 else None
        self.facade = Facade(policy, self.backend, v060_options=options, v080_options=v080_options,
                             v100_options=v100_options, v110_options=v110_options,
                             config_path=self.config
                             if (self.v060 or self.v080 or self.v100 or self.v110) else None)

    def tearDown(self):
        self.facade.close()
        self.tmp.cleanup()

    def call(self, name: str, project: str = 'pilot', **args) -> dict:
        return asyncio.run(self.facade.call(name, project, args))

    def assert_error(self, code: str, result: dict):
        self.assertFalse(result['ok'], result)
        self.assertEqual(result['error']['code'], code, result)
        return result['error']

    def seed(self, path: str, content: str, request_id: str | None = None) -> dict:
        result = self.call('file_write', path=path, content=content, expected_sha256='absent',
                           request_id=request_id or ('seed-' + path.replace('/', '-').replace('.', '-').ljust(8, 'x')))
        self.assertTrue(result['ok'], result)
        return result

    def read_text(self, relative: str) -> str:
        return (self.project / relative).read_text(encoding='utf-8')

    def read_sha(self, relative: str) -> str:
        result = self.call('read_batch', requests=[{'path': relative, 'stat': True}])
        self.assertTrue(result['ok'], result)
        return result['data']['items'][0]['sha256']

    def plan(self, operations: list) -> dict:
        result = self.call('transaction_plan', operations=operations)
        self.assertTrue(result['ok'], result)
        return result['data']

    def apply(self, plan: dict, request_id: str = 'tx-apply-0001') -> dict:
        return self.call('transaction_apply', plan=plan['plan'], request_id=request_id)

