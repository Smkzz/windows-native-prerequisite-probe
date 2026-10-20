"""Owned project-local data fixtures, inheriting the enrolled workspace ACL.

Python 3.13's private mode0700 tempfile directories remove the AppContainer
writer ACE. These ordinary unit-data directories test file logic, not the
private native operator root or worker confinement boundaries.
"""
from pathlib import Path
import shutil
import uuid

class ProjectTemporaryDirectory:
    def __init__(self, prefix='fixture-', dir=None):
        root=Path(__file__).absolute().parents[1]
        parent=Path(dir) if dir is not None else root/'artifacts'/'unit-data'
        if not parent.absolute().is_relative_to(root):raise ValueError('FIXTURE_OUTSIDE_PACKAGE')
        parent.mkdir(parents=True,exist_ok=True)
        self.path=parent/(prefix+uuid.uuid4().hex)
        self.path.mkdir()
        self.name=str(self.path)
        self.root=root
    def cleanup(self):
        if not self.path.exists():return
        if self.path.is_symlink() or not self.path.absolute().is_relative_to(self.root):
            raise ValueError('FIXTURE_IDENTITY_CHANGED')
        shutil.rmtree(self.path)
