import pytest
from localcontrol.v060.core import Rejected
from localcontrol.v060.discovery import DirectoryObservation,classify
from localcontrol.v060.isolation import validate_control_plane_isolation
from localcontrol.v060.registry import RegistrySnapshot,Workspace,Collection

def test_discovery_top_level_git_repo():
    out=classify([DirectoryObservation(r'C:\Projects\WW2',('.git','package.json'))])
    assert len(out)==1 and out[0].confidence=='high' and out[0].classification=='top_level'

def test_discovery_nested_component():
    out=classify([
        DirectoryObservation(r'C:\Projects\OpenBuy',('.git','package.json')),
        DirectoryObservation(r'C:\Projects\OpenBuy\mobile',('package.json',)),
    ])
    assert out[1].classification=='nested_component' and out[1].parent_candidate==r'C:\Projects\OpenBuy'

def test_discovery_vendor_not_promoted():
    out=classify([DirectoryObservation(r'C:\Projects\A\node_modules\pkg',('package.json',))])
    assert out[0].classification=='likely_vendor'

def test_discovery_ignores_unmarked_directory():
    assert classify([DirectoryObservation(r'C:\Temp\stuff',('notes.txt',))])==[]

def test_discovery_sln_is_signal():
    out=classify([DirectoryObservation(r'C:\Code\Game',('game.sln',))])
    assert out and out[0].confidence=='medium'

def test_control_plane_outside_projects_passes():
    s=RegistrySnapshot(1,(Workspace('ww2',r'C:\Projects\WW2'),),(Collection('projects',r'C:\Projects'),))
    r=validate_control_plane_isolation(s,runtime_roots=[r'C:\Users\samis\.local\lib\localcontrol'],state_root=r'C:\Users\samis\.local\state\localcontrol')
    assert r['isolated']

def test_runtime_inside_collection_blocked():
    s=RegistrySnapshot(1,(),(Collection('projects',r'C:\Projects'),))
    with pytest.raises(Rejected) as e:validate_control_plane_isolation(s,runtime_roots=[r'C:\Projects\LocalControlRuntime'],state_root=r'C:\Users\samis\.local\state\lc')
    assert e.value.code=='CONTROL_PLANE_OVERLAP'

def test_state_inside_workspace_blocked():
    s=RegistrySnapshot(1,(Workspace('a',r'C:\Projects\A'),))
    with pytest.raises(Rejected) as e:validate_control_plane_isolation(s,runtime_roots=[r'C:\LC'],state_root=r'C:\Projects\A\.state')
    assert e.value.code=='CONTROL_PLANE_OVERLAP'
