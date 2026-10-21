import pytest
from localcontrol.v060.admin import RegistryEditor,validate_publish
from localcontrol.v060.contract import BASE_V050,V060_ADDITIONS,V070_ADDITIONS,V080_ADDITIONS,OPERATOR_ONLY,validate_contract
from localcontrol.v060.core import Rejected
from localcontrol.v060.registry import RegistrySnapshot,Workspace,Collection

def test_contract_preserves_all_v050_tools():
    r=validate_contract()
    assert r['v050_tools']==20 and r['v060_total']==34 and r['total']==45 and not r['control_plane_exposed']

def test_operator_registry_writes_not_mcp():
    assert {'workspace_add','workspace_remove','collection_add','collection_remove','usage_import'} <= OPERATOR_ONLY
    assert not set(V060_ADDITIONS)&OPERATOR_ONLY
    assert not set(V070_ADDITIONS)&OPERATOR_ONLY
    assert not set(V080_ADDITIONS)&OPERATOR_ONLY

def test_editor_add_collection():
    s=RegistrySnapshot(1,(Workspace('a',r'C:\Projects\A'),));n=RegistryEditor(s).add_collection(Collection('projects',r'C:\Projects',True));assert n.revision==2 and n.collections[0].name=='projects'

def test_editor_add_workspace():
    s=RegistrySnapshot(1,(),(Collection('projects',r'C:\Projects'),));n=RegistryEditor(s).add_workspace(Workspace('a',r'C:\Projects\A'));assert n.revision==2

def test_editor_remove_workspace():
    s=RegistrySnapshot(1,(Workspace('a',r'C:\A'),));n=RegistryEditor(s).remove_workspace('A');assert n.workspaces==()

def test_editor_remove_unknown_rejected():
    with pytest.raises(Rejected) as e:RegistryEditor(RegistrySnapshot(1,())).remove_workspace('x')
    assert e.value.code=='UNKNOWN_WORKSPACE'

def test_publish_blocks_current_runtime_layout():
    s=RegistrySnapshot(2,(),(Collection('projects',r'C:\Projects'),))
    with pytest.raises(Rejected) as e:validate_publish(s,runtime_roots=[r'C:\Projects\LocalControlLab-20260908\runtime-repair-v050'],state_root=r'C:\Users\samis\.local\state\localcontrol-v050')
    assert e.value.code=='CONTROL_PLANE_OVERLAP'

def test_publish_accepts_proposed_runtime_layout():
    s=RegistrySnapshot(2,(),(Collection('projects',r'C:\Projects'),));r=validate_publish(s,runtime_roots=[r'C:\Users\samis\.local\lib\localcontrol\0.6.0'],state_root=r'C:\Users\samis\.local\state\localcontrol-v060')
    assert r['publishable']
