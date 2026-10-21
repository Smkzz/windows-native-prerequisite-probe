import json, pytest
from localcontrol.v060.core import Rejected
from localcontrol.v060.migration import Entry,TreeSnapshot,Risk,scan_text_risks,make_move_plan,MovePlanCodec,MoveJournal

def c(e):return e.value.code

def snap():
    return TreeSnapshot(r'C:\Old\Proj','vol1:file42','vol1',(Entry('a.txt','file',1,'a'*64,'f1'),Entry('sub','dir',0,None,'d1')))

def test_snapshot_fingerprint_stable_order():
    a=snap();b=TreeSnapshot(a.root,a.root_identity,a.volume_id,tuple(reversed(a.entries)))
    assert a.fingerprint==b.fingerprint

def test_duplicate_entry_casefold_rejected():
    with pytest.raises(Rejected) as e:TreeSnapshot(r'C:\A','id','v',(Entry('X','file'),Entry('x','file')))
    assert c(e)=='DUPLICATE_ENTRY'

def test_plan_happy_path():
    p=make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-12345678')
    assert p.source_volume==p.destination_parent_volume and p.plan_id.startswith('move-')

def test_cross_volume_rejected():
    with pytest.raises(Rejected) as e:make_move_plan(snap(),r'D:\Projects\Proj',destination_parent_volume='vol2',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'D:\\Projects',lease_id='lease-x')
    assert c(e)=='CROSS_VOLUME_UNSUPPORTED'

def test_destination_exists_rejected():
    with pytest.raises(Rejected) as e:make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=False,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x')
    assert c(e)=='DESTINATION_EXISTS'

def test_destination_inside_source_rejected():
    with pytest.raises(Rejected) as e:make_move_plan(snap(),r'C:\Old\Proj\nested',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Old',lease_id='lease-x')
    assert c(e)=='DESTINATION_INSIDE_SOURCE'

def test_blocker_risk_rejects_plan():
    risk=(Risk('GIT','blocker','.git','x'),)
    with pytest.raises(Rejected) as e:make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x',risks=risk)
    assert c(e)=='MOVE_BLOCKED'

def test_warning_allowed():
    risk=(Risk('X','warning','x','x'),)
    assert make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x',risks=risk).risks

def test_plan_codec_roundtrip():
    p=make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x',now_ns=100,ttl_s=1)
    cdc=MovePlanCodec(b'z'*32);q=cdc.decode(cdc.encode(p),now_ns=200);assert q==p

def test_plan_codec_tamper():
    p=make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x')
    cdc=MovePlanCodec(b'z'*32);o=json.loads(cdc.encode(p));o['body']['destination']=r'C:\Elsewhere'
    with pytest.raises(Rejected) as e:cdc.decode(json.dumps(o))
    assert c(e)=='INVALID_PLAN'

def test_plan_expiry():
    p=make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x',now_ns=100,ttl_s=1)
    cdc=MovePlanCodec(b'z'*32)
    with pytest.raises(Rejected) as e:cdc.decode(cdc.encode(p),now_ns=1_000_000_101)
    assert c(e)=='PLAN_EXPIRED'

def test_risk_scanner_absolute_source():
    r=scan_text_risks(r'C:\Old\Proj',[('config.json',r'{"path":"C:\\Old\\Proj\\data"}')])
    assert any(x.code=='ABSOLUTE_SOURCE_REFERENCE' for x in r)

def test_risk_scanner_gitdir_blocker():
    r=scan_text_risks(r'C:\Old\Proj',[('.git',r'gitdir: C:\Repos\Main\.git\worktrees\Proj')])
    assert any(x.code=='GITDIR_ABSOLUTE' and x.severity=='blocker' for x in r)

def test_risk_scanner_venv():
    r=scan_text_risks(r'C:\Old\Proj',[('pyvenv.cfg',r'executable = C:\Old\Proj\.venv\Scripts\python.exe')])
    assert any(x.code=='VENV_ABSOLUTE_REFERENCE' for x in r)

def test_risk_scanner_reparse_warning():
    r=scan_text_risks(r'C:\Old\Proj',[],[r'node_modules\pkg'])
    assert r[0].code=='REPARSE_PRESENT' and r[0].severity=='warning'

def test_journal_happy_path():
    p=make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x')
    j=MoveJournal();x=j.begin(p);assert x['state']=='PLANNED'
    j.advance(p.plan_id,'PLANNED','PRECHECKED',preflight='ok');j.advance(p.plan_id,'PRECHECKED','MOVED',rename='ok');j.advance(p.plan_id,'MOVED','VERIFIED',identity='ok');j.advance(p.plan_id,'VERIFIED','COMMITTED')
    assert j.current(p.plan_id)['state']=='COMMITTED'

def test_journal_begin_replay():
    p=make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x');j=MoveJournal();j.begin(p)
    assert j.begin(p)['replayed']

def test_journal_out_of_order_rejected():
    p=make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x');j=MoveJournal();j.begin(p)
    with pytest.raises(Rejected) as e:j.advance(p.plan_id,'PLANNED','MOVED')
    assert c(e)=='INVALID_TRANSITION'

def test_journal_rollback_path():
    p=make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',destination_collection_root=r'C:\\Projects',lease_id='lease-x');j=MoveJournal();j.begin(p)
    j.advance(p.plan_id,'PLANNED','PRECHECKED');j.advance(p.plan_id,'PRECHECKED','MOVED');j.mark_rollback_required(p.plan_id,'verify failed');j.mark_rolled_back(p.plan_id,{'identity':'ok'})
    assert j.current(p.plan_id)['state']=='ROLLED_BACK'

def test_source_must_be_in_authorized_scope():
    with pytest.raises(Rejected) as e:make_move_plan(snap(),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='wrong',source_authority_root=r'C:\Other',destination_collection_root=r'C:\Projects',lease_id='lease-x')
    assert c(e)=='SOURCE_OUTSIDE_AUTHORITY'

def test_destination_must_be_in_collection():
    with pytest.raises(Rejected) as e:make_move_plan(snap(),r'C:\Elsewhere\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\Old\Proj',destination_collection_root=r'C:\Projects',lease_id='lease-x')
    assert c(e)=='DESTINATION_OUTSIDE_COLLECTION'

def test_incomplete_snapshot_cannot_be_planned():
    s=snap();incomplete=TreeSnapshot(s.root,s.root_identity,s.volume_id,s.entries,complete=False)
    with pytest.raises(Rejected) as e:make_move_plan(incomplete,r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=2,source_scope='oldproj',source_authority_root=r'C:\Old\Proj',destination_collection_root=r'C:\Projects',lease_id='lease-x')
    assert c(e)=='INCOMPLETE_SNAPSHOT'

def test_internal_absolute_reparse_blocks():
    from localcontrol.v060.migration import scan_reparse_risks
    entries=(Entry('node_modules/pkg','reparse',0,None,'id',r'C:\Old\Proj\.pnpm\pkg'),)
    r=scan_reparse_risks(r'C:\Old\Proj',entries);assert r[0].code=='INTERNAL_ABSOLUTE_REPARSE' and r[0].severity=='blocker'

def test_external_absolute_reparse_warns():
    from localcontrol.v060.migration import scan_reparse_risks
    entries=(Entry('external','reparse',0,None,'id',r'C:\Shared\SDK'),)
    r=scan_reparse_risks(r'C:\Old\Proj',entries);assert r[0].code=='EXTERNAL_ABSOLUTE_REPARSE' and r[0].severity=='warning'

def test_relative_reparse_is_info():
    from localcontrol.v060.migration import scan_reparse_risks
    entries=(Entry('relative','reparse',0,None,'id',r'..\shared'),)
    r=scan_reparse_risks(r'C:\Old\Proj',entries);assert r[0].code=='RELATIVE_REPARSE' and r[0].severity=='info'

def test_unknown_reparse_target_blocks():
    from localcontrol.v060.migration import scan_reparse_risks
    entries=(Entry('mystery','reparse',0,None,'id',None),)
    r=scan_reparse_risks(r'C:\Old\Proj',entries);assert r[0].code=='REPARSE_TARGET_UNKNOWN' and r[0].severity=='blocker'

def test_git_linked_worktrees_structural_blocker():
    from localcontrol.v060.migration import scan_structural_risks
    r=scan_structural_risks((Entry('.git/worktrees','dir'),Entry('.git/worktrees/w1/gitdir','file'),));assert r[0].code=='GIT_LINKED_WORKTREES' and r[0].severity=='blocker'

def test_venv_structural_warning():
    from localcontrol.v060.migration import scan_structural_risks
    r=scan_structural_risks((Entry('.venv','dir'),));assert r[0].code=='VENV_PRESENT' and r[0].severity=='warning'

def test_node_modules_structural_info():
    from localcontrol.v060.migration import scan_structural_risks
    r=scan_structural_risks((Entry('node_modules','dir'),));assert r[0].code=='NODE_MODULES_PRESENT'
