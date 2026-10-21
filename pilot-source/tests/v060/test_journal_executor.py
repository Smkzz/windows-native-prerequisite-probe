from pathlib import Path
import pytest
from localcontrol.v060.core import Rejected
from localcontrol.v060.executor import MoveExecutor
from localcontrol.v060.journal import DurableMoveJournal
from localcontrol.v060.leases import MaintenanceLeases
from localcontrol.v060.migration import Entry,TreeSnapshot,make_move_plan

class Clock:
    def __init__(self):self.n=1_000_000_000
    def __call__(self):return self.n

class FakeAdapter:
    def __init__(self):
        self.trees={r'C:\Old\Proj':TreeSnapshot(r'C:\Old\Proj','id42','vol1',(Entry('x.txt','file',1,'a'*64,'f1'),))}
        self.fail_rename=False;self.corrupt_identity_after=False
    def snapshot(self,path):
        t=self.trees[path]
        if self.corrupt_identity_after and path==r'C:\Projects\Proj':return TreeSnapshot(path,'different','vol1',t.entries)
        return TreeSnapshot(path,t.root_identity,t.volume_id,t.entries)
    def exists(self,path):return path in self.trees
    def parent_volume(self,path):return 'vol1' if path.startswith('C:') else 'vol2'
    def rename(self,source,destination):
        if self.fail_rename:raise OSError('locked')
        t=self.trees.pop(source);self.trees[destination]=TreeSnapshot(destination,t.root_identity,t.volume_id,t.entries)

def setup(tmp_path):
    a=FakeAdapter();clock=Clock();leases=MaintenanceLeases(clock);lease=leases.begin_many(('oldproj','projects'),'owner','binding','move',300)
    p=make_move_plan(a.snapshot(r'C:\Old\Proj'),r'C:\Projects\Proj',destination_parent_volume='vol1',destination_absent=True,registry_revision=7,lease_id=lease.lease_id,now_ns=clock.n,source_scope='oldproj',source_authority_root=r'C:\\Old\\Proj',collection='projects',destination_collection_root=r'C:\\Projects')
    j=DurableMoveJournal(tmp_path/'m.db');x=MoveExecutor(a,j,leases);return a,leases,lease,p,j,x

def test_durable_journal_survives_reopen(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path);j.begin(p);j.transition(p.plan_id,'PLANNED','PRECHECKED',{'x':1});j.close()
    j2=DurableMoveJournal(tmp_path/'m.db');assert j2.get(p.plan_id)['state']=='PRECHECKED';assert [e['state'] for e in j2.events(p.plan_id)]==['PLANNED','PRECHECKED'];j2.close()

def test_executor_success(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path);r=x.apply(p,registry_revision=7,owner='owner',binding='binding')
    assert r['state']=='COMMITTED' and not a.exists(p.source) and a.exists(p.destination)
    assert [e['state'] for e in j.events(p.plan_id)]==['PLANNED','PRECHECKED','MOVED','VERIFIED','COMMITTED'];j.close()

def test_executor_replay_committed(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path);x.apply(p,registry_revision=7,owner='owner',binding='binding');r=x.apply(p,registry_revision=7,owner='owner',binding='binding')
    assert r['state']=='COMMITTED' and r['replayed'];j.close()

def test_registry_change_aborts_before_move(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path)
    with pytest.raises(Rejected) as e:x.apply(p,registry_revision=8,owner='owner',binding='binding')
    assert e.value.code=='REGISTRY_CHANGED' and a.exists(p.source) and j.get(p.plan_id)['state']=='ABORTED';j.close()

def test_source_change_aborts(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path);a.trees[p.source]=TreeSnapshot(p.source,'id42','vol1',(Entry('other','file',2,'b'*64,'f2'),))
    with pytest.raises(Rejected) as e:x.apply(p,registry_revision=7,owner='owner',binding='binding')
    assert e.value.code=='SOURCE_CHANGED' and j.get(p.plan_id)['state']=='ABORTED';j.close()

def test_destination_appears_aborts(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path);a.trees[p.destination]=TreeSnapshot(p.destination,'other','vol1',())
    with pytest.raises(Rejected) as e:x.apply(p,registry_revision=7,owner='owner',binding='binding')
    assert e.value.code=='DESTINATION_EXISTS';assert j.get(p.plan_id)['state']=='ABORTED';j.close()

def test_rename_failure_stays_prechecked_for_safe_retry(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path);a.fail_rename=True
    with pytest.raises(OSError):x.apply(p,registry_revision=7,owner='owner',binding='binding')
    assert j.get(p.plan_id)['state']=='PRECHECKED' and a.exists(p.source);j.close()

def test_post_move_bad_identity_rolls_back(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path);a.corrupt_identity_after=True
    with pytest.raises(Rejected):
        x.apply(p,registry_revision=7,owner='owner',binding='binding')
    # Corrupt adapter reports unverifiable destination identity, so rollback must fail closed.
    assert j.get(p.plan_id)['state']=='ROLLBACK_REQUIRED';j.close()

def test_reconcile_crash_after_move_commits(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path);j.begin(p);j.transition(p.plan_id,'PLANNED','PRECHECKED');a.rename(p.source,p.destination);j.transition(p.plan_id,'PRECHECKED','MOVED')
    r=x.reconcile(p,owner='owner',binding='binding');assert r['state']=='COMMITTED' and r['reconciled'];j.close()

def test_unresolved_lists_nonterminal(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path);j.begin(p);assert j.unresolved()[0]['plan_id']==p.plan_id;j.transition(p.plan_id,'PLANNED','ABORTED');assert j.unresolved()==[];j.close()

def test_wrong_lease_owner_prevents_move(tmp_path):
    a,l,lease,p,j,x=setup(tmp_path)
    with pytest.raises(Rejected) as e:x.apply(p,registry_revision=7,owner='attacker',binding='binding')
    assert e.value.code=='LEASE_MISMATCH' and a.exists(p.source);j.close()
