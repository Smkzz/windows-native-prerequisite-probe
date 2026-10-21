import pytest
from localcontrol.v060.core import Rejected
from localcontrol.v060.leases import MaintenanceLeases

class Clock:
    def __init__(self): self.n=1_000_000_000
    def __call__(self): return self.n
    def add(self,s): self.n+=s*1_000_000_000

def c(e):return e.value.code

def test_begin_and_verify():
    clock=Clock();m=MaintenanceLeases(clock)
    l=m.begin('ww2','owner','binding','move',10)
    assert m.verify(l.lease_id,'ww2','owner','binding')==l

def test_second_lease_blocked():
    m=MaintenanceLeases(Clock());m.begin('ww2','o','b','move')
    with pytest.raises(Rejected) as e:m.begin('WW2','o','b','cleanup')
    assert c(e)=='WORKSPACE_BUSY'

def test_expired_lease_frees_workspace():
    clock=Clock();m=MaintenanceLeases(clock);m.begin('ww2','o','b','move',1);clock.add(2)
    assert m.begin('ww2','o','b','move').lease_id

def test_wrong_owner_rejected():
    m=MaintenanceLeases(Clock());l=m.begin('ww2','o','b','move')
    with pytest.raises(Rejected) as e:m.verify(l.lease_id,'ww2','x','b')
    assert c(e)=='LEASE_MISMATCH'

def test_release():
    m=MaintenanceLeases(Clock());l=m.begin('ww2','o','b','move');assert m.end(l.lease_id,'ww2','o','b')['released']
    assert m.mutation_allowed('ww2',None)

def test_other_mutation_blocked_during_lease():
    m=MaintenanceLeases(Clock());l=m.begin('ww2','o','b','move')
    assert not m.mutation_allowed('ww2',None) and m.mutation_allowed('ww2',l.lease_id)

def test_ttl_bound():
    m=MaintenanceLeases(Clock(),max_ttl_s=30)
    with pytest.raises(Rejected) as e:m.begin('ww2','o','b','move',31)
    assert c(e)=='INVALID_TTL'

def test_composite_lease_blocks_both_scopes():
    m=MaintenanceLeases(Clock());l=m.begin_many(('source','projects'),'o','b','move')
    assert not m.mutation_allowed('source',None) and not m.mutation_allowed('projects',None)
    assert m.mutation_allowed('source',l.lease_id) and m.mutation_allowed('projects',l.lease_id)

def test_composite_lease_acquisition_is_atomic():
    m=MaintenanceLeases(Clock());m.begin('projects','o','b','move')
    with pytest.raises(Rejected) as e:m.begin_many(('free','projects'),'o','b','move')
    assert c(e)=='WORKSPACE_BUSY' and m.mutation_allowed('free',None)

def test_composite_release_releases_all():
    m=MaintenanceLeases(Clock());l=m.begin_many(('a','b'),'o','bind','move');m.end(l.lease_id,'a','o','bind')
    assert m.mutation_allowed('a',None) and m.mutation_allowed('b',None)
