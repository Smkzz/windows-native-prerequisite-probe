from pathlib import Path
import pytest
from localcontrol.v060.core import Rejected
from localcontrol.v060.health import HealthBook,HealthSample
from localcontrol.v060.usage_store import DurableUsageStore,normalize

def sample(**kw):
    d=dict(time_ns=1,server_version='0.5.0-rc.1',tool_count=20,runtime_count=1,audit_chain_ok=True,sandbox_ok=True,network_listener=False,owned_jobs_running=0,oldest_running_job_seconds=0,recovery_pending_seconds=None,unexpected_errors_delta=0,policy_rejections_delta=0,calls_delta=10);d.update(kw);return HealthSample(**d)

def test_health_good(): assert HealthBook().add(sample())['healthy']
@pytest.mark.parametrize('field,value,code',[('audit_chain_ok',False,'AUDIT_CHAIN'),('sandbox_ok',False,'SANDBOX'),('network_listener',True,'NETWORK_LISTENER'),('runtime_count',2,'RUNTIME_COUNT')])
def test_health_hard_failures(field,value,code):
    r=HealthBook().add(sample(**{field:value}));assert not r['healthy'] and code in r['failures']

def test_health_stuck_warning():
    r=HealthBook(stuck_job_s=10).add(sample(oldest_running_job_seconds=11));assert r['healthy'] and 'POSSIBLE_STUCK_JOB' in r['warnings']

def test_health_recovery_timeout():
    r=HealthBook(max_recovery_s=30).add(sample(recovery_pending_seconds=31));assert not r['healthy'] and 'RECOVERY_TIMEOUT' in r['failures']

def test_health_high_error_warning():
    r=HealthBook().add(sample(unexpected_errors_delta=6,calls_delta=100));assert 'HIGH_UNEXPECTED_ERROR_RATE' in r['warnings']

def test_health_summary_accumulates():
    h=HealthBook();h.add(sample());h.add(sample(time_ns=2,owned_jobs_running=3));s=h.summary();assert s['healthy'] and s['samples']==2 and s['max_owned_jobs_running']==3

def event(**kw):
    d={'schema':1,'event_id':'e1','project':'ww2','task':'phase12','model':'sol','stage':'implementation','basis':'per_request','finalized':True,'tokens':{'input_total':100,'cached_input':40,'output_total':20,'reasoning_output':5},'evidence_sha256':'a'*64,'adapter':'openai_usage'};d.update(kw);return d

def test_usage_ingest_and_summary(tmp_path):
    u=DurableUsageStore(tmp_path/'u.db',frozenset({'openai_usage'}));assert not u.ingest(event())['replayed'];s=u.summary('ww2','phase12');assert s['tokens']['uncached_input']['total']==60;u.close()

def test_usage_replay(tmp_path):
    u=DurableUsageStore(tmp_path/'u.db',frozenset({'openai_usage'}));u.ingest(event());assert u.ingest(event())['replayed'];u.close()

def test_usage_id_conflict(tmp_path):
    u=DurableUsageStore(tmp_path/'u.db',frozenset({'openai_usage'}));u.ingest(event())
    with pytest.raises(Rejected) as e:u.ingest(event(tokens={'input_total':101,'cached_input':40,'output_total':20,'reasoning_output':5}))
    assert e.value.code=='IDEMPOTENCY_CONFLICT';u.close()

def test_usage_untrusted_adapter(tmp_path):
    u=DurableUsageStore(tmp_path/'u.db',frozenset({'trusted'}))
    with pytest.raises(Rejected) as e:u.ingest(event())
    assert e.value.code=='UNTRUSTED_ADAPTER';u.close()

def test_usage_missing_counter_propagates_unknown(tmp_path):
    u=DurableUsageStore(tmp_path/'u.db',frozenset({'openai_usage'}));e=event();e['tokens']['cached_input']=None;u.ingest(e);s=u.summary();assert s['tokens']['uncached_input']['total'] is None and s['tokens']['uncached_input']['missing_events']==1;u.close()

def test_usage_subset_guard():
    e=event();e['tokens']['cached_input']=101
    with pytest.raises(Rejected) as x:normalize(e)
    assert x.value.code=='USAGE_SUBSET_EXCEEDS_TOTAL'

def test_expected_policy_rejections_do_not_warn():
    r=HealthBook().add(sample(policy_rejections_delta=20,calls_delta=20));assert r['healthy'] and not r['warnings']

def test_version_drift_fails_summary():
    h=HealthBook();h.add(sample());h.add(sample(time_ns=2,server_version='0.6.0-rc.1'));s=h.summary();assert not s['healthy'] and 'VERSION_DRIFT' in s['failures']

def test_tool_catalog_drift_fails_summary():
    h=HealthBook();h.add(sample());h.add(sample(time_ns=2,tool_count=21));s=h.summary();assert not s['healthy'] and 'TOOL_CATALOG_DRIFT' in s['failures']
