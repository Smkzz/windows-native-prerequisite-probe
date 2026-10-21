import pytest
from localcontrol.v060.windows_discovery import should_skip_dir
from localcontrol.v060.health_store import DurableHealthStore
from localcontrol.v060.health import HealthSample
from localcontrol.v060.core import Rejected

def sample(t=1,**kw):
    d=dict(time_ns=t,server_version='0.6.0-rc.1',tool_count=34,runtime_count=1,audit_chain_ok=True,sandbox_ok=True,network_listener=False,owned_jobs_running=0,oldest_running_job_seconds=0,recovery_pending_seconds=None,unexpected_errors_delta=0,policy_rejections_delta=0,calls_delta=10);d.update(kw);return HealthSample(**d)

def test_discovery_skips_sensitive_roots():
    for n in ['.ssh','.aws','.azure','.gnupg','AppData']:assert should_skip_dir(n,1)

def test_discovery_skips_vendor_dirs():
    for n in ['node_modules','.venv','vendor','target','.git']:assert should_skip_dir(n,2)

def test_discovery_skips_system_at_drive_root():
    assert should_skip_dir('Windows',0) and should_skip_dir('Program Files',0)

def test_discovery_does_not_skip_normal_project():assert not should_skip_dir('ww2game',0)

def test_health_store_persists(tmp_path):
    p=tmp_path/'h.db';h=DurableHealthStore(p);h.ingest(sample());h.close();h=DurableHealthStore(p);s=h.summary();assert s['healthy'] and s['samples']==1;h.close()

def test_health_store_replay(tmp_path):
    h=DurableHealthStore(tmp_path/'h.db');h.ingest(sample());assert h.ingest(sample())['replayed'];h.close()

def test_health_store_conflict(tmp_path):
    h=DurableHealthStore(tmp_path/'h.db');h.ingest(sample())
    with pytest.raises(Rejected) as e:h.ingest(sample(runtime_count=2))
    assert e.value.code=='HEALTH_IDEMPOTENCY_CONFLICT';h.close()

def test_health_store_since_filter(tmp_path):
    h=DurableHealthStore(tmp_path/'h.db');h.ingest(sample(1));h.ingest(sample(2));assert h.summary(since_ns=2)['samples']==1;h.close()

def test_health_store_detects_drift(tmp_path):
    h=DurableHealthStore(tmp_path/'h.db');h.ingest(sample(1));h.ingest(sample(2,tool_count=35));s=h.summary();assert not s['healthy'] and 'TOOL_CATALOG_DRIFT' in s['failures'];h.close()
