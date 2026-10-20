from __future__ import annotations
from dataclasses import dataclass, asdict
from collections import deque
import time
from .core import need

@dataclass(frozen=True)
class HealthSample:
    time_ns: int
    server_version: str
    tool_count: int
    runtime_count: int
    audit_chain_ok: bool
    sandbox_ok: bool
    network_listener: bool
    owned_jobs_running: int
    oldest_running_job_seconds: int
    recovery_pending_seconds: int|None = None
    unexpected_errors_delta: int = 0
    policy_rejections_delta: int = 0
    calls_delta: int = 0

class HealthBook:
    """Bounded soak evaluation. Collection is adapter-owned; this class never enumerates foreign processes."""
    def __init__(self,max_samples:int=4096,stuck_job_s:int=3600,max_recovery_s:int=180):
        need(type(max_samples)is int and 24<=max_samples<=100000)
        self.samples=deque(maxlen=max_samples);self.stuck_job_s=stuck_job_s;self.max_recovery_s=max_recovery_s
    def add(self,s:HealthSample):
        need(isinstance(s,HealthSample));self.samples.append(s);return self.evaluate_one(s)
    def evaluate_one(self,s:HealthSample)->dict:
        failures=[];warnings=[]
        if not s.audit_chain_ok: failures.append("AUDIT_CHAIN")
        if not s.sandbox_ok: failures.append("SANDBOX")
        if s.network_listener: failures.append("NETWORK_LISTENER")
        if s.runtime_count!=1: failures.append("RUNTIME_COUNT")
        if s.oldest_running_job_seconds>self.stuck_job_s: warnings.append("POSSIBLE_STUCK_JOB")
        if s.recovery_pending_seconds is not None and s.recovery_pending_seconds>self.max_recovery_s: failures.append("RECOVERY_TIMEOUT")
        if s.calls_delta>0 and s.unexpected_errors_delta/s.calls_delta>0.05: warnings.append("HIGH_UNEXPECTED_ERROR_RATE")
        return {"healthy":not failures,"failures":failures,"warnings":warnings}
    def summary(self)->dict:
        if not self.samples:
            return {"samples":0,"healthy":None,"state":"unknown-no-samples",
                    "reason":"NO_SAMPLES","uncertainty":"no telemetry samples observed"}
        evals=[self.evaluate_one(s) for s in self.samples]
        failures=sorted({x for e in evals for x in e["failures"]});warnings=sorted({x for e in evals for x in e["warnings"]})
        versions=sorted({s.server_version for s in self.samples});tool_counts=sorted({s.tool_count for s in self.samples})
        if len(versions)>1: failures.append("VERSION_DRIFT")
        if len(tool_counts)>1: failures.append("TOOL_CATALOG_DRIFT")
        failures=sorted(set(failures))
        state = "healthy" if not failures else "unhealthy"
        if self.samples and (time.time_ns() - self.samples[-1].time_ns) > self.max_recovery_s * 1_000_000_000:
            state = "stale"
            healthy = None
            warnings = sorted(set(warnings + ["STALE_SAMPLE"]))
        else:
            healthy = not failures
        return {"samples":len(self.samples),"healthy":healthy,"state":state,"failures":failures,"warnings":warnings,
                "first_time_ns":self.samples[0].time_ns,"last_time_ns":self.samples[-1].time_ns,
                "versions":versions,"tool_counts":tool_counts,
                "policy_rejections":sum(s.policy_rejections_delta for s in self.samples),
                "unexpected_errors":sum(s.unexpected_errors_delta for s in self.samples),
                "max_runtime_count":max(s.runtime_count for s in self.samples),
                "max_owned_jobs_running":max(s.owned_jobs_running for s in self.samples)}
