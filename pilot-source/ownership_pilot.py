"""Bounded runner-only pilot. Candidate source is imported unchanged; no server starts."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from localcontrol import appcontainer
from localcontrol.errors import ControlError
from localcontrol.job_ownership import Custody
from localcontrol.jobs import JobManager
from localcontrol.policy import Policy, Project, no_links
from localcontrol.store import Store
from localcontrol.windows_job import WindowsJob

def need(value, code):
    if not value:
        raise RuntimeError(code)

def until(check, seconds=12):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.03)
    raise RuntimeError("BOUNDED_WAIT_FAILED")

def dump(value):
    print(json.dumps(value, sort_keys=True), flush=True)

def token_sid():
    k = c.WinDLL("kernel32", use_last_error=True)
    a = c.WinDLL("advapi32", use_last_error=True)
    k.GetCurrentProcess.restype = w.HANDLE
    a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    a.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
    k.LocalFree.argtypes = [c.c_void_p]
    k.CloseHandle.argtypes = [w.HANDLE]
    token = w.HANDLE()
    need(a.OpenProcessToken(k.GetCurrentProcess(), 8, c.byref(token)), "TOKEN_OPEN")
    try:
        n = w.DWORD()
        a.GetTokenInformation(token, 1, None, 0, c.byref(n))
        buf = c.create_string_buffer(n.value)
        need(a.GetTokenInformation(token, 1, buf, n, c.byref(n)), "TOKEN_USER")
        ptr = c.cast(buf, c.POINTER(c.c_void_p))[0]
        s = w.LPWSTR()
        need(a.ConvertSidToStringSidW(ptr, c.byref(s)), "TOKEN_SID_TEXT")
        try:
            sid = s.value
        finally:
            k.LocalFree(c.cast(s, c.c_void_p))
        for kind in (20, 29):  # elevation and AppContainer: coordinator is neither
            val = w.DWORD()
            need(a.GetTokenInformation(token, kind, c.byref(val), 4, c.byref(n)), "COORDINATOR_TOKEN")
            if kind == 29:
                need(val.value == 0, "NATIVE_COORDINATOR_REQUIRED")
            else:
                dump({"runner_coordinator_elevated": bool(val.value), "elevation_requested": False})
        return sid
    finally:
        k.CloseHandle(token)

def acl(path, *args):
    exe = str(Path(os.environ["SYSTEMROOT"]) / "System32" / "icacls.exe")
    p = subprocess.run([exe, str(path), *args], capture_output=True, timeout=10,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    need(p.returncode == 0, "NEW_FIXTURE_ACL_FAILED")

class InjectedStore(Store):
    """Only the owned-transition SQLite fault is synthetic; native APIs remain real."""
    armed = False
    observed = None
    manager = None
    def commit_job_transition(self, job_id, scope, phase, revision, record, kind, metadata):
        if self.armed and phase == "owned":
            self.armed = False
            owner = self.manager.owners[job_id]
            need(job_id in self.manager.starting, "STARTING_REMOVED_BEFORE_OWNED_COMMIT")
            need(owner.custody.process is not None, "NO_REAL_PROCESS_AT_OWNED_FAULT")
            need(owner.custody.api.wait(owner.custody.process._handle, 0) == 258, "FAULT_PROCESS_NOT_LIVE")
            need(owner.custody.command_released is False, "COMMAND_RELEASED_BEFORE_OWNED_COMMIT")
            self.observed = {"starting_retained": True, "real_process_suspended": True,
                             "command_released": False, "job_id": job_id}
            raise sqlite3.OperationalError("intentional fixture owned-transition failure")
        return super().commit_job_transition(job_id, scope, phase, revision, record, kind, metadata)

def run(root):
    need(os.name == "nt" and c.sizeof(c.c_void_p) == 8, "WINDOWS_X64_REQUIRED")
    need(sys.version_info >= (3, 11), "PYTHON_VERSION_REQUIRED")
    dump({"python_version": sys.version.split()[0], "python_x64": True})
    need(re.fullmatch(r"C:\\LocalControlOwnershipPilot-[a-f0-9]{32}", str(root)) is not None,
         "ROOT_SCOPE_REFUSED")
    no_links(root)
    need(not any("TOKEN" in key.upper() or key.upper().startswith("ACTIONS_")
                 for key in os.environ), "CREDENTIAL_ENV_NOT_STRIPPED")
    owner_sid = token_sid()
    fixture = root / "fixture"
    subject = fixture / "subject"
    output = fixture / "out"
    runtime = fixture / "runtime"
    for directory in (fixture, subject, output, runtime, root / "controller"):
        directory.mkdir(exist_ok=False)
    exe = runtime / "GenericBoundaryProbe.exe"
    exe.write_bytes((root / "compiled-helper.exe").read_bytes())
    allowed, denied = fixture / "allowed.txt", fixture / "denied.txt"
    allowed.write_text("public-positive-control")
    denied.write_text("synthetic-denial-sentinel")
    profile = "LocalControl.Pilot." + uuid.uuid4().hex
    u = c.WinDLL("userenv")
    a = c.WinDLL("advapi32")
    k = c.WinDLL("kernel32")
    u.CreateAppContainerProfile.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
    u.CreateAppContainerProfile.restype = c.c_long
    u.DeleteAppContainerProfile.argtypes = [w.LPCWSTR]
    u.DeleteAppContainerProfile.restype = c.c_long
    a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
    a.FreeSid.argtypes = [c.c_void_p]
    a.FreeSid.restype = c.c_void_p
    k.LocalFree.argtypes = [c.c_void_p]
    sid = c.c_void_p()
    profile_created = False
    try:
        need(u.CreateAppContainerProfile(profile, profile, "Disposable ownership pilot", None, 0, c.byref(sid)) == 0,
             "PROFILE_CREATE_FAILED")
        profile_created = True
        text = w.LPWSTR()
        need(a.ConvertSidToStringSidW(sid, c.byref(text)), "PROFILE_SID_TEXT")
        try:
            sid_text = text.value
        finally:
            k.LocalFree(c.cast(text, c.c_void_p))
        # All ACL mutations are on this newly created runner fixture.
        acl(root, "/grant", "*" + sid_text + ":(RX)")  # traversal; no inheritance
        acl(fixture, "/grant", "*" + sid_text + ":(OI)(CI)(RX)")
        acl(output, "/grant", "*" + sid_text + ":(OI)(CI)(M)")
        acl(denied, "/inheritance:r", "/grant:r", "*" + owner_sid + ":(F)", "*S-1-5-18:(F)")
        # Explicit coordinator positive control on exactly the denied file.
        with denied.open("r+b") as stream:
            need(stream.read() == b"synthetic-denial-sentinel", "DENIED_POSITIVE_CONTROL")
        manifest = root / "controller" / "worker.json"
        manifest.write_text(json.dumps({"workspace": str(subject), "network_capabilities": [],
            "profile_name": profile, "runtime": str(runtime), "temp": str(output), "home": str(subject)}))

        def app_args(witness):
            return [str(exe), "app", str(allowed), str(denied), str(witness), sid_text]

        def manager_case(label, mode):
            state = root / "controller" / label
            policy = Policy({"pilot": Project(subject, True)}, state,
                exec_mode="appcontainer", workers={"pilot": {"manifest": str(manifest)}},
                max_active_jobs=1, max_queued_jobs=1, max_timeout_ms=20000,
                max_wait_ms=1000, min_free_memory_bytes=1024**3, min_free_disk_bytes=1024**3)
            store = InjectedStore(state)
            mgr = None
            leaf = None
            leaf_api = None
            started = time.monotonic()
            result = {}
            try:
                mgr = JobManager(policy, store)  # real Policy, lease, SQLite, scheduler, pressure sampler
                pressure = mgr.pressure.snapshot()
                need(not pressure.pressured and pressure.free_memory_bytes is not None,
                     "RUNNER_MEMORY_ADMISSION_DEFERRED")
                witness = output / (label + ".json")
                if mode == "owned_fault":
                    store.manager = mgr
                    store.armed = True
                argv = [str(exe), "tree", str(witness)] if mode == "tree_stop" else app_args(witness)
                argv = policy.command("pilot", argv, None)
                try:
                    jid = mgr.start("pilot", "pilot", argv, 20000,
                                    limits={"max_processes": 4, "memory_bytes": 256*1024**2})
                except ControlError as error:
                    need(mode == "owned_fault" and store.observed is not None, "UNEXPECTED_LAUNCH_FAILURE")
                    need(error.code in {"JOB_SETUP_FAILED", "STORE_FAILURE"}, "FAULT_ERROR_CODE")
                    jid = store.observed["job_id"]
                if mode == "tree_stop":
                    dump({"case": label, "stage": "WAIT_DESCENDANT_WITNESS"})
                    try:
                        until(witness.exists, 8)
                    except RuntimeError:
                        observed = mgr.read("pilot", jid, 0)
                        helper_error = str(observed.get("stderr", "")).strip()
                        safe_helper_error = helper_error if re.fullmatch(
                            r"(?:Win32Exception|InvalidOperationException):[A-Z0-9_]{1,100}",
                            helper_error) else "NO_ALLOWLISTED_HELPER_ERROR"
                        dump({"case": label, "stage": "DESCENDANT_WITNESS_TIMEOUT",
                              "status": observed.get("status"),
                              "returncode": observed.get("returncode"),
                              "helper_error": safe_helper_error})
                        raise RuntimeError("DESCENDANT_WITNESS_TIMEOUT")
                    # Open only PID emitted by our live helper; never terminate by PID.
                    pid = int(witness.read_text())
                    owner = mgr.owners[jid]
                    leaf_api = c.WinDLL("kernel32", use_last_error=True)
                    leaf_api.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
                    leaf_api.OpenProcess.restype = w.HANDLE
                    leaf_api.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]
                    leaf_api.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
                    leaf_api.CloseHandle.argtypes = [w.HANDLE]
                    leaf = leaf_api.OpenProcess(0x101000, False, pid)  # query + synchronization only
                    need(bool(leaf), "DESCENDANT_QUERY_HANDLE")
                    inside = w.BOOL()
                    need(leaf_api.IsProcessInJob(leaf, owner.custody.job.handle, c.byref(inside)) and inside.value,
                         "DESCENDANT_EXACT_JOB_FAILED")
                    need(leaf_api.WaitForSingleObject(leaf, 0) == 258, "DESCENDANT_NOT_ALIVE")
                    need(time.monotonic()-started < 15, "STOP_TOO_LATE_FOR_30_SECOND_CONTROL")
                    trigger = time.monotonic()
                    mgr.stop("pilot", jid)
                    need(leaf_api.WaitForSingleObject(leaf, 5000) == 0, "DESCENDANT_CLEANUP_FAILED")
                    result["cleanup_latency_ms"] = round((time.monotonic()-trigger)*1000, 3)
                    result["descendant_exact_job"] = True
                    result["natural_expiry_ms"] = 30000
                dump({"case": label, "stage": "WAIT_DURABLE_RETIREMENT"})
                try:
                    until(lambda: jid not in mgr.owners, 12)
                except RuntimeError:
                    observed = mgr.read("pilot", jid, 0)
                    dump({"case": label, "stage": "DURABLE_RETIREMENT_TIMEOUT",
                          "status": observed.get("status"), "returncode": observed.get("returncode")})
                    raise RuntimeError("DURABLE_RETIREMENT_TIMEOUT")
                record = store.get_job(jid, "pilot")
                expected = {"normal": "completed", "tree_stop": "stopped", "owned_fault": "start_failed"}[mode]
                need(record["status"] == expected, "UNEXPECTED_TERMINAL_STATUS")
                diagnostic = record.get("launch_diagnostic", {})
                need(diagnostic.get("durable_terminal_receipt") is True and
                     diagnostic.get("native_quiescence_proven") is True, "TERMINAL_PROOF_MISSING")
                if mode == "normal":
                    evidence = json.loads(witness.read_text())
                    need(evidence["passed"] and evidence["denied_read_error"] == 5 and
                         evidence["denied_write_error"] == 5, "ACCESS_DENIAL_FAILED")
                    result["access_denial"] = evidence
                if mode == "owned_fault":
                    need(not witness.exists(), "FAILED_START_COMMAND_EXECUTED")
                    result["injected_owned_transition_fault"] = store.observed
                need(store.verify(), "AUDIT_CHAIN_FAILED")
                before = store.db.execute("SELECT count(*) FROM audit").fetchone()[0]
                mgr.close()
                mgr = None
                store.close()
                store = None
                # Same disposable state, fresh SQLite/lease/manager, no attestor installed.
                store = Store(state)
                mgr = JobManager(policy, store)
                need(store.get_job(jid, "pilot")["status"] == expected, "REOPEN_TERMINAL_DRIFT")
                need(not mgr.owners and not mgr.startup_unresolved, "REOPEN_OWNERSHIP_UNRESOLVED")
                need(store.db.execute("SELECT count(*) FROM audit").fetchone()[0] == before,
                     "REOPEN_DUPLICATED_AUDIT")
                need(store.verify(), "REOPEN_AUDIT_FAILED")
                result.update(passed=True, terminal_status=expected,
                    fresh_store_and_manager_reopen=True, no_replay=True, audit_chain=True)
                return result
            finally:
                if leaf:
                    leaf_api.CloseHandle(leaf)
                if mgr is not None:
                    mgr.close()  # failure remains a failed pilot; never discard unresolved ownership
                if store is not None:
                    store.close()

        results = {}
        for label, mode in (("N02_descendant_stop_durable_reopen", "tree_stop"),
                            ("N03_owned_commit_failure_before_release", "owned_fault")):
            result = manager_case(label, mode)
            results[label] = result
            dump({"case": label, "evidence": result})

        custody = Custody()
        job = WindowsJob({"max_processes": 2, "memory_bytes": 256*1024**2}, custody=custody)
        marker = output / "must-not-execute.json"
        callback = {"entered": False}
        def reject_before_release(*_):
            callback["entered"] = True
            raise RuntimeError("intentional fixture pre-resume rejection")
        try:
            env = {name: os.environ[name] for name in ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "LOCALAPPDATA")
                   if name in os.environ}
            env.update(PATH=str(runtime)+";"+str(Path(os.environ["SYSTEMROOT"])/"System32"),
                       TEMP=str(output), TMP=str(output))
            try:
                appcontainer.spawn(app_args(marker), subject, env, profile, job,
                                   pre_resume_check=reject_before_release, custody=custody)
                raise RuntimeError("INJECTED_PRE_RELEASE_FAILURE_NOT_OBSERVED")
            except RuntimeError as error:
                need(str(error) == "intentional fixture pre-resume rejection", "UNEXPECTED_SPAWN_ERROR")
            need(callback["entered"] and custody.created() and custody.assigned, "REAL_CUSTODY_NOT_RETAINED")
            need(custody.api.wait(custody.process._handle, 0) == 258, "SUSPENDED_PROCESS_NOT_LIVE")
            need(not marker.exists(), "REJECTED_COMMAND_EXECUTED")
            need(custody.stop_and_prove(), "CUSTODY_TERMINATION_NOT_PROVEN")
            custody.close_verified()
            need(custody.closed and job.handle is None and not marker.exists(), "CHECKED_CLOSE_FAILED")
            results["N04_pre_release_failure_retained_cleanup"] = {
                "passed": True, "real_suspended_process": True, "command_not_executed": True,
                "native_process_exit_and_job_zero_proven": True, "checked_handles_closed": True}
            dump({"case": "N04_pre_release_failure_retained_cleanup",
                  "evidence": results["N04_pre_release_failure_retained_cleanup"]})
        finally:
            if not custody.closed:
                need(custody.stop_and_prove(), "FINAL_CUSTODY_CLEANUP_UNRESOLVED")
                custody.close_verified()
        return results
    finally:
        if sid:
            need(not a.FreeSid(sid), "FREE_PROFILE_SID")
        if profile_created:
            need(u.DeleteAppContainerProfile(profile) == 0, "PROFILE_DELETE_FAILED")
            dump({"profile_cleanup": "PASS"})

if __name__ == "__main__":
    try:
        evidence = run(Path(sys.argv[1]))
        dump({"schema": "localcontrol-bounded-ownership-pilot/v1", "result": "PASS_BOUNDED_PILOT_ONLY",
              "candidate_commit": "e071dd2d099577e3ded081f1ffefd7c2bf22e3a8",
              "case_count": len(evidence), "production_activation_authorized": False,
              "full_release_qualification": False})
    except BaseException as error:
        # Do not print arbitrary exception contents, configuration or environment values.
        dump({"schema": "localcontrol-bounded-ownership-pilot/v1", "result": "FAIL_OR_BLOCKED",
              "error_type": type(error).__name__,
              "reason": str(error) if isinstance(error, RuntimeError) and
                 re.fullmatch(r"[A-Z0-9_]+", str(error)) else "BOUNDED_PILOT_EXCEPTION"})
        sys.exit(1)


