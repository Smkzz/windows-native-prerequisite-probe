"""Disposable Windows runner only. Crash checkpoints pause after real durable commits.
No production config, startup attestor, PID termination, server or network listener.
"""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ownership_pilot as fixture
from localcontrol import appcontainer as app
from localcontrol.errors import ControlError
from localcontrol.job_ownership import Custody
from localcontrol.jobs import JobManager
from localcontrol.policy import Policy, Project, no_links
from localcontrol.store import Store
from localcontrol.windows_job import WindowsJob

need = fixture.need
dump = fixture.dump
PHASES = ("starting", "owned", "started")
ROOT_PATTERN = r"C:\\LocalControlCrashRestart-[a-f0-9]{32}"
CONTEXT = {"role": "coordinator", "phase": "NONE", "stage": "INITIALIZE"}

def atomic(path, value):
    temp = path.with_suffix(".tmp")
    with temp.open("x", encoding="utf-8") as out:
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)

def validate(root, phase):
    need(os.name == "nt" and c.sizeof(c.c_void_p) == 8, "WINDOWS_X64_REQUIRED")
    need(re.fullmatch(ROOT_PATTERN, str(root)) is not None and phase in PHASES,
         "FIXED_ROOT_AND_PHASE_REQUIRED")
    no_links(root)
    case = root / phase
    no_links(case)
    return case

def policy_for(case):
    return Policy({"pilot": Project(case / "fixture" / "subject", True)},
        case / "controller" / "state", exec_mode="appcontainer",
        workers={"pilot": {"manifest": str(case / "controller" / "worker.json")}},
        max_active_jobs=1, max_queued_jobs=1, max_timeout_ms=20000,
        max_wait_ms=1000, min_free_memory_bytes=1024**3, min_free_disk_bytes=1024**3)

class PausingStore(Store):
    """Test-only pause after the real Store commits; no native API is mocked."""
    manager = None
    target = None
    checkpoint = None
    witness = None
    fired = False
    def commit_job_transition(self, jid, scope, phase, revision, record, kind, metadata):
        result = super().commit_job_transition(jid, scope, phase, revision, record, kind, metadata)
        if phase == self.target and not self.fired:
            CONTEXT.update(stage="AFTER_TARGET_DURABLE_COMMIT")
            self.fired = True
            owner = self.manager.owners[jid]
            custody = owner.custody
            cp = {"phase": phase, "job_id": jid, "command_released": custody.command_released,
                  "process_created": custody.created(), "worker_pid": None,
                  "worker_created_100ns": None, "job_handle_in_owner": None, "leaf_pid": None}
            if phase == "starting":
                need(not custody.created() and custody.job is None, "PRECREATE_CHECKPOINT_NOT_PRECREATE")
            else:
                need(custody.process is not None and custody.assigned, "NATIVE_CUSTODY_MISSING")
                need(custody.api.wait(custody.process._handle, 0) == 258, "CHECKPOINT_WORKER_NOT_LIVE")
                custody.process.verify_sandbox() if custody.process._token else None
                cp.update(worker_pid=custody.process.pid,
                          worker_created_100ns=custody.process.creation_time_100ns,
                          job_handle_in_owner=int(custody.job.handle))
                if phase == "owned":
                    need(custody.command_released is False and not self.witness.exists(),
                         "OWNED_CHECKPOINT_ALREADY_RELEASED")
                else:
                    need(custody.command_released is True, "STARTED_CHECKPOINT_NOT_RELEASED")
                    fixture.until(self.witness.exists, 6)
                    cp["leaf_pid"] = int(self.witness.read_text())
            atomic(self.checkpoint, cp)
            # Parent must crash this exact owner by handle before the deadline.
            time.sleep(20)
            raise RuntimeError("CRASH_INJECTION_DEADLINE_MISSED")
        return result

def owner_main(root, phase):
    CONTEXT.update(role="owner", phase=phase, stage="OWNER_INITIALIZE")
    case = validate(root, phase)
    store = PausingStore(case / "controller" / "state")
    manager = None
    try:
        policy = policy_for(case)
        manager = JobManager(policy, store)  # real lease, SQLite, scheduler and pressure telemetry
        pressure = manager.pressure.snapshot()
        need(pressure.free_memory_bytes is not None and not pressure.pressured,
             "RUNNER_ADMISSION_DEFERRED")
        store.manager, store.target = manager, phase
        store.checkpoint = case / "controller" / "checkpoint.json"
        store.witness = case / "fixture" / "out" / "descendant.txt"
        exe = case / "fixture" / "runtime" / "GenericBoundaryProbe.exe"
        argv = policy.command("pilot", [str(exe), "tree", str(store.witness)], None)
        CONTEXT.update(stage="OWNER_REAL_ADMISSION_AND_LAUNCH")
        manager.start("pilot", "pilot", argv, 20000,
                      limits={"max_processes": 4, "memory_bytes": 256*1024**2})
        raise RuntimeError("TARGET_CHECKPOINT_NOT_REACHED")
    finally:
        if manager is not None:
            manager.close()
        store.close()

def minimal_environment():
    env = {k: os.environ[k] for k in
           ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "LOCALAPPDATA", "PATH", "TEMP", "TMP", "USERPROFILE")
           if k in os.environ}
    need(env.get("LOCALAPPDATA"), "EXPLICIT_LOCALAPPDATA_REQUIRED")
    return env

def host_owner(root, phase, custody):
    """Fixed coordinator Python only; atomically contained in outer test Job before resume."""
    api = app.WinAPI()
    pi = app.PROCESS_INFORMATION()
    custody.bind_native(api, pi)  # retain mutable native PI before CreateProcess
    attrs = None
    initialized = False
    try:
        size = c.c_size_t()
        api.init(None, 1, 0, c.byref(size))
        need(0 < size.value < 65536, "OWNER_ATTRIBUTE_SIZE")
        attrs = c.create_string_buffer(size.value)
        api.check(api.init(attrs, 1, 0, c.byref(size)))
        initialized = True
        jobs = (w.HANDLE * 1)(int(custody.job.handle))
        api.check(api.update(attrs, 0, 0x2000D, c.byref(jobs), c.sizeof(jobs), None, None))
        start = app.STARTUPINFOEX()
        start.StartupInfo.cb = c.sizeof(start)
        start.lpAttributeList = c.cast(attrs, c.c_void_p)
        argv = [sys.executable, "-I", "-B", "-S", "-X", "utf8", str(Path(__file__).resolve()),
                "owner", str(root), phase]
        command = c.create_unicode_buffer(subprocess.list2cmdline(argv))
        environment = c.create_unicode_buffer(app._environment_block(minimal_environment()))
        CONTEXT.update(stage="OWNER_CREATE_SUSPENDED")
        api.check(api.create(sys.executable, command, None, None, False,
                  0x08000000 | 0x80000 | 0x400 | 4, environment, str(root),
                  c.byref(start), c.byref(pi)))
        CONTEXT.update(stage="OWNER_MEMBERSHIP_AND_RESUME")
        inside = w.BOOL()
        api.check(api.is_in_job(pi.hProcess, custody.job.handle, c.byref(inside)))
        need(inside.value, "OWNER_OUTER_JOB_MEMBERSHIP")
        custody.assigned = True
        need(api.resume(pi.hThread) != 0xffffffff, "OWNER_RESUME_FAILED")
        custody.command_released = True
        api.check(api.close(pi.hThread))
        pi.hThread = None
        return api, pi
    finally:
        if initialized:
            api.delete(attrs)

def wait_checkpoint(path, api, process, error_path):
    end = time.monotonic() + 9
    while time.monotonic() < end:
        if path.exists():
            return json.loads(path.read_text())
        if error_path.exists():
            error = json.loads(error_path.read_text())
            dump({"stage": "OWNER_CHECKPOINT_ERROR", "owner_error": error})
            raise RuntimeError("OWNER_FAILED_BEFORE_CHECKPOINT")
        need(api.wait(process, 0) == 258, "OWNER_EXITED_BEFORE_CHECKPOINT")
        time.sleep(.02)
    raise RuntimeError("CRASH_CHECKPOINT_TIMEOUT")

def creation_time(api, handle):
    created, exited, kernel, user = w.FILETIME(), w.FILETIME(), w.FILETIME(), w.FILETIME()
    api.check(api.get_times(handle, c.byref(created), c.byref(exited), c.byref(kernel), c.byref(user)))
    return (created.dwHighDateTime << 32) | created.dwLowDateTime

def owned_job_inventory(api, job, expected_owner_pid, baseline):
    """Query at most six members of this exact synthetic Job; never enumerate host processes."""
    capacity = 6
    buf = c.create_string_buffer(8 + capacity * c.sizeof(c.c_size_t))
    api.check(job.k.QueryInformationJobObject(job.handle, 3, buf, c.sizeof(buf), None))
    assigned = w.DWORD.from_buffer(buf, 0).value
    count = w.DWORD.from_buffer(buf, 4).value
    need(count <= capacity and assigned <= capacity, "OWNED_JOB_INVENTORY_BOUND")
    api.k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    api.k.OpenProcess.restype = w.HANDLE
    api.k.QueryFullProcessImageNameW.argtypes = [
        w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
    api.k.QueryFullProcessImageNameW.restype = w.BOOL
    records = []
    for index in range(count):
        pid = c.c_size_t.from_buffer(buf, 8 + index*c.sizeof(c.c_size_t)).value
        handle = api.k.OpenProcess(0x1000, False, pid)  # query only
        if not handle:
            records.append({"expected_owner": pid == expected_owner_pid, "query": "UNAVAILABLE"})
            continue
        try:
            inside = w.BOOL()
            api.check(api.is_in_job(handle, job.handle, c.byref(inside)))
            if not inside.value:
                records.append({"expected_owner": pid == expected_owner_pid, "query": "LEFT_OWNED_JOB"})
                continue
            length = w.DWORD(32768)
            image = c.create_unicode_buffer(length.value)
            api.check(api.k.QueryFullProcessImageNameW(handle, 0, image, c.byref(length)))
            name = Path(image.value).name.casefold()
            allowed = {"python.exe", "pythonw.exe", "conhost.exe", "genericboundaryprobe.exe"}
            image_path = Path(image.value)
            expected_owner = pid == expected_owner_pid
            owner_match = expected_owner and os.path.normcase(str(image_path)) == os.path.normcase(sys.executable)
            console_match = (not expected_owner and
                os.path.normcase(str(image_path)) == os.path.normcase(baseline["path"]))
            if console_match:
                no_links(image_path, allow_hardlinks=True)
                need(hashlib.sha256(image_path.read_bytes()).hexdigest() == baseline["sha256"],
                     "SYSTEM_CONSOLE_HASH_DRIFT")
            records.append({"expected_owner": expected_owner,
                            "owner_image_verified": owner_match,
                            "system_console_verified": console_match,
                            "image": name if name in allowed else "OTHER_OWNED_IMAGE"})
        finally:
            api.check(api.close(handle))
    return {"assigned": assigned, "listed": count, "members": records}


def system_console_baseline(root):
    """Consume the fixed workflow's OS signature check; never create a recovery attestor."""
    path = root / "OS_CONHOST_BASELINE.json"
    no_links(path)
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    expected = Path(os.environ["SYSTEMROOT"]) / "System32" / "conhost.exe"
    need(value.get("schema") == "owned-test-system-console/v1" and
         os.path.normcase(value.get("path", "")) == os.path.normcase(str(expected)),
         "SYSTEM_CONSOLE_PATH_MISMATCH")
    need(value.get("signature_status") == "Valid" and value.get("microsoft_signer") is True and
         re.fullmatch(r"[A-Fa-f0-9]{40}", value.get("signer_thumbprint", "")) is not None and
         re.fullmatch(r"[a-f0-9]{64}", value.get("sha256", "")) is not None,
         "SYSTEM_CONSOLE_SIGNATURE_BASELINE_REQUIRED")
    no_links(expected, allow_hardlinks=True)
    need(hashlib.sha256(expected.read_bytes()).hexdigest() == value["sha256"],
         "SYSTEM_CONSOLE_BASELINE_HASH_DRIFT")
    return value

def precreate_baseline(stats, inventory):
    """Permit only the exact owner and at most one previously verified system console."""
    need(stats.get("accounting_available") is True, "PRECREATE_ACCOUNTING_UNAVAILABLE")
    members = inventory["members"]
    count = inventory["listed"]
    need(count in (1, 2) and inventory["assigned"] == count and len(members) == count,
         "PRECREATE_MEMBER_COUNT_MISMATCH")
    need(sum(x.get("expected_owner") is True and x.get("owner_image_verified") is True
             for x in members) == 1, "PRECREATE_OWNER_IDENTITY_MISMATCH")
    need(all(x.get("owner_image_verified") is True if x.get("expected_owner") is True
             else x.get("system_console_verified") is True for x in members),
         "UNEXPLAINED_PRECREATE_MEMBER")
    need(stats.get("active_processes") == count and stats.get("total_processes") == count and
         not stats.get("job_tree_limit_events"), "PRECREATE_ACCOUNTING_BASELINE_MISMATCH")
    return count

def accounting_diagnostic(stats):
    return {key: stats.get(key) for key in (
        "accounting_available", "active_processes", "total_processes",
        "terminated_processes", "job_tree_event_counts", "job_tree_limit_events")}

def verify_token(api, process, expected_sid):
    token = w.HANDLE()
    api.check(api.open_token(process, 8, c.byref(token)))
    try:
        n, flag = w.DWORD(), w.DWORD()
        api.check(api.token_info(token, 29, c.byref(flag), 4, c.byref(n)))
        need(flag.value == 1, "WORKER_NOT_APPCONTAINER")
        for kind in (30, 31):
            size = w.DWORD()
            api.token_info(token, kind, None, 0, c.byref(size))
            buf = c.create_string_buffer(size.value)
            api.check(api.token_info(token, kind, buf, size.value, c.byref(size)))
            if kind == 30:
                need(c.cast(buf, c.POINTER(w.DWORD))[0] == 0, "WORKER_CAPABILITY_EXPANSION")
            else:
                actual = c.cast(buf, c.POINTER(c.c_void_p))[0]
                need(api.equal_sid(actual, expected_sid), "WORKER_SID_MISMATCH")
    finally:
        api.check(api.close(token))

def recovery_checks(case, phase, jid):
    expected = "interrupted" if phase == "starting" else "ownership_unresolved"
    fenced = phase != "starting"
    first_count = None
    witness = case / "fixture" / "out" / "descendant.txt"
    before_witness = (witness.read_bytes(), witness.stat().st_mtime_ns) if witness.exists() else None
    for reopen in (1, 2):
        CONTEXT.update(stage="RESTART_REOPEN_" + str(reopen))
        store = Store(case / "controller" / "state")
        manager = None
        try:
            manager = JobManager(policy_for(case), store)  # default verifier remains None
            need(manager.restart_verifier is None, "RESTART_ATTESTOR_MUST_REMAIN_ABSENT")
            record = store.get_job(jid, "pilot")
            need(record["status"] == expected, "RESTART_STATUS_MISMATCH")
            need(manager.storage_fenced is fenced and not manager.owners, "RESTART_FENCE_MISMATCH")
            need((jid in manager.startup_unresolved) is fenced, "RESTART_UNRESOLVED_BINDING")
            need(store.verify(), "RESTART_AUDIT_CHAIN_FAILED")
            recovered = sum(json.loads(row[0]).get("kind") == "job_recovered"
                            for row in store.db.execute("SELECT payload FROM audit"))
            need(recovered == 1, "RECOVERY_EVENT_NOT_EXACTLY_ONCE")
            count = store.db.execute("SELECT count(*) FROM audit").fetchone()[0]
            if first_count is None:
                first_count = count
            else:
                need(count == first_count, "SECOND_RESTART_DUPLICATED_AUDIT")
            if fenced:
                need(not manager.reserve_task_attempt("must-not-admit"), "RESTART_ADMISSION_NOT_FENCED")
                try:
                    manager.start("pilot", "pilot",
                        [str(case / "fixture" / "runtime" / "GenericBoundaryProbe.exe"), "hold"], 1000)
                    raise RuntimeError("FENCED_START_ADMITTED")
                except ControlError as error:
                    need(error.code == "STORE_FAILURE", "FENCED_START_WRONG_ERROR")
                try:
                    manager.reconcile_startup("pilot", jid,
                        evidence={"quiescent": True, "authorized": True, "job_id": jid})
                    raise RuntimeError("UNATTESTED_CLAIM_ACCEPTED")
                except ControlError as error:
                    need(error.code == "OWNERSHIP_PENDING", "UNATTESTED_CLAIM_WRONG_ERROR")
                try:
                    manager.read("different-scope", jid, 0)
                    raise RuntimeError("CROSS_SCOPE_RECORD_EXPOSED")
                except ControlError as error:
                    need(error.code == "UNKNOWN_JOB", "CROSS_SCOPE_WRONG_ERROR")
            need(store.db.execute("SELECT count(*) FROM audit").fetchone()[0] == count,
                 "REJECTED_OPERATION_CHANGED_AUDIT")
            need(store.get_job(jid, "pilot")["status"] == expected, "REJECTED_CLAIM_CHANGED_STATE")
        finally:
            if manager is not None:
                manager.close()
            store.close()
    after_witness = (witness.read_bytes(), witness.stat().st_mtime_ns) if witness.exists() else None
    need(before_witness == after_witness, "RESTART_CHANGED_EXECUTION_WITNESS")
    return {"expected_status": expected, "admission_fenced": fenced,
            "fresh_process_owner_killed": True, "fresh_manager_store_reopens": 2,
            "recovery_event_exactly_once": True, "repeated_restart_idempotent": True,
            "default_attestor_absent": True, "unattested_claim_rejected": True if fenced else None,
            "cross_scope_read_rejected": True if fenced else None,
            "execution_witness_unchanged": True, "audit_chain": True}

def one_case(root, phase, owner_sid, baseline):
    CONTEXT.update(role="coordinator", phase=phase, stage="PROFILE_AND_FIXTURE_SETUP")
    case = validate(root, phase)
    case.mkdir(exist_ok=False)
    for relative in ("fixture", "fixture/subject", "fixture/out", "fixture/runtime", "controller"):
        (case / relative).mkdir(exist_ok=False)
    exe = case / "fixture" / "runtime" / "GenericBoundaryProbe.exe"
    exe.write_bytes((root / "compiled-helper.exe").read_bytes())
    api = app.WinAPI()
    profile = "LocalControl.Crash." + uuid.uuid4().hex
    sid = c.c_void_p()
    custody = Custody()
    handles = []
    borrowed = w.HANDLE()
    profile_created = False
    try:
        need(api.create_profile(profile, profile, "Disposable crash restart fixture", None, 0,
                                c.byref(sid)) == 0, "CRASH_PROFILE_CREATE")
        profile_created = True
        text = w.LPWSTR()
        api.a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
        api.a.ConvertSidToStringSidW.restype = w.BOOL
        api.k.LocalFree.argtypes = [c.c_void_p]
        need(api.a.ConvertSidToStringSidW(sid, c.byref(text)), "CRASH_PROFILE_SID_TEXT")
        try:
            sid_text = text.value
        finally:
            api.k.LocalFree(c.cast(text, c.c_void_p))
        # Only fresh runner fixture directories receive these ACEs.
        fixture.acl(root, "/grant", "*" + sid_text + ":(RX)")
        fixture.acl(case, "/grant", "*" + sid_text + ":(RX)")
        fixture.acl(case / "fixture", "/grant", "*" + sid_text + ":(OI)(CI)(RX)")
        fixture.acl(case / "fixture" / "out", "/grant", "*" + sid_text + ":(OI)(CI)(M)")
        manifest = {"workspace": str(case / "fixture" / "subject"), "network_capabilities": [],
                    "profile_name": profile, "runtime": str(exe.parent),
                    "temp": str(case / "fixture" / "out"), "home": str(case / "fixture" / "subject")}
        (case / "controller" / "worker.json").write_text(json.dumps(manifest))
        outer = WindowsJob({"max_processes": 6, "memory_bytes": 512*1024**2}, custody=custody)
        clock = time.monotonic()
        owner_api, pi = host_owner(root, phase, custody)
        CONTEXT.update(stage="WAIT_DURABLE_CRASH_CHECKPOINT")
        cp = wait_checkpoint(case / "controller" / "checkpoint.json", owner_api, pi.hProcess,
                             case / "controller" / "owner_error.json")
        need(cp["phase"] == phase, "CHECKPOINT_PHASE_MISMATCH")
        pre_stats = outer.stats()
        inventory = owned_job_inventory(owner_api, outer, pi.dwProcessId, baseline)
        expected_precreate_total = precreate_baseline(pre_stats, inventory) if phase == "starting" else None
        dump({"case": phase, "stage": "PRECRASH_OWNED_JOB_DIAGNOSTIC",
              "checkpoint_process_created": cp["process_created"],
              "checkpoint_command_released": cp["command_released"],
              "accounting": accounting_diagnostic(pre_stats),
              "owned_members": inventory, "verified_precreate_total": expected_precreate_total})
        CONTEXT.update(stage="OBSERVE_EXACT_NATIVE_WORKERS")
        if phase != "starting":
            owner_api.k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
            owner_api.k.OpenProcess.restype = w.HANDLE
            owner_api.k.GetCurrentProcess.restype = w.HANDLE
            owner_api.k.DuplicateHandle.argtypes = [
                w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]
            owner_api.k.DuplicateHandle.restype = w.BOOL
            owner_api.check(owner_api.k.DuplicateHandle(pi.hProcess, cp["job_handle_in_owner"],
                owner_api.k.GetCurrentProcess(), c.byref(borrowed), 4, False, 0))
            for kind, pid in (("worker", cp["worker_pid"]), ("leaf", cp["leaf_pid"])):
                if pid is None:
                    continue
                handle = owner_api.k.OpenProcess(0x101000, False, pid)  # query+wait; never terminate by PID
                need(bool(handle), "OWNED_WORKER_QUERY_HANDLE")
                handles.append(handle)
                need(owner_api.wait(handle, 0) == 258, "WORKER_NOT_LIVE_BEFORE_CRASH")
                inside = w.BOOL()
                owner_api.check(owner_api.is_in_job(handle, borrowed, c.byref(inside)))
                need(inside.value, "EXACT_INNER_JOB_MEMBERSHIP_FAILED")
                owner_api.check(owner_api.is_in_job(handle, outer.handle, c.byref(inside)))
                need(inside.value, "EXACT_OUTER_JOB_MEMBERSHIP_FAILED")
                verify_token(owner_api, handle, sid)
                if kind == "worker":
                    need(creation_time(owner_api, handle) == cp["worker_created_100ns"],
                         "WORKER_CREATION_IDENTITY_MISMATCH")
            need(len(handles) == (1 if phase == "owned" else 2), "EXPECTED_TREE_NOT_OBSERVED")
            # Critical: do not retain an extra inner-job handle across owner death.
            owner_api.check(owner_api.close(borrowed))
            borrowed = w.HANDLE()
        else:
            need(not cp["process_created"] and cp["worker_pid"] is None, "PRECREATE_WORKER_EXISTS")
        witness = case / "fixture" / "out" / "descendant.txt"
        if phase != "started":
            need(not witness.exists(), "SUSPENDED_OR_PRECREATE_COMMAND_EXECUTED")
        need(time.monotonic() - clock < 12, "CRASH_TRIGGER_TOO_LATE")
        trigger = time.monotonic()
        CONTEXT.update(stage="FORCE_OWNED_COORDINATOR_CRASH")
        owner_api.check(owner_api.terminate(pi.hProcess, 97))  # only retained owned coordinator handle
        CONTEXT.update(stage="PROVE_NATIVE_TREE_EXIT_BEFORE_OUTER_CLEANUP")
        need(owner_api.wait(pi.hProcess, 5000) == 0, "OWNER_DEATH_NOT_PROVEN")
        for handle in handles:
            need(owner_api.wait(handle, 5000) == 0, "OWNED_TREE_SURVIVED_OWNER_DEATH")
        # No outer TerminateJobObject has been called before these witnesses.
        tree_empty = outer.prove_empty(timeout=2)
        stats = outer.stats()
        dump({"case": phase, "stage": "POSTCRASH_OWNED_JOB_DIAGNOSTIC",
              "native_tree_empty": tree_empty, "accounting": accounting_diagnostic(stats)})
        need(tree_empty, "OUTER_TREE_NOT_EMPTY_AFTER_OWNER_DEATH")
        need(stats.get("accounting_available") is True, "POSTCRASH_ACCOUNTING_UNAVAILABLE")
        if phase == "starting":
            need(stats["total_processes"] == expected_precreate_total and stats["active_processes"] == 0,
                 "PRECREATE_LIFETIME_BASELINE_CHANGED")
        cleanup_ms = round((time.monotonic() - trigger)*1000, 3)
        result = recovery_checks(case, phase, cp["job_id"])
        result.update(passed=True, durable_crash_phase=phase, owner_forcibly_terminated_by_handle=True,
                      observed_native_worker_count=len(handles), exact_job_and_token_witnesses=True,
                      borrowed_inner_job_handle_closed_before_crash=True,
                      native_tree_exit_before_outer_cleanup=True, crash_cleanup_ms=cleanup_ms,
                      natural_worker_expiry_ms=30000, crash_trigger_before_12_seconds=True)
        return result
    finally:
        if borrowed:
            api.check(api.close(borrowed))
        # This fallback acts only on this exact owned outer test Job, after evidence checks.
        if custody.job is not None:
            need(custody.stop_and_prove(), "OWNED_CRASH_FIXTURE_CLEANUP_UNRESOLVED")
            custody.close_verified()
        for handle in handles:
            api.check(api.close(handle))
        if sid:
            need(not api.free_sid(sid), "CRASH_PROFILE_SID_FREE")
        if profile_created:
            need(api.delete_profile(profile) == 0, "CRASH_PROFILE_DELETE")
            dump({"case": phase, "profile_cleanup": "PASS"})

def coordinator(root):
    need(os.name == "nt" and c.sizeof(c.c_void_p) == 8, "WINDOWS_X64_REQUIRED")
    need(sys.version_info[:3] == (3, 12, 10), "CACHED_PYTHON_VERSION_MISMATCH")
    dump({"python_version": sys.version.split()[0], "python_x64": True})
    need(re.fullmatch(ROOT_PATTERN, str(root)) is not None, "FIXED_ROOT_REQUIRED")
    no_links(root)
    need(not any("TOKEN" in k.upper() or k.upper().startswith("ACTIONS_") for k in os.environ),
         "COORDINATOR_CREDENTIAL_ENV_NOT_STRIPPED")
    owner_sid = fixture.token_sid()
    baseline = system_console_baseline(root)
    results = {}
    for phase in PHASES:
        dump({"case": phase, "stage": "BEGIN_OWNED_CRASH_CASE"})
        results[phase] = one_case(root, phase, owner_sid, baseline)
        dump({"case": phase, "evidence": results[phase]})
    dump({"schema": "localcontrol-bounded-crash-restart/v1", "result": "PASS_CRASH_RESTART_BOUNDARIES_ONLY",
          "case_count": len(results), "candidate_commit": "e071dd2d099577e3ded081f1ffefd7c2bf22e3a8",
          "post_creation_fences_auto_cleared": False, "attestor_installed": False,
          "full_release_qualification": False, "production_activation_authorized": False})

def safe_error(error):
    text = str(error)
    result = {"error_type": type(error).__name__, "context": dict(CONTEXT),
              "reason": text if isinstance(error, RuntimeError) and re.fullmatch(r"[A-Z0-9_]+", text)
                        else "BOUNDED_CRASH_RESTART_EXCEPTION"}
    number = getattr(error, "winerror", None) if isinstance(error, OSError) else None
    if type(number) is int and 0 <= number <= 0xffffffff:
        result["win32_error"] = number
    if isinstance(error, ControlError) and re.fullmatch(r"[A-Z0-9_]{1,100}", error.code):
        result["control_error_code"] = error.code
    return result

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "owner":
        root, phase = Path(sys.argv[2]), sys.argv[3]
        try:
            owner_main(root, phase)
        except BaseException as error:
            # Path validated first; no arbitrary exception/argv/environment output.
            case = validate(root, phase)
            atomic(case / "controller" / "owner_error.json", safe_error(error))
            sys.exit(2)
    else:
        try:
            need(len(sys.argv) == 2, "FIXED_COORDINATOR_ARGUMENT_REQUIRED")
            coordinator(Path(sys.argv[1]))
        except BaseException as error:
            dump(dict(safe_error(error), schema="localcontrol-bounded-crash-restart/v1",
                      result="FAIL_OR_BLOCKED"))
            sys.exit(1)
