"""Disposable runner only: delegated native seams and real SQLite crash atomicity.
No source edits, fake native results, recovery attestor, PID termination or policy changes.
"""
from contextlib import contextmanager
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
import ownership_pilot as fixture
import restart_pilot as prior
from localcontrol import appcontainer as app
from localcontrol.errors import ControlError
from localcontrol.job_ownership import Custody
from localcontrol.jobs import JobManager
from localcontrol.store import Store
from localcontrol.windows_job import WindowsJob

need, dump, atomic = fixture.need, fixture.dump, prior.atomic
ROOT_PATTERN = r"C:\\LocalControlCrashMatrix-[a-f0-9]{32}"
CASES = ("C01_create_intent", "C02_created_before_publication",
         "C03_release_intent", "C04_resumed_before_started",
         "C05_terminal_before_process_close", "C06_terminal_before_job_close",
         "C07_terminal_before_port_close", "C08_resumed_before_thread_close",
         "C09_resumed_before_token_close", "T01_audit_before_row", "T02_row_before_commit")
CONTEXT = {"case": "NONE", "stage": "INITIALIZE"}
TERMINAL_CASES = frozenset(CASES[4:7])
TRANSACTION_CASES = frozenset(CASES[-2:])
LIVE_WORKER_CASES = frozenset(CASES[1:4] + CASES[7:9])

def validate(root, label):
    need(os.name == "nt" and c.sizeof(c.c_void_p) == 8, "WINDOWS_X64_REQUIRED")
    need(re.fullmatch(ROOT_PATTERN, str(root)) is not None and label in CASES,
         "FIXED_ROOT_AND_CASE_REQUIRED")
    no_links = prior.no_links
    no_links(root)
    no_links(root / label)
    return root / label

def hvalue(handle):
    return handle if isinstance(handle, int) else int(getattr(handle, "value", 0) or 0)

def visible_receipt(path, jid):
    """Fresh read-only observer; never acquire the owner's Store lease or write SQL."""
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)
    try:
        need(connection.execute("PRAGMA quick_check").fetchone()[0] == "ok", "SQLITE_QUICK_CHECK_FAILED")
        row = connection.execute("SELECT record FROM jobs WHERE id=? AND scope='pilot'", (jid,)).fetchone()
        need(row is not None, "DURABLE_JOB_ROW_MISSING")
        record = json.loads(row[0])
        audit_rows = connection.execute("SELECT seq,payload,prev,hash FROM audit ORDER BY seq").fetchall()
        payloads = [json.loads(row[1]) for row in audit_rows]
        return {"row_sha256": hashlib.sha256(row[0].encode()).hexdigest(),
                "audit_rows_sha256": hashlib.sha256(json.dumps(
                    audit_rows, separators=(",", ":")).encode()).hexdigest(),
                "phase": record["_ownership"]["phase"], "status": record["status"],
                "audit_count": len(payloads),
                "finished_count": sum(x.get("kind") == "job_finished" and
                    x.get("metadata", {}).get("job_id") == jid for x in payloads),
                "terminal_marker": "terminal" in record["_ownership"]["events"]}
    finally:
        connection.close()

class CheckpointStore(Store):
    manager = None
    target = None
    checkpoint = None
    fired = False
    terminal_inflight = False
    terminal_jid = None
    native_release_returned = False
    native_resume_returned = False
    durable_before_terminal = None

    def checkpoint_now(self, jid, seam):
        if self.fired:
            return
        self.fired = True
        CONTEXT.update(stage="PAUSE_" + seam.upper())
        owner = self.manager.owners[jid]
        custody = owner.custody
        process, job = custody.process, custody.job
        raw = json.loads(self.db.execute("SELECT record FROM jobs WHERE id=?", (jid,)).fetchone()[0])
        cp = {"case": self.target, "seam": seam, "job_id": jid,
              "process_created": custody.created(), "command_released": custody.command_released,
              "native_release_returned": self.native_release_returned,
              "native_resume_returned": self.native_resume_returned,
              "terminal_committed": owner.terminal_committed,
              "quiescence_frozen": custody.quiescence_frozen,
              "in_transaction": self.db.in_transaction, "private_row_phase": raw["_ownership"]["phase"],
              "worker_pid": process.pid if process is not None else None,
              "worker_created_100ns": process.creation_time_100ns if process is not None else None,
              "worker_handle_open": bool(process is not None and process._handle),
              "worker_thread_open": bool(process is not None and process._thread),
              "worker_token_open": bool(process is not None and process._token),
              "job_handle_in_owner": hvalue(job.handle) if job is not None and job.handle else None,
              "port_handle_open": bool(job is not None and job._completion_port),
              "durable_before_terminal": self.durable_before_terminal}
        cp["private_finished_count"] = sum(
            value.get("kind") == "job_finished" and
            value.get("metadata", {}).get("job_id") == jid
            for value in (json.loads(row[0]) for row in self.db.execute("SELECT payload FROM audit")))
        if self.target in TERMINAL_CASES or self.target in TRANSACTION_CASES:
            need(custody.quiescence_frozen and custody.termination_confirmed,
                 "TERMINAL_CHECKPOINT_WITHOUT_NATIVE_QUIESCENCE")
            final = owner.live.accounting_final
            need(final.get("accounting_available") is True and final.get("active_processes") == 0,
                 "FROZEN_NATIVE_ZERO_REQUIRED")
            cp["frozen_native_zero"] = True
            if job.handle:
                stats = job.stats()
                need(stats.get("accounting_available") is True and stats.get("active_processes") == 0,
                     "CHECKPOINT_REAL_JOB_NOT_ZERO")
            need(owner.terminal_committed is (self.target in TERMINAL_CASES),
                 "TERMINAL_COMMIT_FLAG_MISMATCH")
        else:
            need(not owner.terminal_committed and not self.db.in_transaction,
                 "LAUNCH_CHECKPOINT_STATE_MISMATCH")
            if self.target == "C01_create_intent":
                need(not custody.created() and process is None, "CREATE_INTENT_ALREADY_CREATED")
            else:
                need(process is not None and process._handle and
                     custody.api.wait(process._handle, 0) == 258 and custody.assigned,
                     "CHECKPOINT_WORKER_NOT_LIVE")
                prior.verify_token(custody.api, process._handle, process._sid) if process._sid else None
                need(self.native_release_returned is (self.target == "C04_resumed_before_started"),
                     "NATIVE_RELEASE_CHECKPOINT_MISMATCH")
                need(self.native_resume_returned is (self.target in {
                    "C04_resumed_before_started", "C08_resumed_before_thread_close",
                    "C09_resumed_before_token_close"}), "NATIVE_RESUME_CHECKPOINT_MISMATCH")
        atomic(self.checkpoint, cp)
        time.sleep(20)  # coordinator must crash the exact retained owner before 12 seconds
        raise RuntimeError("CRASH_INJECTION_DEADLINE_MISSED")

    def arm_checked_close(self, jid):
        owner = self.manager.owners[jid]
        custody = owner.custody
        job = custody.job
        # Delegating observers are local to this synthetic owner. No success or failure is faked.
        real_process_close = custody.api.close
        def process_close(handle):
            if self.target == "C05_terminal_before_process_close" and hvalue(handle) == hvalue(custody.process._handle):
                self.checkpoint_now(jid, "terminal_before_process_close")
            return real_process_close(handle)
        custody.api.close = process_close
        real_job_close = job.k.CloseHandle
        def job_close(handle):
            value = hvalue(handle)
            if self.target == "C06_terminal_before_job_close" and value == hvalue(job.handle):
                need(custody.process._handle is None, "PROCESS_HANDLE_CLOSE_NOT_OBSERVED")
                self.checkpoint_now(jid, "terminal_before_job_close")
            if self.target == "C07_terminal_before_port_close" and value == hvalue(job._completion_port):
                need(custody.process._handle is None and job.handle is None,
                     "EARLIER_HANDLE_CLOSE_NOT_OBSERVED")
                self.checkpoint_now(jid, "terminal_before_port_close")
            return real_job_close(handle)
        job.k.CloseHandle = job_close

    def commit_job_transition(self, jid, scope, phase, revision, record, kind, metadata):
        if phase == "terminal" and self.target in (TERMINAL_CASES | TRANSACTION_CASES):
            self.terminal_jid = jid
            self.durable_before_terminal = visible_receipt(self.root / "receipts.sqlite", jid)
            self.terminal_inflight = True
        try:
            result = super().commit_job_transition(jid, scope, phase, revision, record, kind, metadata)
            if (self.target, phase) in {("C01_create_intent", "create_intent"),
                                      ("C03_release_intent", "release_intent")}:
                self.checkpoint_now(jid, phase)
            if phase == "terminal" and self.target in TERMINAL_CASES:
                self.arm_checked_close(jid)
            return result
        finally:
            self.terminal_inflight = False

    def _audit(self, kind, metadata, *, essential=False):
        result = super()._audit(kind, metadata, essential=essential)
        if self.target == "T01_audit_before_row" and self.terminal_inflight:
            need(kind == "job_finished" and metadata["job_id"] == self.terminal_jid,
                 "WRONG_TRANSACTION_AUDIT_BOUNDARY")
            need(self.db.in_transaction, "AUDIT_NOT_IN_REAL_TRANSACTION")
            self.checkpoint_now(self.terminal_jid, "audit_inserted_before_job_row")
        return result

    @contextmanager
    def transaction(self):
        with super().transaction():
            yield
            if self.target == "T02_row_before_commit" and self.terminal_inflight:
                need(self.db.in_transaction, "JOB_ROW_NOT_IN_REAL_TRANSACTION")
                self.checkpoint_now(self.terminal_jid, "job_row_written_before_commit")

def owner_main(root, label):
    CONTEXT.update(case=label, stage="OWNER_INITIALIZE")
    case = validate(root, label)
    store = CheckpointStore(case / "controller" / "state")
    manager = None
    real_spawn = app.spawn
    real_release = app.AppProcess.release
    try:
        policy = prior.policy_for(case)
        store.target, store.checkpoint = label, case / "controller" / "checkpoint.json"
        manager = JobManager(policy, store)
        store.manager = manager
        pressure = manager.pressure.snapshot()
        need(pressure.free_memory_bytes is not None and not pressure.pressured,
             "RUNNER_ADMISSION_DEFERRED")
        def observed_spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            real_resume = process.api.resume
            def observed_resume(handle):
                result = real_resume(handle)
                if result != 0xffffffff:
                    store.native_resume_returned = True
                return result
            process.api.resume = observed_resume
            if label in {"C08_resumed_before_thread_close", "C09_resumed_before_token_close"}:
                real_close = process.api.close
                def observed_release_close(handle):
                    target = process._thread if label == "C08_resumed_before_thread_close" else process._token
                    if target and hvalue(handle) == hvalue(target):
                        need(store.native_resume_returned, "NATIVE_RESUME_NOT_OBSERVED")
                        matches = [jid for jid, owner in manager.owners.items()
                                   if owner.custody.process is process]
                        need(len(matches) == 1, "RELEASE_CLOSE_CUSTODY_MISMATCH")
                        store.checkpoint_now(matches[0], "resumed_before_" +
                            ("thread_close" if label == "C08_resumed_before_thread_close" else "token_close"))
                    return real_close(handle)
                process.api.close = observed_release_close
            if label == "C02_created_before_publication":
                custody = kwargs["custody"]
                matches = [jid for jid, owner in manager.owners.items() if owner.custody is custody]
                need(len(matches) == 1, "RAW_CUSTODY_BINDING_MISMATCH")
                store.checkpoint_now(matches[0], "native_create_returned_before_publication")
            return process
        def observed_release(process, *args, **kwargs):
            result = real_release(process, *args, **kwargs)
            store.native_release_returned = True
            if label == "C04_resumed_before_started":
                matches = [jid for jid, owner in manager.owners.items()
                           if owner.custody.process is process]
                need(len(matches) == 1, "RELEASE_CUSTODY_BINDING_MISMATCH")
                store.checkpoint_now(matches[0], "native_resume_returned_before_started")
            return result
        app.spawn = observed_spawn
        app.AppProcess.release = observed_release
        terminal = label in (TERMINAL_CASES | TRANSACTION_CASES)
        executable = "LimitedIoProbe.exe" if terminal else "GenericBoundaryProbe.exe"
        argv = policy.command("pilot", [str(case / "fixture" / "runtime" / executable),
                                      "stdio" if terminal else "hold"], None)
        jid = manager.start("pilot", "pilot", argv, 20000,
                            limits={"max_processes": 4, "memory_bytes": 256*1024**2})
        if terminal:
            manager.input("pilot", jid, "LOCALCONTROL_STDIO_V1\n" + "a"*128, eof=True)
            fixture.until(lambda: store.fired, 9)
            time.sleep(20)
        raise RuntimeError("TARGET_CHECKPOINT_NOT_REACHED")
    finally:
        if manager is not None:
            manager.close()
        app.spawn, app.AppProcess.release = real_spawn, real_release
        store.close()

def minimal_environment():
    return prior.minimal_environment()

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


def recovery_checks(case, label, jid, durable):
    completed = label in TERMINAL_CASES
    expected = "completed" if completed else "ownership_unresolved"
    first_count = None
    for reopen in (1, 2):
        store = Store(case / "controller" / "state")
        manager = None
        try:
            manager = JobManager(prior.policy_for(case), store)
            need(manager.restart_verifier is None, "ATTESTOR_MUST_REMAIN_ABSENT")
            record = store.get_job(jid, "pilot")
            need(record["status"] == expected and manager.storage_fenced is (not completed),
                 "RESTART_STATUS_OR_FENCE_MISMATCH")
            need((jid in manager.startup_unresolved) is (not completed) and not manager.owners,
                 "RESTART_OWNERSHIP_MISMATCH")
            need(store.verify(), "REOPEN_AUDIT_FAILED")
            current = visible_receipt(case / "controller" / "state" / "receipts.sqlite", jid)
            payloads = [json.loads(x[0]) for x in store.db.execute("SELECT payload FROM audit")]
            recovered = sum(x.get("kind") == "job_recovered" and
                            x.get("metadata", {}).get("job_id") == jid for x in payloads)
            need(recovered == (0 if completed else 1), "RECOVERY_AUDIT_COUNT_MISMATCH")
            need(current["finished_count"] == (1 if completed else 0),
                 "HALF_TERMINAL_AUDIT_SURVIVED")
            need(current["audit_count"] == durable["audit_count"] + (0 if completed else 1),
                 "UNEXPECTED_RECOVERY_AUDIT_WRITE")
            if completed:
                need(current == durable, "DURABLE_TERMINAL_ROW_OR_AUDIT_CHANGED")
            else:
                need(not manager.reserve_task_attempt("must-not-admit"), "ADMISSION_NOT_FENCED")
                try:
                    manager.reconcile_startup("pilot", jid, evidence={"authorized": True, "quiescent": True})
                    raise RuntimeError("UNATTESTED_CLAIM_ACCEPTED")
                except ControlError as error:
                    need(error.code == "OWNERSHIP_PENDING", "UNATTESTED_CLAIM_WRONG_ERROR")
            count = store.db.execute("SELECT count(*) FROM audit").fetchone()[0]
            if first_count is None:
                first_count = count
            else:
                need(first_count == count, "REPEATED_REOPEN_CHANGED_AUDIT")
        finally:
            if manager is not None:
                manager.close()
            store.close()
    return {"expected_status": expected, "admission_fenced": not completed,
            "default_attestor_absent": True, "unattested_claim_rejected": not completed,
            "fresh_reopens": 2, "recovery_event_count": 0 if completed else 1,
            "terminal_event_count": 1 if completed else 0, "audit_chain": True,
            "repeated_restart_idempotent": True, "terminal_receipt_unchanged": completed}

def one_case(root, label, baseline):
    CONTEXT.update(case=label, stage="FIXTURE_SETUP")
    case = validate(root, label)
    case.mkdir(exist_ok=False)
    for relative in ("fixture", "fixture/subject", "fixture/out", "fixture/runtime", "controller"):
        (case / relative).mkdir(exist_ok=False)
    for name in ("GenericBoundaryProbe.exe", "LimitedIoProbe.exe"):
        (case / "fixture" / "runtime" / name).write_bytes((root / name).read_bytes())
    api = app.WinAPI()
    profile = "LocalControl.CrashMatrix." + uuid.uuid4().hex
    sid = c.c_void_p()
    custody = Custody()
    borrowed = w.HANDLE()
    held_worker = None
    created = False
    try:
        need(api.create_profile(profile, profile, "Disposable crash matrix", None, 0,
                                c.byref(sid)) == 0, "PROFILE_CREATE")
        created = True
        text = w.LPWSTR()
        api.a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
        api.a.ConvertSidToStringSidW.restype = w.BOOL
        api.k.LocalFree.argtypes = [c.c_void_p]
        need(api.a.ConvertSidToStringSidW(sid, c.byref(text)), "PROFILE_SID_TEXT")
        try:
            sid_text = text.value
        finally:
            api.k.LocalFree(c.cast(text, c.c_void_p))
        fixture.acl(root, "/grant", "*" + sid_text + ":(RX)")
        fixture.acl(case, "/grant", "*" + sid_text + ":(RX)")
        fixture.acl(case / "fixture", "/grant", "*" + sid_text + ":(OI)(CI)(RX)")
        fixture.acl(case / "fixture" / "out", "/grant", "*" + sid_text + ":(OI)(CI)(M)")
        manifest = {"workspace": str(case / "fixture" / "subject"), "network_capabilities": [],
                    "profile_name": profile, "runtime": str(case / "fixture" / "runtime"),
                    "temp": str(case / "fixture" / "out"), "home": str(case / "fixture" / "subject")}
        (case / "controller" / "worker.json").write_text(json.dumps(manifest))
        outer = WindowsJob({"max_processes": 6, "memory_bytes": 512*1024**2}, custody=custody)
        clock = time.monotonic()
        owner_api, pi = host_owner(root, label, custody)
        cp = prior.wait_checkpoint(case / "controller" / "checkpoint.json", owner_api, pi.hProcess,
                                   case / "controller" / "owner_error.json")
        need(cp["case"] == label, "CHECKPOINT_CASE_MISMATCH")
        expected_phase = ("create_intent" if label in CASES[:2] else
                          "release_intent" if label in (frozenset(CASES[2:4]) | frozenset(CASES[7:9])) else
                          "terminal" if label in TERMINAL_CASES else "started")
        path = case / "controller" / "state" / "receipts.sqlite"
        durable = visible_receipt(path, cp["job_id"])
        need(durable["phase"] == expected_phase and
             durable["terminal_marker"] is (label in TERMINAL_CASES),
             "DURABLE_PHASE_MISMATCH")
        if label in TRANSACTION_CASES:
            need(cp["in_transaction"] is True and cp["frozen_native_zero"] is True and
                 durable == cp["durable_before_terminal"], "UNCOMMITTED_STATE_BECAME_VISIBLE")
            private_phase = "started" if label == "T01_audit_before_row" else "terminal"
            need(cp["private_row_phase"] == private_phase and durable["finished_count"] == 0 and
                 cp["private_finished_count"] == 1,
                 "TRANSACTION_BOUNDARY_MISMATCH")
        elif label in TERMINAL_CASES:
            need(not cp["in_transaction"] and cp["terminal_committed"] and
                 durable["status"] == "completed" and durable["finished_count"] == 1,
                 "TERMINAL_COMMIT_NOT_DURABLE")
        else:
            need(not cp["in_transaction"] and not cp["terminal_committed"],
                 "LAUNCH_CHECKPOINT_INVALID")
        stats = outer.stats()
        inventory = prior.owned_job_inventory(owner_api, outer, pi.dwProcessId, baseline)
        # Every non-worker member must be the exact verified system console helper.
        need(all(x.get("owner_image_verified") is True or
                 x.get("system_console_verified") is True or
                 (cp["worker_pid"] is not None and x.get("image") == "genericboundaryprobe.exe")
                 for x in inventory["members"]), "UNEXPLAINED_OWNED_MEMBER")
        if label == "C01_create_intent":
            need(not cp["process_created"] and cp["worker_pid"] is None,
                 "PRECREATE_WORKER_EXISTS")
            prior.precreate_baseline(stats, inventory)
        elif label in LIVE_WORKER_CASES:
            need(sum(x.get("owner_image_verified") is True for x in inventory["members"]) == 1 and
                 sum(x.get("image") == "genericboundaryprobe.exe" for x in inventory["members"]) == 1 and
                 inventory["assigned"] == inventory["listed"] and inventory["listed"] in (2, 3, 4) and
                 stats.get("accounting_available") is True and
                 stats.get("active_processes") == inventory["listed"] and
                 stats.get("total_processes") == inventory["listed"] and
                 not stats.get("job_tree_limit_events"), "LIVE_MEMBER_BASELINE_MISMATCH")
            owner_api.k.GetCurrentProcess.restype = w.HANDLE
            owner_api.k.DuplicateHandle.argtypes = [
                w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]
            owner_api.k.DuplicateHandle.restype = w.BOOL
            owner_api.check(owner_api.k.DuplicateHandle(pi.hProcess, cp["job_handle_in_owner"],
                owner_api.k.GetCurrentProcess(), c.byref(borrowed), 4, False, 0))
            owner_api.k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
            owner_api.k.OpenProcess.restype = w.HANDLE
            held_worker = owner_api.k.OpenProcess(0x101000, False, cp["worker_pid"])
            need(bool(held_worker) and owner_api.wait(held_worker, 0) == 258, "WORKER_QUERY_WITNESS_FAILED")
            for job_handle in (borrowed, outer.handle):
                inside = w.BOOL()
                owner_api.check(owner_api.is_in_job(held_worker, job_handle, c.byref(inside)))
                need(inside.value, "EXACT_JOB_MEMBERSHIP_FAILED")
            prior.verify_token(owner_api, held_worker, sid)
            image_length = w.DWORD(32768)
            image_path = c.create_unicode_buffer(image_length.value)
            owner_api.check(owner_api.k.QueryFullProcessImageNameW(
                held_worker, 0, image_path, c.byref(image_length)))
            need(os.path.normcase(image_path.value) == os.path.normcase(
                str(case / "fixture" / "runtime" / "GenericBoundaryProbe.exe")),
                "WORKER_IMAGE_PATH_MISMATCH")
            need(prior.creation_time(owner_api, held_worker) == cp["worker_created_100ns"],
                 "WORKER_IDENTITY_MISMATCH")
            need(cp["native_release_returned"] is (label == "C04_resumed_before_started"),
                 "RELEASE_OBSERVER_MISMATCH")
            need(cp["native_resume_returned"] is (label in {
                "C04_resumed_before_started", "C08_resumed_before_thread_close",
                "C09_resumed_before_token_close"}), "RESUME_OBSERVER_MISMATCH")
            if label == "C08_resumed_before_thread_close":
                need(cp["worker_thread_open"] and cp["worker_token_open"], "THREAD_CLOSE_POSITION_MISMATCH")
            if label == "C09_resumed_before_token_close":
                need(not cp["worker_thread_open"] and cp["worker_token_open"], "TOKEN_CLOSE_POSITION_MISMATCH")
            owner_api.check(owner_api.close(borrowed))
            borrowed = w.HANDLE()
        else:
            need(cp["frozen_native_zero"] is True, "TERMINAL_ZERO_NOT_FROZEN")
            # Lifetime counts include the already exited worker and its optional console host.
            need(sum(x.get("owner_image_verified") is True for x in inventory["members"]) == 1 and
                 all(x.get("owner_image_verified") is True or x.get("system_console_verified") is True
                     for x in inventory["members"]) and
                 inventory["assigned"] == inventory["listed"] and inventory["listed"] in (1, 2) and
                 stats.get("accounting_available") is True and
                 stats.get("active_processes") == inventory["listed"] and
                 stats.get("total_processes") in (2, 3, 4) and
                 stats["total_processes"] > inventory["listed"] and
                 not stats.get("job_tree_limit_events"), "QUIESCENT_CONTROLLER_BASELINE_MISMATCH")
            if label == "C05_terminal_before_process_close":
                need(cp["worker_handle_open"] and cp["job_handle_in_owner"] and cp["port_handle_open"],
                     "PROCESS_CLOSE_POSITION_MISMATCH")
            if label == "C06_terminal_before_job_close":
                need(not cp["worker_handle_open"] and cp["job_handle_in_owner"] and cp["port_handle_open"],
                     "JOB_CLOSE_POSITION_MISMATCH")
            if label == "C07_terminal_before_port_close":
                need(not cp["worker_handle_open"] and cp["job_handle_in_owner"] is None and cp["port_handle_open"],
                     "PORT_CLOSE_POSITION_MISMATCH")
        need(time.monotonic()-clock < 12, "CRASH_TRIGGER_TOO_LATE")
        dump({"case": label, "stage": "PRECRASH_CHECKPOINT_VERIFIED",
              "seam": cp["seam"], "durable_phase": durable["phase"],
              "private_row_phase": cp["private_row_phase"], "in_transaction": cp["in_transaction"],
              "private_finished_count": cp["private_finished_count"],
              "terminal_committed": cp["terminal_committed"], "quiescence_frozen": cp["quiescence_frozen"],
              "native_release_returned": cp["native_release_returned"],
              "native_resume_returned": cp["native_resume_returned"],
              "accounting": prior.accounting_diagnostic(stats)})
        owner_api.check(owner_api.terminate(pi.hProcess, 97))  # exact owned coordinator HANDLE only
        need(owner_api.wait(pi.hProcess, 5000) == 0, "OWNER_DEATH_NOT_PROVEN")
        if held_worker:
            need(owner_api.wait(held_worker, 5000) == 0, "WORKER_SURVIVED_OWNER_DEATH")
        need(outer.prove_empty(timeout=2), "OUTER_JOB_NOT_EMPTY")
        after = outer.stats()
        need(after.get("accounting_available") is True and after.get("active_processes") == 0,
             "POSTCRASH_NATIVE_ZERO_REQUIRED")
        # Observe crash rollback BEFORE any fresh manager can append recovery records.
        after_crash = visible_receipt(path, cp["job_id"])
        need(after_crash == durable, "CRASH_CHANGED_DURABLE_ROW_OR_AUDIT")
        recovery = recovery_checks(case, label, cp["job_id"], durable)
        recovery.update(passed=True, seam=cp["seam"], crash_before_12_seconds=True,
                        native_tree_empty_before_outer_cleanup=True,
                        observer_read_only=True, durable_row_and_audit_unchanged_before_recovery=True,
                        transaction_rollback_proven=label in TRANSACTION_CASES,
                        terminal_handle_position_verified=label in TERMINAL_CASES)
        return recovery
    finally:
        if borrowed:
            api.check(api.close(borrowed))
        if custody.job is not None:
            need(custody.stop_and_prove(), "FIXTURE_CLEANUP_UNRESOLVED")
            custody.close_verified()
        if held_worker:
            api.check(api.close(held_worker))
        if sid:
            need(not api.free_sid(sid), "PROFILE_SID_FREE")
        if created:
            need(api.delete_profile(profile) == 0, "PROFILE_DELETE")
            dump({"case": label, "profile_cleanup": "PASS"})

def coordinator(root):
    need(sys.version_info[:3] == (3,12,10), "CACHED_PYTHON_VERSION_MISMATCH")
    need(re.fullmatch(ROOT_PATTERN, str(root)) is not None, "FIXED_ROOT_REQUIRED")
    prior.no_links(root)
    need(not any("TOKEN" in name.upper() or name.upper().startswith("ACTIONS_")
                 for name in os.environ), "CREDENTIAL_ENV_NOT_STRIPPED")
    fixture.token_sid()
    baseline = prior.system_console_baseline(root)
    for label in CASES:
        dump({"case": label, "stage": "BEGIN"})
        dump({"case": label, "evidence": one_case(root, label, baseline)})
    dump({"schema": "localcontrol-bounded-crash-matrix/v1", "result": "PASS_CRASH_MATRIX_ONLY",
          "case_count": len(CASES), "candidate_commit": "e071dd2d099577e3ded081f1ffefd7c2bf22e3a8",
          "attestor_installed": False, "post_creation_fences_auto_cleared": False,
          "full_release_qualification": False, "production_activation_authorized": False})

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "owner":
        root, label = Path(sys.argv[2]), sys.argv[3]
        try:
            owner_main(root, label)
        except BaseException as error:
            case = validate(root, label)
            atomic(case / "controller" / "owner_error.json",
                   dict(prior.safe_error(error), context=dict(CONTEXT)))
            sys.exit(2)
    else:
        try:
            need(len(sys.argv) == 2, "FIXED_COORDINATOR_ARGUMENT_REQUIRED")
            coordinator(Path(sys.argv[1]))
        except BaseException as error:
            dump(dict(prior.safe_error(error), context=dict(CONTEXT),
                      schema="localcontrol-bounded-crash-matrix/v1", result="FAIL_OR_BLOCKED"))
            sys.exit(1)
