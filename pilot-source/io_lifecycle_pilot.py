"""Disposable Windows runner: actual candidate stdio and early-root lifecycle only."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ownership_pilot as fixture
import restart_pilot as restart
from localcontrol import appcontainer as app
from localcontrol.jobs import JobManager
from localcontrol.policy import Policy, Project, no_links
from localcontrol.store import Store

need = fixture.need
dump = fixture.dump
ROOT_PATTERN = r"C:\\LocalControlIoLifecycle-[a-f0-9]{32}"
CONTEXT = {"case": "NONE", "stage": "INITIALIZE"}

def terminal_checks(manager, store, jid, owner, process, job):
    fixture.until(lambda: jid not in manager.owners, 12)
    record = store.get_job(jid, "pilot")
    need(record["status"] == "completed" and record["returncode"] == 0,
         "TERMINAL_STATUS_OR_EXIT_MISMATCH")
    proof = record.get("launch_diagnostic", {})
    need(proof.get("durable_terminal_receipt") is True and
         proof.get("native_quiescence_proven") is True, "TERMINAL_PROOF_MISSING")
    state = record.get("resource_limit_state", {})
    need(state.get("accounting_available") is True and state.get("active_processes") == 0,
         "NATIVE_ZERO_ACCOUNTING_REQUIRED")
    need(not state.get("job_tree_limit_events"), "UNEXPECTED_JOB_LIMIT_EVENT")
    need(owner.custody.closed and job.handle is None and
         all(stream.closed for stream in (process.stdin, process.stdout, process.stderr)) and
         all(getattr(process, name) is None for name in ("_handle", "_thread", "_token", "_sid")),
         "OWNED_STREAM_OR_HANDLE_NOT_CLOSED")
    need(store.verify(), "AUDIT_CHAIN_FAILED")
    return record

def native_witness(process, job, sid):
    # Keep a query+synchronize duplicate: never retain an extra Job handle.
    api = app.WinAPI()
    api.k.GetCurrentProcess.restype = w.HANDLE
    api.k.DuplicateHandle.argtypes = [
        w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]
    api.k.DuplicateHandle.restype = w.BOOL
    held = w.HANDLE()
    current = api.k.GetCurrentProcess()
    api.check(api.k.DuplicateHandle(current, process._handle, current, c.byref(held),
                                   0x101000, False, 0))
    try:
        inside = w.BOOL()
        api.check(api.is_in_job(held, job.handle, c.byref(inside)))
        need(inside.value and api.wait(held, 0) == 258, "OWNED_ROOT_NOT_LIVE_IN_EXACT_JOB")
        restart.verify_token(api, held, sid)
        return api, held
    except BaseException:
        api.check(api.close(held))
        raise

def reopen_checks(policy, state, ids, audit_count):
    for reopen in (1, 2):
        store = Store(state)
        manager = None
        try:
            manager = JobManager(policy, store)
            need(manager.restart_verifier is None and not manager.owners and
                 not manager.startup_unresolved and not manager.storage_fenced,
                 "TERMINAL_REOPEN_UNRESOLVED")
            for jid in ids:
                need(store.get_job(jid, "pilot")["status"] == "completed",
                     "REOPEN_TERMINAL_DRIFT")
            need(store.verify() and store.db.execute("SELECT count(*) FROM audit").fetchone()[0]
                 == audit_count, "REOPEN_AUDIT_CHANGED")
        finally:
            if manager is not None:
                manager.close()
            store.close()

def manager_case(root, label, sid, profile):
    CONTEXT.update(case=label, stage="SETUP")
    case = root / label
    case.mkdir(exist_ok=False)
    subject = case / "subject"
    subject.mkdir(exist_ok=False)
    output = case / "out"
    output.mkdir(exist_ok=False)
    fixture.acl(case, "/grant", "*" + profile["sid_text"] + ":(OI)(CI)(RX)")
    fixture.acl(output, "/grant", "*" + profile["sid_text"] + ":(OI)(CI)(M)")
    controller = root / "controller" / label
    controller.mkdir(exist_ok=False)
    manifest = controller / "worker.json"
    manifest.write_text(json.dumps({"workspace": str(subject), "network_capabilities": [],
        "profile_name": profile["name"], "runtime": str(root / "runtime"),
        "temp": str(output), "home": str(subject)}))
    state = controller / "state"
    policy = Policy({"pilot": Project(subject, True)}, state, exec_mode="appcontainer",
        workers={"pilot": {"manifest": str(manifest)}}, max_active_jobs=1, max_queued_jobs=1,
        max_timeout_ms=20000, max_wait_ms=1000,
        min_free_memory_bytes=1024**3, min_free_disk_bytes=1024**3)
    store = Store(state)
    manager = None
    held = []
    ids = []
    canary = (controller / "fd-canary.bin").open("x+b", buffering=0)
    try:
        manager = JobManager(policy, store)
        pressure = manager.pressure.snapshot()
        need(pressure.free_memory_bytes is not None and not pressure.pressured,
             "RUNNER_ADMISSION_DEFERRED")
        repetitions = 2 if label == "IO01_transferred_stdio" else 1
        for repetition in range(repetitions):
            CONTEXT.update(stage="REAL_ADMISSION")
            witness, release = output / "leaf.pid", output / "release-root.signal"
            args = ["stdio"] if label == "IO01_transferred_stdio" else [
                "early-root", str(witness), str(release)]
            argv = policy.command("pilot", [str(root / "runtime" / "LimitedIoProbe.exe"), *args], None)
            started = time.monotonic()
            jid = manager.start("pilot", "pilot", argv, 20000,
                                limits={"max_processes": 4, "memory_bytes": 256*1024**2})
            ids.append(jid)
            owner = manager.owners[jid]
            process, job = owner.custody.process, owner.custody.job
            api, root_handle = native_witness(process, job, sid)
            held.append((api, root_handle))
            if label == "IO01_transferred_stdio":
                CONTEXT.update(stage="STDIN_AND_DUAL_PIPE_CAPTURE")
                ack = manager.input("pilot", jid, "LOCALCONTROL_STDIO_V1\n" + "a"*128, eof=True)
                need(ack["eof_queued"] is True, "STDIN_EOF_NOT_QUEUED")
                record = terminal_checks(manager, store, jid, owner, process, job)
                for name, byte in (("stdout", b"O"), ("stderr", b"E")):
                    expected = byte * (3*32768)
                    need(record.get(name + "_bytes") == len(expected) and
                         record.get(name + "_truncated") is False and
                         hashlib.sha256(record[name].encode("ascii")).digest() ==
                         hashlib.sha256(expected).digest(), "TRANSFERRED_OUTPUT_MISMATCH")
                need(record["stdin_bytes"] == len(b"LOCALCONTROL_STDIO_V1\n") + 128,
                     "STDIN_BYTE_COUNT_MISMATCH")
            else:
                CONTEXT.update(stage="OBSERVE_DESCENDANT_BEFORE_ROOT_EXIT")
                fixture.until(witness.exists, 5)
                pid = int(witness.read_text())
                api.k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
                api.k.OpenProcess.restype = w.HANDLE
                leaf = api.k.OpenProcess(0x101000, False, pid)
                need(bool(leaf), "LEAF_QUERY_HANDLE_REQUIRED")
                held.append((api, leaf))
                inside = w.BOOL()
                api.check(api.is_in_job(leaf, job.handle, c.byref(inside)))
                need(inside.value and api.wait(leaf, 0) == 258, "LEAF_NOT_LIVE_IN_EXACT_JOB")
                restart.verify_token(api, leaf, sid)
                need(time.monotonic()-started < 8, "EARLY_ROOT_RELEASE_TOO_LATE")
                release.write_text("release-owned-root")
                CONTEXT.update(stage="ROOT_EXIT_AND_DESCENDANT_CLEANUP")
                need(api.wait(root_handle, 5000) == 0, "OWNED_ROOT_EXIT_NOT_PROVEN")
                code = w.DWORD()
                api.check(api.code(root_handle, c.byref(code)))
                need(code.value == 0, "ROOT_DID_NOT_EXIT_NORMALLY")
                need(api.wait(leaf, 5000) == 0, "LEAF_SURVIVED_ROOT_EXIT_CLEANUP")
                need(time.monotonic()-started < 15, "LEAF_NATURAL_EXPIRY_NOT_EXCLUDED")
                record = terminal_checks(manager, store, jid, owner, process, job)
            # Unrelated, task-owned descriptor remains usable across actual startup/cleanup.
            canary.seek(0)
            canary.write(b"fd-canary-" + bytes([65+repetition]))
            canary.seek(0)
            need(canary.read() == b"fd-canary-" + bytes([65+repetition]),
                 "UNRELATED_FD_CANARY_CORRUPTED")
            need(api.wait(root_handle, 0) == 0, "ROOT_HANDLE_EXIT_NOT_PROVEN")
            dump({"case": label, "iteration": repetition+1, "stage": "DURABLE_TERMINAL",
                  "passed": True, "native_zero": True, "checked_owned_handles_closed": True,
                  "fd_canary_intact": True, "stdout_bytes": record.get("stdout_bytes"),
                  "stderr_bytes": record.get("stderr_bytes")})
        count = store.db.execute("SELECT count(*) FROM audit").fetchone()[0]
        manager.close()
        manager = None
        store.close()
        store = None
        reopen_checks(policy, state, ids, count)
        result = {"passed": True, "iterations": repetitions, "fresh_reopens": 2,
                  "audit_unchanged": True, "native_membership_and_zero_capability_sid": True,
                  "owned_handle_cleanup": True, "fd_canary_intact": True,
                  "no_attestor": True, "no_fence_clearing": True}
        if label == "IO02_early_root_exit":
            result.update(leaf_natural_expiry_ms=20000, cleanup_completed_before_15000_ms=True,
                          root_exited_normally=True, leaf_exit_proven_by_retained_handle=True)
        return result
    finally:
        if manager is not None:
            manager.close()
        for api, handle in held:
            api.check(api.close(handle))
        canary.close()
        if store is not None:
            store.close()

def run(root):
    need(os.name == "nt" and c.sizeof(c.c_void_p) == 8 and sys.version_info[:3] == (3,12,10),
         "FIXED_WINDOWS_X64_PYTHON_REQUIRED")
    need(re.fullmatch(ROOT_PATTERN, str(root)) is not None, "FIXED_ROOT_REQUIRED")
    no_links(root)
    need(not any("TOKEN" in name.upper() or name.upper().startswith("ACTIONS_")
                 for name in os.environ), "CREDENTIAL_ENV_NOT_STRIPPED")
    fixture.token_sid()
    (root / "controller").mkdir(exist_ok=False)
    runtime = root / "runtime"
    runtime.mkdir(exist_ok=False)
    (runtime / "LimitedIoProbe.exe").write_bytes((root / "compiled-helper.exe").read_bytes())
    api = app.WinAPI()
    name = "LocalControl.IO." + uuid.uuid4().hex
    sid = c.c_void_p()
    created = False
    try:
        need(api.create_profile(name, name, "Disposable IO lifecycle fixture", None, 0,
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
        fixture.acl(runtime, "/grant", "*" + sid_text + ":(OI)(CI)(RX)")
        results = {}
        for label in ("IO01_transferred_stdio", "IO02_early_root_exit"):
            dump({"case": label, "stage": "BEGIN"})
            results[label] = manager_case(root, label, sid, {"name": name, "sid_text": sid_text})
            dump({"case": label, "evidence": results[label]})
        return len(results)
    finally:
        if sid:
            need(not api.free_sid(sid), "PROFILE_SID_FREE")
        if created:
            need(api.delete_profile(name) == 0, "PROFILE_DELETE")
            dump({"profile_cleanup": "PASS"})

if __name__ == "__main__":
    try:
        need(len(sys.argv) == 2, "FIXED_ROOT_ARGUMENT_REQUIRED")
        count = run(Path(sys.argv[1]))
        dump({"schema": "localcontrol-bounded-io-lifecycle/v1", "result": "PASS_IO_LIFECYCLE_ONLY",
              "case_count": count, "candidate_commit": "e071dd2d099577e3ded081f1ffefd7c2bf22e3a8",
              "full_release_qualification": False, "production_activation_authorized": False})
    except BaseException as error:
        record = restart.safe_error(error)
        record["context"] = dict(CONTEXT)
        dump(dict(record, schema="localcontrol-bounded-io-lifecycle/v1", result="FAIL_OR_BLOCKED"))
        sys.exit(1)
