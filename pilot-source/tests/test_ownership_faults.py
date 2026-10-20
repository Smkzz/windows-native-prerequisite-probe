"""DEV_SOURCE_ONLY: synthetic handles and in-memory SQLite; no native authority."""
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import unittest
from collections import deque
from types import SimpleNamespace as NS
from unittest.mock import patch
from localcontrol.errors import ControlError
from localcontrol.store import Store, digest, AUDIT_ROWS_PER_ACTIVE_JOB
from localcontrol.jobs import JobManager, PendingJob, LiveJob
from localcontrol.job_ownership import Custody, safe_failure
from localcontrol import jobs, appcontainer, windows_job

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "source"

def memory_store():
    # Deliberate unit construction: no Store path/lease initialization is claimed.
    s = Store.__new__(Store)
    s.root = ROOT / "fixture-unused-path"
    s.lock = threading.RLock()
    s.db = sqlite3.connect(":memory:", check_same_thread=False)
    s.db.row_factory = sqlite3.Row
    s.db.executescript("""
    CREATE TABLE requests(scope TEXT,key TEXT,fingerprint TEXT,status TEXT,result TEXT,PRIMARY KEY(scope,key));
    CREATE TABLE jobs(id TEXT PRIMARY KEY,scope TEXT,record TEXT);
    CREATE TABLE job_archives(id TEXT PRIMARY KEY,scope TEXT,record TEXT,archived_ns INTEGER,reason TEXT,record_sha256 TEXT);
    CREATE TABLE audit(seq INTEGER PRIMARY KEY,payload TEXT,prev TEXT,hash TEXT);
    """)
    s.max_requests = 10000
    s.max_audit_rows = 100000
    s.audit_reserve_margin = 256
    s._rotation_failure = s._last_rotation_error = s._owed_cache = None
    s._rotation_backoff_until_ns = 0
    s.write_poisoned = False
    return s

class FaultDB:
    def __init__(self, db, *, commit=None, rollback=False, sql=None):
        self.db, self.commit_fault, self.rollback_fault, self.sql_fault = db, commit, rollback, sql
        self.calls = []
    def __getattr__(self, name):
        return getattr(self.db, name)
    def execute(self, sql, args=()):
        self.calls.append(sql)
        if self.sql_fault and self.sql_fault in sql:
            raise sqlite3.OperationalError("synthetic SQL failure")
        return self.db.execute(sql, args)
    def commit(self):
        fault, self.commit_fault = self.commit_fault, None
        if fault == "after":
            self.db.commit()
        if fault:
            raise sqlite3.OperationalError("synthetic COMMIT acknowledgement failure")
        return self.db.commit()
    def rollback(self):
        if self.rollback_fault:
            raise sqlite3.OperationalError("synthetic rollback failure")
        return self.db.rollback()

class NativeJob:
    def __init__(self, limits=None, *, custody=None):
        self.handle = 31
        self.stops = self.proofs = self.closes = 0
        self.empty = True
        self.stop_error = False
        self.close_error = False
        if custody:
            custody.job = self
    def stop(self):
        self.stops += 1
        if self.stop_error:
            raise OSError("synthetic native stop")
    def prove_empty(self, timeout=2):
        self.proofs += 1
        return self.empty
    def stats(self):
        return {"accounting_available":True,"limits_available":True,"active_processes":0}
    def close_verified(self):
        if self.close_error:
            self.close_error = False
            raise OSError("synthetic close")
        self.closes += 1

class NativeAPI:
    def __init__(self):
        self.exited = True
        self.closed = []
        self.fail_handle = None
    def terminate(self, *_):
        return True
    def wait(self, *_):
        return 0 if self.exited else 258
    def close(self, handle):
        if handle == self.fail_handle:
            self.fail_handle = None
            return False
        self.closed.append(handle)
        return True
    def check(self, ok):
        if not ok:
            raise OSError("synthetic handle close")
    def free_sid(self, *_):
        pass

class Process:
    pid = 123456789  # synthetic identity; never sent to OS.
    def __init__(self):
        self.stdin, self.stdout, self.stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
        self._thread, self._token, self._handle, self._sid = 11, 12, 13, None
        self.releases = 0
        self.release_error = False
    def release(self):
        self.releases += 1
        if self.release_error:
            raise OSError("synthetic ResumeThread uncertainty")

class InertThread:
    fail_name = None
    def __init__(self, target=None, args=(), **_):
        self.target, self.args = target, args
        self.ident = None
    def start(self):
        if getattr(self.target, "__name__", "") == self.fail_name:
            raise RuntimeError("synthetic Thread.start")
    def is_alive(self):
        return False
    def join(self, timeout=None):
        pass

def manager(s):
    m = JobManager.__new__(JobManager)
    m.store = s
    m.policy = NS(exec_mode="appcontainer", max_timeout_ms=30000, max_wait_ms=30000,
        max_active_jobs=1,max_queued_jobs=8,max_job_records=100,terminal_retention=10,
        max_output_bytes=10000,
        path=lambda *a,**kw: ROOT,
        workers={"p":{"manifest":str(ROOT / "fixture_manifest.json")}})
    m.live, m.pending, m.starting = {}, {}, {}
    m.launching, m.task_attempts = set(), set()
    m.pending_order = deque()
    m.lock = threading.RLock()
    m.condition = threading.Condition(m.lock)
    m.closed = False
    m._scratch, m._scratch_identity = {}, {}
    m.restart_verifier = None
    m.pressure = NS(snapshot=lambda:NS(pressured=False))
    m.admission_metrics = dict(queued_total=0,queue_full_rejections=0,pressure_deferrals=0,
        started_from_queue=0,max_queue_depth=0)
    m._ownership_init()
    m.scheduler = InertThread()
    return m

class OwnershipFaultTests(unittest.TestCase):
    def setUp(self):
        self.s = memory_store()
        self.db = self.s.db
        self.addCleanup(self.db.close)
        self.m = manager(self.s)
        self.api = NativeAPI()
        self.proc = Process()
        self.creations = 0
    def owner(self, jid="job-A", phase="admitted"):
        p = PendingJob(jid,"scope","p",["synthetic.exe"],1000,None,{},"immediate")
        o = self.m._register_owner(p)
        self.m.pending[jid] = p
        self.m.pending_order.append(jid)
        if phase:
            self.m._persist(o,"admitted",self.m._raw_snapshot(o),"job_start_intent",{})
            for step in ["queued","starting","create_intent","owned","release_intent","started"]:
                if phase == "admitted":
                    break
                self.m._persist(o,step,self.m._raw_snapshot(o),"job_"+step,{})
                if step == phase:
                    break
        return o
    def launch(self, o, *, spawn_error=None):
        if o.phase in {"admitted","queued"}:
            with self.m.condition:
                self.m._reserve_start_locked(o.pending)
        def spawn(*a, custody=None, **kw):
            self.creations += 1
            custody.process = self.proc
            custody.api = self.api
            custody.assigned = True
            if spawn_error:
                raise spawn_error
            return self.proc
        fake_threads = NS(Thread=InertThread,current_thread=threading.current_thread)
        with patch.object(windows_job,"WindowsJob",NativeJob), \
             patch.object(appcontainer,"spawn",side_effect=spawn), \
             patch.object(jobs,"threading",fake_threads):
            return self.m._launch_reserved(o.pending,from_queue=False,raise_errors=True)
    def events(self, kind=None):
        rows = [json.loads(r[0]) for r in self.db.execute("SELECT payload FROM audit ORDER BY seq")]
        return [r for r in rows if kind is None or r["kind"] == kind]
    def fail_phase(self, phase, *, after=False):
        real = self.s.commit_job_transition
        def call(*a,**kw):
            if a[2] == phase:
                if after:
                    real(*a,**kw)
                raise sqlite3.OperationalError("synthetic transition outage")
            return real(*a,**kw)
        return patch.object(self.s,"commit_job_transition",side_effect=call)
    def test_QF01_initial_admission_fences_without_creation(self):
        with self.fail_phase("admitted"):
            with self.assertRaises(ControlError):
                self.m.start("scope","p",["synthetic.exe"],1000)
        self.assertEqual(len(self.m.owners),1)
        o = next(iter(self.m.owners.values()))
        self.assertFalse(o.pending.done.is_set())
        self.assertFalse(self.m.reserve_task_attempt("new"))
        with self.assertRaises(ControlError):
            self.m.start("scope","p",["synthetic.exe"],1000)
        self.assertEqual(len(self.m.owners),1)
        self.assertFalse(o.custody.created())
    def test_QF02_queued_SQL_failure_keeps_identity_out_of_FIFO(self):
        self.m.pressure = NS(snapshot=lambda:NS(pressured=True))
        with self.fail_phase("queued"):
            with self.assertRaises(ControlError):
                self.m.start("scope","p",["synthetic.exe"],1000)
        self.assertEqual(list(self.m.pending_order),[])
        self.assertEqual(len(self.m.owners),1)
        self.assertEqual(self.events("job_queued"),[])
    def test_QF03_starting_ack_loss_never_creates(self):
        o = self.owner()
        with self.fail_phase("starting",after=True):
            with self.assertRaises(ControlError):
                with self.m.condition:
                    self.m._reserve_start_locked(o.pending)
        frozen = o.transition
        self.assertTrue(self.m._complete_owner(o,"start_failed"))
        self.assertEqual(len(self.events("job_starting")),1)
        self.assertTrue(o.pending.done.is_set())
        self.assertEqual(self.creations,0)
        self.assertEqual(frozen[0],"starting")
    def test_QF04_created_before_live_publication_retains_raw_owner(self):
        o = self.owner()
        with patch.object(jobs,"LiveJob",side_effect=RuntimeError("synthetic transfer")), \
             patch.object(NativeJob,"prove_empty",return_value=False):
            with self.assertRaises(ControlError):
                self.launch(o)
        self.assertIs(o.custody.process,self.proc)
        self.assertIsNone(o.live)
        self.assertEqual(self.proc.releases,0)
        self.assertEqual(self.api.closed,[])
        self.assertIn(o.pending.id,self.m.owners)
    def test_QF05_owned_write_and_unknown_termination_retain_capacity(self):
        o = self.owner()
        self.api.exited = False
        with self.fail_phase("owned"):
            with self.assertRaises(ControlError):
                self.launch(o)
        self.assertIsNotNone(o.live)
        self.assertIn(o.pending.id,self.m.starting)
        self.assertEqual(self.m._active_count_locked(),1)
        self.assertFalse(o.pending.done.is_set())
        self.assertEqual(self.api.closed,[])
    def test_QF06_release_intent_failure_never_releases(self):
        o = self.owner()
        with self.fail_phase("release_intent"):
            with self.assertRaises(ControlError):
                self.launch(o)
        self.assertEqual(self.proc.releases,0)
        self.assertIn(o.pending.id,self.m.owners)
        self.m.stop("scope",o.pending.id)
        self.assertEqual(self.proc.releases,0)
    def test_QF07_resume_uncertainty_is_never_replayed(self):
        o = self.owner()
        self.proc.release_error = True
        with self.assertRaises(ControlError):
            self.launch(o)
        self.assertEqual(self.proc.releases,1)
        self.assertIsNone(o.custody.command_released)
        self.assertEqual(self.creations,1)
        self.assertNotEqual(self.s.get_job(o.pending.id,"scope")["status"],"completed")
    def test_QF08_cancel_before_release_claim_prevents_release(self):
        o = self.owner()
        real = self.s.commit_job_transition
        def hook(*a,**kw):
            value = real(*a,**kw)
            if a[2] == "release_intent":
                o.pending.cancel_requested = True
            return value
        with patch.object(self.s,"commit_job_transition",side_effect=hook):
            self.launch(o)
        self.assertFalse(o.release_claimed)
        self.assertEqual(self.proc.releases,0)
        self.assertFalse(o.custody.command_released)
    def test_QF09_stop_after_claim_retains_native_until_launch_finishes(self):
        o = self.owner()
        original = self.proc.release
        def release():
            self.assertTrue(o.release_claimed)
            self.m.stop("scope",o.pending.id)
            self.assertFalse(o.custody.closed)
            self.assertGreater(o.custody.job.stops,0)
            original()
        self.proc.release = release
        self.launch(o)
        self.assertEqual(self.proc.releases,1)
        self.assertTrue(o.custody.command_released)
        self.assertEqual(o.live.status,"stopped")
    def test_QF10_late_creation_cannot_finalize_during_shutdown(self):
        o = self.owner()
        with self.m.condition:
            self.m._reserve_start_locked(o.pending)
        self.m.closed = True
        self.assertFalse(self.m._complete_owner(o,"server_shutdown"))
        self.assertFalse(o.pending.done.is_set())
        with self.assertRaises(ControlError):
            self.launch(o)
        self.assertEqual(self.creations,0)
        self.assertTrue(o.custody.closed)
    def test_QF11_native_proof_failure_forbids_early_close(self):
        o = self.owner()
        o.custody.api, o.custody.process, o.custody.job = self.api,self.proc,NativeJob()
        o.launch_finished.set()
        o.custody.job.empty = False
        self.assertFalse(self.m._complete_owner(o,"start_failed"))
        self.assertFalse(o.terminal_committed)
        self.assertEqual(self.api.closed,[])
        o.custody.job.empty = True
        self.assertTrue(self.m._complete_owner(o,"start_failed"))
    def test_QF12_terminal_write_failure_freezes_payload_retains_owner(self):
        o = self.owner()
        o.launch_finished.set()
        with self.fail_phase("terminal"):
            self.assertFalse(self.m._complete_owner(o,"stopped"))
        frozen = json.dumps(o.terminal_record,sort_keys=True)
        self.assertFalse(o.pending.done.is_set())
        self.assertFalse(o.custody.closed)
        self.assertTrue(self.m._complete_owner(o,"failed"))
        self.assertEqual(json.dumps(o.terminal_record,sort_keys=True),frozen)
        self.assertEqual(o.terminal_record["status"],"stopped")
    def test_QF13_audit_or_row_SQL_error_rolls_back_whole_transition(self):
        for sql in ("INSERT INTO audit","INSERT INTO jobs"):
            with self.subTest(sql=sql):
                s = memory_store()
                try:
                    db = s.db
                    s.db = FaultDB(db,sql=sql)
                    with self.assertRaises(sqlite3.OperationalError):
                        s.commit_job_transition("j","s","terminal",0,{"status":"stopped"},"finished",{})
                    self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0],0)
                    self.assertEqual(db.execute("SELECT count(*) FROM audit").fetchone()[0],0)
                    self.assertFalse(db.in_transaction)
                finally:
                    db.close()
    def test_QF15_terminal_commit_ack_loss_reconciles_once(self):
        o = self.owner()
        o.launch_finished.set()
        self.s.db = FaultDB(self.db,commit="after")
        self.assertFalse(self.m._complete_owner(o,"stopped"))
        self.assertFalse(o.terminal_committed)
        self.assertEqual(len(self.events("job_queue_terminal")),1)
        self.assertTrue(self.m._complete_owner(o,"failed"))
        self.assertEqual(len(self.events("job_queue_terminal")),1)
        self.assertEqual(o.terminal_record["status"],"stopped")
    def test_QF16_failed_commit_and_rollback_poison_connection(self):
        self.s.db = FaultDB(self.db,commit="before",rollback=True)
        with self.assertRaises(sqlite3.OperationalError):
            self.s.commit_job_transition("j","s","terminal",0,{"status":"stopped"},"finished",{})
        self.assertTrue(self.s.write_poisoned)
        with self.assertRaises(ControlError):
            self.s.audit("new",{})
    def test_QF17_repeated_restart_never_replays_or_duplicates(self):
        for phase in ("queued","starting","create_intent","release_intent","started"):
            with self.subTest(phase=phase):
                s = memory_store()
                try:
                    m = manager(s)
                    o = self.owner("recovery-"+phase,phase)
                    # Copy only synthetic committed receipt/audit via SQLite backup.
                    self.db.backup(s.db)
                    m._recover_startup()
                    first = s.db.execute("SELECT count(*) FROM audit").fetchone()[0]
                    n = manager(s)
                    n._recover_startup()
                    self.assertEqual(s.db.execute("SELECT count(*) FROM audit").fetchone()[0],first)
                    if phase in ("queued","starting"):
                        self.assertEqual(s.get_job(o.pending.id,"scope")["status"],"interrupted")
                    else:
                        self.assertTrue(n.storage_fenced)
                        self.assertIn(o.pending.id,n.startup_unresolved)
                finally:
                    s.db.close()
    def test_QF18_outage_retry_is_bounded_and_frozen(self):
        o = self.owner()
        o.launch_finished.set()
        with self.fail_phase("terminal") as call:
            self.m._complete_owner(o,"stopped")
            frozen = o.transition
            before = call.call_count
            self.m.stop("scope",o.pending.id)
            self.assertLessEqual(call.call_count-before,2)
            before = call.call_count
            self.m.stop("scope",o.pending.id)
            self.assertEqual(call.call_count,before)
            self.assertEqual(o.transition,frozen)
        o.next_retry = 0
        self.m.stop("scope",o.pending.id)
        self.assertTrue(o.pending.done.is_set())
    def test_QF19_unresolved_fences_FIFO_capacity_and_archival(self):
        a,b,c = (self.owner(j,"queued") for j in ("A","B","C"))
        self.m._fault(a,"starting","SYNTHETIC")
        self.assertEqual(list(self.m.pending_order),["B","C"])
        self.assertEqual(self.m._active_count_locked(),1)
        self.assertEqual(self.m._protected_ids_locked(),{"A","B","C"})
        self.assertFalse(self.m.reserve_task_attempt("other"))
        with self.assertRaises(ControlError):
            self.m.archive_terminal_jobs("scope")
        a.launch_finished.set()
        self.m._complete_owner(a,"stopped")
        self.assertFalse(self.m.storage_fenced)
        self.assertEqual(list(self.m.pending_order),["B","C"])
    def test_QF20_idempotency_replay_and_conflict(self):
        self.assertIsNone(self.s.reserve("scope","request001","fp"))
        self.assertEqual(self.s.reserve("scope","request001","fp")["error"]["code"],"INDETERMINATE")
        with self.assertRaises(ControlError) as err:
            self.s.reserve("scope","request001","changed")
        self.assertEqual(err.exception.code,"IDEMPOTENCY_CONFLICT")
        self.s.finish("scope","request001",{"ok":True,"data":{"job_id":"same"}})
        self.assertEqual(self.s.reserve("scope","request001","fp")["data"]["job_id"],"same")
        self.assertIsNone(self.s.reserve("scope","request002","fp"))
    def test_QF21_thread_start_faults_retain_or_prove_before_done(self):
        for name in ("_drain","_watch","_write_input"):
            with self.subTest(name=name):
                # Each iteration gets its own synthetic state and handles.
                self.m = manager(self.s)
                self.proc = Process()
                self.api = NativeAPI()
                o = self.owner("thread-"+name)
                InertThread.fail_name = name
                try:
                    with self.assertRaises(ControlError):
                        self.launch(o)
                    self.assertLessEqual(self.proc.releases,1)
                    self.assertTrue(o.custody.closed or o.pending.id in self.m.owners)
                    if o.pending.done.is_set():
                        self.assertTrue(o.terminal_committed and o.custody.closed)
                finally:
                    InertThread.fail_name = None
        o = self.owner("reader")
        o.launch_finished.set()
        o.readers = [NS(ident=None,is_alive=lambda:True)]
        self.assertFalse(self.m._complete_owner(o,"completed"))
        self.assertFalse(o.pending.done.is_set())
    def test_QF22_partial_handle_close_retains_identity(self):
        o = self.owner()
        o.launch_finished.set()
        o.custody.api,o.custody.process,o.custody.job = self.api,self.proc,NativeJob()
        self.api.fail_handle = 12
        self.assertFalse(self.m._complete_owner(o,"stopped"))
        self.assertTrue(o.terminal_committed)
        self.assertFalse(o.custody.closed)
        self.assertIn(o.pending.id,self.m.owners)
    def test_QF23_protected_reclamation_and_archive_integrity(self):
        o = self.owner()
        o.launch_finished.set()
        self.m._complete_owner(o,"stopped")
        self.s.reclaim_terminal_jobs("scope",keep_recent=0,protected_ids={o.pending.id},reason="test")
        self.assertEqual(self.db.execute("SELECT count(*) FROM job_archives").fetchone()[0],0)
        self.s.reclaim_terminal_jobs("scope",keep_recent=0,protected_ids=set(),reason="test")
        row = self.db.execute("SELECT * FROM job_archives").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["record_sha256"],digest(json.loads(row["record"])))
        self.assertNotIn("_ownership",self.s.get_job(o.pending.id,"scope"))
        with self.assertRaises(ControlError):
            self.s.commit_job_transition(o.pending.id,"scope","terminal",0,{"status":"stopped"},"changed",{})
    def test_QF24_diagnostics_redact_exception_and_argv(self):
        secret = "SYNTHETIC_SECRET_NOT_REAL"
        self.assertNotIn(secret,json.dumps(safe_failure("creation","FAILED",RuntimeError(secret))))
        error = OSError(secret)
        error.winerror = 5
        self.assertEqual(safe_failure("create","FAILED",error),{"stage":"create","reason_code":"FAILED","winerror":5})
        o = self.owner()
        o.pending.argv.append(secret)
        self.m._fault(o,"create","FAILED",error)
        self.assertNotIn(secret,json.dumps(self.m.read("scope",o.pending.id)))
    def test_QF25_positive_launch_terminalizes_once(self):
        o = self.owner()
        self.launch(o)
        self.assertEqual(self.creations,1)
        self.assertEqual(self.proc.releases,1)
        self.assertTrue(self.m._complete_owner(o,"completed"))
        self.assertEqual(self.s.get_job(o.pending.id,"scope")["status"],"completed")
        self.assertTrue(self.s.verify())
        self.assertEqual(len(self.events("job_finished")),1)
        self.assertEqual(self.m.ownership_status()["retained_owners"],0)
    def test_QF26_stop_with_delayed_proof_is_unresolved(self):
        o = self.owner()
        self.launch(o)
        self.api.exited = False
        value = self.m.stop("scope",o.pending.id)
        self.assertEqual(value["status"],"ownership_unresolved")
        self.assertFalse(o.pending.done.is_set())
        self.assertEqual(self.api.closed,[])
        self.api.exited = True
        o.next_retry = 0
        self.m.stop("scope",o.pending.id)
        self.assertTrue(o.custody.closed)
    def test_QF27_launch_claim_exists_before_dispatch(self):
        o = self.owner()
        with self.m.condition:
            self.m._reserve_start_locked(o.pending)
        self.assertIn(o.pending.id,self.m.launching)
        self.assertFalse(o.launch_finished.is_set())
        self.m.stop("scope",o.pending.id)
        self.assertIn(o.pending.id,self.m.owners)
        self.launch(o)
        self.assertEqual(self.creations,0)
        self.assertNotIn(o.pending.id,self.m.owners)
    def test_QF28_admission_ack_loss_preserves_request_binding(self):
        self.s.reserve("scope","request001","fp")
        self.s.db = FaultDB(self.db,commit="after")
        with self.assertRaises(ControlError) as err:
            self.m.start("scope","p",["synthetic.exe"],1000,request_id="request001")
        jid = err.exception.details["job_id"]
        value = self.s.reserve("scope","request001","fp")
        self.assertEqual(value["data"]["job_id"],jid)
        self.assertEqual(len(self.m.owners),1)
        self.assertEqual(self.creations,0)
    def test_QF29_restart_default_and_mismatched_attestor_fail_closed(self):
        o = self.owner(phase="create_intent")
        m = manager(self.s)
        m._recover_startup()
        for verifier in (None,NS(verify=lambda *a,**kw:{"authorized":True,"quiescent":True,"job_id":"wrong"})):
            m.restart_verifier = verifier
            with self.assertRaises(ControlError):
                m.reconcile_startup("scope",o.pending.id,evidence={})
            self.assertTrue(m.storage_fenced)
        with self.assertRaises(ControlError):
            m.reconcile_startup("foreign",o.pending.id,evidence={})
        # This fake verifier tests binding logic only, never real authentication.
        m.restart_verifier = NS(verify=lambda *a,expected:dict(expected,authorized=True,quiescent=True,proof_sha256="a"*64))
        m.reconcile_startup("scope",o.pending.id,evidence={})
        self.assertFalse(m.storage_fenced)
        self.assertEqual(self.s.get_job(o.pending.id,"scope")["status"],"interrupted")
    def test_QF30_partial_close_retry_uses_frozen_native_proof(self):
        for handle in (11,12,13):
            with self.subTest(handle=handle):
                m = manager(self.s)
                self.m = m
                self.api,self.proc = NativeAPI(),Process()
                o = self.owner("close-"+str(handle))
                o.launch_finished.set()
                o.custody.api,o.custody.process,o.custody.job = self.api,self.proc,NativeJob()
                self.api.fail_handle = handle
                self.assertFalse(m._complete_owner(o,"stopped"))
                proofs = o.custody.job.proofs
                self.assertTrue(o.custody.quiescence_frozen)
                self.assertTrue(m._complete_owner(o,"failed"))
                self.assertEqual(o.custody.job.proofs,proofs)
                self.assertCountEqual(self.api.closed,[11,12,13])
                self.assertEqual(o.terminal_record["status"],"stopped")
    def test_QF32_direct_unsupported_modes_admit_nothing(self):
        for mode in ("recipes","trusted_local","disabled"):
            self.m.policy.exec_mode = mode
            with self.assertRaises(ControlError) as err:
                self.m.start("scope","p",["synthetic.exe"],1000)
            self.assertEqual(err.exception.code,"SANDBOX_REQUIRED")
        self.assertEqual(self.m.owners,{})
    def test_QF33_known_supervision_fault_cannot_ack_success(self):
        o = self.owner()
        real = self.s.commit_job_transition
        def hook(*a,**kw):
            value = real(*a,**kw)
            if a[2] == "started":
                self.m._fault(o,"supervision","SYNTHETIC_WATCH_FAULT")
            return value
        with patch.object(self.s,"commit_job_transition",side_effect=hook):
            with self.assertRaises(ControlError):
                self.launch(o)
        self.assertFalse(o.launch_acknowledged)
        self.assertEqual(self.proc.releases,1)
    def test_QF34_cancel_intent_and_terminal_private_markers(self):
        o = self.owner()
        o.pending.cancel_requested = True
        self.assertTrue(self.m._persist_cancel_intent(o))
        self.assertTrue(self.m._persist_cancel_intent(o))
        self.assertEqual(len(self.events("job_stop_intent")),1)
        internal = self.s.jobs(include_ownership=True)[0]
        self.assertIn("cancel_intent",internal["_ownership"]["events"])
        self.assertNotIn("_ownership",self.s.jobs()[0])
        self.assertNotIn("_ownership",self.s.get_job(o.pending.id,"scope"))
        o.launch_finished.set()
        self.m._complete_owner(o,"stopped")
        self.assertEqual(len(self.events("job_queue_terminal")),1)
        self.assertTrue(self.s.verify())
    def test_QF35_active_audit_debt_and_admission_capacity(self):
        self.assertEqual(AUDIT_ROWS_PER_ACTIVE_JOB,12)
        o = self.owner()
        self.assertEqual(self.s._owed_reserve_locked(),12+self.s.audit_reserve_margin)
        self.m._fault(o,"test","UNRESOLVED")
        self.assertEqual(self.s._owed_reserve_locked(),12+self.s.audit_reserve_margin)
        # Avoid rotating a filesystem archive in this in-memory fixture.
        self.s.max_audit_rows = 280
        with patch.object(self.s,"_headroom_or_degraded"):
            with self.assertRaises(ControlError) as err:
                self.s.commit_job_transition("new","scope","admitted",0,{"status":"queued"},"new",{})
        self.assertEqual(err.exception.code,"AUDIT_CAPACITY")
        self.assertEqual(self.db.execute("SELECT count(*) FROM jobs").fetchone()[0],1)
    def test_QF36_uncommitted_marker_on_poisoned_connection_is_not_proof(self):
        o = self.owner()
        o.launch_finished.set()
        self.s.db = FaultDB(self.db,commit="before",rollback=True)
        self.assertFalse(self.m._complete_owner(o,"stopped"))
        self.assertTrue(self.db.in_transaction)
        self.assertTrue(self.s.write_poisoned)
        self.assertFalse(self.m._complete_owner(o,"stopped"))
        self.assertFalse(o.terminal_committed)
        self.assertFalse(o.custody.closed)
    def test_QF37_failed_admission_finished_error_reconciles_same_job(self):
        self.s.reserve("scope","request001","fp")
        with self.fail_phase("admitted"):
            with self.assertRaises(ControlError) as err:
                self.m.start("scope","p",["synthetic.exe"],1000,request_id="request001")
        jid = err.exception.details["job_id"]
        result = {"ok":False,"data":{"job_id":jid},"error":{"code":"STORE_FAILURE"}}
        self.s.finish("scope","request001",result)
        self.m.stop("scope",jid)
        self.assertEqual(self.s.reserve("scope","request001","fp"),result)
        self.assertEqual(self.s.get_job(jid,"scope")["status"],"start_failed")
        self.assertEqual(self.creations,0)
    def test_QF38_late_cancel_requests_stop_before_and_after_release(self):
        o = self.owner()
        original = self.proc.release
        def release():
            self.m.stop("scope",o.pending.id)
            self.assertGreaterEqual(o.custody.job.stops,1)
            self.assertFalse(o.launch_finished.is_set())
            self.assertFalse(o.custody.closed)
            original()
        self.proc.release = release
        self.launch(o)
        self.assertGreaterEqual(o.custody.job.stops,2)
        self.assertTrue(o.custody.command_released)
        self.assertEqual(o.live.status,"stopped")
    def test_QF40_retired_live_read_uses_frozen_snapshot_without_store(self):
        o = self.owner()
        self.launch(o)
        live = o.live
        self.m._complete_owner(o,"completed")
        with patch.object(self.s,"get_job",side_effect=AssertionError("closed Store")):
            self.assertEqual(self.m._record(live),o.terminal_record)
        copy = self.m._record(live)
        copy["launch_diagnostic"]["reason_code"] = "mutated caller"
        self.assertNotEqual(copy,self.m._record(live))
    def test_QF41_native_stop_error_cannot_skip_durable_cancel_intent(self):
        o = self.owner()
        self.launch(o)
        self.m.launching.add(o.pending.id)
        o.release_claimed = True
        o.custody.job.stop_error = True
        self.m.stop("scope",o.pending.id)
        self.assertEqual(len(self.events("job_stop_intent")),1)
        row = self.s.get_job(o.pending.id,"scope")
        self.assertTrue(row["launch_diagnostic"]["cancellation_requested"])
        self.assertTrue(o.unresolved)
        self.assertFalse(o.custody.closed)
    def test_QF42_frozen_terminal_is_not_durable_stop_ack(self):
        o = self.owner()
        o.launch_finished.set()
        with self.fail_phase("terminal"):
            self.assertFalse(self.m._complete_owner(o,"completed"))
            self.assertIsNotNone(o.terminal_record)
            self.assertFalse(self.m._persist_cancel_intent(o))
            self.assertFalse(o.terminal_committed)
        self.assertTrue(self.m._persist_cancel_intent(o))
        self.assertTrue(o.terminal_committed)
        self.assertEqual(len(self.events("job_queue_terminal")),1)
        self.assertTrue(self.m._complete_owner(o,"failed"))
        with patch.object(self.s,"get_job",side_effect=AssertionError("closed Store")):
            self.assertEqual(o.terminal_record["status"],"completed")
