import hashlib
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from localcontrol.v120_runner import (
    AttemptLedger,
    RunnerError,
    TaskOnlyRunner,
    WindowsAttemptBroker,
    _WORKLOAD_SCHEMA,
    _canonical,
    derive_attempt_identity,
    sign_workload_manifest,
    verify_workload_manifest,
)


_KEY = bytes(range(32))
_LIMITS = {"memory_bytes": 64 * 1024 * 1024, "max_processes": 4, "cpu_ms": 5000}


class AttemptLedgerConcurrencyTests(unittest.TestCase):
    def test_verify_serializes_event_and_claim_snapshots(self):
        handle = tempfile.NamedTemporaryFile(
            prefix=".v120-attempt-race-", suffix=".sqlite3",
            dir=Path(__file__).parent, delete=False,
        )
        ledger_path = Path(handle.name)
        handle.close()
        ledger = None
        verifier = claimer = None
        release_verify = threading.Event()
        snapshot_ready = threading.Event()
        verify_errors = []
        claim_errors = []

        class SignalingRLock:
            def __init__(self):
                self._lock = threading.RLock()
                self.claim_attempted = threading.Event()
                self.claim_acquired_without_block = None

            def __enter__(self):
                if threading.current_thread().name == "v120-claim-race":
                    acquired = self._lock.acquire(blocking=False)
                    self.claim_acquired_without_block = acquired
                    self.claim_attempted.set()
                    if not acquired:
                        self._lock.acquire()
                    return self
                self._lock.acquire()
                return self

            def __exit__(self, *_exc):
                self._lock.release()

        try:
            ledger = AttemptLedger(ledger_path, _KEY)
            ledger.lock = SignalingRLock()
            original_events = ledger.events

            def pause_after_event_snapshot():
                events = original_events()
                if threading.current_thread().name == "v120-verify-race":
                    snapshot_ready.set()
                    if not release_verify.wait(timeout=5):
                        raise AssertionError("verification snapshot was not released")
                return events

            ledger.events = pause_after_event_snapshot

            def verify_worker():
                try:
                    ledger.verify()
                except Exception as exc:
                    verify_errors.append(exc)

            digest = "a" * 64
            attempt_id = "b" * 32

            def claim_worker():
                try:
                    ledger.claim_receipt(
                        digest, attempt_id,
                        {
                            "kind": "claimed",
                            "attempt_id": attempt_id,
                            "preflight_receipt_sha256": digest,
                        },
                    )
                except Exception as exc:
                    claim_errors.append(exc)

            verifier = threading.Thread(
                target=verify_worker, name="v120-verify-race"
            )
            claimer = threading.Thread(
                target=claim_worker, name="v120-claim-race"
            )
            verifier.start()
            self.assertTrue(snapshot_ready.wait(timeout=3))
            claimer.start()
            self.assertTrue(ledger.lock.claim_attempted.wait(timeout=3))
            self.assertFalse(
                ledger.lock.claim_acquired_without_block,
                "receipt claim acquired the lock before verification completed",
            )
            release_verify.set()
            verifier.join(timeout=3)
            claimer.join(timeout=3)

            self.assertFalse(verifier.is_alive())
            self.assertFalse(claimer.is_alive())
            self.assertEqual(verify_errors, [])
            self.assertEqual(claim_errors, [])
            self.assertTrue(ledger.verify())
        finally:
            release_verify.set()
            for worker in (verifier, claimer):
                if worker is not None and worker.is_alive():
                    worker.join(timeout=3)
            if ledger is not None:
                ledger.close()
            ledger_path.unlink(missing_ok=True)


class V120RunnerFixture(unittest.TestCase):
    def temp_root(self):
        from tests.project_fixtures import ProjectTemporaryDirectory
        temp = ProjectTemporaryDirectory(
            prefix=".v120-runner-", dir=Path(__file__).parent
        )
        self.addCleanup(temp.cleanup)
        return Path(temp.name)

    def build_manifest(self, root, entries, *, runtime_roots=None,
                       executable_relative=None, signature_edit=None):
        source_root = root / "runtime-source"
        source_root.mkdir(exist_ok=True)
        files = []
        for source_name, relative_path, data in entries:
            source = source_root / source_name
            source.write_bytes(data)
            files.append({
                "source_path": str(source),
                "relative_path": relative_path,
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        manifest = {
            "schema": _WORKLOAD_SCHEMA,
            "workload_id": "unit-workload",
            "executable_relative": executable_relative or entries[0][1],
            "argv": ["--task", "fixture"],
            "runtime_files": files,
            "resource_limits": dict(_LIMITS),
            "shell": False,
            "environment": {},
        }
        envelope = sign_workload_manifest(manifest, _KEY)
        if signature_edit is not None:
            signature_edit(envelope)
        raw = _canonical(envelope)
        workload = {"workload_id": "unit-workload", "resource_limits": dict(_LIMITS)}
        roots = [str(source_root)] if runtime_roots is None else runtime_roots
        return raw, workload, roots

    def verify(self, built):
        raw, workload, roots = built
        return verify_workload_manifest(
            raw, hashlib.sha256(raw).hexdigest(), _KEY, workload, roots
        )


class AttemptIdentityTests(V120RunnerFixture):
    def _identity(self, **overrides):
        args = {
            "scope_key": _KEY,
            "scope_id": "phaseb-" + "a" * 16,
            "task_id": "integration-task",
            "workload_id": "unit-workload",
            "launch_request_id": "launch-001",
            "scope_revision": 1,
            "candidate_identity": {"kind": "git", "commit": "1" * 40, "tree": "2" * 40},
            "registry_revision": 3,
            "registry_sha256": "3" * 64,
            "registry_file_sha256": "4" * 64,
            "preflight_receipt_sha256": "5" * 64,
        }
        args.update(overrides)
        return derive_attempt_identity(**args)

    def test_attempt_identity_changes_with_every_authority_binding(self):
        baseline = self._identity()
        variants = [
            {"scope_revision": 2},
            {"candidate_identity": {"kind": "git", "commit": "6" * 40, "tree": "2" * 40}},
            {"registry_revision": 4},
            {"registry_sha256": "7" * 64},
            {"registry_file_sha256": "8" * 64},
            {"preflight_receipt_sha256": "9" * 64},
            {"launch_request_id": "launch-002"},
            {"workload_id": "other-workload"},
        ]
        for change in variants:
            with self.subTest(change=change):
                identity = self._identity(**change)
                self.assertNotEqual(identity["attempt_id"], baseline["attempt_id"])
                self.assertNotEqual(identity["profile_name"], baseline["profile_name"])
                self.assertNotEqual(identity["job_name"], baseline["job_name"])


class WorkloadManifestTests(V120RunnerFixture):
    def test_signed_manifest_is_accepted_and_binds_source_bytes(self):
        root = self.temp_root()
        built = self.build_manifest(root, [("worker.bin", "bin/worker.bin", b"worker")])
        manifest = self.verify(built)
        self.assertEqual(manifest["workload_id"], "unit-workload")
        self.assertEqual(manifest["runtime_files"][0]["sha256"], hashlib.sha256(b"worker").hexdigest())

    def test_modified_bytes_and_forged_signature_are_rejected(self):
        root = self.temp_root()
        raw, workload, roots = self.build_manifest(
            root, [("worker.bin", "worker.bin", b"worker")]
        )
        with self.assertRaises(RunnerError):
            verify_workload_manifest(raw + b" ", hashlib.sha256(raw).hexdigest(), _KEY, workload, roots)

        forged, workload, roots = self.build_manifest(
            root,
            [("forged.bin", "forged.bin", b"worker")],
            signature_edit=lambda envelope: envelope["signature"].update(
                hmac_sha256="0" * 64
            ),
        )
        with self.assertRaises(RunnerError):
            verify_workload_manifest(
                forged, hashlib.sha256(forged).hexdigest(), _KEY, workload, roots
            )

    def test_traversal_and_alternate_stream_paths_are_rejected(self):
        for relative in ("../outside.bin", "worker.bin:stream"):
            with self.subTest(relative=relative):
                root = self.temp_root()
                built = self.build_manifest(
                    root, [("worker.bin", relative, b"worker")]
                )
                with self.assertRaises(RunnerError):
                    self.verify(built)

    def test_case_insensitive_duplicate_runtime_paths_are_rejected(self):
        root = self.temp_root()
        built = self.build_manifest(
            root,
            [
                ("one.bin", "Lib/Runtime.dll", b"one"),
                ("two.bin", "lib/runtime.DLL", b"two"),
            ],
            executable_relative="Lib/Runtime.dll",
        )
        with self.assertRaises(RunnerError):
            self.verify(built)

    def test_runtime_source_outside_allowlisted_root_is_rejected(self):
        root = self.temp_root()
        source_root = root / "runtime-source"
        source_root.mkdir()
        outside = root / "outside.bin"
        outside.write_bytes(b"worker")
        item = {
            "source_path": str(outside),
            "relative_path": "worker.bin",
            "sha256": hashlib.sha256(b"worker").hexdigest(),
        }
        manifest = {
            "schema": _WORKLOAD_SCHEMA,
            "workload_id": "unit-workload",
            "executable_relative": "worker.bin",
            "argv": [],
            "runtime_files": [item],
            "resource_limits": dict(_LIMITS),
            "shell": False,
            "environment": {},
        }
        raw = _canonical(sign_workload_manifest(manifest, _KEY))
        workload = {"workload_id": "unit-workload", "resource_limits": dict(_LIMITS)}
        with self.assertRaises(RunnerError):
            verify_workload_manifest(
                raw, hashlib.sha256(raw).hexdigest(), _KEY, workload, [str(source_root)]
            )


class AttemptLedgerTests(V120RunnerFixture):
    def test_receipt_claim_is_unique_across_restart_and_replay(self):
        root = self.temp_root()
        path = root / "attempts.sqlite3"
        receipt = "a" * 64
        attempt = "b" * 32
        event = {
            "kind": "claimed", "attempt_id": attempt,
            "preflight_receipt_sha256": receipt, "task_id": "integration-task",
        }
        ledger = AttemptLedger(path, _KEY)
        self.assertIsNone(ledger.claim_receipt(receipt, attempt, event))
        ledger.close()

        ledger = AttemptLedger(path, _KEY)
        self.assertEqual(ledger.receipt_owner(receipt), attempt)
        retry = dict(event, attempt_id="c" * 32)
        self.assertEqual(ledger.claim_receipt(receipt, "c" * 32, retry), attempt)
        self.assertEqual(len(ledger.events()), 1)
        ledger.close()

    def test_hmac_chain_detects_tampering_after_restart(self):
        root = self.temp_root()
        path = root / "attempts.sqlite3"
        ledger = AttemptLedger(path, _KEY)
        ledger.append({"kind": "probe", "attempt_id": "d" * 32})
        ledger.db.execute("DROP TRIGGER attempts_no_update")
        ledger.db.execute(
            "UPDATE events SET event_json=? WHERE sequence=1",
            (_canonical({"kind": "altered", "attempt_id": "d" * 32}).decode("ascii"),),
        )
        with self.assertRaises(RunnerError):
            ledger.events()
        ledger.close()


class OwnerMarkerTests(V120RunnerFixture):
    def _runner(self):
        runner = object.__new__(TaskOnlyRunner)
        runner.registry_key = _KEY
        return runner

    def _marker_inputs(self, root):
        payload = {
            "scope_id": "phaseb-" + "e" * 16,
            "scope_revision": 2,
            "task_id": "integration-task",
            "candidate_identity": {"kind": "git", "commit": "1" * 40, "tree": "2" * 40},
            "registry_revision": 3,
            "registry_sha256": "3" * 64,
            "registry_file_sha256": "4" * 64,
            "worker": {
                "runner_policy_sha256": "5" * 64,
                "subject_parent": str(root),
            },
        }
        workload = {"workload_id": "unit-workload", "manifest_sha256": "6" * 64}
        identity = {
            "attempt_id": "7" * 32,
            "job_name": "LocalControl.v120.Job.fixture",
            "profile_name": "LocalControl.v120.a.fixture",
        }
        parent = {
            "path": str(root), "volume": 1, "file_id": 2,
            "acl_sha256": "8" * 64,
        }
        return payload, workload, identity, parent

    def test_owner_marker_is_signed_and_rejects_tampering(self):
        root = self.temp_root()
        runner = self._runner()
        payload, workload, identity, parent = self._marker_inputs(root)
        marker = runner._create_owner_marker(
            payload, workload, identity, "launch-001", "preflight-001",
            "9" * 64, parent,
        )
        claim = {key: value for key, value in marker.items() if key != "mac"}
        claim["owner_marker"] = marker
        self.assertEqual(
            runner._verify_owner_marker(claim)["subject_parent_snapshot"], parent
        )

        altered = dict(marker, task_id="different-task")
        with self.assertRaises(RunnerError):
            runner._verify_owner_marker(dict(claim, owner_marker=altered))

    def test_owner_marker_cannot_be_rebound_to_another_claim(self):
        root = self.temp_root()
        runner = self._runner()
        payload, workload, identity, parent = self._marker_inputs(root)
        marker = runner._create_owner_marker(
            payload, workload, identity, "launch-001", "preflight-001",
            "9" * 64, parent,
        )
        claim = {key: value for key, value in marker.items() if key != "mac"}
        claim["owner_marker"] = marker
        claim["registry_revision"] += 1
        with self.assertRaises(RunnerError):
            runner._verify_owner_marker(claim)


class PartialRecoveryTests(V120RunnerFixture):
    def _broker(self, parent, snapshot, deleted):
        broker = object.__new__(WindowsAttemptBroker)
        broker.security = SimpleNamespace(snapshot=lambda path: snapshot)
        broker._job_if_present = lambda claim: None
        broker._delete_profile = lambda profile_name, allow_missing: deleted.append(
            (profile_name, allow_missing)
        )
        return broker

    def test_partial_root_is_removed_only_with_exact_owner_marker(self):
        root = self.temp_root()
        parent = root / "subjects"
        parent.mkdir()
        attempt_id = "a" * 32
        subject = parent / attempt_id
        subject.mkdir()
        marker = {"schema": "fixture-owner", "attempt_id": attempt_id}
        (subject / ".localcontrol-attempt-owner.json").write_bytes(_canonical(marker))
        (subject / "workspace").mkdir()
        (subject / "workspace" / "output.txt").write_text("owned", encoding="utf-8")
        snapshot = {"path": str(parent), "volume": 1, "file_id": 2, "acl_sha256": "f" * 64}
        deleted = []
        broker = self._broker(parent, snapshot, deleted)
        claim = {
            "attempt_id": attempt_id, "subject_parent": str(parent),
            "subject_parent_snapshot": snapshot, "owner_marker": marker,
            "profile_name": "LocalControl.v120.a.fixture",
        }
        result = broker.recover_partial(claim)
        self.assertTrue(result["cleaned"])
        self.assertFalse(subject.exists())
        self.assertEqual(deleted, [(claim["profile_name"], True)])

    def test_partial_root_without_matching_marker_is_preserved(self):
        root = self.temp_root()
        parent = root / "subjects"
        parent.mkdir()
        attempt_id = "b" * 32
        subject = parent / attempt_id
        subject.mkdir()
        (subject / ".localcontrol-attempt-owner.json").write_bytes(b"unknown")
        snapshot = {"path": str(parent), "volume": 1, "file_id": 2, "acl_sha256": "f" * 64}
        deleted = []
        broker = self._broker(parent, snapshot, deleted)
        claim = {
            "attempt_id": attempt_id, "subject_parent": str(parent),
            "subject_parent_snapshot": snapshot,
            "owner_marker": {"schema": "expected", "attempt_id": attempt_id},
            "profile_name": "LocalControl.v120.a.fixture",
        }
        with self.assertRaises(RunnerError):
            broker.recover_partial(claim)
        self.assertTrue(subject.exists())
        self.assertEqual(deleted, [])

    def test_cleanup_recovery_requires_proven_partial_cleanup(self):
        attempt_id = "c" * 32
        claim = {"attempt_id": attempt_id, "profile_name": "LocalControl.v120.a.fixture"}
        candidate = {'kind': 'overlay', 'sha256': 'a' * 64}
        owned_calls = []

        class Ledger:
            def __init__(self):
                self.events = [{
                    "kind": "failed", "attempt_id": attempt_id,
                    "cleanup": {"cleaned": False, "pending": True},
                }]
            def latest(self, _attempt_id):
                return self.events[-1]
            def append(self, event):
                self.events.append(event)

        class Broker:
            def recover_partial(self, _claim):
                raise RunnerError("V120_PARTIAL_OWNER_UNPROVEN")

        runner = object.__new__(TaskOnlyRunner)
        def owned_event(_attempt_id, *, expected_task_id=None, expected_candidate_identity=None):
            owned_calls.append((_attempt_id, expected_task_id, expected_candidate_identity))
            return claim, None
        runner._owned_event = owned_event
        runner._get_broker = lambda: Broker()
        runner.ledger = Ledger()
        runner.clock = lambda: 1
        runner.lock = threading.RLock()
        runner.live = {}
        with self.assertRaises(RunnerError):
            runner.cleanup(attempt_id, expected_task_id='qualification-task',
                           expected_candidate_identity=candidate)
        self.assertEqual(owned_calls, [(attempt_id, 'qualification-task', candidate)])
        self.assertEqual([event["kind"] for event in runner.ledger.events], ["failed"])


if __name__ == "__main__":
    unittest.main()
