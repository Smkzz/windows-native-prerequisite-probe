"""Filesystem-independent v1.2 runner logic checks for restricted project sandboxes.

These tests mock path identity and byte hashing. They do not qualify Windows ACLs,
AppContainer provisioning, process containment, or durable on-disk recovery.
"""
import hashlib
import hmac
import ntpath
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from localcontrol.appcontainer import (
    _environment_block,
    _valid_spawn_argv,
    _valid_worker_environment,
)
from localcontrol.v120_api import _preflight_request_binding_sha256
from localcontrol.v120_runner import (
    AttemptLedger,
    RunnerError,
    TaskOnlyRunner,
    _WORKLOAD_SCHEMA,
    _canonical,
    derive_attempt_identity,
    sign_workload_manifest,
    verify_workload_manifest,
    _validate_acl_ace_header,
    _validate_acl_entries,
)

_KEY = bytes(range(32))
_LIMITS = {"memory_bytes": 64 * 1024 * 1024, "max_processes": 4, "cpu_ms": 5000}
_SOURCE = r"C:\Projects\LocalControl\worktrees\phase-b-execution-blocker-20261012\localcontrol\v120_preflight.py"
_SOURCE_SHA256 = "125aa09715440f045c78b9f15e85f2631fe74bcf0d23992cd84280c6b3709702"
_RUNTIME_ROOT = r"C:\Projects\LocalControl\worktrees\phase-b-execution-blocker-20261012\localcontrol"
_FIXTURE_PARENT = r"C:\Projects\LocalControl\worktrees\phase-b-execution-blocker-20261012\tests\v060\disposable-subjects"
_WORKLOAD = {"workload_id": "unit-workload", "resource_limits": dict(_LIMITS)}


class PeerRootRecoveryTests(unittest.TestCase):
    def runner(self, latest):
        runner = TaskOnlyRunner.__new__(TaskOnlyRunner)
        prepared = {"attempt_id": "peer", "kind": "prepared",
                    "subject_root": r"C:\owned\peer"}
        released = {"attempt_id": "peer", "kind": "capacity_released",
                    "capacity_released": True}
        runner.ledger = SimpleNamespace(
            events=lambda: [prepared, latest, released],
            latest=lambda attempt: latest,
            for_attempt=lambda attempt: [prepared, latest, released])
        return runner

    def test_failed_attempt_with_verified_cleanup_is_not_an_existing_peer(self):
        runner = self.runner({"kind": "failed", "cleanup": {"cleaned": True}})
        with patch("localcontrol.v120_runner._safe_existing") as lookup:
            self.assertEqual(runner._other_attempt_roots("current", r"C:\owned"), [])
            lookup.assert_not_called()

    def test_capacity_release_without_cleanup_does_not_hide_missing_peer(self):
        runner = self.runner({"kind": "failed", "capacity_released": True,
                              "cleanup": {"cleaned": False}})
        with patch("localcontrol.v120_runner._safe_existing",
                   side_effect=RunnerError("V120_PATH_MISSING")):
            with self.assertRaises(RunnerError):
                runner._other_attempt_roots("current", r"C:\owned")

    def test_existing_live_peer_remains_in_access_validation(self):
        runner = self.runner({"kind": "running"})
        with patch("localcontrol.v120_runner._safe_existing",
                   side_effect=lambda path, file=None: path), \
             patch("localcontrol.v120_runner._inside", return_value=True):
            self.assertEqual(runner._other_attempt_roots("current", r"C:\owned"),
                             [Path(r"C:\owned\peer")])


class ReadOnlyRunnerLogicTests(unittest.TestCase):
    def manifest(self, relative="bin/worker.dll", *, second=None, source=_SOURCE,
                 source_sha256=_SOURCE_SHA256, forged=False):
        item = {"source_path": source, "relative_path": relative, "sha256": source_sha256}
        files = [item]
        if second is not None:
            files.append({"source_path": source, "relative_path": second,
                          "sha256": source_sha256})
        payload = {
            "schema": _WORKLOAD_SCHEMA,
            "workload_id": "unit-workload",
            "executable_relative": relative,
            "argv": ["--task", "fixture"],
            "runtime_files": files,
            "resource_limits": dict(_LIMITS),
            "shell": False,
            "environment": {},
        }
        envelope = sign_workload_manifest(payload, _KEY)
        if forged:
            envelope["signature"]["hmac_sha256"] = "0" * 64
        raw = _canonical(envelope)
        return raw

    @staticmethod
    def inside(path, root):
        candidate = ntpath.normcase(ntpath.abspath(str(path)))
        base = ntpath.normcase(ntpath.abspath(str(root)))
        try:
            return ntpath.commonpath([candidate, base]) == base
        except ValueError:
            return False

    def verify(self, raw, roots=None, expected_sha256=None):
        roots = [_RUNTIME_ROOT] if roots is None else roots
        expected = hashlib.sha256(raw).hexdigest() if expected_sha256 is None else expected_sha256
        with patch("localcontrol.v120_runner._safe_existing",
                   side_effect=lambda path, file=None: Path(str(path))), \
             patch("localcontrol.v120_runner._sha256", return_value=_SOURCE_SHA256), \
             patch("localcontrol.v120_runner._inside", side_effect=self.inside):
            return verify_workload_manifest(raw, expected, _KEY, _WORKLOAD, roots)

    def test_signed_manifest_binds_manifest_and_runtime_hash(self):
        result = self.verify(self.manifest())
        self.assertEqual(result["runtime_files"][0]["sha256"], _SOURCE_SHA256)
        self.assertEqual(result["runtime_files"][0]["relative_path"], "bin/worker.dll")

    def test_wrong_manifest_digest_is_rejected(self):
        raw = self.manifest()
        with self.assertRaises(RunnerError) as raised:
            self.verify(raw, expected_sha256="0" * 64)
        self.assertEqual(raised.exception.code, "V120_WORKLOAD_MANIFEST_HASH")

    def test_changed_runtime_digest_is_rejected(self):
        raw = self.manifest(source_sha256="0" * 64)
        with self.assertRaises(RunnerError) as raised:
            self.verify(raw)
        self.assertEqual(raised.exception.code, "V120_WORKLOAD_FILE_HASH")

    def test_forged_manifest_signature_is_rejected(self):
        with self.assertRaises(RunnerError) as raised:
            self.verify(self.manifest(forged=True))
        self.assertEqual(raised.exception.code, "V120_WORKLOAD_SIGNATURE")

    def test_traversal_and_alternate_stream_paths_are_rejected(self):
        for relative in ("../outside.bin", "worker.bin:stream"):
            with self.subTest(relative=relative):
                with self.assertRaises(RunnerError) as raised:
                    self.verify(self.manifest(relative=relative))
                self.assertEqual(raised.exception.code, "V120_WORKLOAD_PATH")

    def test_case_insensitive_duplicate_paths_are_rejected(self):
        raw = self.manifest(relative="Lib/Runtime.dll", second="lib/runtime.DLL")
        with self.assertRaises(RunnerError) as raised:
            self.verify(raw)
        self.assertEqual(raised.exception.code, "V120_WORKLOAD_FILES")

    def test_source_outside_allowlisted_runtime_root_is_rejected(self):
        source = r"C:\Projects\LocalControl\worktrees\phase-b-execution-blocker-20261012\tests\v060\test_v120_preflight.py"
        raw = self.manifest(source=source)
        with self.assertRaises(RunnerError) as raised:
            self.verify(raw)
        self.assertEqual(raised.exception.code, "V120_WORKLOAD_PATH")

    def test_attempt_identity_changes_with_authority_bindings(self):
        args = {
            "scope_key": _KEY, "scope_id": "phaseb-" + "a" * 16,
            "task_id": "integration-task", "workload_id": "unit-workload",
            "launch_request_id": "launch-001", "scope_revision": 1,
            "candidate_identity": {"kind": "git", "commit": "1" * 40, "tree": "2" * 40},
            "registry_revision": 3, "registry_sha256": "3" * 64,
            "registry_file_sha256": "4" * 64, "preflight_receipt_sha256": "5" * 64,
        }
        baseline = derive_attempt_identity(**args)
        for change in ({"scope_revision": 2}, {"registry_revision": 4},
                       {"preflight_receipt_sha256": "6" * 64},
                       {"launch_request_id": "launch-002"}):
            variant = dict(args)
            variant.update(change)
            self.assertNotEqual(derive_attempt_identity(**variant)["attempt_id"],
                                baseline["attempt_id"])

    def test_receipt_replay_returns_existing_attempt_in_memory(self):
        ledger = AttemptLedger(Path(":memory:"), _KEY)
        try:
            digest, attempt = "a" * 64, "b" * 32
            event = {"kind": "claimed", "attempt_id": attempt,
                     "preflight_receipt_sha256": digest, "task_id": "integration-task"}
            self.assertIsNone(ledger.claim_receipt(digest, attempt, event))
            self.assertEqual(ledger.claim_receipt(digest, attempt, event), attempt)
            self.assertEqual(ledger.receipt_owner(digest), attempt)
            self.assertEqual(len(ledger.events()), 1)
        finally:
            ledger.close()

    def test_owner_marker_authenticates_attempt_binding(self):
        runner = object.__new__(TaskOnlyRunner)
        runner.registry_key = _KEY
        payload = {
            "scope_id": "phaseb-" + "e" * 16, "scope_revision": 2,
            "task_id": "integration-task",
            "candidate_identity": {"kind": "git", "commit": "1" * 40, "tree": "2" * 40},
            "registry_revision": 3, "registry_sha256": "3" * 64,
            "registry_file_sha256": "4" * 64,
            "worker": {"runner_policy_sha256": "5" * 64,
                       "subject_parent": _FIXTURE_PARENT},
        }
        workload = {"workload_id": "unit-workload", "manifest_sha256": "6" * 64}
        identity = {"attempt_id": "7" * 32, "job_name": "LocalControl.v120.Job.fixture",
                    "profile_name": "LocalControl.v120.a.fixture"}
        parent = {"path": _FIXTURE_PARENT, "volume": 1, "file_id": 2,
                  "acl_sha256": "8" * 64}
        marker = runner._create_owner_marker(
            payload, workload, identity, "launch-001", "preflight-001", "9" * 64, parent
        )
        claim = {key: value for key, value in marker.items() if key != "mac"}
        claim["owner_marker"] = marker
        self.assertEqual(runner._verify_owner_marker(claim)["subject_parent_snapshot"], parent)
        altered = dict(marker, task_id="different-task")
        with self.assertRaises(RunnerError):
            runner._verify_owner_marker(dict(claim, owner_marker=altered))

    def test_cleanup_does_not_claim_unproven_partial_recovery(self):
        attempt_id = "c" * 32
        claim = {"attempt_id": attempt_id, "profile_name": "LocalControl.v120.a.fixture"}

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
        runner._owned_event = lambda _attempt_id, **_context: (claim, None)
        runner._get_broker = lambda: Broker()
        runner.ledger = Ledger()
        runner.clock = lambda: 1
        runner.lock = threading.RLock()
        runner.live = {}
        with self.assertRaises(RunnerError):
            runner.cleanup(attempt_id)
        self.assertEqual([event["kind"] for event in runner.ledger.events], ["failed"])


    def test_environment_block_uses_nuls_and_rejects_embedded_nuls(self):
        environment = {"TEMP": r"C:\worker\tmp", "PATH": r"C:\runtime"}
        block = _environment_block(environment)
        self.assertEqual(
            block.split("\x00"),
            [r"PATH=C:\runtime", r"TEMP=C:\worker\tmp", "", ""],
        )
        self.assertNotIn(r"\0", block)
        self.assertFalse(_valid_worker_environment({"TOKEN": "prefix\x00suffix"}))
        self.assertFalse(_valid_worker_environment({"BAD\x00KEY": "value"}))
        self.assertFalse(_valid_worker_environment({"Path": "a", "PATH": "b"}))
        self.assertFalse(_valid_spawn_argv(["worker.exe", "bad\x00arg"]))
        self.assertTrue(_valid_spawn_argv(["worker.exe", r"literal\0"]))
        with self.assertRaises(ValueError):
            _environment_block({"TEMP": "bad\x00value"})


    def test_preflight_binding_digest_covers_scope_candidate_workload_registry_and_request(self):
        payload = {
            "task_id": "integration-task",
            "scope_id": "scope-001",
            "scope_revision": 2,
            "candidate_identity": {"kind": "git", "commit": "1" * 40, "tree": "2" * 40},
            "worker": {"runner_policy_sha256": "a" * 64, "subject_parent": _FIXTURE_PARENT},
        }
        workload = {
            "workload_id": "unit-workload",
            "manifest_sha256": "b" * 64,
            "planned_bytes": 4096,
        }
        registry = {
            "revision": 3,
            "snapshot_sha256": "c" * 64,
            "signed_file_sha256": "d" * 64,
            "task_scope_signature_sha256": "e" * 64,
        }
        baseline = _preflight_request_binding_sha256("request-001", payload, workload, registry)
        changed_payload = dict(payload)
        changed_payload["candidate_identity"] = dict(payload["candidate_identity"], tree="f" * 40)
        changed_scope = dict(payload, scope_revision=3)
        changed_workload = dict(workload, planned_bytes=8192)
        changed_manifest = dict(workload, manifest_sha256="f" * 64)
        changed_registry = dict(registry, revision=4)
        for request_id, scope, work, binding in (
            ("request-002", payload, workload, registry),
            ("request-001", changed_payload, workload, registry),
            ("request-001", changed_scope, workload, registry),
            ("request-001", payload, changed_workload, registry),
            ("request-001", payload, changed_manifest, registry),
            ("request-001", payload, workload, changed_registry),
        ):
            with self.subTest(request_id=request_id, scope=scope["scope_revision"],
                              planned_bytes=work["planned_bytes"]):
                self.assertNotEqual(
                    _preflight_request_binding_sha256(request_id, scope, work, binding),
                    baseline,
                )


    def test_safe_attempt_operations_require_current_task_and_candidate(self):
        runner = object.__new__(TaskOnlyRunner)
        runner.registry_key = _KEY
        scope_key = hmac.new(
            _KEY, b"LocalControl/v1.2/task-scope", hashlib.sha256
        ).digest()
        candidate = {"kind": "git", "commit": "1" * 40, "tree": "2" * 40}
        identity_args = {
            "scope_key": scope_key,
            "scope_id": "scope-" + "a" * 16,
            "task_id": "integration-task",
            "workload_id": "unit-workload",
            "launch_request_id": "launch-001",
            "scope_revision": 1,
            "candidate_identity": candidate,
            "registry_revision": 3,
            "registry_sha256": "3" * 64,
            "registry_file_sha256": "4" * 64,
            "preflight_receipt_sha256": "5" * 64,
        }
        identity = derive_attempt_identity(**identity_args)
        claim = {
            "kind": "claimed",
            "attempt_id": identity["attempt_id"],
            "scope_id": identity_args["scope_id"],
            "task_id": identity_args["task_id"],
            "workload_id": identity_args["workload_id"],
            "launch_request_id": identity_args["launch_request_id"],
            "scope_revision": identity_args["scope_revision"],
            "candidate_identity": candidate,
            "registry_revision": identity_args["registry_revision"],
            "registry_sha256": identity_args["registry_sha256"],
            "registry_file_sha256": identity_args["registry_file_sha256"],
            "preflight_receipt_sha256": identity_args["preflight_receipt_sha256"],
            "job_name": identity["job_name"],
            "profile_name": identity["profile_name"],
            "worker_scope_sha256": "6" * 64,
            "runner_policy_sha256": "7" * 64,
        }

        class Ledger:
            def for_attempt(self, _attempt_id):
                return [claim]
            def latest(self, _attempt_id):
                return {"kind": "interrupted", "attempt_id": claim["attempt_id"]}

        runner.ledger = Ledger()
        runner._verify_owner_marker = lambda _claim: None
        args = {"attempt_id": identity["attempt_id"]}
        with self.assertRaises(RunnerError) as raised:
            runner.call("task_worker_observe", args)
        self.assertEqual(raised.exception.code, "V120_TASK_BINDING_REQUIRED")
        with self.assertRaises(RunnerError) as raised:
            runner.call("task_worker_observe", args, expected_task_id="another-task",
                        expected_candidate_identity=candidate)
        self.assertEqual(raised.exception.code, "V120_ATTEMPT_TASK_MISMATCH")
        changed_candidate = dict(candidate, tree="8" * 40)
        with self.assertRaises(RunnerError) as raised:
            runner.call("task_worker_observe", args, expected_task_id="integration-task",
                        expected_candidate_identity=changed_candidate)
        self.assertEqual(raised.exception.code, "V120_ATTEMPT_CANDIDATE_MISMATCH")

        result = runner.call(
            "task_worker_observe", args, expected_task_id="integration-task",
            expected_candidate_identity=candidate,
        )
        self.assertEqual(result["status"], "interrupted")


    def test_signing_and_job_acls_reject_untrusted_principals_and_owner_drift(self):
        self.assertEqual(_validate_acl_ace_header(b"\x00\x00\x10\x00"), (0, 0, 16))
        for header in (b"\x05\x00\x18\x00", b"\x00\x00\x08\x00", b"\x00\x00"):
            with self.subTest(header=header), self.assertRaises(RunnerError):
                _validate_acl_ace_header(header)
        allowed = {b"system", b"admins", b"operator"}
        exact = [
            (0, 0, 0x10000000, b"system"),
            (0, 0, 0x10000000, b"admins"),
            (0, 0, 0x10000000, b"operator"),
        ]
        self.assertEqual(
            _validate_acl_entries(
                b"operator", exact, allowed, exact_allow_mask=0x10000000,
                expected_allow_sids=allowed, allow_deny_aces=False,
            ),
            allowed,
        )
        invalid = [
            (b"operator", [(0, 0, 0x10000000, b"foreign")]),
            (b"foreign", exact),
            (b"operator", [(0, 0x10, 0x10000000, b"operator")]),
            (b"operator", [(5, 0, 0x10000000, b"operator")]),
            (b"operator", [(0, 0, 0x00000001, b"operator")]),
            (b"operator", exact[:-1]),
        ]
        for owner, entries in invalid:
            with self.subTest(owner=owner, entries=entries):
                with self.assertRaises(RunnerError):
                    _validate_acl_entries(
                        owner, entries, allowed, exact_allow_mask=0x10000000,
                        expected_allow_sids=allowed, allow_deny_aces=False,
                    )

    def test_monitor_survives_one_transient_scope_read_error(self):
        class WaitSequence:
            def __init__(self):
                self.results = iter((False, False, True))
            def wait(self, _timeout):
                return next(self.results)

        runner = object.__new__(TaskOnlyRunner)
        runner.closed = WaitSequence()
        runner.lock = threading.RLock()
        runner.live = {}
        calls = []
        def scope():
            calls.append(None)
            if len(calls) == 1:
                raise OSError("temporary scope read failure")
            return {}
        runner._scope = scope
        runner._monitor()
        self.assertEqual(len(calls), 2)

    def test_monitor_stops_when_attempt_ledger_cannot_be_read(self):
        attempt_id = "e" * 32

        class WaitSequence:
            def __init__(self):
                self.results = iter((False, False, False, True))
            def wait(self, _timeout):
                return next(self.results)

        class Ledger:
            def __init__(self):
                self.events = []
            def latest(self, _attempt_id):
                raise OSError("attempt ledger temporarily unavailable")
            def append(self, event):
                self.events.append(event)

        class Job:
            def __init__(self):
                self.stops = 0
            def stop(self):
                self.stops += 1
            def stats(self):
                return {"active_processes": 0}

        job = Job()
        ledger = Ledger()
        runner = object.__new__(TaskOnlyRunner)
        runner.closed = WaitSequence()
        runner.lock = threading.RLock()
        runner.live = {attempt_id: (None, job)}
        runner.ledger = ledger
        runner.clock = lambda: 123
        def scope_unavailable():
            raise OSError("scope unavailable")
        runner._scope = scope_unavailable
        runner._monitor()
        self.assertEqual(job.stops, 1)
        self.assertEqual(
            [event["kind"] for event in ledger.events],
            ["cancellation_pending", "cancelled_by_authority"],
        )
        self.assertTrue(all(
            event["reason"] == "attempt_ledger_unavailable" for event in ledger.events
        ))

    def test_shutdown_records_pending_and_failed_cancellation(self):
        attempt_id = "d" * 32

        class Ledger:
            def __init__(self):
                self.events = []
                self.closed = False
            def latest(self, _attempt_id):
                return {"kind": "running"}
            def append(self, event):
                self.events.append(event)
            def close(self):
                self.closed = True

        class Job:
            def __init__(self):
                self.closed = False
            def stop(self):
                raise OSError("stop failed")
            def close(self):
                self.closed = True

        runner = object.__new__(TaskOnlyRunner)
        runner.closed = threading.Event()
        runner.monitor = None
        runner.lock = threading.RLock()
        runner.lifecycle = threading.Condition(runner.lock)
        runner.inflight=set();runner.admitting=set();runner.cancelled=set()
        runner.live = {attempt_id: (None, Job())}
        runner.ledger = Ledger()
        runner.clock = lambda: 123
        job = runner.live[attempt_id][1]
        with self.assertRaisesRegex(RunnerError,'V120_SHUTDOWN_PENDING'):
            runner.close()
        self.assertEqual(
            [event["kind"] for event in runner.ledger.events],
            ["cancellation_pending", "cancellation_failed"],
        )
        self.assertEqual(
            runner.ledger.events[-1]["reason"], "runner_shutdown_stop_failed"
        )
        self.assertFalse(job.closed)
        self.assertFalse(runner.ledger.closed)
        self.assertIn(attempt_id,runner.live)


if __name__ == "__main__":
    unittest.main()
