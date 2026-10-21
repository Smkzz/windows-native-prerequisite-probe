import hashlib
import hmac
import json
import sqlite3
import threading
import time
import unittest
import tempfile
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from tests.project_fixtures import ProjectTemporaryDirectory

from localcontrol.errors import ControlError
from localcontrol.v120_api import (
    V120API, RUNNER_POLICY_SHA256, _SCOPE_DOMAIN, _SCOPE_ENVELOPE,
    _SCOPE_SCHEMA, _decode_task_scope,
)
from localcontrol.v120_authority import ScopeAuthorityLedger
from localcontrol.v120_preflight import (
    GIB, POLICY_DOCUMENT, POLICY_SHA256, TELEMETRY_SOURCE,
    ReceiptLedger, TelemetryError, evaluate_preflight, sign_receipt,
    verify_signed_receipt,
)


def healthy_sample(**overrides):
    now = time.monotonic_ns()
    sample = {
        "source": TELEMETRY_SOURCE,
        "sampled_at_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "sampled_monotonic_ns": now,
        "sample_started_monotonic_ns": now - 1_000_000,
        "physical_total_bytes": 32 * GIB,
        "available_bytes": 10 * GIB,
        "committed_bytes": 40 * GIB,
        "commit_limit_bytes": 50 * GIB,
        "c_free_bytes": 18 * GIB,
        "c_total_free_bytes": 20 * GIB,
        "c_total_bytes": 100 * GIB,
        "page_size_bytes": 4096,
    }
    sample.update(overrides)
    return sample


def evaluate(sample=None, **kwargs):
    reader = kwargs.pop("telemetry_reader", None)
    if reader is None:
        reader = (lambda: healthy_sample()) if sample is None else (lambda: sample)
    return evaluate_preflight(
        "AI-COMPANY-INTEGRATION-20261011-INC1",
        "focused-unit",
        {"kind": "git", "commit": "1" * 40, "tree": "2" * 40},
        2 * GIB,
        telemetry_reader=reader,
        **kwargs,
    )


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


class FakeRegistry:
    def __init__(self, path, revision=7):
        self.path = Path(path)
        if not self.path.is_file():
            raise AssertionError("fixture file must already exist")
        self.revision = revision
        self.snapshot_sha256 = "a" * 64

    def load(self):
        return SimpleNamespace(revision=self.revision, sha256=self.snapshot_sha256)


class V120Fixture(unittest.TestCase):
    def setUp(self):
        # These are signature/receipt/file-backed lifecycle logic tests. The
        # real native Q gates exercise ancestor inspection and protected ACLs;
        # the enrolled AppContainer cannot inspect the C: volume root.
        from unittest.mock import patch
        inspection = patch('localcontrol.v120_api.no_links')
        inspection.start()
        self.addCleanup(inspection.stop)
        self.root = Path(__file__).parent
        self.fixture = ProjectTemporaryDirectory(prefix='.phaseb-v120-', dir=self.root)
        self.state = Path(self.fixture.name)
        self.config = Path(__file__)
        self.registry = FakeRegistry(self.config)
        self.key = bytes(range(32))
        self.policy = SimpleNamespace(state_dir=self.state, max_active_jobs=4)
        self.clock_value = datetime.now(timezone.utc).replace(microsecond=0)
        self.monotonic_value = time.monotonic_ns()
        self.apis = []
        self.workloads = [{
            "workload_id": "focused-unit", "planned_bytes": 2 * GIB,
            "manifest_sha256": "5" * 64,
            "resource_limits": {"memory_bytes": 512 * 1024 * 1024, "max_processes": 8, "cpu_ms": 600_000},
        }]
        profile_root = str(Path.home())
        self.worker = {
            "subject_parent": str(self.root / "disposable-subjects"),
            "runtime_roots": [str(self.root / "runtime-source")],
            "canonical_readonly_roots": [
                str(self.root / "kernel-source"),
                str(self.root / "console-source"),
                str(self.root / "supervisor-source"),
            ],
            "protected_roots": [
                str(self.state), str(self.config),
                str(self.root / "evaluator"), str(self.root / "installed-localcontrol"),
                str(self.root / "controller-source"), profile_root,
                str(Path(profile_root) / ".codex"),
            ],
            "controller_root": str(self.root / "controller-source"),
            "evaluator_root": str(self.root / "evaluator"),
            "user_profile_root": profile_root,
            "credential_roots": [str(Path(profile_root) / ".codex")],
            "network_enabled": False,
            "capabilities": [],
            "credential_mode": "none",
            "runner_policy_sha256": RUNNER_POLICY_SHA256,
        }

    def signed_scope(self, *, worker=None, task_id="AI-COMPANY-INTEGRATION-20261011-INC1",
                    workloads=None, signature_override=None, ttl=timedelta(minutes=30),
                    issued_at=None, scope_id="phaseb-" + "b" * 16, revision=1):
        now = self.clock_value if issued_at is None else issued_at
        payload = {
            "schema": _SCOPE_SCHEMA,
            "scope_id": scope_id,
            "scope_revision": revision,
            "task_id": task_id,
            "candidate_identity": {"kind": "git", "commit": "3" * 40, "tree": "4" * 40},
            "workloads": self.workloads if workloads is None else workloads,
            "registry_revision": self.registry.revision,
            "registry_sha256": self.registry.snapshot_sha256,
            "registry_file_sha256": hashlib.sha256(self.registry.path.read_bytes()).hexdigest(),
            "worker": self.worker if worker is None else worker,
            "issued_at_utc": now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "expires_at_utc": (now + ttl).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        }
        scope_key = hmac.new(self.key, _SCOPE_DOMAIN, hashlib.sha256).digest()
        signature = {
            "algorithm": "HMAC-SHA256",
            "key_id": hashlib.sha256(scope_key).hexdigest()[:16],
            "hmac_sha256": hmac.new(scope_key, canonical(payload), hashlib.sha256).hexdigest(),
        }
        if signature_override is not None:
            signature["hmac_sha256"] = signature_override
        return {"schema": _SCOPE_ENVELOPE, "payload": payload, "signature": signature}, payload

    def make_api(self, telemetry_reader=lambda: healthy_sample(), *, worker=None,
                 task_id="AI-COMPANY-INTEGRATION-20261011-INC1", signature_override=None,
                 ttl=timedelta(minutes=30), issued_at=None):
        import uuid
        scope_dir = self.state / 'v120'
        scope_dir.mkdir(exist_ok=True)
        authority = ScopeAuthorityLedger(scope_dir / 'authority-ledger.sqlite3', self.key)
        prior = authority.latest_for_task(task_id)
        revision = 1 if prior is None else prior['revision'] + 1
        if prior is not None:
            previous_time=datetime.fromisoformat(prior['issued_at_utc'].replace('Z','+00:00'))
            self.clock_value=max(self.clock_value, previous_time+timedelta(microseconds=1))
        envelope, payload = self.signed_scope(
            worker=worker, task_id=task_id, signature_override=signature_override,
            ttl=ttl, issued_at=issued_at,
            revision=revision, scope_id='phaseb-'+uuid.uuid4().hex[:16],
        )
        raw = canonical(envelope)
        scope_dir = self.state / "v120"
        scope_dir.mkdir(exist_ok=True)
        scope_path = scope_dir / "task-scope.json"
        scope_path.write_bytes(raw)
        try:
            authority.record_issue(
                task_id=payload["task_id"], scope_id=payload["scope_id"], revision=payload["scope_revision"],
                issued_at_utc=payload["issued_at_utc"], envelope_sha256=hashlib.sha256(raw).hexdigest(),
            )
        finally:authority.close()
        return self.open_api(telemetry_reader)

    def open_api(self, telemetry_reader=lambda: healthy_sample()):
        api = V120API(
            self.policy, "test-principal", self.config, {"enabled": True},
            registry_store=self.registry, registry_key=self.key,
            telemetry_reader=telemetry_reader, clock=lambda: self.clock_value,
            monotonic_clock=lambda: self.monotonic_value,
            start_runner_monitor=False,
        )
        self.apis.append(api)
        return api

    def tearDown(self):
        for api in self.apis:
            api.close()
        self.fixture.cleanup()


class PreflightThresholdTests(unittest.TestCase):
    def test_all_thresholds_admit_at_inclusive_reserves(self):
        # 6 GiB remains free after the planned 2 GiB workload in both dimensions.
        # A 32 GiB commit limit also keeps forecast commit below the 85% ceiling.
        receipt = evaluate(healthy_sample(
            available_bytes=8 * GIB, committed_bytes=24 * GIB,
            commit_limit_bytes=32 * GIB,
        ))
        self.assertEqual(receipt["decision"], "ADMIT")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertTrue(all(receipt["comparisons"].values()))
        self.assertEqual(receipt["measurements"]["available_after_bytes"], 6 * GIB)
        self.assertEqual(receipt["measurements"]["commit_headroom_after_bytes"], 6 * GIB)
        self.assertEqual(receipt["telemetry"]["raw"]["c_total_free_bytes"], 20 * GIB)
        self.assertTrue(receipt["comparisons"]["forecast_commit_lt_85_percent"])

    def test_available_reserve_below_by_one_byte_defers(self):
        receipt = evaluate(healthy_sample(available_bytes=8 * GIB - 1))
        self.assertEqual((receipt["decision"], receipt["exit_code"]), ("DEFER", 75))
        self.assertFalse(receipt["comparisons"]["available_after_gte_6_gib"])

    def test_commit_reserve_below_by_one_byte_defers(self):
        receipt = evaluate(healthy_sample(committed_bytes=24 * GIB + 1, commit_limit_bytes=32 * GIB))
        self.assertEqual(receipt["decision"], "DEFER")
        self.assertFalse(receipt["comparisons"]["commit_headroom_after_gte_6_gib"])

    def test_forecast_at_exactly_85_percent_defers(self):
        receipt = evaluate(healthy_sample(committed_bytes=40 * GIB + GIB // 2))
        self.assertEqual(receipt["decision"], "DEFER")
        self.assertFalse(receipt["comparisons"]["forecast_commit_lt_85_percent"])

    def test_volume_free_space_boundary_uses_actual_volume_free(self):
        passing = evaluate(healthy_sample(c_free_bytes=18 * GIB, c_total_free_bytes=20 * GIB))
        failing = evaluate(healthy_sample(c_free_bytes=18 * GIB, c_total_free_bytes=20 * GIB - 1))
        self.assertEqual(passing["decision"], "ADMIT")
        self.assertEqual(failing["decision"], "DEFER")
        self.assertFalse(failing["comparisons"]["c_free_gte_20_gib"])

    def test_missing_or_denied_telemetry_fails_closed(self):
        missing = evaluate({"source": TELEMETRY_SOURCE})
        denied = evaluate(telemetry_reader=lambda: (_ for _ in ()).throw(TelemetryError("TELEMETRY_DISK_DENIED")))
        self.assertEqual(missing["decision"], "ERROR")
        self.assertEqual(missing["error"]["code"], "TELEMETRY_MISSING_FIELD")
        self.assertEqual(denied["decision"], "ERROR")
        self.assertEqual(denied["exit_code"], 1)

    def test_malformed_or_stale_sample_fails_closed(self):
        malformed = evaluate(healthy_sample(source="caller supplied counters"))
        stale_ns = time.monotonic_ns() - 11_000_000_000
        stale = evaluate(healthy_sample(sampled_monotonic_ns=stale_ns, sample_started_monotonic_ns=stale_ns - 1_000_000))
        self.assertEqual(malformed["error"]["code"], "TELEMETRY_INVALID_SOURCE")
        self.assertEqual(stale["error"]["code"], "TELEMETRY_STALE")

    def test_malformed_estimate_and_policy_mismatch_fail_before_telemetry(self):
        called = []
        reader = lambda: called.append(True) or healthy_sample()
        base = (
            "AI-COMPANY-INTEGRATION-20261011-INC1", "focused-unit",
            {"kind": "git", "commit": "1" * 40, "tree": "2" * 40},
        )
        bad_estimate = evaluate_preflight(*base, True, telemetry_reader=reader)
        wrong_policy = evaluate_preflight(
            *base, 2 * GIB, telemetry_reader=reader, expected_policy_sha256="0" * 64
        )
        too_large = evaluate_preflight(*base, POLICY_DOCUMENT["max_planned_bytes"] + 1,
                                       telemetry_reader=reader)
        self.assertEqual(bad_estimate["decision"], "ERROR")
        self.assertIn("PLANNED_BYTES_INVALID", bad_estimate["reasons"])
        self.assertIn("POLICY_IDENTITY_MISMATCH", wrong_policy["reasons"])
        self.assertIn("PLANNED_BYTES_INVALID", too_large["reasons"])
        self.assertEqual(called, [])

    def test_candidate_identity_types_fail_closed(self):
        receipt = evaluate_preflight(
            "AI-COMPANY-INTEGRATION-20261011-INC1", "focused-unit",
            {"kind": "git", "commit": 123, "tree": "2" * 40}, 2 * GIB,
            telemetry_reader=lambda: healthy_sample(),
        )
        self.assertEqual(receipt["error"]["code"], "CANDIDATE_IDENTITY_INVALID")


class ReceiptTests(unittest.TestCase):
    def test_receipt_signature_detects_tampering_and_wrong_key(self):
        key = bytes(range(32))
        signed = sign_receipt(evaluate(), key)
        self.assertTrue(verify_signed_receipt(signed, key))
        self.assertFalse(verify_signed_receipt(signed, b"x" * 32))
        altered = dict(signed)
        altered["decision"] = "ADMIT" if signed["decision"] != "ADMIT" else "DEFER"
        self.assertFalse(verify_signed_receipt(altered, key))

    def test_ledger_is_append_only_and_detects_row_tampering(self):
        key = b"k" * 32
        ledger = ReceiptLedger(":memory:", key)
        signed = ledger.append(evaluate())
        self.assertTrue(verify_signed_receipt(signed, key))
        self.assertTrue(ledger.verify())
        with self.assertRaises(sqlite3.DatabaseError):
            ledger.db.execute("UPDATE receipts SET receipt_json='{}' WHERE sequence=1")
        ledger.db.execute("DROP TRIGGER receipts_no_update")
        ledger.db.execute("UPDATE receipts SET receipt_json='{}' WHERE sequence=1")
        with self.assertRaises(TelemetryError) as err:
            ledger.verify()
        self.assertEqual(err.exception.code, "PREFLIGHT_LEDGER_CORRUPT")
        ledger.close()



    def test_receipt_ledger_supports_cross_thread_append_and_lookup(self):
        key = b"t" * 32
        ledger = ReceiptLedger(":memory:", key)
        receipt = evaluate()
        receipt["request_id"] = "preflight-thread-001"
        receipt["request_binding_sha256"] = "c" * 64
        results = []
        errors = []

        def use_ledger_from_worker():
            try:
                appended = ledger.append(receipt)
                looked_up = ledger.get_by_request_id("preflight-thread-001")
                results.append(appended == looked_up)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=use_ledger_from_worker)
        try:
            worker.start()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive(), "ledger worker thread did not finish")
            self.assertEqual(errors, [])
            self.assertEqual(results, [True])
            self.assertTrue(ledger.verify())
        finally:
            if worker.is_alive():
                worker.join(timeout=1)
            ledger.close()

    def test_request_id_replay_requires_identical_full_binding_digest(self):
        key = b"r" * 32
        ledger = ReceiptLedger(":memory:", key)
        try:
            receipt = evaluate()
            receipt["request_id"] = "preflight-replay-001"
            receipt["request_binding_sha256"] = "a" * 64
            original = ledger.append(receipt)
            retry = dict(receipt)
            retry["measurements"] = {"available_after_bytes": -1}
            self.assertEqual(ledger.append(retry), original)

            altered = dict(receipt)
            altered["request_binding_sha256"] = "b" * 64
            with self.assertRaises(TelemetryError) as raised:
                ledger.append(altered)
            self.assertEqual(raised.exception.code, "PREFLIGHT_REQUEST_REPLAY")

            missing = evaluate()
            missing["request_id"] = "preflight-replay-002"
            with self.assertRaises(TelemetryError) as raised:
                ledger.append(missing)
            self.assertEqual(raised.exception.code, "PREFLIGHT_REQUEST_BINDING_INVALID")
        finally:
            ledger.close()


class TaskScopeTests(V120Fixture):
    def test_signed_task_scope_pins_estimate_and_returns_signed_receipt(self):
        api = self.make_api()
        try:
            info = api.scope_info()
            self.assertEqual(info["task_id"], "AI-COMPANY-INTEGRATION-20261011-INC1")
            self.assertEqual(info["runner_status"], "SOURCE_IMPLEMENTED_OS_TESTS_PENDING")
            receipt = api.call("resource_preflight", "projects", {
                "task_id": info["task_id"], "workload_id": "focused-unit", "request_id": "req-001",
            })
            self.assertEqual(receipt["decision"], "ADMIT")
            self.assertEqual(receipt["workload"]["planned_bytes"], 2 * GIB)
            self.assertEqual(receipt["registry"]["revision"], 7)
            self.assertEqual(receipt["request_id"], "req-001")
            self.assertTrue(verify_signed_receipt(receipt, self.key))
            self.assertTrue(api.ledger.verify())
        finally:
            api.close()

    def test_task_or_workload_mismatch_is_rejected(self):
        api = self.make_api()
        try:
            with self.assertRaises(ControlError) as err:
                api.call("resource_preflight", "projects", {
                    "task_id": "OTHER-TASK", "workload_id": "focused-unit", "request_id": "req-002",
                })
            self.assertEqual(err.exception.code, "V120_TASK_MISMATCH")
            with self.assertRaises(ControlError) as err:
                api.call("resource_preflight", "projects", {
                    "task_id": "AI-COMPANY-INTEGRATION-20261011-INC1",
                    "workload_id": "not-pinned", "request_id": "req-003",
                })
            self.assertEqual(err.exception.code, "V120_WORKLOAD_UNKNOWN")
        finally:
            api.close()

    def test_registry_change_invalidates_scope(self):
        api = self.make_api()
        try:
            self.registry.revision += 1
            with self.assertRaises(ControlError) as err:
                api.scope_info()
            self.assertEqual(err.exception.code, "AUTHORITY_CHANGED")
        finally:
            api.close()

    def test_bad_signature_and_unsafe_worker_scope_fail_closed(self):
        envelope, _ = self.signed_scope(signature_override="0" * 64)
        with self.assertRaises(ControlError):
            _decode_task_scope(canonical(envelope), self.key)
        unsafe = dict(self.worker)
        unsafe["network_enabled"] = True
        with self.assertRaises(ControlError):
            self.make_api(worker=unsafe)
        unsafe = dict(self.worker)
        unsafe["subject_parent"] = str(Path(self.worker["canonical_readonly_roots"][0]) / "attempt")
        with self.assertRaises(ControlError):
            self.make_api(worker=unsafe)

    def test_scope_lifetime_is_bounded_and_future_issue_is_rejected(self):
        with self.assertRaises(ControlError) as err:
            self.make_api(ttl=timedelta(hours=2))
        self.assertEqual(err.exception.code, "V120_SCOPE_LIFETIME")
        with self.assertRaises(ControlError) as err:
            self.make_api(issued_at=self.clock_value + timedelta(seconds=1))
        self.assertEqual(err.exception.code, "V120_SCOPE_EXPIRED")

    def test_expiry_is_revalidated_after_initialization(self):
        api = self.make_api()
        try:
            self.clock_value = api.payload["expires_at_utc"]
            self.clock_value = datetime.fromisoformat(self.clock_value.replace("Z", "+00:00"))
            with self.assertRaises(ControlError) as err:
                api.call("task_scope_info", "projects", {})
            self.assertEqual(err.exception.code, "V120_SCOPE_EXPIRED")
        finally:
            api.close()

    def test_scope_file_change_after_initialization_is_rejected(self):
        api = self.make_api()
        try:
            api.scope_path.write_bytes(api.scope_path.read_bytes() + b" ")
            with self.assertRaises(ControlError) as err:
                api.scope_info()
            self.assertEqual(err.exception.code, "V120_SCOPE_CHANGED")
        finally:
            api.close()

    def test_persistent_revocation_blocks_live_and_restarted_api(self):
        api = self.make_api()
        api.authority.revoke(api.payload["scope_id"], self.clock_value.isoformat().replace("+00:00", "Z"))
        with self.assertRaises(ControlError) as err:
            api.scope_info()
        self.assertEqual(err.exception.code, "V120_SCOPE_REVOKED")
        api.close()
        with self.assertRaises(ControlError) as err:
            self.open_api()
        self.assertEqual(err.exception.code, "V120_SCOPE_REVOKED")

    def test_scope_replacement_requires_operator_issue_record_and_restart(self):
        api = self.make_api()
        api.close()
        replacement, _ = self.signed_scope(
            scope_id="phaseb-" + "c" * 16, revision=2, issued_at=self.clock_value,
        )
        (self.state / "v120" / "task-scope.json").write_bytes(canonical(replacement))
        with self.assertRaises(ControlError) as err:
            self.open_api()
        self.assertEqual(err.exception.code, "V120_SCOPE_STALE")


if __name__ == "__main__":
    unittest.main()
