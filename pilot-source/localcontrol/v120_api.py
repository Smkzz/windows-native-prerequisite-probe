"""LocalControl v1.2 task-bound memory preflight API.

This opt-in API accepts identifiers only. Candidate identity and workload estimates
come from the operator-signed task scope in protected LocalControl state.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import ntpath
import os
import re
from pathlib import Path
from typing import Callable

from .errors import require
from .nextlib.core import Rejected
from .v120_authority import ScopeAuthorityError, ScopeAuthorityLedger
from .policy import no_links
from .v120_preflight import (
    POLICY_SHA256,
    ReceiptLedger,
    TelemetryError,
    _candidate_error,
    _canonical,
    _valid_identifier,
    evaluate_preflight,
    read_windows_telemetry,
)

VERSION = "1.2.0"
OPTION_KEYS = frozenset({"enabled"})
V120_FIELDS = {
    "task_scope_info": set(),
    "resource_preflight": {"task_id", "workload_id", "request_id"},
    "task_worker_launch": {"task_id", "workload_id", "preflight_request_id", "launch_request_id", "request_id"},
    "task_worker_observe": {"attempt_id"},
    "task_worker_stop": {"attempt_id", "request_id"},
    "task_worker_recover": {"attempt_id", "request_id"},
    "task_worker_cleanup": {"attempt_id", "request_id"},
}
MUTATING_TOOLS = frozenset({
    "resource_preflight", "task_worker_launch", "task_worker_stop",
    "task_worker_recover", "task_worker_cleanup",
})
V120_SCHEMAS = {
    "task_scope_info": (
        "Report the active operator-signed task scope and pinned workload names.",
        {}, [],
    ),
    "resource_preflight": (
        "Evaluate one pinned workload estimate using trusted Windows telemetry; this operation never launches a command.",
        {"task_id": {"type": "string"}, "workload_id": {"type": "string"},
         "request_id": {"type": "string"}},
        ["task_id", "workload_id", "request_id"],
    ),
    "task_worker_launch": (
        "Launch only the task and pinned workload after a fresh admitted preflight receipt.",
        {"task_id": {"type": "string"}, "workload_id": {"type": "string"},
         "preflight_request_id": {"type": "string"},
         "launch_request_id": {"type": "string"}, "request_id": {"type": "string"}},
        ["task_id", "workload_id", "preflight_request_id", "launch_request_id", "request_id"],
    ),
    "task_worker_observe": (
        "Observe only one recorded task attempt by its opaque attempt identifier.",
        {"attempt_id": {"type": "string"}}, ["attempt_id"],
    ),
    "task_worker_stop": (
        "Stop only one recorded task attempt, including after its scope expires or is revoked.",
        {"attempt_id": {"type": "string"}, "request_id": {"type": "string"}}, ["attempt_id", "request_id"],
    ),
    "task_worker_recover": (
        "Recover only one recorded task attempt without resuming a process that was suspended at interruption.",
        {"attempt_id": {"type": "string"}, "request_id": {"type": "string"}}, ["attempt_id", "request_id"],
    ),
    "task_worker_cleanup": (
        "Clean up only a terminal attempt whose recorded path, ACL manifest, and job identity still match.",
        {"attempt_id": {"type": "string"}, "request_id": {"type": "string"}}, ["attempt_id", "request_id"],
    ),
}
_SCOPE_DOMAIN = b"LocalControl/v1.2/task-scope"
_SCOPE_ENVELOPE = "localcontrol-task-scope-envelope-v1"
_SCOPE_SCHEMA = "localcontrol-task-scope-v2"
_SCOPE_FIELDS = {
    "schema", "scope_id", "scope_revision", "task_id", "candidate_identity", "workloads",
    "registry_revision", "registry_sha256", "registry_file_sha256",
    "worker", "issued_at_utc", "expires_at_utc",
}
_WORKER_FIELDS = {
    "subject_parent", "runtime_roots", "canonical_readonly_roots", "protected_roots",
    "controller_root", "evaluator_root", "user_profile_root", "credential_roots",
    "network_enabled", "capabilities", "credential_mode", "runner_policy_sha256",
}
_WORKLOAD_FIELDS = {"workload_id", "planned_bytes", "manifest_sha256", "resource_limits"}
_LIMIT_FIELDS = {"memory_bytes", "max_processes", "cpu_ms"}
MAX_SCOPE_LIFETIME_SECONDS = 3600
MAX_PREFLIGHT_AGE_NS = 5_000_000_000
_HEX64 = re.compile(r"[0-9a-f]{64}")
_REQUEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")

RUNNER_POLICY = {
    "schema": "localcontrol-task-runner-policy-v1",
    "platform": "windows-appcontainer",
    "network_enabled": False,
    "capabilities": [],
    "shell": False,
    "environment": "explicit-no-inheritance",
    "inherited_handles": ["stdin", "stdout", "stderr"],
    "runtime": "signed-manifest-copy-read-execute-only",
    "identity": "unique-appcontainer-per-attempt",
    "job": "kill-on-close-cpu-memory-process-limits",
    "scope_recheck_seconds": 0.5,
    "cancellation_grace_seconds": 2,
    "preflight_max_age_ns": MAX_PREFLIGHT_AGE_NS,
    "maximum_scope_lifetime_seconds": MAX_SCOPE_LIFETIME_SECONDS,
    "output": "drained-sha256-and-byte-count-only",
}
RUNNER_POLICY_SHA256 = hashlib.sha256(_canonical(RUNNER_POLICY)).hexdigest()


def _inside(path: str, root: str) -> bool:
    try:
        return ntpath.commonpath((ntpath.normcase(path), ntpath.normcase(root))) == ntpath.normcase(root)
    except ValueError:
        return False


def _absolute_local_path(value) -> bool:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return False
    separator = chr(92)
    if value.startswith((separator * 2, separator + "?" + separator)):
        return False
    drive, tail = ntpath.splitdrive(value)
    if len(drive) != 2 or drive[1:] != ":" or not tail.startswith(separator):
        return False
    if "/" in value or ntpath.normcase(ntpath.normpath(value)) != ntpath.normcase(value):
        return False
    if any(ch in value for ch in ("*", "?", chr(34), chr(0))) or ":" in tail:
        return False
    parts = tail.split(separator)[1:]
    if any(not part or part in (".", "..") or part.endswith((" ", ".")) for part in parts):
        return False
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    return not any(part.split(".")[0].upper() in reserved for part in parts)
def _utc(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        return None
    return parsed


def _file_sha256(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with Path(path).open("rb") as stream:
            for block in iter(lambda: stream.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        raise TelemetryError("PREFLIGHT_SOURCE_INVALID") from None

def _require(condition, code):
    require(condition, code, code)


def _decode_task_scope(raw: bytes, registry_key: bytes) -> tuple[dict, str]:
    _require(isinstance(raw, bytes) and len(raw) <= 1_048_576, "V120_SCOPE_PATH")
    _require(isinstance(registry_key, bytes) and len(registry_key) == 32, "V120_KEY")
    try:
        outer = json.loads(raw)
    except (TypeError, ValueError, UnicodeDecodeError):
        _require(False, "V120_SCOPE_CORRUPT")
    _require(isinstance(outer, dict)
            and set(outer) == {"schema", "payload", "signature"}
            and outer["schema"] == _SCOPE_ENVELOPE, "V120_SCOPE_SCHEMA")
    payload, signature = outer["payload"], outer["signature"]
    _require(isinstance(payload, dict) and set(payload) == _SCOPE_FIELDS
            and payload.get("schema") == _SCOPE_SCHEMA, "V120_SCOPE_SCHEMA")
    _require(isinstance(signature, dict)
            and set(signature) == {"algorithm", "key_id", "hmac_sha256"}
            and signature.get("algorithm") == "HMAC-SHA256"
            and isinstance(signature.get("key_id"), str)
            and isinstance(signature.get("hmac_sha256"), str), "V120_SCOPE_SIGNATURE")
    scope_key = hmac.new(registry_key, _SCOPE_DOMAIN, hashlib.sha256).digest()
    expected = hmac.new(scope_key, _canonical(payload), hashlib.sha256).hexdigest()
    _require(hmac.compare_digest(signature["key_id"], hashlib.sha256(scope_key).hexdigest()[:16])
            and hmac.compare_digest(signature["hmac_sha256"], expected),
            "V120_SCOPE_SIGNATURE")
    return payload, hashlib.sha256(_canonical(signature)).hexdigest()


def _preflight_request_binding_sha256(
    request_id: str, payload: dict, workload: dict, registry: dict,
) -> str:
    binding = {
        "schema": "localcontrol-preflight-request-binding-v1",
        "request_id": request_id,
        "task_id": payload["task_id"],
        "workload_id": workload["workload_id"],
        "workload_manifest_sha256": workload["manifest_sha256"],
        "planned_bytes": workload["planned_bytes"],
        "candidate_identity": payload["candidate_identity"],
        "scope_id": payload["scope_id"],
        "scope_revision": payload["scope_revision"],
        "scope_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
        "worker_scope_sha256": hashlib.sha256(
            _canonical(payload["worker"])
        ).hexdigest(),
        "registry": registry,
        "preflight_policy_sha256": POLICY_SHA256,
        "runner_policy_sha256": payload["worker"]["runner_policy_sha256"],
    }
    return hashlib.sha256(_canonical(binding)).hexdigest()


class V120API:
    def __init__(
        self, policy, principal: str, config_path: Path, options: dict, *,
        registry_store, registry_key: bytes,
        telemetry_reader: Callable = read_windows_telemetry,
        clock: Callable = lambda: datetime.now(timezone.utc),
        monotonic_clock: Callable = __import__("time").monotonic_ns,
        runner=None, start_runner_monitor: bool = True, admission=None,
    ):
        _require(isinstance(options, dict) and set(options) == OPTION_KEYS
                and options.get("enabled") is True, "V120_CONFIG")
        _require(isinstance(registry_key, bytes) and len(registry_key) == 32, "V120_KEY")
        self.policy, self.principal = policy, principal
        self.config_path = Path(config_path)
        self.registry_store = registry_store
        self.registry_key = registry_key
        self.scope_key = hmac.new(registry_key, _SCOPE_DOMAIN, hashlib.sha256).digest()
        self.telemetry_reader = telemetry_reader
        self.clock, self.monotonic_clock = clock, monotonic_clock
        self.runner = runner
        base_state = Path(policy.state_dir)
        _require(base_state.is_dir(), "V120_STATE_PATH")
        no_links(base_state)
        self.state = base_state / "v120"
        self.state.mkdir(exist_ok=True)
        no_links(self.state)
        self.scope_path = self.state / "task-scope.json"
        self.authority = ScopeAuthorityLedger(self.state / "authority-ledger.sqlite3", registry_key)
        self.ledger = None
        try:
            self.payload, self.scope_signature_sha256, self.scope_file_sha256 = self._load_scope()
            self.scope_sha256 = hashlib.sha256(_canonical(self.payload)).hexdigest()
            self.ledger = ReceiptLedger(self.state / "preflight-ledger.sqlite3", registry_key)
            self._authorize_scope()
            self._assert_registry_binding()
            if self.runner is None:
                from .v120_runner import TaskOnlyRunner
                self.runner = TaskOnlyRunner(
                    self.state, self.registry_key,
                    scope_provider=self._authorize_scope,
                    registry_provider=self._assert_registry_binding,
                    preflight_ledger=self.ledger,
                    clock=lambda: self.clock().timestamp(),
                    monotonic_clock=self.monotonic_clock,
                    start_monitor=start_runner_monitor,
                    admission=admission, max_active_jobs=policy.max_active_jobs,
                )
        except BaseException:
            if self.ledger is not None:
                self.ledger.close()
            self.authority.close()
            raise

    def close(self) -> None:
        if self.runner is not None:
            self.runner.close()
        self.ledger.close()
        self.authority.close()

    def _load_scope(self) -> tuple[dict, str, str]:
        _require(self.scope_path.is_file() and not self.scope_path.is_symlink(), "V120_SCOPE_MISSING")
        stat_result = self.scope_path.stat()
        _require(stat_result.st_nlink == 1 and stat_result.st_size <= 1_048_576, "V120_SCOPE_PATH")
        try:
            raw = self.scope_path.read_bytes()
        except OSError:
            _require(False, "V120_SCOPE_CORRUPT")
        payload, signature_sha256 = _decode_task_scope(raw, self.registry_key)
        self._validate_payload(payload)
        return payload, signature_sha256, hashlib.sha256(raw).hexdigest()

    def _validate_payload(self, payload: dict) -> None:
        _require(_valid_identifier(payload.get("scope_id"))
                and _valid_identifier(payload.get("task_id"))
                and type(payload.get("scope_revision")) is int
                and payload["scope_revision"] >= 1, "V120_SCOPE_ID")
        _require(_candidate_error(payload.get("candidate_identity")) is None, "V120_CANDIDATE")
        _require(type(payload.get("registry_revision")) is int and payload["registry_revision"] >= 1,
                "V120_REGISTRY_BINDING")
        _require(isinstance(payload.get("registry_sha256"), str)
                and isinstance(payload.get("registry_file_sha256"), str)
                and _HEX64.fullmatch(payload["registry_sha256"]) is not None
                and _HEX64.fullmatch(payload["registry_file_sha256"]) is not None,
                "V120_REGISTRY_BINDING")
        now = self.clock()
        issued, expires = _utc(payload.get("issued_at_utc")), _utc(payload.get("expires_at_utc"))
        _require(issued is not None and expires is not None and issued <= now < expires,
                "V120_SCOPE_EXPIRED")
        _require((expires - issued).total_seconds() <= MAX_SCOPE_LIFETIME_SECONDS,
                "V120_SCOPE_LIFETIME")
        workloads = payload.get("workloads")
        _require(isinstance(workloads, list) and 1 <= len(workloads) <= 32, "V120_WORKLOADS")
        ids = []
        for workload in workloads:
            _require(isinstance(workload, dict)
                    and set(workload) == _WORKLOAD_FIELDS
                    and _valid_identifier(workload.get("workload_id"))
                    and type(workload.get("planned_bytes")) is int
                    and 1 <= workload["planned_bytes"] <= (128 << 30)
                    and isinstance(workload.get("manifest_sha256"), str)
                    and _HEX64.fullmatch(workload["manifest_sha256"]) is not None,
                    "V120_WORKLOADS")
            limits = workload.get("resource_limits")
            _require(isinstance(limits, dict) and set(limits) == _LIMIT_FIELDS
                    and all(type(value) is int and value >= 1 for value in limits.values())
                    and limits["memory_bytes"] >= (1 << 20)
                    and limits["memory_bytes"] <= (128 << 30)
                    and limits["max_processes"] <= 64
                    and limits["cpu_ms"] <= 24 * 3600 * 1000,
                    "V120_WORKLOADS")
            _require(workload['planned_bytes'] >= limits['memory_bytes'],
                     'V120_WORKLOAD_ESTIMATE')
            ids.append(workload["workload_id"])
        _require(len(ids) == len(set(ids)), "V120_WORKLOADS")

        worker = payload.get("worker")
        _require(isinstance(worker, dict) and set(worker) == _WORKER_FIELDS,
                "V120_WORKER_SCOPE")
        _require(_absolute_local_path(worker.get("subject_parent"))
                and isinstance(worker.get("runner_policy_sha256"), str)
                and _HEX64.fullmatch(worker["runner_policy_sha256"]) is not None
                and worker["runner_policy_sha256"] == RUNNER_POLICY_SHA256,
                "V120_WORKER_SCOPE")
        _require(worker.get("network_enabled") is False
                and worker.get("capabilities") == []
                and worker.get("credential_mode") == "none",
                "V120_WORKER_SCOPE")
        runtime = worker.get("runtime_roots")
        readonly = worker.get("canonical_readonly_roots")
        protected = worker.get("protected_roots")
        credentials = worker.get("credential_roots")
        _require(isinstance(runtime, list) and 1 <= len(runtime) <= 8
                and all(_absolute_local_path(value) for value in runtime)
                and isinstance(readonly, list) and 1 <= len(readonly) <= 16
                and all(_absolute_local_path(value) for value in readonly)
                and isinstance(protected, list) and 6 <= len(protected) <= 64
                and all(_absolute_local_path(value) for value in protected)
                and isinstance(credentials, list) and 1 <= len(credentials) <= 16
                and all(_absolute_local_path(value) for value in credentials),
                "V120_WORKER_SCOPE")
        controller = worker.get("controller_root")
        evaluator = worker.get("evaluator_root")
        profile = worker.get("user_profile_root")
        _require(all(_absolute_local_path(value)
                     for value in (controller, evaluator, profile)),
                "V120_WORKER_SCOPE")
        expected_profile = str(Path.home())
        _require(ntpath.normcase(profile) == ntpath.normcase(expected_profile),
                "V120_CREDENTIAL_HOME")
        configured_profile = os.environ.get("USERPROFILE")
        if configured_profile:
            _require(ntpath.normcase(profile) == ntpath.normcase(configured_profile),
                    "V120_CREDENTIAL_HOME")

        roots = (*readonly, *protected)
        _require(len({ntpath.normcase(value) for value in roots}) == len(roots)
                and len({ntpath.normcase(value) for value in runtime}) == len(runtime),
                "V120_WORKER_SCOPE")
        subject_parent = worker["subject_parent"]
        _require(not any(_inside(subject_parent, value) or _inside(value, subject_parent)
                         for value in (*readonly, *protected, *runtime)),
                "V120_WORKER_SCOPE")
        _require(not any(_inside(read, protected_root) or _inside(protected_root, read)
                         for read in readonly for protected_root in protected),
                "V120_WORKER_SCOPE")
        _require(not any(_inside(read, runtime_root) or _inside(runtime_root, read)
                         for read in readonly for runtime_root in runtime),
                "V120_WORKER_SCOPE")

        required_protected = [
            str(self.policy.state_dir), str(self.config_path),
            str(self.registry_store.path), controller, evaluator, profile, *credentials,
        ]
        _require(all(any(_inside(required, root) for root in protected)
                     for required in required_protected),
                "V120_PROTECTED_ROOTS")

    def _authorize_scope(self) -> dict:
        payload, signature_sha256, file_sha256 = self._load_scope()
        _require(hmac.compare_digest(file_sha256, self.scope_file_sha256)
                and hmac.compare_digest(signature_sha256, self.scope_signature_sha256)
                and hmac.compare_digest(hashlib.sha256(_canonical(payload)).hexdigest(), self.scope_sha256),
                "V120_SCOPE_CHANGED")
        try:
            self.authority.authorize(payload, file_sha256)
        except ScopeAuthorityError as exc:
            _require(False, exc.code)
        self.payload = payload
        return payload

    def _assert_registry_binding(self) -> dict:
        try:
            snapshot = self.registry_store.load()
            raw = self.registry_store.path.read_bytes()
        except (OSError, ValueError):
            _require(False, "AUTHORITY_CHANGED")
        snapshot_sha = snapshot.sha256
        file_sha = hashlib.sha256(raw).hexdigest()
        _require(snapshot.revision == self.payload["registry_revision"]
                and hmac.compare_digest(snapshot_sha, self.payload["registry_sha256"])
                and hmac.compare_digest(file_sha, self.payload["registry_file_sha256"]),
                "AUTHORITY_CHANGED")
        return {
            "revision": snapshot.revision,
            "snapshot_sha256": snapshot_sha,
            "signed_file_sha256": file_sha,
            "task_scope_signature_sha256": self.scope_signature_sha256,
        }

    def _workload(self, workload_id: str) -> dict:
        for item in self.payload["workloads"]:
            if item["workload_id"] == workload_id:
                return item
        _require(False, "V120_WORKLOAD_UNKNOWN")

    def scope_info(self) -> dict:
        self._authorize_scope()
        binding = self._assert_registry_binding()
        return {
            "version": VERSION,
            "scope_id": self.payload["scope_id"],
            "scope_revision": self.payload["scope_revision"],
            "issued_at_utc": self.payload["issued_at_utc"],
            "expires_at_utc": self.payload["expires_at_utc"],
            "max_lifetime_seconds": MAX_SCOPE_LIFETIME_SECONDS,
            "task_id": self.payload["task_id"],
            "candidate_identity": self.payload["candidate_identity"],
            "workloads": [{"workload_id": x["workload_id"],
                           "planned_bytes": x["planned_bytes"]}
                          for x in self.payload["workloads"]],
            "task_scope_sha256": self.scope_sha256,
            "registry": binding,
            "worker": {
                "network_enabled": False,
                "capabilities": [],
                "credential_mode": "none",
                "subject_parent_sha256": hashlib.sha256(
                    self.payload["worker"]["subject_parent"].casefold().encode("utf-8")
                ).hexdigest(),
                "runner_policy_sha256": self.payload["worker"]["runner_policy_sha256"],
            },
            "runner_status": "SOURCE_IMPLEMENTED_OS_TESTS_PENDING",
        }

    def call(self, tool: str, project, args: dict) -> dict:
        safe_after_expiry = {
            "task_worker_observe", "task_worker_stop",
            "task_worker_recover", "task_worker_cleanup",
        }
        if tool in safe_after_expiry:
            _require(tool in V120_FIELDS and isinstance(args, dict)
                    and set(args) == V120_FIELDS[tool], "INVALID_ARGUMENT")
            _require(self.runner is not None, "V120_RUNNER_UNAVAILABLE")
            try:
                return self.runner.call(
                    tool, args, expected_task_id=self.payload["task_id"],
                    expected_candidate_identity=self.payload["candidate_identity"],
                )
            except Exception as exc:
                raise Rejected(getattr(exc, "code", "V120_RUNNER_ERROR")) from None

        self._authorize_scope()
        if tool == "task_scope_info":
            return self.scope_info()
        if tool == "task_worker_launch":
            _require(isinstance(args, dict) and set(args) == V120_FIELDS[tool],
                    "INVALID_ARGUMENT")
            _require(self.runner is not None, "V120_RUNNER_UNAVAILABLE")
            try:
                return self.runner.call(tool, args)
            except Exception as exc:
                raise Rejected(getattr(exc, "code", "V120_RUNNER_ERROR")) from None
        _require(tool == "resource_preflight", "INVALID_ARGUMENT")
        _require(isinstance(args, dict) and set(args) == V120_FIELDS[tool],
                "INVALID_ARGUMENT")
        request_id = args.get("request_id")
        _require(isinstance(request_id, str) and _REQUEST.fullmatch(request_id) is not None,
                "INVALID_REQUEST_ID")
        _require(args.get("task_id") == self.payload["task_id"], "V120_TASK_MISMATCH")
        workload = self._workload(args.get("workload_id"))
        registry = self._assert_registry_binding()
        receipt = evaluate_preflight(
            self.payload["task_id"], workload["workload_id"],
            self.payload["candidate_identity"], workload["planned_bytes"],
            telemetry_reader=self.telemetry_reader,
            expected_policy_sha256=POLICY_SHA256,
            registry=registry,
        )
        receipt["request_id"] = request_id
        receipt["task_scope"] = {
            "scope_id": self.payload["scope_id"],
            "sha256": self.scope_sha256,
            "worker_scope_sha256": hashlib.sha256(_canonical(self.payload["worker"])).hexdigest(),
        }
        receipt["request_binding_sha256"] = _preflight_request_binding_sha256(
            request_id, self.payload, workload, registry
        )
        from . import v120_authority, v120_preflight, v120_runner
        control_files = {
            "preflight_module_sha256": _file_sha256(Path(v120_preflight.__file__)),
            "api_module_sha256": _file_sha256(Path(__file__)),
            "facade_module_sha256": _file_sha256(Path(__file__).with_name("facade.py")),
            "server_module_sha256": _file_sha256(Path(__file__).with_name("server.py")),
            "runner_module_sha256": _file_sha256(Path(v120_runner.__file__)),
            "authority_module_sha256": _file_sha256(Path(v120_authority.__file__)),
            "appcontainer_module_sha256": _file_sha256(Path(__file__).with_name("appcontainer.py")),
            "windows_job_module_sha256": _file_sha256(Path(__file__).with_name("windows_job.py")),
            "admission_module_sha256": _file_sha256(Path(__file__).with_name("v120_admission.py")),
            "jobs_module_sha256": _file_sha256(Path(__file__).with_name("jobs.py")),
        }
        receipt["source"]["control_plane_files_sha256"] = control_files
        receipt["source"]["broker_sha256"] = hashlib.sha256(_canonical(control_files)).hexdigest()
        receipt["source"]["broker_api_version"] = VERSION
        try:
            return self.ledger.append(receipt)
        except TelemetryError as exc:
            raise Rejected(exc.code) from None
