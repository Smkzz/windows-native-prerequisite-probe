"""Fixed-function memory admission for LocalControl v1.2.

The only production telemetry path uses Windows APIs in the trusted LocalControl
broker process. This module never launches a shell or accepts a command.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid
from typing import Callable, Mapping

GIB = 1 << 30
POLICY_DOCUMENT = {
    "schema": "localcontrol-memory-policy-v1",
    "policy_id": "memory-prevention-20261014-6gib-reserve-v3",
    "available_reserve_bytes": 6 * GIB,
    "commit_reserve_bytes": 6 * GIB,
    "forecast_commit_percent_exclusive": 85,
    "c_free_bytes": 20 * GIB,
    "max_planned_bytes": 128 * GIB,
    "max_sample_age_ns": 10_000_000_000,
}
POLICY_BYTES = json.dumps(
    POLICY_DOCUMENT, ensure_ascii=True, sort_keys=True, separators=(",", ":")
).encode("ascii")
POLICY_SHA256 = hashlib.sha256(POLICY_BYTES).hexdigest()
POLICY_ID = POLICY_DOCUMENT["policy_id"]
IMPLEMENTATION_ID = "localcontrol.v120.memory_preflight"
TELEMETRY_SOURCE = "win32.psapi.GetPerformanceInfo+kernel32.GetDiskFreeSpaceExW"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HEX40_RE = re.compile(r"[0-9a-fA-F]{40}\Z")
_HEX64_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


class TelemetryError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("CommitTotal", ctypes.c_size_t),
        ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t),
        ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t),
        ("KernelPaged", ctypes.c_size_t),
        ("KernelNonpaged", ctypes.c_size_t),
        ("PageSize", ctypes.c_size_t),
        ("HandleCount", wintypes.DWORD),
        ("ProcessCount", wintypes.DWORD),
        ("ThreadCount", wintypes.DWORD),
    ]


def implementation_sha256() -> str:
    source_path = Path(__file__)
    try:
        digest = hashlib.sha256()
        with source_path.open("rb") as stream:
            for block in iter(lambda: stream.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        raise TelemetryError("PREFLIGHT_SOURCE_INVALID") from None

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def read_windows_telemetry() -> dict:
    """Read one bounded, trusted snapshot; never falls back to shell commands."""
    if os.name != "nt":
        raise TelemetryError("TELEMETRY_PLATFORM_UNSUPPORTED")
    try:
        info = _PERFORMANCE_INFORMATION()
        info.cb = ctypes.sizeof(info)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        get_performance = psapi.GetPerformanceInfo
        get_performance.argtypes = [ctypes.POINTER(_PERFORMANCE_INFORMATION), wintypes.DWORD]
        get_performance.restype = wintypes.BOOL

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        disk_free = kernel32.GetDiskFreeSpaceExW
        disk_free.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_ulonglong),
        ]
        disk_free.restype = wintypes.BOOL

        started_ns = time.monotonic_ns()
        if not get_performance(ctypes.byref(info), info.cb):
            raise TelemetryError("TELEMETRY_COMMIT_OR_MEMORY_DENIED")
        caller_free = ctypes.c_ulonglong()
        total_bytes = ctypes.c_ulonglong()
        total_free = ctypes.c_ulonglong()
        if not disk_free("C:\\", ctypes.byref(caller_free), ctypes.byref(total_bytes),
                         ctypes.byref(total_free)):
            raise TelemetryError("TELEMETRY_DISK_DENIED")
        sampled_ns = time.monotonic_ns()
        sampled_utc = _utc_now()

        page_size = int(info.PageSize)
        if page_size <= 0:
            raise TelemetryError("TELEMETRY_INVALID_PAGE_SIZE")
        return {
            "source": "win32.psapi.GetPerformanceInfo+kernel32.GetDiskFreeSpaceExW",
            "sampled_at_utc": sampled_utc,
            "sampled_monotonic_ns": sampled_ns,
            "sample_started_monotonic_ns": started_ns,
            "physical_total_bytes": int(info.PhysicalTotal) * page_size,
            "available_bytes": int(info.PhysicalAvailable) * page_size,
            "committed_bytes": int(info.CommitTotal) * page_size,
            "commit_limit_bytes": int(info.CommitLimit) * page_size,
            "c_free_bytes": int(caller_free.value),
            "c_total_bytes": int(total_bytes.value),
            "c_total_free_bytes": int(total_free.value),
            "page_size_bytes": page_size,
        }
    except TelemetryError:
        raise
    except (AttributeError, OSError, OverflowError, ValueError, ctypes.ArgumentError):
        raise TelemetryError("TELEMETRY_API_FAILURE") from None


def _safe_input(value, *, limit: int = 128) -> dict:
    if value is None or type(value) in (bool, int, float, str):
        text = repr(value)
    else:
        text = f"<{type(value).__name__}>"
    return {"type": type(value).__name__, "value": text[:limit]}


def _valid_identifier(value) -> bool:
    return isinstance(value, str) and _ID_RE.fullmatch(value) is not None


def _candidate_error(candidate) -> str | None:
    if not isinstance(candidate, dict):
        return "CANDIDATE_IDENTITY_INVALID"
    if set(candidate) == {"kind", "commit", "tree"} and candidate.get("kind") == "git":
        commit, tree = candidate.get("commit"), candidate.get("tree")
        if isinstance(commit, str) and isinstance(tree, str):
            if _HEX40_RE.fullmatch(commit) and _HEX40_RE.fullmatch(tree):
                return None
    if set(candidate) == {"kind", "sha256"} and candidate.get("kind") == "overlay":
        digest = candidate.get("sha256")
        if isinstance(digest, str) and _HEX64_RE.fullmatch(digest):
            return None
    return "CANDIDATE_IDENTITY_INVALID"


def _valid_int(value, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= (1 << 63) - 1


def _valid_sample(sample: Mapping) -> str | None:
    if not isinstance(sample, Mapping):
        return "TELEMETRY_INVALID_SHAPE"
    required = {
        "source", "sampled_at_utc", "sampled_monotonic_ns", "sample_started_monotonic_ns",
        "physical_total_bytes", "available_bytes", "committed_bytes", "commit_limit_bytes",
        "c_free_bytes", "c_total_bytes", "c_total_free_bytes", "page_size_bytes",
    }
    if set(sample) != required:
        return "TELEMETRY_MISSING_FIELD"
    if sample["source"] != TELEMETRY_SOURCE:
        return "TELEMETRY_INVALID_SOURCE"
    sampled_at = sample["sampled_at_utc"]
    if not isinstance(sampled_at, str):
        return "TELEMETRY_INVALID_TIME"
    try:
        parsed = datetime.fromisoformat(sampled_at.replace("Z", "+00:00"))
    except ValueError:
        return "TELEMETRY_INVALID_TIME"
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        return "TELEMETRY_INVALID_TIME"
    for key in required - {"source", "sampled_at_utc"}:
        if not _valid_int(sample[key]):
            return "TELEMETRY_INVALID_COUNTER"
    if sample["sample_started_monotonic_ns"] > sample["sampled_monotonic_ns"]:
        return "TELEMETRY_INVALID_INTERVAL"
    if sample["sampled_monotonic_ns"] - sample["sample_started_monotonic_ns"] > POLICY_DOCUMENT["max_sample_age_ns"]:
        return "TELEMETRY_INVALID_INTERVAL"
    if sample["page_size_bytes"] <= 0:
        return "TELEMETRY_INVALID_PAGE_SIZE"
    if sample["physical_total_bytes"] <= 0 or sample["commit_limit_bytes"] <= 0:
        return "TELEMETRY_INVALID_LIMIT"
    if sample["available_bytes"] > sample["physical_total_bytes"]:
        return "TELEMETRY_INCONSISTENT_MEMORY"
    if sample["committed_bytes"] > sample["commit_limit_bytes"]:
        return "TELEMETRY_INCONSISTENT_COMMIT"
    if not (sample["c_free_bytes"] <= sample["c_total_free_bytes"] <= sample["c_total_bytes"]):
        return "TELEMETRY_INCONSISTENT_DISK"
    return None


def _receipt_base(task_id, workload_id, candidate, planned_bytes, source_sha256,
                  policy_sha256, registry, sampled_at_utc) -> dict:
    return {
        "schema": "localcontrol-preflight-receipt-v1",
        "receipt_id": uuid.uuid4().hex,
        "created_at_utc": _utc_now(),
        "task_id": task_id if _valid_identifier(task_id) else None,
        "workload_id": workload_id if _valid_identifier(workload_id) else None,
        "candidate_identity": candidate if _candidate_error(candidate) is None else None,
        "workload": {
            "planned_bytes": planned_bytes if _valid_int(planned_bytes, 1) else None,
            "invalid_input": None if _valid_int(planned_bytes, 1) else _safe_input(planned_bytes),
        },
        "source": {
            "implementation_id": IMPLEMENTATION_ID,
            "implementation_sha256": source_sha256,
            "telemetry": "win32.psapi.GetPerformanceInfo+kernel32.GetDiskFreeSpaceExW",
        },
        "policy": {
            "policy_id": POLICY_ID,
            "policy_sha256": policy_sha256,
            "thresholds": dict(POLICY_DOCUMENT),
        },
        "registry": registry,
        "telemetry": {
            "sampled_at_utc": sampled_at_utc,
            "raw": None,
        },
        "comparisons": {
            "available_after_gte_6_gib": None,
            "commit_headroom_after_gte_6_gib": None,
            "forecast_commit_lt_85_percent": None,
            "c_free_gte_20_gib": None,
        },
        "decision": "ERROR",
        "exit_code": 1,
        "reasons": [],
        "error": None,
        "captured_output": {
            "stdout_bytes": 0,
            "stdout_sha256": EMPTY_SHA256,
            "stderr_bytes": 0,
            "stderr_sha256": EMPTY_SHA256,
        },
    }


def evaluate_preflight(
    task_id,
    workload_id,
    candidate_identity,
    planned_bytes,
    *,
    telemetry_reader: Callable[[], Mapping] = read_windows_telemetry,
    expected_policy_sha256: str = POLICY_SHA256,
    registry: Mapping | None = None,
    now_monotonic_ns: int | None = None,
) -> dict:
    """Return a complete fail-closed decision receipt before operator signing."""
    try:
        source_sha = implementation_sha256()
    except TelemetryError:
        source_sha = None
    receipt = _receipt_base(
        task_id, workload_id, candidate_identity, planned_bytes, source_sha,
        POLICY_SHA256, dict(registry or {}), None
    )

    invalid = []
    if not _valid_identifier(task_id):
        invalid.append("TASK_ID_INVALID")
    if not _valid_identifier(workload_id):
        invalid.append("WORKLOAD_ID_INVALID")
    candidate_problem = _candidate_error(candidate_identity)
    if candidate_problem:
        invalid.append(candidate_problem)
    if not _valid_int(planned_bytes, 1) or planned_bytes > POLICY_DOCUMENT["max_planned_bytes"]:
        invalid.append("PLANNED_BYTES_INVALID")
    if expected_policy_sha256 != POLICY_SHA256:
        invalid.append("POLICY_IDENTITY_MISMATCH")
    if source_sha is None:
        invalid.append("PREFLIGHT_SOURCE_INVALID")
    if invalid:
        receipt["reasons"] = sorted(set(invalid))
        receipt["error"] = {"code": invalid[0], "message": "Preflight input or pinned identity is invalid."}
        return receipt

    try:
        sample = dict(telemetry_reader())
    except TelemetryError as exc:
        receipt["reasons"] = [exc.code]
        receipt["error"] = {"code": exc.code, "message": "Trusted telemetry is unavailable."}
        return receipt
    except Exception:
        receipt["reasons"] = ["TELEMETRY_API_FAILURE"]
        receipt["error"] = {"code": "TELEMETRY_API_FAILURE", "message": "Trusted telemetry is unavailable."}
        return receipt

    receipt["telemetry"]["sampled_at_utc"] = sample.get("sampled_at_utc")
    problem = _valid_sample(sample)
    if problem:
        receipt["reasons"] = [problem]
        receipt["error"] = {"code": problem, "message": "Trusted telemetry is incomplete or inconsistent."}
        return receipt
    now_ns = time.monotonic_ns() if now_monotonic_ns is None else now_monotonic_ns
    age_ns = now_ns - sample["sampled_monotonic_ns"]
    if not _valid_int(now_ns) or age_ns < 0 or age_ns > POLICY_DOCUMENT["max_sample_age_ns"]:
        receipt["reasons"] = ["TELEMETRY_STALE"]
        receipt["error"] = {"code": "TELEMETRY_STALE", "message": "Trusted telemetry is stale."}
        return receipt

    planned = planned_bytes
    available_after = sample["available_bytes"] - planned
    commit_headroom_after = sample["commit_limit_bytes"] - sample["committed_bytes"] - planned
    forecast_numerator = (sample["committed_bytes"] + planned) * 100
    forecast_denominator = sample["commit_limit_bytes"] * POLICY_DOCUMENT["forecast_commit_percent_exclusive"]
    comparisons = {
        "available_after_gte_6_gib": available_after >= POLICY_DOCUMENT["available_reserve_bytes"],
        "commit_headroom_after_gte_6_gib": commit_headroom_after >= POLICY_DOCUMENT["commit_reserve_bytes"],
        "forecast_commit_lt_85_percent": forecast_numerator < forecast_denominator,
        "c_free_gte_20_gib": sample["c_total_free_bytes"] >= POLICY_DOCUMENT["c_free_bytes"],
    }
    receipt["telemetry"]["raw"] = {
        key: sample[key] for key in (
            "source", "sampled_at_utc", "sampled_monotonic_ns", "sample_started_monotonic_ns",
            "physical_total_bytes", "available_bytes", "committed_bytes", "commit_limit_bytes",
            "c_free_bytes", "c_total_bytes", "c_total_free_bytes", "page_size_bytes",
        ) if key in sample
    }
    receipt["measurements"] = {
        "available_after_bytes": available_after,
        "commit_headroom_after_bytes": commit_headroom_after,
        "forecast_commit_percent": round(
            ((sample["committed_bytes"] + planned) * 100) / sample["commit_limit_bytes"], 6
        ),
    }
    receipt["comparisons"] = comparisons
    failures = [name for name, passed in comparisons.items() if not passed]
    if failures:
        receipt["decision"] = "DEFER"
        receipt["exit_code"] = 75
        receipt["reasons"] = failures
        receipt["error"] = {"code": "RESOURCE_THRESHOLD_NOT_MET", "message": "One or more admission thresholds were not met."}
    else:
        receipt["decision"] = "ADMIT"
        receipt["exit_code"] = 0
        receipt["reasons"] = []
    return receipt


def _canonical(value: Mapping) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _receipt_payload(receipt: Mapping) -> dict:
    return {key: value for key, value in receipt.items() if key not in {"integrity"}}


def sign_receipt(receipt: Mapping, operator_key: bytes) -> dict:
    if not isinstance(operator_key, bytes) or len(operator_key) < 32:
        raise ValueError("receipt signing key must contain at least 32 bytes")
    payload = _receipt_payload(receipt)
    payload_bytes = _canonical(payload)
    receipt_key = hmac.new(operator_key, b"LocalControl/v1.2/preflight-receipt", hashlib.sha256).digest()
    signature = hmac.new(receipt_key, payload_bytes, hashlib.sha256).hexdigest()
    payload["integrity"] = {
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "signature_algorithm": "HMAC-SHA256",
        "key_id": hashlib.sha256(operator_key).hexdigest()[:16],
        "hmac_sha256": signature,
    }
    return payload


def verify_signed_receipt(receipt: Mapping, operator_key: bytes) -> bool:
    try:
        if not isinstance(receipt, Mapping) or not isinstance(operator_key, bytes) or len(operator_key) < 32:
            return False
        integrity = receipt["integrity"]
        if not isinstance(integrity, Mapping) or set(integrity) != {
            "payload_sha256", "signature_algorithm", "key_id", "hmac_sha256"
        }:
            return False
        if integrity.get("signature_algorithm") != "HMAC-SHA256":
            return False
        if not hmac.compare_digest(
            integrity.get("key_id", ""),
            hashlib.sha256(operator_key).hexdigest()[:16],
        ):
            return False
        payload_bytes = _canonical(_receipt_payload(receipt))
        if not hmac.compare_digest(
            integrity.get("payload_sha256", ""),
            hashlib.sha256(payload_bytes).hexdigest(),
        ):
            return False
        receipt_key = hmac.new(operator_key, b"LocalControl/v1.2/preflight-receipt", hashlib.sha256).digest()
        expected = hmac.new(receipt_key, payload_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(integrity.get("hmac_sha256", ""), expected)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False

    
class ReceiptLedger:
    """Protected append-only receipt journal with a signed, verifiable hash chain.

    Filesystem ACLs on the parent state directory remain the authority boundary;
    the trigger and HMAC chain detect accidental or unauthorized in-place edits.
    """
    _ZERO = "0" * 64

    def __init__(self, path: Path | str, operator_key: bytes):
        if not isinstance(operator_key, bytes) or len(operator_key) < 32:
            raise ValueError("receipt signing key must contain at least 32 bytes")
        self._memory = str(path) == ":memory:"
        self.path = None if self._memory else Path(path)
        if not self._memory:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.is_symlink():
                raise TelemetryError("PREFLIGHT_LEDGER_PATH_INVALID")
            if self.path.exists() and (not self.path.is_file() or self.path.stat().st_nlink != 1):
                raise TelemetryError("PREFLIGHT_LEDGER_PATH_INVALID")
        self.operator_key = operator_key
        self.chain_key = hmac.new(
            operator_key, b"LocalControl/v1.2/preflight-ledger", hashlib.sha256
        ).digest()
        self.lock = threading.RLock()
        try:
            self.db = sqlite3.connect(
                ":memory:" if self._memory else str(self.path),
                timeout=5, isolation_level=None, check_same_thread=False,
            )
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS receipts ("
                "sequence INTEGER PRIMARY KEY, receipt_json TEXT NOT NULL, "
                "previous_sha256 TEXT NOT NULL, row_sha256 TEXT NOT NULL, "
                "row_hmac_sha256 TEXT NOT NULL)"
            )
            self.db.execute(
                "CREATE TRIGGER IF NOT EXISTS receipts_no_update "
                "BEFORE UPDATE ON receipts BEGIN SELECT RAISE(ABORT, 'append_only'); END"
            )
            self.db.execute(
                "CREATE TRIGGER IF NOT EXISTS receipts_no_delete "
                "BEFORE DELETE ON receipts BEGIN SELECT RAISE(ABORT, 'append_only'); END"
            )
            self.verify()
        except (sqlite3.Error, OSError):
            raise TelemetryError("PREFLIGHT_LEDGER_UNAVAILABLE") from None

    def close(self) -> None:
        with self.lock:
            self.db.close()

    @staticmethod
    def _row_hash(sequence: int, previous: str, receipt_json: str) -> str:
        body = json.dumps(
            {"sequence": sequence, "previous_sha256": previous, "receipt_json": receipt_json},
            ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(body).hexdigest()

    def verify(self) -> bool:
        with self.lock:
            previous = self._ZERO
            rows = self.db.execute(
                "SELECT sequence, receipt_json, previous_sha256, row_sha256, row_hmac_sha256 "
                "FROM receipts ORDER BY sequence"
            ).fetchall()
            for expected_sequence, row in enumerate(rows, 1):
                sequence, receipt_json, recorded_previous, row_hash, row_hmac = row
                if sequence != expected_sequence or recorded_previous != previous:
                    raise TelemetryError("PREFLIGHT_LEDGER_CORRUPT")
                calculated = self._row_hash(sequence, previous, receipt_json)
                expected_mac = hmac.new(
                    self.chain_key, calculated.encode("ascii"), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(row_hash, calculated) or not hmac.compare_digest(row_hmac, expected_mac):
                    raise TelemetryError("PREFLIGHT_LEDGER_CORRUPT")
                try:
                    receipt = json.loads(receipt_json)
                except (TypeError, ValueError):
                    raise TelemetryError("PREFLIGHT_LEDGER_CORRUPT") from None
                if not verify_signed_receipt(receipt, self.operator_key):
                    raise TelemetryError("PREFLIGHT_LEDGER_CORRUPT")
                previous = calculated
            return True

    def get_by_request_id(self, request_id: str) -> dict | None:
        """Return one signed receipt after verifying the complete append-only chain."""
        if not isinstance(request_id, str) or not request_id:
            raise TelemetryError("PREFLIGHT_REQUEST_ID_INVALID")
        self.verify()
        with self.lock:
            rows = self.db.execute(
                "SELECT receipt_json FROM receipts ORDER BY sequence"
            ).fetchall()
        matches = []
        for (raw,) in rows:
            try:
                receipt = json.loads(raw)
            except (TypeError, ValueError):
                raise TelemetryError("PREFLIGHT_LEDGER_CORRUPT") from None
            if receipt.get("request_id") == request_id:
                matches.append(receipt)
        if len(matches) > 1:
            raise TelemetryError("PREFLIGHT_REQUEST_REPLAY")
        return matches[0] if matches else None

    def append(self, receipt: Mapping) -> dict:
        """Append one receipt, returning the original receipt on an exact request retry."""
        signed = sign_receipt(receipt, self.operator_key)
        request_id = receipt.get("request_id") if isinstance(receipt, Mapping) else None
        request_binding_sha256 = None
        if isinstance(request_id, str) and request_id:
            request_binding_sha256 = receipt.get("request_binding_sha256")
            if (not isinstance(request_binding_sha256, str)
                    or len(request_binding_sha256) != 64
                    or any(character not in "0123456789abcdef"
                           for character in request_binding_sha256)):
                raise TelemetryError("PREFLIGHT_REQUEST_BINDING_INVALID")
        with self.lock:
            begun = False
            try:
                self.db.execute("BEGIN IMMEDIATE")
                begun = True
                self.verify()
                if isinstance(request_id, str) and request_id:
                    rows = self.db.execute(
                        "SELECT receipt_json FROM receipts ORDER BY sequence"
                    ).fetchall()
                    matches = []
                    for (raw,) in rows:
                        try:
                            existing = json.loads(raw)
                        except (TypeError, ValueError):
                            raise TelemetryError("PREFLIGHT_LEDGER_CORRUPT") from None
                        if existing.get("request_id") == request_id:
                            matches.append(existing)
                    if len(matches) > 1:
                        raise TelemetryError("PREFLIGHT_REQUEST_REPLAY")
                    if matches:
                        prior = matches[0]
                        if (prior.get("request_binding_sha256")
                                != request_binding_sha256):
                            raise TelemetryError("PREFLIGHT_REQUEST_REPLAY")
                        self.db.execute("COMMIT")
                        return prior

                row = self.db.execute(
                    "SELECT sequence, row_sha256 FROM receipts ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = 1 if row is None else row[0] + 1
                previous = self._ZERO if row is None else row[1]
                receipt_json = _canonical(signed).decode("ascii")
                row_hash = self._row_hash(sequence, previous, receipt_json)
                row_mac = hmac.new(
                    self.chain_key, row_hash.encode("ascii"), hashlib.sha256
                ).hexdigest()
                self.db.execute(
                    "INSERT INTO receipts(sequence, receipt_json, previous_sha256, row_sha256, row_hmac_sha256) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (sequence, receipt_json, previous, row_hash, row_mac),
                )
                self.db.execute("COMMIT")
                return signed
            except TelemetryError:
                if begun:
                    try:
                        self.db.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise
            except (sqlite3.Error, OSError):
                if begun:
                    try:
                        self.db.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise TelemetryError("PREFLIGHT_LEDGER_UNAVAILABLE") from None
