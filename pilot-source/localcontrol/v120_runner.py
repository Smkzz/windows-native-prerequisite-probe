"""Task-only Windows worker execution for LocalControl v1.2.

The MCP surface accepts identifiers only. Workload manifests are offline-signed;
each attempt gets a derived AppContainer identity, disposable ACL boundary, and
named bounded Job Object. Every OS failure is fail-closed.
"""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from dataclasses import dataclass
import hashlib
import hmac
import json
import ntpath
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import threading
import time
from typing import Callable

from .errors import require
from .policy import no_links
from .v120_api import (
    MAX_PREFLIGHT_AGE_NS, _absolute_local_path, _canonical, _inside, _utc,
)
from .v120_preflight import verify_signed_receipt
from .windows_job import WindowsJob, _Accounting, _ExtendedLimits
from .v120_admission import RunnerLease, TaskAdmission

_WORKLOAD_DOMAIN = b"LocalControl/v1.2/workload-manifest"
_WORKLOAD_SCHEMA = "localcontrol-workload-manifest-v1"
_WORKLOAD_ENVELOPE = "localcontrol-workload-envelope-v1"
_ATTEMPT_DOMAIN = b"LocalControl/v1.2/attempt-ledger"
_ATTEMPT_ID = re.compile(r"[a-f0-9]{32}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_HEX = re.compile(r"[a-f0-9]{64}")
_MAX_MANIFEST_BYTES = 1_048_576
_MAX_RUNTIME_FILES = 512
_FILE_GENERIC_READ = 0x00120089
_FILE_GENERIC_WRITE = 0x00120116
_FILE_GENERIC_EXECUTE = 0x001200A0
_FILE_DELETE = 0x00010000
_FILE_DELETE_CHILD = 0x00000040
_FILE_READ_EXECUTE = _FILE_GENERIC_READ | _FILE_GENERIC_EXECUTE
_FILE_MODIFY = _FILE_GENERIC_READ | _FILE_GENERIC_WRITE | _FILE_GENERIC_EXECUTE | _FILE_DELETE | _FILE_DELETE_CHILD
_ACCESS_READ = _FILE_GENERIC_READ
_ACCESS_WRITE = _FILE_GENERIC_WRITE | _FILE_DELETE | _FILE_DELETE_CHILD | 0x00040000 | 0x00080000
_WRITE_ACCESS_BITS = (0x00000002, 0x00000004, 0x00000010, 0x00000100,
                      _FILE_DELETE, _FILE_DELETE_CHILD, 0x00040000, 0x00080000)
_ATTRIBUTE_REPARSE_POINT = 0x0400
_OWNER_MARKER_NAME = ".localcontrol-attempt-owner.json"


class RunnerError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _sid_bytes_from_text(advapi, kernel, sid_text: str) -> bytes:
    advapi.ConvertStringSidToSidW.argtypes = [w.LPCWSTR, c.POINTER(c.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = w.BOOL
    advapi.GetLengthSid.argtypes = [c.c_void_p]
    advapi.GetLengthSid.restype = w.DWORD
    kernel.LocalFree.argtypes = [c.c_void_p]
    kernel.LocalFree.restype = c.c_void_p
    sid = c.c_void_p()
    if not advapi.ConvertStringSidToSidW(sid_text, c.byref(sid)):
        raise RunnerError("V120_SECURITY_SID")
    try:
        length = advapi.GetLengthSid(sid)
        if not length:
            raise RunnerError("V120_SECURITY_SID")
        return c.string_at(sid, length)
    finally:
        kernel.LocalFree(sid)


def _current_process_user_sid(advapi, kernel) -> bytes:
    class TokenUser(c.Structure):
        _fields_ = [("sid", c.c_void_p), ("attributes", w.DWORD)]

    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    advapi.OpenProcessToken.restype = w.BOOL
    advapi.GetTokenInformation.argtypes = [
        w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD),
    ]
    advapi.GetTokenInformation.restype = w.BOOL
    advapi.GetLengthSid.argtypes = [c.c_void_p]
    advapi.GetLengthSid.restype = w.DWORD
    token = w.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, c.byref(token)):
        raise RunnerError("V120_SECURITY_TOKEN")
    try:
        size = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, c.byref(size))
        if not size.value:
            raise RunnerError("V120_SECURITY_TOKEN")
        buffer = c.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(
                token, 1, buffer, size.value, c.byref(size)):
            raise RunnerError("V120_SECURITY_TOKEN")
        user = TokenUser.from_buffer(buffer)
        length = advapi.GetLengthSid(user.sid)
        if not user.sid or not length:
            raise RunnerError("V120_SECURITY_TOKEN")
        return c.string_at(user.sid, length)
    finally:
        kernel.CloseHandle(token)


def _validate_acl_ace_header(header: bytes) -> tuple[int, int, int]:
    if not isinstance(header, bytes) or len(header) != 4:
        raise RunnerError("V120_SECURITY_ACE")
    ace_type, ace_flags = header[0], header[1]
    ace_size = int.from_bytes(header[2:4], "little")
    if ace_type not in (0, 1) or ace_size < 16:
        raise RunnerError("V120_SECURITY_ACE")
    return ace_type, ace_flags, ace_size


def _validate_acl_entries(
    owner_sid: bytes, entries: list[tuple[int, int, int, bytes]],
    allowed_sids: set[bytes], *, exact_allow_mask: int | None = None,
    expected_allow_sids: set[bytes] | None = None, allow_deny_aces: bool = True,
) -> set[bytes]:
    if owner_sid not in allowed_sids:
        raise RunnerError("V120_SECURITY_OWNER")
    allowed_entries: set[bytes] = set()
    for ace_type, ace_flags, mask, sid in entries:
        if ace_flags != 0:
            raise RunnerError("V120_SECURITY_ACE_FLAGS")
        if ace_type == 1 and allow_deny_aces:
            continue
        if ace_type != 0 or sid not in allowed_sids or sid in allowed_entries:
            raise RunnerError("V120_SECURITY_DACL_PRINCIPAL")
        if exact_allow_mask is not None and mask != exact_allow_mask:
            raise RunnerError("V120_SECURITY_DACL_MASK")
        allowed_entries.add(sid)
    if expected_allow_sids is not None and allowed_entries != expected_allow_sids:
        raise RunnerError("V120_SECURITY_DACL_SET")
    return allowed_entries


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value or ":" in value:
        raise RunnerError("V120_WORKLOAD_PATH")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise RunnerError("V120_WORKLOAD_PATH")
    if any(part.endswith((" ", ".")) for part in relative.parts):
        raise RunnerError("V120_WORKLOAD_PATH")
    return relative


def _file_identity(path: Path) -> dict:
    info = path.stat(follow_symlinks=False)
    if info.st_file_attributes & _ATTRIBUTE_REPARSE_POINT:
        raise RunnerError("V120_REPARSE_POINT")
    return {"volume": int(info.st_dev), "file_id": int(info.st_ino), "links": int(info.st_nlink)}


def _safe_existing(path: Path, *, file: bool | None = None) -> Path:
    text = str(path)
    if not _absolute_local_path(text):
        raise RunnerError("V120_PATH_ALIAS")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            raise RunnerError("V120_PATH_MISSING") from None
        if info.st_file_attributes & _ATTRIBUTE_REPARSE_POINT:
            raise RunnerError("V120_REPARSE_POINT")
    identity = _file_identity(path)
    if file is True and not path.is_file():
        raise RunnerError("V120_PATH_TYPE")
    if file is False and not path.is_dir():
        raise RunnerError("V120_PATH_TYPE")
    if file is True and identity["links"] != 1:
        raise RunnerError("V120_HARDLINK")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise RunnerError('V120_PATH_UNINSPECTABLE') from None
    if ntpath.normcase(str(resolved)) != ntpath.normcase(text):
        raise RunnerError("V120_PATH_ALIAS")
    return resolved


def sign_workload_manifest(manifest: dict, registry_key: bytes) -> dict:
    if not isinstance(registry_key, bytes) or len(registry_key) != 32:
        raise RunnerError("V120_KEY")
    payload = dict(manifest)
    key = hmac.new(registry_key, _WORKLOAD_DOMAIN, hashlib.sha256).digest()
    return {
        "schema": _WORKLOAD_ENVELOPE,
        "payload": payload,
        "signature": {
            "algorithm": "HMAC-SHA256",
            "key_id": hashlib.sha256(key).hexdigest()[:16],
            "hmac_sha256": hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest(),
        },
    }


def verify_workload_manifest(raw: bytes, expected_sha256: str, registry_key: bytes,
                             scope_workload: dict, runtime_roots: list[str]) -> dict:
    if (not isinstance(raw, bytes) or len(raw) > _MAX_MANIFEST_BYTES
            or not isinstance(expected_sha256, str) or _HEX.fullmatch(expected_sha256) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)):
        raise RunnerError("V120_WORKLOAD_MANIFEST_HASH")
    try:
        envelope = json.loads(raw)
    except (TypeError, ValueError, UnicodeDecodeError):
        raise RunnerError("V120_WORKLOAD_MANIFEST_CORRUPT") from None
    if (not isinstance(envelope, dict) or set(envelope) != {"schema", "payload", "signature"}
            or envelope.get("schema") != _WORKLOAD_ENVELOPE):
        raise RunnerError("V120_WORKLOAD_MANIFEST_SCHEMA")
    payload, signature = envelope["payload"], envelope["signature"]
    if (not isinstance(payload, dict) or set(payload) != {
            "schema", "workload_id", "executable_relative", "argv", "runtime_files",
            "resource_limits", "shell", "environment"}
            or payload.get("schema") != _WORKLOAD_SCHEMA
            or payload.get("workload_id") != scope_workload.get("workload_id")
            or payload.get("shell") is not False or payload.get("environment") != {}
            or payload.get("resource_limits") != scope_workload.get("resource_limits")):
        raise RunnerError("V120_WORKLOAD_MANIFEST_SCHEMA")
    if (not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "hmac_sha256"}
            or signature.get("algorithm") != "HMAC-SHA256"
            or not isinstance(signature.get("key_id"), str)
            or not isinstance(signature.get("hmac_sha256"), str)):
        raise RunnerError("V120_WORKLOAD_SIGNATURE")
    key = hmac.new(registry_key, _WORKLOAD_DOMAIN, hashlib.sha256).digest()
    expected = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    if (not hmac.compare_digest(signature["key_id"], hashlib.sha256(key).hexdigest()[:16])
            or not hmac.compare_digest(signature["hmac_sha256"], expected)):
        raise RunnerError("V120_WORKLOAD_SIGNATURE")
    argv = payload["argv"]
    if (not isinstance(argv, list) or len(argv) > 128
            or any(not isinstance(arg, str) or len(arg) > 8192 or "\0" in arg for arg in argv)):
        raise RunnerError("V120_WORKLOAD_ARGUMENTS")
    runtime_files = payload["runtime_files"]
    if not isinstance(runtime_files, list) or not 1 <= len(runtime_files) <= _MAX_RUNTIME_FILES:
        raise RunnerError("V120_WORKLOAD_FILES")
    seen = set()
    executable = _safe_relative(payload["executable_relative"])
    executable_seen = False
    clean_files = []
    for item in runtime_files:
        if (not isinstance(item, dict) or set(item) != {"source_path", "relative_path", "sha256"}
                or not isinstance(item.get("source_path"), str)
                or not isinstance(item.get("sha256"), str)
                or _HEX.fullmatch(item["sha256"]) is None):
            raise RunnerError("V120_WORKLOAD_FILES")
        source = _safe_existing(Path(item["source_path"]), file=True)
        if not any(_inside(str(source), root) for root in runtime_roots):
            raise RunnerError("V120_WORKLOAD_PATH")
        relative = _safe_relative(item["relative_path"])
        key_path = relative.as_posix().casefold()
        if key_path in seen:
            raise RunnerError("V120_WORKLOAD_FILES")
        seen.add(key_path)
        if relative == executable:
            executable_seen = True
        if not hmac.compare_digest(_sha256(source), item["sha256"]):
            raise RunnerError("V120_WORKLOAD_FILE_HASH")
        clean_files.append({"source_path": str(source), "relative_path": relative.as_posix(),
                            "sha256": item["sha256"]})
    if not executable_seen:
        raise RunnerError("V120_WORKLOAD_EXECUTABLE")
    exe_name = executable.name.casefold()
    if exe_name in {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                    "bash", "sh", "zsh"}:
        raise RunnerError("V120_SHELL_FORBIDDEN")
    return dict(payload) | {"runtime_files": clean_files,
                            "executable_relative": executable.as_posix()}


class AttemptLedger:
    """HMAC-chained attempt journal with a unique preflight-receipt claim."""

    def __init__(self, path: Path, registry_key: bytes):
        if not isinstance(registry_key, bytes) or len(registry_key) != 32:
            raise RunnerError("V120_KEY")
        self.path = Path(path)
        self.key = hmac.new(registry_key, _ATTEMPT_DOMAIN, hashlib.sha256).digest()
        self.lock = threading.RLock()
        if self.path.is_symlink() or (self.path.exists() and (
                not self.path.is_file() or self.path.stat().st_nlink != 1)):
            raise RunnerError("V120_ATTEMPT_LEDGER_PATH")
        self.db = sqlite3.connect(
            str(self.path), isolation_level=None, check_same_thread=False, timeout=5
        )
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, "
            "event_json TEXT NOT NULL, previous_hmac TEXT NOT NULL, event_hmac TEXT NOT NULL)"
        )
        self.db.execute(
            "CREATE TRIGGER IF NOT EXISTS attempts_no_update "
            "BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append only'); END"
        )
        self.db.execute(
            "CREATE TRIGGER IF NOT EXISTS attempts_no_delete "
            "BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append only'); END"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS receipt_claims (receipt_sha256 TEXT PRIMARY KEY, "
            "attempt_id TEXT NOT NULL, event_sequence INTEGER NOT NULL)"
        )
        self.db.execute(
            "CREATE TRIGGER IF NOT EXISTS receipt_claims_no_update "
            "BEFORE UPDATE ON receipt_claims BEGIN SELECT RAISE(ABORT,'append only'); END"
        )
        self.db.execute(
            "CREATE TRIGGER IF NOT EXISTS receipt_claims_no_delete "
            "BEFORE DELETE ON receipt_claims BEGIN SELECT RAISE(ABORT,'append only'); END"
        )
        self.verify()

    def close(self):
        with self.lock:
            self.db.close()

    def _mac(self, sequence: int, previous: str, event_json: str) -> str:
        return hmac.new(
            self.key, f"{sequence}:{previous}:{event_json}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def events(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                "SELECT sequence,event_json,previous_hmac,event_hmac "
                "FROM events ORDER BY sequence"
            ).fetchall()
        result, previous = [], "0" * 64
        for expected, row in enumerate(rows, 1):
            sequence, raw, linked, mac = row
            if sequence != expected or linked != previous or not hmac.compare_digest(
                    mac, self._mac(sequence, linked, raw)):
                raise RunnerError("V120_ATTEMPT_LEDGER_CORRUPT")
            try:
                event = json.loads(raw)
            except (TypeError, ValueError):
                raise RunnerError("V120_ATTEMPT_LEDGER_CORRUPT") from None
            if not isinstance(event, dict):
                raise RunnerError("V120_ATTEMPT_LEDGER_CORRUPT")
            result.append(event)
            previous = mac
        return result

    def verify(self):
        # Keep the authenticated event snapshot and receipt-claim index consistent
        # with concurrent claim_receipt calls on this shared connection.
        with self.lock:
            events = self.events()
            expected = {}
            for sequence, event in enumerate(events, 1):
                if event.get("kind") == "claimed":
                    digest, attempt_id = event.get("preflight_receipt_sha256"), event.get("attempt_id")
                    if (not isinstance(digest, str) or _HEX.fullmatch(digest) is None
                            or not isinstance(attempt_id, str)
                            or digest in expected):
                        raise RunnerError("V120_ATTEMPT_LEDGER_CORRUPT")
                    expected[digest] = (attempt_id, sequence)
            rows = self.db.execute(
                "SELECT receipt_sha256,attempt_id,event_sequence FROM receipt_claims"
            ).fetchall()
            actual = {digest: (attempt_id, sequence) for digest, attempt_id, sequence in rows}
            if actual != expected:
                raise RunnerError("V120_ATTEMPT_LEDGER_CORRUPT")
            return True
    def append(self, event: dict) -> dict:
        with self.lock:
            begun = False
            try:
                self.db.execute("BEGIN IMMEDIATE")
                begun = True
                events = self.events()
                previous = "0" * 64 if not events else self.db.execute(
                    "SELECT event_hmac FROM events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()[0]
                sequence = len(events) + 1
                raw = _canonical(event).decode("ascii")
                self.db.execute(
                    "INSERT INTO events VALUES(?,?,?,?)",
                    (sequence, raw, previous, self._mac(sequence, previous, raw)),
                )
                self.db.execute("COMMIT")
            except BaseException:
                if begun:
                    try:
                        self.db.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise
        return event

    def claim_receipt(self, receipt_sha256: str, attempt_id: str, event: dict) -> str | None:
        """Atomically claim one signed receipt; return the prior owning attempt on replay."""
        if (_HEX.fullmatch(receipt_sha256 or "") is None
                or _ATTEMPT_ID.fullmatch(attempt_id or "") is None
                or event.get("kind") != "claimed"
                or event.get("attempt_id") != attempt_id
                or event.get("preflight_receipt_sha256") != receipt_sha256):
            raise RunnerError("V120_PREFLIGHT_BINDING")
        with self.lock:
            begun = False
            try:
                self.db.execute("BEGIN IMMEDIATE")
                begun = True
                events = self.events()
                row = self.db.execute(
                    "SELECT attempt_id FROM receipt_claims WHERE receipt_sha256=?",
                    (receipt_sha256,),
                ).fetchone()
                if row:
                    self.db.execute("COMMIT")
                    return row[0]
                if any(item.get("attempt_id") == attempt_id for item in events):
                    raise RunnerError("V120_ATTEMPT_LEDGER_CORRUPT")
                sequence = len(events) + 1
                previous = "0" * 64 if not events else self.db.execute(
                    "SELECT event_hmac FROM events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()[0]
                raw = _canonical(event).decode("ascii")
                mac = self._mac(sequence, previous, raw)
                self.db.execute(
                    "INSERT INTO events VALUES(?,?,?,?)",
                    (sequence, raw, previous, mac),
                )
                self.db.execute(
                    "INSERT INTO receipt_claims VALUES(?,?,?)",
                    (receipt_sha256, attempt_id, sequence),
                )
                self.db.execute("COMMIT")
                return None
            except BaseException:
                if begun:
                    try:
                        self.db.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise

    def for_attempt(self, attempt_id: str) -> list[dict]:
        return [event for event in self.events() if event.get("attempt_id") == attempt_id]

    def latest(self, attempt_id: str) -> dict | None:
        items = self.for_attempt(attempt_id)
        business = [item for item in items if item.get('kind') != 'capacity_released']
        if not business:return None
        latest = dict(business[-1])
        if any(item.get('kind') == 'capacity_released'
               and item.get('capacity_released') is True for item in items):
            latest['capacity_released'] = True
        return latest

    def receipt_owner(self, receipt_sha256: str) -> str | None:
        with self.lock:
            row = self.db.execute(
                "SELECT attempt_id FROM receipt_claims WHERE receipt_sha256=?",
                (receipt_sha256,),
            ).fetchone()
        return None if row is None else row[0]

    def receipt_claimed(self, receipt_sha256: str) -> bool:
        return self.receipt_owner(receipt_sha256) is not None


def derive_attempt_identity(scope_key: bytes, scope_id: str, task_id: str,
                            workload_id: str, launch_request_id: str, *,
                            scope_revision: int, candidate_identity: dict,
                            registry_revision: int, registry_sha256: str,
                            registry_file_sha256: str, preflight_receipt_sha256: str) -> dict:
    if (not isinstance(scope_key, bytes) or len(scope_key) != 32
            or any(not isinstance(value, str) or not _ID.fullmatch(value)
                   for value in (scope_id, task_id, workload_id, launch_request_id))
            or type(scope_revision) is not int or scope_revision < 1
            or type(registry_revision) is not int or registry_revision < 1
            or not isinstance(candidate_identity, dict)
            or not all(isinstance(value, str) and _HEX.fullmatch(value)
                       for value in (registry_sha256, registry_file_sha256,
                                     preflight_receipt_sha256))):
        raise RunnerError("V120_ATTEMPT_IDENTITY")
    material = _canonical({
        "scope_id": scope_id, "scope_revision": scope_revision, "task_id": task_id,
        "workload_id": workload_id, "launch_request_id": launch_request_id,
        "candidate_identity": candidate_identity, "registry_revision": registry_revision,
        "registry_sha256": registry_sha256,
        "registry_file_sha256": registry_file_sha256,
        "preflight_receipt_sha256": preflight_receipt_sha256,
    })
    attempt_id = hmac.new(scope_key, b"attempt:" + material, hashlib.sha256).hexdigest()[:32]
    profile_id = hmac.new(scope_key, b"profile:" + material, hashlib.sha256).hexdigest()[:24]
    job_id = hmac.new(scope_key, b"job:" + material, hashlib.sha256).hexdigest()[:32]
    return {
        "attempt_id": attempt_id,
        "profile_name": "LocalControl.v120.a." + profile_id,
        "job_name": "LocalControl.v120.Job." + job_id,
    }


@dataclass(frozen=True)
class PreparedAttempt:
    attempt_id: str
    profile_name: str
    sid_string: str
    root: Path
    workspace: Path
    runtime: Path
    temp: Path
    cache: Path
    logs: Path
    home: Path
    environment: dict[str, str]
    acl_manifest: dict


class _GenericMapping(c.Structure):
    _fields_ = [("read", w.DWORD), ("write", w.DWORD),
                ("execute", w.DWORD), ("all", w.DWORD)]


class _Trustee(c.Structure):
    _fields_ = [("multiple", c.c_void_p), ("operation", c.c_int),
                ("form", c.c_int), ("kind", c.c_int), ("name", c.c_void_p)]


class _ExplicitAccess(c.Structure):
    _fields_ = [("permissions", w.DWORD), ("mode", c.c_int),
                ("inheritance", w.DWORD), ("trustee", _Trustee)]


class _SecurityAttributes(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]


class _WindowsSecurity:
    """Windows ACL editor and token AccessCheck for the trusted operator broker."""

    def __init__(self):
        if os.name != "nt":
            raise RunnerError("PLATFORM_UNSUPPORTED")
        self.k = c.WinDLL("kernel32", use_last_error=True)
        self.a = c.WinDLL("advapi32", use_last_error=True)
        self.user = c.WinDLL("userenv", use_last_error=True)
        self._bind()
        self.user_sid = self._current_user_sid()

    def _bind(self):
        self.a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
        self.a.OpenProcessToken.restype = w.BOOL
        self.a.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
        self.a.GetTokenInformation.restype = w.BOOL
        self.a.EqualSid.argtypes = [c.c_void_p, c.c_void_p]
        self.a.EqualSid.restype = w.BOOL
        self.a.GetLengthSid.argtypes = [c.c_void_p]
        self.a.GetLengthSid.restype = w.DWORD
        self.a.CopySid.argtypes = [w.DWORD, c.c_void_p, c.c_void_p]
        self.a.CopySid.restype = w.BOOL
        self.a.ConvertStringSidToSidW.argtypes = [w.LPCWSTR, c.POINTER(c.c_void_p)]
        self.a.ConvertStringSidToSidW.restype = w.BOOL
        self.a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
        self.a.ConvertSidToStringSidW.restype = w.BOOL
        self.a.SetEntriesInAclW.argtypes = [w.ULONG, c.POINTER(_ExplicitAccess), c.c_void_p, c.POINTER(c.c_void_p)]
        self.a.SetEntriesInAclW.restype = w.DWORD
        self.a.SetNamedSecurityInfoW.argtypes = [w.LPWSTR, c.c_int, w.DWORD, c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p]
        self.a.SetNamedSecurityInfoW.restype = w.DWORD
        self.a.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, c.c_int, w.DWORD, c.POINTER(c.c_void_p),
                                                  c.POINTER(c.c_void_p), c.POINTER(c.c_void_p),
                                                  c.POINTER(c.c_void_p), c.POINTER(c.c_void_p)]
        self.a.GetNamedSecurityInfoW.restype = w.DWORD
        self.a.GetSecurityDescriptorDacl.argtypes = [c.c_void_p, c.POINTER(w.BOOL), c.POINTER(c.c_void_p),
                                                      c.POINTER(w.BOOL)]
        self.a.GetSecurityDescriptorDacl.restype = w.BOOL
        self.a.GetSecurityDescriptorOwner.argtypes = [c.c_void_p, c.POINTER(c.c_void_p),
                                                       c.POINTER(w.BOOL)]
        self.a.GetSecurityDescriptorOwner.restype = w.BOOL
        self.a.GetSecurityDescriptorControl.argtypes = [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)]
        self.a.GetSecurityDescriptorControl.restype = w.BOOL
        self.a.GetSecurityDescriptorLength.argtypes = [c.c_void_p]
        self.a.GetSecurityDescriptorLength.restype = w.DWORD
        self.a.GetAclInformation.argtypes = [c.c_void_p, c.c_void_p, w.DWORD, c.c_int]
        self.a.GetAclInformation.restype = w.BOOL
        self.a.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
        self.a.GetAce.restype = w.BOOL
        self.a.DuplicateTokenEx.argtypes = [w.HANDLE, w.DWORD, c.c_void_p, c.c_int, c.c_int, c.POINTER(w.HANDLE)]
        self.a.DuplicateTokenEx.restype = w.BOOL
        self.a.AccessCheck.argtypes = [c.c_void_p, w.HANDLE, w.DWORD, c.POINTER(_GenericMapping),
                                       c.c_void_p, c.POINTER(w.DWORD), c.POINTER(w.DWORD), c.POINTER(w.BOOL)]
        self.a.AccessCheck.restype = w.BOOL
        self.k.GetCurrentProcess.restype = w.HANDLE
        self.k.CloseHandle.argtypes = [w.HANDLE]
        self.k.CloseHandle.restype = w.BOOL
        self.k.LocalFree.argtypes = [c.c_void_p]
        self.k.LocalFree.restype = c.c_void_p

    def _check(self, ok, code="V120_ACL"):
        if not ok:
            raise RunnerError(code)

    def _current_user_sid(self):
        token = w.HANDLE()
        self._check(self.a.OpenProcessToken(self.k.GetCurrentProcess(), 0x0008, c.byref(token)))
        try:
            size = w.DWORD()
            self.a.GetTokenInformation(token, 1, None, 0, c.byref(size))
            data = c.create_string_buffer(size.value)
            self._check(self.a.GetTokenInformation(token, 1, data, size.value, c.byref(size)))
            sid = c.cast(data, c.POINTER(c.c_void_p))[0]
            sid_size = self.a.GetLengthSid(sid)
            copied = c.create_string_buffer(sid_size)
            self._check(bool(self.a.CopySid(sid_size, copied, sid)))
            return copied
        finally:
            self.k.CloseHandle(token)

    def sid_string(self, sid) -> str:
        text = w.LPWSTR()
        self._check(self.a.ConvertSidToStringSidW(sid, c.byref(text)))
        try:
            return text.value
        finally:
            self.k.LocalFree(text)

    def sid_from_string(self, value: str):
        sid = c.c_void_p()
        self._check(self.a.ConvertStringSidToSidW(value, c.byref(sid)))
        return sid

    def _sid_bytes(self, sid) -> bytes:
        size = self.a.GetLengthSid(sid)
        return c.string_at(sid, size)

    def _apply_acl(self, path: Path, app_sid, app_rights: int, inherit: int):
        system = self.sid_from_string("S-1-5-18")
        admins = self.sid_from_string("S-1-5-32-544")
        sids = [system, admins, c.cast(self.user_sid, c.c_void_p), app_sid]
        rights = [0x001F01FF, 0x001F01FF, 0x001F01FF, app_rights]
        # Worker-created descendants must retain the same trusted custodians.
        # Only attempt-owned directories receive inheritable ACEs; protected
        # files and the owner marker retain their explicit noninheriting ACLs.
        flags = [inherit, inherit, inherit, inherit]
        if app_rights == 0:
            # No worker allow ACE is the exact deny-by-default representation.
            # SetEntriesInAclW omits zero-mask allow entries on Windows.
            sids, rights, flags = sids[:3], rights[:3], flags[:3]
        holders = []
        entries = (_ExplicitAccess * len(sids))()
        for i, sid in enumerate(sids):
            trustee = _Trustee(None, 0, 0, 0, c.cast(sid, c.c_void_p))
            entries[i] = _ExplicitAccess(rights[i], 2, flags[i], trustee)
            holders.append(sid)
        acl = c.c_void_p()
        status = self.a.SetEntriesInAclW(len(entries), entries, None, c.byref(acl))
        if status != 0:
            raise RunnerError("V120_ACL_CREATE")
        try:
            status = self.a.SetNamedSecurityInfoW(
                str(path), 1, 0x00000001 | 0x00000004 | 0x80000000,
                c.cast(self.user_sid, c.c_void_p), None, acl, None,
            )
            if status != 0:
                raise RunnerError("V120_ACL_APPLY")
        finally:
            self.k.LocalFree(acl)
            for sid in (system, admins):
                self.k.LocalFree(sid)

    def descriptor(self, path: Path) -> tuple[bytes, c.c_void_p, c.c_void_p]:
        owner, group, dacl, sacl, descriptor = (c.c_void_p(), c.c_void_p(), c.c_void_p(),
                                                  c.c_void_p(), c.c_void_p())
        status = self.a.GetNamedSecurityInfoW(
            str(path), 1, 0x00000001 | 0x00000002 | 0x00000004, c.byref(owner), c.byref(group),
            c.byref(dacl), c.byref(sacl), c.byref(descriptor),
        )
        if status != 0:
            raise RunnerError("V120_ACL_READ")
        length = self.a.GetSecurityDescriptorLength(descriptor)
        raw = c.string_at(descriptor, length)
        return raw, descriptor, dacl

    def _assert_dacl(self, path: Path, expected: dict[bytes, tuple[int, int]]):
        raw, descriptor, dacl = self.descriptor(path)
        try:
            owner, owner_defaulted = c.c_void_p(), w.BOOL()
            self._check(self.a.GetSecurityDescriptorOwner(
                descriptor, c.byref(owner), c.byref(owner_defaulted)))
            if not self.a.EqualSid(owner, c.cast(self.user_sid, c.c_void_p)):
                raise RunnerError("V120_ACL_OWNER")
            present, defaulted = w.BOOL(), w.BOOL()
            self._check(self.a.GetSecurityDescriptorDacl(
                descriptor, c.byref(present), c.byref(dacl), c.byref(defaulted)))
            control, revision = w.WORD(), w.DWORD()
            self._check(self.a.GetSecurityDescriptorControl(
                descriptor, c.byref(control), c.byref(revision)))
            if not present.value or not dacl or not (control.value & 0x1000):
                raise RunnerError("V120_ACL_INHERITANCE")
            class _AclSize(c.Structure):
                _fields_ = [("ace_count", w.DWORD), ("bytes_free", w.DWORD), ("bytes_used", w.DWORD)]
            info = _AclSize()
            self._check(self.a.GetAclInformation(dacl, c.byref(info), c.sizeof(info), 2))
            if info.ace_count != len(expected):
                raise RunnerError("V120_ACL_MISMATCH")
            actual = {}
            for index in range(info.ace_count):
                ace = c.c_void_p()
                self._check(self.a.GetAce(dacl, index, c.byref(ace)))
                header = c.string_at(ace, 8)
                ace_type, ace_flags = header[0], header[1]
                mask = int.from_bytes(header[4:8], "little")
                if ace_type != 0:
                    raise RunnerError("V120_ACL_UNEXPECTED_ACE")
                sid = c.c_void_p(ace.value + 8)
                sid_bytes = self._sid_bytes(sid)
                if sid_bytes in actual:
                    raise RunnerError("V120_ACL_DUPLICATE_ACE")
                actual[sid_bytes] = (mask, ace_flags)
            if actual != expected:
                raise RunnerError("V120_ACL_MISMATCH")
            return hashlib.sha256(raw).hexdigest()
        finally:
            self.k.LocalFree(descriptor)

    def snapshot(self, path: Path) -> dict:
        target = _safe_existing(Path(path))
        info = target.stat(follow_symlinks=False)
        raw, descriptor, _ = self.descriptor(target)
        try:
            return {
                "path": str(target),
                "volume": int(info.st_dev),
                "file_id": int(info.st_ino),
                "acl_sha256": hashlib.sha256(raw).hexdigest(),
            }
        finally:
            self.k.LocalFree(descriptor)

    def apply_and_verify(self, path: Path, app_sid, app_rights: int, inherit: int) -> dict:
        self._apply_acl(path, app_sid, app_rights, inherit)
        system, admins = self.sid_from_string("S-1-5-18"), self.sid_from_string("S-1-5-32-544")
        try:
            expected = {
                self._sid_bytes(system): (0x001F01FF, inherit),
                self._sid_bytes(admins): (0x001F01FF, inherit),
                self._sid_bytes(c.cast(self.user_sid, c.c_void_p)): (0x001F01FF, inherit),
            }
            if app_rights != 0:
                expected[self._sid_bytes(app_sid)] = (app_rights, inherit)
            digest = self._assert_dacl(path, expected)
            info = path.stat(follow_symlinks=False)
            return {"path": str(path.resolve(strict=True)), "file_id": int(info.st_ino),
                    "volume": int(info.st_dev), "is_directory": bool(path.is_dir()),
                    "links": int(info.st_nlink), "acl_sha256": digest,
                    "worker_rights": app_rights, "inherit_flags": inherit}
        finally:
            self.k.LocalFree(system)
            self.k.LocalFree(admins)

    def access(self, token, path: Path, desired: int) -> bool:
        _, descriptor, _ = self.descriptor(path)
        impersonation = w.HANDLE()
        try:
            self._check(self.a.DuplicateTokenEx(token, 0x0008, None, 2, 2, c.byref(impersonation)))
            mapping = _GenericMapping(_FILE_GENERIC_READ, _FILE_GENERIC_WRITE,
                                      _FILE_GENERIC_EXECUTE, 0x001F01FF)
            size, granted, allowed = w.DWORD(), w.DWORD(), w.BOOL()
            ok = self.a.AccessCheck(descriptor, impersonation, desired, c.byref(mapping),
                                    None, c.byref(size), c.byref(granted), c.byref(allowed))
            if not ok and c.get_last_error() == 122:
                privileges = c.create_string_buffer(size.value)
                ok = self.a.AccessCheck(descriptor, impersonation, desired, c.byref(mapping),
                                        privileges, c.byref(size), c.byref(granted), c.byref(allowed))
            self._check(ok, "V120_ACL_ACCESS_CHECK")
            return bool(allowed.value)
        finally:
            self.k.CloseHandle(impersonation)
            self.k.LocalFree(descriptor)

    def has_write_access(self, token, path: Path) -> bool:
        # A combined AccessCheck requires every requested bit. Reject even a
        # single mutation right on a protected object, including ACL changes.
        return any(self.access(token, path, bit) for bit in _WRITE_ACCESS_BITS)

    def verify_worker_access(self, token, prepared: PreparedAttempt, worker: dict,
                             other_attempt_roots=()):
        manifest = prepared.acl_manifest
        body = {key: value for key, value in manifest.items() if key != "acl_manifest_sha256"}
        if not hmac.compare_digest(
                hashlib.sha256(_canonical(body)).hexdigest(),
                manifest.get("acl_manifest_sha256", "")):
            raise RunnerError("V120_ACL_MANIFEST_TAMPERED")
        root_text = ntpath.normcase(str(prepared.root.resolve(strict=True)))
        seen = set()
        for entry in manifest.get("acl_entries", []):
            target = _safe_existing(Path(entry["path"]))
            normalized = ntpath.normcase(str(target))
            if normalized in seen or not _inside(normalized, root_text):
                raise RunnerError("V120_ACL_MANIFEST_PATH")
            seen.add(normalized)
            info = target.stat(follow_symlinks=False)
            if (int(info.st_dev) != entry.get("volume")
                    or int(info.st_ino) != entry.get("file_id")
                    or bool(target.is_dir()) != entry.get("is_directory")
                    or int(info.st_nlink) != entry.get("links")
                    or (not target.is_dir() and info.st_nlink != 1)):
                raise RunnerError("V120_ACL_PATH_CHANGED")
            raw, descriptor, _ = self.descriptor(target)
            try:
                current_acl = hashlib.sha256(raw).hexdigest()
            finally:
                self.k.LocalFree(descriptor)
            if not hmac.compare_digest(current_acl, entry.get("acl_sha256", "")):
                raise RunnerError("V120_ACL_CHANGED")

        for category in ("protected_roots", "canonical_readonly_roots"):
            snapshots = manifest.get(category, [])
            expected = {ntpath.normcase(item["path"]): item for item in snapshots}
            requested = worker["protected_roots"] if category == "protected_roots" else worker["canonical_readonly_roots"]
            if set(expected) != {ntpath.normcase(str(_safe_existing(Path(item)))) for item in requested}:
                raise RunnerError("V120_ACL_ROOT_SET_CHANGED")
            for item in requested:
                target = _safe_existing(Path(item))
                observed = self.snapshot(target)
                original = expected[ntpath.normcase(str(target))]
                if any(observed[key] != original.get(key)
                       for key in ("path", "volume", "file_id", "acl_sha256")):
                    raise RunnerError("V120_ACL_ROOT_CHANGED")

        owner_marker = manifest.get("owner_marker")
        marker_path = prepared.root / _OWNER_MARKER_NAME
        if (not isinstance(owner_marker, dict)
                or manifest.get("owner_marker_sha256") != hashlib.sha256(
                    _canonical(owner_marker)
                ).hexdigest()):
            raise RunnerError("V120_ATTEMPT_OWNER_MARKER")
        marker = _safe_existing(marker_path, file=True)
        if (marker.stat(follow_symlinks=False).st_nlink != 1
                or marker.read_bytes() != _canonical(owner_marker)):
            raise RunnerError("V120_ATTEMPT_OWNER_MARKER")
        marker_entries = [
            entry for entry in manifest.get("acl_entries", [])
            if ntpath.normcase(entry.get("path", "")) == ntpath.normcase(str(marker))
        ]
        if (len(marker_entries) != 1 or marker_entries[0].get("worker_rights") != 0
                or self.access(token, marker, _FILE_READ_EXECUTE)
                or self.has_write_access(token, marker)):
            raise RunnerError("V120_ATTEMPT_OWNER_MARKER_ACCESS")

        expected_runtime = {}
        for item in manifest.get("runtime_files", []):
            if not isinstance(item, dict):
                raise RunnerError("V120_RUNTIME_MANIFEST")
            relative = _safe_relative(item.get("relative_path"))
            key = ntpath.normcase(relative.as_posix().replace("/", "\\"))
            if key in expected_runtime:
                raise RunnerError("V120_RUNTIME_MANIFEST")
            target = _safe_existing(prepared.runtime.joinpath(*relative.parts), file=True)
            if (not _inside(str(target), str(prepared.runtime))
                    or target.stat(follow_symlinks=False).st_nlink != 1
                    or not hmac.compare_digest(_sha256(target), item.get("sha256", ""))):
                raise RunnerError("V120_RUNTIME_COPY_HASH")
            expected_runtime[key] = item["sha256"]
        actual_runtime = set()
        for target in prepared.runtime.rglob("*"):
            target = _safe_existing(target)
            if target.is_dir():
                continue
            key = ntpath.normcase(
                target.relative_to(prepared.runtime).as_posix().replace("/", "\\")
            )
            if key not in expected_runtime or key in actual_runtime:
                raise RunnerError("V120_RUNTIME_MANIFEST")
            actual_runtime.add(key)
        if actual_runtime != set(expected_runtime):
            raise RunnerError("V120_RUNTIME_MANIFEST")

        if not self.access(token, prepared.root, _FILE_READ_EXECUTE):
            raise RunnerError("V120_SUBJECT_ROOT_DENIED")
        if self.has_write_access(token, prepared.root):
            raise RunnerError("V120_SUBJECT_ROOT_WRITABLE")
        if not self.access(token, prepared.workspace, _FILE_READ_EXECUTE):
            raise RunnerError("V120_SUBJECT_READ_DENIED")
        if not self.access(token, prepared.workspace, _FILE_GENERIC_WRITE):
            raise RunnerError("V120_SUBJECT_WRITE_DENIED")
        for path in (prepared.temp, prepared.cache, prepared.logs, prepared.home):
            if not self.access(token, path, _FILE_READ_EXECUTE):
                raise RunnerError("V120_PRIVATE_DIRECTORY_READ_DENIED")
            if not self.access(token, path, _FILE_GENERIC_WRITE):
                raise RunnerError("V120_PRIVATE_DIRECTORY_WRITE_DENIED")
        if not self.access(token, prepared.runtime, _FILE_READ_EXECUTE):
            raise RunnerError("V120_RUNTIME_READ_DENIED")
        if self.has_write_access(token, prepared.runtime):
            raise RunnerError("V120_RUNTIME_WRITABLE")
        parent = _safe_existing(Path(worker["subject_parent"]), file=False)
        if self.access(token, parent, _FILE_READ_EXECUTE) or self.has_write_access(token, parent):
            raise RunnerError("V120_SUBJECT_PARENT_ACCESS")
        for path in manifest.get("acl_entries", []):
            if path.get("path") == str(prepared.runtime):
                continue
            target = Path(path["path"])
            if path.get("worker_rights") == _FILE_READ_EXECUTE:
                if not self.access(token, target, _FILE_READ_EXECUTE):
                    raise RunnerError("V120_RUNTIME_READ_DENIED")
                if self.has_write_access(token, target):
                    raise RunnerError("V120_RUNTIME_WRITABLE")
        for path in worker["protected_roots"]:
            target = _safe_existing(Path(path))
            if self.access(token, target, _FILE_READ_EXECUTE) or self.has_write_access(token, target):
                raise RunnerError("V120_PROTECTED_ROOT_ACCESS")
        for path in worker["canonical_readonly_roots"]:
            target = _safe_existing(Path(path))
            if not self.access(token, target, _FILE_READ_EXECUTE):
                raise RunnerError("V120_READONLY_ROOT_DENIED")
            if self.has_write_access(token, target):
                raise RunnerError("V120_READONLY_ROOT_WRITABLE")
        for path in other_attempt_roots:
            target = _safe_existing(Path(path), file=False)
            if ntpath.normcase(str(target)) == ntpath.normcase(str(prepared.root)):
                continue
            if self.access(token, target, _FILE_READ_EXECUTE) or self.has_write_access(token, target):
                raise RunnerError("V120_OTHER_ATTEMPT_ACCESS")


class NamedAttemptJob(WindowsJob):
    """Named exact-attempt Job Object with an operator-only DACL."""

    def __init__(self, limits: dict, name: str, sddl: str):
        super().__init__(limits)
        self.close()
        self.name = name
        self.k.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
        self.k.CreateJobObjectW.restype = w.HANDLE
        advapi = c.WinDLL("advapi32", use_last_error=True)
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.POINTER(w.DWORD)]
        convert.restype = w.BOOL
        descriptor = c.c_void_p()
        c.set_last_error(0)
        if not convert(sddl, 1, c.byref(descriptor), None):
            raise c.WinError(c.get_last_error())
        try:
            attrs = _SecurityAttributes(c.sizeof(_SecurityAttributes), descriptor, False)
            self.handle = self.k.CreateJobObjectW(c.byref(attrs), name)
            error = c.get_last_error()
            if not self.handle:
                raise c.WinError(error)
            if error == 183:
                self.close()
                raise RunnerError("V120_JOB_NAME_REPLAY")
            try:
                # The base constructor's unnamed job and IOCP were closed above.
                # Attach a fresh port to this named job before assigning a worker.
                self._initialize_completion_port()
                self._set_limits()
                self._verify_security()
            except BaseException:
                self.close()
                raise
        finally:
            self.k.LocalFree(descriptor)

    @classmethod
    def reopen(cls, limits: dict, name: str):
        instance = cls.__new__(cls)
        WindowsJob.__init__(instance, limits)
        instance.close()
        # This is an observation/termination handle, never a new monitor owner.
        # A job has one IOCP; replacing it could displace the live owner's port
        # and cannot reconstruct notifications from before this handle opened.
        instance._completion_port_available = False
        instance._completion_port_error = "reopened_observer_history_unknown"
        instance.name = name
        instance.k.OpenJobObjectW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
        instance.k.OpenJobObjectW.restype = w.HANDLE
        instance.handle = instance.k.OpenJobObjectW(0x0002000C, False, name)
        if not instance.handle:
            raise c.WinError(c.get_last_error())
        try:
            instance._verify_security()
            instance._verify_limits()
        except BaseException:
            instance.close()
            raise
        return instance

    def stats(self) -> dict:
        result = super().stats()
        observer = self._completion_port_error == "reopened_observer_history_unknown"
        healthy = (result.get("completion_port_available") is True
                   and result.get("completion_port_error") is None)
        result["monitor_role"] = "observer" if observer else ("owner" if healthy else "owner_monitor_unavailable")
        result["completion_history"] = "owned_port_notifications" if healthy and not observer else "unknown"
        return result

    def _verify_security(self):
        advapi = c.WinDLL("advapi32", use_last_error=True)
        advapi.GetSecurityInfo.argtypes = [
            w.HANDLE, w.DWORD, w.DWORD,
            c.POINTER(c.c_void_p), c.POINTER(c.c_void_p),
            c.POINTER(c.c_void_p), c.POINTER(c.c_void_p), c.POINTER(c.c_void_p),
        ]
        advapi.GetSecurityInfo.restype = w.DWORD
        advapi.GetSecurityDescriptorDacl.argtypes = [
            c.c_void_p, c.POINTER(w.BOOL), c.POINTER(c.c_void_p), c.POINTER(w.BOOL),
        ]
        advapi.GetSecurityDescriptorDacl.restype = w.BOOL
        advapi.GetSecurityDescriptorControl.argtypes = [
            c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD),
        ]
        advapi.GetSecurityDescriptorControl.restype = w.BOOL
        advapi.GetAclInformation.argtypes = [
            c.c_void_p, c.c_void_p, w.DWORD, c.c_int,
        ]
        advapi.GetAclInformation.restype = w.BOOL
        advapi.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
        advapi.GetAce.restype = w.BOOL
        advapi.GetLengthSid.argtypes = [c.c_void_p]
        advapi.GetLengthSid.restype = w.DWORD
        kernel = c.WinDLL("kernel32", use_last_error=True)
        kernel.LocalFree.argtypes = [c.c_void_p]
        kernel.LocalFree.restype = c.c_void_p

        owner, dacl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
        status = advapi.GetSecurityInfo(
            self.handle, 6, 0x00000001 | 0x00000004,
            c.byref(owner), None, c.byref(dacl), None, c.byref(descriptor),
        )
        if status != 0:
            raise RunnerError("V120_JOB_SECURITY_READ")
        try:
            present, defaulted = w.BOOL(), w.BOOL()
            if not owner or not advapi.GetSecurityDescriptorDacl(
                    descriptor, c.byref(present), c.byref(dacl), c.byref(defaulted)):
                raise RunnerError("V120_JOB_SECURITY_READ")
            control, revision = w.WORD(), w.DWORD()
            if not advapi.GetSecurityDescriptorControl(
                    descriptor, c.byref(control), c.byref(revision)):
                raise RunnerError("V120_JOB_SECURITY_READ")
            if not present.value or not dacl or not (control.value & 0x1000):
                raise RunnerError("V120_JOB_SECURITY_INHERITANCE")

            class AclSize(c.Structure):
                _fields_ = [
                    ("ace_count", w.DWORD), ("bytes_free", w.DWORD),
                    ("bytes_used", w.DWORD),
                ]

            info = AclSize()
            if not advapi.GetAclInformation(
                    dacl, c.byref(info), c.sizeof(info), 2):
                raise RunnerError("V120_JOB_SECURITY_READ")
            owner_sid = c.string_at(owner, advapi.GetLengthSid(owner))
            allowed_sids = {
                _sid_bytes_from_text(advapi, kernel, "S-1-5-18"),
                _sid_bytes_from_text(advapi, kernel, "S-1-5-32-544"),
                _current_process_user_sid(advapi, kernel),
            }
            entries = []
            for index in range(info.ace_count):
                ace = c.c_void_p()
                if not advapi.GetAce(dacl, index, c.byref(ace)):
                    raise RunnerError("V120_JOB_SECURITY_READ")
                if not ace:
                    raise RunnerError("V120_JOB_SECURITY_READ")
                header = c.string_at(ace, 4)
                ace_type, ace_flags, ace_size = _validate_acl_ace_header(header)
                mask = int.from_bytes(c.string_at(ace.value + 4, 4), "little")
                sid = c.c_void_p(ace.value + 8)
                sid_length = advapi.GetLengthSid(sid)
                if not sid_length or sid_length > ace_size - 8:
                    raise RunnerError("V120_JOB_SECURITY_READ")
                entries.append((
                    ace_type, ace_flags, mask, c.string_at(sid, sid_length),
                ))
            _validate_acl_entries(
                owner_sid, entries, allowed_sids,
                exact_allow_mask=0x001F001F,
                expected_allow_sids=allowed_sids,
                allow_deny_aces=False,
            )
        finally:
            kernel.LocalFree(descriptor)

    def _set_limits(self):
        info = _ExtendedLimits()
        flags = self.LIMIT_KILL_ON_JOB_CLOSE
        if "cpu_ms" in self.limits:
            flags |= self.LIMIT_JOB_TIME
            info.basic.job = self.limits["cpu_ms"] * 10000
        if "max_processes" in self.limits:
            flags |= self.LIMIT_ACTIVE_PROCESS
            info.basic.active = self.limits["max_processes"]
        if "memory_bytes" in self.limits:
            flags |= self.LIMIT_JOB_MEMORY
            info.job_mem = self.limits["memory_bytes"]
        info.basic.flags = flags
        if not self.k.SetInformationJobObject(self.handle, 9, c.byref(info), c.sizeof(info)):
            raise c.WinError(c.get_last_error())

    def _verify_limits(self):
        info = _ExtendedLimits()
        if not self.k.QueryInformationJobObject(self.handle, 9, c.byref(info), c.sizeof(info), None):
            raise c.WinError(c.get_last_error())
        expected_flags = self.LIMIT_KILL_ON_JOB_CLOSE
        if self.limits.get("cpu_ms"):
            expected_flags |= self.LIMIT_JOB_TIME
        if self.limits.get("max_processes"):
            expected_flags |= self.LIMIT_ACTIVE_PROCESS
        if self.limits.get("memory_bytes"):
            expected_flags |= self.LIMIT_JOB_MEMORY
        if info.basic.flags != expected_flags:
            raise RunnerError("V120_JOB_POLICY")
        if self.limits.get("cpu_ms") and info.basic.job != self.limits["cpu_ms"] * 10000:
            raise RunnerError("V120_JOB_POLICY")
        if self.limits.get("memory_bytes") and info.job_mem != self.limits["memory_bytes"]:
            raise RunnerError("V120_JOB_POLICY")
        if self.limits.get("max_processes") and info.basic.active != self.limits["max_processes"]:
            raise RunnerError("V120_JOB_POLICY")


class WindowsAttemptBroker:
    """Trusted LocalControl side that creates and verifies one disposable attempt."""

    def __init__(self):
        self.security = _WindowsSecurity()

    def _profile_sid(self, profile_name: str):
        from .appcontainer import WinAPI
        api = WinAPI()
        created = c.c_void_p()
        hr = api.create_profile(
            profile_name, profile_name,
            "Disposable LocalControl v1.2 task attempt", None, 0, c.byref(created)
        )
        if (hr & 0xFFFFFFFF) != 0:
            raise RunnerError("V120_PROFILE_CREATE")
        try:
            sid_text = self.security.sid_string(created)
        finally:
            api.free_sid(created)
        sid = c.c_void_p()
        status = api.derive(profile_name, c.byref(sid))
        if status != 0:
            raise RunnerError("V120_PROFILE_DERIVE")
        return api, sid, sid_text

    def _delete_profile(self, profile_name: str, *, allow_missing: bool = False) -> bool:
        from .appcontainer import WinAPI
        api = WinAPI()
        hr = api.delete_profile(profile_name)
        if hr == 0:
            return True
        status = hr & 0xFFFFFFFF
        if allow_missing and status == 0x80070002:
            return False
        raise RunnerError("V120_PROFILE_DELETE")

    def snapshot_subject_parent(self, worker: dict, attempt_id: str) -> dict:
        parent = _safe_existing(Path(worker["subject_parent"]), file=False)
        if not isinstance(attempt_id, str) or _ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise RunnerError("V120_ATTEMPT_ID")
        root = parent / attempt_id
        if root.exists() or root.is_symlink():
            raise RunnerError("V120_ATTEMPT_PATH_EXISTS")
        return self.security.snapshot(parent)

    def prepare(self, payload: dict, identity: dict, workload: dict,
                manifest: dict) -> PreparedAttempt:
        if os.name != "nt":
            raise RunnerError("PLATFORM_UNSUPPORTED")
        worker = payload["worker"]
        parent = _safe_existing(Path(worker["subject_parent"]), file=False)
        parent_snapshot = self.security.snapshot(parent)
        if parent_snapshot != identity.get("subject_parent_snapshot"):
            raise RunnerError("V120_ATTEMPT_PARENT_CHANGED")
        root = parent / identity["attempt_id"]
        if root.exists() or root.is_symlink():
            raise RunnerError("V120_ATTEMPT_PATH_EXISTS")
        owner_marker = identity.get("owner_marker")
        if not isinstance(owner_marker, dict):
            raise RunnerError("V120_ATTEMPT_OWNER_MARKER")
        marker_path = root / _OWNER_MARKER_NAME
        api, sid, sid_text = self._profile_sid(identity["profile_name"])
        created_root = False
        try:
            root.mkdir()
            created_root = True
            with marker_path.open("xb") as stream:
                stream.write(_canonical(owner_marker))
                stream.flush()
                os.fsync(stream.fileno())
            marker = _safe_existing(marker_path, file=True)
            dirs = {name: root / name for name in
                    ("workspace", "runtime", "tmp", "cache", "logs", "home")}
            for target in dirs.values():
                target.mkdir()
            acl = [self.security.apply_and_verify(root, sid, _FILE_READ_EXECUTE, 0)]
            acl.append(self.security.apply_and_verify(marker, sid, 0, 0))
            for name in ("workspace", "tmp", "cache", "logs", "home"):
                acl.append(self.security.apply_and_verify(
                    dirs[name], sid, _FILE_MODIFY, 3
                ))
            runtime_source_roots = worker["runtime_roots"]
            for item in manifest["runtime_files"]:
                source = _safe_existing(Path(item["source_path"]), file=True)
                if not any(_inside(str(source), root_path) for root_path in runtime_source_roots):
                    raise RunnerError("V120_WORKLOAD_PATH")
                relative = _safe_relative(item["relative_path"])
                destination = dirs["runtime"].joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                _safe_existing(destination.parent, file=False)
                shutil.copyfile(source, destination, follow_symlinks=False)
                copied = _safe_existing(destination, file=True)
                if not hmac.compare_digest(_sha256(copied), item["sha256"]):
                    raise RunnerError("V120_RUNTIME_COPY_HASH")
                acl.append(self.security.apply_and_verify(
                    copied, sid, _FILE_READ_EXECUTE, 0
                ))
            runtime_tree = sorted(
                dirs["runtime"].rglob("*"), key=lambda target: len(target.parts), reverse=True
            )
            for target in runtime_tree:
                _safe_existing(target)
                if target.is_dir():
                    acl.append(self.security.apply_and_verify(
                        target, sid, _FILE_READ_EXECUTE, 3
                    ))
            acl.append(self.security.apply_and_verify(
                dirs["runtime"], sid, _FILE_READ_EXECUTE, 3
            ))
            executable = dirs["runtime"].joinpath(
                *_safe_relative(manifest["executable_relative"]).parts
            )
            _safe_existing(executable, file=True)
            if not hmac.compare_digest(_sha256(executable),
                                       next(item["sha256"] for item in manifest["runtime_files"]
                                            if item["relative_path"].casefold()
                                            == manifest["executable_relative"].casefold())):
                raise RunnerError("V120_WORKLOAD_EXECUTABLE")

            protected_snapshots = [
                self.security.snapshot(_safe_existing(Path(value)))
                for value in worker["protected_roots"]
            ]
            readonly_snapshots = [
                self.security.snapshot(_safe_existing(Path(value)))
                for value in worker["canonical_readonly_roots"]
            ]
            private_home = str(dirs["home"])
            env = {
                "SYSTEMROOT": os.environ.get("SystemRoot", r"C:\Windows"),
                "WINDIR": os.environ.get("WINDIR", os.environ.get("SystemRoot", r"C:\Windows")),
                "TEMP": str(dirs["tmp"]), "TMP": str(dirs["tmp"]),
                "USERPROFILE": private_home, "APPDATA": private_home,
                "LOCALAPPDATA": private_home, "HOMEDRIVE": str(root.drive),
                "HOMEPATH": private_home[len(root.drive):],
                "PATH": str(dirs["runtime"]), "PYTHONHOME": str(dirs["runtime"]),
                "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUTF8": "1",
            }
            if set(env) != {
                "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "APPDATA",
                "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH", "PATH", "PYTHONHOME",
                "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE", "PYTHONUTF8",
            } or any("\0" in key or "\0" in value for key, value in env.items()):
                raise RunnerError("V120_ENVIRONMENT")
            identity_manifest = {
                "schema": "localcontrol-v120-attempt-acl-v1",
                "attempt_id": identity["attempt_id"],
                "scope_id": payload["scope_id"],
                "scope_revision": payload["scope_revision"],
                "task_id": payload["task_id"],
                "workload_id": workload["workload_id"],
                "candidate_identity": payload["candidate_identity"],
                "registry_revision": payload["registry_revision"],
                "registry_sha256": payload["registry_sha256"],
                "registry_file_sha256": payload["registry_file_sha256"],
                "runner_policy_sha256": worker["runner_policy_sha256"],
                "profile_name": identity["profile_name"],
                "sid": sid_text,
                "job_name": identity["job_name"],
                "subject_parent": str(parent),
                "subject_parent_snapshot": parent_snapshot,
                "owner_marker": owner_marker,
                "owner_marker_sha256": hashlib.sha256(_canonical(owner_marker)).hexdigest(),
                "root": str(root),
                "directories": {key: str(value) for key, value in dirs.items()},
                "acl_entries": acl,
                "protected_roots": protected_snapshots,
                "canonical_readonly_roots": readonly_snapshots,
                "runtime_files": manifest["runtime_files"],
                "workload_manifest_sha256": workload["manifest_sha256"],
            }
            acl_manifest = identity_manifest | {
                "acl_manifest_sha256": hashlib.sha256(
                    _canonical(identity_manifest)
                ).hexdigest()
            }
            return PreparedAttempt(
                identity["attempt_id"], identity["profile_name"], sid_text, root,
                dirs["workspace"], dirs["runtime"], dirs["tmp"], dirs["cache"],
                dirs["logs"], dirs["home"], env, acl_manifest,
            )
        except BaseException as original:
            cleanup_failed = False
            if created_root:
                try:
                    self._remove_exact_tree(root)
                except BaseException:
                    cleanup_failed = True
            try:
                api.delete_profile(identity["profile_name"])
            except BaseException:
                cleanup_failed = True
            if cleanup_failed:
                raise RunnerError("V120_PREPARE_CLEANUP_FAILED") from original
            raise
        finally:
            api.free_sid(sid)

    def recover_partial(self, claim: dict) -> dict:
        parent = _safe_existing(Path(claim["subject_parent"]), file=False)
        expected_snapshot = claim.get("subject_parent_snapshot")
        if self.security.snapshot(parent) != expected_snapshot:
            raise RunnerError("V120_ATTEMPT_PARENT_CHANGED")
        root = parent / claim["attempt_id"]
        if root.is_symlink():
            raise RunnerError("V120_PARTIAL_OWNER_UNPROVEN")
        if root.exists():
            root = _safe_existing(root, file=False)
            marker_path = root / _OWNER_MARKER_NAME
            try:
                marker = _safe_existing(marker_path, file=True)
                raw = marker.read_bytes()
            except OSError:
                raise RunnerError("V120_PARTIAL_OWNER_UNPROVEN") from None
            if (marker.stat(follow_symlinks=False).st_nlink != 1
                    or raw != _canonical(claim.get("owner_marker"))):
                raise RunnerError("V120_PARTIAL_OWNER_UNPROVEN")
        job = self._job_if_present(claim)
        if job is not None:
            job.close()
            raise RunnerError("V120_PARTIAL_JOB_EXISTS")
        if root.exists():
            self._remove_exact_tree(root)
        self._delete_profile(claim["profile_name"], allow_missing=True)
        return {"attempt_id": claim["attempt_id"], "cleaned": True,
                "partial_resources_removed": True}

    def job_sddl(self) -> str:
        current = self.security.sid_string(c.cast(self.security.user_sid, c.c_void_p))
        # Pin concrete Job Object rights. Windows maps GENERIC_ALL when it
        # creates the object, so comparing the returned DACL to GA is invalid.
        return f"D:P(A;;0x001F001F;;;SY)(A;;0x001F001F;;;BA)(A;;0x001F001F;;;{current})"

    def start_suspended(self, prepared: PreparedAttempt, identity: dict,
                        manifest: dict, workload: dict, other_attempt_roots=()):
        from .appcontainer import spawn
        job = NamedAttemptJob(workload["resource_limits"], identity["job_name"], self.job_sddl())
        executable = prepared.runtime.joinpath(
            *_safe_relative(manifest["executable_relative"]).parts
        )
        argv = [str(executable), *manifest["argv"]]
        try:
            process = spawn(
                argv, prepared.workspace, prepared.environment, prepared.profile_name, job,
                pre_resume_check=lambda handle, token, sid: self.security.verify_worker_access(
                    token, prepared, identity["worker"], other_attempt_roots
                ),
            )
            return process, job
        except BaseException:
            job.close()
            raise

    def _check_manifest_paths(self, event: dict) -> Path:
        manifest = event.get("acl_manifest")
        recorded_hash = event.get("acl_manifest_sha256")
        if (not isinstance(manifest, dict)
                or not isinstance(recorded_hash, str)
                or not hmac.compare_digest(
                    hashlib.sha256(_canonical({
                        key: value for key, value in manifest.items()
                        if key != "acl_manifest_sha256"
                    })).hexdigest(), recorded_hash)
                or manifest.get("acl_manifest_sha256") != recorded_hash
                or manifest.get("attempt_id") != event.get("attempt_id")
                or manifest.get("profile_name") != event.get("profile_name")
                or manifest.get("job_name") != event.get("job_name")
                or manifest.get("subject_parent") != event.get("subject_parent")
                or manifest.get("owner_marker") != event.get("owner_marker")
                or manifest.get("owner_marker_sha256") != hashlib.sha256(
                    _canonical(event.get("owner_marker"))
                ).hexdigest()):
            raise RunnerError("V120_CLEANUP_IDENTITY")
        parent = _safe_existing(Path(event["subject_parent"]), file=False)
        root = _safe_existing(Path(event["subject_root"]), file=False)
        expected = parent / event["attempt_id"]
        if ntpath.normcase(str(root)) != ntpath.normcase(str(expected)):
            raise RunnerError("V120_ATTEMPT_PATH")
        if ntpath.normcase(str(root)) != ntpath.normcase(str(manifest.get("root", ""))):
            raise RunnerError("V120_ATTEMPT_PATH")
        marker_path = _safe_existing(root / _OWNER_MARKER_NAME, file=True)
        if (marker_path.stat(follow_symlinks=False).st_nlink != 1
                or marker_path.read_bytes() != _canonical(event["owner_marker"])):
            raise RunnerError("V120_ATTEMPT_OWNER_MARKER")
        marker_entries = [
            entry for entry in manifest.get("acl_entries", [])
            if ntpath.normcase(entry.get("path", "")) == ntpath.normcase(str(marker_path))
        ]
        if len(marker_entries) != 1 or marker_entries[0].get("worker_rights") != 0:
            raise RunnerError("V120_ATTEMPT_OWNER_MARKER_ACCESS")
        directories = manifest.get("directories")
        if not isinstance(directories, dict) or any(
                ntpath.normcase(str(directories.get(name, "")))
                != ntpath.normcase(str(root / name))
                for name in ("workspace", "runtime", "tmp", "cache", "logs", "home")):
            raise RunnerError("V120_CLEANUP_IDENTITY")
        parent_snapshot = self.security.snapshot(parent)
        if parent_snapshot != manifest.get("subject_parent_snapshot"):
            raise RunnerError("V120_ATTEMPT_PARENT_CHANGED")
        for entry in manifest.get("acl_entries", []):
            target = _safe_existing(Path(entry["path"]))
            if not _inside(str(target), str(root)):
                raise RunnerError("V120_ACL_MANIFEST_PATH")
            info = target.stat(follow_symlinks=False)
            if (int(info.st_dev) != entry.get("volume")
                    or int(info.st_ino) != entry.get("file_id")
                    or int(info.st_nlink) != entry.get("links")
                    or bool(target.is_dir()) != entry.get("is_directory")
                    or (not target.is_dir() and info.st_nlink != 1)):
                raise RunnerError("V120_CLEANUP_IDENTITY")
            raw, descriptor, _ = self.security.descriptor(target)
            try:
                if not hmac.compare_digest(
                        hashlib.sha256(raw).hexdigest(), entry.get("acl_sha256", "")):
                    raise RunnerError("V120_ACL_CHANGED")
            finally:
                self.security.k.LocalFree(descriptor)
        for category in ("protected_roots", "canonical_readonly_roots"):
            for snapshot in manifest.get(category, []):
                observed = self.security.snapshot(Path(snapshot["path"]))
                if observed != snapshot:
                    raise RunnerError("V120_ACL_ROOT_CHANGED")
        runtime_root = _safe_existing(root / "runtime", file=False)
        expected_runtime = {}
        for item in manifest.get("runtime_files", []):
            if not isinstance(item, dict):
                raise RunnerError("V120_RUNTIME_MANIFEST")
            relative = _safe_relative(item.get("relative_path"))
            key = ntpath.normcase(relative.as_posix().replace("/", "\\"))
            if key in expected_runtime:
                raise RunnerError("V120_RUNTIME_MANIFEST")
            target = _safe_existing(runtime_root.joinpath(*relative.parts), file=True)
            if (not _inside(str(target), str(runtime_root))
                    or target.stat(follow_symlinks=False).st_nlink != 1
                    or not hmac.compare_digest(_sha256(target), item.get("sha256", ""))):
                raise RunnerError("V120_RUNTIME_COPY_HASH")
            expected_runtime[key] = item["sha256"]
        actual_runtime = set()
        for target in runtime_root.rglob("*"):
            target = _safe_existing(target)
            if target.is_dir():
                continue
            key = ntpath.normcase(
                target.relative_to(runtime_root).as_posix().replace("/", "\\")
            )
            if key not in expected_runtime or key in actual_runtime:
                raise RunnerError("V120_RUNTIME_MANIFEST")
            actual_runtime.add(key)
        if actual_runtime != set(expected_runtime):
            raise RunnerError("V120_RUNTIME_MANIFEST")
        return root

    def _job_if_present(self, event: dict):
        try:
            return NamedAttemptJob.reopen(event["resource_limits"], event["job_name"])
        except OSError as exc:
            if getattr(exc, "winerror", None) == 2 or (exc.args and exc.args[0] == 2):
                return None
            raise

    def observe(self, event: dict) -> dict:
        job = self._job_if_present(event)
        if job is None:
            return {"attempt_id": event["attempt_id"], "job_missing": True,
                    "active_processes": 0}
        try:
            stats = job.stats()
            return {"attempt_id": event["attempt_id"], "job": stats,
                    "active_processes": stats.get("active_processes")}
        finally:
            job.close()

    def stop(self, event: dict) -> dict:
        job = self._job_if_present(event)
        if job is None:
            return {"attempt_id": event["attempt_id"], "stopped": True,
                    "job_missing": True}
        try:
            job.stop()
            deadline = time.monotonic() + 2.0
            stats = job.stats()
            while stats.get("active_processes") != 0 and time.monotonic() < deadline:
                time.sleep(0.05)
                stats = job.stats()
            if stats.get("active_processes") != 0:
                job.stop()
                stats = job.stats()
            if stats.get("active_processes") != 0:
                raise RunnerError("V120_JOB_STOP_TIMEOUT")
            return {"attempt_id": event["attempt_id"], "stopped": True, "job": stats}
        finally:
            job.close()

    def recover(self, event: dict) -> dict:
        observed = self.observe(event)
        return {"attempt_id": event["attempt_id"], "recovered": True, **observed}

    def cleanup_prepared(self, event: dict, job=None) -> dict:
        root_path = Path(event["subject_root"])
        if root_path.is_symlink():
            raise RunnerError("V120_CLEANUP_IDENTITY")
        owned_job = job
        close_job = False
        if owned_job is None:
            owned_job = self._job_if_present(event)
            close_job = owned_job is not None
        if owned_job is not None:
            try:
                if owned_job.name != event["job_name"]:
                    raise RunnerError("V120_JOB_OWNERSHIP")
                if owned_job.stats().get("active_processes") != 0:
                    raise RunnerError("V120_ATTEMPT_STILL_ACTIVE")
            finally:
                if close_job:
                    owned_job.close()
        if root_path.exists():
            root = self._check_manifest_paths(event)
            self._remove_exact_tree(root)
        else:
            manifest = event.get("acl_manifest")
            recorded_hash = event.get("acl_manifest_sha256")
            if (not isinstance(manifest, dict) or not isinstance(recorded_hash, str)
                    or manifest.get("acl_manifest_sha256") != recorded_hash
                    or manifest.get("attempt_id") != event.get("attempt_id")
                    or manifest.get("profile_name") != event.get("profile_name")
                    or manifest.get("job_name") != event.get("job_name")
                    or manifest.get("subject_parent") != event.get("subject_parent")
                    or not isinstance(event.get("owner_marker"), dict)
                    or manifest.get("owner_marker") != event.get("owner_marker")
                    or manifest.get("owner_marker_sha256") != hashlib.sha256(
                        _canonical(event["owner_marker"])
                    ).hexdigest()
                    or ntpath.normcase(str(root_path))
                    != ntpath.normcase(str(manifest.get("root", "")))
                    or not hmac.compare_digest(
                        hashlib.sha256(_canonical({
                            key: value for key, value in manifest.items()
                            if key != "acl_manifest_sha256"
                        })).hexdigest(), recorded_hash)):
                raise RunnerError("V120_CLEANUP_IDENTITY")
            parent = _safe_existing(Path(event["subject_parent"]), file=False)
            if ntpath.normcase(str(parent / event["attempt_id"])) != ntpath.normcase(str(root_path)):
                raise RunnerError("V120_ATTEMPT_PATH")
            if self.security.snapshot(parent) != manifest.get("subject_parent_snapshot"):
                raise RunnerError("V120_ATTEMPT_PARENT_CHANGED")
        self._delete_profile(event["profile_name"], allow_missing=True)
        return {"attempt_id": event["attempt_id"], "cleaned": True}

    def cleanup(self, event: dict, job=None) -> dict:
        return self.cleanup_prepared(event, job=job)

    def _remove_exact_tree(self, root: Path):
        target = _safe_existing(Path(root), file=False)
        if ntpath.normcase(str(target)) != ntpath.normcase(str(Path(root))):
            raise RunnerError("V120_ATTEMPT_PATH")
        for parent, dirs, files in os.walk(target, topdown=False, followlinks=False):
            parent_path = Path(parent)
            _safe_existing(parent_path, file=False)
            for name in files:
                path = parent_path / name
                info = path.lstat()
                if info.st_file_attributes & _ATTRIBUTE_REPARSE_POINT or info.st_nlink != 1:
                    raise RunnerError("V120_CLEANUP_IDENTITY")
                path.unlink()
            for name in dirs:
                path = parent_path / name
                info = path.lstat()
                if info.st_file_attributes & _ATTRIBUTE_REPARSE_POINT:
                    raise RunnerError("V120_CLEANUP_IDENTITY")
                path.rmdir()
        target.rmdir()


class TaskOnlyRunner:
    """Identifier-only worker API with freshness checks and exact-attempt recovery."""

    _TERMINAL = {
        "completed", "stopped", "failed", "interrupted",
        "cancelled_before_launch", "cancelled_by_authority", "cleaned",
    }

    def __init__(self, state: Path, registry_key: bytes, *, scope_provider: Callable,
                 registry_provider: Callable, preflight_ledger, clock=lambda: time.time(),
                 monotonic_clock=time.monotonic_ns, broker=None, start_monitor: bool = True,
                 admission=None, max_active_jobs: int = 4):
        self.state = Path(state)
        if not self.state.is_dir() or self.state.is_symlink():
            raise RunnerError("V120_STATE_PATH")
        self.registry_key = registry_key
        self.scope_provider = scope_provider
        self.registry_provider = registry_provider
        self.preflight_ledger = preflight_ledger
        self.clock, self.monotonic_clock = clock, monotonic_clock
        self.admission = admission if admission is not None else TaskAdmission(max_active_jobs)
        self.lease = RunnerLease(self.state)
        try:
            self.ledger = AttemptLedger(self.state / "attempt-ledger.sqlite3", registry_key)
            latest = {}
            released = set()
            for event in self.ledger.events():
                if event.get('kind') == 'capacity_released' and event.get('capacity_released') is True:
                    released.add(event['attempt_id'])
                else:latest[event['attempt_id']] = event
            for attempt_id, event in latest.items():
                # Uncertain failure/interruption retains capacity until owned
                # cleanup or an authenticated zero-process observation proves it safe.
                if not (attempt_id in released or event.get('capacity_released') is True
                        or event.get('kind') in {'cleaned', 'completed', 'stopped',
                            'cancelled_before_launch', 'cancelled_by_authority'}
                        or (event.get('kind') == 'failed'
                            and event.get('cleanup', {}).get('cleaned') is True)):
                    if not self.admission.reserve_task_attempt(attempt_id, restore=True):
                        raise RunnerError('V120_ADMISSION_RESTORE')
        except BaseException:
            if hasattr(self, 'ledger'):self.ledger.close()
            self.lease.close()
            raise
        self.broker = broker
        self.lock = threading.RLock()
        self.lifecycle = threading.Condition(self.lock)
        self.live: dict[str, tuple[object | None, object]] = {}
        self.inflight: set[str] = set()
        self.admitting: set[str] = set()
        self.cancelled: set[str] = set()
        self.closed = threading.Event()
        self.monitor = (
            threading.Thread(target=self._monitor,
                             name="localcontrol-v120-attempt-monitor", daemon=True)
            if start_monitor else None
        )
        if self.monitor:
            self.monitor.start()

    def _get_broker(self):
        if self.broker is None:
            if os.name != "nt":
                raise RunnerError("PLATFORM_UNSUPPORTED")
            self.broker = WindowsAttemptBroker()
        return self.broker

    def _release_capacity(self, attempt_id):
        # Also supports legacy isolated test doubles; real runners always have admission.
        admission = getattr(self, 'admission', None)
        if admission is not None:
            try:
                latest = self.ledger.latest(attempt_id)
                if latest is not None and latest.get('capacity_released') is not True:
                    self.ledger.append({'kind':'capacity_released','attempt_id':attempt_id,
                                        'capacity_released':True,'at':self.clock()})
            finally:
                # Callers supply a proven terminal/empty ownership state. Audit
                # failure remains visible but cannot retain a live capacity slot.
                admission.release_task_attempt(attempt_id)

    def _append_status(self, event: dict) -> bool:
        try:
            self.ledger.append(event)
            return True
        except Exception:
            return False

    @staticmethod
    def _stop_owned_job(job, timeout_seconds: float = 2.0) -> bool:
        try:
            job.stop()
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                if job.stats().get("active_processes") == 0:
                    return True
                time.sleep(0.05)
        except Exception:
            return False
        return False

    def close(self):
        if getattr(self,'_close_complete',False):return
        self.closed.set()
        deadline = time.monotonic() + 30
        with self.lifecycle:
            self.cancelled.update(self.inflight | self.admitting)
            while self.inflight or self.admitting:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # Keep the ledger and exclusive lease alive while an
                    # in-flight launch has not reached its safe checkpoint.
                    raise RunnerError('V120_SHUTDOWN_PENDING')
                self.lifecycle.wait(timeout=min(remaining, .2))
        if self.monitor:
            self.monitor.join()
        with self.lock:
            active = list(self.live.items())
        shutdown_pending=False
        for attempt_id, (process, job) in active:
            try:
                latest = self.ledger.latest(attempt_id)
            except Exception:
                latest = None
            terminal=latest is not None and latest.get('kind') in self._TERMINAL
            if not terminal and (latest is None or latest.get("kind") not in {
                    "cancellation_pending", "cancellation_failed"}):
                self._append_status({
                    "kind": "cancellation_pending", "attempt_id": attempt_id,
                    "at": self.clock(), "reason": "runner_shutdown",
                })
            stopped = (latest is not None and latest.get('capacity_released') is True
                       or self._stop_owned_job(job))
            if stopped and not terminal:
                self._append_status({
                    "kind": "cancelled_by_authority", "attempt_id": attempt_id,
                    "at": self.clock(), "reason": "runner_shutdown",
                })
            elif not stopped:
                self._append_status({
                    "kind": "cancellation_failed", "attempt_id": attempt_id,
                    "at": self.clock(), "reason": "runner_shutdown_stop_failed",
                })
                shutdown_pending=True
                continue
            if process is not None:
                try:
                    process.capture_summary(wait_seconds=1)
                    process.close_handles()
                except Exception:
                    self._append_status({
                        'kind':'cancellation_failed','attempt_id':attempt_id,
                        'at':self.clock(),'reason':'runner_shutdown_process_cleanup_failed'})
                    shutdown_pending=True
                    continue
            try:
                self._release_capacity(attempt_id)
                job.close()
                with self.lock:self.live.pop(attempt_id,None)
            except Exception:
                shutdown_pending=True
                self._append_status({
                    "kind": "cancellation_failed", "attempt_id": attempt_id,
                    "at": self.clock(), "reason": "runner_shutdown_job_close_failed",
                })
        if shutdown_pending:raise RunnerError('V120_SHUTDOWN_PENDING')
        self.ledger.close()
        lease = getattr(self, 'lease', None)
        if lease is not None:lease.close()
        self._close_complete=True

    def _monitor(self):
        consecutive_scope_failures = 0
        while not self.closed.wait(0.5):
            with self.lock:
                active_ids = list(self.live)
            for attempt_id in active_ids:
                try:
                    self.observe(attempt_id)
                except Exception:
                    # Unknown accounting never releases a reservation.
                    pass
            try:
                self._scope()
                consecutive_scope_failures = 0
                continue
            except Exception:
                consecutive_scope_failures += 1
                if consecutive_scope_failures < 3:
                    continue
            try:
                with self.lock:
                    active = list(self.live.items())
            except Exception:
                continue
            for attempt_id, (process, job) in active:
                audit_unavailable = False
                try:
                    latest = self.ledger.latest(attempt_id)
                except Exception:
                    latest = None
                    audit_unavailable = True
                if (not audit_unavailable and latest is not None
                        and latest.get("kind") in self._TERMINAL):
                    continue
                reason = (
                    "attempt_ledger_unavailable" if audit_unavailable
                    else "scope_expired_revoked_or_registry_changed"
                )
                if audit_unavailable or latest is None or latest.get("kind") not in {
                        "cancellation_pending", "cancellation_failed"}:
                    self._append_status({
                        "kind": "cancellation_pending", "attempt_id": attempt_id,
                        "at": self.clock(), "reason": reason,
                    })
                stopped = self._stop_owned_job(job)
                if stopped:
                    if process is not None:
                        try:
                            process.capture_summary(wait_seconds=1)
                            process.close_handles()
                        except Exception:
                            pass
                    with self.lock:
                        if attempt_id in self.live:
                            self.live[attempt_id] = (None, job)
                    self._append_status({
                        "kind": "cancelled_by_authority", "attempt_id": attempt_id,
                        "at": self.clock(), "reason": reason,
                    })
                elif (audit_unavailable
                      or latest is None or latest.get("kind") != "cancellation_failed"):
                    failure_reason = (
                        "attempt_ledger_unavailable_stop_failed" if audit_unavailable
                        else "owned_job_stop_failed"
                    )
                    self._append_status({
                        "kind": "cancellation_failed", "attempt_id": attempt_id,
                        "at": self.clock(), "reason": failure_reason,
                    })

    def _scope(self) -> dict:
        payload = self.scope_provider()
        binding = self.registry_provider()
        if not isinstance(payload, dict) or not isinstance(binding, dict):
            raise RunnerError("V120_SCOPE_INVALID")
        return payload

    def _module_fingerprints(self) -> dict:
        from . import v120_api, v120_authority, v120_preflight
        control = {
            "preflight_module_sha256": _sha256(Path(v120_preflight.__file__)),
            "api_module_sha256": _sha256(Path(v120_api.__file__)),
            "facade_module_sha256": _sha256(Path(v120_api.__file__).with_name("facade.py")),
            "server_module_sha256": _sha256(Path(v120_api.__file__).with_name("server.py")),
            "runner_module_sha256": _sha256(Path(__file__)),
            "authority_module_sha256": _sha256(Path(v120_authority.__file__)),
            "appcontainer_module_sha256": _sha256(Path(v120_api.__file__).with_name("appcontainer.py")),
            "windows_job_module_sha256": _sha256(Path(v120_api.__file__).with_name("windows_job.py")),
            "admission_module_sha256": _sha256(Path(v120_api.__file__).with_name("v120_admission.py")),
            "jobs_module_sha256": _sha256(Path(v120_api.__file__).with_name("jobs.py")),
        }
        return control

    def _manifest(self, payload: dict, workload: dict) -> dict:
        path = self.state / "workloads" / (workload["workload_id"] + ".json")
        _safe_existing(path, file=True)
        raw = path.read_bytes()
        return verify_workload_manifest(
            raw, workload["manifest_sha256"], self.registry_key, workload,
            payload["worker"]["runtime_roots"],
        )

    def _preflight(self, payload: dict, workload: dict, request_id: str, *,
                   allow_attempt_id: str | None = None) -> tuple[dict, str]:
        try:
            receipt = self.preflight_ledger.get_by_request_id(request_id)
        except BaseException as exc:
            raise RunnerError(getattr(exc, "code", "V120_PREFLIGHT_RECEIPT_INVALID")) from None
        if not isinstance(receipt, dict) or not verify_signed_receipt(receipt, self.registry_key):
            raise RunnerError("V120_PREFLIGHT_RECEIPT_INVALID")
        receipt_sha = hashlib.sha256(_canonical(receipt)).hexdigest()
        sample = receipt.get("telemetry", {}).get("raw")
        sampled = sample.get("sampled_monotonic_ns") if isinstance(sample, dict) else None
        now_ns = self.monotonic_clock()
        if (receipt.get("decision") != "ADMIT" or type(receipt.get("exit_code")) is not int
                or receipt.get("exit_code") != 0 or type(sampled) is not int
                or now_ns < sampled or now_ns - sampled > MAX_PREFLIGHT_AGE_NS):
            raise RunnerError("V120_PREFLIGHT_STALE_OR_DENIED")
        task_scope = receipt.get("task_scope")
        registry = receipt.get("registry")
        work = receipt.get("workload")
        if (receipt.get("schema") != "localcontrol-preflight-receipt-v1"
                or receipt.get("request_id") != request_id
                or receipt.get("task_id") != payload["task_id"]
                or receipt.get("workload_id") != workload["workload_id"]
                or receipt.get("candidate_identity") != payload["candidate_identity"]
                or not isinstance(work, dict)
                or work.get("planned_bytes") != workload["planned_bytes"]
                or not isinstance(task_scope, dict)
                or task_scope.get("scope_id") != payload["scope_id"]
                or task_scope.get("sha256") != hashlib.sha256(_canonical(payload)).hexdigest()
                or task_scope.get("worker_scope_sha256") != hashlib.sha256(
                    _canonical(payload["worker"])
                ).hexdigest()
                or not isinstance(registry, dict)
                or registry.get("revision") != payload["registry_revision"]
                or registry.get("snapshot_sha256") != payload["registry_sha256"]
                or registry.get("signed_file_sha256") != payload["registry_file_sha256"]):
            raise RunnerError("V120_PREFLIGHT_BINDING")
        from .v120_api import RUNNER_POLICY_SHA256
        from .v120_preflight import POLICY_SHA256
        if (payload["worker"]["runner_policy_sha256"] != RUNNER_POLICY_SHA256
                or receipt.get("policy", {}).get("policy_sha256") != POLICY_SHA256):
            raise RunnerError("V120_RUNNER_POLICY")
        source = receipt.get("source")
        fingerprints = source.get("control_plane_files_sha256") if isinstance(source, dict) else None
        from . import v120_preflight
        if (not isinstance(source, dict)
                or source.get("broker_api_version") != "1.2.0"
                or source.get("implementation_sha256") != _sha256(Path(v120_preflight.__file__))
                or fingerprints != self._module_fingerprints()
                or source.get("broker_sha256") != hashlib.sha256(
                    _canonical(self._module_fingerprints())
                ).hexdigest()):
            raise RunnerError("V120_RUNNER_IDENTITY")
        owner = self.ledger.receipt_owner(receipt_sha)
        if owner is not None and allow_attempt_id is not None and owner != allow_attempt_id:
            raise RunnerError("V120_PREFLIGHT_REPLAY")
        return receipt, receipt_sha

    def _workload(self, payload: dict, workload_id: str) -> dict:
        if not isinstance(workload_id, str) or not _ID.fullmatch(workload_id):
            raise RunnerError("V120_WORKLOAD_UNKNOWN")
        for item in payload["workloads"]:
            if item["workload_id"] == workload_id:
                return item
        raise RunnerError("V120_WORKLOAD_UNKNOWN")

    def _attempt_bindings(self, payload: dict, workload: dict, launch_request_id: str,
                          receipt_sha: str) -> dict:
        identity = derive_attempt_identity(
            hmac.new(self.registry_key, b"LocalControl/v1.2/task-scope", hashlib.sha256).digest(),
            payload["scope_id"], payload["task_id"], workload["workload_id"],
            launch_request_id, scope_revision=payload["scope_revision"],
            candidate_identity=payload["candidate_identity"],
            registry_revision=payload["registry_revision"],
            registry_sha256=payload["registry_sha256"],
            registry_file_sha256=payload["registry_file_sha256"],
            preflight_receipt_sha256=receipt_sha,
        )
        identity["worker"] = payload["worker"]
        return identity

    def _create_owner_marker(self, payload: dict, workload: dict, identity: dict,
                             launch_request_id: str, preflight_request_id: str,
                             receipt_sha: str, parent_snapshot: dict) -> dict:
        body = {
            "schema": "localcontrol-v120-attempt-owner-v1",
            "attempt_id": identity["attempt_id"],
            "scope_id": payload["scope_id"],
            "scope_revision": payload["scope_revision"],
            "scope_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
            "task_id": payload["task_id"],
            "workload_id": workload["workload_id"],
            "candidate_identity": payload["candidate_identity"],
            "registry_revision": payload["registry_revision"],
            "registry_sha256": payload["registry_sha256"],
            "registry_file_sha256": payload["registry_file_sha256"],
            "worker_scope_sha256": hashlib.sha256(_canonical(payload["worker"])).hexdigest(),
            "runner_policy_sha256": payload["worker"]["runner_policy_sha256"],
            "launch_request_id": launch_request_id,
            "preflight_request_id": preflight_request_id,
            "preflight_receipt_sha256": receipt_sha,
            "workload_manifest_sha256": workload["manifest_sha256"],
            "job_name": identity["job_name"],
            "profile_name": identity["profile_name"],
            "subject_parent": payload["worker"]["subject_parent"],
            "subject_parent_snapshot": parent_snapshot,
        }
        mac = hmac.new(
            self.registry_key,
            b"LocalControl/v1.2/attempt-owner-marker\x00" + _canonical(body),
            hashlib.sha256,
        ).hexdigest()
        return body | {"mac": mac}

    def _verify_owner_marker(self, claim: dict) -> dict:
        marker = claim.get("owner_marker")
        if not isinstance(marker, dict) or not isinstance(marker.get("mac"), str):
            raise RunnerError("V120_ATTEMPT_OWNER_MARKER")
        body = {key: value for key, value in marker.items() if key != "mac"}
        required = {
            "schema", "attempt_id", "scope_id", "scope_revision", "scope_sha256",
            "task_id", "workload_id", "candidate_identity", "registry_revision",
            "registry_sha256", "registry_file_sha256", "worker_scope_sha256",
            "runner_policy_sha256", "launch_request_id", "preflight_request_id",
            "preflight_receipt_sha256", "workload_manifest_sha256", "job_name",
            "profile_name", "subject_parent", "subject_parent_snapshot",
        }
        expected_mac = hmac.new(
            self.registry_key,
            b"LocalControl/v1.2/attempt-owner-marker\x00" + _canonical(body),
            hashlib.sha256,
        ).hexdigest()
        bindings = {
            "attempt_id": "attempt_id", "scope_id": "scope_id",
            "scope_revision": "scope_revision", "scope_sha256": "scope_sha256",
            "task_id": "task_id", "workload_id": "workload_id",
            "candidate_identity": "candidate_identity",
            "registry_revision": "registry_revision",
            "registry_sha256": "registry_sha256",
            "registry_file_sha256": "registry_file_sha256",
            "worker_scope_sha256": "worker_scope_sha256",
            "runner_policy_sha256": "runner_policy_sha256",
            "launch_request_id": "launch_request_id",
            "preflight_request_id": "preflight_request_id",
            "preflight_receipt_sha256": "preflight_receipt_sha256",
            "workload_manifest_sha256": "workload_manifest_sha256",
            "job_name": "job_name", "profile_name": "profile_name",
            "subject_parent": "subject_parent",
            "subject_parent_snapshot": "subject_parent_snapshot",
        }
        if (set(body) != required
                or body.get("schema") != "localcontrol-v120-attempt-owner-v1"
                or not hmac.compare_digest(expected_mac, marker["mac"])
                or any(body.get(source) != claim.get(target)
                       for source, target in bindings.items())):
            raise RunnerError("V120_ATTEMPT_OWNER_MARKER")
        return body

    def _claim_event(self, payload: dict, workload: dict, identity: dict,
                     launch_request_id: str, preflight_request_id: str,
                     receipt_sha: str) -> dict:
        return {
            "kind": "claimed", "attempt_id": identity["attempt_id"],
            "scope_id": payload["scope_id"], "scope_revision": payload["scope_revision"],
            "scope_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
            "task_id": payload["task_id"], "workload_id": workload["workload_id"],
            "candidate_identity": payload["candidate_identity"],
            "registry_revision": payload["registry_revision"],
            "registry_sha256": payload["registry_sha256"],
            "registry_file_sha256": payload["registry_file_sha256"],
            "worker_scope_sha256": hashlib.sha256(_canonical(payload["worker"])).hexdigest(),
            "runner_policy_sha256": payload["worker"]["runner_policy_sha256"],
            "launch_request_id": launch_request_id,
            "preflight_request_id": preflight_request_id,
            "preflight_receipt_sha256": receipt_sha,
            "workload_manifest_sha256": workload["manifest_sha256"],
            "job_name": identity["job_name"], "profile_name": identity["profile_name"],
            "subject_parent": payload["worker"]["subject_parent"],
            "subject_parent_snapshot": identity["subject_parent_snapshot"],
            "owner_marker": identity["owner_marker"],
            "resource_limits": dict(workload["resource_limits"]),
            "at": self.clock(),
        }

    def _other_attempt_roots(self, current_attempt_id: str, subject_parent: str) -> list[Path]:
        latest_by_attempt = {}
        for event in self.ledger.events():
            attempt_id = event.get("attempt_id")
            if isinstance(attempt_id, str):
                latest_by_attempt[attempt_id] = event
        roots = []
        for attempt_id, latest in latest_by_attempt.items():
            latest = self.ledger.latest(attempt_id)
            if (attempt_id == current_attempt_id or latest.get("kind") == "cleaned"
                    or (latest.get("kind") == "failed"
                        and latest.get("cleanup", {}).get("cleaned") is True)):
                continue
            for event in self.ledger.for_attempt(attempt_id):
                if event.get("kind") == "prepared" and isinstance(event.get("subject_root"), str):
                    root = _safe_existing(Path(event["subject_root"]), file=False)
                    if _inside(str(root), subject_parent):
                        roots.append(root)
                    break
        return roots

    def _existing_attempt_result(self, attempt_id: str) -> dict:
        latest = self.ledger.latest(attempt_id)
        if latest is None:
            raise RunnerError("V120_ATTEMPT_UNKNOWN")
        if latest.get("kind") in {"claimed", "prepared"}:
            return {"attempt_id": attempt_id, "status": latest["kind"]}
        return self.observe(attempt_id)

    def launch(self, args: dict) -> dict:
        if not isinstance(args, dict) or set(args) != {
                "task_id", "workload_id", "preflight_request_id",
                "launch_request_id", "request_id"}:
            raise RunnerError("INVALID_ARGUMENT")
        if not isinstance(args.get("request_id"), str) or _ID.fullmatch(args["request_id"]) is None:
            raise RunnerError("V120_REQUEST_ID")
        if (not isinstance(args.get("launch_request_id"), str)
                or _ID.fullmatch(args["launch_request_id"]) is None
                or not isinstance(args.get("preflight_request_id"), str)
                or _ID.fullmatch(args["preflight_request_id"]) is None):
            raise RunnerError("V120_REQUEST_ID")
        payload = self._scope()
        if args.get("task_id") != payload["task_id"]:
            raise RunnerError("V120_TASK_MISMATCH")
        workload = self._workload(payload, args.get("workload_id"))
        manifest = self._manifest(payload, workload)
        _, receipt_sha = self._preflight(payload, workload, args["preflight_request_id"])
        identity = self._attempt_bindings(
            payload, workload, args["launch_request_id"], receipt_sha
        )
        attempt_id = identity["attempt_id"]
        previous = self.ledger.latest(attempt_id)
        if previous is not None:
            claim = self.ledger.for_attempt(attempt_id)[0]
            if (claim.get("launch_request_id") != args["launch_request_id"]
                    or claim.get("preflight_request_id") != args["preflight_request_id"]
                    or claim.get("preflight_receipt_sha256") != receipt_sha
                    or claim.get("scope_sha256") != hashlib.sha256(_canonical(payload)).hexdigest()):
                raise RunnerError("V120_LAUNCH_REPLAY_CONFLICT")
            return self._existing_attempt_result(attempt_id)
        with self.lock:
            if self.closed.is_set():
                raise RunnerError('V120_RUNNER_CLOSED')
            if attempt_id in self.admitting or attempt_id in self.inflight:
                raise RunnerError('V120_LAUNCH_PENDING')
            if self.ledger.latest(attempt_id) is not None:
                return self._existing_attempt_result(attempt_id)
            if not self.admission.reserve_task_attempt(attempt_id):
                raise RunnerError('V120_ACTIVE_JOB_LIMIT')
            self.admitting.add(attempt_id)
        try:
            return self._launch_reserved(args, payload, workload, manifest, receipt_sha,
                                         identity, self._get_broker())
        except BaseException:
            # No ledger claim means process creation could not have started.
            if self.ledger.latest(attempt_id) is None:
                self._release_capacity(attempt_id)
            raise
        finally:
            with self.lock:
                self.admitting.discard(attempt_id)
                self.inflight.discard(attempt_id)
                self.lifecycle.notify_all()

    def _launch_reserved(self, args, payload, workload, manifest, receipt_sha, identity, broker):
        attempt_id = identity['attempt_id']
        parent_snapshot = broker.snapshot_subject_parent(payload['worker'], attempt_id)
        identity["subject_parent_snapshot"] = parent_snapshot
        identity["owner_marker"] = self._create_owner_marker(
            payload, workload, identity, args["launch_request_id"],
            args["preflight_request_id"], receipt_sha, parent_snapshot,
        )
        claim_event = self._claim_event(
            payload, workload, identity, args["launch_request_id"],
            args["preflight_request_id"], receipt_sha,
        )
        with self.lock:
            prior_owner = self.ledger.claim_receipt(receipt_sha, attempt_id, claim_event)
            if prior_owner is not None:
                if prior_owner != attempt_id:
                    raise RunnerError("V120_PREFLIGHT_REPLAY")
                return self._existing_attempt_result(attempt_id)
            self.inflight.add(attempt_id)
            self.admitting.discard(attempt_id)
        prepared = None
        process = None
        job = None
        cleanup_result = None
        error_code = "V120_ATTEMPT_FAILED"
        preparation_started = False
        try:
            preparation_started = True
            prepared = broker.prepare(payload, identity, workload, manifest)
            prepared_event = {
                "kind": "prepared", "attempt_id": attempt_id,
                "subject_root": str(prepared.root),
                "acl_manifest": prepared.acl_manifest,
                "acl_manifest_sha256": prepared.acl_manifest["acl_manifest_sha256"],
                "sid": prepared.sid_string, "at": self.clock(),
            }
            self.ledger.append(prepared_event)

            current = self._scope()
            if hashlib.sha256(_canonical(current)).hexdigest() != claim_event["scope_sha256"]:
                raise RunnerError("V120_SCOPE_CHANGED")
            current_workload = self._workload(current, workload["workload_id"])
            current_manifest = self._manifest(current, current_workload)
            if _canonical(current_manifest) != _canonical(manifest):
                raise RunnerError("V120_WORKLOAD_CHANGED")
            self._preflight(
                current, current_workload, args["preflight_request_id"],
                allow_attempt_id=attempt_id,
            )
            other_roots = self._other_attempt_roots(
                attempt_id, current["worker"]["subject_parent"]
            )
            process, job = broker.start_suspended(
                prepared, identity, manifest, workload, other_roots
            )
            process.start_output_capture()
            created = getattr(process, "creation_time_100ns", None)
            if type(process.pid) is not int or type(created) is not int:
                raise RunnerError("V120_PROCESS_IDENTITY")
            self.ledger.append({
                "kind": "suspended_assigned", "attempt_id": attempt_id,
                "pid": process.pid, "process_created_100ns": created,
                "job_name": identity["job_name"], "sid": prepared.sid_string,
                "acl_manifest_sha256": prepared.acl_manifest["acl_manifest_sha256"],
                "at": self.clock(),
            })

            def final_check(handle, token, sid):
                with self.lock:
                    if self.closed.is_set():
                        raise RunnerError('V120_RUNNER_CLOSED')
                    if attempt_id in self.cancelled:
                        raise RunnerError("V120_ATTEMPT_CANCELLED")
                    current_state = self.ledger.latest(attempt_id)
                    if current_state is None or current_state.get("kind") != "suspended_assigned":
                        raise RunnerError("V120_ATTEMPT_STATE")
                final_payload = self._scope()
                if hashlib.sha256(_canonical(final_payload)).hexdigest() != claim_event["scope_sha256"]:
                    raise RunnerError("V120_SCOPE_CHANGED")
                final_workload = self._workload(final_payload, workload["workload_id"])
                final_manifest = self._manifest(final_payload, final_workload)
                if _canonical(final_manifest) != _canonical(manifest):
                    raise RunnerError("V120_WORKLOAD_CHANGED")
                self._preflight(
                    final_payload, final_workload, args["preflight_request_id"],
                    allow_attempt_id=attempt_id,
                )
                broker.security.verify_worker_access(
                    token, prepared, final_payload["worker"], other_roots
                )

            with self.lock:
                if self.closed.is_set():
                    raise RunnerError('V120_RUNNER_CLOSED')
                self.live[attempt_id] = (process, job)
                process.release(pre_resume_check=final_check)
                self.ledger.append({
                    "kind": "running", "attempt_id": attempt_id, "at": self.clock()
                })
            return {
                "attempt_id": attempt_id, "status": "running",
                "scope_id": payload["scope_id"], "task_id": payload["task_id"],
                "workload_id": workload["workload_id"],
                "profile_name": identity["profile_name"], "sid": prepared.sid_string,
                "job_name": identity["job_name"],
                "acl_manifest_sha256": prepared.acl_manifest["acl_manifest_sha256"],
                "preflight_receipt_sha256": receipt_sha,
            }
        except BaseException as exc:
            error_code = getattr(exc, "code", "V120_ATTEMPT_FAILED")
            stopped = job is None
            if job is not None:
                try:
                    job.stop()
                    deadline = time.monotonic() + 2.0
                    while time.monotonic() < deadline:
                        if job.stats().get("active_processes") == 0:
                            stopped = True
                            break
                        time.sleep(0.05)
                except BaseException:
                    stopped = False
            if process is not None:
                try:
                    process.capture_summary(wait_seconds=1)
                    process.close_handles()
                except BaseException:
                    pass
            if prepared is not None and stopped:
                try:
                    event = dict(claim_event) | {
                        "subject_root": str(prepared.root),
                        "acl_manifest": prepared.acl_manifest,
                        "acl_manifest_sha256": prepared.acl_manifest["acl_manifest_sha256"],
                    }
                    cleanup_result = self._get_broker().cleanup_prepared(event, job=job)
                except BaseException as cleanup_exc:
                    cleanup_result = {
                        "cleaned": False,
                        "error_code": getattr(cleanup_exc, "code", "V120_CLEANUP_PENDING"),
                    }
            if job is not None:
                try:
                    job.close()
                except BaseException:
                    pass
            with self.lock:
                self.live.pop(attempt_id, None)
            failure = {
                "kind": "failed", "attempt_id": attempt_id,
                "error_code": error_code, "at": self.clock(),
                "cleanup": cleanup_result or {
                    "cleaned": not preparation_started,
                    "pending": preparation_started,
                },
            }
            self.ledger.append(failure)
            if stopped and (cleanup_result or {}).get('cleaned') is True:
                self._release_capacity(attempt_id)
            raise

    def _owned_event(
        self, attempt_id: str, *, expected_task_id: str | None = None,
        expected_candidate_identity: dict | None = None,
    ) -> tuple[dict, dict | None]:
        if not isinstance(attempt_id, str) or _ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise RunnerError("V120_ATTEMPT_ID")
        events = self.ledger.for_attempt(attempt_id)
        if not events or events[0].get("kind") != "claimed":
            raise RunnerError("V120_ATTEMPT_UNKNOWN")
        claim = events[0]
        if (expected_task_id is not None and claim.get("task_id") != expected_task_id):
            raise RunnerError("V120_ATTEMPT_TASK_MISMATCH")
        if (expected_candidate_identity is not None
                and claim.get("candidate_identity") != expected_candidate_identity):
            raise RunnerError("V120_ATTEMPT_CANDIDATE_MISMATCH")
        self._verify_owner_marker(claim)
        identity = derive_attempt_identity(
            hmac.new(self.registry_key, b"LocalControl/v1.2/task-scope", hashlib.sha256).digest(),
            claim["scope_id"], claim["task_id"], claim["workload_id"],
            claim["launch_request_id"], scope_revision=claim["scope_revision"],
            candidate_identity=claim["candidate_identity"],
            registry_revision=claim["registry_revision"],
            registry_sha256=claim["registry_sha256"],
            registry_file_sha256=claim["registry_file_sha256"],
            preflight_receipt_sha256=claim["preflight_receipt_sha256"],
        )
        if (identity["attempt_id"] != attempt_id
                or claim.get("job_name") != identity["job_name"]
                or claim.get("profile_name") != identity["profile_name"]
                or claim.get("worker_scope_sha256") is None
                or claim.get("runner_policy_sha256") is None):
            raise RunnerError("V120_ATTEMPT_OWNERSHIP")
        prepared = next((event for event in events if event.get("kind") == "prepared"), None)
        if prepared is not None:
            manifest = prepared.get("acl_manifest")
            digest = prepared.get("acl_manifest_sha256")
            if (not isinstance(manifest, dict)
                    or not isinstance(digest, str)
                    or manifest.get("acl_manifest_sha256") != digest
                    or not hmac.compare_digest(
                        hashlib.sha256(_canonical({
                            key: value for key, value in manifest.items()
                            if key != "acl_manifest_sha256"
                        })).hexdigest(), digest)):
                raise RunnerError("V120_ACL_MANIFEST_TAMPERED")
        return claim, prepared

    @staticmethod
    def _monitoring_receipt(stats: dict | None) -> dict:
        stats = stats if isinstance(stats, dict) else {}
        result = {}
        for key in ("monitor_role", "completion_history", "completion_port_error", "limit_breach"):
            value = stats.get(key)
            result[key] = value[:128] if isinstance(value, str) else None
        result["completion_port_available"] = stats.get("completion_port_available") is True
        if (not result["completion_port_available"] or result["completion_port_error"] is not None
                or result["monitor_role"] != "owner"
                or result["completion_history"] != "owned_port_notifications"):
            result["completion_history"] = "unknown"
        return result

    def _terminal_result(self, attempt_id: str, latest: dict) -> dict:
        if (latest.get('capacity_released') is True
                or (latest.get('kind') == 'failed' and (latest.get('cleanup') or {}).get('cleaned') is True)
                or latest.get('kind') in {'cleaned', 'completed', 'stopped',
                'cancelled_before_launch', 'cancelled_by_authority'}):
            self._release_capacity(attempt_id)
        return {
            "attempt_id": attempt_id, "status": latest.get("kind"),
            "exit_code": latest.get("exit_code"),
            "error_code": latest.get("error_code"),
            "cleanup": latest.get("cleanup"),
            "monitoring": self._monitoring_receipt(latest.get("monitoring", latest.get("job"))),
        }

    def observe(
        self, attempt_id: str, *, expected_task_id: str | None = None,
        expected_candidate_identity: dict | None = None,
    ) -> dict:
        claim, prepared = self._owned_event(
            attempt_id, expected_task_id=expected_task_id,
            expected_candidate_identity=expected_candidate_identity,
        )
        latest = self.ledger.latest(attempt_id)
        if latest.get("kind") in self._TERMINAL:
            return self._terminal_result(attempt_id, latest)
        if latest.get("kind") in {"claimed", "prepared"}:
            return {"attempt_id": attempt_id, "status": latest["kind"]}
        if latest.get("kind") == "suspended_assigned":
            observed = self._get_broker().observe(claim)
            if observed.get("job_missing"):
                self.ledger.append({
                    "kind": "interrupted", "attempt_id": attempt_id,
                    "reason": "owned_job_missing_after_restart", "at": self.clock(),
                })
                self._release_capacity(attempt_id)
                return {"attempt_id": attempt_id, "status": "interrupted", "recovered": True}
            return {"attempt_id": attempt_id, "status": "suspended_pending_recovery",
                    **observed}
        with self.lock:
            live = self.live.get(attempt_id)
        if live is not None:
            process, job = live
            stats = job.stats()
            if stats.get("active_processes") == 0:
                exit_code = None if process is None else process.poll()
                output = (
                    {"stdout": None, "stderr": None}
                    if process is None else process.capture_summary(wait_seconds=1)
                )
                self.ledger.append({
                    "kind": "completed", "attempt_id": attempt_id,
                    "exit_code": exit_code, "output": output, "job": stats,
                    "at": self.clock(),
                })
                if process is not None:
                    process.close_handles()
                with self.lock:
                    self.live[attempt_id] = (None, job)
                self._release_capacity(attempt_id)
                return {"attempt_id": attempt_id, "status": "completed",
                        "exit_code": exit_code, "output": output, "job": stats}
            exit_code = None if process is None else process.poll()
            return {
                "attempt_id": attempt_id, "status": "running", "job": stats,
                "root_exit_code": exit_code,
            }
        broker = self._get_broker()
        observed = broker.observe(claim)
        if observed.get("job_missing"):
            self.ledger.append({
                "kind": "interrupted", "attempt_id": attempt_id,
                "reason": "owned_job_missing_after_restart", "at": self.clock(),
            })
            self._release_capacity(attempt_id)
            return {"attempt_id": attempt_id, "status": "interrupted", "recovered": True}
        return {"attempt_id": attempt_id, "status": "running", **observed}

    def stop(
        self, attempt_id: str, *, expected_task_id: str | None = None,
        expected_candidate_identity: dict | None = None,
    ) -> dict:
        claim, prepared = self._owned_event(
            attempt_id, expected_task_id=expected_task_id,
            expected_candidate_identity=expected_candidate_identity,
        )
        latest = self.ledger.latest(attempt_id)
        if latest.get("kind") in self._TERMINAL:
            return self._terminal_result(attempt_id, latest)
        with self.lock:
            self.cancelled.add(attempt_id)
            if attempt_id in self.inflight:
                return {"attempt_id": attempt_id, "status": "cancellation_requested"}
            live = self.live.get(attempt_id)
        if latest.get("kind") in {"claimed", "prepared"}:
            if latest.get("kind") == "prepared":
                result = self._get_broker().stop(claim)
                if not result.get("stopped"):
                    raise RunnerError("V120_JOB_STOP_TIMEOUT")
            self.ledger.append({
                "kind": "cancelled_before_launch", "attempt_id": attempt_id,
                "at": self.clock(),
            })
            self._release_capacity(attempt_id)
            return {"attempt_id": attempt_id, "status": "cancelled_before_launch"}
        if live is not None:
            process, job = live
            job.stop()
            deadline = time.monotonic() + 2.0
            stats = job.stats()
            while stats.get("active_processes") != 0 and time.monotonic() < deadline:
                time.sleep(0.05)
                stats = job.stats()
            if stats.get("active_processes") != 0:
                raise RunnerError("V120_JOB_STOP_TIMEOUT")
            output = (
                {"stdout": None, "stderr": None}
                if process is None else process.capture_summary(wait_seconds=1)
            )
            if process is not None:
                process.close_handles()
            with self.lock:
                self.live[attempt_id] = (None, job)
        else:
            result = self._get_broker().stop(claim)
            if not result.get("stopped"):
                raise RunnerError("V120_JOB_STOP_TIMEOUT")
            stats = result.get("job")
        monitoring = self._monitoring_receipt(stats)
        self.ledger.append({
            "kind": "stopped", "attempt_id": attempt_id, "at": self.clock(),
            "monitoring": monitoring,
        })
        self._release_capacity(attempt_id)
        return {"attempt_id": attempt_id, "status": "stopped", "monitoring": monitoring}

    def recover(
        self, attempt_id: str, *, expected_task_id: str | None = None,
        expected_candidate_identity: dict | None = None,
    ) -> dict:
        claim, prepared = self._owned_event(
            attempt_id, expected_task_id=expected_task_id,
            expected_candidate_identity=expected_candidate_identity,
        )
        latest = self.ledger.latest(attempt_id)
        if latest.get("kind") in self._TERMINAL:
            return {**self._terminal_result(attempt_id, latest), "recovered": True}
        if latest.get("kind") in {"claimed", "prepared"}:
            with self.lock:
                if attempt_id in self.inflight:
                    self.cancelled.add(attempt_id)
                    return {"attempt_id": attempt_id, "status": "recovery_pending"}
                self.cancelled.add(attempt_id)
            if latest.get("kind") == "claimed":
                result = self._get_broker().recover_partial(claim)
            else:
                result = self._get_broker().stop(claim)
            event = {
                "kind": "interrupted", "attempt_id": attempt_id,
                "reason": "recovered_before_process_start",
                "cleanup": result, "at": self.clock(),
            }
            self.ledger.append(event)
            if result.get('cleaned') is True or result.get('stopped') is True:
                self._release_capacity(attempt_id)
            return {"attempt_id": attempt_id, "status": "interrupted",
                    "recovered": True, "cleanup": result}
        if latest.get("kind") == "suspended_assigned":
            result = self._get_broker().stop(claim)
            if result.get('stopped') is not True:
                raise RunnerError('V120_JOB_STOP_TIMEOUT')
            event = {
                "kind": "interrupted", "attempt_id": attempt_id,
                "reason": "suspended_process_terminated_during_recovery",
                "job": result.get("job"), "at": self.clock(),
            }
            self.ledger.append(event)
            self._release_capacity(attempt_id)
            return {"attempt_id": attempt_id, "status": "interrupted", "recovered": True}
        with self.lock:
            live = self.live.get(attempt_id)
        if live is not None:
            return self.observe(
                attempt_id, expected_task_id=expected_task_id,
                expected_candidate_identity=expected_candidate_identity,
            )
        result = self._get_broker().recover(claim)
        if result.get("job_missing") or result.get("active_processes") == 0:
            self.ledger.append({
                "kind": "interrupted", "attempt_id": attempt_id,
                "reason": "owned_job_empty_or_missing_after_restart", "at": self.clock(),
                "monitoring": self._monitoring_receipt(result.get("job")),
            })
            self._release_capacity(attempt_id)
            return {"attempt_id": attempt_id, "status": "interrupted",
                    "recovered": True, **result}
        return {"attempt_id": attempt_id, "status": "running",
                "recovered": True, **result}

    def cleanup(
        self, attempt_id: str, *, expected_task_id: str | None = None,
        expected_candidate_identity: dict | None = None,
    ) -> dict:
        claim, prepared = self._owned_event(
            attempt_id, expected_task_id=expected_task_id,
            expected_candidate_identity=expected_candidate_identity,
        )
        latest = self.ledger.latest(attempt_id)
        if latest.get("kind") == "cleaned":
            self._release_capacity(attempt_id)
            return {"attempt_id": attempt_id, "cleaned": True, "replayed": True}
        if latest.get("kind") == "failed" and latest.get("cleanup", {}).get("cleaned") is True:
            self.ledger.append({
                "kind": "cleaned", "attempt_id": attempt_id,
                "at": self.clock(), "already_cleaned": True,
            })
            self._release_capacity(attempt_id)
            return {"attempt_id": attempt_id, "cleaned": True, "replayed": True}
        if latest.get("kind") not in self._TERMINAL:
            raise RunnerError("V120_CLEANUP_STATE")
        if prepared is None:
            if latest.get("kind") not in {
                    "failed", "interrupted", "cancelled_before_launch"}:
                raise RunnerError("V120_CLEANUP_IDENTITY")
            prior_cleanup = latest.get("cleanup")
            if not (isinstance(prior_cleanup, dict)
                    and prior_cleanup.get("cleaned") is True):
                result = self._get_broker().recover_partial(claim)
                if result.get("cleaned") is not True:
                    raise RunnerError("V120_CLEANUP_IDENTITY")
                self.ledger.append({
                    "kind": "cleanup_recovered", "attempt_id": attempt_id,
                    "cleanup": result, "at": self.clock(),
                })
            self.ledger.append({
                "kind": "cleaned", "attempt_id": attempt_id,
                "at": self.clock(), "no_prepared_resource": True,
            })
            self._release_capacity(attempt_id)
            return {"attempt_id": attempt_id, "cleaned": True}
        if not isinstance(prepared.get("subject_root"), str):
            raise RunnerError("V120_CLEANUP_IDENTITY")
        event = dict(claim) | {
            "subject_root": prepared["subject_root"],
            "subject_parent": claim["subject_parent"],
            "profile_name": claim["profile_name"],
            "acl_manifest": prepared["acl_manifest"],
            "acl_manifest_sha256": prepared["acl_manifest_sha256"],
        }
        with self.lock:
            live = self.live.get(attempt_id)
        job = None if live is None else live[1]
        result = self._get_broker().cleanup(event, job=job)
        if live is not None:
            process = live[0]
            if process is not None:
                process.close_handles()
            job.close()
            with self.lock:
                self.live.pop(attempt_id, None)
        self.ledger.append({"kind": "cleaned", "attempt_id": attempt_id, "at": self.clock()})
        self._release_capacity(attempt_id)
        return result

    def call(
        self, tool: str, args: dict, *, expected_task_id: str | None = None,
        expected_candidate_identity: dict | None = None,
    ) -> dict:
        if not isinstance(args, dict):
            raise RunnerError("INVALID_ARGUMENT")
        fields = {
            "task_worker_launch": {
                "task_id", "workload_id", "preflight_request_id", "launch_request_id", "request_id"
            },
            "task_worker_observe": {"attempt_id"},
            "task_worker_stop": {"attempt_id", "request_id"},
            "task_worker_recover": {"attempt_id", "request_id"},
            "task_worker_cleanup": {"attempt_id", "request_id"},
        }
        if tool not in fields or set(args) != fields[tool]:
            raise RunnerError("INVALID_ARGUMENT")
        if tool in {
            "task_worker_observe", "task_worker_stop",
            "task_worker_recover", "task_worker_cleanup",
        } and (
            not isinstance(expected_task_id, str) or not expected_task_id
            or not isinstance(expected_candidate_identity, dict)
        ):
            raise RunnerError("V120_TASK_BINDING_REQUIRED")
        if tool == "task_worker_launch":
            return self.launch(args)
        if tool != "task_worker_observe" and (
                not isinstance(args.get("request_id"), str)
                or _ID.fullmatch(args["request_id"]) is None):
            raise RunnerError("V120_REQUEST_ID")
        attempt_id = args["attempt_id"]
        context = {
            "expected_task_id": expected_task_id,
            "expected_candidate_identity": expected_candidate_identity,
        }
        if tool == "task_worker_observe":
            return self.observe(attempt_id, **context)
        if tool == "task_worker_stop":
            return self.stop(attempt_id, **context)
        if tool == "task_worker_recover":
            return self.recover(attempt_id, **context)
        if tool == "task_worker_cleanup":
            return self.cleanup(attempt_id, **context)
        raise RunnerError("INVALID_ARGUMENT")
