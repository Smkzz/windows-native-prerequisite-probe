"""Offline elevated operator scope and workload administration; never an MCP surface."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import tempfile

from .v060.registry import RegistryCodec, RegistryStore
from .v120_api import (
    MAX_SCOPE_LIFETIME_SECONDS, RUNNER_POLICY_SHA256, _SCOPE_DOMAIN,
    _SCOPE_ENVELOPE, _SCOPE_FIELDS, _SCOPE_SCHEMA, V120API, _canonical,
)
from .v120_authority import ScopeAuthorityError, ScopeAuthorityLedger
from .v120_runner import (
    RunnerError,
    _current_process_user_sid,
    _sid_bytes_from_text,
    _validate_acl_ace_header,
    _validate_acl_entries,
    sign_workload_manifest,
    verify_workload_manifest,
)
from .policy import no_links

_REQUEST_SCHEMA = "localcontrol-task-scope-request-v1"
_WORKLOAD_REQUEST_SCHEMA = "localcontrol-workload-request-v1"
_SCOPE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_WORKLOAD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
_OPERATOR_SIDS = ("S-1-5-18", "S-1-5-32-544")
_DACL_PROTECTED = 0x1000


def _require_admin() -> None:
    if os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin():
        raise ScopeAuthorityError("V120_OPERATOR_ADMIN_REQUIRED")


def _assert_private_acl(path: Path) -> None:
    """Require a protected DACL with no broad read/write ACEs on signing state."""
    if os.name != "nt":
        raise ScopeAuthorityError("V120_OPERATOR_ACL_UNSUPPORTED")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAce.restype = wintypes.BOOL
    advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi.GetLengthSid.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p

    owner, group, dacl, sacl, descriptor = (
        ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p(),
        ctypes.c_void_p(), ctypes.c_void_p(),
    )
    status = advapi.GetNamedSecurityInfoW(
        str(path), 1, 0x00000001 | 0x00000004,
        ctypes.byref(owner), ctypes.byref(group), ctypes.byref(dacl),
        ctypes.byref(sacl), ctypes.byref(descriptor),
    )
    if status != 0:
        raise ScopeAuthorityError("V120_OPERATOR_ACL_READ")
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        if not advapi.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise ScopeAuthorityError("V120_OPERATOR_ACL_READ")
        control, revision = wintypes.WORD(), wintypes.DWORD()
        if not advapi.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise ScopeAuthorityError("V120_OPERATOR_ACL_READ")
        if not present.value or not dacl or not (control.value & _DACL_PROTECTED):
            raise ScopeAuthorityError("V120_OPERATOR_ACL_INHERITANCE")

        class AclSize(ctypes.Structure):
            _fields_ = [("ace_count", wintypes.DWORD), ("bytes_free", wintypes.DWORD),
                        ("bytes_used", wintypes.DWORD)]

        info = AclSize()
        if not advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise ScopeAuthorityError("V120_OPERATOR_ACL_READ")
        try:
            if not owner:
                raise ScopeAuthorityError("V120_OPERATOR_ACL_OWNER")
            owner_bytes = ctypes.string_at(owner, advapi.GetLengthSid(owner))
            allowed_sids = {
                _sid_bytes_from_text(advapi, kernel, sid_text)
                for sid_text in _OPERATOR_SIDS
            }
            allowed_sids.add(_current_process_user_sid(advapi, kernel))
            entries = []
            for index in range(info.ace_count):
                ace = ctypes.c_void_p()
                if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                    raise ScopeAuthorityError("V120_OPERATOR_ACL_READ")
                if not ace:
                    raise ScopeAuthorityError("V120_OPERATOR_ACL_READ")
                header = ctypes.string_at(ace, 4)
                try:
                    ace_type, ace_flags, ace_size = _validate_acl_ace_header(header)
                except RunnerError:
                    raise ScopeAuthorityError("V120_OPERATOR_ACL_PRINCIPAL") from None
                mask = int.from_bytes(ctypes.string_at(ace.value + 4, 4), "little")
                sid = ctypes.c_void_p(ace.value + 8)
                sid_length = advapi.GetLengthSid(sid)
                if not sid_length or sid_length > ace_size - 8:
                    raise ScopeAuthorityError("V120_OPERATOR_ACL_READ")
                entries.append((
                    ace_type, ace_flags, mask, ctypes.string_at(sid, sid_length),
                ))
            _validate_acl_entries(owner_bytes, entries, allowed_sids)
        except RunnerError:
            raise ScopeAuthorityError("V120_OPERATOR_ACL_PRINCIPAL") from None
    finally:
        kernel.LocalFree(descriptor)


def _read_key(state_dir: Path) -> bytes:
    path = state_dir / "registry-key.bin"
    no_links(path)
    info = path.stat()
    if path.is_symlink() or info.st_nlink != 1 or info.st_size != 32:
        raise ScopeAuthorityError("V120_OPERATOR_KEY_PATH")
    _assert_private_acl(path)
    key = path.read_bytes()
    if len(key) != 32:
        raise ScopeAuthorityError("V120_OPERATOR_KEY_INVALID")
    return key


def _sign(payload: dict, key: bytes) -> dict:
    scope_key = hmac.new(key, _SCOPE_DOMAIN, hashlib.sha256).digest()
    return {
        "schema": _SCOPE_ENVELOPE,
        "payload": payload,
        "signature": {
            "algorithm": "HMAC-SHA256",
            "key_id": hashlib.sha256(scope_key).hexdigest()[:16],
            "hmac_sha256": hmac.new(scope_key, _canonical(payload), hashlib.sha256).hexdigest(),
        },
    }


class OfflineScopeAdmin:
    """Elevated-only writer using the protected registry key in-process."""

    def __init__(self, state_dir: Path, config_path: Path, *, require_admin: bool = True,
                 clock=lambda: datetime.now(timezone.utc)):
        if require_admin:
            _require_admin()
        self.state_dir = Path(state_dir)
        self.config_path = Path(config_path)
        no_links(self.state_dir)
        no_links(self.config_path)
        if not self.state_dir.is_dir() or not self.config_path.is_file():
            raise ScopeAuthorityError("V120_OPERATOR_PATH")
        _assert_private_acl(self.state_dir)
        self.key = _read_key(self.state_dir / 'v060')
        self.registry = RegistryStore(
            self.state_dir / 'v060' / "workspace-registry.json", RegistryCodec(self.key)
        )
        self.clock = clock
        self.state = self.state_dir / "v120"
        self.state.mkdir(exist_ok=True)
        no_links(self.state)
        self.authority = ScopeAuthorityLedger(
            self.state / "authority-ledger.sqlite3", self.key
        )
        self.requests = self.state / "requests"
        self.requests.mkdir(exist_ok=True)
        no_links(self.requests)
        self.workloads = self.state / "workloads"
        self.workloads.mkdir(exist_ok=True)
        no_links(self.workloads)

    def close(self) -> None:
        self.authority.close()

    def _read_request(self, request_path: Path, max_bytes: int = 1_048_576) -> dict:
        request_path = Path(request_path)
        no_links(request_path)
        if (request_path.parent.resolve(strict=True) != self.requests.resolve(strict=True)
                or request_path.suffix.casefold() != ".json"):
            raise ScopeAuthorityError("V120_OPERATOR_REQUEST_PATH")
        info = request_path.stat()
        if (request_path.is_symlink() or info.st_nlink != 1
                or info.st_size > max_bytes or not request_path.is_file()):
            raise ScopeAuthorityError("V120_OPERATOR_REQUEST_PATH")
        try:
            value = json.loads(request_path.read_bytes())
        except (OSError, ValueError, UnicodeDecodeError):
            raise ScopeAuthorityError("V120_OPERATOR_REQUEST_INVALID") from None
        if not isinstance(value, dict):
            raise ScopeAuthorityError("V120_OPERATOR_REQUEST_INVALID")
        return value

    def _atomic_create(self, target: Path, raw: bytes, *, replace: bool) -> None:
        no_links(target.parent)
        if target.is_symlink():
            raise ScopeAuthorityError("V120_OPERATOR_TARGET_PATH")
        if target.exists():
            if target.is_symlink() or target.stat().st_nlink != 1 or not target.is_file():
                raise ScopeAuthorityError("V120_OPERATOR_TARGET_PATH")
            if not replace:
                raise ScopeAuthorityError("V120_OPERATOR_TARGET_EXISTS")
        fd, tmp_name = tempfile.mkstemp(prefix="." + target.stem + ".", suffix=".tmp",
                                        dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if replace:
                os.replace(tmp_name, target)
            else:
                try:
                    os.link(tmp_name, target)
                except FileExistsError:
                    raise ScopeAuthorityError("V120_OPERATOR_TARGET_EXISTS") from None
                os.unlink(tmp_name)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def _publish_scope(self, target: Path, raw: bytes, payload: dict,
                       envelope_sha256: str) -> None:
        if target.is_symlink():
            raise ScopeAuthorityError("V120_SCOPE_PATH")
        previous_raw = None
        if target.exists():
            if (target.is_symlink() or target.stat().st_nlink != 1
                    or not target.is_file() or target.stat().st_size > 1_048_576):
                raise ScopeAuthorityError("V120_SCOPE_PATH")
            previous_raw = target.read_bytes()
        self._atomic_create(target, raw, replace=True)
        try:
            self.authority.record_issue(
                task_id=payload["task_id"], scope_id=payload["scope_id"],
                revision=payload["scope_revision"], issued_at_utc=payload["issued_at_utc"],
                envelope_sha256=envelope_sha256,
            )
        except BaseException:
            try:
                no_links(target)
                current_info = target.stat()
                if (target.is_symlink() or current_info.st_nlink != 1
                        or not target.is_file() or current_info.st_size > 1_048_576
                        or not hmac.compare_digest(
                            hashlib.sha256(target.read_bytes()).hexdigest(), envelope_sha256)):
                    raise ScopeAuthorityError("V120_SCOPE_ISSUE_RECONCILIATION_REQUIRED")
                if previous_raw is None:
                    target.unlink()
                else:
                    self._atomic_create(target, previous_raw, replace=True)
            except Exception:
                raise ScopeAuthorityError(
                    "V120_SCOPE_ISSUE_RECONCILIATION_REQUIRED"
                ) from None
            raise

    def publish_workload(self, request_path: Path) -> dict:
        request = self._read_request(request_path)
        if (set(request) != {"schema", "runtime_roots", "payload"}
                or request.get("schema") != _WORKLOAD_REQUEST_SCHEMA
                or not isinstance(request.get("runtime_roots"), list)
                or not 1 <= len(request["runtime_roots"]) <= 32
                or any(not isinstance(root, str) or len(root) > 32767
                       for root in request["runtime_roots"])
                or not isinstance(request.get("payload"), dict)):
            raise ScopeAuthorityError("V120_OPERATOR_WORKLOAD_REQUEST")
        payload = request["payload"]
        envelope = sign_workload_manifest(payload, self.key)
        workload_id = payload.get("workload_id")
        if not isinstance(workload_id, str) or _WORKLOAD_ID.fullmatch(workload_id) is None:
            raise ScopeAuthorityError("V120_WORKLOAD_ID")
        candidate = {
            "workload_id": workload_id,
            "resource_limits": payload.get("resource_limits"),
        }
        raw = _canonical(envelope)
        digest = hashlib.sha256(raw).hexdigest()
        verify_workload_manifest(
            raw, digest, self.key, candidate, request["runtime_roots"]
        )
        target = self.workloads / (workload_id + ".json")
        if target.exists():
            existing = target.read_bytes()
            if hashlib.sha256(existing).hexdigest() == digest:
                return {"workload_id": workload_id, "manifest_sha256": digest,
                        "published": False, "replayed": True}
            raise ScopeAuthorityError("V120_WORKLOAD_IMMUTABLE")
        self._atomic_create(target, raw, replace=False)
        return {"workload_id": workload_id, "manifest_sha256": digest,
                "published": True}

    def issue(self, request_path: Path) -> dict:
        request = self._read_request(request_path)
        if (set(request) != {"schema", "payload", "ttl_seconds"}
                or request.get("schema") != _REQUEST_SCHEMA
                or type(request.get("ttl_seconds")) is not int
                or not 1 <= request["ttl_seconds"] <= MAX_SCOPE_LIFETIME_SECONDS
                or not isinstance(request.get("payload"), dict)):
            raise ScopeAuthorityError("V120_OPERATOR_REQUEST_INVALID")
        payload = dict(request["payload"])
        if set(payload) != {
                "scope_id", "task_id", "candidate_identity", "workloads", "worker"}:
            raise ScopeAuthorityError("V120_OPERATOR_REQUEST_INVALID")
        worker = payload.get("worker")
        workloads = payload.get("workloads")
        if not isinstance(worker, dict) or not isinstance(workloads, list) or not 1 <= len(workloads) <= 32:
            raise ScopeAuthorityError("V120_WORKER_SCOPE")
        runtime_roots = worker.get("runtime_roots")
        if (not isinstance(runtime_roots, list) or not 1 <= len(runtime_roots) <= 32
                or any(not isinstance(root, str) or len(root) > 32767
                       for root in runtime_roots)):
            raise ScopeAuthorityError("V120_WORKER_SCOPE")
        workload_ids = set()
        for item in workloads:
            if not isinstance(item, dict):
                raise ScopeAuthorityError("V120_WORKLOADS")
            workload_id = item.get("workload_id")
            manifest_sha256 = item.get("manifest_sha256")
            if (not isinstance(workload_id, str)
                    or _WORKLOAD_ID.fullmatch(workload_id) is None
                    or workload_id in workload_ids
                    or not isinstance(manifest_sha256, str)
                    or re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is None):
                raise ScopeAuthorityError("V120_WORKLOADS")
            workload_ids.add(workload_id)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ScopeAuthorityError("V120_OPERATOR_CLOCK")
        now = now.astimezone(timezone.utc)
        if not isinstance(payload.get("scope_id"), str) or _SCOPE_ID.fullmatch(payload["scope_id"]) is None:
            raise ScopeAuthorityError("V120_SCOPE_ID")
        snapshot = self.registry.load()
        registry_raw = self.registry.path.read_bytes()
        prior = self.authority.latest_for_task(payload.get("task_id", ""))
        payload.update({
            "schema": _SCOPE_SCHEMA,
            "scope_revision": 1 if prior is None else prior["revision"] + 1,
            "registry_revision": snapshot.revision,
            "registry_sha256": snapshot.sha256,
            "registry_file_sha256": hashlib.sha256(registry_raw).hexdigest(),
            "issued_at_utc": now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "expires_at_utc": (now + timedelta(seconds=request["ttl_seconds"]))
                .isoformat(timespec="microseconds").replace("+00:00", "Z"),
        })
        for workload in payload.get("workloads", []):
            if not isinstance(workload, dict):
                raise ScopeAuthorityError("V120_WORKLOADS")
            manifest_path = self.workloads / (workload["workload_id"] + ".json")
            no_links(manifest_path)
            info = manifest_path.stat()
            if (manifest_path.is_symlink() or info.st_nlink != 1
                    or info.st_size > 1_048_576 or not manifest_path.is_file()):
                raise ScopeAuthorityError("V120_WORKLOAD_MANIFEST_PATH")
            raw = manifest_path.read_bytes()
            if not hmac.compare_digest(
                    hashlib.sha256(raw).hexdigest(), workload.get("manifest_sha256", "")):
                raise ScopeAuthorityError("V120_WORKLOAD_MANIFEST_HASH")
            verify_workload_manifest(
                raw, workload["manifest_sha256"], self.key, workload,
                runtime_roots,
            )
        validator = object.__new__(V120API)
        validator.clock = self.clock
        validator.policy = type("ScopePolicy", (), {"state_dir": str(self.state_dir)})()
        validator.config_path = self.config_path
        validator.registry_store = self.registry
        validator._validate_payload(payload)
        envelope = _sign(payload, self.key)
        raw = _canonical(envelope)
        envelope_sha256 = hashlib.sha256(raw).hexdigest()
        target = self.state / "task-scope.json"
        self._publish_scope(target, raw, payload, envelope_sha256)
        return {
            "scope_id": payload["scope_id"],
            "scope_revision": payload["scope_revision"],
            "task_id": payload["task_id"],
            "expires_at_utc": payload["expires_at_utc"],
            "envelope_sha256": envelope_sha256,
            "registry_revision": snapshot.revision,
            "runner_policy_sha256": RUNNER_POLICY_SHA256,
        }

    def revoke(self, scope_id: str) -> dict:
        if not isinstance(scope_id, str) or _SCOPE_ID.fullmatch(scope_id) is None:
            raise ScopeAuthorityError("V120_SCOPE_ID")
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ScopeAuthorityError("V120_OPERATOR_CLOCK")
        now = now.astimezone(timezone.utc)
        return self.authority.revoke(
            scope_id, now.isoformat(timespec="microseconds").replace("+00:00", "Z")
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline LocalControl v1.2 scope administration")
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--config-path", required=True)
    sub = parser.add_subparsers(dest="operation", required=True)
    publish = sub.add_parser("publish-workload", help="Sign and publish one immutable runtime manifest")
    publish.add_argument("request_file")
    issue = sub.add_parser("issue", help="Issue or renew one short-lived task scope")
    issue.add_argument("request_file")
    revoke = sub.add_parser("revoke", help="Persistently revoke one task scope")
    revoke.add_argument("scope_id")
    args = parser.parse_args(argv)
    admin = None
    try:
        admin = OfflineScopeAdmin(Path(args.state_dir), Path(args.config_path))
        if args.operation == "publish-workload":
            result = admin.publish_workload(Path(args.request_file))
        elif args.operation == "issue":
            result = admin.issue(Path(args.request_file))
        else:
            result = admin.revoke(args.scope_id)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, ScopeAuthorityError) as exc:
        code = getattr(exc, "code", "V120_OPERATOR_ERROR")
        print(json.dumps({"ok": False, "error": code}, sort_keys=True))
        return 1
    finally:
        if admin is not None:
            admin.close()


if __name__ == "__main__":
    raise SystemExit(main())
