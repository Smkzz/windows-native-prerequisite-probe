"""Operator authority and persistent scope lifecycle for LocalControl v1.2.

The MCP data plane can verify and revocation-check scopes but cannot issue,
renew, or revoke them. Those writes belong to the offline elevated operator utility.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from pathlib import Path

from .v120_preflight import _canonical

_DOMAIN = b"LocalControl/v1.2/scope-authority-ledger"


class ScopeAuthorityError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ScopeAuthorityLedger:
    """Append-only keyed event chain for scope issuance and revocation."""

    def __init__(self, path: Path, registry_key: bytes):
        if not isinstance(registry_key, bytes) or len(registry_key) != 32:
            raise ScopeAuthorityError("V120_KEY")
        self.path = Path(path)
        self.key = hmac.new(registry_key, _DOMAIN, hashlib.sha256).digest()
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), isolation_level=None,
                                  check_same_thread=False, timeout=5)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS events ("
                        "sequence INTEGER PRIMARY KEY, event_json TEXT NOT NULL, "
                        "previous_hmac TEXT NOT NULL, event_hmac TEXT NOT NULL)")
        self.db.execute("CREATE TRIGGER IF NOT EXISTS authority_no_update "
                        "BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append only'); END")
        self.db.execute("CREATE TRIGGER IF NOT EXISTS authority_no_delete "
                        "BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append only'); END")
        self.verify()

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def _event_mac(self, sequence: int, previous: str, event_json: str) -> str:
        message = f"{sequence}:{previous}:{event_json}".encode("utf-8")
        return hmac.new(self.key, message, hashlib.sha256).hexdigest()

    def _events(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT sequence,event_json,previous_hmac,event_hmac FROM events ORDER BY sequence"
        ).fetchall()
        events = []
        previous = "0" * 64
        for expected_sequence, row in enumerate(rows, 1):
            sequence, event_json, linked, mac = row
            if sequence != expected_sequence or linked != previous:
                raise ScopeAuthorityError("V120_AUTHORITY_LEDGER_CORRUPT")
            if not hmac.compare_digest(mac, self._event_mac(sequence, linked, event_json)):
                raise ScopeAuthorityError("V120_AUTHORITY_LEDGER_CORRUPT")
            try:
                event = json.loads(event_json)
            except (TypeError, ValueError):
                raise ScopeAuthorityError("V120_AUTHORITY_LEDGER_CORRUPT") from None
            if not isinstance(event, dict):
                raise ScopeAuthorityError("V120_AUTHORITY_LEDGER_CORRUPT")
            events.append(event)
            previous = mac
        return events

    def verify(self) -> bool:
        with self.lock:
            self._events()
        return True

    def _append(self, event: dict) -> dict:
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                events = self._events()
                previous = "0" * 64 if not events else self.db.execute(
                    "SELECT event_hmac FROM events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()[0]
                sequence = len(events) + 1
                event_json = _canonical(event).decode("ascii")
                mac = self._event_mac(sequence, previous, event_json)
                self.db.execute(
                    "INSERT INTO events(sequence,event_json,previous_hmac,event_hmac) VALUES(?,?,?,?)",
                    (sequence, event_json, previous, mac),
                )
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        return event

    def latest_for_task(self, task_id: str) -> dict | None:
        latest = None
        for event in self._events():
            if event.get("kind") == "issued" and event.get("task_id") == task_id:
                latest = event
        return latest

    def record_issue(self, *, task_id: str, scope_id: str, revision: int,
                     issued_at_utc: str, envelope_sha256: str) -> dict:
        if (not isinstance(task_id, str) or not isinstance(scope_id, str)
                or type(revision) is not int or revision < 1
                or not isinstance(issued_at_utc, str)
                or not isinstance(envelope_sha256, str) or len(envelope_sha256) != 64):
            raise ScopeAuthorityError("V120_SCOPE_ISSUE_INVALID")
        with self.lock:
            events = self._events()
            prior = self.latest_for_task(task_id)
            expected = 1 if prior is None else prior["revision"] + 1
            if revision != expected:
                raise ScopeAuthorityError("V120_SCOPE_REVISION_REPLAY")
            if prior is not None and issued_at_utc <= prior["issued_at_utc"]:
                raise ScopeAuthorityError("V120_SCOPE_ISSUE_REPLAY")
            if any(e.get("kind") == "issued" and e.get("scope_id") == scope_id for e in events):
                raise ScopeAuthorityError("V120_SCOPE_ID_REPLAY")
            return self._append({
                "kind": "issued", "task_id": task_id, "scope_id": scope_id,
                "revision": revision, "issued_at_utc": issued_at_utc,
                "envelope_sha256": envelope_sha256,
            })

    def revoke(self, scope_id: str, revoked_at_utc: str) -> dict:
        if not isinstance(scope_id, str) or not isinstance(revoked_at_utc, str):
            raise ScopeAuthorityError("V120_SCOPE_REVOKE_INVALID")
        with self.lock:
            events = self._events()
            issued = [e for e in events if e.get("kind") == "issued" and e.get("scope_id") == scope_id]
            if not issued:
                raise ScopeAuthorityError("V120_SCOPE_UNKNOWN")
            if any(e.get("kind") == "revoked" and e.get("scope_id") == scope_id for e in events):
                return {"kind": "revoked", "scope_id": scope_id, "replayed": True}
            return self._append({"kind": "revoked", "scope_id": scope_id,
                                 "revoked_at_utc": revoked_at_utc})

    def authorize(self, payload: dict, envelope_sha256: str) -> None:
        with self.lock:
            events = self._events()
            latest = self.latest_for_task(payload["task_id"])
            if (latest is None or latest.get("scope_id") != payload.get("scope_id")
                    or latest.get("revision") != payload.get("scope_revision")
                    or latest.get("envelope_sha256") != envelope_sha256):
                raise ScopeAuthorityError("V120_SCOPE_STALE")
            if any(e.get("kind") == "revoked" and e.get("scope_id") == payload["scope_id"]
                   for e in events):
                raise ScopeAuthorityError("V120_SCOPE_REVOKED")
