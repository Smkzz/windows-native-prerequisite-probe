"""Supervised long-running runs: durable identity, leases, ownership and state.

One server process owns the state directory at a time, so an ``active`` run
found at startup belongs to a dead process and is moved to ``interrupted``.
Resuming is always explicit, workspace-identity-classified, and gated by the
lease: another owner's live lease cannot be silently taken over. Completion is
never inferred; only ``run_finish`` or an explicit resume can end a run.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from ..nextlib.core import Rejected, Signer, digest, ident, integer, need, packed
from ..store import canonical

SCHEMA_VERSION = 2
STATES = frozenset({'active', 'interrupted', 'completed', 'failed', 'cancelled'})
TERMINAL = frozenset({'completed', 'failed', 'cancelled'})
FINISH_STATES = frozenset({'completed', 'failed', 'cancelled'})
NOTE_KEYS = frozenset({'progress', 'phase', 'next_action', 'blockers', 'decisions'})
MAX_EVENTS = 10000
MAX_RUNS = 5000
MAX_NOTE_LIST = 16
MAX_NOTE_TEXT = 1024


def _regular_unlinked(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return (not os.path.islink(str(path)) and not (getattr(info, 'st_file_attributes', 0) & 0x400)
            and info.st_nlink == 1)


def load_key(state_dir: Path) -> bytes:
    path = state_dir / 'run-key.bin'
    if path.exists() or path.is_symlink():
        need(_regular_unlinked(path), 'UNSAFE_STATE_PATH')
        data = path.read_bytes()
        need(len(data) == 32, 'STATE_CORRUPT')
        return data
    data = os.urandom(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags, 0o600)
    try:
        written = os.write(fd, data)
        need(written == len(data), 'STATE_WRITE_FAILED')
        os.fsync(fd)
    finally:
        os.close(fd)
    need(_regular_unlinked(path), 'UNSAFE_STATE_PATH')
    return data


def validate_notes(notes: dict) -> dict:
    need(isinstance(notes, dict) and bool(notes) and len(notes) <= len(NOTE_KEYS), 'INVALID_NOTES')
    need(set(notes) <= NOTE_KEYS, 'INVALID_NOTES')
    out = {}
    for key, value in notes.items():
        if key in {'progress', 'next_action', 'phase'}:
            need(isinstance(value, str) and 0 < len(value) <= MAX_NOTE_TEXT, 'INVALID_NOTES')
            out[key] = value
        else:
            need(isinstance(value, list) and len(value) <= MAX_NOTE_LIST, 'INVALID_NOTES')
            need(all(isinstance(item, str) and 0 < len(item) <= MAX_NOTE_TEXT for item in value), 'INVALID_NOTES')
            out[key] = list(value)
    need(len(packed(out)) <= 8192, 'INVALID_NOTES')
    return out


class RunStore:
    def __init__(self, state_dir: Path):
        self.lock = threading.RLock()
        self.key = load_key(state_dir)
        self.signer = Signer(self.key)
        self.db = sqlite3.connect(state_dir / 'runs.sqlite', check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('''
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runs(
              run_id TEXT PRIMARY KEY, project TEXT NOT NULL, objective TEXT NOT NULL,
              continuation_id TEXT NOT NULL, state TEXT NOT NULL, owner_epoch TEXT NOT NULL,
              owner_jti TEXT, lease_expires_ns INTEGER NOT NULL DEFAULT 0,
              created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL, last_heartbeat_ns INTEGER NOT NULL,
              heartbeats INTEGER NOT NULL DEFAULT 0, identity TEXT NOT NULL, identity_digest TEXT NOT NULL,
              notes TEXT NOT NULL DEFAULT '{}', summary TEXT, finished_ns INTEGER,
              chain_head TEXT, events_pruned INTEGER NOT NULL DEFAULT 0,
              resume_count INTEGER NOT NULL DEFAULT 0, interruption_count INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS run_events(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, event TEXT NOT NULL,
              detail TEXT NOT NULL, time_ns INTEGER NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
            ''')
            need(self.db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'RUN_STORE_CORRUPT')
            with self._tx():
                row = self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
                need(row is None or row['value'] in (str(1), str(SCHEMA_VERSION)), 'RUN_STORE_SCHEMA')
                self.db.execute("INSERT OR REPLACE INTO meta VALUES('schema',?)", (str(SCHEMA_VERSION),))
        except (sqlite3.DatabaseError, OSError):
            try:
                self.db.close()
            except Exception:
                pass
            raise Rejected('RUN_STORE_CORRUPT') from None

    def _tx(self):
        class _Txn:
            def __init__(self, store):
                self.store = store

            def __enter__(self):
                self.store.db.execute('BEGIN IMMEDIATE')
                return self

            def __exit__(self, exc_type, exc, tb):
                if exc_type is None:
                    self.store.db.commit()
                else:
                    self.store.db.rollback()
                return False
        return _Txn(self)

    def _event_locked(self, run_id: str, event: str, detail: dict, now: int) -> str:
        row = self.db.execute('SELECT hash FROM run_events WHERE run_id=? ORDER BY seq DESC LIMIT 1',
                              (run_id,)).fetchone()
        prev = row['hash'] if row else self.db.execute(
            'SELECT chain_head FROM runs WHERE run_id=?', (run_id,)).fetchone()['chain_head'] or '0' * 64
        payload = canonical({'run_id': run_id, 'event': event, 'detail': detail, 'time_ns': now})
        head = hmac.new(self.key, (prev + payload).encode(), 'sha256').hexdigest()
        self.db.execute('INSERT INTO run_events(run_id,event,detail,time_ns,prev_hash,hash) VALUES(?,?,?,?,?,?)',
                        (run_id, event, canonical(detail), now, prev, head))
        self.db.execute('UPDATE runs SET chain_head=? WHERE run_id=?', (head, run_id))
        return head

    def _prune_events_locked(self):
        count = self.db.execute('SELECT count(*) FROM run_events').fetchone()[0]
        if count <= MAX_EVENTS:
            return
        terminal = self.db.execute(
            "SELECT run_id FROM runs WHERE state IN ('completed','failed','cancelled') ORDER BY updated_ns")
        for row in terminal:
            self.db.execute('DELETE FROM run_events WHERE run_id=?', (row['run_id'],))
            self.db.execute('UPDATE runs SET events_pruned=1 WHERE run_id=?', (row['run_id'],))
            count = self.db.execute('SELECT count(*) FROM run_events').fetchone()[0]
            if count <= MAX_EVENTS:
                break

    def _prune_runs_locked(self) -> int:
        """Bound total retained runs by dropping the oldest terminal records."""
        count = self.db.execute('SELECT count(*) FROM runs').fetchone()[0]
        if count <= MAX_RUNS:
            return 0
        excess = count - MAX_RUNS
        rows = self.db.execute(
            "SELECT run_id FROM runs WHERE state IN ('completed','failed','cancelled') "
            'ORDER BY updated_ns LIMIT ?', (excess,)).fetchall()
        for row in rows:
            self.db.execute('DELETE FROM run_events WHERE run_id=?', (row['run_id'],))
            self.db.execute('DELETE FROM runs WHERE run_id=?', (row['run_id'],))
        if rows:
            current = self.db.execute("SELECT value FROM meta WHERE key='pruned_runs'").fetchone()
            total = int(current['value']) if current else 0
            self.db.execute("INSERT OR REPLACE INTO meta VALUES('pruned_runs',?)", (str(total + len(rows)),))
        return len(rows)

    def _token(self, project: str, context, run_id: str, epoch: str, jti: str, ttl_s: int) -> str:
        return self.signer.sign(context, 'run', {'run_id': run_id, 'epoch': epoch, 'jti': jti}, ttl=ttl_s)

    def _row(self, run_id: str) -> sqlite3.Row:
        ident(run_id)
        row = self.db.execute('SELECT * FROM runs WHERE run_id=?', (run_id,)).fetchone()
        need(row is not None, 'UNKNOWN_RUN')
        return row

    def startup(self, epoch: str, now: int | None = None) -> dict:
        now = time.time_ns() if now is None else now
        interrupted = []
        with self.lock:
            with self._tx():
                rows = self.db.execute("SELECT run_id, project FROM runs WHERE state='active'").fetchall()
                for row in rows:
                    self.db.execute("UPDATE runs SET state='interrupted', updated_ns=?, "
                                    "interruption_count=interruption_count+1 WHERE run_id=?",
                                    (now, row['run_id']))
                    self._event_locked(row['run_id'], 'interrupted', {'reason': 'server_restart'}, now)
                    interrupted.append({'run_id': row['run_id'], 'project': row['project']})
                previous = self.db.execute("SELECT value FROM meta WHERE key='epoch'").fetchone()
                self.db.execute("INSERT OR REPLACE INTO meta VALUES('epoch',?)", (epoch,))
                self.db.execute("INSERT OR REPLACE INTO meta VALUES('last_startup_ns',?)", (str(now),))
                self._prune_events_locked()
                pruned = self._prune_runs_locked()
        return {'interrupted': interrupted, 'previous_epoch': previous['value'] if previous else None,
                'pruned_runs': pruned}

    def begin_or_resume(self, *, project: str, context, identity: dict, classification: dict | None,
                        objective: str | None, run_id: str | None, continuation_id: str | None,
                        ttl_s: int, accept_divergence: str | None, takeover: bool, epoch: str,
                        token: str | None = None) -> dict:
        integer(ttl_s, 30, 3600)
        now = time.time_ns()
        with self.lock:
            if run_id is None:
                need(isinstance(objective, str) and 0 < len(objective) <= 2048, 'OBJECTIVE_REQUIRED')
                new_id = 'run-' + uuid.uuid4().hex[:20]
                continuation = continuation_id or new_id
                ident(continuation)
                jti = secrets.token_hex(16)
                with self._tx():
                    self.db.execute(
                        'INSERT INTO runs(run_id,project,objective,continuation_id,state,owner_epoch,owner_jti,'
                        'lease_expires_ns,created_ns,updated_ns,last_heartbeat_ns,identity,identity_digest) '
                        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        (new_id, project, objective, continuation, 'active', epoch, jti, now + ttl_s * 1_000_000_000,
                         now, now, now, packed(identity), identity['digest']))
                    self._event_locked(new_id, 'created', {'project': project, 'objective_sha256': digest(objective)}, now)
                token = self._token(project, context, new_id, epoch, jti, ttl_s)
                return {'run_id': new_id, 'state': 'active', 'created': True, 'resumed': False,
                        'token': token, 'continuation_id': continuation, 'ttl_s': ttl_s,
                        'lease_expires_ns': now + ttl_s * 1_000_000_000,
                        'identity_digest': identity['digest'], 'classification': 'created'}
            row = self._row(run_id)
            need(row['chain_head'] is None or self._chain_ok(run_id, row) is not False, 'RUN_STATE_TAMPERED')
            need(row['project'] == project, 'RUN_PROJECT_MISMATCH')
            need(row['state'] not in TERMINAL, 'RUN_TERMINAL')
            if classification['requires_acceptance'] and accept_divergence != classification['classification']:
                raise Rejected('RUN_WORKSPACE_DIVERGED', {
                    'run_id': run_id, 'classification': classification['classification'],
                    'differences': classification['differences'], 'stored_digest': classification['stored_digest'],
                    'current_digest': classification['current_digest'],
                    'required_acceptance': classification['classification']})
            active_now = row['state'] == 'active'
            lease_live = active_now and row['lease_expires_ns'] > now
            same_epoch_live = active_now and row['owner_epoch'] == epoch and lease_live
            proves_ownership = False
            if same_epoch_live and token is not None:
                try:
                    payload = self.signer.verify(token, context, 'run')
                    proves_ownership = bool(isinstance(payload, dict) and payload.get('run_id') == run_id
                                            and payload.get('epoch') == epoch
                                            and payload.get('jti') == row['owner_jti'])
                except Rejected:
                    proves_ownership = False
            if same_epoch_live and takeover:
                raise Rejected('RUN_OWNED', {'run_id': run_id, 'owner_epoch': row['owner_epoch'],
                                             'lease_expires_ns': row['lease_expires_ns']})
            if same_epoch_live and not proves_ownership:
                raise Rejected('RUN_ACTIVE', {'run_id': run_id, 'lease_expires_ns': row['lease_expires_ns'],
                                              'note': 'live lease owned by this server; pass the current run token to re-bind'})
            jti = secrets.token_hex(16)
            previous_state = row['state']
            takeover_note = active_now and (not lease_live or row['owner_epoch'] != epoch)
            with self._tx():
                self.db.execute(
                    'UPDATE runs SET state=?, owner_epoch=?, owner_jti=?, lease_expires_ns=?, updated_ns=?, '
                    'last_heartbeat_ns=?, identity=?, identity_digest=?, resume_count=resume_count+1 WHERE run_id=?',
                    ('active', epoch, jti, now + ttl_s * 1_000_000_000, now, now, packed(identity),
                     identity['digest'], run_id))
                self._event_locked(run_id, 'resumed', {'classification': (classification or {}).get('classification'),
                                                       'previous_state': previous_state,
                                                       'stale_takeover': bool(takeover_note)}, now)
            token = self._token(project, context, run_id, epoch, jti, ttl_s)
            return {'run_id': run_id, 'state': 'active', 'created': False, 'resumed': True, 'token': token,
                    'continuation_id': row['continuation_id'], 'ttl_s': ttl_s,
                    'lease_expires_ns': now + ttl_s * 1_000_000_000,
                    'identity_digest': identity['digest'],
                    'classification': (classification or {}).get('classification'),
                    'differences': (classification or {}).get('differences', []),
                    'previous_state': previous_state}

    def heartbeat(self, *, run_id: str, project: str, context, token: str, notes: dict | None,
                  ttl_s: int, epoch: str) -> dict:
        integer(ttl_s, 30, 3600)
        now = time.time_ns()
        with self.lock:
            row = self._row(run_id)
            need(row['chain_head'] is None or self._chain_ok(run_id, row) is not False, 'RUN_STATE_TAMPERED')
            need(row['project'] == project, 'RUN_PROJECT_MISMATCH')
            need(row['state'] == 'active', 'RUN_NOT_ACTIVE')
            need(row['owner_epoch'] == epoch, 'RUN_OWNED')
            payload = self.signer.verify(token, context, 'run')
            need(isinstance(payload, dict) and payload.get('run_id') == run_id
                 and payload.get('epoch') == epoch and payload.get('jti') == row['owner_jti'], 'RUN_TOKEN_INVALID')
            clean_notes = validate_notes(notes) if notes is not None else None
            jti = secrets.token_hex(16)
            merged = json.loads(row['notes'])
            if clean_notes:
                merged.update(clean_notes)
            need(len(packed(merged)) <= 8192, 'INVALID_NOTES')
            with self._tx():
                self.db.execute('UPDATE runs SET owner_jti=?, lease_expires_ns=?, last_heartbeat_ns=?, '
                                'updated_ns=?, heartbeats=heartbeats+1, notes=? WHERE run_id=?',
                                (jti, now + ttl_s * 1_000_000_000, now, now, packed(merged), run_id))
            new_token = self._token(project, context, run_id, epoch, jti, ttl_s)
            return {'run_id': run_id, 'state': 'active', 'token': new_token, 'ttl_s': ttl_s,
                    'lease_expires_ns': now + ttl_s * 1_000_000_000, 'heartbeats': row['heartbeats'] + 1,
                    'notes': merged}

    def finish(self, *, run_id: str, project: str, context, token: str, state: str, summary: str | None,
               epoch: str) -> dict:
        need(state in FINISH_STATES, 'INVALID_RUN_STATE')
        now = time.time_ns()
        with self.lock:
            row = self._row(run_id)
            need(row['chain_head'] is None or self._chain_ok(run_id, row) is not False, 'RUN_STATE_TAMPERED')
            need(row['project'] == project, 'RUN_PROJECT_MISMATCH')
            need(row['state'] == 'active', 'RUN_NOT_ACTIVE')
            need(row['owner_epoch'] == epoch, 'RUN_OWNED')
            payload = self.signer.verify(token, context, 'run')
            need(isinstance(payload, dict) and payload.get('run_id') == run_id
                 and payload.get('epoch') == epoch and payload.get('jti') == row['owner_jti'], 'RUN_TOKEN_INVALID')
            if summary is not None:
                need(isinstance(summary, str) and 0 < len(summary) <= 2048, 'INVALID_SUMMARY')
            with self._tx():
                self.db.execute('UPDATE runs SET state=?, updated_ns=?, finished_ns=?, summary=?, owner_jti=NULL '
                                'WHERE run_id=?', (state, now, now, summary, run_id))
                self._event_locked(run_id, 'finished', {'state': state,
                                                        'summary_sha256': digest(summary) if summary else None}, now)
            return {'run_id': run_id, 'state': state, 'finished_ns': now, 'summary_present': bool(summary),
                    'heartbeats': row['heartbeats']}

    def _chain_ok(self, run_id: str, row) -> bool | None:
        if row['events_pruned']:
            return None
        prev = '0' * 64
        for event in self.db.execute('SELECT * FROM run_events WHERE run_id=? ORDER BY seq', (run_id,)):
            payload = canonical({'run_id': event['run_id'], 'event': event['event'],
                                 'detail': json.loads(event['detail']), 'time_ns': event['time_ns']})
            head = hmac.new(self.key, (prev + payload).encode(), 'sha256').hexdigest()
            if event['prev_hash'] != prev or event['hash'] != head:
                return False
            prev = head
        return prev == (row['chain_head'] or '0' * 64)

    @staticmethod
    def _summary(run_id: str, row, now: int, chain_ok) -> dict:
        return {'run_id': run_id, 'project': row['project'], 'objective': row['objective'],
                'continuation_id': row['continuation_id'], 'state': row['state'],
                'created_ns': row['created_ns'], 'updated_ns': row['updated_ns'],
                'last_heartbeat_ns': row['last_heartbeat_ns'],
                'lease_expires_ns': row['lease_expires_ns'],
                'lease_live': bool(row['state'] == 'active' and row['lease_expires_ns'] > now),
                'stale': bool(row['state'] == 'active' and row['lease_expires_ns'] <= now),
                'heartbeats': row['heartbeats'], 'resume_count': row['resume_count'],
                'interruption_count': row['interruption_count'], 'notes': json.loads(row['notes']),
                'summary': row['summary'], 'finished_ns': row['finished_ns'],
                'identity_digest': row['identity_digest'], 'events_pruned': bool(row['events_pruned']),
                'chain_ok': chain_ok}

    def status(self, *, project: str | None = None, run_id: str | None = None) -> dict:
        now = time.time_ns()
        with self.lock:
            if run_id:
                row = self._row(run_id)
                if project:
                    need(row['project'] == project, 'RUN_PROJECT_MISMATCH')
                chain_ok = self._chain_ok(run_id, row)
                return {'run': self._summary(run_id, row, now, chain_ok),
                        'events': [{'seq': e['seq'], 'event': e['event'], 'detail': json.loads(e['detail']),
                                    'time_ns': e['time_ns']}
                                   for e in self.db.execute('SELECT * FROM run_events WHERE run_id=? '
                                                            'ORDER BY seq DESC LIMIT 16', (run_id,))][::-1],
                        'active_run_id': self._active_locked(project)}
            active = self.db.execute("SELECT * FROM runs WHERE state='active' AND (?='' OR project=?) "
                                     'ORDER BY updated_ns DESC LIMIT 1', (project or '', project or '')).fetchone()
            latest = self.db.execute('SELECT * FROM runs WHERE (?=\'\' OR project=?) ORDER BY updated_ns DESC LIMIT 1',
                                     (project or '', project or '')).fetchone()
            chosen = active or latest
            if chosen is None:
                return {'run': None, 'active_run_id': None, 'note': 'no supervised runs recorded'}
            chain_ok = self._chain_ok(chosen['run_id'], chosen)
            return {'run': self._summary(chosen['run_id'], chosen, now, chain_ok), 'active_run_id': active['run_id']
                    if active else None}

    def _active_locked(self, project: str | None) -> str | None:
        row = self.db.execute("SELECT run_id FROM runs WHERE state='active' AND (?='' OR project=?) "
                              'ORDER BY updated_ns DESC LIMIT 1', (project or '', project or '')).fetchone()
        return row['run_id'] if row else None

    def active_run(self, project: str) -> str | None:
        with self.lock:
            return self._active_locked(project)

    def identity_of(self, run_id: str) -> dict:
        with self.lock:
            row = self._row(run_id)
            try:
                record = json.loads(row['identity'])
            except (TypeError, ValueError):
                raise Rejected('RUN_STATE_TAMPERED') from None
            need(isinstance(record, dict) and record.get('schema') == 1, 'RUN_STATE_TAMPERED')
            need(isinstance(record.get('root'), str) and isinstance(record.get('root_id'), dict)
                 and isinstance(record.get('git'), dict) and isinstance(record.get('watched'), dict),
                 'RUN_STATE_TAMPERED')
            return record

    def close(self):
        with self.lock:
            if self.db is not None:
                self.db.close()
                self.db = None

