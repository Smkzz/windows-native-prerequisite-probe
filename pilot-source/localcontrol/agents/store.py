"""Durable delegation plane store. HMAC-chained events, intent queue, replay ledger.

Lives under <state_dir>/v110/agents.sqlite. This file is also opened by the
in-child delegation shim (separate process, WAL + busy_timeout), which is
allowed ONLY to insert into delegation_intents and read its own rows. The
manager process is the sole writer for agents/agent_events.
"""
from __future__ import annotations

import hmac
import json
import sqlite3
import threading
import time
from pathlib import Path

from ..nextlib.core import Rejected, digest, ident, need, packed
from ..v100.missions import load_or_create_key
from . import state as st

MAX_TASK_BYTES = 32768
MAX_EVENT_BYTES = 8192
MAX_PAYLOAD_BYTES = 65536
MAX_EVENTS_PER_AGENT = 4096
SCHEMA_VERSION = '1'


def _bounded_json(value, limit: int, code: str) -> str:
    try:
        encoded = packed(value)
    except (TypeError, ValueError):
        raise Rejected(code) from None
    need(len(encoded) <= limit, code)
    return encoded.decode('ascii')


class AgentStore:
    """SQLite-backed durable store. All mutating methods run under self.lock
    with BEGIN IMMEDIATE semantics; the chained event log is written in the
    same transaction as the state change it records."""

    def __init__(self, state_dir: Path, runtime_instance: str, clock_ns=time.time_ns):
        self.state = state_dir / 'v110'
        self.state.mkdir(parents=True, exist_ok=True)
        self.clock_ns = clock_ns
        self.runtime_instance = ident(runtime_instance)
        self.key = load_or_create_key(self.state / 'agent-key.bin')
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.state / 'agents.sqlite', check_same_thread=False, timeout=15)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=NORMAL')
            self.db.execute('PRAGMA busy_timeout=15000')
            self._schema()
            chain = self.verify_chain()
            need(chain['ok'], 'AGENT_CHAIN_CORRUPT')
        except BaseException:
            # A corrupt/unsuitable store must fail closed AND release the file.
            self.db.close()
            raise
        self._chain = {'ok': True, 'entries': chain['entries'], 'head': chain['head'],
                       'verified_ns': self.clock_ns()}

    def _schema(self) -> None:
        with self.lock:
            self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS agents(
                    agent_id TEXT PRIMARY KEY,
                    scope TEXT NOT NULL,
                    project TEXT NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0,
                    generation INTEGER NOT NULL DEFAULT 1,
                    created_ns INTEGER NOT NULL,
                    updated_ns INTEGER NOT NULL,
                    terminal_ns INTEGER,
                    task TEXT NOT NULL,
                    task_sha256 TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT,
                    effort TEXT,
                    workspace_mode TEXT NOT NULL,
                    workspace_root TEXT NOT NULL,
                    workspace_managed INTEGER NOT NULL DEFAULT 0,
                    worktree_ref TEXT,
                    depth INTEGER NOT NULL DEFAULT 0,
                    parent_agent_id TEXT,
                    lineage_json TEXT NOT NULL DEFAULT '[]',
                    dedupe_key TEXT,
                    request_id TEXT,
                    limits_json TEXT NOT NULL DEFAULT '{}',
                    provider_json TEXT NOT NULL DEFAULT '{}',
                    status_detail_json TEXT NOT NULL DEFAULT '{}',
                    result_json TEXT,
                    output_schema_json TEXT,
                    token_usage_json TEXT,
                    files_changed_json TEXT NOT NULL DEFAULT '[]',
                    delegation_token_sha256 TEXT,
                    delegation_pid INTEGER,
                    delegation_exe TEXT,
                    turns_completed INTEGER NOT NULL DEFAULT 0,
                    tool_denials INTEGER NOT NULL DEFAULT 0,
                    events_seen INTEGER NOT NULL DEFAULT 0,
                    last_event_ns INTEGER,
                    active_turn_id TEXT,
                    active_process INTEGER NOT NULL DEFAULT 0,
                    recovery_attempts INTEGER NOT NULL DEFAULT 0,
                    recovery_next_ns INTEGER,
                    policy_binding TEXT,
                    archived INTEGER NOT NULL DEFAULT 0
                );
                DROP INDEX IF EXISTS agents_dedupe;
                CREATE UNIQUE INDEX agents_dedupe
                    ON agents(scope, dedupe_key) WHERE dedupe_key IS NOT NULL;
                CREATE INDEX IF NOT EXISTS agents_parent ON agents(parent_agent_id);
                CREATE INDEX IF NOT EXISTS agents_state ON agents(state, archived);
                CREATE TABLE IF NOT EXISTS agent_events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    time_ns INTEGER NOT NULL,
                    prev_hmac TEXT,
                    hmac TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS agent_events_agent ON agent_events(agent_id, seq);
                CREATE TABLE IF NOT EXISTS delegation_intents(
                    intent_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_sha256 TEXT NOT NULL,
                    parent_agent_id TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    op TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    result_json TEXT,
                    created_ns INTEGER NOT NULL,
                    done_ns INTEGER
                );
                CREATE UNIQUE INDEX IF NOT EXISTS intents_key
                    ON delegation_intents(parent_agent_id, request_key);
                CREATE INDEX IF NOT EXISTS intents_queued
                    ON delegation_intents(status) WHERE status='queued';
                CREATE TABLE IF NOT EXISTS agent_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self.db.execute("INSERT OR REPLACE INTO agent_meta(key,value) VALUES('schema',?)",
                            (SCHEMA_VERSION,))
            self.db.commit()

    def close(self) -> None:
        with self.lock:
            self.db.close()

    # ---------- chained event log ----------

    def _event(self, agent_id: str, kind: str, payload: dict) -> int:
        """Append a chained event. Caller must hold self.lock and be inside a
        transaction (or this will commit immediately)."""
        row = self.db.execute('SELECT hmac FROM agent_events ORDER BY seq DESC LIMIT 1').fetchone()
        prev = row['hmac'] if row else None
        now = self.clock_ns()
        body = packed({'agent': agent_id, 'kind': kind, 'payload': payload, 'time_ns': now, 'prev': prev})
        sig = hmac.new(self.key, body, 'sha256').hexdigest()
        cur = self.db.execute(
            'INSERT INTO agent_events(agent_id,kind,payload_json,time_ns,prev_hmac,hmac) VALUES(?,?,?,?,?,?)',
            (agent_id, kind, _bounded_json(payload, MAX_EVENT_BYTES, 'EVENT_TOO_LARGE'), now, prev, sig))
        self.db.execute('UPDATE agents SET events_seen=events_seen+1 WHERE agent_id=?', (agent_id,))
        self._chain = {'ok': True, 'entries': self._chain['entries'] + 1, 'head': sig,
                       'verified_ns': self.clock_ns()}
        return int(cur.lastrowid)

    def chain_status(self) -> dict:
        return dict(self._chain)

    def verify_chain(self) -> dict:
        with self.lock:
            prev = None
            count = 0
            for row in self.db.execute('SELECT seq,agent_id,kind,payload_json,time_ns,prev_hmac,hmac '
                                       'FROM agent_events ORDER BY seq'):
                expected = hmac.new(self.key, packed({'agent': row['agent_id'], 'kind': row['kind'],
                                                      'payload': json.loads(row['payload_json']),
                                                      'time_ns': row['time_ns'], 'prev': prev}),
                                    'sha256').hexdigest()
                if row['prev_hmac'] != prev or not hmac.compare_digest(expected, row['hmac']):
                    return {'ok': False, 'entries': count, 'failed_seq': row['seq']}
                prev = row['hmac']
                count += 1
            return {'ok': True, 'entries': count, 'head': prev}

    # ---------- agent records ----------

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        data = dict(row)
        for key in ('lineage', 'limits', 'status_detail', 'result',
                    'output_schema', 'token_usage', 'files_changed'):
            raw = data.pop(key + '_json', None)
            data[key] = json.loads(raw) if raw else ([] if key in ('lineage', 'files_changed') else
                                                     ({} if key in ('limits', 'status_detail')
                                                      else None))
        raw = data.pop('provider_json', None)
        # 'provider' column keeps the provider NAME ('codex'); the runtime
        # snapshot (thread ids, sandbox, exe, home) lives in provider_state.
        data['provider_state'] = json.loads(raw) if raw else {}
        return data

    def get(self, agent_id: str) -> dict:
        ident(agent_id)
        with self.lock:
            row = self.db.execute('SELECT * FROM agents WHERE agent_id=?', (agent_id,)).fetchone()
            need(row is not None, 'AGENT_NOT_FOUND')
            return self._row(row)

    def maybe_get(self, agent_id: str) -> dict | None:
        with self.lock:
            row = self.db.execute('SELECT * FROM agents WHERE agent_id=?', (agent_id,)).fetchone()
            return self._row(row) if row else None

    def create(self, record: dict) -> dict:
        """Insert a new agent row + spawn.accepted event in one transaction.
        Returns the stored record. Raises DEDUPE_CONFLICT with the existing
        record attached when the dedupe_key already exists."""
        with self.lock:
            now = self.clock_ns()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                if record.get('dedupe_key'):
                    existing = self.db.execute(
                        'SELECT * FROM agents WHERE scope=? AND dedupe_key=?',
                        (record['scope'], record['dedupe_key'])).fetchone()
                    if existing is not None:
                        error = Rejected('DEDUPE_CONFLICT')
                        error.existing = self._row(existing)
                        raise error
                self.db.execute(
                    'INSERT INTO agents(agent_id,scope,project,state,revision,generation,created_ns,'
                    'updated_ns,task,task_sha256,profile,provider,model,effort,workspace_mode,'
                    'workspace_root,workspace_managed,worktree_ref,depth,parent_agent_id,lineage_json,'
                    'dedupe_key,request_id,limits_json,provider_json,status_detail_json,result_json,'
                    'output_schema_json,delegation_token_sha256,delegation_pid,delegation_exe,'
                    'last_event_ns,policy_binding) VALUES(' + ','.join(['?'] * 33) + ')',
                    (record['agent_id'], record['scope'], record['project'], st.QUEUED, 0, 1, now, now,
                     record['task'], record['task_sha256'], record['profile'], record['provider'],
                     record.get('model'), record.get('effort'), record['workspace_mode'],
                     record['workspace_root'], 1 if record.get('workspace_managed') else 0,
                     record.get('worktree_ref'), record['depth'], record.get('parent_agent_id'),
                     packed(record.get('lineage', [])).decode('ascii'), record.get('dedupe_key'),
                     record.get('request_id'), _bounded_json(record.get('limits', {}), 8192, 'LIMITS_TOO_LARGE'),
                     _bounded_json(record.get('provider_state', {}), MAX_PAYLOAD_BYTES,
                                   'PROVIDER_TOO_LARGE'),
                     '{}', None,
                     _bounded_json(record['output_schema'], MAX_PAYLOAD_BYTES, 'SCHEMA_TOO_LARGE')
                     if record.get('output_schema') is not None else None,
                     record.get('delegation_token_sha256'), record.get('delegation_pid'),
                     record.get('delegation_exe'), now, record.get('policy_binding')))
                self._event(record['agent_id'], 'spawn.accepted',
                            {'project': record['project'], 'profile': record['profile'],
                             'provider': record['provider'], 'depth': record['depth'],
                             'parent': record.get('parent_agent_id'),
                             'task_sha256': record['task_sha256'],
                             'workspace_mode': record['workspace_mode'],
                             'workspace_root': record['workspace_root'],
                             'policy_binding': record.get('policy_binding'),
                             'dedupe_key': record.get('dedupe_key')})
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
            return self.get(record['agent_id'])

    def transition(self, agent_id: str, expect: set | frozenset | tuple, to: str,
                   kind: str, payload: dict | None = None, **updates) -> dict:
        """Guarded state transition + chained event, one transaction.
        `updates` may set any whitelisted column."""
        need(to in st.STATES, 'INVALID_STATE')
        columns = {'state', 'provider_json', 'status_detail_json', 'result_json', 'token_usage_json',
                   'files_changed_json', 'active_turn_id', 'active_process', 'turns_completed',
                   'tool_denials', 'events_seen', 'last_event_ns', 'terminal_ns', 'recovery_attempts',
                   'recovery_next_ns', 'generation', 'delegation_token_sha256', 'delegation_pid',
                   'delegation_exe', 'archived'}
        need(set(updates) <= columns, 'INVALID_COLUMN')
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                # State check inside the transaction: a second writer on this
                # store cannot interleave between the guard and the update.
                row = self.db.execute('SELECT state,revision,generation,events_seen FROM agents '
                                      'WHERE agent_id=?', (agent_id,)).fetchone()
                if row is None:
                    raise Rejected('AGENT_NOT_FOUND')
                if row['state'] not in set(expect):
                    raise Rejected('STATE_MISMATCH', {'state': row['state'],
                                                      'expected': sorted(expect)})
                allowed = st.TRANSITIONS.get(row['state'], set())
                if to not in allowed:
                    raise Rejected('STATE_MISMATCH', {'state': row['state'], 'to': to})
                assignments = ['state=?', 'revision=?', 'updated_ns=?']
                params = [to, row['revision'] + 1, self.clock_ns()]
                if to in st.TERMINAL:
                    assignments.append('terminal_ns=?')
                    params.append(self.clock_ns())
                for key, value in updates.items():
                    if key.endswith('_json') or key in ('provider_json', 'status_detail_json', 'result_json',
                                                        'token_usage_json', 'files_changed_json'):
                        value = _bounded_json(value, MAX_PAYLOAD_BYTES, 'PAYLOAD_TOO_LARGE')
                    assignments.append(f'"{key}"=?')
                    params.append(value)
                params.append(agent_id)
                self.db.execute(f'UPDATE agents SET {", ".join(assignments)} WHERE agent_id=?', params)
                self._event(agent_id, kind, payload or {'state': to})
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
            return self.get(agent_id)

    def update_fields(self, agent_id: str, kind: str, payload: dict | None = None, **updates) -> dict:
        """Non-state column update + optional event (no state transition)."""
        columns = {'provider_json', 'status_detail_json', 'result_json', 'token_usage_json',
                   'files_changed_json', 'active_turn_id', 'active_process', 'turns_completed',
                   'tool_denials', 'events_seen', 'last_event_ns', 'recovery_attempts',
                   'recovery_next_ns', 'generation', 'delegation_token_sha256', 'delegation_pid',
                   'delegation_exe', 'archived'}
        need(set(updates) <= columns, 'INVALID_COLUMN')
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row = self.db.execute('SELECT revision FROM agents WHERE agent_id=?', (agent_id,)).fetchone()
                need(row is not None, 'AGENT_NOT_FOUND')
                assignments = ['revision=?', 'updated_ns=?']
                params = [row['revision'] + 1, self.clock_ns()]
                for key, value in updates.items():
                    if key.endswith('_json'):
                        value = _bounded_json(value, MAX_PAYLOAD_BYTES, 'PAYLOAD_TOO_LARGE')
                    assignments.append(f'"{key}"=?')
                    params.append(value)
                params.append(agent_id)
                self.db.execute(f'UPDATE agents SET {", ".join(assignments)} WHERE agent_id=?', params)
                if kind:
                    self._event(agent_id, kind, payload or {})
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
            return self.get(agent_id)

    def list(self, *, project: str | None = None, state: str | None = None,
             limit: int = 64, include_archived: bool = False,
             parent: str | None = None) -> list[dict]:
        clauses, params = [], []
        if not include_archived:
            clauses.append('archived=0')
        if project is not None:
            clauses.append('project=?'); params.append(project)
        if state is not None:
            clauses.append('state=?'); params.append(state)
        if parent is not None:
            clauses.append('parent_agent_id=?'); params.append(parent)
        sql = 'SELECT * FROM agents' + (' WHERE ' + ' AND '.join(clauses) if clauses else '') + \
              ' ORDER BY created_ns DESC LIMIT ?'
        params.append(min(max(1, limit), 256))
        with self.lock:
            return [self._row(r) for r in self.db.execute(sql, params)]

    def subtree(self, root_id: str) -> list[dict]:
        """All agents whose lineage contains root_id (the root's descendants)."""
        with self.lock:
            rows = self.db.execute('SELECT agent_id,lineage_json FROM agents').fetchall()
        found = []
        for row in rows:
            if root_id in json.loads(row['lineage_json']):
                found.append(row['agent_id'])
        if not found:
            return []
        with self.lock:
            marks = ','.join('?' for _ in found)
            return [self._row(r) for r in
                    self.db.execute(f'SELECT * FROM agents WHERE agent_id IN ({marks})', found)]

    def events(self, agent_id: str, *, after_seq: int = 0, limit: int = 64,
               tail: bool = False) -> dict:
        ident(agent_id)
        with self.lock:
            order = 'DESC' if tail else 'ASC'
            rows = self.db.execute(
                f'SELECT seq,kind,payload_json,time_ns FROM agent_events WHERE agent_id=? AND seq>? '
                f'ORDER BY seq {order} LIMIT ?',
                (agent_id, max(0, int(after_seq)), min(max(1, limit), 256))).fetchall()
            if tail:
                rows = list(reversed(rows))  # ascending within the tail slice
            return {'events': [{'seq': r['seq'], 'kind': r['kind'],
                                'payload': json.loads(r['payload_json']), 'time_ns': r['time_ns']}
                               for r in rows],
                    'next_cursor': rows[-1]['seq'] if rows else after_seq}

    def live_agents(self) -> list[dict]:
        with self.lock:
            return [self._row(r) for r in self.db.execute(
                'SELECT * FROM agents WHERE state IN ({})'.format(
                    ','.join('?' for _ in st.LIVE)), tuple(st.LIVE))]

    def recover(self) -> list[dict]:
        """At daemon start: every live agent loses its provider session.
        queued→interrupted is deliberate (never silently double-run)."""
        recovered = []
        with self.lock:
            rows = self.db.execute(
                'SELECT agent_id,state FROM agents WHERE state IN ({})'.format(
                    ','.join('?' for _ in st.LIVE)), tuple(st.LIVE)).fetchall()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                for row in rows:
                    self.db.execute("UPDATE agents SET state='interrupted', active_process=0, "
                                    'active_turn_id=NULL, revision=revision+1, updated_ns=? WHERE agent_id=?',
                                    (self.clock_ns(), row['agent_id']))
                    self._event(row['agent_id'], 'daemon.restarted',
                                {'from_state': row['state'], 'runtime_instance': self.runtime_instance})
                    recovered.append({'agent_id': row['agent_id'], 'from_state': row['state']})
                # Intents claimed but never finished belong to the dead runtime:
                # re-queue them so a shim waiting on a result is not stranded.
                self.db.execute("UPDATE delegation_intents SET status='queued' WHERE status='running'")
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
        return recovered

    def stats(self) -> dict:
        with self.lock:
            rows = self.db.execute('SELECT state, COUNT(*) c FROM agents WHERE archived=0 GROUP BY state').fetchall()
            by_state = {r['state']: r['c'] for r in rows}
            intents = self.db.execute("SELECT COUNT(*) c FROM delegation_intents WHERE status='queued'").fetchone()['c']
            return {'agents_by_state': by_state, 'total': sum(by_state.values()),
                    'queued_intents': intents, 'chain': self.chain_status()}

    # ---------- delegation intent queue (shared with the shim process) ----------

    def enqueue_intent(self, token_sha256: str, parent_agent_id: str, request_key: str,
                       op: str, payload: dict) -> dict:
        """Idempotent enqueue keyed on (parent, request_key). Safe for the
        shim process to call on its own connection."""
        need(len(request_key) >= 8 and len(request_key) <= 128, 'INVALID_REQUEST_KEY')
        need(op in {'spawn', 'send', 'cancel'}, 'INVALID_INTENT_OP')
        data = _bounded_json(payload, MAX_PAYLOAD_BYTES, 'PAYLOAD_TOO_LARGE')
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                cur = self.db.execute(
                    'INSERT OR IGNORE INTO delegation_intents(token_sha256,parent_agent_id,request_key,'
                    'op,payload_json,created_ns) VALUES(?,?,?,?,?,?)',
                    (token_sha256, parent_agent_id, request_key, op, data, self.clock_ns()))
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
            row = self.db.execute('SELECT * FROM delegation_intents WHERE parent_agent_id=? AND request_key=?',
                                  (parent_agent_id, request_key)).fetchone()
            return dict(row)

    def poll_intent(self, intent_id: int, timeout_s: float = 30.0) -> dict:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with self.lock:
                row = self.db.execute('SELECT * FROM delegation_intents WHERE intent_id=?',
                                      (intent_id,)).fetchone()
            if row is not None and row['status'] in ('done', 'rejected'):
                return dict(row)
            time.sleep(0.1)
        with self.lock:
            row = self.db.execute('SELECT * FROM delegation_intents WHERE intent_id=?',
                                  (intent_id,)).fetchone()
            need(row is not None, 'INTENT_LOST')
            return dict(row)

    def dequeue_intents(self, limit: int = 32) -> list[dict]:
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                rows = self.db.execute(
                    "SELECT * FROM delegation_intents WHERE status='queued' ORDER BY intent_id LIMIT ?",
                    (min(max(1, limit), 64),)).fetchall()
                claimed = []
                for row in rows:
                    self.db.execute("UPDATE delegation_intents SET status='running' WHERE intent_id=?",
                                    (row['intent_id'],))
                    claimed.append(dict(row))
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
        return claimed

    def requeue_intent(self, intent_id: int) -> None:
        """Return a claimed intent to the queue — the work is still wanted,
        only its precondition (a live parent) is temporarily unmet."""
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute(
                    "UPDATE delegation_intents SET status='queued' "
                    "WHERE intent_id=? AND status='running'", (intent_id,))
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise

    def finish_intent(self, intent_id: int, ok: bool, result: dict) -> None:
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute(
                    'UPDATE delegation_intents SET status=?, result_json=?, done_ns=? WHERE intent_id=?',
                    ('done' if ok else 'rejected',
                     _bounded_json(result, MAX_PAYLOAD_BYTES, 'PAYLOAD_TOO_LARGE'),
                     self.clock_ns(), intent_id))
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise

    def token_lookup(self, token_sha256: str) -> dict | None:
        """Find the agent row a delegation token belongs to."""
        with self.lock:
            row = self.db.execute('SELECT * FROM agents WHERE delegation_token_sha256=?',
                                  (token_sha256,)).fetchone()
            return self._row(row) if row else None
