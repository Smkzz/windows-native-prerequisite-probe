"""LocalControl v1.0 mission runtime: durable missions, budgets and evidence.

Authority stays with the operator policy. A mission snapshot records exactly
what authority existed at begin; no mission operation can widen it. Mission
state lives in SQLite (WAL, synchronous=NORMAL) and every transition is
HMAC-chained. Completion is never a direct state write: the runtime moves a
mission to VERIFYING and only the independent verifier may commit SUCCEEDED.
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

from ..errors import ControlError
from ..nextlib.core import Rejected, digest, ident, need, packed

NON_TERMINAL = frozenset({'READY', 'RUNNING', 'WAITING', 'BLOCKED', 'VERIFYING', 'RECOVERING'})
TERMINAL = frozenset({'SUCCEEDED', 'FAILED', 'CANCELLED', 'ABANDONED'})
STATES = NON_TERMINAL | TERMINAL
TRANSITIONS = {
    'READY': {'RUNNING', 'RECOVERING', 'CANCELLED', 'ABANDONED'},
    'RUNNING': {'WAITING', 'BLOCKED', 'VERIFYING', 'RECOVERING', 'CANCELLED', 'ABANDONED'},
    'WAITING': {'RUNNING', 'BLOCKED', 'VERIFYING', 'RECOVERING', 'CANCELLED', 'ABANDONED'},
    'BLOCKED': {'RUNNING', 'WAITING', 'VERIFYING', 'RECOVERING', 'CANCELLED', 'ABANDONED'},
    'VERIFYING': {'SUCCEEDED', 'FAILED', 'RECOVERING', 'CANCELLED'},
    'RECOVERING': {'RUNNING', 'WAITING', 'BLOCKED', 'VERIFYING', 'CANCELLED', 'ABANDONED', 'FAILED'},
}
RESUMABLE = frozenset({'RECOVERING', 'WAITING', 'BLOCKED'})

# Departure-state -> time accumulator. ACTIVE = states where the mission may
# consume execution resources; SUSPENDED = attributable interruption
# (infrastructure or owner pause); READY = queue before first admission.
TIME_ACCOUNTING = {
    'READY': 'ready_ns',
    'RUNNING': 'active_ns',
    'VERIFYING': 'active_ns',
    'WAITING': 'suspended_ns',
    'BLOCKED': 'suspended_ns',
    'RECOVERING': 'suspended_ns',
}
ACTIVE_STATES = frozenset({'RUNNING', 'VERIFYING'})
SUSPENDED_STATES = frozenset({'WAITING', 'BLOCKED', 'RECOVERING'})
TRUST_CLASSES = frozenset({'operator', 'policy', 'config', 'project', 'repository', 'external',
                           'tool_output', 'model', 'memory'})
# Trust classes that only the server may assign; MCP callers cannot claim them.
SERVER_TRUST = frozenset({'operator', 'policy', 'config'})
MAX_NOTES_BYTES = 16384
MAX_EVIDENCE_BYTES = 65536
MAX_CONTRACT_BYTES = 16384
MAX_BUDGETS_BYTES = 4096
MAX_EVIDENCE_ITEMS = 128
MAX_DETAILS_BYTES = 4096
DEFAULT_BUDGETS = {
    'max_jobs': 16,
    'max_transactions': 16,
    'max_tool_calls': 500,
    'max_output_bytes': 4 * 1024 * 1024,
    'max_wall_ms': 8 * 3600 * 1000,
    'max_job_memory_bytes': 512 * 1024 * 1024,
    'max_job_cpu_ms': 120000,
    'max_job_processes': 8,
}
# Optional time budgets (None = not declared). max_deadline_ms is an absolute
# elapsed cap that cannot be evaded by suspension; max_active_ms caps time in
# execution states only. When max_deadline_ms is declared without an explicit
# max_wall_ms, the legacy elapsed wall cap is superseded (still reported).
OPTIONAL_BUDGETS = {
    'max_active_ms': 7 * 24 * 3600 * 1000,
    'max_deadline_ms': 30 * 24 * 3600 * 1000,
}
BUDGET_KEYS = frozenset(DEFAULT_BUDGETS) | frozenset(OPTIONAL_BUDGETS)
MAX_RESOURCE_KEYS = 32
MAX_RESOURCE_KEY_BYTES = 512
RECOVERY_MAX_ATTEMPTS = 6
RECOVERY_BACKOFF_S = (5, 15, 60, 300, 900, 1800)
MAX_PROBE_ERROR_BYTES = 200


def _bounded_error(exc: BaseException, limit: int = MAX_PROBE_ERROR_BYTES) -> str:
    """Bounded, single-line diagnostic: exception class + sanitized message.

    Deliberately excludes tracebacks, environment values and non-ASCII content
    so persisted recovery evidence stays small and free of secrets."""
    try:
        name = type(exc).__name__
        name = ''.join(ch if 32 <= ord(ch) < 127 else '?' for ch in name)
    except Exception:
        name = 'Error'
    try:
        # Slice before normalizing so a pathological __str__ cannot force an
        # unbounded intermediate allocation.
        text = ' '.join(str(exc)[: limit * 4].split())
    except Exception:
        text = ''
    text = ''.join(ch if 32 <= ord(ch) < 127 else '?' for ch in text)
    out = f'{name}: {text}' if text else name
    return out if len(out) <= limit else out[: limit - 3] + '...'


def normalize_resource_keys(value) -> list[str]:
    """Validate explicit resource identities; never infer them from prose."""
    if value is None:
        return []
    need(isinstance(value, list) and len(value) <= MAX_RESOURCE_KEYS, 'INVALID_RESOURCE_KEYS')
    result = []
    seen = set()
    for item in value:
        need(isinstance(item, str) and 0 < len(item) <= MAX_RESOURCE_KEY_BYTES,
             'INVALID_RESOURCE_KEY')
        need(all(ord(char) >= 32 and char not in '\r\n' for char in item), 'INVALID_RESOURCE_KEY')
        canonical = item.strip().casefold()
        need(bool(canonical), 'INVALID_RESOURCE_KEY')
        if canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return sorted(result)


def normalize_dedupe_key(value) -> str | None:
    if value is None:
        return None
    need(isinstance(value, str) and 0 < len(value) <= 256, 'INVALID_DEDUPE_KEY')
    need(all(ord(char) >= 32 and char not in '\r\n' for char in value), 'INVALID_DEDUPE_KEY')
    return value


def _bounded(value, limit: int, code: str):
    try:
        encoded = packed(value)
    except (TypeError, ValueError):
        raise Rejected(code) from None
    need(len(encoded) <= limit, code)
    return value


def load_or_create_key(path: Path) -> bytes:
    if path.exists():
        data = path.read_bytes()
        need(len(data) == 32, 'MISSION_KEY_INVALID')
        return data
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    tmp = path.with_suffix('.tmp')
    tmp.write_bytes(key)
    os.replace(tmp, path)
    return key


class MissionStore:
    def __init__(self, state_dir: Path, runtime_instance: str, clock_ns=time.time_ns):
        self.state = state_dir / 'v100'
        self.state.mkdir(parents=True, exist_ok=True)
        self.clock_ns = clock_ns
        self.runtime_instance = ident(runtime_instance)
        self.key = load_or_create_key(self.state / 'mission-key.bin')
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.state / 'missions.sqlite', check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.execute('PRAGMA foreign_keys=ON')
        self._schema()
        chain = self.verify_chain()
        need(chain['ok'], 'MISSION_CHAIN_CORRUPT')
        self._chain = {'ok': True, 'entries': chain['entries'], 'head': chain['head'],
                       'verified_ns': self.clock_ns()}

    def _schema(self) -> None:
        with self.lock:
            self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS missions(
                    mission_id TEXT PRIMARY KEY,
                    project TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    created_ns INTEGER NOT NULL,
                    updated_ns INTEGER NOT NULL,
                    terminal_ns INTEGER,
                    owner_token_sha256 TEXT,
                    lease_expires_ns INTEGER,
                    runtime_instance TEXT,
                    workspace_root TEXT,
                    workspace_identity_json TEXT,
                    workspace_identity_sha256 TEXT,
                    policy_binding TEXT,
                    policy_snapshot_json TEXT,
                    policy_snapshot_sha256 TEXT,
                    success_contract_json TEXT,
                    success_contract_sha256 TEXT,
                    budgets_json TEXT,
                    notes_json TEXT NOT NULL DEFAULT '{}',
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    verification_json TEXT,
                    runs_json TEXT NOT NULL DEFAULT '[]',
                    jobs_json TEXT NOT NULL DEFAULT '[]',
                    transactions_json TEXT NOT NULL DEFAULT '[]',
                    tool_calls INTEGER NOT NULL DEFAULT 0,
                    output_bytes INTEGER NOT NULL DEFAULT 0,
                    schedule_id TEXT,
                    request_id TEXT,
                    last_event_seq INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    recovery_reason TEXT,
                    recovery_action TEXT,
                    recovery_next_ns INTEGER,
                    recovery_attempts INTEGER NOT NULL DEFAULT 0,
                    recovery_stuck_since_ns INTEGER,
                    recovery_last_ns INTEGER,
                    generation INTEGER NOT NULL DEFAULT 1,
                    fence_token_sha256 TEXT,
                    resource_keys_json TEXT NOT NULL DEFAULT '[]',
                    dedupe_key TEXT,
                    intent_sha256 TEXT,
                    superseded_by TEXT,
                    dispatch_id TEXT
                );
                CREATE TABLE IF NOT EXISTS mission_events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    mission_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    time_ns INTEGER NOT NULL,
                    prev_hmac TEXT,
                    hmac TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS mission_events_mission ON mission_events(mission_id, seq);
                CREATE TABLE IF NOT EXISTS requests(
                    scope TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    mission_id TEXT,
                    input_sha256 TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_ns INTEGER NOT NULL,
                    PRIMARY KEY(scope, request_id)
                );
                CREATE TABLE IF NOT EXISTS mission_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mission_fences(
                    fence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    resource_key TEXT NOT NULL,
                    mission_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    fence_token_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    acquired_ns INTEGER NOT NULL,
                    released_ns INTEGER,
                    superseded_by TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS mission_active_resource_fence
                    ON mission_fences(resource_key) WHERE state='ACTIVE';
                CREATE INDEX IF NOT EXISTS mission_fences_mission
                    ON mission_fences(mission_id, state);
                CREATE INDEX IF NOT EXISTS missions_recovery_due
                    ON missions(state, recovery_next_ns);
                CREATE INDEX IF NOT EXISTS missions_dispatch
                    ON missions(dispatch_id);
                """
            )
            columns = {row[1] for row in self.db.execute('PRAGMA table_info(missions)')}
            additive = {
                'recovery_reason': 'TEXT',
                'recovery_action': 'TEXT',
                'recovery_next_ns': 'INTEGER',
                'recovery_attempts': 'INTEGER NOT NULL DEFAULT 0',
                'recovery_stuck_since_ns': 'INTEGER',
                'recovery_last_ns': 'INTEGER',
                'generation': 'INTEGER NOT NULL DEFAULT 1',
                'fence_token_sha256': 'TEXT',
                'resource_keys_json': "TEXT NOT NULL DEFAULT '[]'",
                'dedupe_key': 'TEXT',
                'intent_sha256': 'TEXT',
                'superseded_by': 'TEXT',
                'dispatch_id': 'TEXT',
                'state_since_ns': 'INTEGER',
                'active_ns': 'INTEGER NOT NULL DEFAULT 0',
                'suspended_ns': 'INTEGER NOT NULL DEFAULT 0',
                'ready_ns': 'INTEGER NOT NULL DEFAULT 0',
                'first_running_ns': 'INTEGER',
                'time_accounting': 'TEXT',
            }
            for name, declaration in additive.items():
                if name not in columns:
                    self.db.execute(f'ALTER TABLE missions ADD COLUMN "{name}" {declaration}')
            self.db.execute('CREATE UNIQUE INDEX IF NOT EXISTS mission_active_dedupe '
                            'ON missions(project,dedupe_key) WHERE dedupe_key IS NOT NULL')
            self.db.commit()
            self.db.execute("INSERT OR REPLACE INTO mission_meta(key,value) VALUES('schema','2')")
            self.db.execute("INSERT OR REPLACE INTO mission_meta(key,value) VALUES('recovery_model','autonomy-closure')")
            self.db.commit()

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def _event(self, mission_id: str, kind: str, payload: dict) -> int:
        row = self.db.execute('SELECT hmac FROM mission_events ORDER BY seq DESC LIMIT 1').fetchone()
        prev = row['hmac'] if row else None
        now = self.clock_ns()
        body = packed({'mission': mission_id, 'kind': kind, 'payload': payload, 'time_ns': now, 'prev': prev})
        sig = hmac.new(self.key, body, 'sha256').hexdigest()
        cur = self.db.execute(
            'INSERT INTO mission_events(mission_id,kind,payload_json,time_ns,prev_hmac,hmac) VALUES(?,?,?,?,?,?)',
            (mission_id, kind, packed(payload).decode('ascii'), now, prev, sig))
        self._chain = {'ok': True, 'entries': self._chain['entries'] + 1, 'head': sig,
                       'verified_ns': self.clock_ns()}
        return int(cur.lastrowid)

    def chain_status(self) -> dict:
        return dict(self._chain)

    def verify_chain(self) -> dict:
        with self.lock:
            prev = None
            count = 0
            for row in self.db.execute('SELECT seq,mission_id,kind,payload_json,time_ns,prev_hmac,hmac FROM mission_events ORDER BY seq'):
                expected = hmac.new(self.key, packed({'mission': row['mission_id'], 'kind': row['kind'],
                                                      'payload': json.loads(row['payload_json']),
                                                      'time_ns': row['time_ns'], 'prev': prev}), 'sha256').hexdigest()
                if row['prev_hmac'] != prev or not hmac.compare_digest(expected, row['hmac']):
                    return {'ok': False, 'entries': count, 'failed_seq': row['seq']}
                prev = row['hmac']
                count += 1
            return {'ok': True, 'entries': count, 'head': prev}

    @staticmethod
    def _row(row: sqlite3.Row, *, notes: bool = True) -> dict:
        data = {
            'mission_id': row['mission_id'], 'project': row['project'], 'objective': row['objective'],
            'state': row['state'], 'revision': row['revision'],
            'created_ns': row['created_ns'], 'updated_ns': row['updated_ns'],
            'terminal_ns': row['terminal_ns'],
            'lease_expires_ns': row['lease_expires_ns'],
            'workspace_root': row['workspace_root'],
            'workspace_identity_sha256': row['workspace_identity_sha256'],
            'policy_binding': row['policy_binding'],
            'policy_snapshot_sha256': row['policy_snapshot_sha256'],
            'success_contract_sha256': row['success_contract_sha256'],
            'budgets': json.loads(row['budgets_json']),
            'runs': json.loads(row['runs_json']),
            'jobs': json.loads(row['jobs_json']),
            'transactions': json.loads(row['transactions_json']),
            'tool_calls': row['tool_calls'],
            'output_bytes': row['output_bytes'],
            'schedule_id': row['schedule_id'],
            'last_error': row['last_error'],
            'recovery': {
                'reason': row['recovery_reason'],
                'action': row['recovery_action'],
                'next_eligible_ns': row['recovery_next_ns'],
                'attempts': row['recovery_attempts'],
                'stuck_since_ns': row['recovery_stuck_since_ns'],
                'last_ns': row['recovery_last_ns'],
            },
            'generation': row['generation'],
            'fence_token_sha256': row['fence_token_sha256'],
            'resource_keys': json.loads(row['resource_keys_json'] or '[]'),
            'dedupe_key': row['dedupe_key'],
            'superseded_by': row['superseded_by'],
            'dispatch_id': row['dispatch_id'],
            'state_since_ns': row['state_since_ns'],
            'active_ns': row['active_ns'],
            'suspended_ns': row['suspended_ns'],
            'ready_ns': row['ready_ns'],
            'first_running_ns': row['first_running_ns'],
            'time_accounting': row['time_accounting'] or 'partial',
            'terminal_result': row['state'] if row['state'] in TERMINAL else None,
            'verification': json.loads(row['verification_json']) if row['verification_json'] else None,
        }
        if notes:
            data['notes'] = json.loads(row['notes_json'])
            data['evidence'] = json.loads(row['evidence_json'])
            data['policy_snapshot'] = json.loads(row['policy_snapshot_json'])
            data['success_contract'] = json.loads(row['success_contract_json'])
            data['workspace_identity'] = json.loads(row['workspace_identity_json'])
        return data

    def get(self, mission_id: str, *, notes: bool = True) -> dict:
        with self.lock:
            row = self.db.execute('SELECT * FROM missions WHERE mission_id=?', (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            return self._row(row, notes=notes)

    def request_replay(self, scope: str, request_id: str, tool: str, input_sha256: str):
        with self.lock:
            row = self.db.execute('SELECT tool,input_sha256,response_json FROM requests WHERE scope=? AND request_id=?',
                                  (scope, request_id)).fetchone()
        if row is None:
            return None
        need(row['tool'] == tool and row['input_sha256'] == input_sha256, 'IDEMPOTENCY_CONFLICT')
        return json.loads(row['response_json'])

    def _record_request(self, scope: str, request_id: str, tool: str, mission_id: str | None,
                        input_sha256: str, response: dict) -> None:
        # Replay never reissues bearer credentials: a replayed response carries
        # the outcome but not the token/fence_token minted for the first caller.
        # An owner that lost its delivery must reacquire via takeover.
        replay_safe = {k: v for k, v in response.items() if k not in ('token', 'fence_token')}
        with self.lock:
            self.db.execute('INSERT OR REPLACE INTO requests(scope,request_id,tool,mission_id,input_sha256,response_json,created_ns) '
                            'VALUES(?,?,?,?,?,?,?)',
                            (scope, request_id, tool, mission_id, input_sha256,
                             packed(replay_safe).decode('ascii'), self.clock_ns()))

    def _token_valid(self, row: sqlite3.Row, token, *, allow_stale: bool = False) -> bool:
        if allow_stale and row['lease_expires_ns'] is not None and int(row['lease_expires_ns']) <= self.clock_ns():
            return True
        expected = row['owner_token_sha256']
        if not expected or not isinstance(token, str):
            return False
        return hmac.compare_digest(expected, digest(token))

    @staticmethod
    def _assert_generation(row: sqlite3.Row, generation: int | None, fence_token: str | None) -> None:
        if generation is not None:
            need(type(generation) is int and generation == row['generation'], 'STALE_GENERATION')
        if fence_token is not None:
            need(isinstance(fence_token, str) and
                 hmac.compare_digest(row['fence_token_sha256'] or '', digest(fence_token)),
                 'STALE_FENCE')

    def assert_generation(self, mission_id: str, generation: int | None = None,
                          fence_token: str | None = None) -> None:
        with self.lock:
            row = self.db.execute('SELECT * FROM missions WHERE mission_id=?',
                                  (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            self._assert_generation(row, generation, fence_token)

    def begin(self, *, project: str, objective: str, workspace_root: str, workspace_identity: dict,
              policy_binding: str, policy_snapshot: dict, success_contract: dict, budgets: dict,
              ttl_s: int, request_id: str, schedule_id: str | None = None,
              state: str = 'RUNNING', trust_origin: str = 'model', mission_id: str | None = None,
              resource_keys: list[str] | None = None, dedupe_key: str | None = None,
              supersedes_mission_id: str | None = None, supersedes_token: str | None = None,
              takeover: bool = False, dispatch_id: str | None = None) -> dict:
        ident(project)
        need(isinstance(objective, str) and 0 < len(objective) <= 2048, 'INVALID_OBJECTIVE')
        need(trust_origin in TRUST_CLASSES, 'INVALID_TRUST_CLASS')
        need(isinstance(ttl_s, int) and 30 <= ttl_s <= 86400, 'INVALID_TTL')
        ident(request_id)
        need(state in {'READY', 'RUNNING'}, 'INVALID_STATE')
        contract = _bounded(success_contract, MAX_CONTRACT_BYTES, 'CONTRACT_TOO_LARGE')
        snapshot = _bounded(policy_snapshot, MAX_CONTRACT_BYTES, 'POLICY_SNAPSHOT_TOO_LARGE')
        budget_data = _bounded(budgets, MAX_BUDGETS_BYTES, 'INVALID_BUDGETS')
        resource_keys = normalize_resource_keys(resource_keys)
        dedupe_key = normalize_dedupe_key(dedupe_key)
        if supersedes_mission_id is not None:
            ident(supersedes_mission_id)
        intent_sha = digest({'project': project, 'objective': objective, 'contract': contract,
                             'budgets': budget_data, 'schedule_id': schedule_id,
                             'workspace_identity': workspace_identity,
                             'policy_binding': policy_binding, 'resource_keys': resource_keys,
                             'dedupe_key': dedupe_key, 'supersedes_mission_id': supersedes_mission_id})
        scope = 'mission-begin:' + project
        input_sha = digest({'project': project, 'objective': objective, 'contract': contract, 'budgets': budget_data,
                            'schedule_id': schedule_id, 'resource_keys': resource_keys, 'takeover': bool(takeover),
                            'dedupe_key': dedupe_key, 'supersedes_mission_id': supersedes_mission_id})
        replayed = self.request_replay(scope, request_id, 'mission_begin', input_sha)
        if replayed is not None:
            return {**replayed, 'replayed': True}
        mission_id = mission_id or ('mission-' + uuid.uuid4().hex[:16])
        token = secrets.token_urlsafe(24)
        fence_token = secrets.token_urlsafe(24)
        dispatch_id = dispatch_id or ('dispatch-' + uuid.uuid4().hex[:16])
        ident(dispatch_id)
        now = self.clock_ns()
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                existing = None
                if dedupe_key is not None:
                    existing = self.db.execute(
                        'SELECT * FROM missions WHERE project=? AND dedupe_key=?',
                        (project, dedupe_key)).fetchone()
                if existing is None:
                    existing = self.db.execute(
                        'SELECT * FROM missions WHERE mission_id=?', (mission_id,)).fetchone()
                if existing is not None:
                    need(existing['project'] == project and existing['intent_sha256'] == intent_sha,
                         'MISSION_DEDUPE_CONFLICT')
                    response = {'mission_id': existing['mission_id'], 'state': existing['state'],
                                'revision': existing['revision'], 'generation': existing['generation'],
                                'dedupe_key': existing['dedupe_key'],
                                'resource_keys': json.loads(existing['resource_keys_json'] or '[]')}
                    self.db.rollback()
                    return {**response, 'replayed': True, 'dedupe_replayed': True}
                predecessor = None
                if supersedes_mission_id is not None:
                    predecessor = self.db.execute(
                        'SELECT * FROM missions WHERE mission_id=? AND project=?',
                        (supersedes_mission_id, project)).fetchone()
                    need(predecessor is not None, 'SUPERSESSION_TARGET_NOT_FOUND')
                    need(predecessor['mission_id'] != mission_id, 'INVALID_SUPERSESSION')
                    need(predecessor['state'] in NON_TERMINAL, 'SUPERSESSION_TARGET_TERMINAL')
                    # `takeover` is the operator escape and, as on resume/cancel,
                    # it is honored only once the predecessor's lease has lapsed
                    # or the row awaits its owner — otherwise a live mission
                    # could be terminated without any credential (this also
                    # governs scheduled dispatch, which always passes takeover).
                    takeover_stale = takeover and (
                        int(predecessor['lease_expires_ns'] or 0) <= now
                        or predecessor['recovery_action'] == 'AWAIT_OWNER_RESUME')
                    need(takeover_stale or self._token_valid(predecessor, supersedes_token),
                         'MISSION_TOKEN_INVALID')
                conflicts = []
                if resource_keys:
                    marks = ','.join('?' * len(resource_keys))
                    conflicts = self.db.execute(
                        "SELECT * FROM mission_fences WHERE state='ACTIVE' AND resource_key IN (" + marks + ")",
                        tuple(resource_keys)).fetchall()
                if conflicts:
                    owners = {row['mission_id'] for row in conflicts}
                    need(supersedes_mission_id is not None and owners == {supersedes_mission_id},
                         'RESOURCE_CONFLICT')
                generation = int(predecessor['generation']) + 1 if predecessor is not None else 1
                if predecessor is not None:
                    self._supersede_locked(predecessor, mission_id, now)
                self.db.execute(
                    'INSERT INTO missions(mission_id,project,objective,state,revision,created_ns,updated_ns,'
                    'owner_token_sha256,lease_expires_ns,runtime_instance,workspace_root,workspace_identity_json,'
                    'workspace_identity_sha256,policy_binding,policy_snapshot_json,policy_snapshot_sha256,'
                    'success_contract_json,success_contract_sha256,budgets_json,notes_json,evidence_json,schedule_id,'
                    'request_id,generation,fence_token_sha256,resource_keys_json,dedupe_key,intent_sha256,dispatch_id,'
                    'state_since_ns,time_accounting)'
                    ' VALUES(:mission_id,:project,:objective,:state,0,:created_ns,:updated_ns,'
                    ':owner_token_sha256,:lease_expires_ns,:runtime_instance,:workspace_root,:workspace_identity_json,'
                    ':workspace_identity_sha256,:policy_binding,:policy_snapshot_json,:policy_snapshot_sha256,'
                    ':success_contract_json,:success_contract_sha256,:budgets_json,:notes_json,:evidence_json,'
                    ':schedule_id,:request_id,:generation,:fence_token_sha256,:resource_keys_json,:dedupe_key,'
                    ':intent_sha256,:dispatch_id,:state_since_ns,:time_accounting)',
                    {'mission_id': mission_id, 'project': project, 'objective': objective, 'state': state,
                     'created_ns': now, 'updated_ns': now, 'owner_token_sha256': digest(token),
                     'lease_expires_ns': now + ttl_s * 1_000_000_000, 'runtime_instance': self.runtime_instance,
                     'workspace_root': workspace_root, 'workspace_identity_json': json.dumps(workspace_identity),
                     'workspace_identity_sha256': workspace_identity.get('digest'),
                     'policy_binding': policy_binding, 'policy_snapshot_json': json.dumps(snapshot),
                     'policy_snapshot_sha256': digest(snapshot), 'success_contract_json': json.dumps(contract),
                     'success_contract_sha256': digest(contract), 'budgets_json': json.dumps(budget_data),
                     'notes_json': '{}', 'evidence_json': '[]', 'schedule_id': schedule_id,
                     'request_id': request_id, 'generation': generation,
                     'fence_token_sha256': digest(fence_token), 'resource_keys_json': json.dumps(resource_keys),
                     'dedupe_key': dedupe_key, 'intent_sha256': intent_sha, 'dispatch_id': dispatch_id,
                     'state_since_ns': now, 'time_accounting': 'full'})
                seq = self._event(mission_id, 'mission_created', {'objective': objective, 'project': project,
                                                                  'state': state, 'policy_binding': policy_binding,
                                                                  'trust_origin': trust_origin,
                                                                  'resource_keys': resource_keys,
                                                                  'generation': generation,
                                                                  'dispatch_id': dispatch_id})
                self.db.execute('UPDATE missions SET last_event_seq=? WHERE mission_id=?', (seq, mission_id))
                for resource_key in resource_keys:
                    self.db.execute(
                        'INSERT INTO mission_fences(resource_key,mission_id,generation,fence_token_sha256,state,acquired_ns)'
                        ' VALUES(?,?,?,?,?,?)',
                        (resource_key, mission_id, generation, digest(fence_token), 'ACTIVE', now))
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                self.db.rollback()
                raise Rejected('RESOURCE_CONFLICT') from exc
            except BaseException:
                self.db.rollback()
                raise
            response = {'mission_id': mission_id, 'state': state, 'token': token, 'revision': 0,
                        'created_ns': now, 'policy_binding': policy_binding,
                        'workspace_identity_sha256': workspace_identity.get('digest'),
                        'success_contract_sha256': digest(contract), 'budgets': budget_data,
                        'generation': generation, 'fence_token': fence_token,
                        'resource_keys': resource_keys, 'dedupe_key': dedupe_key,
                        'dispatch_id': dispatch_id}
            self._record_request(scope, request_id, 'mission_begin', mission_id, input_sha, response)
            self.db.commit()
        return response

    def transition(self, mission_id: str, expect: str, target: str, kind: str, payload: dict, *,
                   token=None, allow_stale: bool = False, generation: int | None = None,
                   fence_token: str | None = None, extra_sql: str = '', extra_args: tuple = (),
                   last_error: str | None = None) -> sqlite3.Row:
        ident(mission_id)
        need(expect in STATES and target in STATES, 'INVALID_STATE')
        need(target in TRANSITIONS.get(expect, ()), 'ILLEGAL_TRANSITION')
        with self.lock:
            row = self.db.execute('SELECT * FROM missions WHERE mission_id=?', (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            need(row['state'] == expect, 'STATE_MISMATCH')
            if token is not None or allow_stale:
                need(self._token_valid(row, token, allow_stale=allow_stale), 'MISSION_TOKEN_INVALID')
            self._assert_generation(row, generation, fence_token)
            now = self.clock_ns()
            target_terminal = target in TERMINAL
            guard_sql = ''
            guard_args = []
            if generation is not None:
                guard_sql += ' AND generation=?'
                guard_args.append(generation)
            if fence_token is not None:
                guard_sql += ' AND fence_token_sha256=?'
                guard_args.append(digest(fence_token))
            self.db.execute('BEGIN IMMEDIATE')
            try:
                seq = self._event(mission_id, kind, {**payload, 'from': expect, 'to': target})
                # Durable time-in-state accounting: the departing state's
                # elapsed interval folds into its category accumulator so
                # active/suspended/queue accounting survives restarts.
                acc_sql, acc_args = ', state_since_ns=?', [now]
                prev_since = row['state_since_ns']
                if prev_since is not None:
                    delta = max(0, now - prev_since)
                    bucket = TIME_ACCOUNTING.get(expect)
                    if bucket:
                        acc_sql += f', {bucket}={bucket}+?'
                        acc_args.append(delta)
                if target == 'RUNNING' and row['first_running_ns'] is None:
                    acc_sql += ', first_running_ns=?'
                    acc_args.append(now)
                self.db.execute(
                    'UPDATE missions SET state=?, revision=revision+1, updated_ns=?, terminal_ns=?, last_event_seq=?, '
                    'last_error=COALESCE(?,last_error) ' + acc_sql + extra_sql +
                    ' WHERE mission_id=? AND state=?' + guard_sql,
                    (target, now, now if target_terminal else None, seq, last_error, *acc_args,
                     *extra_args, mission_id, expect, *guard_args))
                changed = self.db.execute('SELECT changes() AS n').fetchone()['n']
                need(changed == 1, 'STATE_RACE')
                if target_terminal:
                    self._release_fences_locked(mission_id, now)
                    self.db.execute(
                        'UPDATE missions SET recovery_reason=NULL,recovery_action=NULL,recovery_next_ns=NULL,'
                        'recovery_attempts=0,recovery_stuck_since_ns=NULL,recovery_last_ns=? WHERE mission_id=?',
                        (now, mission_id))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            return self.db.execute('SELECT * FROM missions WHERE mission_id=?', (mission_id,)).fetchone()

    def heartbeat_lease(self, mission_id: str, *, token: str, ttl_s: int, expect: str) -> str:
        need(isinstance(ttl_s, int) and 30 <= ttl_s <= 86400, 'INVALID_TTL')
        with self.lock:
            row = self.db.execute('SELECT * FROM missions WHERE mission_id=?', (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            need(row['state'] == expect, 'STATE_MISMATCH')
            need(self._token_valid(row, token), 'MISSION_TOKEN_INVALID')
            new_token = secrets.token_urlsafe(24)
            now = self.clock_ns()
            self._event(mission_id, 'lease_renewed', {'ttl_s': ttl_s})
            self.db.execute('UPDATE missions SET owner_token_sha256=?, lease_expires_ns=?, runtime_instance=?, '
                            'updated_ns=?, revision=revision+1 WHERE mission_id=?',
                            (digest(new_token), now + ttl_s * 1_000_000_000, self.runtime_instance, now, mission_id))
            self.db.commit()
            return new_token

    def _release_fences_locked(self, mission_id: str, now: int, superseded_by: str | None = None) -> None:
        self.db.execute(
            "UPDATE mission_fences SET state='RELEASED',released_ns=?,superseded_by=? "
            "WHERE mission_id=? AND state='ACTIVE'",
            (now, superseded_by, mission_id))

    def _supersede_locked(self, row: sqlite3.Row, replacement_id: str, now: int) -> None:
        if row['state'] not in NON_TERMINAL:
            return
        seq = self._event(row['mission_id'], 'mission_superseded',
                          {'replacement_mission_id': replacement_id,
                           'generation': row['generation']})
        self.db.execute(
            'UPDATE missions SET state=?,revision=revision+1,updated_ns=?,terminal_ns=?,'
            'last_event_seq=?,last_error=?,superseded_by=?,recovery_reason=?,recovery_action=? '
            'WHERE mission_id=? AND state=?',
            ('ABANDONED', now, now, seq, 'superseded by explicit replacement', replacement_id,
             'superseded', 'reject_stale_generation', row['mission_id'], row['state']))
        self._release_fences_locked(row['mission_id'], now, replacement_id)

    def resume(self, mission_id: str, *, token: str | None, expect: str,
               ttl_s: int, allow_stale: bool, takeover: bool = False,
               generation: int | None = None,
               fence_token: str | None = None, classification: str = 'same',
               differences: list | None = None,
               workspace_identity: dict | None = None) -> dict:
        need(expect in RESUMABLE, 'STATE_MISMATCH')
        need(isinstance(ttl_s, int) and 30 <= ttl_s <= 86400, 'INVALID_TTL')
        need(workspace_identity is None or isinstance(workspace_identity, dict),
             'INVALID_IDENTITY')
        with self.lock:
            row = self.db.execute('SELECT * FROM missions WHERE mission_id=?',
                                  (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            need(row['state'] == expect, 'STATE_MISMATCH')
            expired_lease = (row['lease_expires_ns'] is not None
                             and int(row['lease_expires_ns']) <= self.clock_ns())
            if row['recovery_action'] == 'AWAIT_OWNER_RESUME' or expired_lease:
                # Ownership acquisition: the claimant must prove the last
                # delivered credential (the claim anchor — never rotated by
                # the scheduler) or invoke an explicit takeover. The blanket
                # expired-lease stale-token bypass does not apply here, nor in
                # any other expired-lease recovery state (e.g. a swept mission
                # still mid-reconcile) — an expired lease means ownership has
                # lapsed and no unauthenticated claim is ever allowed.
                need(self._token_valid(row, token) or takeover,
                     'MISSION_TOKEN_INVALID')
            else:
                need(self._token_valid(row, token, allow_stale=allow_stale),
                     'MISSION_TOKEN_INVALID')
            self._assert_generation(row, generation, fence_token)
            now = self.clock_ns()
            resource_keys = json.loads(row['resource_keys_json'] or '[]')
            new_token = secrets.token_urlsafe(24)
            new_fence = secrets.token_urlsafe(24)
            new_generation = int(row['generation'] or 1) + 1
            self.db.execute('BEGIN IMMEDIATE')
            try:
                if resource_keys:
                    marks = ','.join('?' * len(resource_keys))
                    conflicts = self.db.execute(
                        "SELECT mission_id FROM mission_fences WHERE state='ACTIVE' AND mission_id<>? "
                        "AND resource_key IN (" + marks + ")",
                        (mission_id, *resource_keys)).fetchall()
                    need(not conflicts, 'RESOURCE_CONFLICT')
                seq = self._event(mission_id, 'mission_resumed',
                                  {'classification': classification,
                                   'differences': (differences or [])[:16],
                                   'generation': new_generation,
                                   'identity_rebound': workspace_identity is not None
                                   and classification != 'same',
                                   'workspace_identity_sha256': workspace_identity.get('digest')
                                   if workspace_identity is not None else None})
                identity_sql = ''
                identity_args: tuple = ()
                if workspace_identity is not None:
                    identity_sql = ',workspace_identity_json=?,workspace_identity_sha256=?'
                    identity_args = (json.dumps(workspace_identity),
                                     workspace_identity.get('digest'))
                self.db.execute(
                    'UPDATE missions SET state=?,revision=revision+1,updated_ns=?,terminal_ns=NULL,'
                    'last_event_seq=?,last_error=NULL,owner_token_sha256=?,lease_expires_ns=?,'
                    'runtime_instance=?,generation=?,fence_token_sha256=?,recovery_reason=NULL,'
                    'recovery_action=NULL,recovery_next_ns=NULL,recovery_attempts=0,'
                    'recovery_stuck_since_ns=NULL,recovery_last_ns=?' + identity_sql +
                    ' WHERE mission_id=? AND state=?',
                    ('RUNNING', now, seq, digest(new_token), now + ttl_s * 1_000_000_000,
                     self.runtime_instance, new_generation, digest(new_fence), now,
                     *identity_args, mission_id, expect))
                need(self.db.execute('SELECT changes() AS n').fetchone()['n'] == 1, 'STATE_RACE')
                self.db.execute(
                    "UPDATE mission_fences SET generation=?,fence_token_sha256=? "
                    "WHERE mission_id=? AND state='ACTIVE'",
                    (new_generation, digest(new_fence), mission_id))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            return {'mission_id': mission_id, 'state': 'RUNNING',
                    'revision': row['revision'] + 1, 'token': new_token,
                    'fence_token': new_fence, 'generation': new_generation,
                    'classification': classification,
                    'differences': (differences or [])[:16]}

    def checkpoint(self, mission_id: str, *, token: str, expected_revision: int | None, notes: dict | None,
                   evidence: list | None, state: str | None, ttl_s: int, trust_origin: str = 'model',
                   generation: int | None = None, fence_token: str | None = None) -> dict:
        need(state in (None, 'RUNNING', 'WAITING', 'BLOCKED'), 'INVALID_STATE')
        need(type(ttl_s) is int and 30 <= ttl_s <= 86400, 'INVALID_TTL')
        with self.lock:
            row = self.db.execute('SELECT * FROM missions WHERE mission_id=?', (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            need(row['state'] in NON_TERMINAL - {'VERIFYING', 'RECOVERING'}, 'STATE_MISMATCH')
            need(self._token_valid(row, token), 'MISSION_TOKEN_INVALID')
            self._assert_generation(row, generation, fence_token)
            if expected_revision is not None:
                need(type(expected_revision) is int and expected_revision == row['revision'], 'STALE_REVISION')
            merged = json.loads(row['notes_json'])
            if notes is not None:
                need(isinstance(notes, dict), 'INVALID_NOTES')
                merged.update(notes)
                _bounded(merged, MAX_NOTES_BYTES, 'NOTES_TOO_LARGE')
            items = json.loads(row['evidence_json'])
            if evidence is not None:
                need(isinstance(evidence, list) and len(evidence) <= 32, 'INVALID_EVIDENCE')
                for item in evidence:
                    need(isinstance(item, dict) and set(item) <= {'kind', 'ref', 'sha256', 'note', 'trust'}, 'INVALID_EVIDENCE')
                    item_trust = item.get('trust', trust_origin)
                    need(item_trust in TRUST_CLASSES, 'INVALID_TRUST_CLASS')
                    if trust_origin not in SERVER_TRUST:
                        need(item_trust not in SERVER_TRUST, 'TRUST_CLASS_RESERVED')
                    if trust_origin in SERVER_TRUST:
                        need(item_trust in SERVER_TRUST, 'TRUST_CLASS_ESCALATION')
                    items.append({**item, 'trust': item_trust, 'time_ns': self.clock_ns()})
                need(len(items) <= MAX_EVIDENCE_ITEMS, 'EVIDENCE_TOO_LARGE')
                _bounded(items, MAX_EVIDENCE_BYTES, 'EVIDENCE_TOO_LARGE')
            target = state or row['state']
            self._assert_generation(row, generation, fence_token)
            if target != row['state']:
                # Only ordinary RUNNING/WAITING churn is allowed here. Exiting
                # BLOCKED (operator gates) or RECOVERING (reclaim) requires the
                # resume path, which enforces binding/divergence checks and
                # rotates generation/fence credentials.
                need(row['state'] in ('RUNNING', 'WAITING')
                     and target in TRANSITIONS.get(row['state'], ()), 'ILLEGAL_TRANSITION')
            now = self.clock_ns()
            new_token = secrets.token_urlsafe(24)
            guard_sql = ''
            guard_args = []
            if generation is not None:
                guard_sql += ' AND generation=?'
                guard_args.append(generation)
            if fence_token is not None:
                guard_sql += ' AND fence_token_sha256=?'
                guard_args.append(digest(fence_token))
            self.db.execute('BEGIN IMMEDIATE')
            try:
                seq = self._event(
                    mission_id, 'checkpoint',
                    {'state': target, 'notes_keys': sorted((notes or {}).keys()),
                     'evidence_added': len(evidence or [])})
                self.db.execute(
                    'UPDATE missions SET notes_json=?, evidence_json=?, state=?, revision=revision+1, updated_ns=?, '
                    'owner_token_sha256=?, lease_expires_ns=?, runtime_instance=?, last_event_seq=?,'
                    'recovery_reason=NULL,recovery_action=NULL,recovery_next_ns=NULL,recovery_attempts=0,'
                    'recovery_stuck_since_ns=NULL,recovery_last_ns=? WHERE mission_id=? AND state=?' + guard_sql,
                    (json.dumps(merged), json.dumps(items), target, now, digest(new_token),
                     now + ttl_s * 1_000_000_000, self.runtime_instance, seq, now, mission_id,
                     row['state'], *guard_args))
                need(self.db.execute('SELECT changes() AS n').fetchone()['n'] == 1, 'STATE_RACE')
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            return {'mission_id': mission_id, 'state': target, 'revision': row['revision'] + 1,
                    'token': new_token, 'generation': row['generation'],
                    'fence_token_sha256': row['fence_token_sha256'],
                    'notes_bytes': len(packed(merged))}

    def bind(self, mission_id: str, *, run_id: str | None = None, job_id: str | None = None,
             transaction_id: str | None = None, output_bytes: int = 0) -> None:
        with self.lock:
            row = self.db.execute('SELECT * FROM missions WHERE mission_id=?', (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            runs = json.loads(row['runs_json'])
            jobs = json.loads(row['jobs_json'])
            transactions = json.loads(row['transactions_json'])
            if run_id:
                ident(run_id)
                if run_id not in runs:
                    runs.append(run_id)
            if job_id:
                ident(job_id)
                if job_id not in jobs:
                    jobs.append(job_id)
            if transaction_id:
                ident(transaction_id)
                if transaction_id not in transactions:
                    transactions.append(transaction_id)
            need(len(runs) <= 64 and len(jobs) <= 256 and len(transactions) <= 256, 'CORRELATION_LIMIT')
            need(type(output_bytes) is int and output_bytes >= 0, 'INVALID_OUTPUT')
            self.db.execute('UPDATE missions SET runs_json=?, jobs_json=?, transactions_json=?, output_bytes=output_bytes+? '
                            'WHERE mission_id=?',
                            (json.dumps(runs), json.dumps(jobs), json.dumps(transactions), output_bytes, mission_id))
            self.db.commit()

    def charge_tool_call(self, mission_id: str, *, max_calls: int) -> int:
        with self.lock:
            row = self.db.execute('SELECT tool_calls FROM missions WHERE mission_id=?', (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            need(row['tool_calls'] + 1 <= max_calls, 'BUDGET_TOOL_CALLS')
            self.db.execute('UPDATE missions SET tool_calls=tool_calls+1 WHERE mission_id=?', (mission_id,))
            self.db.commit()
            return row['tool_calls'] + 1

    def budget_state(self, mission_id: str) -> dict:
        with self.lock:
            row = self.db.execute('SELECT budgets_json,tool_calls,output_bytes,jobs_json,transactions_json FROM missions '
                                  'WHERE mission_id=?', (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            budgets = json.loads(row['budgets_json'])
            return {'budgets': budgets, 'tool_calls': row['tool_calls'], 'output_bytes': row['output_bytes'],
                    'jobs': len(json.loads(row['jobs_json'])), 'transactions': len(json.loads(row['transactions_json']))}

    def commit_verification(self, mission_id: str, *, verdict: bool, verification: dict, detail: str | None = None) -> dict:
        need(isinstance(verification, dict), 'INVALID_VERIFICATION')
        _bounded(verification, MAX_EVIDENCE_BYTES, 'VERIFICATION_TOO_LARGE')
        target = 'SUCCEEDED' if verdict else 'FAILED'
        row = self.transition(mission_id, 'VERIFYING', target, 'mission_verdict',
                              {'verdict': verdict, 'verification_sha256': digest(verification)},
                              extra_sql=', verification_json=?', extra_args=(packed(verification).decode('ascii'),),
                              last_error=None if verdict else (detail or 'verification failed'))
        return self._row(row)

    def cancel(self, mission_id: str, *, token: str | None, reason: str, abandon: bool, allow_stale: bool,
               generation: int | None = None, fence_token: str | None = None) -> dict:
        need(isinstance(reason, str) and 0 < len(reason) <= 512, 'INVALID_REASON')
        target = 'ABANDONED' if abandon else 'CANCELLED'
        with self.lock:
            row = self.db.execute('SELECT * FROM missions WHERE mission_id=?', (mission_id,)).fetchone()
            need(row is not None, 'MISSION_NOT_FOUND')
            need(row['state'] in NON_TERMINAL, 'ALREADY_TERMINAL')
            need(self._token_valid(row, token, allow_stale=allow_stale), 'MISSION_TOKEN_INVALID')
            self._assert_generation(row, generation, fence_token)
            need(target in TRANSITIONS[row['state']], 'ILLEGAL_TRANSITION')
        out = self.transition(mission_id, row['state'], target, 'mission_cancelled',
                              {'reason': reason, 'abandon': abandon}, token=token, allow_stale=allow_stale,
                              generation=generation, fence_token=fence_token)
        return self._row(out)

    def recover(self) -> list[dict]:
        """Mark non-terminal missions owned by a previous runtime RECOVERING.

        A fresh process is the only owner of the state directory (instance
        lease), so a foreign runtime_instance means the owner is gone.
        Completion is never inferred: missions become RECOVERING, not terminal.
        Missions already RECOVERING stay RECOVERING (idempotent startup).
        """
        recovered = []
        with self.lock:
            rows = self.db.execute('SELECT * FROM missions WHERE state IN (%s)' %
                                   ','.join('?' * len(NON_TERMINAL)), tuple(NON_TERMINAL)).fetchall()
            for row in rows:
                if row['runtime_instance'] == self.runtime_instance:
                    continue
                if row['state'] == 'RECOVERING':
                    recovered.append({'mission_id': row['mission_id'], 'from': row['state'],
                                      'reobserved': True})
                    continue
                try:
                    self.transition(row['mission_id'], row['state'], 'RECOVERING', 'runtime_lost',
                                    {'previous_runtime': row['runtime_instance']},
                                    extra_sql=', recovery_reason=?, recovery_action=?, recovery_next_ns=?,'
                                              'recovery_stuck_since_ns=COALESCE(recovery_stuck_since_ns,?),'
                                              'recovery_last_ns=?',
                                    extra_args=('runtime_lost', 'RECONCILE_STARTUP', self.clock_ns(),
                                                self.clock_ns(), self.clock_ns()))
                except Rejected as exc:
                    recovered.append({'mission_id': row['mission_id'], 'from': row['state'],
                                      'error': exc.code})
                    continue
                recovered.append({'mission_id': row['mission_id'], 'from': row['state']})
            if recovered:
                self.db.commit()
        return recovered

    @staticmethod
    def _recovery_delay(attempts: int) -> int:
        index = max(0, min(int(attempts), len(RECOVERY_BACKOFF_S) - 1))
        return RECOVERY_BACKOFF_S[index]

    def _recovery_event_locked(self, row: sqlite3.Row, *, state: str, reason: str,
                               action: str, next_ns: int | None, attempts: int,
                               last_error: str | None = None) -> None:
        now = self.clock_ns()
        seq = self._event(row['mission_id'], 'recovery_decision',
                          {'from': row['state'], 'to': state, 'reason': reason,
                           'action': action, 'next_eligible_ns': next_ns,
                           'attempts': attempts})
        self.db.execute(
            'UPDATE missions SET state=?,revision=revision+1,updated_ns=?,last_event_seq=?,'
            'last_error=COALESCE(?,last_error),recovery_reason=?,recovery_action=?,'
            'recovery_next_ns=?,recovery_attempts=?,recovery_stuck_since_ns=COALESCE(recovery_stuck_since_ns,?),'
            'recovery_last_ns=? WHERE mission_id=? AND state=?',
            (state, now, seq, last_error, reason, action, next_ns, attempts,
             now if state == 'RECOVERING' else row['recovery_stuck_since_ns'], now,
             row['mission_id'], row['state']))
        need(self.db.execute('SELECT changes() AS n').fetchone()['n'] == 1, 'RECOVERY_STATE_RACE')

    def _reclaim_locked(self, row: sqlite3.Row, *, reason: str,
                        ttl_s: int, now: int) -> dict:
        """Mark a recoverable mission as awaiting owner acquisition.

        The scheduler never mints an ownership credential: a token generated
        here would be returned only to scheduler-internal receipts, leaving the
        mission RUNNING but unreachable (C-D1). Instead the mission stays
        RECOVERING with action AWAIT_OWNER_RESUME, its lease is expired, and
        the existing owner_token_sha256 — the last credential actually
        delivered to an external caller — remains as the sole claim anchor.
        resume() performs the atomic generation/fence rotation only when a
        claimant proves that anchor (or an explicit takeover). No unreachable
        owned state is ever created.
        """
        resource_keys = json.loads(row['resource_keys_json'] or '[]')
        conflicts = []
        if resource_keys:
            marks = ','.join('?' * len(resource_keys))
            conflicts = self.db.execute(
                "SELECT mission_id FROM mission_fences WHERE state='ACTIVE' AND mission_id<>? "
                "AND resource_key IN (" + marks + ")",
                (row['mission_id'], *resource_keys)).fetchall()
        need(not conflicts, 'RESOURCE_CONFLICT')
        seq = self._event(row['mission_id'], 'recovery_reclaimed',
                          {'reason': reason, 'action': 'AWAIT_OWNER_RESUME',
                           'generation': int(row['generation'] or 1)})
        self.db.execute(
            'UPDATE missions SET revision=revision+1,updated_ns=?,'
            'last_event_seq=?,last_error=NULL,lease_expires_ns=?,'
            'runtime_instance=NULL,recovery_reason=?,'
            'recovery_action=?,recovery_next_ns=NULL,recovery_attempts=?,'
            'recovery_last_ns=? WHERE mission_id=? AND state=?',
            (now, seq, 0, reason, 'AWAIT_OWNER_RESUME', int(row['recovery_attempts'] or 0), now,
             row['mission_id'], row['state']))
        need(self.db.execute('SELECT changes() AS n').fetchone()['n'] == 1, 'RECOVERY_STATE_RACE')
        current = self.db.execute('SELECT * FROM missions WHERE mission_id=?',
                                  (row['mission_id'],)).fetchone()
        result = self._row(current, notes=False)
        result.update({'recovery_action': 'AWAIT_OWNER_RESUME', 'recovery_reason': reason,
                       'awaiting_owner': True})
        return result

    def _probe_recovery(self, probe, row: sqlite3.Row) -> dict:
        if probe is None:
            return {}
        result = probe(self._row(row, notes=False))
        if result is None:
            return {}
        if isinstance(result, str):
            return {'state': result, 'classification': result}
        need(isinstance(result, dict), 'RECOVERY_PROBE_INVALID')
        return result

    def reconcile_recovering(self, *, identity_probe=None, policy_probe=None,
                             worker_probe=None, transaction_probe=None, move_probe=None,
                             ttl_s: int = 3600, now_ns: int | None = None,
                             limit: int = 64) -> list[dict]:
        """Resolve only recoverable states; ambiguity is durable and fail-closed.

        Probes are observations, never completion authority. A mission is
        auto-reclaimed only when identity and policy are unchanged, no
        unresolved side effect exists, and ownership is either proven safe or
        its lease has expired.
        """
        need(type(limit) is int and 1 <= limit <= 200, 'INVALID_LIMIT')
        now = self.clock_ns() if now_ns is None else now_ns
        receipts = []
        with self.lock:
            # An expired lease on an owned nonterminal state means ownership
            # has lapsed: sweep it back into RECOVERING so the normal path —
            # never a restart — can reconcile it and an owner can reacquire.
            # BLOCKED is excluded: a blocked mission is already quiescent and
            # owner-gated, so re-sweeping it every tick would oscillate it
            # RECOVERING<->BLOCKED and defeat the circuit breaker. VERIFYING
            # is included because an abandoned verification would otherwise
            # pin the mission in a state no owner can reach.
            stale = self.db.execute(
                "SELECT * FROM missions WHERE state IN ('RUNNING','WAITING','VERIFYING') "
                "AND lease_expires_ns IS NOT NULL AND lease_expires_ns<=? "
                "ORDER BY updated_ns LIMIT ?", (now, limit)).fetchall()
            for srow in stale:
                try:
                    self.db.execute('BEGIN IMMEDIATE')
                    self._recovery_event_locked(
                        srow, state='RECOVERING', reason='lease_expired',
                        action='RECONCILE_LEASE', next_ns=None, attempts=0)
                    self.db.commit()
                    receipts.append({'mission_id': srow['mission_id'], 'state': 'RECOVERING',
                                     'reason': 'lease_expired', 'action': 'RECONCILE_LEASE'})
                except (Rejected, ControlError) as exc:
                    if self.db.in_transaction:
                        self.db.rollback()
                    receipts.append({'mission_id': srow['mission_id'], 'state': srow['state'],
                                     'reason': 'lease_sweep_error', 'error': getattr(exc, 'code', 'ERR')})
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM missions WHERE state='RECOVERING' AND "
                "(recovery_next_ns IS NULL OR recovery_next_ns<=?) "
                "ORDER BY updated_ns LIMIT ?", (now, limit)).fetchall()
        for original in rows:
            with self.lock:
                row = self.db.execute('SELECT * FROM missions WHERE mission_id=?',
                                      (original['mission_id'],)).fetchone()
                if row is None or row['state'] != 'RECOVERING':
                    continue
                if row['recovery_action'] == 'AWAIT_OWNER_RESUME':
                    # Quiescent: recoverability is established; only an
                    # external claimant may advance it (resume or takeover).
                    continue
                attempts = int(row['recovery_attempts'] or 0)
                try:
                    stage = 'probe_identity'
                    identity = self._probe_recovery(identity_probe, row)
                    stage = 'probe_policy'
                    policy = self._probe_recovery(policy_probe, row)
                    stage = 'probe_worker'
                    worker = self._probe_recovery(worker_probe, row)
                    stage = 'probe_transaction'
                    transaction = self._probe_recovery(transaction_probe, row)
                    stage = 'probe_move'
                    move = self._probe_recovery(move_probe, row)
                    stage = 'classify'
                    classification = identity.get('classification', identity.get('state', 'same'))
                    authority = policy.get('classification', policy.get('state', 'same'))
                    if classification not in ('same', 'unchanged', 'identical'):
                        self.db.execute('BEGIN IMMEDIATE')
                        self._recovery_event_locked(
                            row, state='BLOCKED', reason='workspace_divergence:' + str(classification),
                            action='OPERATOR_ACCEPT_DIVERGENCE', next_ns=None,
                            attempts=attempts, last_error='workspace identity is not unchanged')
                        self.db.commit()
                        receipts.append({'mission_id': row['mission_id'], 'state': 'BLOCKED',
                                         'reason': 'workspace_divergence:' + str(classification),
                                         'action': 'OPERATOR_ACCEPT_DIVERGENCE'})
                        continue
                    if authority not in ('same', 'unchanged', 'identical'):
                        self.db.execute('BEGIN IMMEDIATE')
                        self._recovery_event_locked(
                            row, state='BLOCKED', reason='authority_changed',
                            action='OPERATOR_REAUTHORIZE', next_ns=None,
                            attempts=attempts, last_error='policy binding or authority changed')
                        self.db.commit()
                        receipts.append({'mission_id': row['mission_id'], 'state': 'BLOCKED',
                                         'reason': 'authority_changed',
                                         'action': 'OPERATOR_REAUTHORIZE'})
                        continue
                    if transaction.get('unresolved') or transaction.get('state') in (
                            'UNRESOLVED', 'INDETERMINATE', 'UNKNOWN'):
                        self.db.execute('BEGIN IMMEDIATE')
                        self._recovery_event_locked(
                            row, state='BLOCKED', reason='transaction_unresolved',
                            action='TRANSACTION_RECONCILE', next_ns=None,
                            attempts=attempts, last_error='transaction outcome is unresolved')
                        self.db.commit()
                        receipts.append({'mission_id': row['mission_id'], 'state': 'BLOCKED',
                                         'reason': 'transaction_unresolved',
                                         'action': 'TRANSACTION_RECONCILE'})
                        continue
                    if move.get('unresolved') or move.get('state') in (
                            'UNRESOLVED', 'INDETERMINATE', 'UNKNOWN'):
                        self.db.execute('BEGIN IMMEDIATE')
                        self._recovery_event_locked(
                            row, state='BLOCKED', reason='move_unresolved',
                            action='MOVE_RECONCILE', next_ns=None,
                            attempts=attempts, last_error='project move outcome is unresolved')
                        self.db.commit()
                        receipts.append({'mission_id': row['mission_id'], 'state': 'BLOCKED',
                                         'reason': 'move_unresolved', 'action': 'MOVE_RECONCILE'})
                        continue
                    if worker.get('unresolved'):
                        self.db.execute('BEGIN IMMEDIATE')
                        self._recovery_event_locked(
                            row, state='BLOCKED', reason='worker_ownership_unresolved',
                            action='OWNERSHIP_RECONCILE', next_ns=None,
                            attempts=attempts, last_error='worker custody is unresolved')
                        self.db.commit()
                        receipts.append({'mission_id': row['mission_id'], 'state': 'BLOCKED',
                                         'reason': 'worker_ownership_unresolved',
                                         'action': 'OWNERSHIP_RECONCILE'})
                        continue
                    live = bool(worker.get('live') or worker.get('running'))
                    owned = bool(worker.get('owned', live))
                    if live and not owned:
                        self.db.execute('BEGIN IMMEDIATE')
                        self._recovery_event_locked(
                            row, state='BLOCKED', reason='foreign_worker_observed',
                            action='FENCE_AND_OPERATOR_REVIEW', next_ns=None,
                            attempts=attempts, last_error='worker exists outside this authority')
                        self.db.commit()
                        receipts.append({'mission_id': row['mission_id'], 'state': 'BLOCKED',
                                         'reason': 'foreign_worker_observed',
                                         'action': 'FENCE_AND_OPERATOR_REVIEW'})
                        continue
                    stage = 'reclaim'
                    lease_fresh = row['lease_expires_ns'] is not None and int(row['lease_expires_ns']) > now
                    if lease_fresh and not live:
                        next_ns = int(row['lease_expires_ns'])
                        self.db.execute('BEGIN IMMEDIATE')
                        self._recovery_event_locked(
                            row, state='RECOVERING', reason='fresh_lease',
                            action='WAIT_FRESH_LEASE', next_ns=next_ns,
                            attempts=attempts)
                        self.db.commit()
                        receipts.append({'mission_id': row['mission_id'], 'state': 'RECOVERING',
                                         'reason': 'fresh_lease', 'action': 'WAIT_FRESH_LEASE',
                                         'next_eligible_ns': next_ns})
                        continue
                    self.db.execute('BEGIN IMMEDIATE')
                    result = self._reclaim_locked(
                        row, reason='live_worker_reattach' if live else 'stale_owner_reclaimed',
                        ttl_s=ttl_s, now=now)
                    self.db.commit()
                    receipts.append(result)
                except Rejected as exc:
                    if self.db.in_transaction:
                        self.db.rollback()
                    attempts += 1
                    if exc.code == 'RESOURCE_CONFLICT':
                        reason, action, terminal = 'resource_conflict', 'FENCE_AND_OPERATOR_REVIEW', True
                    else:
                        reason, action, terminal = 'recovery_probe_error', 'RETRY_RECOVERY', False
                    with self.lock:
                        current = self.db.execute('SELECT * FROM missions WHERE mission_id=?',
                                                  (row['mission_id'],)).fetchone()
                        if current is None or current['state'] != 'RECOVERING':
                            continue
                        self.db.execute('BEGIN IMMEDIATE')
                        if attempts >= RECOVERY_MAX_ATTEMPTS or terminal:
                            self._recovery_event_locked(current, state='BLOCKED', reason=reason,
                                                        action=action, next_ns=None, attempts=attempts,
                                                        last_error=exc.code)
                            state = 'BLOCKED'
                            next_eligible = None
                        else:
                            next_eligible = now + self._recovery_delay(attempts) * 1_000_000_000
                            self._recovery_event_locked(current, state='RECOVERING', reason=reason,
                                                        action=action, next_ns=next_eligible,
                                                        attempts=attempts, last_error=exc.code)
                            state = 'RECOVERING'
                        self.db.commit()
                    receipts.append({'mission_id': row['mission_id'], 'state': state,
                                     'reason': reason, 'action': action,
                                     'next_eligible_ns': next_eligible, 'error': exc.code})
                except Exception as exc:
                    if self.db.in_transaction:
                        self.db.rollback()
                    attempts += 1
                    detail = stage + ':' + _bounded_error(exc)
                    with self.lock:
                        current = self.db.execute('SELECT * FROM missions WHERE mission_id=?',
                                                  (row['mission_id'],)).fetchone()
                        if current is None or current['state'] != 'RECOVERING':
                            continue
                        self.db.execute('BEGIN IMMEDIATE')
                        if attempts >= RECOVERY_MAX_ATTEMPTS:
                            self._recovery_event_locked(current, state='BLOCKED',
                                                        reason='recovery_circuit_open',
                                                        action='OPERATOR_REVIEW', next_ns=None,
                                                        attempts=attempts, last_error=detail)
                            state, next_eligible = 'BLOCKED', None
                        else:
                            next_eligible = now + self._recovery_delay(attempts) * 1_000_000_000
                            self._recovery_event_locked(current, state='RECOVERING',
                                                        reason='recovery_probe_exception',
                                                        action='RETRY_RECOVERY', next_ns=next_eligible,
                                                        attempts=attempts, last_error=detail)
                            state = 'RECOVERING'
                        self.db.commit()
                    receipts.append({'mission_id': row['mission_id'], 'state': state,
                                     'reason': 'recovery_circuit_open' if state == 'BLOCKED'
                                              else 'recovery_probe_exception',
                                     'action': 'OPERATOR_REVIEW' if state == 'BLOCKED'
                                              else 'RETRY_RECOVERY',
                                     'next_eligible_ns': next_eligible, 'error': detail})
        return receipts

    def list_missions(self, *, project: str | None = None, state: str | None = None, limit: int = 50) -> list[dict]:
        require_limit = lambda n: need(type(n) is int and 1 <= n <= 200, 'INVALID_LIMIT')  # noqa: E731
        require_limit(limit)
        if state is not None:
            need(state in STATES, 'INVALID_STATE')
        query = 'SELECT * FROM missions'
        clauses, args = [], []
        if project:
            clauses.append('project=?')
            args.append(project)
        if state:
            clauses.append('state=?')
            args.append(state)
        if clauses:
            query += ' WHERE ' + ' AND '.join(clauses)
        query += ' ORDER BY created_ns DESC LIMIT ?'
        args.append(limit)
        with self.lock:
            rows = self.db.execute(query, tuple(args)).fetchall()
        return [self._row(r, notes=False) for r in rows]

    def stats(self) -> dict:
        with self.lock:
            counts = {row['state']: row['n'] for row in
                      self.db.execute('SELECT state,count(*) AS n FROM missions GROUP BY state')}
            total = self.db.execute('SELECT count(*) AS n FROM missions').fetchone()['n']
            events = self.db.execute('SELECT count(*) AS n FROM mission_events').fetchone()['n']
            fences = {row['state']: row['n'] for row in
                      self.db.execute('SELECT state,count(*) AS n FROM mission_fences GROUP BY state')}
            recovery = self.db.execute(
                "SELECT count(*) AS n,COALESCE(max(recovery_attempts),0) AS max_attempts,"
                "COALESCE(min(recovery_next_ns),0) AS next_ns FROM missions WHERE state='RECOVERING'"
            ).fetchone()
            awaiting = self.db.execute(
                "SELECT count(*) AS n FROM missions WHERE state='RECOVERING' "
                "AND recovery_action='AWAIT_OWNER_RESUME'").fetchone()
        return {'missions': total, 'by_state': counts, 'events': events,
                'fences': fences,
                'recovery': {'pending': recovery['n'], 'max_attempts': recovery['max_attempts'],
                             'awaiting_owner': awaiting['n'],
                             'next_eligible_ns': recovery['next_ns'] or None},
                'chain': self.chain_status()}
