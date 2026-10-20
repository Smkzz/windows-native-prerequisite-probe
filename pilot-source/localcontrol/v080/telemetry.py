"""Durable, bounded, crash-safe operation telemetry.

Cumulative totals are always derived as ``rollups + live operations`` so there
is no separate counter that can silently diverge. Compaction aggregates the
oldest raw records into hourly per-project rollups in one transaction; the
invariant ``before == after`` is enforced by tests. Unknown values (for example
model token counts that were never supplied by an authoritative adapter) stay
``null`` and are never estimated.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from ..nextlib.core import Rejected, ident, integer, need, packed
from ..store import canonical

SCHEMA_VERSION = 1
MAX_OPERATIONS = 20000
COMPACT_BATCH = 2000
MAX_ROLLUPS = 87600
ROLLUP_MERGE = 1000
MAX_TEXT = 256
MAX_DETAILS_BYTES = 4096
VIEWS = frozenset({'summary', 'delta', 'operations'})
FAILURE_CLASSES = {
    'CONFLICT': 'state_conflict', 'NOT_FOUND': 'not_found', 'NOT_FILE': 'not_found',
    'PROJECT_REQUIRED': 'scope', 'UNKNOWN_PROJECT': 'scope', 'CATALOG_SCOPE_REQUIRED': 'scope',
    'READ_ONLY': 'authority', 'DENIED': 'authority', 'PROTECTED_PATH': 'security',
    'INVALID_PATH': 'security', 'LINK_FORBIDDEN': 'security', 'HARDLINK_FORBIDDEN': 'security',
    'OUTSIDE_ROOT': 'security', 'INVALID_CURSOR': 'integrity', 'STALE_CURSOR': 'integrity',
    'PLAN_DIGEST_MISMATCH': 'integrity', 'IDEMPOTENCY_CONFLICT': 'integrity',
    'MAINTENANCE_ACTIVE': 'lease', 'UNRESOLVED_MOVE': 'lease', 'LEASE_MISMATCH': 'lease',
    'UNKNOWN_PLAN': 'state', 'JOURNAL_CONFLICT': 'state', 'TRANSACTION_CLOSED': 'state',
    'ALREADY_APPLIED': 'state', 'DRIFT_DETECTED': 'state', 'INDETERMINATE': 'state',
    'PRECONDITION_REQUIRED': 'precondition', 'INVALID_ARGUMENT': 'invalid_input',
    'INVALID_OPERATIONS': 'invalid_input', 'INVALID_TEXT': 'invalid_input', 'FILE_LIMIT': 'limit',
    'RESPONSE_LIMIT': 'limit', 'TRANSACTION_TOO_LARGE': 'limit', 'TASK_CAPACITY': 'limit',
    'UNKNOWN_TASK': 'not_found', 'UNKNOWN_JOB': 'not_found', 'UNKNOWN_SCOPE': 'not_found',
    'INTERNAL_ERROR': 'internal',
}


def classify_failure(code: str | None) -> str | None:
    if not code:
        return None
    if code.startswith('TRANSACTION_'):
        return 'transaction'
    if code.startswith('RUN_'):
        return 'supervision'
    return FAILURE_CLASSES.get(code, 'other')


def _bounded_text(value, limit: int = MAX_TEXT):
    if value is None:
        return None
    text = str(value)
    need(len(text) <= 4096, 'TELEMETRY_FIELD')
    return text[:limit]


class TelemetryStore:
    def __init__(self, path: Path):
        self.lock = threading.RLock()
        self.path = path
        self.db = None
        self._since_compact = 0
        try:
            self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
            self.db.row_factory = sqlite3.Row
            # WAL + NORMAL: committed operations survive a process crash and a
            # host restart (SQLite replays the WAL); only an unclean power loss
            # can lose the very last commits, and it can never corrupt totals.
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=NORMAL')
            self.db.executescript('''
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS operations(
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              start_ns INTEGER NOT NULL, end_ns INTEGER NOT NULL, duration_ms REAL NOT NULL,
              project TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL, category TEXT NOT NULL,
              origin TEXT NOT NULL DEFAULT 'client', run_id TEXT, continuation_id TEXT, task TEXT,
              status TEXT NOT NULL, error_code TEXT, failure_class TEXT,
              request_bytes INTEGER NOT NULL, response_bytes INTEGER NOT NULL,
              details TEXT NOT NULL DEFAULT '{}');
            CREATE INDEX IF NOT EXISTS operations_run ON operations(run_id, seq);
            CREATE TABLE IF NOT EXISTS rollups(
              bucket_ns INTEGER NOT NULL, project TEXT NOT NULL, operations INTEGER NOT NULL,
              errors INTEGER NOT NULL, request_bytes INTEGER NOT NULL, response_bytes INTEGER NOT NULL,
              per_tool TEXT NOT NULL, PRIMARY KEY(bucket_ns, project));
            ''')
            need(self.db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'TELEMETRY_CORRUPT')
            with self._tx():
                row = self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
                need(row is None or row['value'] == str(SCHEMA_VERSION), 'TELEMETRY_SCHEMA')
                self.db.execute("INSERT OR IGNORE INTO meta VALUES('schema',?)", (str(SCHEMA_VERSION),))
                self.db.execute("INSERT OR IGNORE INTO meta VALUES('created_ns',?)", (str(time.time_ns()),))
        except (sqlite3.DatabaseError, OSError):
            if self.db is not None:
                try:
                    self.db.close()
                except Exception:
                    pass
            raise Rejected('TELEMETRY_CORRUPT') from None

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

    def integrity(self) -> bool:
        with self.lock:
            try:
                return self.db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
            except sqlite3.DatabaseError:
                return False

    def record(self, *, tool: str, category: str, start_ns: int, end_ns: int, project: str = '',
               origin: str = 'client', run_id: str | None = None, continuation_id: str | None = None,
               task: str | None = None, status: str = 'ok', error_code: str | None = None,
               request_bytes: int = 0, response_bytes: int = 0, details: dict | None = None) -> int:
        ident(tool)
        need(category in {'discovery', 'read', 'write', 'execution', 'task', 'maintenance', 'transaction',
                          'supervision', 'telemetry', 'bootstrap', 'mission', 'recovery', 'unknown'}, 'TELEMETRY_CATEGORY')
        need(status in {'ok', 'error', 'replayed'}, 'TELEMETRY_STATUS')
        need(origin in {'client', 'internal'}, 'TELEMETRY_ORIGIN')
        integer(start_ns, 0, 2**63 - 1)
        integer(end_ns, start_ns, 2**63 - 1)
        integer(request_bytes, 0, 2**31)
        integer(response_bytes, 0, 2**31)
        payload = json.dumps(details or {}, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        need(len(payload) <= MAX_DETAILS_BYTES, 'TELEMETRY_DETAILS')
        duration_ms = round((end_ns - start_ns) / 1_000_000, 3)
        with self.lock:
            with self._tx():
                cursor = self.db.execute(
                    'INSERT INTO operations(start_ns,end_ns,duration_ms,project,tool,category,origin,run_id,'
                    'continuation_id,task,status,error_code,failure_class,request_bytes,response_bytes,details) '
                    'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (start_ns, end_ns, duration_ms, _bounded_text(project) or '', tool, category, origin,
                     _bounded_text(run_id), _bounded_text(continuation_id), _bounded_text(task), status,
                     _bounded_text(error_code), classify_failure(error_code), request_bytes, response_bytes, payload))
                seq = cursor.lastrowid
                self._since_compact += 1
                if self._since_compact >= 256:
                    self._since_compact = 0
                    count = self.db.execute('SELECT count(*) FROM operations').fetchone()[0]
                    if count > MAX_OPERATIONS:
                        self._compact_locked()
            return int(seq)

    def _bucket(self, ts_ns: int) -> int:
        return (ts_ns // 3_600_000_000_000) * 3_600_000_000_000

    def _compact_locked(self) -> dict:
        """Deterministic: aggregate the oldest COMPACT_BATCH raw records."""
        rows = self.db.execute('SELECT * FROM operations ORDER BY seq LIMIT ?', (COMPACT_BATCH,)).fetchall()
        if not rows:
            return {'operations': 0}
        groups = {}
        for row in rows:
            key = (self._bucket(row['start_ns']), row['project'])
            group = groups.setdefault(key, {'operations': 0, 'errors': 0, 'request_bytes': 0,
                                            'response_bytes': 0, 'per_tool': {}})
            group['operations'] += 1
            if row['status'] != 'ok':
                group['errors'] += 1
            group['request_bytes'] += row['request_bytes']
            group['response_bytes'] += row['response_bytes']
            tool = group['per_tool'].setdefault(row['tool'], {'operations': 0, 'errors': 0,
                                                              'request_bytes': 0, 'response_bytes': 0})
            tool['operations'] += 1
            if row['status'] != 'ok':
                tool['errors'] += 1
            tool['request_bytes'] += row['request_bytes']
            tool['response_bytes'] += row['response_bytes']
        for (bucket, project), group in groups.items():
            existing = self.db.execute('SELECT * FROM rollups WHERE bucket_ns=? AND project=?',
                                       (bucket, project)).fetchone()
            if existing is None:
                self.db.execute('INSERT INTO rollups VALUES(?,?,?,?,?,?,?)',
                                (bucket, project, group['operations'], group['errors'],
                                 group['request_bytes'], group['response_bytes'],
                                 canonical(group['per_tool'])))
            else:
                merged = json.loads(existing['per_tool'])
                for tool, counters in group['per_tool'].items():
                    current = merged.setdefault(tool, {'operations': 0, 'errors': 0, 'request_bytes': 0,
                                                       'response_bytes': 0})
                    for field in ('operations', 'errors', 'request_bytes', 'response_bytes'):
                        current[field] += counters[field]
                self.db.execute('UPDATE rollups SET operations=operations+?, errors=errors+?, '
                                'request_bytes=request_bytes+?, response_bytes=response_bytes+?, per_tool=? '
                                'WHERE bucket_ns=? AND project=?',
                                (group['operations'], group['errors'], group['request_bytes'],
                                 group['response_bytes'], canonical(merged), bucket, project))
        last_seq = rows[-1]['seq']
        self.db.execute('DELETE FROM operations WHERE seq<=?', (last_seq,))
        count = self.db.execute('SELECT count(*) FROM rollups').fetchone()[0]
        if count > MAX_ROLLUPS:
            oldest = self.db.execute('SELECT * FROM rollups ORDER BY bucket_ns LIMIT ?', (ROLLUP_MERGE,)).fetchall()
            target = oldest[0]
            totals = {'operations': 0, 'errors': 0, 'request_bytes': 0, 'response_bytes': 0, 'per_tool': {}}
            for row in oldest:
                totals['operations'] += row['operations']
                totals['errors'] += row['errors']
                totals['request_bytes'] += row['request_bytes']
                totals['response_bytes'] += row['response_bytes']
                for tool, counters in json.loads(row['per_tool']).items():
                    current = totals['per_tool'].setdefault(tool, {'operations': 0, 'errors': 0,
                                                                   'request_bytes': 0, 'response_bytes': 0})
                    for field in ('operations', 'errors', 'request_bytes', 'response_bytes'):
                        current[field] += counters[field]
            self.db.execute('DELETE FROM rollups WHERE bucket_ns<=?', (target['bucket_ns'],))
            self.db.execute('INSERT INTO rollups VALUES(?,?,?,?,?,?,?)',
                            (target['bucket_ns'], '', totals['operations'], totals['errors'],
                             totals['request_bytes'], totals['response_bytes'], canonical(totals['per_tool'])))
        return {'operations': len(rows), 'rollup_groups': len(groups)}

    def compact(self) -> dict:
        with self.lock:
            with self._tx():
                count = self.db.execute('SELECT count(*) FROM operations').fetchone()[0]
                during = self.db.execute('SELECT count(*) FROM operations').fetchone()[0]
            while count > MAX_OPERATIONS:
                with self._tx():
                    result = self._compact_locked()
                    became = self.db.execute('SELECT count(*) FROM operations').fetchone()[0]
                count = became
                if result['operations'] == 0:
                    break
        return {'remaining': count}

    def latest_sequence(self) -> int:
        with self.lock:
            row = self.db.execute('SELECT coalesce(max(seq),0) FROM operations').fetchone()
            return int(row[0])

    def _filters(self, project, run_id, tool, since_ns):
        clauses, args = [], []
        if project:
            clauses.append('project=?')
            args.append(project)
        if run_id:
            clauses.append('run_id=?')
            args.append(run_id)
        if tool:
            clauses.append('tool=?')
            args.append(tool)
        if since_ns:
            clauses.append('start_ns>=?')
            args.append(since_ns)
        return (' AND '.join(clauses), args)

    def summary(self, *, project: str | None = None, run_id: str | None = None, tool: str | None = None,
                since_ns: int | None = None, max_response_bytes: int = 65536) -> dict:
        integer(max_response_bytes, 2048, 131072)
        where, args = self._filters(project, run_id, tool, since_ns)
        clause = (' WHERE ' + where) if where else ''
        with self.lock:
            live = self.db.execute(
                f'SELECT count(*) AS operations, sum(status!=\'ok\') AS errors, coalesce(sum(request_bytes),0) AS '
                f'request_bytes, coalesce(sum(response_bytes),0) AS response_bytes, min(start_ns) AS first_ns, '
                f'max(end_ns) AS last_ns FROM operations{clause}', args).fetchone()
            per_tool = {}
            for row in self.db.execute(f'SELECT tool, count(*) AS operations, sum(status!=\'ok\') AS errors, '
                                       f'coalesce(sum(request_bytes),0) AS request_bytes, '
                                       f'coalesce(sum(response_bytes),0) AS response_bytes FROM operations{clause} '
                                       f'GROUP BY tool', args):
                per_tool[row['tool']] = {'operations': row['operations'], 'errors': row['errors'] or 0,
                                         'request_bytes': row['request_bytes'], 'response_bytes': row['response_bytes']}
            rolled = ({'operations': 0, 'errors': 0, 'request_bytes': 0, 'response_bytes': 0, 'per_tool': {}}
                      if run_id else self._rollup_totals(project, tool, since_ns))
        totals = self._merge_totals(live, per_tool, rolled)
        answer = {'view': 'summary', 'scope': {'project': project or None, 'run_id': run_id or None,
                                               'tool': tool or None, 'since_ns': since_ns},
                  'totals': {'operations': totals['operations'], 'errors': totals['errors'],
                             'request_bytes': totals['request_bytes'], 'response_bytes': totals['response_bytes'],
                             'first_ns': live['first_ns'], 'last_ns': live['last_ns']},
                  'per_tool': self._top_tools(totals['per_tool']),
                  'rollups': {'applied': not run_id, 'note': 'run-scoped summaries use retained raw operations only'},
                  'latest_sequence': self.latest_sequence(), 'integrity': self.integrity(),
                  'schema_version': SCHEMA_VERSION, 'retention': {'max_raw_operations': MAX_OPERATIONS},
                  'model_tokens': None,
                  'model_telemetry': 'authoritative adapter events only; see usage_summary; never estimated'}
        need(len(packed(answer)) <= max_response_bytes, 'RESPONSE_LIMIT')
        return answer

    def _rollup_totals(self, project, tool, since_ns):
        clauses, args = [], []
        if project:
            clauses.append('project=?')
            args.append(project)
        if since_ns:
            clauses.append('bucket_ns>=?')
            args.append(self._bucket(since_ns))
        clause = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        totals = {'operations': 0, 'errors': 0, 'request_bytes': 0, 'response_bytes': 0, 'per_tool': {}}
        for row in self.db.execute(f'SELECT * FROM rollups{clause}', args):
            totals['operations'] += row['operations']
            totals['errors'] += row['errors']
            totals['request_bytes'] += row['request_bytes']
            totals['response_bytes'] += row['response_bytes']
            for name, counters in json.loads(row['per_tool']).items():
                if tool and name != tool:
                    continue
                current = totals['per_tool'].setdefault(name, {'operations': 0, 'errors': 0,
                                                               'request_bytes': 0, 'response_bytes': 0})
                for field in ('operations', 'errors', 'request_bytes', 'response_bytes'):
                    current[field] += counters[field]
        return totals

    @staticmethod
    def _merge_totals(live, per_tool, rolled):
        merged = {'operations': 0, 'errors': 0, 'request_bytes': 0, 'response_bytes': 0, 'per_tool': {}}
        live_errors = live['errors'] or 0
        merged['operations'] += live['operations'] or 0
        merged['errors'] += live_errors
        merged['request_bytes'] += live['request_bytes']
        merged['response_bytes'] += live['response_bytes']
        for name, counters in per_tool.items():
            merged['per_tool'][name] = dict(counters)
        merged['operations'] += rolled['operations']
        merged['errors'] += rolled['errors']
        merged['request_bytes'] += rolled['request_bytes']
        merged['response_bytes'] += rolled['response_bytes']
        for name, counters in rolled['per_tool'].items():
            current = merged['per_tool'].setdefault(name, {'operations': 0, 'errors': 0,
                                                           'request_bytes': 0, 'response_bytes': 0})
            for field in ('operations', 'errors', 'request_bytes', 'response_bytes'):
                current[field] += counters[field]
        return merged

    @staticmethod
    def _top_tools(per_tool, limit: int = 16):
        ordered = sorted(per_tool.items(), key=lambda item: (-item[1]['operations'], item[0]))
        return {name: counters for name, counters in ordered[:limit]}

    def operations(self, *, project: str | None = None, run_id: str | None = None, tool: str | None = None,
                   since_sequence: int = 0, limit: int = 200, max_response_bytes: int = 65536) -> dict:
        integer(since_sequence, 0, 2**63 - 1)
        integer(limit, 1, 500)
        integer(max_response_bytes, 2048, 131072)
        where, args = self._filters(project, run_id, tool, None)
        clauses = [where] if where else []
        clauses.append('seq>?')
        args.append(since_sequence)
        with self.lock:
            rows = self.db.execute(
                f'SELECT * FROM operations WHERE {" AND ".join(clauses)} ORDER BY seq LIMIT ?',
                (*args, limit + 1)).fetchall()
            items = []
            for row in rows[:limit]:
                items.append({'seq': row['seq'], 'start_ns': row['start_ns'], 'end_ns': row['end_ns'],
                              'duration_ms': row['duration_ms'], 'project': row['project'] or None,
                              'tool': row['tool'], 'category': row['category'], 'origin': row['origin'],
                              'run_id': row['run_id'], 'continuation_id': row['continuation_id'],
                              'task': row['task'], 'status': row['status'], 'error_code': row['error_code'],
                              'failure_class': row['failure_class'], 'request_bytes': row['request_bytes'],
                              'response_bytes': row['response_bytes'], 'details': json.loads(row['details'])})
        answer = {'view': 'operations', 'items': items,
                  'next_sequence': items[-1]['seq'] if len(rows) > limit and items else None,
                  'truncated': len(rows) > limit, 'latest_sequence': self.latest_sequence(),
                  'integrity': self.integrity()}
        need(len(packed(answer)) <= max_response_bytes, 'RESPONSE_LIMIT')
        return answer

    def delta(self, *, after_sequence: int, project: str | None = None, max_response_bytes: int = 65536) -> dict:
        integer(after_sequence, 0, 2**63 - 1)
        integer(max_response_bytes, 2048, 131072)
        with self.lock:
            rows = self.db.execute('SELECT tool, status, request_bytes, response_bytes FROM operations '
                                   'WHERE seq>? AND (?=\'\' OR project=?) ORDER BY seq',
                                   (after_sequence, project or '', project or '')).fetchall()
            latest = self.latest_sequence()
        per_tool = {}
        errors = 0
        request_bytes = response_bytes = 0
        for row in rows:
            request_bytes += row['request_bytes']
            response_bytes += row['response_bytes']
            if row['status'] != 'ok':
                errors += 1
            current = per_tool.setdefault(row['tool'], {'operations': 0, 'errors': 0, 'request_bytes': 0,
                                                        'response_bytes': 0})
            current['operations'] += 1
            if row['status'] != 'ok':
                current['errors'] += 1
            current['request_bytes'] += row['request_bytes']
            current['response_bytes'] += row['response_bytes']
        answer = {'view': 'delta', 'after_sequence': after_sequence, 'next_sequence': latest,
                  'operations': len(rows), 'errors': errors, 'request_bytes': request_bytes,
                  'response_bytes': response_bytes, 'per_tool': self._top_tools(per_tool),
                  'latest_sequence': latest, 'integrity': self.integrity()}
        need(len(packed(answer)) <= max_response_bytes, 'RESPONSE_LIMIT')
        return answer

    def close(self):
        with self.lock:
            if self.db is not None:
                self.db.close()
                self.db = None

