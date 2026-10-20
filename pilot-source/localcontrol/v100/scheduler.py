"""Durable scheduler for queued, delayed, dependency-bound and retried missions.

Purpose-built for LocalControl: schedules bind the exact mission snapshot taken
at creation time (policy binding, workspace identity, contract, budgets). The
tick is a single bounded SQLite scan and never busy-polls.
"""
from __future__ import annotations

import json
import time
import uuid

from ..nextlib.core import Rejected, digest, ident, need, packed
from .missions import MissionStore, normalize_dedupe_key, normalize_resource_keys

SCHEDULE_STATES = frozenset({'ACTIVE', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED', 'EXPIRED'})
TERMINAL_SCHEDULE = frozenset({'COMPLETED', 'FAILED', 'CANCELLED', 'EXPIRED'})
SCHEDULE_TERMINAL_MISSION = frozenset({'SUCCEEDED', 'FAILED', 'CANCELLED', 'ABANDONED'})
MAX_SNAPSHOT_BYTES = 32768
DISPATCH_CLAIM_TIMEOUT_NS = 60 * 1_000_000_000


def _bounded(value, limit, code):
    try:
        encoded = packed(value)
    except (TypeError, ValueError):
        raise Rejected(code) from None
    need(len(encoded) <= limit, code)
    return value


class DurableScheduler:
    def __init__(self, store: MissionStore, now_ns=time.time_ns):
        self.store = store
        self.now_ns = now_ns
        with store.lock:
            store.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS schedules(
                    schedule_id TEXT PRIMARY KEY,
                    project TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    contract_json TEXT NOT NULL,
                    budgets_json TEXT NOT NULL,
                    ttl_s INTEGER NOT NULL,
                    watch_paths_json TEXT NOT NULL DEFAULT '[]',
                    state TEXT NOT NULL,
                    run_at_ns INTEGER NOT NULL,
                    recur_s INTEGER,
                    skipped_runs INTEGER NOT NULL DEFAULT 0,
                    depends_on TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    backoff_base_s INTEGER NOT NULL DEFAULT 30,
                    backoff_max_s INTEGER NOT NULL DEFAULT 900,
                    deadline_ns INTEGER,
                    grace_s INTEGER NOT NULL DEFAULT 300,
                    mission_id TEXT,
                    last_error TEXT,
                    created_ns INTEGER NOT NULL,
                    updated_ns INTEGER NOT NULL,
                    request_id TEXT,
                    dispatch_id TEXT,
                    dispatch_claim_ns INTEGER,
                    dispatch_generation INTEGER NOT NULL DEFAULT 0,
                    resource_keys_json TEXT NOT NULL DEFAULT '[]',
                    dedupe_key TEXT,
                    supersedes_mission_id TEXT
                );
                """
            )
            columns = {row[1] for row in store.db.execute('PRAGMA table_info(schedules)')}
            additive = {
                'dispatch_id': 'TEXT',
                'dispatch_claim_ns': 'INTEGER',
                'dispatch_generation': 'INTEGER NOT NULL DEFAULT 0',
                'resource_keys_json': "TEXT NOT NULL DEFAULT '[]'",
                'dedupe_key': 'TEXT',
                'supersedes_mission_id': 'TEXT',
            }
            for name, declaration in additive.items():
                if name not in columns:
                    store.db.execute(f'ALTER TABLE schedules ADD COLUMN "{name}" {declaration}')
            store.db.execute('CREATE INDEX IF NOT EXISTS schedules_dispatch ON schedules(dispatch_id)')
            store.db.commit()

    def create(self, *, project: str, objective: str, snapshot: dict, contract: dict, budgets: dict,
               ttl_s: int, watch_paths: list, run_at_ns: int | None, delay_s: int | None,
               recur_s: int | None, depends_on: str | None, max_attempts: int, backoff_base_s: int,
               backoff_max_s: int, deadline_ns: int | None, grace_s: int, request_id: str,
               state: str = 'ACTIVE', resource_keys: list[str] | None = None,
               dedupe_key: str | None = None, supersedes_mission_id: str | None = None) -> dict:
        ident(project)
        need(isinstance(objective, str) and 0 < len(objective) <= 2048, 'INVALID_OBJECTIVE')
        need(state in ('ACTIVE', 'PAUSED'), 'INVALID_STATE')
        need(isinstance(ttl_s, int) and 30 <= ttl_s <= 86400, 'INVALID_TTL')
        need(recur_s is None or (type(recur_s) is int and 30 <= recur_s <= 30 * 86400), 'INVALID_RECURRENCE')
        need(type(max_attempts) is int and 1 <= max_attempts <= 20, 'INVALID_ATTEMPTS')
        need(type(backoff_base_s) is int and 1 <= backoff_base_s <= 86400, 'INVALID_BACKOFF')
        need(type(backoff_max_s) is int and backoff_base_s <= backoff_max_s <= 7 * 86400, 'INVALID_BACKOFF')
        need(type(grace_s) is int and 0 <= grace_s <= 86400, 'INVALID_GRACE')
        need(isinstance(watch_paths, list) and len(watch_paths) <= 32, 'INVALID_WATCH_PATHS')
        resource_keys = normalize_resource_keys(resource_keys)
        dedupe_key = normalize_dedupe_key(dedupe_key)
        if supersedes_mission_id is not None:
            ident(supersedes_mission_id)
        if deadline_ns is not None:
            need(type(deadline_ns) is int and deadline_ns > 0, 'INVALID_DEADLINE')
        if depends_on is not None:
            ident(depends_on)
            with self.store.lock:
                found = self.store.db.execute('SELECT 1 FROM schedules WHERE schedule_id=?', (depends_on,)).fetchone()
            need(found is not None, 'UNKNOWN_DEPENDENCY')
        snapshot = _bounded(snapshot, MAX_SNAPSHOT_BYTES, 'SCHEDULE_SNAPSHOT_TOO_LARGE')
        input_sha = digest({'project': project, 'objective': objective, 'snapshot': snapshot, 'contract': contract,
                            'budgets': budgets, 'run_at_ns': run_at_ns, 'delay_s': delay_s, 'recur_s': recur_s,
                            'depends_on': depends_on, 'resource_keys': resource_keys,
                            'dedupe_key': dedupe_key, 'supersedes_mission_id': supersedes_mission_id})
        scope = 'schedule-create:' + project
        replayed = self.store.request_replay(scope, request_id, 'mission_schedule', input_sha)
        if replayed is not None:
            return {**replayed, 'replayed': True}
        now = self.now_ns()
        if run_at_ns is None:
            base = now + max(0, delay_s or 0) * 1_000_000_000
        else:
            need(type(run_at_ns) is int and run_at_ns > 0, 'INVALID_SCHEDULE_TIME')
            base = run_at_ns
        schedule_id = 'schedule-' + uuid.uuid4().hex[:16]
        with self.store.lock:
            self.store.db.execute(
                'INSERT INTO schedules(schedule_id,project,objective,snapshot_json,contract_json,budgets_json,ttl_s,'
                'watch_paths_json,state,run_at_ns,recur_s,depends_on,max_attempts,backoff_base_s,backoff_max_s,'
                'deadline_ns,grace_s,created_ns,updated_ns,request_id,resource_keys_json,dedupe_key,'
                'supersedes_mission_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (schedule_id, project, objective, json.dumps(snapshot), json.dumps(contract), json.dumps(budgets),
                 ttl_s, json.dumps(watch_paths), state, base, recur_s, depends_on, max_attempts, backoff_base_s,
                 backoff_max_s, deadline_ns, grace_s, now, now, request_id, json.dumps(resource_keys),
                 dedupe_key, supersedes_mission_id))
            self.store.db.commit()
        response = {'schedule_id': schedule_id, 'state': state, 'run_at_ns': base, 'recur_s': recur_s,
                    'depends_on': depends_on, 'max_attempts': max_attempts,
                    'resource_keys': resource_keys, 'dedupe_key': dedupe_key,
                    'supersedes_mission_id': supersedes_mission_id}
        with self.store.lock:
            self.store._record_request(scope, request_id, 'mission_schedule', None,
                                       input_sha, response)
            self.store.db.commit()
        return response

    @staticmethod
    def _row(row) -> dict:
        return {'schedule_id': row['schedule_id'], 'project': row['project'], 'objective': row['objective'],
                'state': row['state'], 'run_at_ns': row['run_at_ns'], 'recur_s': row['recur_s'],
                'skipped_runs': row['skipped_runs'], 'depends_on': row['depends_on'],
                'attempts': row['attempts'], 'max_attempts': row['max_attempts'],
                'mission_id': row['mission_id'], 'last_error': row['last_error'],
                'deadline_ns': row['deadline_ns'], 'created_ns': row['created_ns'], 'updated_ns': row['updated_ns'],
                'dispatch_id': row['dispatch_id'], 'dispatch_claim_ns': row['dispatch_claim_ns'],
                'dispatch_generation': row['dispatch_generation'],
                'resource_keys': json.loads(row['resource_keys_json'] or '[]'),
                'dedupe_key': row['dedupe_key'], 'supersedes_mission_id': row['supersedes_mission_id']}

    def get(self, schedule_id: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute('SELECT * FROM schedules WHERE schedule_id=?', (schedule_id,)).fetchone()
        need(row is not None, 'SCHEDULE_NOT_FOUND')
        return self._row(row)

    def list(self, *, project: str | None = None, state: str | None = None, limit: int = 50) -> list[dict]:
        need(type(limit) is int and 1 <= limit <= 200, 'INVALID_LIMIT')
        if state is not None:
            need(state in SCHEDULE_STATES, 'INVALID_STATE')
        query, args, clauses = 'SELECT * FROM schedules', [], []
        if project:
            clauses.append('project=?')
            args.append(project)
        if state:
            clauses.append('state=?')
            args.append(state)
        if clauses:
            query += ' WHERE ' + ' AND '.join(clauses)
        query += ' ORDER BY run_at_ns ASC LIMIT ?'
        args.append(limit)
        with self.store.lock:
            rows = self.store.db.execute(query, tuple(args)).fetchall()
        return [self._row(r) for r in rows]

    def cancel(self, schedule_id: str, *, reason: str) -> dict:
        need(isinstance(reason, str) and 0 < len(reason) <= 512, 'INVALID_REASON')
        with self.store.lock:
            row = self.store.db.execute('SELECT state FROM schedules WHERE schedule_id=?', (schedule_id,)).fetchone()
            need(row is not None, 'SCHEDULE_NOT_FOUND')
            need(row['state'] not in TERMINAL_SCHEDULE, 'ALREADY_TERMINAL')
            self.store.db.execute('UPDATE schedules SET state=?,last_error=?,updated_ns=? WHERE schedule_id=?',
                                  ('CANCELLED', reason, self.now_ns(), schedule_id))
            self.store.db.commit()
        return self.get(schedule_id)

    def tick(self) -> dict:
        now = self.now_ns()
        actions = []
        for _ in range(16):
            row = self._claim_due(now)
            if row is None:
                break
            action = self._advance(row, now)
            if action is None:
                break
            actions.append(action)
        return {'ticked_ns': now, 'actions': actions}

    def _claim_due(self, now: int):
        with self.store.lock:
            self.store.db.execute('BEGIN IMMEDIATE')
            row = self.store.db.execute(
                'SELECT * FROM schedules WHERE state=? AND run_at_ns<=? AND '
                '(dispatch_id IS NULL OR dispatch_claim_ns IS NULL OR dispatch_claim_ns<=?) '
                'ORDER BY run_at_ns LIMIT 1',
                ('ACTIVE', now, now - DISPATCH_CLAIM_TIMEOUT_NS)).fetchone()
            if row is None:
                self.store.db.rollback()
                return None
            if row['mission_id']:
                mission = self.store.db.execute(
                    'SELECT state FROM missions WHERE mission_id=?', (row['mission_id'],)).fetchone()
                if mission is not None and mission['state'] not in SCHEDULE_TERMINAL_MISSION:
                    self.store.db.rollback()
                    return row
            attempt = int(row['attempts']) + 1
            if row['dispatch_id']:
                # A prior process may have committed the claim but died before
                # creating the mission. Preserve that exact dispatch identity so
                # replay relinks instead of creating a second execution.
                dispatch_id = row['dispatch_id']
                dispatch_generation = max(int(row['dispatch_generation'] or 0), attempt, 1)
            else:
                # attempts resets for a successful recurring run and therefore
                # cannot be the durable identity. Count prior missions as a
                # compatibility fallback for pre-generation v1.0.2 state.
                history = self.store.db.execute(
                    'SELECT count(*) AS n FROM missions WHERE schedule_id=?',
                    (row['schedule_id'],)).fetchone()['n']
                dispatch_generation = max(int(row['dispatch_generation'] or 0) + 1,
                                          int(history) + 1)
                dispatch_id = f"dispatch-{row['schedule_id']}-{dispatch_generation}"
            self.store.db.execute(
                'UPDATE schedules SET dispatch_id=?,dispatch_claim_ns=?,dispatch_generation=?,updated_ns=? '
                'WHERE schedule_id=? AND state=? AND run_at_ns<=?',
                (dispatch_id, now, dispatch_generation, now, row['schedule_id'], 'ACTIVE', now))
            need(self.store.db.execute('SELECT changes() AS n').fetchone()['n'] == 1,
                 'SCHEDULE_CLAIM_RACE')
            claimed = self.store.db.execute('SELECT * FROM schedules WHERE schedule_id=?',
                                             (row['schedule_id'],)).fetchone()
            self.store.db.commit()
            return claimed

    def _clear_claim(self, schedule_id: str, now: int) -> None:
        with self.store.lock:
            self.store.db.execute(
                'UPDATE schedules SET dispatch_id=NULL,dispatch_claim_ns=NULL,updated_ns=? '
                'WHERE schedule_id=?', (now, schedule_id))
            self.store.db.commit()

    def _advance(self, row, now: int) -> dict | None:
        schedule_id, mission_id = row['schedule_id'], row['mission_id']
        if row['deadline_ns'] is not None and now > int(row['deadline_ns']) + int(row['grace_s']) * 1_000_000_000:
            return self._terminal(schedule_id, 'EXPIRED', 'deadline exceeded', 'expired')
        if row['mission_id']:
            mission = self.store.get(mission_id, notes=False)
            if mission['state'] not in SCHEDULE_TERMINAL_MISSION:
                self._clear_claim(schedule_id, now)
                return None
            if mission['state'] == 'SUCCEEDED':
                if row['recur_s']:
                    next_at = int(row['run_at_ns']) + int(row['recur_s']) * 1_000_000_000
                    skipped = 0
                    while next_at <= now:
                        next_at += int(row['recur_s']) * 1_000_000_000
                        skipped += 1
                    with self.store.lock:
                        self.store.db.execute('UPDATE schedules SET run_at_ns=?,mission_id=NULL,attempts=0,'
                                              'skipped_runs=skipped_runs+?,dispatch_id=NULL,'
                                              'dispatch_claim_ns=NULL,'
                                              'dispatch_generation=MAX(dispatch_generation-1,0),updated_ns=? WHERE schedule_id=?',
                                              (next_at, skipped, now, schedule_id))
                        self.store.db.commit()
                    return {'schedule': schedule_id, 'action': 'rescheduled', 'run_at_ns': next_at}
                return self._terminal(schedule_id, 'COMPLETED', None, 'completed')
            if row['depends_on']:
                return self._terminal(schedule_id, 'FAILED', 'dependency mission failed', 'dependency_failed')
            if int(row['attempts']) >= int(row['max_attempts']):
                return self._terminal(schedule_id, 'FAILED', 'attempts exhausted', 'attempts_exhausted')
            return self._retry(schedule_id, row, now)
        if row['depends_on']:
            with self.store.lock:
                dep = self.store.db.execute('SELECT mission_id FROM schedules WHERE schedule_id=?',
                                            (row['depends_on'],)).fetchone()
            dep_mission = dep['mission_id'] if dep else None
            if not dep_mission:
                return None
            current = self.store.get(dep_mission, notes=False)
            if current['state'] in ('FAILED', 'CANCELLED', 'ABANDONED'):
                return self._terminal(schedule_id, 'FAILED', 'dependency failed', 'dependency_failed')
            if current['state'] != 'SUCCEEDED':
                return None
        snapshot = json.loads(row['snapshot_json'])
        contract = json.loads(row['contract_json'])
        budgets = json.loads(row['budgets_json'])
        attempt = int(row['attempts']) + 1
        dispatch_id = row['dispatch_id'] or f"dispatch-{schedule_id}-{attempt}"
        dispatch_generation = int(row['dispatch_generation'] or attempt or 1)
        mission_seed = {'schedule_id': schedule_id, 'attempt': attempt}
        if dispatch_generation > 1:
            mission_seed['dispatch_generation'] = dispatch_generation
        mission_id_new = 'mission-' + digest(mission_seed)[:16]
        with self.store.lock:
            existing = self.store.db.execute(
                'SELECT * FROM missions WHERE dispatch_id=?', (dispatch_id,)).fetchone()
        if existing is not None:
            started = {'mission_id': existing['mission_id']}
        else:
            try:
                mission_dedupe = row['dedupe_key']
                if mission_dedupe:
                    mission_dedupe = f'{mission_dedupe}:dispatch:{dispatch_generation}'
                started = self.store.begin(
                    project=row['project'], objective=row['objective'], workspace_root=snapshot['workspace_root'],
                    workspace_identity=snapshot['workspace_identity'], policy_binding=snapshot['binding'],
                    policy_snapshot=snapshot, success_contract=contract, budgets=budgets,
                    ttl_s=int(row['ttl_s']), request_id=f"sched-{schedule_id}-{dispatch_generation}",
                    mission_id=mission_id_new, schedule_id=schedule_id, state='RUNNING', trust_origin='policy',
                    resource_keys=json.loads(row['resource_keys_json'] or '[]'),
                    dedupe_key=mission_dedupe,
                    supersedes_mission_id=row['supersedes_mission_id'],
                    takeover=True,
                    dispatch_id=dispatch_id)
            except Rejected as exc:
                if exc.code == 'RESOURCE_CONFLICT':
                    return self._defer(schedule_id, row, now, exc.code)
                # MISSION_TOKEN_INVALID on a superseding dispatch means the
                # predecessor still holds a live lease — takeover is lease-
                # gated now, so defer until it lapses instead of failing.
                if exc.code == 'MISSION_TOKEN_INVALID' and row['supersedes_mission_id']:
                    return self._defer(schedule_id, row, now, exc.code)
                return self._terminal(schedule_id, 'FAILED', exc.code, 'dispatch_rejected')
        with self.store.lock:
            self.store.db.execute(
                'UPDATE schedules SET mission_id=?,attempts=attempts+1,dispatch_id=NULL,'
                'dispatch_claim_ns=NULL,updated_ns=? WHERE schedule_id=? AND dispatch_id=?',
                (started['mission_id'], now, schedule_id, dispatch_id))
            need(self.store.db.execute('SELECT changes() AS n').fetchone()['n'] == 1,
                 'SCHEDULE_CLAIM_LOST')
            self.store.db.commit()
        return {'schedule': schedule_id, 'action': 'dispatched', 'mission_id': started['mission_id'],
                'attempt': attempt, 'dispatch_generation': dispatch_generation, 'dispatch_id': dispatch_id}

    def _retry(self, schedule_id: str, row, now: int) -> dict:
        delay = min(int(row['backoff_base_s']) * (2 ** int(row['attempts'])), int(row['backoff_max_s']))
        next_at = now + delay * 1_000_000_000
        with self.store.lock:
            self.store.db.execute('UPDATE schedules SET mission_id=NULL,run_at_ns=?,updated_ns=?,last_error=?,'
                                  'dispatch_id=NULL,dispatch_claim_ns=NULL WHERE schedule_id=?',
                                  (next_at, now, 'retry scheduled', schedule_id))
            self.store.db.commit()
        return {'schedule': schedule_id, 'action': 'retry_scheduled', 'run_at_ns': next_at, 'delay_s': delay}

    def _terminal(self, schedule_id: str, state: str, error: str | None, action: str) -> dict:
        with self.store.lock:
            self.store.db.execute('UPDATE schedules SET state=?,last_error=?,updated_ns=?,'
                                  'dispatch_id=NULL,dispatch_claim_ns=NULL WHERE schedule_id=?',
                                  (state, error, self.now_ns(), schedule_id))
            self.store.db.commit()
        return {'schedule': schedule_id, 'action': action, 'state': state}

    def _defer(self, schedule_id: str, row, now: int, error: str) -> dict:
        delay = min(int(row['backoff_base_s']), int(row['backoff_max_s']))
        next_at = now + max(1, delay) * 1_000_000_000
        with self.store.lock:
            self.store.db.execute(
                'UPDATE schedules SET run_at_ns=?,last_error=?,updated_ns=?,dispatch_id=NULL,'
                'dispatch_claim_ns=NULL WHERE schedule_id=?',
                (next_at, f'dispatch deferred: {error}', now, schedule_id))
            self.store.db.commit()
        return {'schedule': schedule_id, 'action': 'dispatch_deferred',
                'reason': error, 'run_at_ns': next_at}
