"""Bounded multi-file transactions with durable journal and compensation.

There is no filesystem-wide atomic commit. Every operation is preflighted with
exact SHA-256 guards, applied sequentially through the existing broker, and
recorded in a durable journal. On failure the engine observes which operations
actually landed and reverses exactly those using stored pre-images. Partial
application is never reported as success: a transaction ends in APPLIED,
ROLLED_BACK or INDETERMINATE, and INDETERMINATE is resolved through
transaction_reconcile from the durable journal plus observed file state.

Authority remains the operator policy: paths go through Policy.path, mutations
go through the broker callbacks (never direct writes), and the service never
accepts a project, writable flag or sandbox claim from the plan payload.
Text-only: rollback of non-UTF-8 content cannot be proven, so such plans are
refused instead of silently weakening recovery.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from ..nextlib.core import Rejected, digest, need, safe_relative, sha

OPS = frozenset({'create', 'replace', 'patch', 'delete'})
MAX_OPS = 32
MAX_CONTENT_BYTES = 1_048_576
MAX_PREIMAGE_BYTES = 1_048_576
MAX_ROWS = 512
PRUNE_AGE_NS = 30 * 24 * 3600 * 1_000_000_000
PLAN_TTL_DEFAULT = 300
PLAN_TTL_MAX = 3600

ALLOWED_TRANSITIONS = {
    'PLANNED': {'APPLYING', 'ROLLED_BACK'},
    'APPLYING': {'APPLIED', 'ROLLING_BACK', 'INDETERMINATE'},
    'ROLLING_BACK': {'ROLLED_BACK', 'INDETERMINATE'},
    'APPLIED': {'ROLLING_BACK'},
    # INDETERMINATE may resume compensation when reconcile finds a landed
    # prefix, or resolve to either terminal state when state is provable.
    # APPLYING is re-entered only by explicit forward-completion reconcile.
    'INDETERMINATE': {'APPLIED', 'ROLLED_BACK', 'ROLLING_BACK', 'APPLYING'},
    'ROLLED_BACK': set(),
}
OP_KEYS = {
    'create': {'op', 'path', 'content', 'expected_sha256'},
    'replace': {'op', 'path', 'content', 'expected_sha256'},
    'patch': {'op', 'path', 'old', 'new', 'expected_count', 'expected_sha256'},
    'delete': {'op', 'path', 'expected_sha256'},
}
TERMINAL = frozenset({'APPLIED', 'ROLLED_BACK'})
NEEDS_RECONCILIATION = frozenset({'APPLYING', 'ROLLING_BACK', 'INDETERMINATE'})
# Broker codes that prove an operation had no side effect. Anything else is
# treated as ambiguous and resolved from observed state or left INDETERMINATE.
NO_EFFECT_CODES = frozenset({'CONFLICT', 'READ_ONLY', 'PROTECTED_PATH', 'INVALID_PATH', 'OUTSIDE_ROOT',
                             'PRECONDITION_REQUIRED', 'NOT_FILE', 'NOT_FOUND', 'FILE_LIMIT',
                             'LINK_FORBIDDEN', 'HARDLINK_FORBIDDEN', 'INVALID_TEXT', 'INVALID_ARGUMENT',
                             'UNKNOWN_PROJECT', 'DENIED', 'INVALID_REQUEST_ID', 'POLICY_CHANGED',
                             'MAINTENANCE_ACTIVE', 'UNRESOLVED_MOVE', 'CONCURRENT_CHANGE'})


class TransactionError(Rejected):
    """Rejected with bounded, non-secret machine-readable details."""

    def __init__(self, code: str, details: dict | None = None):
        super().__init__(code)
        self.details = details or {}


def _is_sha(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


class TransactionJournal:
    """Durable per-transaction state. One owner; crash means later reconcile."""

    def __init__(self, path: Path):
        self.lock = threading.RLock()
        self.db = None
        try:
            self.db = sqlite3.connect(path, check_same_thread=False, timeout=5)
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('''
            CREATE TABLE IF NOT EXISTS transactions(
              plan_id TEXT PRIMARY KEY, project TEXT NOT NULL, state TEXT NOT NULL,
              plan TEXT NOT NULL, pre_images TEXT NOT NULL, result TEXT, evidence TEXT,
              created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS transaction_events(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, plan_id TEXT NOT NULL, state TEXT NOT NULL,
              evidence TEXT NOT NULL, time_ns INTEGER NOT NULL);
            ''')
            need(self.db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'JOURNAL_CORRUPT')
            self.db.commit()
        except (sqlite3.DatabaseError, OSError):
            if self.db is not None:
                try:
                    self.db.close()
                except Exception:
                    pass
            raise Rejected('JOURNAL_CORRUPT') from None

    def _tx(self, fn):
        with self.lock:
            try:
                self.db.execute('BEGIN IMMEDIATE')
                value = fn()
                self.db.commit()
                return value
            except BaseException:
                self.db.rollback()
                raise

    def _event(self, plan_id: str, state: str, evidence: dict, now: int) -> None:
        self.db.execute('INSERT INTO transaction_events(plan_id,state,evidence,time_ns) VALUES(?,?,?,?)',
                        (plan_id, state,
                         json.dumps(evidence, sort_keys=True, separators=(',', ':'))[:16384], now))

    def begin(self, plan_id: str, project: str, plan: dict, pre_images: list) -> dict:
        body = json.dumps(plan, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        images = json.dumps(pre_images, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        # User-facing bounds are enforced on raw bytes in _normalize_ops and
        # plan(); these journal caps only absorb JSON escaping overhead.
        need(len(body) <= 4 * MAX_CONTENT_BYTES, 'TRANSACTION_TOO_LARGE')
        need(len(images) <= 4 * MAX_PREIMAGE_BYTES, 'TRANSACTION_TOO_LARGE')
        now = time.time_ns()

        def op():
            row = self.db.execute('SELECT state, plan FROM transactions WHERE plan_id=?', (plan_id,)).fetchone()
            if row is not None:
                need(row['plan'] == body, 'IDEMPOTENCY_CONFLICT')
                return {'plan_id': plan_id, 'state': row['state'], 'replayed': True}
            count = self.db.execute('SELECT count(*) FROM transactions').fetchone()[0]
            if count >= MAX_ROWS:
                self.db.execute('DELETE FROM transactions WHERE state IN (?,?) AND updated_ns<?',
                                ('ROLLED_BACK', 'APPLIED', now - PRUNE_AGE_NS))
                count = self.db.execute('SELECT count(*) FROM transactions').fetchone()[0]
            need(count < MAX_ROWS, 'TRANSACTION_CAPACITY')
            self.db.execute('INSERT INTO transactions VALUES(?,?,?,?,?,NULL,NULL,?,?)',
                            (plan_id, project, 'PLANNED', body, images, now, now))
            self._event(plan_id, 'PLANNED', {'plan_sha256': digest(plan)}, now)
            return {'plan_id': plan_id, 'state': 'PLANNED', 'replayed': False}
        return self._tx(op)

    def get(self, plan_id: str) -> dict:
        with self.lock:
            row = self.db.execute('SELECT * FROM transactions WHERE plan_id=?', (plan_id,)).fetchone()
        need(row is not None, 'UNKNOWN_PLAN')
        return {'plan_id': plan_id, 'project': row['project'], 'state': row['state'],
                'plan': json.loads(row['plan']), 'pre_images': json.loads(row['pre_images']),
                'result': json.loads(row['result']) if row['result'] else None,
                'evidence': json.loads(row['evidence']) if row['evidence'] else None,
                'created_ns': row['created_ns'], 'updated_ns': row['updated_ns']}

    def transition(self, plan_id: str, expected: str, next_state: str, *,
                   result: dict | None = None, evidence: dict | None = None) -> dict:
        evidence = {} if evidence is None else evidence
        need(type(evidence) is dict, 'INVALID_EVIDENCE')
        payload = json.dumps(evidence, sort_keys=True, separators=(',', ':'))[:16384]
        result_text = None if result is None else json.dumps(result, sort_keys=True, separators=(',', ':'))[:65536]
        now = time.time_ns()

        def op():
            row = self.db.execute('SELECT state FROM transactions WHERE plan_id=?', (plan_id,)).fetchone()
            need(row is not None, 'UNKNOWN_PLAN')
            need(row['state'] == expected, 'JOURNAL_CONFLICT')
            need(next_state in ALLOWED_TRANSITIONS.get(expected, set()), 'INVALID_TRANSITION')
            self.db.execute('UPDATE transactions SET state=?, result=coalesce(?,result), evidence=?, updated_ns=? '
                            'WHERE plan_id=?', (next_state, result_text, payload, now, plan_id))
            self._event(plan_id, next_state, evidence, now)
            return {'plan_id': plan_id, 'state': next_state}
        return self._tx(op)

    def events(self, plan_id: str, limit: int = 64) -> list[dict]:
        with self.lock:
            rows = self.db.execute('SELECT seq,state,evidence,time_ns FROM transaction_events '
                                   'WHERE plan_id=? ORDER BY seq DESC LIMIT ?', (plan_id, limit)).fetchall()
        return [{'seq': r['seq'], 'state': r['state'], 'evidence': json.loads(r['evidence']),
                 'time_ns': r['time_ns']} for r in reversed(rows)]

    def unresolved(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                'SELECT plan_id,project,state,updated_ns FROM transactions WHERE state IN (?,?,?) ORDER BY updated_ns',
                tuple(NEEDS_RECONCILIATION)).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self.db.close()


def _normalize_ops(policy, project: str, operations: list) -> list[dict]:
    need(isinstance(operations, list) and 1 <= len(operations) <= MAX_OPS, 'INVALID_OPERATIONS')
    seen, normalized, total_new = set(), [], 0
    for index, item in enumerate(operations):
        need(isinstance(item, dict), 'INVALID_OPERATIONS')
        op = item.get('op')
        need(op in OPS, 'INVALID_OPERATIONS')
        need(set(item) <= OP_KEYS[op], 'INVALID_OPERATIONS')
        path = safe_relative(item.get('path'))
        key = path.casefold()
        need(key not in seen, 'DUPLICATE_PATH')
        seen.add(key)
        policy.path(project, path, write=True)  # authority check before any observation
        entry = {'index': index, 'op': op, 'path': path}
        if op in ('create', 'replace'):
            content = item.get('content')
            need(isinstance(content, str), 'INVALID_TEXT')
            need(not content.startswith('\ufeff') and '\0' not in content, 'INVALID_TEXT')
            encoded = content.encode('utf-8')
            need(len(encoded) <= policy.max_file_bytes, 'FILE_LIMIT')
            expected = 'absent' if op == 'create' else item.get('expected_sha256')
            need(expected == 'absent' or _is_sha(expected), 'PRECONDITION_REQUIRED')
            entry.update(expected_sha256=expected, content=content, content_sha256=sha(encoded))
            total_new += len(encoded)
        elif op == 'patch':
            old, new = item.get('old'), item.get('new')
            count = item.get('expected_count', 1)
            need(isinstance(old, str) and old and isinstance(new, str), 'INVALID_ARGUMENT')
            need(type(count) is int and 1 <= count <= 10000, 'INVALID_ARGUMENT')
            need(not new.startswith('\ufeff') and '\0' not in new, 'INVALID_TEXT')
            need(len(old.encode('utf-8')) + len(new.encode('utf-8')) <= policy.max_file_bytes, 'FILE_LIMIT')
            expected = item.get('expected_sha256')
            need(_is_sha(expected), 'PRECONDITION_REQUIRED')
            entry.update(expected_sha256=expected, old=old, new=new, expected_count=count)
            total_new += len(new.encode('utf-8')) * count
        else:
            expected = item.get('expected_sha256')
            need(_is_sha(expected), 'PRECONDITION_REQUIRED')
            entry.update(expected_sha256=expected)
        normalized.append(entry)
    need(total_new <= MAX_CONTENT_BYTES, 'TRANSACTION_TOO_LARGE')
    return normalized


class TransactionService:
    """Plan/apply/reconcile/rollback over broker-guarded project files."""

    def __init__(self, policy, principal: str, next_api, journal: TransactionJournal, registry_provider):
        self.policy = policy
        self.principal = principal
        self.next = next_api
        self.journal = journal
        self.registry_provider = registry_provider

    # ---- observation helpers -------------------------------------------
    def _observe(self, project: str, path: str, *, want_content: bool = False) -> dict:
        """Classify one path as pre/post/other. Recovery diagnostics only.

        Broker operations still enforce their own exact guards; this read is
        never used to authorize a mutation.
        """
        try:
            target = self.policy.path(project, path)
        except Rejected as exc:
            return {'exists': None, 'sha256': None, 'code': exc.code}
        try:
            info = target.lstat()
        except FileNotFoundError:
            return {'exists': False, 'sha256': None}
        except OSError:
            return {'exists': None, 'sha256': None, 'code': 'UNREADABLE'}
        attributes = getattr(info, 'st_file_attributes', 0)
        if (info.st_mode & 0o170000) != 0o100000:
            return {'exists': True, 'sha256': None, 'code': 'NOT_FILE'}
        if info.st_nlink != 1 or attributes & 0x400:
            return {'exists': True, 'sha256': None, 'code': 'LINK_FORBIDDEN'}
        if info.st_size > self.policy.max_file_bytes:
            return {'exists': True, 'sha256': None, 'code': 'FILE_LIMIT'}
        try:
            data = target.read_bytes()
        except OSError:
            return {'exists': None, 'sha256': None, 'code': 'UNREADABLE'}
        result = {'exists': True, 'sha256': sha(data)}
        if want_content:
            result['content'] = data
        return result

    @staticmethod
    def _state_of(observation: dict, pre_sha, post_sha) -> str:
        if observation.get('exists') is None:
            return 'OTHER'
        if post_sha is None:
            if observation['exists'] is False:
                return 'POST'
            return 'PRE' if observation.get('sha256') == pre_sha else 'OTHER'
        if observation.get('sha256') == post_sha:
            return 'POST'
        if observation['exists'] is False:
            return 'PRE' if pre_sha is None else 'OTHER'
        return 'PRE' if observation.get('sha256') == pre_sha else 'OTHER'

    def _classify(self, project: str, plan: dict) -> dict:
        rows = []
        for op in plan['operations']:
            observed = self._observe(project, op['path'])
            state = self._state_of(observed, op.get('pre_sha256'), op.get('post_sha256'))
            rows.append({'index': op['index'], 'path': op['path'], 'observed': state,
                         'sha256': observed.get('sha256'), 'code': observed.get('code')})
        landed = [row['index'] for row in rows if row['observed'] == 'POST']
        return {'rows': rows, 'landed': landed,
                'prefix': landed == list(range(len(landed))),
                'indeterminate': [r['index'] for r in rows if r['observed'] == 'OTHER']}

    # ---- planning -------------------------------------------------------
    def plan(self, project: str, operations: list, ttl_s: int = PLAN_TTL_DEFAULT) -> dict:
        need(project in self.policy.projects, 'UNKNOWN_PROJECT')
        need(type(ttl_s) is int and 1 <= ttl_s <= PLAN_TTL_MAX, 'INVALID_ARGUMENT')
        context = self.next.context(project)
        need(context.principal == self.principal, 'PRINCIPAL_MISMATCH')
        ops = _normalize_ops(self.policy, project, operations)
        if any(op['op'] != 'delete' for op in ops):
            context.authorize('file_write')
        if any(op['op'] == 'delete' for op in ops):
            context.authorize('file_delete')
        registry = self.registry_provider()
        pre_images, fingerprints, total_pre = [], [], 0
        for op in ops:
            if op['op'] == 'create':
                observed = self._observe(project, op['path'])
                need(observed.get('exists') is not None, 'PATH_NOT_OBSERVABLE')
                if observed.get('code') in ('NOT_FILE', 'LINK_FORBIDDEN', 'FILE_LIMIT'):
                    raise TransactionError(observed['code'], {'index': op['index'], 'path': op['path']})
                if observed['exists'] is True:
                    raise TransactionError('CONFLICT', {'index': op['index'], 'path': op['path'],
                                                        'observed_sha256': observed.get('sha256')})
                op.update(pre_sha256=None, post_sha256=op['content_sha256'])
                pre_images.append(None)
            else:
                observed = self._observe(project, op['path'], want_content=True)
                need(observed.get('exists') is True, 'NOT_FOUND')
                if observed.get('sha256') != op['expected_sha256']:
                    raise TransactionError('CONFLICT', {'index': op['index'], 'path': op['path'],
                                                        'expected_sha256': op['expected_sha256'],
                                                        'observed_sha256': observed.get('sha256')})
                raw = observed.get('content', b'')
                try:
                    text = raw.decode('utf-8')
                except UnicodeDecodeError:
                    raise TransactionError('TRANSACTION_REQUIRES_TEXT',
                                           {'index': op['index'], 'path': op['path']}) from None
                if op['op'] == 'delete':
                    op.update(pre_sha256=observed['sha256'], post_sha256=None)
                elif op['op'] == 'replace':
                    op.update(pre_sha256=observed['sha256'], post_sha256=op['content_sha256'])
                else:
                    actual = text.count(op['old'])
                    if actual != op['expected_count']:
                        raise TransactionError('CONFLICT', {'index': op['index'], 'path': op['path'],
                                                            'old': op['old'],
                                                            'expected_count': op['expected_count'],
                                                            'actual_count': actual})
                    post_text = text.replace(op['old'], op['new'])
                    need(len(post_text.encode('utf-8')) <= self.policy.max_file_bytes, 'FILE_LIMIT')
                    op.update(pre_sha256=observed['sha256'], post_sha256=sha(post_text.encode('utf-8')))
                pre_images.append(text)
                total_pre += len(raw)
                need(total_pre <= MAX_PREIMAGE_BYTES, 'TRANSACTION_TOO_LARGE')
            fingerprints.append({'index': op['index'], 'op': op['op'], 'path': op['path'],
                                 'expected_sha256': op['expected_sha256'],
                                 'new_sha256': op.get('content_sha256'),
                                 'pre_sha256': op.get('pre_sha256'), 'post_sha256': op.get('post_sha256'),
                                 'expected_count': op.get('expected_count')})
        plan_id = digest({'v': 1, 'principal': self.principal, 'project': project,
                          'policy_binding': context.binding, 'registry': registry,
                          'operations': fingerprints})
        plan = {'v': 1, 'plan_id': plan_id, 'project': project, 'policy_binding': context.binding,
                'registry': registry, 'operations': ops}
        begun = self.journal.begin(plan_id, project, plan, pre_images)
        token = self.next.signer.sign(context, 'transaction',
                                      {'plan_id': plan_id, 'project': project, 'registry': registry,
                                       'plan_digest': digest(plan)}, ttl=ttl_s)
        return {'plan_id': plan_id, 'plan': token, 'state': begun['state'], 'replayed': begun['replayed'],
                'operations': [{'index': op['index'], 'op': op['op'], 'path': op['path'],
                                'expected_sha256': op['expected_sha256'],
                                'post_sha256': op['post_sha256']} for op in ops],
                'expires_ns': time.time_ns() + ttl_s * 1_000_000_000,
                'all_or_nothing': 'compensated', 'max_operations': MAX_OPS,
                'max_content_bytes': MAX_CONTENT_BYTES}

    # ---- apply ----------------------------------------------------------
    def _decode(self, project: str, token: str) -> tuple[dict, dict]:
        context = self.next.context(project)
        need(context.principal == self.principal, 'PRINCIPAL_MISMATCH')
        payload = self.next.signer.verify(token, context, 'transaction')
        need(isinstance(payload, dict) and payload.get('project') == project, 'PLAN_PROJECT_MISMATCH')
        row = self.journal.get(payload['plan_id'])
        need(row['plan']['policy_binding'] == context.binding, 'POLICY_CHANGED')
        need(digest(row['plan']) == payload.get('plan_digest'), 'PLAN_DIGEST_MISMATCH')
        need(self.registry_provider() == payload.get('registry'), 'REGISTRY_CHANGED')
        return payload, row

    @staticmethod
    def _op_args(plan_id: str, op: dict, phase: str = 'apply') -> dict:
        request_id = f'lctxn-{plan_id}-{phase}-{op["index"]}'
        if op['op'] == 'create':
            return {'path': op['path'], 'content': op['content'], 'expected_sha256': 'absent',
                    'request_id': request_id}
        if op['op'] == 'replace':
            return {'path': op['path'], 'content': op['content'], 'expected_sha256': op['pre_sha256'],
                    'request_id': request_id}
        if op['op'] == 'patch':
            return {'path': op['path'], 'old': op['old'], 'new': op['new'],
                    'expected_count': op['expected_count'], 'expected_sha256': op['pre_sha256'],
                    'request_id': request_id}
        return {'path': op['path'], 'expected_sha256': op['pre_sha256'], 'request_id': request_id}

    async def _apply_one(self, project: str, plan_id: str, op: dict, *, phase: str = 'apply') -> dict:
        args = self._op_args(plan_id, op, phase)
        tool = {'create': 'file_write', 'replace': 'file_write', 'patch': 'file_patch',
                'delete': 'file_delete'}[op['op']]
        result = await self.next.caller(tool, project, args)
        need(isinstance(result, dict) and type(result.get('ok')) is bool, 'BACKEND_CONTRACT')
        if result['ok']:
            data = result.get('data', {})
            if op['op'] == 'delete':
                need(data.get('deleted') is True, 'BACKEND_CONTRACT')
            else:
                need(data.get('sha256') == op['post_sha256'], 'BACKEND_CONTRACT')
        return result

    async def _restore(self, project: str, plan_id: str, op: dict, pre_image) -> dict:
        request_id = f'lctxn-{plan_id}-rb-{op["index"]}'
        if op['op'] == 'create':
            return await self.next.caller('file_delete', project, {
                'path': op['path'], 'expected_sha256': op['post_sha256'], 'request_id': request_id})
        expected = 'absent' if op['op'] == 'delete' else op['post_sha256']
        return await self.next.caller('file_write', project, {
            'path': op['path'], 'content': pre_image, 'expected_sha256': expected, 'request_id': request_id})

    async def apply(self, project: str, token: str, *, request_id: str) -> dict:
        payload, row = self._decode(project, token)
        plan_id = payload['plan_id']
        state = row['state']
        if state == 'APPLIED':
            raise TransactionError('ALREADY_APPLIED', {'plan_id': plan_id, 'state': state})
        if state == 'ROLLED_BACK':
            raise TransactionError('TRANSACTION_CLOSED', {'plan_id': plan_id, 'state': state})
        if state in NEEDS_RECONCILIATION:
            raise TransactionError('TRANSACTION_NEEDS_RECONCILE', {'plan_id': plan_id, 'state': state})
        need(state == 'PLANNED', 'JOURNAL_CONFLICT')
        self.journal.transition(plan_id, 'PLANNED', 'APPLYING', evidence={'request_id': request_id})
        try:
            for op in row['plan']['operations']:
                result = await self._apply_one(project, plan_id, op)
                if not result['ok']:
                    failed_code = result.get('error', {}).get('code', 'BACKEND_ERROR')
                    raise TransactionError('TRANSACTION_FAILED',
                                           {'plan_id': plan_id, 'failed_index': op['index'],
                                            'failed_code': failed_code,
                                            'no_effect': failed_code in NO_EFFECT_CODES})
            verified = await self._verify_state(project, row['plan'], expect='POST')
            need(verified['all'], 'TRANSACTION_INDETERMINATE')
            final = {'committed': True, 'reconciled': False, 'operations': len(row['plan']['operations']),
                     'files': [{'index': op['index'], 'path': op['path'], 'sha256': op['post_sha256']}
                               for op in row['plan']['operations']]}
            self.journal.transition(plan_id, 'APPLYING', 'APPLIED', result=final,
                                    evidence={'applied': len(row['plan']['operations'])})
            return {'plan_id': plan_id, 'state': 'APPLIED', **final,
                    'all_or_nothing': 'compensated'}
        except TransactionError as exc:
            return await self._fail_forward(project, plan_id, row['plan'], row['pre_images'], exc)
        except BaseException:
            self.journal.transition(plan_id, 'APPLYING', 'INDETERMINATE',
                                    evidence={'reason': 'UNEXPECTED_ERROR'})
            raise

    async def _verify_state(self, project: str, plan: dict, *, expect: str) -> dict:
        rows = []
        for op in plan['operations']:
            observed = self._observe(project, op['path'])
            rows.append({'index': op['index'], 'path': op['path'],
                         'observed': self._state_of(observed, op.get('pre_sha256'), op.get('post_sha256')),
                         'sha256': observed.get('sha256')})
        return {'all': all(row['observed'] == expect for row in rows), 'rows': rows}

    async def _fail_forward(self, project: str, plan_id: str, plan: dict, pre_images, exc: TransactionError) -> dict:
        details = exc.details or {}
        if exc.code == 'TRANSACTION_INDETERMINATE':
            self.journal.transition(plan_id, 'APPLYING', 'INDETERMINATE', evidence={'reason': exc.code})
            raise TransactionError('TRANSACTION_INDETERMINATE',
                                   {'plan_id': plan_id, 'state': 'INDETERMINATE',
                                    'next_action': {'tool': 'transaction_reconcile'}})
        failed_index = details.get('failed_index')
        if details.get('no_effect') and isinstance(failed_index, int):
            # The broker guarded the failed operation before mutation, so all
            # earlier indexes landed and the failed index did not.
            landed = list(range(failed_index))
        else:
            classification = self._classify(project, plan)
            if classification['indeterminate'] or not classification['prefix']:
                self.journal.transition(plan_id, 'APPLYING', 'INDETERMINATE',
                                        evidence={'reason': exc.code,
                                                  'indeterminate': classification['indeterminate']})
                raise TransactionError('TRANSACTION_INDETERMINATE',
                                       {'plan_id': plan_id, 'state': 'INDETERMINATE',
                                        'indeterminate': classification['indeterminate'],
                                        'next_action': {'tool': 'transaction_reconcile'}})
            landed = classification['landed']
        self.journal.transition(plan_id, 'APPLYING', 'ROLLING_BACK', evidence={'reason': exc.code})
        restored, failed = await self._compensate(project, plan_id, plan, pre_images, landed)
        state = 'ROLLED_BACK' if not failed else 'INDETERMINATE'
        self.journal.transition(plan_id, 'ROLLING_BACK', state,
                                result={'committed': False, 'restored': landed},
                                evidence={'restore_failed': failed})
        if state == 'ROLLED_BACK':
            raise TransactionError('TRANSACTION_ROLLED_BACK',
                                   {'plan_id': plan_id, 'state': state, 'committed': False,
                                    'failed_code': details.get('failed_code', exc.code),
                                    'restored': landed})
        raise TransactionError('TRANSACTION_INDETERMINATE', {'plan_id': plan_id, 'state': state,
                                                             'next_action': {'tool': 'transaction_reconcile'}})

    async def _compensate(self, project: str, plan_id: str, plan: dict, pre_images, landed: list):
        ops = {op['index']: op for op in plan['operations']}
        restored, failed = [], []
        for index in sorted(landed, reverse=True):
            result = await self._restore(project, plan_id, ops[index], pre_images[index])
            if result.get('ok') is True:
                restored.append(index)
            else:
                failed.append({'index': index, 'code': result.get('error', {}).get('code', 'BACKEND_ERROR')})
        return restored, failed

    # ---- status / recovery ---------------------------------------------
    def status(self, plan_id: str) -> dict:
        row = self.journal.get(plan_id)
        classification = self._classify(row['project'], row['plan'])
        return {'plan_id': plan_id, 'project': row['project'], 'state': row['state'],
                'needs_reconciliation': row['state'] in NEEDS_RECONCILIATION,
                'operations': [{'index': op['index'], 'op': op['op'], 'path': op['path']}
                               for op in row['plan']['operations']],
                'observed': classification['rows'], 'landed': classification['landed'],
                'result': row['result'], 'events': self.journal.events(plan_id, limit=16),
                'created_ns': row['created_ns'], 'updated_ns': row['updated_ns'],
                'recovery': ('transaction_reconcile' if row['state'] in NEEDS_RECONCILIATION
                             else ('transaction_rollback' if row['state'] == 'APPLIED' else None))}

    async def reconcile(self, project: str, plan_id: str, *, request_id: str,
                        strategy: str = 'rollback') -> dict:
        need(strategy in ('rollback', 'forward'), 'INVALID_ARGUMENT')
        row = self.journal.get(plan_id)
        need(row['project'] == project, 'PLAN_PROJECT_MISMATCH')
        state = row['state']
        if state == 'PLANNED':
            return {'plan_id': plan_id, 'state': 'PLANNED', 'changed': False,
                    'note': 'plan is intact and not yet applied'}
        classification = self._classify(project, row['plan'])
        if state in TERMINAL:
            return {'plan_id': plan_id, 'state': state, 'changed': False, 'observed': classification['rows']}
        if classification['indeterminate'] or (classification['landed'] and not classification['prefix']):
            self.journal.transition(plan_id, state, 'INDETERMINATE',
                                    evidence={'reconcile': 'indeterminate', 'request_id': request_id})
            raise TransactionError('TRANSACTION_INDETERMINATE',
                                   {'plan_id': plan_id, 'state': 'INDETERMINATE',
                                    'indeterminate': classification['indeterminate'],
                                    'requires_operator_review': True})
        if strategy == 'forward' and len(classification['landed']) < len(row['plan']['operations']):
            return await self._forward(project, plan_id, row, classification, request_id)
        if not classification['landed']:
            self.journal.transition(plan_id, state, 'ROLLED_BACK',
                                    result={'committed': False, 'reconciled': True},
                                    evidence={'reconcile': 'all_pre', 'request_id': request_id})
            return {'plan_id': plan_id, 'state': 'ROLLED_BACK', 'committed': False, 'changed': True,
                    'observed': classification['rows']}
        if len(classification['landed']) == len(row['plan']['operations']):
            final = {'committed': True, 'reconciled': True,
                     'files': [{'index': op['index'], 'path': op['path'], 'sha256': op['post_sha256']}
                               for op in row['plan']['operations']]}
            self.journal.transition(plan_id, state, 'APPLIED', result=final,
                                    evidence={'reconcile': 'all_post', 'request_id': request_id})
            return {'plan_id': plan_id, 'state': 'APPLIED', 'committed': True, 'changed': True,
                    'observed': classification['rows']}
        self.journal.transition(plan_id, state, 'ROLLING_BACK',
                                evidence={'reconcile': 'prefix', 'request_id': request_id})
        restored, failed = await self._compensate(project, plan_id, row['plan'], row['pre_images'],
                                                  classification['landed'])
        final_state = 'ROLLED_BACK' if not failed else 'INDETERMINATE'
        self.journal.transition(plan_id, 'ROLLING_BACK', final_state,
                                result={'committed': False, 'reconciled': True, 'restored': restored},
                                evidence={'restore_failed': failed})
        if final_state != 'ROLLED_BACK':
            raise TransactionError('TRANSACTION_INDETERMINATE', {'plan_id': plan_id, 'state': final_state,
                                                                 'requires_operator_review': True})
        return {'plan_id': plan_id, 'state': 'ROLLED_BACK', 'committed': False, 'changed': True,
                'restored': restored, 'observed': classification['rows']}

    async def _forward(self, project: str, plan_id: str, row: dict, classification: dict,
                       request_id: str) -> dict:
        """Complete the remaining operations after an interruption.

        Every remaining operation re-verifies its own exact preconditions via
        the broker guards, so forwarding can never overwrite external changes.
        Failure falls back to the same compensation path as a fresh apply.
        """
        state = row['state']
        need(state in {'APPLYING', 'INDETERMINATE'}, 'TRANSACTION_NEEDS_RECONCILE')
        operations = row['plan']['operations']
        landed = set(classification['landed'])
        if state != 'APPLYING':
            self.journal.transition(plan_id, state, 'APPLYING', evidence={'strategy': 'forward'})
        try:
            for op in operations:
                if op['index'] in landed:
                    continue
                result = await self._apply_one(project, plan_id, op, phase='fwd')
                if not result['ok']:
                    failed_code = result.get('error', {}).get('code', 'BACKEND_ERROR')
                    raise TransactionError('TRANSACTION_FAILED',
                                           {'plan_id': plan_id, 'failed_index': op['index'],
                                            'failed_code': failed_code,
                                            'no_effect': failed_code in NO_EFFECT_CODES})
            verified = await self._verify_state(project, row['plan'], expect='POST')
            need(verified['all'], 'TRANSACTION_INDETERMINATE')
            final = {'committed': True, 'reconciled': True, 'strategy': 'forward',
                     'operations': len(operations),
                     'files': [{'index': op['index'], 'path': op['path'], 'sha256': op['post_sha256']}
                               for op in operations]}
            self.journal.transition(plan_id, 'APPLYING', 'APPLIED', result=final,
                                    evidence={'reconcile': 'forward_complete', 'request_id': request_id})
            return {'plan_id': plan_id, 'state': 'APPLIED', 'committed': True, 'changed': True,
                    'strategy': 'forward', 'completed': len(operations) - len(landed),
                    'already_landed': sorted(landed), 'observed': verified['rows']}
        except TransactionError as exc:
            return await self._fail_forward(project, plan_id, row['plan'], row['pre_images'], exc)
        except BaseException:
            self.journal.transition(plan_id, 'APPLYING', 'INDETERMINATE',
                                    evidence={'reason': 'UNEXPECTED_ERROR'})
            raise

    async def rollback(self, project: str, plan_id: str, *, request_id: str) -> dict:
        row = self.journal.get(plan_id)
        need(row['project'] == project, 'PLAN_PROJECT_MISMATCH')
        state = row['state']
        if state == 'ROLLED_BACK':
            return {'plan_id': plan_id, 'state': state, 'changed': False}
        if state == 'PLANNED':
            return {'plan_id': plan_id, 'state': state, 'changed': False,
                    'note': 'nothing was applied; the plan may simply expire'}
        if state != 'APPLIED':
            raise TransactionError('TRANSACTION_NEEDS_RECONCILE', {'plan_id': plan_id, 'state': state})
        classification = self._classify(project, row['plan'])
        if classification['indeterminate'] or len(classification['landed']) != len(row['plan']['operations']):
            raise TransactionError('DRIFT_DETECTED',
                                   {'plan_id': plan_id, 'state': state, 'observed': classification['rows'],
                                    'note': 'file state no longer matches the applied transaction'})
        self.journal.transition(plan_id, 'APPLIED', 'ROLLING_BACK', evidence={'request_id': request_id})
        restored, failed = await self._compensate(project, plan_id, row['plan'], row['pre_images'],
                                                  classification['landed'])
        final_state = 'ROLLED_BACK' if not failed else 'INDETERMINATE'
        self.journal.transition(plan_id, 'ROLLING_BACK', final_state,
                                result={'committed': False, 'rolled_back': True, 'restored': restored},
                                evidence={'restore_failed': failed})
        if final_state != 'ROLLED_BACK':
            raise TransactionError('TRANSACTION_INDETERMINATE', {'plan_id': plan_id, 'state': final_state})
        verified = await self._verify_state(project, row['plan'], expect='PRE')
        return {'plan_id': plan_id, 'state': 'ROLLED_BACK', 'changed': True, 'restored': restored,
                'verified_pre_state': verified['all']}
