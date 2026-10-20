"""Small durable receipts and idempotency store. Raw command/file content is not audited."""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
import hashlib
import json
import sqlite3
import threading
import time
from .errors import ControlError, require
from .lease import InstanceLease
from .policy import no_links


TERMINAL_JOB_STATES = frozenset({
    'completed', 'failed', 'timed_out', 'stopped', 'interrupted',
    'server_shutdown', 'start_failed', 'supervision_error', 'capture_incomplete',
})
ACTIVE_JOB_STATES = frozenset({'queued', 'starting', 'running', 'ownership_unresolved'})
JOB_ARCHIVE_SCHEMA = 1

# Audit admission reserve. Every reserved-but-unfinished request owes the ledger
# its mandatory completion record plus the bounded intent/progress records its
# work may emit; each nonterminal job likewise owes its terminal record.
# Worst observed request obligation: mission_finish holds its reservation while
# the verifier runs up to MAX_COMMANDS(8) run_commands; each JobManager.start
# can emit an essential job_terminal_reclamation row at the jobs cap AND a
# job_queue_terminal row on the queue-denial path (2 per command), plus the
# request's own request_finished row => 8*2+1=17, rounded up.
AUDIT_ROWS_PER_RESERVED_REQUEST = 20
# Nine bounded lifecycle phases, optional stop intent, scratch cleanup and margin.
AUDIT_ROWS_PER_ACTIVE_JOB = 12
# Floor for bounded room above max_audit_rows that essential records may use
# when owed debt exceeds the routine reservation (pre-upgrade rows, or a
# reserve margin raised mid-flight). The real ceiling is derived per-write as
# max(max_audit_rows + AUDIT_ESSENTIAL_OVERFLOW, max_audit_rows + owed).
AUDIT_ESSENTIAL_OVERFLOW = 64
# After a failed automatic rotation do not retry on every call.
AUDIT_ROTATION_BACKOFF_S = 60
# Recorded rotation failures that are proven contention/race conditions rather
# than integrity or environment defects. Only these degrade to AUDIT_ROTATION_
# BACKOFF during the backoff window; anything else fails closed.
TRANSIENT_ROTATION_CODES = frozenset({
    'AUDIT_ROTATION_BUSY', 'AUDIT_ROTATION_RACE', 'AUDIT_ARCHIVE_INVALID',
    'OSError', 'FileExistsError', 'FileNotFoundError', 'PermissionError',
    'TimeoutError', 'OperationalError'})


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _replay_safe(value):
    """Stored replay payloads never reissue bearer credentials. A caller who
    lost the original delivery must reacquire authority (e.g. takeover) rather
    than replaying someone else's minted token."""
    if isinstance(value, dict):
        return {k: _replay_safe(v) for k, v in value.items()
                if k not in ('token', 'fence_token')}
    if isinstance(value, list):
        return [_replay_safe(item) for item in value]
    return value


class Store:
    def __init__(self, root: Path, max_requests: int = 10000, max_audit_rows: int = 100000,
                 audit_reserve_margin: int | None = None):
        root.mkdir(parents=True, exist_ok=True)
        no_links(root / "receipts.sqlite")
        self.root = root
        self.lease = InstanceLease(root)
        self.lock = threading.RLock()
        self.max_requests = max_requests
        self.max_audit_rows = max_audit_rows
        if audit_reserve_margin is None:
            audit_reserve_margin = min(256, max(1, max_audit_rows // 8))
        require(type(audit_reserve_margin) is int and 0 < audit_reserve_margin < max_audit_rows,
                'INVALID_CONFIG', 'Invalid audit reserve margin')
        self.audit_reserve_margin = audit_reserve_margin
        self._rotation_failure: dict | None = None
        self._last_rotation_error: dict | None = None
        self._rotation_backoff_until_ns = 0
        self._owed_cache: int | None = None
        self.write_poisoned = False
        try:
            self.db = sqlite3.connect(root / "receipts.sqlite", check_same_thread=False, timeout=5)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript('''
            CREATE TABLE IF NOT EXISTS requests (
              scope TEXT NOT NULL, key TEXT NOT NULL, fingerprint TEXT NOT NULL,
              status TEXT NOT NULL, result TEXT, PRIMARY KEY(scope,key));
            CREATE INDEX IF NOT EXISTS requests_status ON requests(status);
            CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, scope TEXT NOT NULL, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS job_archives (
              id TEXT PRIMARY KEY, scope TEXT NOT NULL, record TEXT NOT NULL,
              archived_ns INTEGER NOT NULL, reason TEXT NOT NULL, record_sha256 TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS job_archives_scope_time
              ON job_archives(scope, archived_ns DESC, id DESC);
            CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, payload TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL);
            ''')
            require(self.db.execute("PRAGMA quick_check").fetchone()[0] == "ok", "STORE_CORRUPT", "Receipt store is corrupt")
            self._verify_archives()
            require(self.verify(), "AUDIT_CORRUPT", "Audit chain does not verify")
            self._headroom_or_degraded("startup capacity threshold")
            self.db.commit()
        except BaseException:
            if hasattr(self,'db'):
                self.db.close()
            self.lease.close()
            raise

    @contextmanager
    def transaction(self):
        with self.lock:
            try:
                require(not self.write_poisoned, 'STORE_FAILURE', 'Store requires operator reconciliation')
                self.db.execute("BEGIN IMMEDIATE")
                yield
                self.db.commit()
            except BaseException:
                # Rolled-back mutations must not survive in the owed-reserve
                # cache — rebuild it from the authoritative tables next read.
                self._owed_cache = None
                try:
                    self.db.rollback()
                except BaseException:
                    self.write_poisoned = True
                raise

    @staticmethod
    def _audit_chain_state(con) -> dict:
        prev = "0" * 64
        entries = 0
        tip = None
        last_seq = 0
        for row in con.execute("SELECT seq,payload,prev,hash FROM audit ORDER BY seq"):
            seq, payload, prev_h, hashed = row[0], row[1], row[2], row[3]
            expected = hashlib.sha256((prev + payload).encode()).hexdigest()
            if prev_h != prev or hashed != expected:
                return {'ok': False, 'entries': entries, 'failed_seq': seq,
                        'tip': tip, 'last_seq': last_seq}
            prev = hashed
            tip = hashed
            last_seq = seq
            entries += 1
        return {'ok': True, 'entries': entries, 'tip': tip, 'last_seq': last_seq}

    def audit_capacity_snapshot(self) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT count(*) FROM audit").fetchone()[0]
            owed = self._owed_reserve_locked()
            first = self.db.execute("SELECT payload FROM audit ORDER BY seq LIMIT 1").fetchone()
            last = self.db.execute("SELECT payload FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            trigger = max(1, (self.max_audit_rows * 85 + 99) // 100)
            if rows < trigger and self._rotation_failure is not None:
                # External rotation already restored headroom — do not keep
                # reporting a resolved failure as active.
                self._rotation_failure = None
                self._rotation_backoff_until_ns = 0
            rotation_failure = self._rotation_failure
            rotation_backoff = self._rotation_backoff_until_ns
            last_rotation_error = self._last_rotation_error
        rate = 0.0
        span_days = 0.0
        if first and last and rows > 1:
            try:
                ft = json.loads(first['payload'])['time_ns']
                lt = json.loads(last['payload'])['time_ns']
                span_days = max((lt - ft) / 86400e9, 1e-6)
                rate = rows / span_days
            except (KeyError, TypeError, ValueError):
                rate = 0.0
        return {'rows': rows, 'max_rows': self.max_audit_rows,
                'rotation_trigger_rows': trigger,
                'fill_pct': round((100.0 * rows) / self.max_audit_rows, 2),
                'reserved_owed_rows': owed,
                'reserve_margin': self.audit_reserve_margin,
                'admission_rows_available': max(0, self.max_audit_rows - rows - owed - 1),
                'essential_overflow_rows': AUDIT_ESSENTIAL_OVERFLOW,
                'rows_per_day': round(rate, 1),
                'est_days_to_trigger': (max(0.0, round((trigger - rows) / rate, 2))
                                        if rate > 0 else None),
                'est_days_to_full': (max(0.0, round((self.max_audit_rows - rows) / rate, 2))
                                     if rate > 0 else None),
                'rotation_failure': rotation_failure,
                'rotation_backoff_active': time.time_ns() < rotation_backoff,
                'last_rotation_error': last_rotation_error}

    def capacity_snapshot(self) -> dict:
        with self.lock:
            requests_rows = self.db.execute("SELECT count(*) FROM requests").fetchone()[0]
            pending = self.db.execute(
                "SELECT count(*) FROM requests WHERE status='reserved'").fetchone()[0]
        return {'audit': self.audit_capacity_snapshot(),
                'requests': {'rows': requests_rows, 'max_rows': self.max_requests,
                             'pending_reserved': pending,
                             'fill_pct': round((100.0 * requests_rows) / self.max_requests, 2)},
                'jobs': self.job_capacity_snapshot()}

    def _rotate_audit_locked(self, reason: str) -> dict:
        require(isinstance(reason, str) and 1 <= len(reason) <= 128 and reason.isascii(),
                'INVALID_ARGUMENT', 'Invalid audit rotation reason')
        chain = self._audit_chain_state(self.db)
        require(chain['ok'], 'AUDIT_CORRUPT', 'Audit chain does not verify')
        if chain['entries'] == 0:
            return {'rotated': False, 'reason': 'empty'}

        archive_dir = self.root / 'audit-archive'
        archive_dir.mkdir(parents=True, exist_ok=True)
        no_links(archive_dir)
        checkpoint = self.db.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
        require(checkpoint is None or checkpoint[0] == 0,
                'AUDIT_ROTATION_BUSY', 'Audit WAL checkpoint could not complete')

        rotated_ns = time.time_ns()
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        archive = archive_dir / (
            f"receipts-audit-{stamp}-{rotated_ns}-rows{chain['entries']}"
            f"-tip{(chain['tip'] or '0')[:12]}.sqlite")
        escaped = str(archive).replace("'", "''")
        self.db.execute("VACUUM INTO '" + escaped + "'")

        hasher = hashlib.sha256()
        with archive.open('rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                hasher.update(chunk)
        archive_sha = hasher.hexdigest()

        archived = sqlite3.connect(f"file:{archive}?mode=ro", uri=True)
        try:
            archived_chain = self._audit_chain_state(archived)
            require(archived_chain['ok']
                    and archived_chain['entries'] == chain['entries']
                    and archived_chain['tip'] == chain['tip'],
                    'AUDIT_ARCHIVE_INVALID', 'Audit archive verification failed')
        finally:
            archived.close()

        genesis_payload = canonical({
            'time_ns': rotated_ns, 'kind': 'audit_rotation',
            'metadata': {
                'reason': reason, 'prev_last_seq': chain['last_seq'],
                'prev_tip_hash': chain['tip'], 'prev_row_count': chain['entries'],
                'archive_file': archive.name, 'archive_sha256': archive_sha,
                'rotated_ns': rotated_ns, 'policy': 'AUDIT_ROTATION_POLICY v1'}})
        genesis_hash = hashlib.sha256((("0" * 64) + genesis_payload).encode()).hexdigest()

        committed = False
        try:
            self.db.execute("BEGIN IMMEDIATE")
            now = self._audit_chain_state(self.db)
            require(now['ok'], 'AUDIT_CORRUPT',
                    'Audit chain failed integrity inside rotation seal')
            require(now['entries'] == chain['entries']
                    and now['tip'] == chain['tip'] and now['last_seq'] == chain['last_seq'],
                    'AUDIT_ROTATION_RACE', 'Audit changed while rotation archive was sealed')
            self.db.execute("DELETE FROM audit")
            self.db.execute("INSERT INTO audit(seq,payload,prev,hash) VALUES(1,?,?,?)",
                            (genesis_payload, "0" * 64, genesis_hash))
            self.db.commit()
            committed = True
        except BaseException:
            self.db.rollback()
            raise
        finally:
            if not committed:
                archive.unlink(missing_ok=True)

        require(self.verify(), 'AUDIT_CORRUPT', 'Audit chain does not verify after rotation')
        return {'rotated': True, 'archived_rows': chain['entries'],
                'archive_file': archive.name, 'archive_sha256': archive_sha,
                'genesis_hash': genesis_hash}

    def _ensure_audit_headroom(self, reason: str) -> dict | None:
        with self.lock:
            require(not self.write_poisoned, 'STORE_FAILURE', 'Store requires operator reconciliation')
            count = self.db.execute("SELECT count(*) FROM audit").fetchone()[0]
            trigger = max(1, (self.max_audit_rows * 85 + 99) // 100)
            if count < trigger:
                # Headroom recovered (e.g. operator rotated externally) — the
                # active failure and any backoff clear; last_rotation_error
                # keeps the failure history for the capacity snapshot.
                self._rotation_failure = None
                self._rotation_backoff_until_ns = 0
                return None
            if time.time_ns() < self._rotation_backoff_until_ns:
                failure = dict(self._rotation_failure or {})
                code = failure.get('code')
                if code == 'AUDIT_CORRUPT':
                    raise ControlError('AUDIT_CORRUPT',
                                       'Audit chain integrity failure persists during rotation backoff',
                                       {'last_rotation_error': failure})
                if code not in TRANSIENT_ROTATION_CODES:
                    # Unclassifiable failure — treat as chain-fatal until the
                    # operator re-verifies; never degrade essential writes onto
                    # a suspect chain.
                    raise ControlError('AUDIT_ROTATION_FATAL',
                                       'Audit rotation failure is not a known-transient condition',
                                       {'last_rotation_error': failure})
                raise ControlError('AUDIT_ROTATION_BACKOFF',
                                   'Automatic audit rotation is in failure backoff',
                                   {'retry_after_ns': self._rotation_backoff_until_ns - time.time_ns(),
                                    'last_rotation_error': failure})
            try:
                result = self._rotate_audit_locked(reason)
            except ControlError as err:
                if err.code == 'AUDIT_ROTATION_BUSY':
                    # WAL/checkpoint contention is not a failure: no backoff,
                    # next call retries. Callers see a transient denial.
                    raise
                self._rotation_failure = {'time_ns': time.time_ns(),
                                          'code': getattr(err, 'code', type(err).__name__),
                                          'message': str(err)[:512]}
                self._last_rotation_error = dict(self._rotation_failure)
                self._rotation_backoff_until_ns = time.time_ns() + int(AUDIT_ROTATION_BACKOFF_S * 1e9)
                raise
            except Exception as err:
                self._rotation_failure = {'time_ns': time.time_ns(),
                                          'code': getattr(err, 'code', type(err).__name__),
                                          'message': str(err)[:512]}
                self._last_rotation_error = dict(self._rotation_failure)
                self._rotation_backoff_until_ns = time.time_ns() + int(AUDIT_ROTATION_BACKOFF_S * 1e9)
                raise
            self._rotation_failure = None
            return result

    def _headroom_or_degraded(self, reason: str) -> None:
        """Essential lane admission check: rotation failures degrade (recorded in
        the capacity snapshot) instead of blocking mandatory completion records.
        Chain corruption still fails closed."""
        try:
            self._ensure_audit_headroom(reason)
        except ControlError as err:
            if err.code in ('AUDIT_CORRUPT', 'AUDIT_ROTATION_FATAL'):
                raise
        except (OSError, sqlite3.OperationalError):
            pass

    def _owed_reserve_locked(self) -> int:
        """Audit rows already promised to admitted work, plus the fixed margin
        reserved for bounded maintenance receipts. Routine admissions may not
        consume this space. Cached per mutation: this Store is the only writer
        (InstanceLease) and the table mutations below invalidate it."""
        if self._owed_cache is not None:
            return self._owed_cache
        pending = self.db.execute(
            "SELECT count(*) FROM requests WHERE status='reserved'").fetchone()[0]
        active_jobs = self.db.execute(
            "SELECT count(*) FROM jobs WHERE json_extract(record,'$.status') "
            "IN ('queued','starting','running','ownership_unresolved')").fetchone()[0]
        self._owed_cache = (pending * AUDIT_ROWS_PER_RESERVED_REQUEST
                            + active_jobs * AUDIT_ROWS_PER_ACTIVE_JOB
                            + self.audit_reserve_margin)
        return self._owed_cache

    def _audit(self, kind: str, metadata: dict, *, essential: bool = False):
        row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else "0" * 64
        count = self.db.execute("SELECT count(*) FROM audit").fetchone()[0]
        if essential:
            # The derived ceiling: enough room to drain every booked obligation
            # even if admission bookkeeping predates the reserve. Bounded by
            # config-bounded owed (pending×12 + active×4 + margin).
            ceiling = self.max_audit_rows + max(AUDIT_ESSENTIAL_OVERFLOW,
                                                self._owed_reserve_locked())
            require(count < ceiling,
                    "AUDIT_CAPACITY",
                    "Audit capacity reached including essential reserve; operator archival required",
                    {'rows': count, 'max_rows': self.max_audit_rows,
                     'essential_overflow': AUDIT_ESSENTIAL_OVERFLOW,
                     'owed': ceiling - self.max_audit_rows})
        else:
            owed = self._owed_reserve_locked()
            require(count + owed + 1 <= self.max_audit_rows, "AUDIT_CAPACITY",
                    "Audit admission reserve exhausted; new work denied until capacity returns",
                    {'rows': count, 'max_rows': self.max_audit_rows,
                     'reserved_owed_rows': owed})
        payload = canonical({"time_ns": time.time_ns(), "kind": kind, "metadata": metadata})
        hashed = hashlib.sha256((prev + payload).encode()).hexdigest()
        self.db.execute("INSERT INTO audit(payload,prev,hash) VALUES(?,?,?)", (payload, prev, hashed))

    def audit(self, kind: str, metadata: dict):
        require(isinstance(kind, str) and 1 <= len(kind) <= 64 and kind.isascii(),
                'INVALID_ARGUMENT', 'Invalid audit kind')
        self._ensure_audit_headroom("automatic threshold rotation before audit")
        with self.transaction():
            self._audit(kind, metadata)

    def audit_essential(self, kind: str, metadata: dict):
        """Mandatory completion/cancellation/accounting record for already
        admitted work. Bypasses rotation-failure denial and the admission
        reserve; bounded by max_audit_rows + max(floor, live owed reserve)."""
        require(isinstance(kind, str) and 1 <= len(kind) <= 64 and kind.isascii(),
                'INVALID_ARGUMENT', 'Invalid audit kind')
        self._headroom_or_degraded("automatic threshold rotation before essential record")
        with self.transaction():
            self._audit(kind, metadata, essential=True)

    def reserve(self, scope: str, key: str, fingerprint: str) -> dict | None:
        require(isinstance(key, str) and 8 <= len(key) <= 128 and key.isascii()
                and all(c.isalnum() or c in '-_.' for c in key), "INVALID_REQUEST_ID", "Use an 8-128 character request ID")
        # Replay fast-path first: returning a stored result costs no ledger
        # capacity, so it must not be denied by rotation backoff.
        with self.lock:
            row = self.db.execute("SELECT * FROM requests WHERE scope=? AND key=?", (scope, key)).fetchone()
        if row is not None:
            require(row["fingerprint"] == fingerprint, "IDEMPOTENCY_CONFLICT", "Request ID was already used for different input")
            if row["result"]:
                return json.loads(row["result"])
            return {"ok": False, "error": {"code": "INDETERMINATE", "message": "Request was reserved; reconcile instead of replaying its side effect"}}
        self._ensure_audit_headroom("automatic threshold rotation before request reservation")
        with self.transaction():
            row = self.db.execute("SELECT * FROM requests WHERE scope=? AND key=?", (scope, key)).fetchone()
            if row:
                require(row["fingerprint"] == fingerprint, "IDEMPOTENCY_CONFLICT", "Request ID was already used for different input")
                if row["result"]:
                    return json.loads(row["result"])
                return {"ok": False, "error": {"code": "INDETERMINATE", "message": "Request was reserved; reconcile instead of replaying its side effect"}}
            count = self.db.execute("SELECT count(*) FROM requests").fetchone()[0]
            require(count < self.max_requests, "STORE_CAPACITY", "Receipt capacity reached; operator archival required")
            self.db.execute("INSERT INTO requests VALUES(?,?,?,?,?)", (scope, key, fingerprint, "reserved", None))
            self._owed_cache = None
            self._audit("request_reserved", {"scope": scope, "request_id": key, "input_sha256": fingerprint})
        return None

    def finish(self, scope: str, key: str, result: dict):
        self._headroom_or_degraded("automatic threshold rotation before request finish")
        with self.transaction():
            cur = self.db.execute("UPDATE requests SET status='finished',result=? WHERE scope=? AND key=? AND status='reserved'",
                                  (canonical(_replay_safe(result)), scope, key))
            if cur.rowcount:
                self._owed_cache = None
                self._audit("request_finished", {"scope": scope, "request_id": key, "ok": result.get("ok"), "result_sha256": digest(result)},
                            essential=True)


    def commit_job_transition(self, job_id, scope, phase, revision, record, kind, metadata):
        """One retry-stable row + audit transaction; never infer failure == rollback.

        Event markers live inside the receipt and survive audit rotation/archival.
        The caller MUST freeze record/metadata and retain native custody on error.
        """
        phases = {'admitted', 'queued', 'starting', 'create_intent', 'owned',
                  'release_intent', 'started', 'terminal', 'restart_unresolved', 'cancel_intent'}
        require(phase in phases and type(revision) is int and revision >= 0,
                'STORE_CORRUPT', 'Invalid ownership transition')
        require('_ownership' not in record, 'STORE_CORRUPT', 'Reserved receipt field')
        require(isinstance(kind, str) and 1 <= len(kind) <= 64 and kind.isascii(),
                'INVALID_ARGUMENT', 'Invalid audit kind')
        require(phase != 'terminal' or record.get('status') in TERMINAL_JOB_STATES,
                'STORE_CORRUPT', 'Terminal transition needs a terminal status')
        body = {'record': record, 'kind': kind, 'metadata': metadata}
        fingerprint = digest(body)
        # Exact retry reads are capacity-neutral, including after audit rotation.
        with self.lock:
            require(not self.write_poisoned and not self.db.in_transaction,
                    'STORE_FAILURE', 'Cannot prove durability on an uncertain connection')
            row = self.db.execute('SELECT scope,record FROM jobs WHERE id=?', (job_id,)).fetchone()
            if row is not None and row['scope'] == scope:
                state = self._decode_record(row).get('_ownership') or {}
                previous_event = state.get('events', {}).get(phase)
                if previous_event is not None:
                    require(previous_event['sha256'] == fingerprint,
                            'STORE_CORRUPT', 'Ownership retry payload changed')
                    return dict(state)
        self._headroom_or_degraded('job ownership transition')
        with self.transaction():
            require(self.db.execute('SELECT 1 FROM job_archives WHERE id=?',
                                    (job_id,)).fetchone() is None,
                    'STORE_ARCHIVED_JOB', 'Archived ownership receipt is immutable')
            row = self.db.execute('SELECT scope,record FROM jobs WHERE id=?',
                                  (job_id,)).fetchone()
            require(row is None or row['scope'] == scope,
                    'STORE_CORRUPT', 'Job scope changed')
            previous = {} if row is None else self._decode_record(row)
            state = previous.get('_ownership') or {
                'schema': 1, 'attempt_id': job_id, 'revision': 0, 'events': {}}
            require(state.get('schema') == 1 and state.get('attempt_id') == job_id,
                    'STORE_CORRUPT', 'Ownership identity changed')
            events = dict(state['events'])
            if phase in events:
                require(events[phase]['sha256'] == fingerprint,
                        'STORE_CORRUPT', 'Ownership retry payload changed')
                return dict(state)
            require(state['revision'] == revision and len(events) < len(phases)
                    and state.get('phase') != 'terminal',
                    'STORE_CORRUPT', 'Ownership revision or terminal fence changed')
            allowed = {
                None: {'admitted', 'restart_unresolved', 'terminal'},
                'admitted': {'queued', 'starting', 'terminal'},
                'queued': {'starting', 'terminal'},
                'starting': {'create_intent', 'terminal'},
                'create_intent': {'owned', 'terminal', 'restart_unresolved'},
                'owned': {'release_intent', 'terminal', 'restart_unresolved'},
                'release_intent': {'started', 'terminal', 'restart_unresolved'},
                'started': {'terminal', 'restart_unresolved'},
                'restart_unresolved': {'terminal'},
            }
            require((phase in allowed.get(state.get('phase'), set())
                     or (phase == 'cancel_intent' and row is not None))
                    and (phase != 'admitted' or row is None),
                    'STORE_CORRUPT', 'Invalid ownership phase transition')
            # Preserve the existing ordinary admission reserve for new work.
            if phase == 'admitted':
                count = self.db.execute('SELECT count(*) FROM audit').fetchone()[0]
                require(count + self._owed_reserve_locked() + 1
                        + AUDIT_ROWS_PER_ACTIVE_JOB <= self.max_audit_rows,
                        'AUDIT_CAPACITY', 'New job must reserve completion headroom')
                self._audit(kind, metadata)
            else:
                self._audit(kind, metadata, essential=True)
            if phase == 'admitted' and metadata.get('request_id') is not None:
                # Bind the existing idempotency reservation before any OS create.
                # An acknowledgement loss can then return this identity without replay.
                key = metadata['request_id']
                request = self.db.execute('SELECT status,result FROM requests WHERE scope=? AND key=?',
                                          (scope, key)).fetchone()
                prior = json.loads(request['result']) if request is not None and request['result'] else None
                same_error = (isinstance(prior, dict) and prior.get('ok') is False
                              and prior.get('data', {}).get('job_id') == job_id)
                require(request is not None and (
                    (request['status'] == 'reserved' and prior is None)
                    or (request['status'] in {'reserved', 'finished'} and same_error)),
                    'STORE_CORRUPT', 'Job request binding changed')
                if prior is None:
                    binding = {'ok': False, 'error': {'code': 'INDETERMINATE',
                        'message': 'Job admitted; reconcile by identity', 'details': {'job_id': job_id}},
                        'data': {'job_id': job_id}}
                    self.db.execute('UPDATE requests SET result=? WHERE scope=? AND key=?',
                                    (canonical(binding), scope, key))
                # A prior same-job failure is retained. This is reconciliation of
                # the frozen failed admission, never a permission to launch again.
            events[phase] = {'sha256': fingerprint, 'revision': revision + 1}
            state = {'schema': 1, 'attempt_id': job_id,
                     'revision': revision + 1,
                     'phase': state.get('phase') if phase == 'cancel_intent' else phase,
                     'events': events}
            value = dict(record, _ownership=state)
            self.db.execute('INSERT INTO jobs VALUES(?,?,?) ON CONFLICT(id) '
                            'DO UPDATE SET record=excluded.record',
                            (job_id, scope, canonical(value)))
            self._owed_cache = None
        return state

    def put_job(self, job_id: str, scope: str, record: dict):
        with self.transaction():
            require(self.db.execute("SELECT 1 FROM job_archives WHERE id=?", (job_id,)).fetchone() is None,
                    "STORE_ARCHIVED_JOB", "Archived job records are immutable")
            existing = self.db.execute("SELECT scope,record FROM jobs WHERE id=?", (job_id,)).fetchone()
            require(existing is None or '_ownership' not in self._decode_record(existing),
                    'STORE_CORRUPT', 'Owned receipts require atomic transitions')
            require(existing is None or existing['scope'] == scope,
                    "STORE_CORRUPT", "Job ownership changed")
            self.db.execute("INSERT INTO jobs VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record", (job_id, scope, canonical(record)))
            self._owed_cache = None

    def get_job(self, job_id: str, scope: str) -> dict:
        with self.lock:
            row = self.db.execute("SELECT record FROM jobs WHERE id=? AND scope=?", (job_id, scope)).fetchone()
            archived = False
            if row is None:
                row = self.db.execute("SELECT id,scope,record,archived_ns,reason,record_sha256 FROM job_archives WHERE id=? AND scope=?",
                                      (job_id, scope)).fetchone()
                archived = row is not None
        require(row is not None, "UNKNOWN_JOB", "No job owned by this scope")
        record = self._decode_record(row)
        if archived:
            record = self._validate_archive(row)
            record.update({'archived': True, 'archived_ns': row['archived_ns'],
                           'archive_reason': row['reason'], 'record_sha256': row['record_sha256']})
        record.pop('_ownership', None)
        return record

    @staticmethod
    def _decode_record(row) -> dict:
        try:
            record = json.loads(row['record'])
        except (TypeError, ValueError):
            raise ControlError('STORE_CORRUPT', 'Stored job record is invalid') from None
        require(isinstance(record, dict), 'STORE_CORRUPT', 'Stored job record is invalid')
        return record

    @classmethod
    def _validate_archive(cls, row) -> dict:
        record = cls._decode_record(row)
        require(record.get('job_id') == row['id'], 'STORE_CORRUPT', 'Archived job identity is invalid')
        require(record.get('status') in TERMINAL_JOB_STATES,
                'STORE_CORRUPT', 'Archived job status is invalid')
        require(type(row['archived_ns']) is int and row['archived_ns'] > 0,
                'STORE_CORRUPT', 'Archived job timestamp is invalid')
        require(isinstance(row['reason'], str) and 1 <= len(row['reason']) <= 64 and row['reason'].isascii(),
                'STORE_CORRUPT', 'Archived job reason is invalid')
        require(digest(record) == row['record_sha256'], 'STORE_CORRUPT', 'Archived job evidence is invalid')
        return record

    def _verify_archives(self) -> None:
        with self.lock:
            overlap = self.db.execute(
                "SELECT 1 FROM jobs INNER JOIN job_archives ON jobs.id=job_archives.id LIMIT 1"
            ).fetchone()
            require(overlap is None, 'STORE_CORRUPT', 'Active and archived job identities overlap')
            rows = self.db.execute(
                "SELECT id,scope,record,archived_ns,reason,record_sha256 FROM job_archives"
            )
            for row in rows:
                self._validate_archive(row)

    def _public_job(self, row, *, archived: bool = False, include_ownership: bool = False) -> dict:
        record = self._decode_record(row)
        if archived:
            record = self._validate_archive(row)
        if not include_ownership:
            record.pop('_ownership', None)
        result = {'id': row['id'], 'scope': row['scope'], **record}
        if archived:
            result.update({'archived': True, 'archived_ns': row['archived_ns'],
                           'archive_reason': row['reason'], 'record_sha256': row['record_sha256']})
        return result

    def jobs(self, scope: str | None = None, *, include_archived: bool = False,
             include_ownership: bool = False) -> list[dict]:
        with self.lock:
            if scope is None:
                rows = list(self.db.execute("SELECT id,scope,record FROM jobs ORDER BY id"))
            else:
                rows = list(self.db.execute("SELECT id,scope,record FROM jobs WHERE scope=? ORDER BY id", (scope,)))
            result = [self._public_job(r, include_ownership=include_ownership) for r in rows]
            if include_archived:
                if scope is None:
                    archived = self.db.execute("SELECT id,scope,record,archived_ns,reason,record_sha256 "
                                               "FROM job_archives ORDER BY archived_ns DESC,id DESC")
                else:
                    archived = self.db.execute("SELECT id,scope,record,archived_ns,reason,record_sha256 "
                                               "FROM job_archives WHERE scope=? ORDER BY archived_ns DESC,id DESC", (scope,))
                result.extend(self._public_job(r, archived=True, include_ownership=include_ownership) for r in archived)
            return result

    def job_status_counts(self) -> dict:
        """Cheap status histogram for telemetry: no record deserialization,
        no stdout materialization."""
        with self.lock:
            rows = self.db.execute(
                "SELECT json_extract(record,'$.status') st, count(*) n FROM jobs GROUP BY st"
            ).fetchall()
        return {str(r['st']): int(r['n']) for r in rows}

    def job_capacity_snapshot(self, scope: str | None = None,
                              protected_ids: set[str] | None = None) -> dict:
        protected = protected_ids or set()
        with self.lock:
            if scope is None:
                rows = list(self.db.execute("SELECT id,scope,record FROM jobs"))
            else:
                rows = list(self.db.execute("SELECT id,scope,record FROM jobs WHERE scope=?", (scope,)))
        decoded = []
        for row in rows:
            decoded.append({'id': row['id'], 'scope': row['scope'], 'record': self._decode_record(row)})
        terminal = [row for row in decoded if row['record'].get('status') in TERMINAL_JOB_STATES]
        eligible = [row for row in terminal if row['id'] not in protected]
        active = [row for row in decoded if row['id'] in protected or row['record'].get('status') in ACTIVE_JOB_STATES]
        return {'scope': scope if scope is not None else '*',
                'stored_records': len(decoded), 'terminal_records': len(terminal),
                'reclaimable_terminal_records': len(eligible), 'active_records': len(active),
                'ineligible_records': len(decoded) - len(eligible),
                'protected_active_records': len([row for row in decoded if row['id'] in protected])}

    def reclaim_terminal_jobs(self, scope: str | None, *, keep_recent: int,
                              protected_ids: set[str] | None = None,
                              reason: str = 'explicit', max_records: int | None = None) -> dict:
        require(type(keep_recent) is int and 0 <= keep_recent <= 10000000,
                'INVALID_ARGUMENT', 'Invalid terminal retention')
        require(scope is None or isinstance(scope, str), 'INVALID_ARGUMENT', 'Invalid job scope')
        require(isinstance(reason, str) and 1 <= len(reason) <= 64 and reason.isascii(),
                'INVALID_ARGUMENT', 'Invalid archive reason')
        require(max_records is None or (type(max_records) is int and 1 <= max_records <= 10000000),
                'INVALID_ARGUMENT', 'Invalid job capacity')
        protected = set(protected_ids or ())
        self._headroom_or_degraded("automatic threshold rotation before terminal reclamation")
        with self.transaction():
            query = "SELECT id,scope,record FROM jobs" if scope is None else \
                    "SELECT id,scope,record FROM jobs WHERE scope=?"
            rows = list(self.db.execute(query) if scope is None else self.db.execute(query, (scope,)))
            decoded = []
            for row in rows:
                decoded.append({'id': row['id'], 'scope': row['scope'], 'record': self._decode_record(row)})

            terminal = [row for row in decoded if row['record'].get('status') in TERMINAL_JOB_STATES]
            eligible = [row for row in terminal if row['id'] not in protected]
            grouped = {}
            for row in eligible:
                grouped.setdefault(row['scope'], []).append(row)
            retained_ids = set()
            for group in grouped.values():
                group.sort(key=lambda row: (row['record'].get('started_ns')
                                            if type(row['record'].get('started_ns')) is int else 0,
                                            row['id']), reverse=True)
                retained_ids.update(row['id'] for row in group[:keep_recent])
            candidates = [row for row in eligible if row['id'] not in retained_ids]
            candidates.sort(key=lambda row: (row['record'].get('started_ns')
                                             if type(row['record'].get('started_ns')) is int else 0,
                                             row['id']))
            if max_records is not None:
                required = max(0, len(decoded) - max_records + 1)
                candidates = candidates[:required]

            archived_ids = []
            affected_scopes = set()
            for row in candidates:
                archived_ns = time.time_ns()
                self.db.execute("INSERT INTO job_archives(id,scope,record,archived_ns,reason,record_sha256) "
                                "VALUES(?,?,?,?,?,?)",
                                (row['id'], row['scope'], canonical(row['record']), archived_ns, reason,
                                 digest(row['record'])))
                deleted = self.db.execute("DELETE FROM jobs WHERE id=? AND scope=?", (row['id'], row['scope']))
                require(deleted.rowcount == 1, 'STORE_CORRUPT', 'Job record changed during archival')
                self._owed_cache = None
                archived_ids.append(row['id'])
                affected_scopes.add(row['scope'])

            active_untouched = len([row for row in decoded
                                    if row['id'] in protected or row['record'].get('status') in ACTIVE_JOB_STATES])
            retained = len(terminal) - len(archived_ids)
            audit_metadata = {
                'scope': scope if scope is not None else '*', 'reason': reason,
                'examined': len(decoded), 'eligible': len(eligible), 'archived': len(archived_ids),
                'retained': retained, 'active_untouched': active_untouched,
                'scopes_affected': sorted(affected_scopes),
                'archived_ids_sha256': digest(sorted(archived_ids)), 'archive_schema': JOB_ARCHIVE_SCHEMA,
            }
            self._audit('job_terminal_reclamation', audit_metadata, essential=True)
            return {**audit_metadata,
                    'archived_job_ids': archived_ids[:64],
                    'archived_job_ids_truncated': len(archived_ids) > 64}

    def verify(self) -> bool:
        prev = "0" * 64
        with self.lock:
            for row in self.db.execute("SELECT * FROM audit ORDER BY seq"):
                expected = hashlib.sha256((prev + row["payload"]).encode()).hexdigest()
                if row["prev"] != prev or row["hash"] != expected:
                    return False
                prev = row["hash"]
        return True

    def close(self):
        with self.lock:
            self.db.close()
            self.lease.close()
