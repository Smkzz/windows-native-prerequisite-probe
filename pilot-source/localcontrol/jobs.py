from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import json
import queue
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
import hashlib
from collections import deque
from .errors import ControlError, require
from .policy import Policy
from .pressure import HostPressureMonitor
from .store import Store
from .job_ownership import Owner, safe_failure

SAFE_ENV = {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT', 'TEMP', 'TMP',
            'LANG', 'LC_ALL', 'SYSTEMDRIVE'}

def _resource_usage(record: dict, accounting: dict) -> dict:
    """Add observed owned-job usage without synthesizing unavailable values."""
    from .windows_job import _usage_from_windows_stats
    usage = _usage_from_windows_stats(accounting)
    result = dict(record)
    result.update(usage)
    state = dict(result.get('resource_limit_state') or {})
    state.update(usage)
    result['resource_limit_state'] = state
    return result


def _accounting_exception() -> dict:
    """Fail closed without persisting exception text or synthesizing usage."""
    return {
        'available': False,
        'accounting_available': False,
        'limits_available': False,
        'active_processes': None,
        'total_processes': None,
        'terminated_processes': None,
        'cpu_user_ns': None,
        'cpu_kernel_ns': None,
        'peak_memory_bytes': None,
        'job_peak_memory_bytes': None,
        'write_transfer_bytes': None,
        'disk_bytes': None,
        'limit_breach': 'monitoring_unavailable',
        'completion_port_available': False,
        'completion_port_delivery_guaranteed': False,
        'completion_port_error': 'accounting_exception',
        'job_tree_event_counts': {},
        'job_tree_limit_events': [],
    }


def job_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.upper() in SAFE_ENV}
    env.update({'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8', 'PYTHONUNBUFFERED': '1'})
    return env


def _exe_identity(argv0: str) -> dict:
    """Executable provenance for the durable job record: name + SHA-256.

    Never stores argv contents; secrets must not ride command lines anyway.
    """
    identity = {'name': Path(argv0).name, 'path': argv0, 'sha256': None}
    try:
        path = Path(argv0)
        if path.is_file() and path.stat().st_size <= 512 * 1024 * 1024:
            h = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b''):
                    h.update(chunk)
            identity['sha256'] = h.hexdigest()
    except OSError:
        pass
    return identity


@dataclass
class PendingJob:
    id: str
    scope: str
    project: str
    argv: list[str]
    timeout_ms: int
    limits: dict | None
    executable: dict
    queued_reason: str
    cwd_rel: str | None = None
    scratch: bool = False
    queued_at: float = field(default_factory=time.monotonic)
    queued_ns: int = field(default_factory=time.time_ns)
    status: str = 'queued'
    interruption: str | None = None
    cancel_requested: bool = False
    done: threading.Event = field(default_factory=threading.Event)


@dataclass
class LiveJob:
    id: str
    scope: str
    project: str
    process: subprocess.Popen
    platform_job: object | None
    timeout_ms: int
    sandboxed: bool = False
    limits: dict | None = None
    executable: dict | None = None
    queued_at: float | None = None
    queued_ns: int | None = None
    started: float = field(default_factory=time.monotonic)
    started_ns: int = field(default_factory=time.time_ns)
    last_output_ns: int = 0
    accounting_final: dict | None = None
    status: str = 'running'
    returncode: int | None = None
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    stdout_total: int = 0
    stderr_total: int = 0
    stdin_bytes: int = 0
    stdin_closed: bool = False
    input_queue: queue.Queue = field(default_factory=lambda: queue.Queue(maxsize=16))
    elapsed_final: float | None = None
    cwd: str | None = None
    scratch: bool = False
    done: threading.Event = field(default_factory=threading.Event)
    finalized: threading.Event = field(default_factory=threading.Event)
    terminal_snapshot: dict | None = None
    lock: threading.RLock = field(default_factory=threading.RLock)


class JobManager:
    def __init__(self, policy: Policy, store: Store, *, pressure_monitor=None,
                 restart_verifier=None):
        self.policy, self.store = policy, store
        # Trusted internal seam only. Production/default has no verifier and no
        # tool routes here. Installing an attestor requires separate authorization.
        self.restart_verifier = restart_verifier
        self.live: dict[str, LiveJob] = {}
        self.pending: dict[str, PendingJob] = {}
        self.starting: dict[str, PendingJob] = {}
        self.launching: set[str] = set()
        self.task_attempts: set[str] = set()
        self.pending_order: deque[str] = deque()
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.closed = False
        self.pressure = pressure_monitor or HostPressureMonitor(
            min_free_memory_bytes=policy.min_free_memory_bytes,
            min_free_disk_bytes=policy.min_free_disk_bytes,
            disk_path=str(policy.state_dir),
            max_ephemeral_port_fraction=policy.max_ephemeral_port_fraction,
            ephemeral_port_start=policy.ephemeral_port_start,
            ephemeral_port_count=policy.ephemeral_port_count,
            sample_interval_ms=policy.pressure_sample_interval_ms,
        )
        self.admission_metrics = {
            'queued_total': 0,
            'queue_full_rejections': 0,
            'pressure_deferrals': 0,
            'started_from_queue': 0,
            'max_queue_depth': 0,
        }
        self._scratch: dict[str, Path] = {}
        self._scratch_identity: dict[str, tuple[int, int]] = {}
        self._ownership_init()
        self._recover_startup()
        self.scheduler = threading.Thread(
            target=self._scheduler_loop,
            daemon=True,
            name='localcontrol-admission',
        )
        self.scheduler.start()
    def _active_count_locked(self):
        owners = {jid for jid, owner in self.owners.items()
                  if jid not in self.pending_order or owner.unresolved}
        return len(owners | set(self.startup_unresolved)) + len(self.task_attempts)

    def _base_reserve_task_attempt(self, attempt_id: str, *, restore=False) -> bool:
        with self.condition:
            if attempt_id in self.task_attempts:
                return True
            if self.closed or (not restore and
                    self._active_count_locked() >= self.policy.max_active_jobs):
                return False
            self.task_attempts.add(attempt_id)
            return True

    def release_task_attempt(self, attempt_id: str) -> None:
        with self.condition:
            self.task_attempts.discard(attempt_id)
            self.condition.notify_all()

    def _protected_ids_locked(self):
        return set(self.owners) | set(self.startup_unresolved)

    def _ensure_job_capacity_locked(self) -> None:
        protected = self._protected_ids_locked()
        capacity = self.store.job_capacity_snapshot(protected_ids=protected)
        if capacity['stored_records'] >= self.policy.max_job_records:
            nonterminal = capacity['stored_records'] - capacity['terminal_records']
            keep_recent = min(
                self.policy.terminal_retention,
                max(0, self.policy.max_job_records - nonterminal - 1),
            )
            self.store.reclaim_terminal_jobs(
                None,
                keep_recent=keep_recent,
                protected_ids=protected,
                reason='capacity',
                max_records=self.policy.max_job_records,
            )
            capacity = self.store.job_capacity_snapshot(protected_ids=protected)
        require(
            capacity['stored_records'] < self.policy.max_job_records,
            'JOB_CAPACITY',
            'Job record capacity is full after safe terminal reclamation',
            {
                'max_job_records': self.policy.max_job_records,
                'stored_records': capacity['stored_records'],
                'active_jobs': capacity['active_records'],
                'terminal_jobs': capacity['terminal_records'],
                'reclaimable_terminal_jobs': capacity['reclaimable_terminal_records'],
                'retained_terminal_jobs':
                    capacity['terminal_records'] - capacity['reclaimable_terminal_records'],
            },
        )

    def _queue_position_locked(self, job_id: str) -> int | None:
        try:
            return list(self.pending_order).index(job_id) + 1
        except ValueError:
            return None

    def _base_pending_record(self, job: PendingJob) -> dict:
        with self.lock:
            position = self._queue_position_locked(job.id) if job.status == 'queued' else None
        queued_ms = max(0, round((time.monotonic() - job.queued_at) * 1000, 3))
        record = {
            'job_id': job.id,
            'project': job.project,
            'status': job.status,
            'pid': None,
            'executable': job.executable,
            'returncode': None,
            'elapsed_ms': 0,
            'queued_ms': queued_ms,
            'queued_ns': job.queued_ns,
            'queue_position': position,
            'queued_reason': job.queued_reason,
            'started_ns': None,
            'timeout_ms': job.timeout_ms,
            'last_output_ns': None,
            'silent_ms': queued_ms,
            'stdout': '',
            'stderr': '',
            'stdout_bytes': 0,
            'stderr_bytes': 0,
            'stdout_truncated': False,
            'stderr_truncated': False,
            'stdin_bytes': 0,
            'cpu_user_ns': None,
            'cpu_kernel_ns': None,
            'peak_memory_bytes': None,
            'active_processes': 0,
            'resource_limit_state': {
                'output_cap_reached': False,
                'timed_out': False,
                'limits': job.limits,
                'limit_breach': None,
                'queued': job.status in {'queued', 'starting'},
            },
            'containment': 'not_started',
            'security_sandbox': self.policy.exec_mode == 'appcontainer',
            'isolation': 'pending_admission',
            'cwd': None,
            'scratch': job.scratch,
        }
        if job.interruption:
            record['interruption'] = job.interruption
        return record

    def _reap_scratch(self, project: str) -> None:
        """Unknown/restarted scratch roots require explicit owned maintenance.

        A directory name or absence from the active list is not ownership proof.
        Never recursively delete caller-created siblings during admission.
        """
        return

    def _drop_scratch(self, job_id: str) -> None:
        self._retire_scratch(job_id)

    def _retire_scratch(self, job_id: str) -> None:
        scratch = self._scratch.pop(job_id, None)
        identity = self._scratch_identity.pop(job_id, None)
        if scratch is None:return
        removed = False
        reason = 'retained_nonempty_owned_scratch'
        try:
            info = scratch.lstat()
            if (identity != (int(info.st_dev), int(info.st_ino))
                    or scratch.is_symlink() or getattr(info, 'st_file_attributes', 0) & 1024):
                reason = 'retained_changed_scratch_identity'
            else:
                # One empty-directory removal; no tree traversal or recursive
                # deletion of worker-controlled content in the admission path.
                scratch.rmdir()
                removed = True
                reason = 'empty_owned_scratch_removed'
        except FileNotFoundError:
            reason = 'scratch_missing'
        except OSError:
            pass
        try:
            self.store.audit_essential('job_scratch_cleanup',
                {'job_id': job_id, 'scratch_bytes': None, 'removed': removed, 'reason': reason})
        except Exception:pass

    def _cleanup_scratch(self, job: LiveJob) -> None:
        self._retire_scratch(job.id)

    def _reserve_start_locked(self, pending):
        owner = self.owners[pending.id]
        pending.status = 'starting'
        try:
            self._persist(owner, 'starting', self._raw_snapshot(owner), 'job_starting',
                          {'job_id': pending.id, 'scope': pending.scope})
        except BaseException:
            # Retained but deliberately not executable; stop() can reconcile.
            owner.terminal_status = 'start_failed'
            owner.launch_finished.set()
            raise ControlError('STORE_FAILURE', 'Job admission requires reconciliation',
                               {'job_id': pending.id}) from None
        self.pending.pop(pending.id, None)
        try:
            self.pending_order.remove(pending.id)
        except ValueError:
            pass
        self.starting[pending.id] = pending
        # Claim dispatch under the same lock as reservation, before stop/close
        # can observe the item outside FIFO. Only the launcher releases this claim.
        self.launching.add(pending.id)
        self.condition.notify_all()

    def _finish_pending(self, pending, status, interruption):
        owner = self.owners[pending.id]
        if pending.id not in self.launching:
            owner.launch_finished.set()
        if not self._complete_owner(owner, status, interruption):
            raise ControlError('STORE_FAILURE', 'Owned job requires reconciliation',
                               {'job_id': pending.id})

    def _launch_reserved(self, queued, *, from_queue, raise_errors):
        # _reserve_start_locked registered both owner and launch claim atomically.
        owner = self.owners[queued.id]
        failure = None
        try:
            result = self._launch_reserved_impl(queued, from_queue=from_queue,
                                                raise_errors=raise_errors)
        except BaseException as error:
            failure = error
            owner.terminal_status = ('start_failed' if owner.custody.command_released is False
                                     else 'supervision_error')
            if not owner.unresolved:
                self._fault(owner, owner.custody.stage, 'LAUNCH_FAILED', error)
        finally:
            with self.condition:
                owner.launch_finished.set()
                self.launching.discard(queued.id)
                # Linearize acknowledgement with _fault. A later asynchronous
                # failure is observable through job_read, never a new execution.
                if failure is None and owner.unresolved:
                    failure = ControlError('OWNERSHIP_PENDING', 'Launch supervision unresolved')
                owner.launch_acknowledged = failure is None
                self.condition.notify_all()
        if failure is None and owner.live is None:
            if not self._complete_owner(owner, 'server_shutdown' if self.closed else 'stopped',
                                        'cancelled before command release'):
                failure = ControlError('OWNERSHIP_PENDING', 'Cancellation is unresolved')
        if failure is None:
            with self.condition:
                if not owner.unresolved:
                    return result
                failure = ControlError('OWNERSHIP_PENDING', 'Launch supervision unresolved')
        # No release can be retried, even if a lost commit is found.
        if owner.watcher is not None and owner.watcher.is_alive():
            self._terminate(owner.live, owner.terminal_status or 'supervision_error')
        else:
            self._complete_owner(owner, owner.terminal_status or
                ('start_failed' if owner.custody.command_released is False else 'supervision_error'),
                'owned launch aborted; reconcile by job identity')
        if raise_errors:
            raise ControlError('STORE_FAILURE' if owner.unresolved else 'JOB_SETUP_FAILED',
                'Launch did not return success; reconcile the owned job',
                {'job_id': queued.id, 'launch_diagnostic': owner.facts()}) from None
        return queued.id

    def _launch_reserved_impl(self, queued, *, from_queue, raise_errors):
        from pathlib import Path
        import sys
        from .jobs import LiveJob, job_env
        owner = self.owners[queued.id]
        owner.custody.stage = 'cwd_validation'
        cwd = self.policy.path(queued.project, queued.cwd_rel or '', directory=True)
        require(cwd.is_dir(), 'INVALID_PATH', 'Job working directory must exist')
        platform_job = None
        creation = 0
        if os.name == 'nt':
            from .windows_job import WindowsJob
            owner.custody.stage = 'job_creation'
            platform_job = WindowsJob(queued.limits, custody=owner.custody)
            owner.custody.job = platform_job
            creation = subprocess.CREATE_NO_WINDOW
        is_sandbox = self.policy.exec_mode == 'appcontainer'
        scratch_dir = None
        owner.custody.stage = 'scratch_setup'
        if queued.scratch:
            root = self.policy.path(queued.project, 'lc-job-scratch', directory=True)
            root.mkdir(parents=True, exist_ok=True)
            scratch_dir = root / queued.id
            scratch_dir.mkdir(parents=True, exist_ok=False)
            self._scratch[queued.id] = scratch_dir
            info = scratch_dir.lstat()
            self._scratch_identity[queued.id] = (int(info.st_dev), int(info.st_ino))
        scratch_env = ({'TEMP': str(scratch_dir), 'TMP': str(scratch_dir),
            'TMPDIR': str(scratch_dir), 'LOCALCONTROL_JOB_SCRATCH': str(scratch_dir)}
            if scratch_dir is not None else {})
        with self.condition:
            if queued.cancel_requested or self.closed:
                owner.failure = safe_failure('creation', 'CANCELLED_BEFORE_RELEASE')
                return queued.id
        self._persist(owner, 'create_intent', self._raw_snapshot(owner),
            'job_create_intent', {'job_id': queued.id, 'scope': queued.scope})
        if is_sandbox:
            from .appcontainer import spawn
            owner.custody.stage = 'worker_manifest'
            manifest = json.loads(Path(self.policy.workers[queued.project]['manifest']).read_text(encoding='utf-8'))
            env = {k: v for k, v in os.environ.items()
                   if k.upper() in {'SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'LOCALAPPDATA'}}
            env.update({'TEMP': str(Path(manifest.get('temp', str(cwd / 'tmp')))),
                'TMP': str(Path(manifest.get('temp', str(cwd / 'tmp')))),
                'TMPDIR': str(Path(manifest.get('temp', str(cwd / 'tmp')))),
                'USERPROFILE': str(Path(manifest.get('home', str(cwd / 'home')))),
                'PATH': manifest['runtime'] + ';' + os.path.join(env.get('SYSTEMROOT', r'C:\Windows'), 'System32'),
                'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8', 'PYTHONUNBUFFERED': '1'})
            env.update(scratch_env)
            proc = spawn(queued.argv, cwd, env, manifest['profile_name'], platform_job,
                         custody=owner.custody)
        live = LiveJob(queued.id, queued.scope, queued.project, proc, platform_job,
            queued.timeout_ms, sandboxed=is_sandbox, limits=queued.limits,
            executable=queued.executable, queued_at=queued.queued_at,
            queued_ns=queued.queued_ns, cwd=str(cwd), scratch=queued.scratch)
        live.status = 'starting'
        owner.live = live
        with self.condition:
            self.live[queued.id] = live
            # Starting remains registered until the owned receipt commits.
        self._save(live)
        with self.condition:
            self.starting.pop(queued.id, None)
            self.condition.notify_all()
        readers = [threading.Thread(target=self._drain, args=(live, name), daemon=True)
                   for name in ('stdout', 'stderr')]
        owner.readers = readers
        for reader in readers:
            reader.start()
        owner.watcher = threading.Thread(target=self._watch, args=(live, readers), daemon=True)
        owner.watcher.start()
        intent = self._raw_snapshot(owner)
        intent['launch_diagnostic']['command_released'] = None
        self._persist(owner, 'release_intent', intent, 'job_release_intent',
                      {'job_id': queued.id, 'scope': queued.scope})
        with self.condition:
            # Linearization point: cancellation before this claim prevents release.
            # Cancellation after it is running/uncertain cancellation, never
            # retrospectively described as "command not run".
            if queued.cancel_requested or self.closed:
                self._terminate(live, 'server_shutdown' if self.closed else 'stopped')
                return queued.id
            owner.release_claimed = True
            owner.custody.command_released = None
        owner.custody.stage = 'command_release'
        proc.release()
        owner.custody.command_released = True
        with self.condition:
            cancelled = queued.cancel_requested or self.closed
            if not cancelled:
                live.status = 'running'
        if cancelled:
            self._terminate(live, 'server_shutdown' if self.closed else 'stopped')
        threading.Thread(target=self._write_input, args=(live,), daemon=True).start()
        self._persist(owner, 'started', self._raw_snapshot(owner), 'job_started',
                      {'job_id': queued.id, 'scope': queued.scope, 'from_queue': from_queue})
        with self.condition:
            if from_queue:
                self.admission_metrics['started_from_queue'] += 1
        return queued.id
    def start(self, scope: str, project: str, argv: list[str], timeout_ms: int,
              limits: dict | None = None, cwd: str | None = None,
              scratch: bool = False, request_id: str | None = None) -> str:
        require(os.name == 'nt' and self.policy.exec_mode == 'appcontainer',
                'SANDBOX_REQUIRED', 'Ownership candidate requires Windows AppContainer execution')
        require(
            type(timeout_ms) is int and 1 <= timeout_ms <= self.policy.max_timeout_ms,
            'INVALID_TIMEOUT',
            'Invalid job lifetime',
        )
        if limits is not None:
            require(
                isinstance(limits, dict)
                and set(limits) <= {'memory_bytes', 'max_processes', 'cpu_ms'},
                'INVALID_LIMITS',
                'Invalid job resource limits',
            )
            for value in limits.values():
                require(
                    type(value) is int and 1 <= value <= 8 * 1024 * 1024 * 1024,
                    'INVALID_LIMITS',
                    'Invalid job resource limits',
                )

        if cwd is not None:
            # Early validation only; _launch_reserved re-resolves at execution.
            resolved = self.policy.path(project, cwd, directory=True)
            require(resolved.is_dir(), 'INVALID_PATH', 'Job working directory must exist')
        if scratch:
            require(self.policy.projects[project].writable, 'READ_ONLY',
                    'Scratch directories require a writable project')
        exe_identity = _exe_identity(argv[0])
        pressure = self.pressure.snapshot()
        with self.condition:
            require(not self.closed, 'SHUTTING_DOWN', 'Server is shutting down')
            require(not self.storage_fenced, 'STORE_FAILURE',
                    'Job ownership reconciliation fences new admission')
            if scratch:
                self._reap_scratch(project)
            self._ensure_job_capacity_locked()
            active = self._active_count_locked()
            backlog = bool(self.pending_order)
            should_queue = (
                backlog
                or active >= self.policy.max_active_jobs
                or pressure.pressured
            )
            if should_queue and len(self.pending) >= self.policy.max_queued_jobs:
                self.admission_metrics['queue_full_rejections'] += 1
                raise ControlError(
                    'QUEUE_FULL',
                    'Execution queue is full; wait for existing work to drain',
                    {
                        'max_queued_jobs': self.policy.max_queued_jobs,
                        'active_jobs': active,
                        'queued_jobs': len(self.pending),
                    },
                )

            jid = uuid.uuid4().hex
            reason = (
                'host_pressure' if pressure.pressured
                else ('concurrency' if active >= self.policy.max_active_jobs
                      else ('fifo_backlog' if backlog else 'immediate'))
            )
            queued = PendingJob(
                jid,
                scope,
                project,
                list(argv),
                timeout_ms,
                limits,
                exe_identity,
                reason,
                cwd_rel=cwd,
                scratch=scratch,
            )
            owner = self._register_owner(queued)
            try:
                self._persist(owner, 'admitted', self._raw_snapshot(owner),
                    'job_start_intent', {'job_id': jid, 'scope': scope, 'project': project,
                    'argv0_name': exe_identity['name'], 'argv0_sha256': exe_identity['sha256'],
                    'request_id': request_id})
                if should_queue:
                    record = self._raw_snapshot(owner)
                    record['queue_position'] = len(self.pending_order) + 1
                    self._persist(owner, 'queued', record, 'job_queued',
                        {'job_id': jid, 'scope': scope, 'reason': reason,
                         'queue_depth': len(self.pending_order) + 1})
                    self.pending[jid] = queued
                    self.pending_order.append(jid)
                    self.admission_metrics['queued_total'] += 1
                    self.admission_metrics['max_queue_depth'] = max(
                        self.admission_metrics['max_queue_depth'], len(self.pending_order))
                    if pressure.pressured:
                        self.admission_metrics['pressure_deferrals'] += 1
                    self.condition.notify_all()
                    return jid
                self._reserve_start_locked(queued)
            except BaseException as error:
                owner.terminal_status = 'start_failed'
                self._fault(owner, owner.phase, 'PERSISTENCE_UNCERTAIN', error)
                owner.launch_finished.set()
                raise ControlError('STORE_FAILURE', 'Job admission requires reconciliation',
                                   {'job_id': jid}) from None

        return self._launch_reserved(queued, from_queue=False, raise_errors=True)

    def _scheduler_loop(self) -> None:
        poll_s = max(0.1, self.policy.pressure_sample_interval_ms / 1000)
        while True:
            queued = None
            with self.condition:
                if self.closed:
                    return
                if self.storage_fenced:
                    self.condition.wait(timeout=.25)
                    continue
                if self.pending_order and self._active_count_locked() < self.policy.max_active_jobs:
                    pressure = self.pressure.snapshot()
                    if pressure.pressured:
                        self.admission_metrics['pressure_deferrals'] += 1
                        self.condition.wait(timeout=poll_s)
                        continue
                    jid = self.pending_order[0]
                    queued = self.pending.get(jid)
                    if queued is not None:
                        try:
                            self._reserve_start_locked(queued)
                        except ControlError as error:
                            if error.code != 'STORE_FAILURE':
                                raise
                            queued = None
                            continue
                if queued is None:
                    self.condition.wait(timeout=min(0.25, poll_s))
                    continue
            try:
                self._launch_reserved(queued, from_queue=True, raise_errors=False)
            except Exception as error:
                # A failed launch must not kill the scheduler thread: the item
                # was already consumed by _reserve_start_locked, so each escape
                # costs at most one queue slot and stale rows reconcile on
                # restart. Surface it through admission metrics instead of
                # silently stalling the queue.
                self.admission_metrics['launch_errors'] = \
                    self.admission_metrics.get('launch_errors', 0) + 1
                self.admission_metrics['last_launch_error'] = \
                    'OWNED_LAUNCH_REQUIRES_RECONCILIATION'

    def admission_status(self) -> dict:
        snapshot = self.pressure.snapshot()
        with self.lock:
            active = self._active_count_locked()
            queued = len(self.pending_order)
            metrics = dict(self.admission_metrics)
        return {
            'profile': 'throughput-first',
            'active_jobs': active,
            'max_active_jobs': self.policy.max_active_jobs,
            'queued_jobs': queued,
            'max_queued_jobs': self.policy.max_queued_jobs,
            'memory_headroom_bytes': self.policy.min_free_memory_bytes,
            'ephemeral_port_threshold': self.policy.max_ephemeral_port_fraction,
            'pressure': snapshot.public(),
            'metrics': metrics,
        }
    def _drain(self, job: LiveJob, stream: str):
        pipe = getattr(job.process, stream)
        try:
            while chunk := pipe.read(4096):
                with job.lock:
                    setattr(job, stream + '_total', getattr(job, stream + '_total') + len(chunk))
                    job.last_output_ns = time.time_ns()
                    buf = getattr(job, stream)
                    remaining = self.policy.max_output_bytes - len(buf)
                    if remaining > 0:
                        buf.extend(chunk[:remaining])
        finally:
            pipe.close()

    def _terminate(self, live, status):
        owner = self.owners.get(live.id)
        if owner is None:
            return True
        with self.condition:
            owner.pending.cancel_requested = True
            if owner.terminal_record is None:
                live.status = status
        # Request only. A native error must not skip the separate stop-intent
        # persistence attempt or discard custody. Proof/close stay centralized.
        try:
            with owner.custody.native_lock:
                if owner.custody.closed:
                    return True
                owner.custody.termination_requested = True
                if owner.custody.job is not None:
                    owner.custody.job.stop()
                elif live.process.poll() is None:
                    if os.name == 'nt':
                        live.process.kill()
                    else:
                        os.killpg(live.process.pid, signal.SIGKILL)
        except BaseException as error:
            self._fault(owner, 'cancellation', 'NATIVE_STOP_UNCONFIRMED', error)
            return False
        return True

    def _watch(self, live, readers):
        owner = self.owners[live.id]
        try:
            remaining = max(.001, live.timeout_ms / 1000 - (time.monotonic() - live.started))
            try:
                rc = live.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                self._terminate(live, 'timed_out')
                rc = live.process.wait(timeout=2)
            if not owner.custody.stop_and_prove():
                self._fault(owner, 'supervision', 'TERMINATION_UNCONFIRMED')
                return
            if live.platform_job is not None:
                live.accounting_final = live.platform_job.stats()
            for reader in readers:
                reader.join(timeout=2)
            with live.lock:
                live.returncode = rc
                live.elapsed_final = round((time.monotonic() - live.started) * 1000, 3)
                if live.status in {'starting', 'running'}:
                    live.status = ('start_failed' if owner.custody.command_released is False else
                                   ('completed' if rc == 0 else 'failed')
                                   if owner.custody.command_released is True else 'supervision_error')
                if any(r.is_alive() for r in readers):
                    live.status = 'capture_incomplete'
            if not owner.launch_finished.wait(2):
                self._fault(owner, 'supervision', 'LAUNCH_FINALIZATION_PENDING')
                return
            self._complete_owner(owner, live.status)
        except BaseException as error:
            self._fault(owner, 'supervision', 'SUPERVISION_FAILED', error)
            self._complete_owner(owner, 'supervision_error')

    def _accounting(self, job: LiveJob) -> dict:
        if job.accounting_final is not None:
            return job.accounting_final
        if job.platform_job is not None:
            try:
                return job.platform_job.stats()
            except Exception:
                return _accounting_exception()
        return {'available': False}

    def _base_record(self, job: LiveJob) -> dict:
        elapsed = job.elapsed_final if job.elapsed_final is not None else round((time.monotonic() - job.started) * 1000, 3)
        accounting = self._accounting(job)
        last = job.last_output_ns or None
        silent_from = last if last is not None else job.started_ns
        truncated = job.stdout_total > len(job.stdout) or job.stderr_total > len(job.stderr)
        queued_ms = (0 if job.queued_at is None
                     else max(0, round((job.started - job.queued_at) * 1000, 3)))
        record = {'job_id': job.id, 'project': job.project, 'status': job.status, 'pid': job.process.pid,
                'executable': job.executable,
                'returncode': job.returncode, 'elapsed_ms': elapsed,
                'queued_ms': queued_ms, 'queued_ns': job.queued_ns,
                'started_ns': job.started_ns, 'timeout_ms': job.timeout_ms,
                'last_output_ns': last, 'silent_ms': max(0, int((time.time_ns() - silent_from) / 1_000_000)),
                'stdout': bytes(job.stdout).decode('utf-8', errors='replace'),
                'stderr': bytes(job.stderr).decode('utf-8', errors='replace'),
                'stdout_bytes': job.stdout_total, 'stderr_bytes': job.stderr_total,
                'stdout_truncated': job.stdout_total > len(job.stdout),
                'stderr_truncated': job.stderr_total > len(job.stderr),
                'stdin_bytes': job.stdin_bytes,
                'cpu_user_ns': accounting.get('cpu_user_ns'),
                'cpu_kernel_ns': accounting.get('cpu_kernel_ns'),
                'peak_memory_bytes': accounting.get('peak_memory_bytes'),
                'active_processes': accounting.get('active_processes'),
                'resource_limit_state': {'output_cap_reached': truncated, 'timed_out': job.status == 'timed_out',
                                         'limits': job.limits, 'limit_breach': accounting.get('limit_breach'),
                                         'accounting_available': accounting.get('accounting_available'),
                                         'limits_available': accounting.get('limits_available'),
                                         'active_processes': accounting.get('active_processes'),
                                         'total_processes': accounting.get('total_processes'),
                                         'terminated_processes': accounting.get('terminated_processes'),
                                         'job_peak_memory_bytes': accounting.get('job_peak_memory_bytes'),
                                         'completion_port_available': accounting.get('completion_port_available'),
                                         'completion_port_delivery_guaranteed': accounting.get('completion_port_delivery_guaranteed'),
                                         'completion_port_error': accounting.get('completion_port_error'),
                                         'job_tree_event_counts': accounting.get('job_tree_event_counts'),
                                         'job_tree_limit_events': accounting.get('job_tree_limit_events')},
                'containment': 'windows_job_object' if os.name == 'nt' else 'posix_process_group',
                'security_sandbox': job.sandboxed,
                'isolation': 'appcontainer_zero_capabilities' if job.sandboxed else 'none',
                'cwd': job.cwd,
                'scratch': job.scratch}
        return _resource_usage(record, accounting)

    def _save(self, live):
        owner = self.owners[live.id]
        self._persist(owner, 'owned', self._raw_snapshot(owner), 'job_owned',
                      {'job_id': live.id, 'scope': live.scope})

    def _base_read(self, scope: str, job_id: str, wait_ms: int = 0) -> dict:
        require(
            type(wait_ms) is int and 0 <= wait_ms <= self.policy.max_wait_ms,
            'INVALID_WAIT',
            'Invalid synchronous wait',
        )
        deadline = time.monotonic() + wait_ms / 1000
        observed_owner = None
        while True:
            with self.condition:
                observed_owner = self.owners.get(job_id) or observed_owner
                job = self.live.get(job_id)
                queued = self.pending.get(job_id) or self.starting.get(job_id)
                if job is not None:
                    require(job.scope == scope, 'UNKNOWN_JOB', 'No job owned by this scope')
                    break
                if queued is not None:
                    require(queued.scope == scope, 'UNKNOWN_JOB', 'No job owned by this scope')
                    remaining = deadline - time.monotonic()
                    if wait_ms == 0 or remaining <= 0:
                        return self._pending_record(queued)
                    self.condition.wait(timeout=remaining)
                    continue
            if (observed_owner is not None and observed_owner.terminal_committed
                    and observed_owner.custody.closed):
                require(observed_owner.pending.scope == scope, 'UNKNOWN_JOB', 'No job owned by this scope')
                return json.loads(json.dumps(observed_owner.terminal_record))
            return self.store.get_job(job_id, scope)

        remaining = max(0.0, deadline - time.monotonic())
        if wait_ms:
            job.done.wait(remaining)
        with job.lock:
            return self._record(job)
    def input(self, scope: str, job_id: str, text: str, eof: bool = False):
        require(
            self.policy.exec_mode in {'trusted_local', 'appcontainer'},
            'INPUT_DISABLED',
            'Interactive stdin is unavailable in recipe mode',
        )
        require(
            isinstance(text, str) and len(text.encode('utf-8')) <= 4096,
            'INPUT_TOO_LARGE',
            'Input limit exceeded',
        )
        with self.lock:
            queued = self.pending.get(job_id) or self.starting.get(job_id)
            job = self.live.get(job_id)
        if queued is not None:
            require(queued.scope == scope, 'UNKNOWN_JOB', 'No job owned by this scope')
            raise ControlError('JOB_NOT_RUNNING', 'Job is queued or starting')
        require(job is not None and job.scope == scope, 'UNKNOWN_JOB', 'No job owned by this scope')
        with job.lock:
            require(
                not job.done.is_set() and job.status == 'running',
                'JOB_FINISHED',
                'Job is not accepting input',
            )
            data = text.encode('utf-8')
            require(
                job.stdin_bytes + len(data) <= 1048576,
                'INPUT_TOO_LARGE',
                'Job stdin capacity reached',
            )
            require(not job.stdin_closed, 'STDIN_CLOSED', 'Job stdin is closing')
            try:
                job.input_queue.put_nowait((data, eof))
            except queue.Full:
                raise ControlError('INPUT_BACKPRESSURE', 'Stdin queue is full')
            job.stdin_bytes += len(data)
            job.stdin_closed = eof
        return {
            'job_id': job_id,
            'queued_bytes': len(data),
            'eof_queued': eof,
            'delivered': 'not_acknowledged_by_child',
        }

    def _write_input(self, job: LiveJob):
        # Never hold the job lock across a pipe write. A nonreading child must not
        # prevent the watchdog from enforcing its timeout.
        while not job.done.is_set():
            try:
                data, eof = job.input_queue.get(timeout=.1)
            except queue.Empty:
                continue
            try:
                job.process.stdin.write(data)
                job.process.stdin.flush()
                if eof:
                    job.process.stdin.close()
                    return
            except (OSError, ValueError):
                return

    def stop(self, scope, job_id):
        with self.condition:
            owner = self.owners.get(job_id)
            if owner is None:
                if job_id in self.startup_unresolved:
                    require(self.startup_unresolved[job_id]['scope'] == scope,
                            'UNKNOWN_JOB', 'No job owned by this scope')
                    if job_id in self.startup_recovery:
                        return self._retry_startup_storage(scope, job_id)
                    raise ControlError('OWNERSHIP_PENDING',
                        'Restart ownership needs approved operator reconciliation')
                return self.store.get_job(job_id, scope)
            require(owner.pending.scope == scope, 'UNKNOWN_JOB', 'No job owned by this scope')
            owner.pending.cancel_requested = True
            owner.stop_requested = True
            try:
                self.pending_order.remove(job_id)
            except ValueError:
                pass
            if time.monotonic() < owner.next_retry:
                return self.read(scope, job_id, 0)
            owner.next_retry = time.monotonic() + 5
            launching = job_id in self.launching
        if launching and owner.release_claimed and owner.live is not None:
            self._terminate(owner.live, 'server_shutdown' if self.closed else 'stopped')
        if not self._persist_cancel_intent(owner):
            return self.read(scope, job_id, 0)
        if launching:
            # After the release claim, cancellation requests native stop now;
            # no handles are closed while launch is in flight. The launcher also
            # rechecks after ResumeThread so this race cannot swallow cancellation.
            return self.read(scope, job_id, 0)
        owner.launch_finished.set()
        if owner.watcher is not None and owner.watcher.is_alive():
            self._terminate(owner.live, 'server_shutdown' if self.closed else 'stopped')
            owner.live.done.wait(2)
            return self.read(scope, job_id, 0)
        status = owner.terminal_status or ('stopped' if not self.closed else 'server_shutdown')
        self._complete_owner(owner, status, 'owned cancellation; command never replayed')
        return self.read(scope, job_id, 0)
    def archive_terminal_jobs(self, scope: str) -> dict:
        with self.lock:
            require(not self.closed, 'SHUTTING_DOWN', 'Server is shutting down')
            require(not self.storage_fenced, 'STORE_FAILURE',
                    'Job ownership reconciliation fences new admission')
            return self.store.reclaim_terminal_jobs(
                scope,
                keep_recent=self.policy.terminal_retention,
                protected_ids=self._protected_ids_locked(),
                reason='explicit',
            )

    def close(self):
        deadline = time.monotonic() + 30
        with self.condition:
            self.closed = True
            owners = list(self.owners.values())
            for owner in owners:
                owner.pending.cancel_requested = True
            self.condition.notify_all()
        # All cancellation flags are set before any fallible persistence.
        for owner in owners:
            if time.monotonic() >= deadline:
                break
            if owner.pending.id in self.launching and owner.release_claimed and owner.live is not None:
                self._terminate(owner.live, 'server_shutdown')
            if not self._persist_cancel_intent(owner, shutdown=True):
                continue
            if owner.pending.id not in self.launching:
                owner.launch_finished.set()
                if owner.watcher is not None and owner.watcher.is_alive():
                    self._terminate(owner.live, 'server_shutdown')
                else:
                    self._complete_owner(owner, owner.terminal_status or 'server_shutdown')
        if threading.current_thread() is not self.scheduler:
            self.scheduler.join(timeout=max(0, deadline-time.monotonic()))
        with self.condition:
            while self.owners and time.monotonic() < deadline:
                self.condition.wait(timeout=min(.1, max(0, deadline-time.monotonic())))
            if self.owners:
                raise ControlError('SHUTDOWN_PENDING', 'Owned handles or receipts remain unresolved')

    def _ownership_init(self):
        self.owners = {}
        self.startup_unresolved = {}
        self.startup_reconciliation = {}
        self.startup_recovery = {}
        self.startup_next_retry = {}
        self.startup_retry_lock = threading.RLock()
        self.storage_fenced = False
    def _register_owner(self, pending):
        owner = Owner(pending)
        self.owners[pending.id] = owner
        return owner
    def _fault(self, owner, stage, reason, error=None):
        with self.condition:
            if owner.terminal_committed and owner.custody.closed:
                return
            owner.unresolved = True
            owner.failure = safe_failure(stage, reason, error)
            owner.pending.cancel_requested = True
            self.storage_fenced = True
            try:
                self.pending_order.remove(owner.pending.id)
            except ValueError:
                pass
            self.condition.notify_all()
    def _persist(self, owner, phase, record, kind, metadata):
        with owner.persist_lock:
            # Retry an indeterminate predecessor before any new transition.
            if owner.transition is not None:
                old_phase, revision, frozen, old_kind, old_meta = owner.transition
                try:
                    state = self.store.commit_job_transition(owner.pending.id,
                        owner.pending.scope, old_phase, revision, json.loads(frozen),
                        old_kind, json.loads(old_meta))
                except BaseException as error:
                    self._fault(owner, old_phase, 'PERSISTENCE_UNCERTAIN', error)
                    raise
                owner.revision = state['revision']
                owner.phase = state['phase']
                owner.transition = None
                if old_phase == phase:
                    return
            frozen = json.dumps(record, sort_keys=True, allow_nan=False)
            frozen_meta = json.dumps(metadata, sort_keys=True, allow_nan=False)
            owner.transition = (phase, owner.revision, frozen, kind, frozen_meta)
            try:
                state = self.store.commit_job_transition(owner.pending.id,
                    owner.pending.scope, phase, owner.revision, json.loads(frozen),
                    kind, json.loads(frozen_meta))
            except BaseException as error:
                self._fault(owner, phase, 'PERSISTENCE_UNCERTAIN', error)
                raise
            owner.revision, owner.phase = state['revision'], state['phase']
            owner.transition = None
    def _raw_snapshot(self, owner):
        value = (self._base_record(owner.live) if owner.live is not None else
                 self._base_pending_record(owner.pending))
        if owner.live is not None and not owner.terminal_committed:
            value['observed_terminal_status'] = owner.live.status
            value['status'] = ('running' if owner.custody.command_released is True else 'starting')
        value['launch_diagnostic'] = owner.facts()
        return value
    def _recover_startup(self):
        for old in self.store.jobs(include_ownership=True):
            if old.get('status') not in {'queued', 'starting', 'running', 'ownership_unresolved'}:
                continue
            scope, jid = old.pop('scope'), old.pop('id')
            state = old.pop('_ownership', {})
            phase = state.get('phase')
            no_create = (phase in {'admitted', 'queued', 'starting'} or
                         (not state and old.get('status') == 'queued'))
            target = 'interrupted' if no_create else 'ownership_unresolved'
            # Repeated restart of an unresolved row is read-only and never replays.
            if old.get('status') != 'ownership_unresolved':
                old.update(status=target, interruption='daemon restart; command not replayed')
                prior_diag = old.get('launch_diagnostic') or {}
                old['launch_diagnostic'] = dict(prior_diag,
                    stage='restart_recovery', reason_code='RESTART_RECONCILIATION_REQUIRED',
                    winerror=None, command_released=(False if no_create else
                        True if phase == 'started' else None),
                    operator_intervention_required=not no_create)
                token = ('terminal' if no_create else 'restart_unresolved',
                         state.get('revision', 0), json.dumps(old, sort_keys=True),
                         json.dumps({'job_id': jid, 'scope': scope, 'status': target}, sort_keys=True))
                try:
                    self.store.commit_job_transition(jid, scope, token[0], token[1],
                        json.loads(token[2]), 'job_recovered', json.loads(token[3]))
                except BaseException:
                    self.startup_recovery[jid] = token
                    target = 'ownership_unresolved'
            if target == 'ownership_unresolved':
                self.startup_unresolved[jid] = dict(old, status='ownership_unresolved', scope=scope)
                self.storage_fenced = True
    def reserve_task_attempt(self, attempt_id, *, restore=False):
        with self.condition:
            if self.storage_fenced and not restore:
                return False
            return self._base_reserve_task_attempt(attempt_id, restore=restore)
    def ownership_status(self):
        with self.condition:
            return {'admission_fenced': self.storage_fenced,
                    'retained_owners': len(self.owners),
                    'unresolved_owners': sum(o.unresolved for o in self.owners.values()),
                    'startup_unresolved': len(self.startup_unresolved),
                    'operator_intervention_required': self.storage_fenced}
    def _pending_record(self, pending):
        result = self._base_pending_record(pending)
        owner = self.owners.get(pending.id)
        if owner is not None:
            result['launch_diagnostic'] = owner.facts()
            if owner.unresolved:
                result['status'] = 'ownership_unresolved'
        return result
    def _record(self, live):
        result = self._base_record(live)
        owner = self.owners.get(live.id)
        if owner is None:
            # A synchronous reader may have captured LiveJob before retirement.
            # Return the frozen committed receipt, including launch diagnostics.
            if live.terminal_snapshot is not None:
                return json.loads(json.dumps(live.terminal_snapshot))
            return self.store.get_job(live.id, live.scope)
        if owner is not None:
            result['launch_diagnostic'] = owner.facts()
            if owner.unresolved:
                result['observed_terminal_status'] = owner.terminal_status or live.status
                result['status'] = 'ownership_unresolved'
            elif not owner.terminal_committed and live.status not in {'running', 'starting'}:
                result['observed_terminal_status'] = live.status
                result['status'] = 'stopping' if owner.pending.cancel_requested else 'finalizing'
        return result
    def _retire_owner(self, owner):
        require(owner.terminal_committed and owner.custody.closed,
                'OWNERSHIP_PENDING', 'Owner cannot be removed')
        jid = owner.pending.id
        with self.condition:
            if owner.live is not None:
                owner.live.terminal_snapshot = json.loads(json.dumps(owner.terminal_record))
            self.pending.pop(jid, None)
            self.starting.pop(jid, None)
            self.live.pop(jid, None)
            self.owners.pop(jid, None)
            try:
                self.pending_order.remove(jid)
            except ValueError:
                pass
            owner.pending.done.set()
            if owner.live is not None:
                owner.live.done.set()
                owner.live.finalized.set()
            self.storage_fenced = (bool(self.startup_unresolved)
                or any(o.unresolved for o in self.owners.values())
                or self.store.write_poisoned)
            self.condition.notify_all()
        # Only after native quiescence and durable terminal commit. Existing
        # empty-exact-scratch cleanup remains conservative and non-recursive.
        self._drop_scratch(jid)
    def _complete_owner(self, owner, status, interruption=None):
        with owner.terminal_lock:
            if owner.terminal_committed and owner.custody.closed:
                return True
            if not owner.launch_finished.is_set():
                self._fault(owner, 'cleanup', 'OWNERSHIP_NOT_PROVEN')
                return False
            if not owner.custody.quiescence_frozen:
                if not owner.custody.stop_and_prove():
                    self._fault(owner, 'cleanup', 'TERMINATION_UNCONFIRMED')
                    return False
                # Launch is finished and cannot create/release again. This proof
                # remains valid across partial checked-handle cleanup retries.
                owner.custody.quiescence_frozen = True
            for reader in owner.readers:
                if reader.ident is not None and reader is not threading.current_thread():
                    reader.join(timeout=2)
            if any(reader.is_alive() for reader in owner.readers):
                self._fault(owner, 'capture', 'CAPTURE_FINALIZATION_PENDING')
                return False
            with owner.persist_lock:
                if owner.terminal_record is None:
                    owner.terminal_status = status
                    record = self._raw_snapshot(owner)
                    record.update(status=status)
                    if interruption:
                        record['interruption'] = interruption
                    record['launch_diagnostic'] = dict(owner.facts(),
                        durable_terminal_receipt=True, operator_intervention_required=False,
                        native_quiescence_proven=True,
                        handle_cleanup_order='after_terminal_commit')
                    owner.terminal_record = record
                    owner.terminal_metadata = {'job_id': owner.pending.id,
                        'scope': owner.pending.scope, 'status': owner.terminal_status,
                        'returncode': record.get('returncode'), 'stop_requested': owner.stop_requested}
                try:
                    kind = 'job_finished' if owner.live is not None else 'job_queue_terminal'
                    self._persist(owner, 'terminal', owner.terminal_record, kind,
                                  owner.terminal_metadata)
                    owner.terminal_committed = True
                except BaseException as error:
                    self._fault(owner, 'terminal', 'PERSISTENCE_OR_CLEANUP_PENDING', error)
                    return False
            try:
                owner.custody.close_verified()
            except BaseException as error:
                self._fault(owner, 'cleanup', 'HANDLE_CLOSE_PENDING', error)
                return False
            self._retire_owner(owner)
            return True
    def read(self, scope, job_id, wait_ms=0):
        with self.condition:
            old = self.startup_unresolved.get(job_id)
            if old is not None:
                require(old['scope'] == scope, 'UNKNOWN_JOB', 'No job owned by this scope')
                return {k: v for k, v in old.items() if k != 'scope'}
            owner = self.owners.get(job_id)
            if owner is not None and job_id not in self.live and job_id not in self.pending and job_id not in self.starting:
                require(owner.pending.scope == scope, 'UNKNOWN_JOB', 'No job owned by this scope')
                result = self._raw_snapshot(owner)
                result['status'] = 'ownership_unresolved'
                return result
        return self._base_read(scope, job_id, wait_ms)

    def reconcile_startup(self, scope, job_id, *, evidence):
        """Internal operator seam; never a tool or a PID-control path.

        The separately authorized verifier authenticates native/offline evidence,
        expiry, replay domain and principal. JSON alone is never authority. It must
        prove the EXACT attempt cannot execute again and its owned tree is gone;
        PID absence or matching process name alone is insufficient. No adapter is
        installed by this patch. Storage-only retries use the frozen decision.
        """
        with self.startup_retry_lock:
            with self.condition:
                old = self.startup_unresolved.get(job_id)
                require(old is not None and old['scope'] == scope,
                        'UNKNOWN_JOB', 'No unresolved startup owner in this scope')
            frozen = self.startup_reconciliation.get(job_id)
            if frozen is None:
                require(self.restart_verifier is not None, 'OWNERSHIP_PENDING',
                        'Approved operator attestor is not installed')
                rows = self.store.jobs(scope=scope, include_ownership=True)
                row = next((r for r in rows if r['id'] == job_id), None)
                require(row is not None, 'OWNERSHIP_PENDING', 'Startup receipt is unavailable')
                from .store import digest
                binding = {'job_id': job_id, 'scope': scope, 'record_sha256': digest(row)}
                proof = self.restart_verifier.verify(evidence, expected=binding)
                require(isinstance(proof, dict) and proof.get('authorized') is True
                        and proof.get('quiescent') is True
                        and all(proof.get(k) == v for k, v in binding.items())
                        and isinstance(proof.get('proof_sha256'), str)
                        and len(proof['proof_sha256']) == 64
                        and all(ch in '0123456789abcdef' for ch in proof['proof_sha256']),
                        'OWNERSHIP_PENDING', 'Approved quiescence evidence is required')
                state = row.pop('_ownership', {})
                row.pop('id', None)
                row.pop('scope', None)
                row.update(status='interrupted', interruption='approved reconciliation; command not replayed')
                row['launch_diagnostic'] = dict(row.get('launch_diagnostic') or {},
                    reason_code='OPERATOR_RECONCILED', termination_confirmed=True,
                    durable_terminal_receipt=True, operator_intervention_required=False)
                meta = {'job_id': job_id, 'scope': scope, 'status': 'interrupted',
                        'proof_sha256': proof['proof_sha256'], 'record_sha256': binding['record_sha256']}
                frozen = (state.get('revision', 0), json.dumps(row, sort_keys=True),
                          json.dumps(meta, sort_keys=True))
                self.startup_reconciliation[job_id] = frozen
            revision, body, metadata = frozen
            # Atomic terminal marker makes a lost COMMIT acknowledgement retryable.
            # No process is created, reopened by PID, resumed or terminated here.
            self.store.commit_job_transition(job_id, scope, 'terminal', revision,
                json.loads(body), 'job_reconciled', json.loads(metadata))
            with self.condition:
                self.startup_unresolved.pop(job_id, None)
                self.startup_reconciliation.pop(job_id, None)
                self.storage_fenced = (bool(self.startup_unresolved)
                    or any(o.unresolved for o in self.owners.values()) or self.store.write_poisoned)
                self.condition.notify_all()
            return self.store.get_job(job_id, scope)

    def _retry_startup_storage(self, scope, job_id):
        # Existing job_stop may retry ONLY a frozen storage decision. It cannot
        # adjudicate native ambiguity or accept caller-supplied process evidence.
        now = time.monotonic()
        if now < self.startup_next_retry.get(job_id, 0):
            return self.read(scope, job_id, 0)
        self.startup_next_retry[job_id] = now + 5
        phase, revision, body, metadata = self.startup_recovery[job_id]
        try:
            self.store.commit_job_transition(job_id, scope, phase, revision,
                json.loads(body), 'job_recovered', json.loads(metadata))
        except BaseException:
            return self.read(scope, job_id, 0)
        self.startup_recovery.pop(job_id, None)
        self.startup_next_retry.pop(job_id, None)
        if phase == 'terminal':
            self.startup_unresolved.pop(job_id, None)
        self.storage_fenced = (bool(self.startup_unresolved)
            or any(o.unresolved for o in self.owners.values()) or self.store.write_poisoned)
        self.condition.notify_all()
        return self.read(scope, job_id, 0)

    def _persist_cancel_intent(self, owner, *, shutdown=False):
        # Cancellation flags/native stop are applied BEFORE this fallible write.
        # Terminal row+audit still commit atomically; cancellation intent is its
        # own earlier row+audit marker, independent of termination success.
        with owner.persist_lock:
            if owner.stop_intent_committed or owner.terminal_committed:
                return True
            if owner.terminal_record is not None:
                # A quiescent terminal decision exists, but is not yet durable.
                # Reconcile it explicitly; never acknowledge merely frozen data.
                try:
                    kind = 'job_finished' if owner.live is not None else 'job_queue_terminal'
                    self._persist(owner, 'terminal', owner.terminal_record, kind,
                                  owner.terminal_metadata)
                except BaseException:
                    return False
                owner.terminal_committed = True
                return True
            try:
                self._persist(owner, 'cancel_intent', self._raw_snapshot(owner),
                    'job_shutdown_intent' if shutdown else 'job_stop_intent',
                    {'job_id': owner.pending.id, 'scope': owner.pending.scope,
                     'reason': 'server_shutdown' if shutdown else 'caller_stop'})
            except BaseException:
                return False
            owner.stop_intent_committed = True
            return True
