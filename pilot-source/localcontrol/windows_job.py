"""Windows lifetime containment. A Job Object is NOT a privilege/security sandbox.

Accounting is queried only for the owned job handle. No foreign process
enumeration or PID-based lookup exists here.
"""
import ctypes as c
from ctypes import wintypes as w
import os
import threading


class _BasicLimits(c.Structure):
    _fields_ = [('user', c.c_int64), ('job', c.c_int64), ('flags', w.DWORD),
                ('minws', c.c_size_t), ('maxws', c.c_size_t), ('active', w.DWORD),
                ('affinity', c.c_size_t), ('priority', w.DWORD), ('sched', w.DWORD)]


class _IoCounters(c.Structure):
    _fields_ = [(x, c.c_uint64) for x in ('r', 'w', 'o', 'rb', 'wb', 'ob')]


class _ExtendedLimits(c.Structure):
    _fields_ = [('basic', _BasicLimits), ('io', _IoCounters), ('process_mem', c.c_size_t),
                ('job_mem', c.c_size_t), ('peak_process', c.c_size_t), ('peak_job', c.c_size_t)]


class _Accounting(c.Structure):
    _fields_ = [('total_user', c.c_int64), ('total_kernel', c.c_int64),
                ('period_user', c.c_int64), ('period_kernel', c.c_int64),
                ('page_faults', w.DWORD), ('total_processes', w.DWORD),
                ('active_processes', w.DWORD), ('terminated_processes', w.DWORD)]

class _AssociateCompletionPort(c.Structure):
    _fields_ = [('completion_key', c.c_void_p), ('completion_port', w.HANDLE)]


def _nonnegative_int(value):
    return value if type(value) is int and value >= 0 else None


def _cpu_ms_from_counters(user_ns, kernel_ns):
    user_ns = _nonnegative_int(user_ns)
    kernel_ns = _nonnegative_int(kernel_ns)
    if user_ns is None or kernel_ns is None:
        return None
    return (user_ns + kernel_ns) // 1_000_000


def _usage_from_windows_stats(stats: dict) -> dict:
    """Map only observed owned-job counters to Supervisor usage fields."""
    cpu_ms = _cpu_ms_from_counters(stats.get('cpu_user_ns'), stats.get('cpu_kernel_ns'))
    job_peak = _nonnegative_int(stats.get('job_peak_memory_bytes'))
    process_peak = _nonnegative_int(stats.get('peak_memory_bytes'))
    memory_bytes = job_peak if job_peak is not None else process_peak
    return {'cpu_ms': cpu_ms, 'memory_bytes': memory_bytes,
            'disk_bytes': _nonnegative_int(stats.get('write_transfer_bytes'))}


class WindowsJob:
    LIMIT_JOB_TIME = 0x00000004
    LIMIT_ACTIVE_PROCESS = 0x00000008
    LIMIT_PROCESS_MEMORY = 0x00000100
    LIMIT_JOB_MEMORY = 0x00000200
    LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    LIMIT_KEYS = frozenset({'memory_bytes', 'max_processes', 'cpu_ms'})
    MAX_COMPLETION_PACKETS_PER_DRAIN = 16384
    WAIT_TIMEOUT = 258
    COMPLETION_MESSAGES = {
        1: 'end_of_job_time', 2: 'end_of_process_time',
        3: 'active_process_limit', 4: 'active_process_zero',
        6: 'new_process', 7: 'exit_process', 8: 'abnormal_exit_process',
        9: 'process_memory_limit', 10: 'job_memory_limit',
        11: 'notification_limit', 12: 'job_cycle_time_limit', 13: 'silo_terminated',
    }
    LIMIT_EVENT_BREACHES = {
        1: 'cpu_limit_event_in_job_tree',
        2: 'cpu_limit_event_in_job_tree',
        3: 'process_limit_event_in_job_tree',
        9: 'memory_limit_event_in_job_tree',
        10: 'memory_limit_event_in_job_tree',
        11: 'notification_limit_event_in_job_tree',
        12: 'cpu_limit_event_in_job_tree',
    }

    def __init__(self, limits: dict | None = None, *, custody=None):
        if os.name != 'nt':
            raise RuntimeError('Windows only')
        if limits is None:
            limits = {}
        if not isinstance(limits, dict) or not set(limits) <= self.LIMIT_KEYS:
            raise ValueError('invalid job limits')
        clean = {}
        for key, value in limits.items():
            if type(value) is not int or value < 1:
                raise ValueError('invalid job limits')
            clean[key] = value
        if 'memory_bytes' in clean and clean['memory_bytes'] < 1024 * 1024:
            raise ValueError('invalid job limits')
        if 'max_processes' in clean and clean['max_processes'] > 64:
            raise ValueError('invalid job limits')
        if 'cpu_ms' in clean and clean['cpu_ms'] > 24 * 3600 * 1000:
            raise ValueError('invalid job limits')
        self.limits = clean
        self.k = c.WinDLL('kernel32', use_last_error=True)
        self.k.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
        self.k.CreateJobObjectW.restype = w.HANDLE
        self.k.SetInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
        self.k.SetInformationJobObject.restype = w.BOOL
        self.k.QueryInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p]
        self.k.QueryInformationJobObject.restype = w.BOOL
        self.k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.k.AssignProcessToJobObject.restype = w.BOOL
        self.k.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        self.k.TerminateJobObject.restype = w.BOOL
        self.k.CloseHandle.argtypes = [w.HANDLE]
        self.k.CloseHandle.restype = w.BOOL
        self.k.CreateIoCompletionPort.argtypes = [w.HANDLE, w.HANDLE, c.c_size_t, w.DWORD]
        self.k.CreateIoCompletionPort.restype = w.HANDLE
        self.k.GetQueuedCompletionStatus.argtypes = [w.HANDLE, c.POINTER(w.DWORD),
            c.POINTER(c.c_size_t), c.POINTER(c.c_void_p), w.DWORD]
        self.k.GetQueuedCompletionStatus.restype = w.BOOL
        self._monitor_lock = threading.RLock()
        self._completion_port = None
        self._completion_key = None
        self._completion_port_available = False
        self._completion_port_error = None
        self._job_tree_event_counts = {}
        self._job_tree_limit_events = set()
        self.handle = None
        if custody is not None:
            # Retain partially initialized empty Job/IOCP resources as well.
            custody.job = self
        try:
            self.handle = self.k.CreateJobObjectW(None, None)
        except BaseException:
            if custody is not None and self.handle is None:
                custody.job = None
            raise
        if not self.handle:
            if custody is not None:
                custody.job = None
            raise c.WinError(c.get_last_error())
        try:
            self._initialize_completion_port()
        except BaseException:
            if custody is None:
                self.close()
            raise
        info = _ExtendedLimits()
        flags = self.LIMIT_KILL_ON_JOB_CLOSE
        if 'cpu_ms' in clean:
            flags |= self.LIMIT_JOB_TIME
            info.basic.job = clean['cpu_ms'] * 10000
        if 'max_processes' in clean:
            flags |= self.LIMIT_ACTIVE_PROCESS
            info.basic.active = clean['max_processes']
        if 'memory_bytes' in clean:
            flags |= self.LIMIT_JOB_MEMORY
            info.job_mem = clean['memory_bytes']
        info.basic.flags = flags
        if not self.k.SetInformationJobObject(self.handle, 9, c.byref(info), c.sizeof(info)):
            code = c.get_last_error()
            if custody is None:
                self.close()
            raise c.WinError(code)

    def assign(self, popen):
        # Popen retains a handle to THIS process object, not a recycled PID lookup.
        if not self.k.AssignProcessToJobObject(self.handle, w.HANDLE(int(popen._handle))):
            raise c.WinError(c.get_last_error())

    def _initialize_completion_port(self):
        """Associate a private completion port before any process is assigned."""
        self._completion_port = self.k.CreateIoCompletionPort(
            c.c_void_p(-1), None, c.c_size_t(0), 1
        )
        if not self._completion_port:
            raise c.WinError(c.get_last_error())
        self._completion_key = int(c.cast(self.handle, c.c_void_p).value or 0)
        association = _AssociateCompletionPort(
            c.c_void_p(self._completion_key), self._completion_port
        )
        if not self.k.SetInformationJobObject(
                self.handle, 7, c.byref(association), c.sizeof(association)):
            raise c.WinError(c.get_last_error())
        self._completion_port_available = True

    def _set_completion_error(self, code: str):
        if self._completion_port_error is None:
            self._completion_port_error = code

    def _record_completion_message(self, message: int, key: int) -> bool:
        if key != self._completion_key:
            self._set_completion_error('completion_port_wrong_key')
            return False
        name = self.COMPLETION_MESSAGES.get(message)
        if name is None:
            self._set_completion_error('completion_port_invalid_message')
            return False
        self._job_tree_event_counts[name] = self._job_tree_event_counts.get(name, 0) + 1
        breach = self.LIMIT_EVENT_BREACHES.get(message)
        if breach is not None:
            self._job_tree_limit_events.add(breach)
        return True

    def _drain_completion_port_locked(self):
        """Poll this job's private IOCP without blocking; errors remain sticky."""
        if not self._completion_port_available or not self._completion_port:
            self._set_completion_error('completion_port_unavailable')
            return
        for _ in range(self.MAX_COMPLETION_PACKETS_PER_DRAIN):
            message = w.DWORD()
            key = c.c_size_t()
            overlapped = c.c_void_p()
            ok = self.k.GetQueuedCompletionStatus(
                self._completion_port, c.byref(message), c.byref(key),
                c.byref(overlapped), 0
            )
            if not ok:
                error = c.get_last_error()
                if error == self.WAIT_TIMEOUT and not overlapped.value:
                    return
                self._set_completion_error('completion_port_query_failed')
                return
            # Sticky monitor errors do not stop servicing the owned port.
            self._record_completion_message(int(message.value), int(key.value))
        # A full bounded drain cannot establish that the queue is empty.
        self._set_completion_error('completion_port_drain_limit')

    def _monitor_state_locked(self) -> dict:
        return {
            'completion_port_available': bool(self._completion_port_available),
            'completion_port_delivery_guaranteed': False,
            'completion_port_error': self._completion_port_error,
            'job_tree_event_counts': dict(self._job_tree_event_counts),
            'job_tree_limit_events': sorted(self._job_tree_limit_events),
        }

    def stats(self) -> dict:
        """Bounded accounting and nonblocking IOCP drain for this owned job only."""
        with self._monitor_lock:
            self._drain_completion_port_locked()
            monitor = self._monitor_state_locked()
            if not self.handle:
                return {'available': False, 'accounting_available': False,
                        'limits_available': False, 'active_processes': None,
                        'total_processes': None, 'terminated_processes': None,
                        'limits': dict(self.limits), **monitor,
                        'limit_breach': self._breach(
                            _ExtendedLimits(), _Accounting(),
                            have_limits=False, have_accounting=False)}
            limits = _ExtendedLimits()
            have_limits = bool(self.k.QueryInformationJobObject(
                self.handle, 9, c.byref(limits), c.sizeof(limits), None
            ))
            accounting = _Accounting()
            have_accounting = bool(self.k.QueryInformationJobObject(
                self.handle, 1, c.byref(accounting), c.sizeof(accounting), None
            ))
            breach = self._breach(
                limits, accounting, have_limits=have_limits,
                have_accounting=have_accounting
            )
            if not have_limits and not have_accounting:
                return {
                    'available': False, 'accounting_available': False,
                    'limits_available': False, 'active_processes': None,
                    'total_processes': None, 'terminated_processes': None,
                    'limits': dict(self.limits), **monitor,
                    'limit_breach': breach,
                }
            return {
                'available': True,
                'accounting_available': have_accounting,
                'limits_available': have_limits,
                'active_processes': accounting.active_processes if have_accounting else None,
                'total_processes': accounting.total_processes if have_accounting else None,
                'terminated_processes': accounting.terminated_processes if have_accounting else None,
                'cpu_user_ns': accounting.total_user * 100 if have_accounting else None,
                'cpu_kernel_ns': accounting.total_kernel * 100 if have_accounting else None,
                'disk_bytes': limits.io.wb if have_limits else None,
                'peak_memory_bytes': limits.peak_process if have_limits else None,
                'job_peak_memory_bytes': limits.peak_job if have_limits else None,
                'write_transfer_bytes': limits.io.wb if have_limits else None,
                'limits': dict(self.limits), **monitor,
                'limit_breach': breach,
            }

    def _breach(self, limits: _ExtendedLimits, accounting: _Accounting, *,
                have_limits: bool, have_accounting: bool) -> str | None:
        configured = self.limits
        missing = False
        if 'cpu_ms' in configured:
            if not have_accounting:
                missing = True
            else:
                total_100ns = accounting.total_user + accounting.total_kernel
                if total_100ns >= configured['cpu_ms'] * 10000:
                    return 'cpu'
        if 'memory_bytes' in configured:
            if not have_limits:
                missing = True
            else:
                peak = max(limits.peak_job, limits.peak_process)
                if peak >= configured['memory_bytes']:
                    return 'memory'
        if 'max_processes' in configured:
            if not have_accounting:
                missing = True
            elif accounting.active_processes > configured['max_processes']:
                return 'processes'

        observed = getattr(self, '_job_tree_limit_events', set())
        for label in (
                'cpu_limit_event_in_job_tree',
                'notification_limit_event_in_job_tree',
                'memory_limit_event_in_job_tree',
                'process_limit_event_in_job_tree'):
            if label in observed:
                return label
        if ('max_processes' in configured and have_accounting
                and accounting.terminated_processes > 0):
            return 'unattributed_limit_termination'
        if getattr(self, '_completion_port_error', None) is not None:
            return 'monitoring_unavailable'
        if not getattr(self, '_completion_port_available', False):
            return 'monitoring_unavailable'
        if missing:
            return 'accounting_unavailable'
        return None

    def stop(self):
        if self.handle and not self.k.TerminateJobObject(self.handle, 124):
            raise c.WinError(c.get_last_error())

    def close(self):
        """Close only this job and its private completion port; safe to repeat."""
        with self._monitor_lock:
            if self.handle:
                self.k.CloseHandle(self.handle)
                self.handle = None
            if self._completion_port:
                self.k.CloseHandle(self._completion_port)
                self._completion_port = None

    def prove_empty(self, timeout=2):
        """Positive native accounting proof; keep the job handle on uncertainty."""
        import time
        deadline = time.monotonic() + max(0, min(timeout, 2))
        while True:
            stats = self.stats()
            if stats.get('accounting_available') is True and stats.get('active_processes') == 0:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(.02)

    def close_verified(self):
        """Checked close for retained legacy owners after process AND tree proof."""
        with self._monitor_lock:
            if self.handle:
                if not self.prove_empty(timeout=0):
                    raise RuntimeError('OWNED_JOB_NOT_EMPTY')
                if not self.k.CloseHandle(self.handle):
                    raise c.WinError(c.get_last_error())
                self.handle = None
            if self._completion_port:
                if not self.k.CloseHandle(self._completion_port):
                    raise c.WinError(c.get_last_error())
                self._completion_port = None
