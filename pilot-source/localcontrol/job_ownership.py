"""Retained legacy-job custody. No command replay, PID reopening, or policy override."""
from dataclasses import dataclass, field
import json
import os
import signal
import subprocess
import threading
import time
from .errors import ControlError, require


def safe_failure(stage, reason, error=None):
    value = {'stage': stage, 'reason_code': reason}
    # Diagnostic adapters can expose hostile attributes; retention must still finish.
    try:
        code = getattr(error, 'winerror', None) if isinstance(error, OSError) else None
    except BaseException:
        code = None
    value['winerror'] = code if type(code) is int and 0 <= code <= 0xffffffff else None
    return value


@dataclass
class Custody:
    job: object = None
    process: object = None
    api: object = None
    pi: object = None
    assigned: bool = False
    stage: str = 'admission'
    ever_created: bool = False
    quiescence_frozen: bool = False
    command_released: bool | None = False
    termination_requested: bool = False
    termination_confirmed: bool = True
    closed: bool = False
    native_lock: threading.RLock = field(default_factory=threading.RLock)

    def bind_native(self, api, pi):
        # The mutable PI is retained BEFORE CreateProcessW fills it.
        self.api, self.pi = api, pi
        self.termination_confirmed = False

    def created(self):
        if self.pi is not None:
            self.ever_created = self.ever_created or bool(self.pi.hProcess)
        self.ever_created = self.ever_created or self.process is not None
        return self.ever_created

    def stop_and_prove(self):
        with self.native_lock:
            try:
                return self._stop_and_prove_locked()
            except BaseException:
                self.termination_confirmed = False
                return False

    def _stop_and_prove_locked(self):
        self.termination_requested = self.created() or self.job is not None
        errors = []
        if self.job is not None:
            try:
                self.job.stop()
            except BaseException as error:
                errors.append(error)
        process = self.process
        handle = (getattr(process, '_handle', None) if process is not None else
                  (self.pi.hProcess if self.pi is not None else None))
        if self.api is not None and handle:
            try:
                self.api.terminate(handle, 125)
            except BaseException as error:
                errors.append(error)
            exited = self.api.wait(handle, 2000) == 0
        elif process is not None:
            try:
                if os.name != 'nt':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            except BaseException as error:
                errors.append(error)
            try:
                process.wait(timeout=2)
                exited = process.poll() is not None
            except BaseException:
                exited = False
        else:
            exited = not self.created()
        # Absence of a handle is never substituted for an accounting sample.
        if self.job is not None:
            try:
                tree_empty = self.job.prove_empty(timeout=2)
            except BaseException:
                tree_empty = False
        else:
            tree_empty = exited
            if os.name != 'nt' and process is not None:
                try:
                    os.killpg(process.pid, 0)
                    tree_empty = False
                except ProcessLookupError:
                    tree_empty = True
                except OSError:
                    tree_empty = False
        self.termination_confirmed = bool(exited and tree_empty)
        return self.termination_confirmed

    def close_verified(self):
        with self.native_lock:
            return self._close_verified_locked()

    def _close_verified_locked(self):
        require(self.termination_confirmed, 'OWNERSHIP_PENDING',
                'Owned termination is not confirmed')
        if self.closed:
            return
        process = self.process
        if self.api is not None:
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                for name in ('_thread', '_token', '_handle'):
                    handle = getattr(process, name, None)
                    if handle:
                        self.api.check(self.api.close(handle))
                        setattr(process, name, None)
                if process._sid:
                    self.api.free_sid(process._sid)
                    process._sid = None
            elif self.pi is not None:
                for name in ('hThread', 'hProcess'):
                    handle = getattr(self.pi, name)
                    if handle:
                        self.api.check(self.api.close(handle))
                        setattr(self.pi, name, None)
        elif process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            if os.name == 'nt' and getattr(process, '_handle', None):
                # Popen's handle object owns CloseHandle; native wait was proved above.
                process._handle.Close()
        if self.job is not None:
            self.job.close_verified()
        self.closed = True


@dataclass
class Owner:
    pending: object
    custody: Custody = field(default_factory=Custody)
    live: object = None
    revision: int = 0
    phase: str = 'registered'
    transition: tuple | None = None
    terminal_record: dict | None = None
    terminal_status: str | None = None
    terminal_metadata: dict | None = None
    stop_requested: bool = False
    stop_intent_committed: bool = False
    launch_acknowledged: bool = False
    terminal_committed: bool = False
    unresolved: bool = False
    failure: dict = field(default_factory=lambda: safe_failure('admission', 'NONE'))
    launch_finished: threading.Event = field(default_factory=threading.Event)
    persist_lock: threading.RLock = field(default_factory=threading.RLock)
    terminal_lock: threading.RLock = field(default_factory=threading.RLock)
    next_retry: float = 0.0
    readers: list = field(default_factory=list)
    watcher: object = None
    release_claimed: bool = False

    def facts(self):
        return {**self.failure, 'ownership_id': self.pending.id,
                'process_created': self.custody.created(),
                'job_ownership_established': self.custody.assigned,
                'command_released': self.custody.command_released,
                'cancellation_requested': self.pending.cancel_requested,
                'termination_requested': self.custody.termination_requested,
                'termination_confirmed': self.custody.termination_confirmed,
                'durable_terminal_receipt': True if self.terminal_committed else None,
                'operator_intervention_required': self.unresolved}
