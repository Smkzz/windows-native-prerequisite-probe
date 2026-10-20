"""Fail-closed admission for the task plane, shared with ordinary jobs."""
import sqlite3
import threading
from pathlib import Path


class TaskAdmission:
    def __init__(self, maximum: int):
        if type(maximum) is not int or maximum < 1:
            raise ValueError('V120_ADMISSION_CONFIG')
        self.maximum = maximum
        self.lock = threading.RLock()
        self.attempts = set()

    def reserve_task_attempt(self, attempt_id, *, restore=False):
        with self.lock:
            if attempt_id in self.attempts:
                return True
            if not restore and len(self.attempts) >= self.maximum:
                return False
            self.attempts.add(attempt_id)
            return True

    def release_task_attempt(self, attempt_id):
        with self.lock:
            self.attempts.discard(attempt_id)


class RunnerLease:
    """A protected-state SQLite exclusive lock, held for the runner lifetime.

    A second process or API instance cannot create a separate task admission
    pool for the same state. Closing/crashing releases the OS file locks; the
    authenticated attempt ledger supplies conservative restart reservations.
    """
    def __init__(self, state: Path):
        self.db = sqlite3.connect(str(state / 'runner-lease.sqlite3'), timeout=0,
                                  isolation_level=None, check_same_thread=False)
        try:
            self.db.execute('BEGIN EXCLUSIVE')
        except BaseException:
            self.db.close()
            raise ValueError('V120_RUNNER_ALREADY_ACTIVE') from None

    def close(self):
        self.db.close()
