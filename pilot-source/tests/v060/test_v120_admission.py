"""Bounded admission logic tests; no Windows containment claims."""
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from localcontrol.jobs import JobManager
from localcontrol.v120_admission import TaskAdmission, RunnerLease
from localcontrol.v120_runner import RunnerError, TaskOnlyRunner


class TaskAdmissionTests(unittest.TestCase):
    def test_state_lease_excludes_a_second_connection_until_close(self):
        from pathlib import Path
        from tests.project_fixtures import ProjectTemporaryDirectory
        fixture=ProjectTemporaryDirectory(prefix='lease-')
        self.addCleanup(fixture.cleanup)
        lease=RunnerLease(Path(fixture.name))
        try:
            with self.assertRaisesRegex(ValueError, 'V120_RUNNER_ALREADY_ACTIVE'):
                RunnerLease(Path(fixture.name))
        finally:lease.close()
        replacement=RunnerLease(Path(fixture.name))
        replacement.close()

    def manager(self, *, ordinary=0, maximum=4):
        manager = object.__new__(JobManager)
        manager.policy = SimpleNamespace(max_active_jobs=maximum)
        manager.live = {str(i): SimpleNamespace(done=threading.Event()) for i in range(ordinary)}
        manager.starting = {}
        manager.task_attempts = set()
        manager.lock = threading.RLock()
        manager.condition = threading.Condition(manager.lock)
        manager.closed = False
        manager._ownership_init()
        manager.pending_order = []
        manager.owners = {jid: SimpleNamespace(unresolved=False) for jid in manager.live}
        return manager

    def test_shared_limit_counts_ordinary_and_task_jobs(self):
        manager = self.manager(ordinary=3)
        self.assertTrue(manager.reserve_task_attempt('first'))
        self.assertFalse(manager.reserve_task_attempt('second'))
        self.assertEqual(manager._active_count_locked(), 4)
        manager.release_task_attempt('first')
        self.assertTrue(manager.reserve_task_attempt('second'))

    def test_parallel_reservation_cannot_oversubscribe(self):
        manager = self.manager()
        with ThreadPoolExecutor(max_workers=8) as pool:
            result = list(pool.map(manager.reserve_task_attempt, map(str, range(32))))
        self.assertEqual(sum(result), 4)
        self.assertEqual(manager._active_count_locked(), 4)

    def test_restore_holds_uncertain_attempts_above_limit(self):
        manager = self.manager(maximum=1)
        self.assertTrue(manager.reserve_task_attempt('old-a', restore=True))
        self.assertTrue(manager.reserve_task_attempt('old-b', restore=True))
        self.assertFalse(manager.reserve_task_attempt('new'))
        manager.release_task_attempt('old-a')
        self.assertFalse(manager.reserve_task_attempt('new'))
        manager.release_task_attempt('old-b')
        self.assertTrue(manager.reserve_task_attempt('new'))

    def test_closed_manager_rejects_new_task_attempt(self):
        manager = self.manager()
        manager.closed = True
        self.assertFalse(manager.reserve_task_attempt('new'))

    def test_capacity_rejection_precedes_any_worker_preparation(self):
        runner = object.__new__(TaskOnlyRunner)
        runner.admission = TaskAdmission(1)
        runner.lock = threading.RLock()
        runner.lifecycle = threading.Condition(runner.lock)
        runner.inflight = set()
        runner.closed = threading.Event()
        runner.admitting = set()
        runner.admission.reserve_task_attempt('old')
        runner._scope = lambda: {'task_id': 'task'}
        runner._workload = lambda *_: {'workload_id': 'workload'}
        runner._manifest = lambda *_: {}
        runner._preflight = lambda *_: ({}, 'a' * 64)
        runner._attempt_bindings = lambda *_: {'attempt_id': 'b' * 32}
        runner.ledger = SimpleNamespace(latest=lambda *_: None)
        calls = []
        runner._get_broker = lambda: SimpleNamespace(snapshot_subject_parent=lambda *_: calls.append('prepare'))
        with self.assertRaisesRegex(RunnerError, 'V120_ACTIVE_JOB_LIMIT'):
            runner.launch({'task_id': 'task', 'workload_id': 'workload',
                           'preflight_request_id': 'preflight', 'launch_request_id': 'launch',
                           'request_id': 'request'})
        self.assertEqual(calls, [])

    def test_preclaim_failure_releases_capacity(self):
        runner=self.runner_for_launch()
        def fail(*_args):raise RunnerError('SNAPSHOT_UNAVAILABLE')
        runner._launch_reserved=fail
        with self.assertRaisesRegex(RunnerError,'SNAPSHOT_UNAVAILABLE'):
            runner.launch(self.launch_args())
        self.assertEqual(runner.admission.attempts,set())
        self.assertEqual(runner.admitting,set())

    def test_claimed_failure_retains_uncertain_capacity(self):
        runner=self.runner_for_launch()
        def fail(*_args):
            runner.ledger.latest=lambda *_: {'kind':'failed','cleanup':{'cleaned':False}}
            raise RunnerError('STOP_UNCONFIRMED')
        runner._launch_reserved=fail
        with self.assertRaisesRegex(RunnerError,'STOP_UNCONFIRMED'):
            runner.launch(self.launch_args())
        self.assertEqual(runner.admission.attempts,{'b'*32})

    def test_duplicate_in_progress_launch_does_not_release_another_reservation(self):
        runner=self.runner_for_launch()
        runner.admission.reserve_task_attempt('b'*32)
        runner.admitting.add('b'*32)
        with self.assertRaisesRegex(RunnerError,'V120_LAUNCH_PENDING'):
            runner.launch(self.launch_args())
        self.assertEqual(runner.admission.attempts,{'b'*32})

    def runner_for_launch(self):
        runner=object.__new__(TaskOnlyRunner)
        runner.admission=TaskAdmission(1)
        runner.lock=threading.RLock();runner.closed=threading.Event();runner.admitting=set()
        runner.lifecycle=threading.Condition(runner.lock);runner.inflight=set()
        runner._scope=lambda: {'task_id':'task'}
        runner._workload=lambda *_: {'workload_id':'workload'}
        runner._manifest=lambda *_: {}
        runner._preflight=lambda *_: ({},'a'*64)
        runner._attempt_bindings=lambda *_: {'attempt_id':'b'*32}
        runner.ledger=SimpleNamespace(latest=lambda *_: None)
        runner._get_broker=lambda: object()
        return runner

    def launch_args(self):
        return {'task_id':'task','workload_id':'workload','preflight_request_id':'preflight',
                'launch_request_id':'launch','request_id':'request'}

    def test_release_proof_survives_restart(self):
        from pathlib import Path
        from tests.project_fixtures import ProjectTemporaryDirectory
        fixture=ProjectTemporaryDirectory(prefix='restart-admission-')
        self.addCleanup(fixture.cleanup)
        args=dict(scope_provider=lambda:None,registry_provider=lambda:None,
                  preflight_ledger=None,start_monitor=False)
        runner=TaskOnlyRunner(Path(fixture.name),b'k'*32,**args)
        attempt='a'*32;receipt='b'*64
        runner.ledger.claim_receipt(receipt,attempt,{'kind':'claimed','attempt_id':attempt,
                                   'preflight_receipt_sha256':receipt})
        runner.admission.reserve_task_attempt(attempt)
        runner.ledger.append({'kind':'interrupted','attempt_id':attempt,
                              'reason':'owned_job_missing_after_restart'})
        runner._release_capacity(attempt)
        self.assertTrue(runner.ledger.latest(attempt)['capacity_released'])
        runner.close()
        restarted=TaskOnlyRunner(Path(fixture.name),b'k'*32,**args)
        try:self.assertEqual(restarted.admission.attempts,set())
        finally:restarted.close()

    def test_proven_clean_failure_releases_slot_even_when_release_audit_fails(self):
        runner=self.runner_for_launch();attempt='b'*32
        runner.clock=lambda:0
        runner.admission.reserve_task_attempt(attempt)
        runner.ledger.latest=lambda *_:{'kind':'failed','cleanup':{'cleaned':True}}
        def fail(*_):raise RunnerError('AUDIT_UNAVAILABLE')
        runner.ledger.append=fail
        with self.assertRaisesRegex(RunnerError,'AUDIT_UNAVAILABLE'):
            runner._terminal_result(attempt,runner.ledger.latest(attempt))
        self.assertEqual(runner.admission.attempts,set())

    def test_close_drains_an_admission_before_closing_the_lease(self):
        runner=self.runner_for_launch()
        entered=threading.Event();proceed=threading.Event();lease_closed=threading.Event()
        runner.monitor=None;runner.live={};runner.cancelled=set()
        runner.ledger.close=lambda:None
        runner.lease=SimpleNamespace(close=lease_closed.set)
        def prepare(*_args):
            entered.set()
            self.assertTrue(proceed.wait(2))
            raise RunnerError('V120_RUNNER_CLOSED')
        runner._launch_reserved=prepare
        errors=[]
        def launch():
            try:runner.launch(self.launch_args())
            except RunnerError as exc:errors.append(exc.code)
        launch_thread=threading.Thread(target=launch)
        launch_thread.start();self.assertTrue(entered.wait(2))
        close_thread=threading.Thread(target=runner.close)
        close_thread.start();self.assertFalse(lease_closed.wait(.05))
        proceed.set();launch_thread.join(2);close_thread.join(2)
        self.assertFalse(launch_thread.is_alive());self.assertFalse(close_thread.is_alive())
        self.assertTrue(lease_closed.is_set());self.assertEqual(errors,['V120_RUNNER_CLOSED'])

    def closing_runner(self,stopped):
        runner=self.runner_for_launch();runner.monitor=None;runner.cancelled=set();runner.clock=lambda:0
        runner.admission.reserve_task_attempt('b'*32);runner.closed_handles=[]
        runner.live={'b'*32:(None,SimpleNamespace(close=lambda:runner.closed_handles.append('job')))}
        runner.ledger.latest=lambda *_:{'kind':'failed','cleanup':{'cleaned':False}}
        runner.ledger.append=lambda *_:None
        runner.ledger.close=lambda:runner.closed_handles.append('ledger')
        runner.lease=SimpleNamespace(close=lambda:runner.closed_handles.append('lease'))
        runner._stop_owned_job=lambda *_:stopped
        return runner

    def test_successful_close_releases_slots_and_is_idempotent(self):
        runner=self.closing_runner(True);runner.close();runner.close()
        self.assertEqual(runner.live,{})
        self.assertEqual(runner.admission.attempts,set())
        self.assertEqual(runner.closed_handles,['job','ledger','lease'])

    def test_unconfirmed_stop_preserves_lease_and_live_ownership(self):
        runner=self.closing_runner(False)
        with self.assertRaisesRegex(RunnerError,'V120_SHUTDOWN_PENDING'):runner.close()
        self.assertEqual(runner.closed_handles,[])
        self.assertIn('b'*32,runner.live)
        self.assertEqual(runner.admission.attempts,{'b'*32})

    def test_process_cleanup_failure_preserves_retryable_ownership(self):
        for failing_method in ['capture_summary','close_handles']:
            with self.subTest(failing_method=failing_method):
                runner=self.closing_runner(True)
                process=SimpleNamespace(capture_summary=lambda **_:None,close_handles=lambda:None)
                def fail(*_a,**_kw):raise OSError('owned process cleanup failed')
                setattr(process,failing_method,fail)
                job=runner.live['b'*32][1];runner.live['b'*32]=(process,job)
                with self.assertRaisesRegex(RunnerError,'V120_SHUTDOWN_PENDING'):runner.close()
                self.assertEqual(runner.closed_handles,[])
                self.assertIn('b'*32,runner.live)
                self.assertEqual(runner.admission.attempts,{'b'*32})


if __name__ == '__main__':unittest.main()
