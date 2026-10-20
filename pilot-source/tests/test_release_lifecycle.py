"""Verifier timeout and conservative scratch-retirement regressions."""
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from localcontrol.facade import Facade
from localcontrol.jobs import JobManager
from localcontrol.errors import ControlError
import threading

class AppContainerPipeOwnershipTests(unittest.TestCase):
    """Real descriptors with mocked process APIs; native Q01 covers actual IO."""
    def exercise(self, fail_assignment=False):
        import os
        from localcontrol import appcontainer as app
        descriptors=[];real_pipe=os.pipe
        def pipe():
            pair=real_pipe();descriptors.extend(pair);return pair
        def init(_attrs,_count,_flags,size):size._obj.value=128;return True
        def derive(_profile,sid):sid._obj.value=123;return 0
        def create(*args):
            pi=args[-1]._obj
            pi.hProcess=101;pi.hThread=102;pi.dwProcessId=999
            return True
        def token(_handle,_access,result):result._obj.value=456;return True
        api=SimpleNamespace(init=init,derive=derive,create=create,open_token=token,
            update=lambda *_:True,check=lambda ok:self.assertTrue(ok),
            get_times=lambda *_:True,delete=lambda *_:None,close=lambda *_:True,
            free_sid=lambda *_:None,terminate=lambda *_:True,wait=lambda *_:0)
        def assign(_proc):
            if fail_assignment:raise RuntimeError('assignment failed')
        job=SimpleNamespace(handle=789,assign=assign)
        with patch.object(app,'WinAPI',return_value=api), \
             patch('localcontrol.policy.no_links'),patch.object(app,'_valid_worker_environment',return_value=True), \
             patch.object(app.os,'pipe',side_effect=pipe), \
             patch.object(app.AppProcess,'verify_sandbox'):
            if fail_assignment:
                with self.assertRaisesRegex(RuntimeError,'assignment failed'):
                    app.spawn(['python.exe','-c','pass'],Path.cwd(),{},'LocalControl.Unit',job)
                proc=None
            else:
                proc=app.spawn(['python.exe','-c','pass'],Path.cwd(),{},'LocalControl.Unit',job)
        return proc,descriptors

    def test_success_keeps_parent_pipe_descriptors_until_process_wrapper_close(self):
        import os
        proc,descriptors=self.exercise()
        try:
            for stream in (proc.stdin,proc.stdout,proc.stderr):os.fstat(stream.fileno())
            self.assertEqual(sum(self.is_open(fd) for fd in descriptors),3)
        finally:proc.close_handles()
        self.assertFalse(any(self.is_open(fd) for fd in descriptors))

    def test_failure_after_transfer_closes_every_pipe_descriptor(self):
        _proc,descriptors=self.exercise(fail_assignment=True)
        self.assertFalse(any(self.is_open(fd) for fd in descriptors))

    @staticmethod
    def is_open(fd):
        import os
        try:os.fstat(fd);return True
        except OSError:return False

class NamedAttemptJobPortTests(unittest.TestCase):
    def test_owner_monitor_fault_never_claims_known_history(self):
        from localcontrol import v120_runner as runner
        job=runner.NamedAttemptJob.__new__(runner.NamedAttemptJob)
        job._completion_port_error='completion_port_query_failed'
        with patch.object(runner.WindowsJob,'stats',return_value={
                'completion_port_available':True,'completion_port_error':job._completion_port_error,
                'limit_breach':'monitoring_unavailable'}):
            receipt=job.stats()
        self.assertEqual(receipt['monitor_role'],'owner_monitor_unavailable')
        self.assertEqual(receipt['completion_history'],'unknown')

    def test_reopen_is_an_observer_and_never_replaces_the_owner_port(self):
        from localcontrol import v120_runner as runner
        calls=[]
        def opened(access,inherit,name):
            self.assertEqual(access,0x0002000C)
            self.assertFalse(inherit)
            return 33
        kernel=SimpleNamespace(OpenJobObjectW=opened,
            CloseHandle=lambda handle:calls.append(('close',handle)))
        def base(instance,limits):
            instance.k=kernel;instance.handle=11;instance._completion_port=22
            instance._completion_port_available=True;instance._completion_port_error=None
            instance._monitor_lock=threading.RLock();instance.limits=limits
        with patch.object(runner.WindowsJob,'__init__',base), \
             patch.object(runner.NamedAttemptJob,'_initialize_completion_port',side_effect=AssertionError('observer stole port')), \
             patch.object(runner.NamedAttemptJob,'_verify_security'), \
             patch.object(runner.NamedAttemptJob,'_verify_limits'):
            observer=runner.NamedAttemptJob.reopen({},'LocalControl.Unit')
        self.assertFalse(observer._completion_port_available)
        self.assertIsNone(observer._completion_port)
        self.assertEqual(observer._completion_port_error,'reopened_observer_history_unknown')
        with patch.object(runner.WindowsJob,'stats',return_value={
                'completion_port_available':False,'limit_breach':'monitoring_unavailable'}):
            receipt=observer.stats()
        self.assertEqual(receipt['monitor_role'],'observer')
        self.assertEqual(receipt['completion_history'],'unknown')
        self.assertEqual(receipt['limit_breach'],'monitoring_unavailable')
        observer.close()
        self.assertEqual(calls,[('close',11),('close',22),('close',33)])

    def exercise(self,fail_attach=False):
        from localcontrol import v120_runner as runner
        calls=[]
        def create(*_):runner.c.set_last_error(0);return 33
        def convert(_text,_rev,out,_size):out._obj.value=123;return True
        kernel=SimpleNamespace(CreateJobObjectW=create,CloseHandle=lambda h:calls.append(('close',h)),LocalFree=lambda *_:None)
        def base_init(instance,limits):
            instance.k=kernel;instance.handle=11;instance._completion_port=22
            instance._monitor_lock=threading.RLock();instance.limits=limits
        def attach(instance):
            calls.append(('attach',instance.handle))
            if fail_attach:raise OSError('attach failed')
            instance._completion_port=44
        def limits(instance):
            self.assertEqual(instance._completion_port,44);calls.append(('limits',instance.handle))
        with patch.object(runner.WindowsJob,'__init__',base_init), \
             patch.object(runner.c,'WinDLL',return_value=SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=convert)), \
             patch.object(runner.NamedAttemptJob,'_initialize_completion_port',attach), \
             patch.object(runner.NamedAttemptJob,'_set_limits',limits), \
             patch.object(runner.NamedAttemptJob,'_verify_security',lambda obj:calls.append(('security',obj.handle))):
            if fail_attach:
                with self.assertRaisesRegex(OSError,'attach failed'):runner.NamedAttemptJob({},'LocalControl.Unit','fixed-sddl')
            else:
                job=runner.NamedAttemptJob({},'LocalControl.Unit','fixed-sddl');job.close()
        return calls

    def test_named_job_receives_fresh_port_before_limits_or_security_checks(self):
        calls=self.exercise();self.assertLess(calls.index(('attach',33)),calls.index(('limits',33)))
        self.assertIn(('security',33),calls);self.assertIn(('close',22),calls);self.assertIn(('close',44),calls)

    def test_failed_port_attachment_closes_the_new_named_job(self):
        calls=self.exercise(fail_attach=True);self.assertIn(('close',33),calls)
        self.assertNotIn(('limits',33),calls)

class ObserverTerminalReceiptTests(unittest.TestCase):
    def runner(self):
        from localcontrol.v120_runner import TaskOnlyRunner,AttemptLedger
        runner=TaskOnlyRunner.__new__(TaskOnlyRunner)
        runner.ledger=AttemptLedger(Path(':memory:'),bytes(range(32)))
        self.addCleanup(runner.ledger.close)
        runner.ledger.append({'kind':'resumed','attempt_id':'owned'})
        runner.lock=threading.RLock();runner.cancelled=set();runner.inflight=set();runner.live={}
        runner.clock=lambda:123;runner._release_capacity=lambda _:None
        runner._owned_event=lambda *_a,**_kw:({'attempt_id':'owned'},None)
        stats={'monitor_role':'observer','completion_history':'unknown',
            'completion_port_available':False,'completion_port_error':'reopened_observer_history_unknown',
            'limit_breach':'monitoring_unavailable','active_processes':0}
        runner._get_broker=lambda:SimpleNamespace(
            stop=lambda _:{'stopped':True,'job':dict(stats)},
            recover=lambda _:{'recovered':True,'active_processes':0,'job':dict(stats)})
        return runner,stats

    def check_roundtrip(self,action):
        runner,stats=self.runner()
        getattr(runner,action)('owned')
        self.assertTrue(runner.ledger.verify())
        persisted=runner.ledger.latest('owned')['monitoring']
        for key,value in persisted.items():self.assertEqual(value,stats[key])
        self.assertEqual(runner.observe('owned')['monitoring'],persisted)
        self.assertEqual(runner.recover('owned')['monitoring'],persisted)
        self.assertEqual(runner.stop('owned')['monitoring'],persisted)
        self.assertEqual(len(runner.ledger.events()),2)

    def test_stopped_observer_uncertainty_survives_authenticated_terminal_replay(self):
        self.check_roundtrip('stop')

    def test_empty_recovery_uncertainty_survives_authenticated_terminal_replay(self):
        self.check_roundtrip('recover')

    def test_legacy_terminal_job_without_history_metadata_remains_explicitly_unknown(self):
        runner,_=self.runner()
        runner.ledger.append({'kind':'completed','attempt_id':'owned','job':{
            'completion_port_available':True,'completion_port_error':None,'limit_breach':None}})
        self.assertTrue(runner.ledger.verify())
        for action in ('observe','stop','recover'):
            receipt=getattr(runner,action)('owned')['monitoring']
            self.assertEqual(receipt['completion_history'],'unknown')
            self.assertIsNone(receipt['monitor_role'])

class ReleaseLifecycleTests(unittest.TestCase):
    def test_shutdown_pending_preserves_every_shared_dependency(self):
        facade=object.__new__(Facade)
        def pending():raise ControlError('V120_SHUTDOWN_PENDING','pending')
        facade.v120=SimpleNamespace(close=pending)
        facade.jobs=SimpleNamespace(close=lambda:self.fail('jobs closed before task drain'))
        facade.store=SimpleNamespace(close=lambda:self.fail('store closed before task drain'))
        with self.assertRaisesRegex(ControlError,'pending'):facade.close()

    def test_verifier_cancellation_failure_cannot_return_a_terminal_verdict(self):
        facade=object.__new__(Facade);facade.principal='owner'
        facade.policy=SimpleNamespace(command=lambda *_:['pinned-python'],max_wait_ms=100)
        def fail(*_):raise ControlError('AUDIT_CAPACITY','audit failed')
        facade.jobs=SimpleNamespace(start=lambda *_a,**_kw:'owned-job',
            read=lambda *_:{'status':'queued'},stop=fail)
        with patch('localcontrol.facade.time.monotonic',side_effect=[0,1]):
            with self.assertRaises(ControlError) as caught:
                facade._v100_run_command('project',{'argv':['pinned-python'],'timeout_ms':100})
        self.assertEqual(caught.exception.code,'VERIFIER_CANCELLATION_PENDING')

    def test_queued_stop_cancels_even_when_intent_audit_fails(self):
        from tests.test_ownership_faults import memory_store,manager
        from localcontrol.jobs import PendingJob
        store=memory_store();self.addCleanup(store.db.close)
        mgr=manager(store)
        p=PendingJob('id','scope','p',['synthetic.exe'],1000,None,{},'pressure')
        owner=mgr._register_owner(p);mgr.pending[p.id]=p;mgr.pending_order.append(p.id)
        mgr._persist(owner,'admitted',mgr._raw_snapshot(owner),'job_start_intent',{})
        real=store.commit_job_transition
        def fail(*args,**kwargs):
            if args[2]=='cancel_intent':raise ControlError('STORE_FAILURE','synthetic intent failure')
            return real(*args,**kwargs)
        with patch.object(store,'commit_job_transition',side_effect=fail):
            result=mgr.stop('scope','id')
        self.assertTrue(p.cancel_requested)
        self.assertEqual(result['status'],'ownership_unresolved')
        self.assertIn('id',mgr.owners)
        self.assertFalse(p.done.is_set())
        self.assertNotIn('id',mgr.pending_order)
        owner.next_retry=0
        mgr.stop('scope','id')
        self.assertTrue(p.done.is_set())
        self.assertTrue(owner.terminal_committed and owner.custody.closed)

    def test_shutdown_waits_for_cleanup_after_capacity_is_released(self):
        from tests.test_ownership_faults import memory_store,manager,NativeJob
        from localcontrol.jobs import PendingJob
        store=memory_store();self.addCleanup(store.db.close)
        mgr=manager(store)
        p=PendingJob('id','scope','p',['synthetic.exe'],1000,None,{},'pressure')
        owner=mgr._register_owner(p);mgr.pending[p.id]=p
        mgr._persist(owner,'admitted',mgr._raw_snapshot(owner),'job_start_intent',{})
        native=NativeJob();native.close_error=True;owner.custody.job=native
        clock=[0]
        def wait(timeout=None):clock[0]=31
        import localcontrol.jobs as module
        import time
        with patch.object(module,'time',SimpleNamespace(monotonic=lambda:clock[0],time_ns=time.time_ns)), \
             patch.object(mgr.condition,'wait',side_effect=wait):
            with self.assertRaises(ControlError) as caught:mgr.close()
        self.assertEqual(caught.exception.code,'SHUTDOWN_PENDING')
        self.assertTrue(owner.terminal_committed)
        self.assertFalse(owner.custody.closed)
        self.assertIn('id',mgr.owners)
        self.assertEqual(native.closes,0)
        self.assertTrue(store.verify())

    def test_shutdown_resnapshots_a_launch_published_after_close_started(self):
        from tests.test_ownership_faults import memory_store,manager
        from localcontrol.jobs import PendingJob
        store=memory_store();self.addCleanup(store.db.close)
        mgr=manager(store)
        p=PendingJob('id','scope','p',['synthetic.exe'],1000,None,{},'immediate')
        owner=mgr._register_owner(p);mgr.pending[p.id]=p
        mgr._persist(owner,'admitted',mgr._raw_snapshot(owner),'job_start_intent',{})
        with mgr.condition:mgr._reserve_start_locked(p)
        entered=threading.Event();finished=threading.Event();errors=[]
        real_wait=mgr.condition.wait
        def wait(timeout=None):
            entered.set()
            return real_wait(timeout)
        def close():
            try:mgr.close()
            except BaseException as error:errors.append(error)
            finally:finished.set()
        with patch.object(mgr.condition,'wait',side_effect=wait):
            thread=threading.Thread(target=close);thread.start()
            try:
                self.assertTrue(entered.wait(2))
                self.assertFalse(finished.is_set())
                self.assertFalse(owner.custody.closed)
                # No real process API. The in-flight dispatcher observes shutdown.
                with patch.object(mgr,'_launch_reserved_impl',return_value=p.id):
                    mgr._launch_reserved(p,from_queue=False,raise_errors=True)
            finally:
                thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors,[])
        self.assertTrue(finished.is_set())
        self.assertTrue(owner.terminal_committed and owner.custody.closed)
        self.assertTrue(p.done.is_set())

    def test_verifier_deadline_cancels_its_queued_command(self):
        stopped=[];reads=[{'status':'queued'},{'status':'stopped'}]
        facade=object.__new__(Facade)
        facade.principal='owner'
        facade.policy=SimpleNamespace(command=lambda *_:['pinned-python'],max_wait_ms=100)
        facade.jobs=SimpleNamespace(start=lambda *_args,**_kwargs:'owned-job',
            read=lambda *_:reads.pop(0),stop=lambda *args:stopped.append(args))
        with patch('localcontrol.facade.time.monotonic',side_effect=[0,1]):
            result=facade._v100_run_command('project',{'argv':['pinned-python'],'timeout_ms':100})
        self.assertFalse(result['ok']);self.assertTrue(result['timed_out'])
        self.assertEqual(stopped,[('owner:v100-verifier:project','owned-job')])

    def manager(self):
        manager=object.__new__(JobManager)
        manager._scratch={};manager._scratch_identity={}
        manager.receipts=[]
        manager.store=SimpleNamespace(audit_essential=lambda *args:manager.receipts.append(args))
        return manager

    def test_unknown_scratch_siblings_are_never_swept(self):
        manager=self.manager()
        manager.policy=SimpleNamespace(path=lambda *_args,**_kwargs: self.fail('no enumeration allowed'))
        manager._reap_scratch('project')

    def test_nonempty_owned_scratch_is_retained_without_recursive_scanning(self):
        from tests.project_fixtures import ProjectTemporaryDirectory
        fixture=ProjectTemporaryDirectory(prefix='retained-scratch-')
        self.addCleanup(fixture.cleanup)
        path=Path(fixture.name);(path/'output.txt').write_text('owned output')
        manager=self.manager();info=path.lstat()
        manager._scratch['job']=path;manager._scratch_identity['job']=(info.st_dev,info.st_ino)
        with patch.object(Path,'rglob',side_effect=AssertionError('recursive scan forbidden')):
            manager._drop_scratch('job')
        self.assertTrue((path/'output.txt').exists())
        self.assertFalse(manager.receipts[-1][1]['removed'])
        self.assertIsNone(manager.receipts[-1][1]['scratch_bytes'])

    def test_replaced_scratch_identity_is_retained(self):
        from tests.project_fixtures import ProjectTemporaryDirectory
        fixture=ProjectTemporaryDirectory(prefix='changed-scratch-')
        self.addCleanup(fixture.cleanup)
        path=Path(fixture.name);manager=self.manager()
        manager._scratch['job']=path;manager._scratch_identity['job']=(-1,-1)
        manager._drop_scratch('job')
        self.assertTrue(path.exists())
        self.assertEqual(manager.receipts[-1][1]['reason'],'retained_changed_scratch_identity')
