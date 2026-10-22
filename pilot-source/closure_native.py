"""Two synthetic-resource native checks; no production paths or fence clearing."""
import ctypes as c
from ctypes import wintypes as w
import errno
import os
from pathlib import Path
import time

from localcontrol import appcontainer as app
from localcontrol.job_ownership import Custody
from localcontrol.windows_job import WindowsJob
from ownership_pilot import need, until
from restart_pilot import verify_token

def exercise(root):
    profile = __import__('json').loads((root/'control'/'profile.json').read_text())
    api = app.WinAPI()
    sid = c.c_void_p()
    need(api.derive(profile['name'], c.byref(sid)) == 0, 'PROFILE_DERIVE')
    config = __import__('json').loads((root/'control'/'mcp.json').read_text())
    subject = Path(config['policy']['projects']['pilot']['root'])
    output = root/'fixture'/'out'
    env = {k:os.environ[k] for k in ('SYSTEMROOT','WINDIR','SYSTEMDRIVE','LOCALAPPDATA') if k in os.environ}
    env.update(PATH=str(root/'runtime')+';'+str(Path(os.environ['SYSTEMROOT'])/'System32'), TEMP=str(output), TMP=str(output))
    exe = root/'runtime'/'LimitedIoProbe.exe'
    results = {}
    api.k.OpenProcess.argtypes = [w.DWORD,w.BOOL,w.DWORD]
    api.k.OpenProcess.restype = w.HANDLE
    try:
        # Native root -> child -> grandchild. The accounting fault is explicitly
        # injected; real process creation, token, membership and exit stay native.
        owner = Custody()
        held = []
        try:
            job = WindowsJob({'max_processes':4,'memory_bytes':256*1024**2}, custody=owner)
            process = app.spawn([str(exe),'chain','3',str(output)], subject, env, profile['name'], job, custody=owner)
            process.release()
            owner.command_released = True
            until(lambda: all((output/('chain-'+str(n)+'.pid')).is_file() for n in (1,2,3)), 5)
            ids = [int((output/('chain-'+str(n)+'.pid')).read_text()) for n in (1,2,3)]
            need(len(set(ids)) == 3 and process.pid in ids, 'EXACT_THREE_MEMBERS_REQUIRED')
            for pid in ids:
                handle = api.k.OpenProcess(0x101000, False, pid)
                need(bool(handle), 'OWNED_QUERY_HANDLE_REQUIRED')
                held.append(handle)
                inside = w.BOOL()
                api.check(api.is_in_job(handle, job.handle, c.byref(inside)))
                need(inside.value and api.wait(handle,0) == 258, 'CHAIN_MEMBER_NOT_LIVE_IN_EXACT_JOB')
                verify_token(api, handle, sid)
            real_stats = job.stats
            def unavailable():
                return {'accounting_available':False, 'active_processes':None,
                        'accounting_error':'INTENTIONAL_FIXTURE_UNKNOWN'}
            job.stats = unavailable
            try:
                empty = job.prove_empty(timeout=0)
                need(empty is False, 'UNKNOWN_NATIVE_ACCOUNTING_ACCEPTED_AS_EMPTY')
                need(owner.stop_and_prove() is False and not owner.termination_confirmed and not owner.closed,
                     'UNKNOWN_ACCOUNTING_ACCEPTED_AS_ZERO')
                need(job.handle is not None and owner.process is process, 'UNCERTAIN_CUSTODY_DISCARDED')
                unknown_snapshot = {'unknown_prove_empty':empty,
                    'unknown_termination_confirmed':owner.termination_confirmed,
                    'unknown_custody_closed':owner.closed,
                    'unknown_job_handle_retained':job.handle is not None}
                need(all(api.wait(handle,5000) == 0 for handle in held), 'CHAIN_EXIT_UNPROVEN')
            finally:
                job.stats = real_stats
            need(owner.stop_and_prove(), 'RESTORED_NATIVE_ZERO_UNPROVEN')
            owner.close_verified()
            need(owner.closed and job.handle is None, 'CHAIN_HANDLE_CLEANUP_FAILED')
            results['D01'] = {'passed':True,'native_levels':3,'all_tokens_verified':True,
                'appcontainer_sid':profile['sid_text'],'owned_native_process_ids':ids,
                'exact_job_membership':True,'all_retained_handles_exited':True,
                'accounting_outage_injected':True,'unknown_accounting_available':False,
                'unknown_active_processes':None,**unknown_snapshot,
                'unknown_retained':True,'no_fence_clearing':True}
        finally:
            close_failure = None
            try:
                if not owner.closed:
                    need(owner.stop_and_prove(), 'D01_FINAL_CLEANUP_UNRESOLVED')
                    owner.close_verified()
            except BaseException as error:
                close_failure = error
            for handle in held:
                try:
                    api.check(api.close(handle))
                except BaseException as error:
                    if close_failure is None: close_failure = error
            if close_failure is not None: raise close_failure

        # All native allocation and transfer are real. Inject an exception AFTER
        # one FileIO close, occupy only that proven-free descriptor with an owned
        # canary, then retry checked closure. A double close would corrupt it.
        owner = Custody()
        canary = None
        try:
            job = WindowsJob({'max_processes':2,'memory_bytes':256*1024**2}, custody=owner)
            process = app.spawn([str(exe),'stdio'], subject, env, profile['name'], job, custody=owner)
            need(owner.command_released is False and api.wait(process._handle,0) == 258,
                 'D02_SUSPENDED_PROCESS_REQUIRED')
            verify_token(api, process._handle, sid)
            need(owner.stop_and_prove(), 'D02_NATIVE_ZERO_UNPROVEN')
            original = process.stdin
            freed = original.fileno()
            class FailAfterClose:
                first = True
                def close(self):
                    original.close()
                    if self.first:
                        self.first = False
                        raise RuntimeError('INTENTIONAL_STREAM_CLOSE_ACK_LOSS')
            process.stdin = FailAfterClose()
            try:
                owner.close_verified()
                raise AssertionError('FAULT_NOT_OBSERVED')
            except RuntimeError as error:
                need(str(error) == 'INTENTIONAL_STREAM_CLOSE_ACK_LOSS', 'UNEXPECTED_CLOSE_ERROR')
            need(not owner.closed and job.handle is not None and original.closed, 'CLOSE_FAILURE_NOT_RETAINED')
            try:
                os.fstat(freed)
                raise AssertionError('DESCRIPTOR_NOT_FREE')
            except OSError as error:
                need(error.errno == errno.EBADF, 'DESCRIPTOR_FREE_PROOF_FAILED')
            opened = os.open(str(root/'control'/'owned-fd-canary.bin'), os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_BINARY)
            if opened == freed:
                canary = opened
            else:
                try:
                    os.dup2(opened, freed, inheritable=False)
                    canary = freed
                finally:
                    os.close(opened)
            os.write(canary, b'owned-descriptor-reuse-canary')
            before = os.fstat(canary)
            owner.close_verified()
            after = os.fstat(canary)
            need((before.st_dev,before.st_ino,before.st_size) == (after.st_dev,after.st_ino,after.st_size), 'REUSED_DESCRIPTOR_IDENTITY_DRIFT')
            os.lseek(canary,0,os.SEEK_SET)
            need(os.read(canary,64) == b'owned-descriptor-reuse-canary', 'REUSED_DESCRIPTOR_CORRUPTED')
            need(owner.closed and job.handle is None, 'D02_HANDLES_NOT_CLOSED')
            results['D02'] = {'passed':True,'real_suspended_process':True,'native_zero_before_close':True,
                'after_close_fault_injected':True,'exact_proven_free_descriptor_reused':True,
                'owned_canary_unchanged':True,'retry_checked_cleanup':True,'command_released':False}
        finally:
            try:
                if not owner.closed:
                    need(owner.stop_and_prove(), 'D02_FINAL_CLEANUP_UNRESOLVED')
                    owner.close_verified()
            finally:
                if canary is not None:
                    os.close(canary)
        need(set(results) == {'D01','D02'}, 'NATIVE_SELECTION_DRIFT')
        return results
    finally:
        if sid:
            need(not api.free_sid(sid), 'PROFILE_SID_FREE')
