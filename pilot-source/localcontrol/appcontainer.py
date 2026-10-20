"""Windows AppContainer worker launch, without network capabilities.

Uses documented Windows APIs. Host configuration must provision a dedicated
workspace and runtime; no ACLs are modified on the tool-call path. Process is
created suspended, assigned to an owned Job Object, then resumed. No same-user
fallback exists. AppContainer is an OS boundary, not a claim of escape immunity.
"""
from __future__ import annotations
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import subprocess
import threading
import time
from .errors import ControlError, require

class STARTUPINFO(c.Structure):
    _fields_=[('cb',w.DWORD),('lpReserved',w.LPWSTR),('lpDesktop',w.LPWSTR),('lpTitle',w.LPWSTR),
              ('dwX',w.DWORD),('dwY',w.DWORD),('dwXSize',w.DWORD),('dwYSize',w.DWORD),
              ('dwXCountChars',w.DWORD),('dwYCountChars',w.DWORD),('dwFillAttribute',w.DWORD),
              ('dwFlags',w.DWORD),('wShowWindow',w.WORD),('cbReserved2',w.WORD),
              ('lpReserved2',c.POINTER(c.c_byte)),('hStdInput',w.HANDLE),('hStdOutput',w.HANDLE),('hStdError',w.HANDLE)]
class STARTUPINFOEX(c.Structure):
    _fields_=[('StartupInfo',STARTUPINFO),('lpAttributeList',c.c_void_p)]
class PROCESS_INFORMATION(c.Structure):
    _fields_=[('hProcess',w.HANDLE),('hThread',w.HANDLE),('dwProcessId',w.DWORD),('dwThreadId',w.DWORD)]
class SECURITY_CAPABILITIES(c.Structure):
    _fields_=[('AppContainerSid',c.c_void_p),('Capabilities',c.c_void_p),('CapabilityCount',w.DWORD),('Reserved',w.DWORD)]

class WinAPI:
    def __init__(self):
        require(os.name=='nt','PLATFORM_UNSUPPORTED','AppContainer requires Windows')
        self.k=c.WinDLL('kernel32',use_last_error=True)
        self.u=c.WinDLL('userenv',use_last_error=True)
        self.a=c.WinDLL('advapi32',use_last_error=True)
        def api(lib,name,args,restype):
            fn=getattr(lib,name);fn.argtypes=args;fn.restype=restype;return fn
        self.init=api(self.k,'InitializeProcThreadAttributeList',[c.c_void_p,w.DWORD,w.DWORD,c.POINTER(c.c_size_t)],w.BOOL)
        self.update=api(self.k,'UpdateProcThreadAttribute',[c.c_void_p,w.DWORD,c.c_size_t,c.c_void_p,c.c_size_t,c.c_void_p,c.c_void_p],w.BOOL)
        self.delete=api(self.k,'DeleteProcThreadAttributeList',[c.c_void_p],None)
        self.create=api(self.k,'CreateProcessW',[w.LPCWSTR,w.LPWSTR,c.c_void_p,c.c_void_p,w.BOOL,w.DWORD,c.c_void_p,w.LPCWSTR,c.POINTER(STARTUPINFOEX),c.POINTER(PROCESS_INFORMATION)],w.BOOL)
        self.derive=api(self.u,'DeriveAppContainerSidFromAppContainerName',[w.LPCWSTR,c.POINTER(c.c_void_p)],c.c_long)
        self.create_profile=api(self.u,'CreateAppContainerProfile',[w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,c.c_void_p,w.DWORD,c.POINTER(c.c_void_p)],c.c_long)
        self.delete_profile=api(self.u,'DeleteAppContainerProfile',[w.LPCWSTR],c.c_long)
        self.free_sid=api(self.a,'FreeSid',[c.c_void_p],c.c_void_p)
        self.open_token=api(self.a,'OpenProcessToken',[w.HANDLE,w.DWORD,c.POINTER(w.HANDLE)],w.BOOL)
        self.token_info=api(self.a,'GetTokenInformation',[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.POINTER(w.DWORD)],w.BOOL)
        self.equal_sid=api(self.a,'EqualSid',[c.c_void_p,c.c_void_p],w.BOOL)
        self.close=api(self.k,'CloseHandle',[w.HANDLE],w.BOOL)
        self.resume=api(self.k,'ResumeThread',[w.HANDLE],w.DWORD)
        self.wait=api(self.k,'WaitForSingleObject',[w.HANDLE,w.DWORD],w.DWORD)
        self.code=api(self.k,'GetExitCodeProcess',[w.HANDLE,c.POINTER(w.DWORD)],w.BOOL)
        self.terminate=api(self.k,'TerminateProcess',[w.HANDLE,w.UINT],w.BOOL)
        self.get_times=api(self.k,'GetProcessTimes',[w.HANDLE,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p],w.BOOL)
        self.is_in_job=api(self.k,'IsProcessInJob',[w.HANDLE,w.HANDLE,c.POINTER(w.BOOL)],w.BOOL)
    def check(self,ok):
        if not ok:raise c.WinError(c.get_last_error())

class AppProcess:
    """Handle-backed process interface; the caller owns the assigned Job Object."""

    def __init__(self, api, pi, stdin, stdout, stderr, creation_time_100ns,
                 token, appcontainer_sid, job_handle):
        self.api, self._handle, self._thread = api, pi.hProcess, pi.hThread
        self.pid = int(pi.dwProcessId)
        self.stdin, self.stdout, self.stderr = stdin, stdout, stderr
        self.creation_time_100ns = creation_time_100ns
        self._token, self._sid, self._job_handle = token, appcontainer_sid, job_handle
        self.returncode = None
        self._capture_lock = threading.RLock()
        self._capture = None
        self._drainers = []

    def verify_sandbox(self):
        in_job = w.BOOL()
        self.api.check(self.api.is_in_job(
            self._handle, w.HANDLE(int(self._job_handle)), c.byref(in_job)
        ))
        require(in_job.value, 'SANDBOX_SETUP_FAILED',
                'Process is not in the exact owned Job Object')
        returned, is_appcontainer = w.DWORD(), w.DWORD()
        self.api.check(self.api.token_info(
            self._token, 29, c.byref(is_appcontainer), c.sizeof(is_appcontainer),
            c.byref(returned)
        ))
        require(is_appcontainer.value == 1, 'SANDBOX_SETUP_FAILED',
                'Created process is not an AppContainer')
        size = w.DWORD()
        self.api.token_info(self._token, 31, None, 0, c.byref(size))
        info = c.create_string_buffer(size.value)
        self.api.check(self.api.token_info(self._token, 31, info, size.value, c.byref(size)))
        actual_sid = c.cast(info, c.POINTER(c.c_void_p))[0]
        require(bool(self.api.equal_sid(actual_sid, self._sid)),
                'SANDBOX_SETUP_FAILED', 'AppContainer SID mismatch')
        size = w.DWORD()
        self.api.token_info(self._token, 30, None, 0, c.byref(size))
        info = c.create_string_buffer(size.value)
        self.api.check(self.api.token_info(self._token, 30, info, size.value, c.byref(size)))
        require(c.cast(info, c.POINTER(w.DWORD))[0] == 0,
                'SANDBOX_SETUP_FAILED', 'Unexpected AppContainer capabilities')

    def start_output_capture(self):
        """Drain pipes continuously while retaining only byte counts and digests."""
        with self._capture_lock:
            if self._capture is not None:
                return
            import hashlib
            self._capture = {
                name: {"hash": hashlib.sha256(), "bytes": 0, "complete": False,
                       "error": False}
                for name in ("stdout", "stderr")
            }
            for name, stream in (("stdout", self.stdout), ("stderr", self.stderr)):
                thread = threading.Thread(
                    target=self._drain, args=(name, stream),
                    name=f"localcontrol-v120-{name}-{self.pid}", daemon=True,
                )
                self._drainers.append(thread)
                thread.start()

    def _drain(self, name, stream):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                with self._capture_lock:
                    item = self._capture[name]
                    item["bytes"] += len(chunk)
                    item["hash"].update(chunk)
        except (OSError, ValueError):
            with self._capture_lock:
                self._capture[name]["error"] = True
        finally:
            with self._capture_lock:
                self._capture[name]["complete"] = True

    def capture_summary(self, *, wait_seconds=0):
        for thread in tuple(self._drainers):
            thread.join(max(0, wait_seconds))
        with self._capture_lock:
            if self._capture is None:
                return {"stdout": None, "stderr": None}
            return {
                name: {
                    "bytes": item["bytes"],
                    "sha256": item["hash"].copy().hexdigest(),
                    "complete": item["complete"],
                    "error": item["error"],
                }
                for name, item in self._capture.items()
            }

    def release(self, pre_resume_check=None):
        try:
            self.verify_sandbox()
            if pre_resume_check is not None:
                pre_resume_check(self._handle, self._token, self._sid)
            if self.api.resume(self._thread) == 0xffffffff:
                raise c.WinError(c.get_last_error())
        finally:
            if self._thread:
                self.api.check(self.api.close(self._thread))
                self._thread = None
            self._close_token_and_sid()

    def _close_token_and_sid(self):
        if self._token:
            self.api.check(self.api.close(self._token))
            self._token = None
        if self._sid:
            self.api.free_sid(self._sid)
            self._sid = None

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        if self._handle is None:
            return None
        if self.api.wait(self._handle, 0) == 0:
            value = w.DWORD()
            self.api.check(self.api.code(self._handle, c.byref(value)))
            self.returncode = int(value.value)
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is not None:
            return self.returncode
        if self._handle is None:
            return self.returncode
        ms = 0xFFFFFFFF if timeout is None else max(0, int(timeout * 1000))
        result = self.api.wait(self._handle, ms)
        if result == 258:
            raise subprocess.TimeoutExpired('appcontainer', timeout)
        if result != 0:
            raise c.WinError(c.get_last_error())
        return self.poll()

    def kill(self):
        if self._handle is not None and self.poll() is None:
            self.api.check(self.api.terminate(self._handle, 125))

    def close_handles(self):
        if self._thread:
            self.api.close(self._thread)
            self._thread = None
        self._close_token_and_sid()
        for stream in (self.stdin, self.stdout, self.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        for thread in tuple(self._drainers):
            thread.join(1)
        if self._handle:
            self.api.close(self._handle)
            self._handle = None

    def __del__(self):
        if hasattr(self, '_handle'):
            self.close_handles()

def _valid_spawn_argv(argv) -> bool:
    return isinstance(argv, list) and bool(argv) and all(
        isinstance(item, str) and item and "\x00" not in item for item in argv
    )


def _valid_worker_environment(env) -> bool:
    if not isinstance(env, dict):
        return False
    normalized = [key.casefold() for key in env if isinstance(key, str)]
    return (
        len(normalized) == len(env)
        and len(set(normalized)) == len(normalized)
        and all(
            key and "=" not in key and "\x00" not in key
            and isinstance(value, str) and "\x00" not in value
            for key, value in env.items()
        )
    )


def _environment_block(env: dict[str, str]) -> str:
    if not _valid_worker_environment(env):
        raise ValueError("invalid worker environment")
    return "\x00".join(
        f"{key}={value}" for key, value in sorted(env.items(), key=lambda item: item[0].upper())
    ) + "\x00\x00"


def _terminate_and_wait(api, handle) -> None:
    """Prove an owned process exited before its only process handle is closed."""
    try:
        api.terminate(handle, 125)
    except BaseException:
        # TerminateProcess can fail if the process exited concurrently. The wait
        # below decides whether cleanup is safe.
        pass
    if api.wait(handle, 5000) != 0:
        raise ControlError(
            'SANDBOX_SETUP_CLEANUP_FAILED',
            'Could not confirm suspended process termination.',
        )


def spawn(argv: list[str], cwd: Path, env: dict[str, str], profile_name: str, job,
          *, pre_resume_check=None, custody=None) -> AppProcess:
    """Create a zero-capability AppContainer process suspended in its owned job."""
    import msvcrt
    from .policy import no_links

    if custody is not None:
        custody.stage = 'native_api'
    api = WinAPI()
    sid = c.c_void_p()
    attrs = None
    fds = []
    pi = PROCESS_INFORMATION()
    proc = None
    token = w.HANDLE()
    require(isinstance(profile_name, str) and profile_name.startswith('LocalControl.'),
            'SANDBOX_CONFIG', 'Only explicitly provisioned LocalControl profiles')
    require(_valid_spawn_argv(argv),
            'SANDBOX_CONFIG', 'A literal argument vector is required')
    require(_valid_worker_environment(env),
            'SANDBOX_CONFIG', 'Invalid explicit worker environment')
    no_links(cwd)
    if custody is not None:
        custody.stage = 'appcontainer_sid'
    hr = api.derive(profile_name, c.byref(sid))
    require(hr == 0, 'SANDBOX_CONFIG', 'AppContainer SID derivation failed')
    try:
        if custody is not None:
            custody.stage = 'stdio_pipes'
        ir, iw = os.pipe()
        orr, ow = os.pipe()
        er, ew = os.pipe()
        fds = [ir, iw, orr, ow, er, ew]
        for fd in (ir, ow, ew):
            os.set_inheritable(fd, True)
        handles = (w.HANDLE * 3)(*[msvcrt.get_osfhandle(fd) for fd in (ir, ow, ew)])
        if custody is not None:
            custody.stage = 'process_attributes'
        size = c.c_size_t()
        attribute_count = 3 if custody is not None else 2
        api.init(None, attribute_count, 0, c.byref(size))
        attrs = c.create_string_buffer(size.value)
        api.check(api.init(attrs, attribute_count, 0, c.byref(size)))
        caps = SECURITY_CAPABILITIES(sid, None, 0, 0)
        api.check(api.update(attrs, 0, 0x20009, c.byref(caps), c.sizeof(caps), None, None))
        api.check(api.update(attrs, 0, 0x20002, c.byref(handles), c.sizeof(handles), None, None))
        if custody is not None:
            # Assign atomically with creation: broker crash cannot strand an
            # unassigned suspended worker. No weaker fallback on older hosts.
            job_handles = (w.HANDLE * 1)(int(job.handle))
            api.check(api.update(attrs, 0, 0x2000D, c.byref(job_handles),
                                 c.sizeof(job_handles), None, None))
            custody.bind_native(api, pi)
        si = STARTUPINFOEX()
        si.StartupInfo.cb = c.sizeof(si)
        si.StartupInfo.dwFlags = 0x100
        si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = handles
        si.lpAttributeList = c.cast(attrs, c.c_void_p)
        command = c.create_unicode_buffer(subprocess.list2cmdline(argv))
        block = c.create_unicode_buffer(_environment_block(env))
        flags = 0x00080000 | 0x00000400 | 0x08000000 | 0x00000004
        if custody is not None:
            custody.stage = 'create_suspended'
        api.check(api.create(
            argv[0], command, None, None, True, flags, block, str(cwd),
            c.byref(si), c.byref(pi)
        ))
        for fd in (ir, ow, ew):
            os.close(fd)
            fds.remove(fd)
        if custody is not None:
            custody.stage = 'process_identity'
        created, exited, kernel, user = w.FILETIME(), w.FILETIME(), w.FILETIME(), w.FILETIME()
        api.check(api.get_times(
            pi.hProcess, c.byref(created), c.byref(exited), c.byref(kernel), c.byref(user)
        ))
        created_100ns = (created.dwHighDateTime << 32) | created.dwLowDateTime
        api.check(api.open_token(pi.hProcess, 0x0008 | 0x0002, c.byref(token)))
        proc = AppProcess(
            api, pi, os.fdopen(iw, 'wb', buffering=0), os.fdopen(orr, 'rb', buffering=0),
            os.fdopen(er, 'rb', buffering=0), created_100ns, token, sid, job.handle,
        )
        if custody is not None:
            custody.process = proc
        # AppProcess now owns the parent pipe ends, including failure cleanup.
        fds.clear()
        token = w.HANDLE()
        sid = c.c_void_p()
        if custody is None:
            job.assign(proc)
        if custody is not None:
            custody.stage = 'ownership_verification'
        proc.verify_sandbox()
        if custody is not None:
            custody.assigned = True
        if pre_resume_check is not None:
            pre_resume_check(proc._handle, proc._token, proc._sid)
        return proc
    except BaseException as original:
        if custody is not None and pi.hProcess:
            # Pre-registered PI/custody retains exact process and Job handles.
            # Manager proves process exit + Job zero before closing them.
            raise
        cleanup_error = None
        if proc:
            try:
                if proc._handle is not None:
                    _terminate_and_wait(api, proc._handle)
            except BaseException as exc:
                cleanup_error = exc
            finally:
                proc.close_handles()
        elif pi.hProcess:
            try:
                _terminate_and_wait(api, pi.hProcess)
            except BaseException as exc:
                cleanup_error = exc
            finally:
                api.close(pi.hProcess)
                if pi.hThread:
                    api.close(pi.hThread)
        if cleanup_error is not None:
            raise ControlError(
                'SANDBOX_SETUP_CLEANUP_FAILED',
                'Could not confirm suspended process termination.',
            ) from original
        raise
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass
        if attrs is not None:
            api.delete(attrs)
        if sid:
            api.free_sid(sid)
        if token:
            api.close(token)
