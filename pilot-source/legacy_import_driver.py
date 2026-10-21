"""Bounded Windows runner coordinator; source and synthetic fixture paths are fixed."""
from contextlib import redirect_stdout, redirect_stderr
import asyncio
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import re
import site
import subprocess
import sys
import time
import uuid

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))
from localcontrol import appcontainer as app
from localcontrol.job_ownership import Custody
from localcontrol.windows_job import WindowsJob

CONTEXT = {"stage":"INITIALIZE"}

def need(value,reason):
    if not value:
        raise RuntimeError(reason)

def dump(value):
    print(json.dumps(value,sort_keys=True),flush=True)

def atomic(path,value):
    temporary=path.with_suffix(".tmp")
    with temporary.open("x",encoding="utf-8") as out:
        json.dump(value,out);out.flush();os.fsync(out.fileno())
    os.replace(temporary,path)

def validate(root):
    need(os.name=="nt" and c.sizeof(c.c_void_p)==8 and sys.version_info[:3]==(3,12,10),
         "FIXED_WINDOWS_PYTHON_REQUIRED")
    need(re.fullmatch(r"C:\\LocalControlRegressionMcp-[a-f0-9]{32}",str(root)) is not None,
         "FIXED_RUNNER_ROOT_REQUIRED")
    for path in (root,SOURCE,root/"venv"/"Lib"/"site-packages"):
        for part in (path,*path.parents):
            if part.exists():
                need(not part.lstat().st_file_attributes&0x400,"REPARSE_INPUT_REFUSED")
    need(not any("TOKEN" in key.upper() or key.upper().startswith("ACTIONS_")
                 for key in os.environ),"RUNTIME_CREDENTIAL_ENV_NOT_STRIPPED")

def minimal_environment():
    env={key:os.environ[key] for key in ("SYSTEMROOT","WINDIR","SYSTEMDRIVE","LOCALAPPDATA",
         "PATH","TEMP","TMP","USERPROFILE") if key in os.environ}
    need(env.get("LOCALAPPDATA"),"EXPLICIT_LOCALAPPDATA_REQUIRED")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"]="1"
    env["PYTHONDONTWRITEBYTECODE"]="1"
    return env

def contained_child(root, phase, custody):
    """Fixed coordinator Python only; atomically contained in outer test Job before resume."""
    api = app.WinAPI()
    pi = app.PROCESS_INFORMATION()
    custody.bind_native(api, pi)  # retain mutable native PI before CreateProcess
    attrs = None
    initialized = False
    try:
        size = c.c_size_t()
        api.init(None, 1, 0, c.byref(size))
        need(0 < size.value < 65536, "OWNER_ATTRIBUTE_SIZE")
        attrs = c.create_string_buffer(size.value)
        api.check(api.init(attrs, 1, 0, c.byref(size)))
        initialized = True
        jobs = (w.HANDLE * 1)(int(custody.job.handle))
        api.check(api.update(attrs, 0, 0x2000D, c.byref(jobs), c.sizeof(jobs), None, None))
        start = app.STARTUPINFOEX()
        start.StartupInfo.cb = c.sizeof(start)
        start.lpAttributeList = c.cast(attrs, c.c_void_p)
        argv = [sys.executable, "-I", "-B", "-S", "-X", "utf8", str(Path(__file__).resolve()),
                "child", phase, str(root)]
        command = c.create_unicode_buffer(subprocess.list2cmdline(argv))
        environment = c.create_unicode_buffer(app._environment_block(minimal_environment()))
        CONTEXT.update(stage="OWNER_CREATE_SUSPENDED")
        api.check(api.create(sys.executable, command, None, None, False,
                  0x08000000 | 0x80000 | 0x400 | 4, environment, str(root),
                  c.byref(start), c.byref(pi)))
        CONTEXT.update(stage="OWNER_MEMBERSHIP_AND_RESUME")
        inside = w.BOOL()
        api.check(api.is_in_job(pi.hProcess, custody.job.handle, c.byref(inside)))
        need(inside.value, "OWNER_OUTER_JOB_MEMBERSHIP")
        custody.assigned = True
        need(api.resume(pi.hThread) != 0xffffffff, "OWNER_RESUME_FAILED")
        custody.command_released = True
        api.check(api.close(pi.hThread))
        pi.hThread = None
        return api, pi
    finally:
        if initialized:
            api.delete(attrs)


def dependencies(root):
    site.addsitedir(str(root/"venv"/"Lib"/"site-packages"))
    import importlib.metadata
    import mcp,pytest,win32api,win32job,win32process,pywintypes
    for module in (mcp,pytest,win32api,win32job,win32process,pywintypes):
        need(Path(module.__file__).resolve().is_relative_to(root/"venv"),
             "DEPENDENCY_OUTSIDE_ISOLATED_VENV")
    need(importlib.metadata.version("mcp")=="1.26.0" and
         importlib.metadata.version("pytest")=="8.3.5" and
         importlib.metadata.version("pywin32")=="312","PINNED_DEPENDENCY_VERSION_MISMATCH")

def selected_regressions(root):
    import pytest
    selection=json.loads((SOURCE/"LEGACY_IMPORT_SELECTION.json").read_text())
    wanted=selection["nodes"]
    need(len(wanted)==selection["selected_declarations"]==109 and len(set(wanted))==109
         and len(selection["expected_collected_nodes"])==selection["expected_count"]==112,
         "FIXED_REGRESSION_SELECTION_REQUIRED")
    class Receipt:
        def __init__(self):
            self.collected=[];self.passed=set();self.failed=set();self.skipped=set();self.failure_reports=[];self.ordinary_tmp_paths=0
        @pytest.fixture
        def tmp_path(self,request,tmp_path_factory):
            # Explicit factory mode creates one ordinary directory, no current symlink.
            name="lc-"+hashlib.sha256(request.node.nodeid.encode()).hexdigest()[:24]
            path=tmp_path_factory.mktemp(name,numbered=False)
            need(path.is_dir() and not path.is_symlink() and not path.lstat().st_file_attributes&0x400,
                 "ORDINARY_TMP_PATH_REQUIRED")
            need(path.resolve().parent== (root/"regression-temp").resolve(),"TMP_PATH_SCOPE_REFUSED")
            self.ordinary_tmp_paths+=1
            return path
        def pytest_collection_finish(self,session):
            self.collected=[item.nodeid for item in session.items]
            need(sorted(self.collected)==sorted(selection["expected_collected_nodes"]),"REGRESSION_COLLECTION_DRIFT")
        def pytest_runtest_logreport(self,report):
            if report.failed:
                self.failed.add(report.nodeid)
                crash=getattr(report.longrepr,"reprcrash",None)
                line=getattr(crash,"lineno",None)
                message=str(getattr(crash,"message",""))[:2048]
                self.failure_reports.append({"node":report.nodeid,"phase":report.when,
                    "assertion_line":line if type(line) is int and 0<line<10000 else None,
                    "assertion_error":"AssertionError" in message,
                    "version_literals":sorted(set(re.findall(r"(?<![\w.])\d+\.\d+\.\d+(?:-rc\.\d+)?(?![\w.])",message)))[:8],
                    "integer_literals":re.findall(r"(?<![\w.])\d{1,9}(?![\w.])",message)[:8]})
            if report.skipped:
                self.skipped.add(report.nodeid)
            if report.when=="call" and report.passed:
                self.passed.add(report.nodeid)
    receipt=Receipt()
    os.chdir(SOURCE)
    code=pytest.main(["-q","--capture=sys","-p","no:cacheprovider","-c",
        str(root/"control"/"pytest.ini"),"--rootdir",str(SOURCE),"--basetemp",
        str(root/"regression-temp"),*wanted],plugins=[receipt])
    result={"exit_code":code,"collected":len(receipt.collected),
            "collection_missing":sorted(set(selection["expected_collected_nodes"])-set(receipt.collected))[:16],
            "collection_unexpected":sorted(set(receipt.collected)-set(selection["expected_collected_nodes"]))[:16],"passed":len(receipt.passed),
            "failed":sorted(receipt.failed),"skipped":sorted(receipt.skipped),
            "failure_reports":receipt.failure_reports[:16],
            "failure_reports_omitted":max(0,len(receipt.failure_reports)-16),
            "ordinary_tmp_path_calls":receipt.ordinary_tmp_paths,
            "expected_ordinary_tmp_path_calls":selection["expected_ordinary_tmp_path_calls"],
            "runner_import_path_correction_only":True,"numbered_false_tmp_path_fixture":True,"native_api_mocks":"EXISTING_UNIT_TEST_SEAMS_ONLY"}
    result["all_passed"]=(code==0 and len(receipt.passed)==112 and not receipt.failed and not receipt.skipped and receipt.ordinary_tmp_paths==selection["expected_ordinary_tmp_path_calls"])
    return result

def child(root,phase):
    validate(root)
    need(phase=="regression","FIXED_PHASE_REQUIRED")
    path=root/"control"/(phase+"-result.json")
    try:
        with (root/"control"/(phase+"-private.log")).open("w",encoding="utf-8") as log:
            with redirect_stdout(log),redirect_stderr(log):
                dependencies(root)
                evidence=selected_regressions(root)
        if phase=="regression" and not evidence["all_passed"]:
            atomic(path,{"status":"FAIL_OR_BLOCKED","phase":phase,"reason":"SELECTED_REGRESSION_NONPASS",
                         "evidence":evidence})
            sys.exit(2)
        atomic(path,{"status":"PASS","phase":phase,"evidence":evidence})
    except SystemExit:
        raise
    except BaseException as error:
        reason=str(error) if isinstance(error,RuntimeError) and re.fullmatch(r"[A-Z0-9_]+",str(error)) else "BOUNDED_PHASE_EXCEPTION"
        value={"status":"FAIL_OR_BLOCKED","phase":phase,"error_type":type(error).__name__,"reason":reason}
        if isinstance(error,ImportError) and isinstance(error.name,str) and re.fullmatch(r"[A-Za-z0-9_.]{1,100}",error.name):
            value["import_module"]=error.name
        if isinstance(error,OSError) and type(getattr(error,"winerror",None)) is int:
            value["win32_error"]=error.winerror
        atomic(path,value)
        sys.exit(2)

def stage(root,phase,seconds):
    custody=Custody()
    try:
        job=WindowsJob({"max_processes":12,"memory_bytes":1024**3},custody=custody)
        api,pi=contained_child(root,phase,custody)
        end=time.monotonic()+seconds
        while api.wait(pi.hProcess,50)==258:
            need(time.monotonic()<end,"OWNED_PHASE_TIMEOUT")
        code=w.DWORD();api.check(api.code(pi.hProcess,c.byref(code)))
        result_path=root/"control"/(phase+"-result.json")
        need(result_path.exists(),"OWNED_PHASE_NO_RECEIPT")
        value=json.loads(result_path.read_text())
        dump({"phase":phase,"stage":"OWNED_PHASE_RECEIPT","receipt":value})
        # A normal assertion nonpass is recorded, not waived; independent phases
        # may continue only after the same native-zero and cleanup gates pass.
        value["child_exit_code"]=code.value
        value["all_passed"]=(code.value==0 and value["status"]=="PASS")
        need(job.prove_empty(timeout=3),"OWNED_PHASE_TREE_NOT_EMPTY")
        stats=job.stats()
        need(stats.get("accounting_available") is True and stats.get("active_processes")==0,
             "OWNED_PHASE_NATIVE_ZERO_UNAVAILABLE")
        need(not stats.get("job_tree_limit_events") and stats.get("completion_port_error") is None,
             "OWNED_PHASE_LIMIT_OR_MONITOR_FAILURE")
        value["native_quiescence_proven"]=True
        return value
    finally:
        if custody.job is not None:
            need(custody.stop_and_prove(),"OWNED_PHASE_CLEANUP_UNRESOLVED")
            custody.close_verified()

def coordinate(root):
    validate(root)
    (root/"control").mkdir(exist_ok=False)
    from ownership_pilot import acl,token_sid
    owner_sid=token_sid()
    acl(root/"control","/inheritance:r","/grant:r",
        "*"+owner_sid+":(OI)(CI)(F)","*S-1-5-18:(OI)(CI)(F)")
    (root/"control"/"pytest.ini").write_text("[pytest]\n")
    regression=stage(root,"regression",105)
    passed=regression["all_passed"]
    dump({"schema":"localcontrol-legacy-import-regression/v1",
          "result":"PASS_LEGACY_IMPORT_REGRESSION_ONLY" if passed else "FAIL_SCOPED_LEGACY_IMPORT",
          "selected_regression_tests":112,"selected_modules":9,"phase_passes":{"regression":passed},
          "runner_import_path_correction_only":True,"numbered_false_tmp_path_fixture":True,"candidate_source_changed":False,
          "provider_activated":False,"real_winfs_repeated":False,"full_regression":False,
          "production_activation_authorized":False})
    if not passed:raise RuntimeError("SCOPED_LEGACY_IMPORT_REGRESSION_NONPASS")

if __name__=="__main__":
    try:
        if len(sys.argv)==4 and sys.argv[1]=="child":
            child(Path(sys.argv[3]),sys.argv[2])
        else:
            need(len(sys.argv)==2,"FIXED_ROOT_ARGUMENT_REQUIRED")
            coordinate(Path(sys.argv[1]))
    except BaseException as error:
        reason=str(error) if isinstance(error,RuntimeError) and re.fullmatch(r"[A-Z0-9_]+",str(error)) else "BOUNDED_COORDINATOR_EXCEPTION"
        dump({"result":"FAIL_OR_BLOCKED","error_type":type(error).__name__,"reason":reason,
              "stage":CONTEXT["stage"]})
        sys.exit(1)
