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
    selection=json.loads((SOURCE/"REGRESSION_SELECTION.json").read_text())
    wanted=selection["nodes"]
    need(len(wanted)==selection["expected_count"]==28 and len(set(wanted))==28,
         "FIXED_REGRESSION_SELECTION_REQUIRED")
    class Receipt:
        def __init__(self):
            self.collected=[];self.passed=set();self.failed=set();self.skipped=set()
        def pytest_collection_finish(self,session):
            self.collected=[item.nodeid for item in session.items]
            need(sorted(self.collected)==sorted(wanted),"REGRESSION_COLLECTION_DRIFT")
        def pytest_runtest_logreport(self,report):
            if report.failed:
                self.failed.add(report.nodeid)
            if report.skipped:
                self.skipped.add(report.nodeid)
            if report.when=="call" and report.passed:
                self.passed.add(report.nodeid)
    receipt=Receipt()
    os.chdir(SOURCE)
    code=pytest.main(["-q","--capture=sys","-p","no:cacheprovider","-c",
        str(root/"control"/"pytest.ini"),"--rootdir",str(SOURCE),"--basetemp",
        str(root/"regression-temp"),*wanted],plugins=[receipt])
    result={"exit_code":code,"collected":len(receipt.collected),"passed":len(receipt.passed),
            "failed":sorted(receipt.failed),"skipped":sorted(receipt.skipped),
            "unmodified_test_sources":True,"native_api_mocks":"EXISTING_UNIT_TEST_SEAMS_ONLY"}
    result["all_passed"]=(code==0 and len(receipt.passed)==28 and not receipt.failed and not receipt.skipped)
    return result

def child(root,phase):
    validate(root)
    need(phase in ("regression","mcp"),"FIXED_PHASE_REQUIRED")
    path=root/"control"/(phase+"-result.json")
    try:
        with (root/"control"/(phase+"-private.log")).open("w",encoding="utf-8") as log:
            with redirect_stdout(log),redirect_stderr(log):
                dependencies(root)
                if phase=="regression":
                    evidence=selected_regressions(root)
                else:
                    from server_mcp_probe import exercise
                    evidence=asyncio.run(asyncio.wait_for(exercise(root),timeout=80))
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
        if phase=="mcp" and "server_mcp_probe" in sys.modules:
            value["probe_stage"]=sys.modules["server_mcp_probe"].STAGE
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
        need(code.value==0 and value["status"]=="PASS","OWNED_PHASE_FAILED")
        need(job.prove_empty(timeout=3),"OWNED_PHASE_TREE_NOT_EMPTY")
        stats=job.stats()
        need(stats.get("accounting_available") is True and stats.get("active_processes")==0,
             "OWNED_PHASE_NATIVE_ZERO_UNAVAILABLE")
        need(not stats.get("job_tree_limit_events") and stats.get("completion_port_error") is None,
             "OWNED_PHASE_LIMIT_OR_MONITOR_FAILURE")
        return value
    finally:
        if custody.job is not None:
            need(custody.stop_and_prove(),"OWNED_PHASE_CLEANUP_UNRESOLVED")
            custody.close_verified()

def setup_mcp(root,api,profile,sid):
    from localcontrol.v060.registry import RegistryCodec,RegistrySnapshot,Workspace,Collection
    fixture=root/"fixture";fixture.mkdir()
    subject=fixture/"project";subject.mkdir()
    collection=fixture/"collection";collection.mkdir()
    output=fixture/"out";output.mkdir()
    (subject/"probe.txt").write_text("public-synthetic-mcp-control\n",encoding="utf-8")
    control=root/"control";state=control/"state";vstate=state/"v060"
    vstate.mkdir(parents=True)
    regkey,movekey=os.urandom(32),os.urandom(32)
    (vstate/"registry-key.bin").write_bytes(regkey)
    (vstate/"move-key.bin").write_bytes(movekey)
    snapshot=RegistrySnapshot(1,(Workspace("pilot",str(subject),True,True,False),),
                              (Collection("projects",str(collection),True),))
    (vstate/"workspace-registry.json").write_bytes(RegistryCodec(regkey).encode(snapshot))
    text=w.LPWSTR()
    api.a.ConvertSidToStringSidW.argtypes=[c.c_void_p,c.POINTER(w.LPWSTR)]
    api.a.ConvertSidToStringSidW.restype=w.BOOL
    api.k.LocalFree.argtypes=[c.c_void_p]
    need(api.a.ConvertSidToStringSidW(sid,c.byref(text)),"PROFILE_SID_TEXT")
    try:
        sid_text=text.value
    finally:
        api.k.LocalFree(c.cast(text,c.c_void_p))
    from ownership_pilot import acl
    acl(root,"/grant","*"+sid_text+":(RX)")
    acl(fixture,"/grant","*"+sid_text+":(OI)(CI)(RX)")
    acl(output,"/grant","*"+sid_text+":(OI)(CI)(M)")
    acl(root/"runtime","/grant","*"+sid_text+":(OI)(CI)(RX)")
    manifest=control/"worker.json"
    manifest.write_text(json.dumps({"workspace":str(subject),"network_capabilities":[],
        "profile_name":profile,"runtime":str(root/"runtime"),"temp":str(output),"home":str(subject)}))
    config={"policy":{"projects":{"pilot":{"root":str(subject),"writable":True}},
        "state_dir":str(state),"exec_mode":"appcontainer","workers":{"pilot":{"manifest":str(manifest)}},
        "max_active_jobs":1,"max_queued_jobs":1,"max_timeout_ms":20000,"max_wait_ms":1000,
        "min_free_memory_bytes":1024**3,"min_free_disk_bytes":1024**3},
        "winfs":{"node":sys.executable,"entry":str(SOURCE/"protocol_backend.py")},
        "v060":{"enabled":True,"allowed_usage_adapters":["synthetic"]}}
    need(set(config)=={"policy","winfs","v060"},"FORBIDDEN_OPTIONAL_RUNTIME_ENABLED")
    (control/"mcp.json").write_text(json.dumps(config))
    (control/"profile.json").write_text(json.dumps({"name":profile,"sid_text":sid_text}))

def coordinate(root):
    validate(root)
    (root/"control").mkdir(exist_ok=False)
    from ownership_pilot import acl,token_sid
    owner_sid=token_sid()
    acl(root/"control","/inheritance:r","/grant:r",
        "*"+owner_sid+":(OI)(CI)(F)","*S-1-5-18:(OI)(CI)(F)")
    (root/"control"/"pytest.ini").write_text("[pytest]\n")
    regression=stage(root,"regression",75)
    api=app.WinAPI();sid=c.c_void_p();created=False
    profile="LocalControl.RegressionMcp."+uuid.uuid4().hex
    try:
        need(api.create_profile(profile,profile,"Disposable regression MCP fixture",None,0,
                                c.byref(sid))==0,"PROFILE_CREATE")
        created=True
        setup_mcp(root,api,profile,sid)
        integration=stage(root,"mcp",100)
    finally:
        if sid:
            need(not api.free_sid(sid),"PROFILE_SID_FREE")
        if created:
            need(api.delete_profile(profile)==0,"PROFILE_DELETE")
            dump({"profile_cleanup":"PASS"})
    dump({"schema":"localcontrol-regression-mcp/v1","result":"PASS_SELECTED_REGRESSION_AND_MCP_PROTOCOL_ONLY",
          "regression_tests":28,"real_stdio_runtime_tools":41,"schema_catalog_tools":66,
          "backend":"SYNTHETIC_PROTOCOL_FIXTURE","full_regression":False,
          "full_production_winfs_integration":False,"full_66_tool_runtime":False,
          "production_activation_authorized":False,"attestor_installed":False})

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
