"""Runner-only real MCP/LocalControl bridge; upstream is a labelled protocol fixture."""
import asyncio
from contextlib import AsyncExitStack
import ctypes as c
from ctypes import wintypes as w
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

STAGE="SCHEMA_CATALOG"
RESTART_DIAGNOSTIC={}

def need(value, reason):
    if not value:
        raise RuntimeError(reason)

def durable(root, jid):
    path = root / "control" / "state" / "receipts.sqlite"
    db = sqlite3.connect(path.as_uri()+"?mode=ro", uri=True, timeout=2)
    try:
        row = db.execute("SELECT record FROM jobs WHERE id=?", (jid,)).fetchone()
        need(row is not None, "DURABLE_JOB_MISSING")
        value = json.loads(row[0])
        rows = db.execute("SELECT seq,payload,prev,hash FROM audit ORDER BY seq LIMIT 513").fetchall()
        need(len(rows)<=512,"AUDIT_SNAPSHOT_BOUND_EXCEEDED")
        return {"status":value["status"],"phase":value["_ownership"]["phase"],
                "row_sha256":hashlib.sha256(row[0].encode()).hexdigest(),
                "audit_sha256":hashlib.sha256(json.dumps(rows,separators=(",",":")).encode()).hexdigest(),
                "finished_count":sum(json.loads(r[1]).get("kind")=="job_finished" and
                    json.loads(r[1]).get("metadata",{}).get("job_id")==jid for r in rows),
                "recovered_count":sum(json.loads(r[1]).get("kind")=="job_recovered" for r in rows),
                "_audit_rows":rows}
    finally:
        db.close()

def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(",",":"),allow_nan=False)

def compare_restart(before,after,jid):
    """Preserve every old row; allow only the two deliberately audited reads."""
    global RESTART_DIAGNOSTIC
    old,new=before["_audit_rows"],after["_audit_rows"]
    suffix=new[len(old):]
    def chain(rows):
        previous="0"*64
        for index,(seq,payload,prev,hashed) in enumerate(rows,1):
            if seq!=index or prev!=previous or hashlib.sha256((prev+payload).encode()).hexdigest()!=hashed:
                return False
            previous=hashed
        return True
    expected=[{"scope":"local-owner:pilot","tool":tool,
               "input_sha256":hashlib.sha256(canonical(args).encode()).hexdigest()}
              for tool,args in (("job_read",{"job_id":jid,"view":"summary"}),("process_list",{}))]
    matches=[]
    for row,metadata in zip(suffix[:2],expected):
        try:
            value=json.loads(row[1])
        except (ValueError,TypeError):
            matches.append(False)
            continue
        if not isinstance(value,dict):
            matches.append(False)
            continue
        matches.append(set(value)=={"time_ns","kind","metadata"} and
                       type(value["time_ns"]) is int and value["time_ns"]>0 and
                       value["kind"]=="read_intent" and value["metadata"]==metadata and
                       canonical(value)==row[1])
    fields=("status","phase","row_sha256","finished_count","recovered_count")
    RESTART_DIAGNOSTIC={"before_audit_rows":len(old),"after_audit_rows":len(new),
        "appended_rows":len(suffix),"before_audit_sha256":before["audit_sha256"],
        "after_audit_sha256":after["audit_sha256"],"before_row_sha256":before["row_sha256"],
        "after_row_sha256":after["row_sha256"],"changed_terminal_fields":[k for k in fields if before[k]!=after[k]],
        "audit_prefix_unchanged":new[:len(old)]==old,"before_chain_valid":chain(old),
        "after_chain_valid":chain(new),"expected_read_metadata_matches":matches}
    need(not RESTART_DIAGNOSTIC["changed_terminal_fields"],"MCP_RESTART_CHANGED_TERMINAL_ROW_OR_COUNTS")
    need(RESTART_DIAGNOSTIC["audit_prefix_unchanged"],"MCP_RESTART_CHANGED_AUDIT_PREFIX")
    need(chain(old) and chain(new),"MCP_RESTART_AUDIT_CHAIN_INVALID")
    need(len(suffix)==2 and matches==[True,True],"MCP_RESTART_UNEXPECTED_AUDIT_APPEND")
    return dict(RESTART_DIAGNOSTIC)

async def exercise(root):
    global STAGE
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from localcontrol.server import make_tools
    from localcontrol import appcontainer as app
    import restart_pilot as native
    schema_tools = make_tools(True,True,True,True,False)
    need(len(schema_tools)==66 and len({tool.name for tool in schema_tools})==66,
         "FULL_CATALOG_SCHEMA_COUNT_MISMATCH")
    actual_names={tool.name for tool in make_tools(True,False,False,False,False)}
    need(len(actual_names)==41, "FIXED_SERVER_CATALOG_COUNT_MISMATCH")
    env={key:os.environ[key] for key in ("SYSTEMROOT","WINDIR","SYSTEMDRIVE","LOCALAPPDATA",
         "PATH","TEMP","TMP","USERPROFILE") if key in os.environ}
    need(not any("TOKEN" in key.upper() or key.upper().startswith("ACTIONS_") for key in env),
         "CREDENTIAL_ENV_NOT_STRIPPED")
    config=root/"control"/"mcp.json"
    params=StdioServerParameters(command=sys.executable,
        args=["-I","-B","-S","-X","utf8",str(Path(__file__).with_name("server_entry.py")),
              "--config",str(config)],env=env)
    async def checked(session, name, args, ok=True):
        result=await session.call_tool(name,args)
        value=result.structuredContent
        need(isinstance(value,dict) and value.get("ok") is ok and
             bool(result.isError) is (not ok),"MCP_TOOL_RESULT_ENVELOPE_MISMATCH")
        texts=[x.text for x in result.content if getattr(x,"type",None)=="text"]
        need(len(texts)==1 and json.loads(texts[0])==value,"MCP_TEXT_STRUCTURED_PARITY_MISMATCH")
        return value
    jid=None
    api=app.WinAPI()
    held=None
    sid=c.c_void_p()
    evidence={}
    try:
        STAGE="PROFILE_QUERY"
        profile=json.loads((root/"control"/"profile.json").read_text())
        need(api.derive(profile["name"],c.byref(sid))==0,"PROFILE_SID_DERIVATION_FAILED")
        with (root/"control"/"sdk-stderr.log").open("w",encoding="utf-8") as errors:
            async with stdio_client(params,errlog=errors) as streams:
                async with ClientSession(*streams,read_timeout_seconds=timedelta(seconds=15)) as session:
                    STAGE="MCP_INITIALIZE"
                    init=await session.initialize()
                    need(init.serverInfo.name=="LocalControl" and init.serverInfo.version=="1.2.0",
                         "MCP_SERVER_IDENTITY_MISMATCH")
                    STAGE="MCP_TOOL_CATALOG"
                    catalog=await session.list_tools()
                    need({tool.name for tool in catalog.tools}==actual_names,
                         "REAL_MCP_TOOL_CATALOG_MISMATCH")
                    STAGE="MCP_CONTEXT"
                    context=await checked(session,"localcontrol_context",{})
                    data=context["data"]
                    need(data["server_version"]=="1.2.0" and data["tool_count"]==41 and
                         data["security_sandbox"] is True and data["network_listener"] is False and
                         data["audit_chain_ok"] is True and data["default_project"]=="pilot",
                         "REAL_MCP_CONTEXT_MISMATCH")
                    STAGE="BACKEND_PROTOCOL_AND_PATH_BOUNDARY"
                    result=await checked(session,"file_read",{"project":"pilot","path":"probe.txt"})
                    need(result["data"]["content"]=="public-synthetic-mcp-control\n",
                         "BACKEND_PROTOCOL_POSITIVE_CONTROL_FAILED")
                    blocked=await checked(session,"file_read",{"project":"pilot","path":"../blocked.txt"},ok=False)
                    need(blocked["error"]["code"]=="INVALID_PATH","PATH_BOUNDARY_RESULT_MISMATCH")
                    argv=[str(root/"runtime"/"LimitedIoProbe.exe"),"stdio"]
                    arguments={"project":"pilot","argv":argv,"wait_ms":0,"timeout_ms":20000,
                               "request_id":"mcp-exec-fixed-0001"}
                    STAGE="MCP_EXEC_AND_REPLAY"
                    first=await checked(session,"exec",arguments)
                    jid=first["data"]["job_id"]
                    replay=await checked(session,"exec",dict(arguments))
                    need(replay.get("replayed") is True and replay["data"]["job_id"]==jid,
                         "EXEC_REPLAY_CREATED_NEW_IDENTITY")
                    running=(await checked(session,"job_read",{"project":"pilot","job_id":jid,"wait_ms":0}))["data"]
                    need(running["status"]=="running" and running["security_sandbox"] is True and
                         running["isolation"]=="appcontainer_zero_capabilities","REAL_MCP_WORKER_NOT_SANDBOXED")
                    api.k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD]
                    api.k.OpenProcess.restype=w.HANDLE
                    held=api.k.OpenProcess(0x101000,False,running["pid"])
                    need(bool(held) and api.wait(held,0)==258,"WORKER_QUERY_WITNESS_FAILED")
                    native.verify_token(api,held,sid)
                    STAGE="MCP_INPUT_AND_COMPLETION"
                    input_args={"project":"pilot","job_id":jid,"text":"LOCALCONTROL_STDIO_V1\n"+"a"*128,
                                "eof":True,"request_id":"mcp-input-fixed-0001"}
                    ack=await checked(session,"job_input",input_args)
                    need(ack["data"]["eof_queued"] is True,"MCP_STDIN_EOF_NOT_QUEUED")
                    again=await checked(session,"job_input",dict(input_args))
                    need(again.get("replayed") is True,"MCP_STDIN_REPLAY_NOT_IDEMPOTENT")
                    end=time.monotonic()+15
                    record=None
                    while time.monotonic()<end:
                        record=(await checked(session,"job_read",{"project":"pilot","job_id":jid,"wait_ms":500}))["data"]
                        if record["status"]=="completed":
                            break
                        await asyncio.sleep(.03)
                    need(record is not None and record["status"]=="completed" and
                         record["returncode"]==0,"MCP_JOB_COMPLETION_FAILED")
                    for name,byte in (("stdout",b"O"),("stderr",b"E")):
                        expected=byte*98304
                        need(record[name+"_bytes"]==len(expected) and record[name+"_truncated"] is False and
                             hashlib.sha256(record[name].encode("ascii")).digest()==hashlib.sha256(expected).digest(),
                             "MCP_OUTPUT_CAPTURE_MISMATCH")
                    proof=record.get("launch_diagnostic",{})
                    need(proof.get("durable_terminal_receipt") is True and
                         proof.get("native_quiescence_proven") is True,"MCP_TERMINAL_PROOF_MISSING")
                    limits=record.get("resource_limit_state",{})
                    need(limits.get("accounting_available") is True and limits.get("active_processes")==0,
                         "MCP_NATIVE_ZERO_MISSING")
                    need(api.wait(held,5000)==0,"MCP_NATIVE_WORKER_EXIT_UNPROVEN")
                    jobs=(await checked(session,"process_list",{"project":"pilot"}))["data"]["jobs"]
                    need(len(jobs)==1 and (jobs[0].get("id") or jobs[0].get("job_id"))==jid,
                         "MCP_REPLAY_JOB_COUNT_MISMATCH")
                    evidence.update(actual_stdio_server=True,server_version="1.2.0",runtime_tools=41,
                        full_66_tool_schema_catalog=True,full_66_tool_runtime=False,
                        backend="SYNTHETIC_PROTOCOL_FIXTURE_NOT_PRODUCTION_WINFS",
                        positive_read=True,path_rejection=True,exec_replay_same_identity=True,
                        stdin_eof_and_replay=True,stdout_bytes=98304,stderr_bytes=98304,
                        actual_worker_AppContainer_sid_and_zero_capabilities=True,
                        native_worker_exit=True,durable_completion=True)
        STAGE="FIRST_SERVER_SHUTDOWN_AND_DURABILITY"
        need(json.loads((root/"control"/"backend-report.json").read_text())["read_calls"]==1,
             "REJECTED_PATH_REACHED_BACKEND")
        before=durable(root,jid)
        need(before["status"]=="completed" and before["phase"]=="terminal" and
             before["finished_count"]==1 and before["recovered_count"]==0,"INITIAL_DURABLE_RECEIPT_MISMATCH")
        # A genuinely fresh stdio server process reopens the exact same synthetic Store.
        STAGE="FRESH_MCP_SERVER_REOPEN"
        with (root/"control"/"sdk-reopen-stderr.log").open("w",encoding="utf-8") as errors:
            async with stdio_client(params,errlog=errors) as streams:
                async with ClientSession(*streams,read_timeout_seconds=timedelta(seconds=15)) as session:
                    await session.initialize()
                    context=await checked(session,"localcontrol_context",{})
                    need(context["data"]["audit_chain_ok"] is True,"RESTART_AUDIT_CHAIN_FAILED")
                    record=(await checked(session,"job_read",{"project":"pilot","job_id":jid,"view":"summary"}))["data"]
                    need(record["status"]=="completed","MCP_RESTART_TERMINAL_DRIFT")
                    jobs=(await checked(session,"process_list",{"project":"pilot"}))["data"]["jobs"]
                    need(len(jobs)==1,"MCP_RESTART_REPLAYED_JOB")
                    context=await checked(session,"localcontrol_context",{})
                    need(context["data"]["audit_chain_ok"] is True,"RESTART_FINAL_AUDIT_CHAIN_FAILED")
        evidence["restart_comparison"]=compare_restart(before,durable(root,jid),jid)
        evidence.update(fresh_server_reopen=True,restart_job_and_audit_prefix_unchanged=True,
                        restart_exactly_two_expected_audited_reads=True,
                        providers_disabled=True,experimental_v120_disabled=True)
        return evidence
    finally:
        if held:
            api.check(api.close(held))
        if sid:
            need(not api.free_sid(sid),"PROFILE_SID_FREE")
