"""Real pinned Winfs over actual SDK stdio and unchanged LocalControl server; owned data only."""
import hashlib,json,os,sys
from datetime import timedelta
from pathlib import Path
STAGE="INITIALIZE"
DIAGNOSTIC={}
def need(value,reason):
    if not value:raise RuntimeError(reason)
def environment(root):
    env={k:os.environ[k] for k in ("SYSTEMROOT","WINDIR","SYSTEMDRIVE","PATH","TEMP","TMP") if k in os.environ}
    for key,sub in (("LOCALAPPDATA","node-localappdata"),("USERPROFILE","node-home")):
        path=root/"control"/sub;path.mkdir(exist_ok=True);env[key]=str(path)
    need(not any("TOKEN" in k or k.startswith("ACTIONS_") for k in env),"CREDENTIAL_ENV_NOT_STRIPPED")
    return env
async def exercise(root):
    global STAGE,DIAGNOSTIC
    from mcp import ClientSession,StdioServerParameters
    from mcp.client.stdio import stdio_client
    from localcontrol.server import make_tools
    node=root/"node/node.exe";entry=root/"upstream/dist/index.js"
    need(node.is_file() and entry.is_file(),"REAL_UPSTREAM_NOT_BUILT")
    subject=root/"fixture/project";outside=root/"fixture/outside-control.txt"
    outside.write_text("public-outside-root-canary\n")
    env=environment(root)
    config=root/"control/direct-winfs.json"
    config.write_text(json.dumps({"allowedRoots":[str(subject)],"defaultTimeoutMs":5000,"maxTimeoutMs":10000,
                                 "auditLogPath":str(root/"control/direct-winfs-audit.jsonl")}))
    params=StdioServerParameters(command=str(node),args=[str(entry),"--config",str(config)],env=env)
    evidence={"upstream_revision":"07672940af20bb30222c4ae161e13c2288d4f38a","upstream_version":"1.0.1"}
    STAGE="DIRECT_UPSTREAM_ROOT_BOUNDARY"
    with (root/"control/direct-winfs-stderr.log").open("w") as log:
        async with stdio_client(params,errlog=log) as streams:
            async with ClientSession(*streams,read_timeout_seconds=timedelta(seconds=12)) as session:
                init=await session.initialize()
                need(init.serverInfo.version=="1.0.1","UPSTREAM_VERSION_MISMATCH")
                names={x.name for x in (await session.list_tools()).tools}
                need({"read","write","edit_file","list","stat"}<=names,"UPSTREAM_CONTRACT_MISSING")
                positive=await session.call_tool("read",{"path":str(subject/"probe.txt"),"max_bytes":4096})
                need(not positive.isError and "public-synthetic-mcp-control" in json.dumps(positive.model_dump()),
                     "DIRECT_UPSTREAM_POSITIVE_FAILED")
                metadata=await session.call_tool("stat",{"path":str(subject/"probe.txt")})
                need(not metadata.isError and isinstance(metadata.structuredContent,dict) and
                     metadata.structuredContent.get("exists") is True and
                     metadata.structuredContent.get("size")==len((subject/"probe.txt").read_bytes()),
                     "DIRECT_REAL_STAT_MISMATCH")
                negative=await session.call_tool("read",{"path":str(outside),"max_bytes":4096})
                need(negative.isError and "public-outside-root-canary" not in json.dumps(negative.model_dump()),
                     "DIRECT_UPSTREAM_OUTSIDE_ROOT_NOT_DENIED")
                need(outside.read_text()=="public-outside-root-canary\n","OUTSIDE_CANARY_CHANGED")
    evidence.update(real_upstream_positive=True,real_upstream_root_denial=True,real_upstream_stat=True)
    server=StdioServerParameters(command=sys.executable,args=["-I","-B","-S","-X","utf8",
        str(Path(__file__).with_name("server_entry.py")),"--config",str(root/"control/mcp.json")],env=env)
    async def checked(session,tool,args,ok=True):
        result=await session.call_tool(tool,args)
        value=result.structuredContent
        need(isinstance(value,dict) and value.get("ok") is ok and bool(result.isError) is (not ok),
             "NORTHBOUND_ENVELOPE_MISMATCH")
        texts=[x.text for x in result.content if getattr(x,"type",None)=="text"]
        need(len(texts)==1 and json.loads(texts[0])==value,"NORTHBOUND_TEXT_STRUCTURED_MISMATCH")
        return value
    STAGE="REAL_WINFS_NORTHBOUND"
    with (root/"control/real-winfs-server-stderr.log").open("w") as log:
        async with stdio_client(server,errlog=log) as streams:
            async with ClientSession(*streams,read_timeout_seconds=timedelta(seconds=12)) as session:
                init=await session.initialize()
                need(init.serverInfo.name=="LocalControl" and init.serverInfo.version=="1.2.0","BROKER_IDENTITY_MISMATCH")
                need({x.name for x in (await session.list_tools()).tools}==
                     {x.name for x in make_tools(True,False,False,False,False)},"BROKER_CATALOG_MISMATCH")
                context=(await checked(session,"localcontrol_context",{}))["data"]
                need(context["tool_count"]==41 and context["security_sandbox"] is True and
                     context["network_listener"] is False and context["audit_chain_ok"] is True,"BROKER_CONTEXT_MISMATCH")
                text="alpha Åäö\nsecond line\n"
                write={"project":"pilot","path":"real.txt","content":text,"expected_sha256":"absent","request_id":"real-write-0001"}
                result=await checked(session,"file_write",write)
                sha=hashlib.sha256(text.encode()).hexdigest()
                need(result["data"]["sha256"]==sha and (subject/"real.txt").read_bytes()==text.encode(),"REAL_WRITE_BYTES_MISMATCH")
                replay=await checked(session,"file_write",dict(write))
                need(replay.get("replayed") is True and (subject/"real.txt").read_bytes()==text.encode(),"WRITE_REPLAY_FAILED")
                read=await checked(session,"file_read",{"project":"pilot","path":"real.txt"})
                need(read["data"]["content"]==text and read["data"]["sha256"]==sha,"REAL_READ_UTF8_MISMATCH")
                stale=await checked(session,"file_write",{**write,"content":"unwanted","expected_sha256":"0"*64,"request_id":"real-stale-0001"},False)
                need(stale["error"]["code"]=="CONFLICT" and (subject/"real.txt").read_bytes()==text.encode(),"STALE_WRITE_NOT_FENCED")
                patch={"project":"pilot","path":"real.txt","old":"alpha","new":"beta","expected_sha256":sha,"request_id":"real-drypatch-0001","dry_run":True}
                await checked(session,"file_patch",patch)
                need((subject/"real.txt").read_bytes()==text.encode(),"REAL_PATCH_DRY_RUN_MUTATED")
                patch.update(request_id="real-patch-0001",dry_run=False)
                patched=await checked(session,"file_patch",patch)
                expected=text.replace("alpha","beta")
                need((subject/"real.txt").read_bytes()==expected.encode() and patched["data"]["sha256"]==
                     hashlib.sha256(expected.encode()).hexdigest(),"REAL_PATCH_BYTES_MISMATCH")
                listing=await checked(session,"file_list",{"project":"pilot","path":"","limit":10})
                need(any(x["path"]=="real.txt" for x in listing["data"]["entries"]),"REAL_LIST_MISSING_FILE")
                batch=await checked(session,"read_batch",{"project":"pilot","requests":[{"path":"real.txt","stat":True}]})
                need(batch["data"]["items"][0]["sha256"]==hashlib.sha256(expected.encode()).hexdigest(),"REAL_STAT_SHA_MISMATCH")
                blocked=await checked(session,"file_read",{"project":"pilot","path":"../outside-control.txt"},False)
                need(blocked["error"]["code"]=="INVALID_PATH","BROKER_PATH_BOUNDARY_FAILED")
                protected=await checked(session,"file_write",{"project":"pilot","path":".env","content":"public-test-only",
                    "expected_sha256":"absent","request_id":"real-protected-0001"},False)
                need(protected["error"]["code"]=="PROTECTED_PATH" and not (subject/".env").exists(),"PROTECTED_WRITE_NOT_DENIED")
                delete={"project":"pilot","path":"real.txt","expected_sha256":patched["data"]["sha256"],"request_id":"real-delete-0001"}
                await checked(session,"file_delete",delete)
                again=await checked(session,"file_delete",dict(delete))
                need(again.get("replayed") is True and not (subject/"real.txt").exists(),"DELETE_REPLAY_FAILED")
                need((await checked(session,"localcontrol_context",{}))["data"]["audit_chain_ok"] is True,"FINAL_AUDIT_INVALID")
    evidence.update(live_tools=41,northbound_real_read_write_patch_list_stat=True,utf8_byte_hashes=True,
        replay_and_stale_precondition=True,dry_run_preserved_file=True,delete_replay=True,protected_path_denial=True,
        no_provider_activation=True,no_exec_calls=True,production_installation_tested=False)
    DIAGNOSTIC={"completed":"DIRECT_ROOT_DENIAL_AND_NORTHBOUND_FILE_OPERATIONS"}
    return evidence

