from __future__ import annotations
import json, sqlite3, threading
from pathlib import Path
from .core import digest, ident, need, HEX

COUNTERS=("input_total","cached_input","output_total","reasoning_output")
STAGES=frozenset(("planning","implementation","validation","review","orchestration","other"))

def normalize(record:dict)->dict:
    fields={"schema","event_id","project","task","model","stage","basis","finalized","tokens","evidence_sha256","adapter"}
    need(type(record)is dict and set(record)==fields,"USAGE_SCHEMA")
    need(record["schema"]==1 and record["basis"]=="per_request" and record["finalized"] is True,"USAGE_SCHEMA")
    for k in ("event_id","project","task","model","adapter"):ident(record[k])
    need(record["stage"] in STAGES,"USAGE_STAGE")
    t=record["tokens"];need(type(t)is dict and set(t)==set(COUNTERS),"USAGE_COUNTERS")
    for v in t.values():need(v is None or (type(v)is int and 0<=v<=10**12),"USAGE_COUNTERS")
    for total,part in (("input_total","cached_input"),("output_total","reasoning_output")):
        need(t[total] is None or t[part] is None or t[part]<=t[total],"USAGE_SUBSET_EXCEEDS_TOTAL")
    need(isinstance(record["evidence_sha256"],str) and bool(HEX.fullmatch(record["evidence_sha256"])),"USAGE_EVIDENCE_HASH")
    return json.loads(json.dumps(record))

class DurableUsageStore:
    """Durable normalized usage. ingest() is for a trusted local adapter, not an MCP tool."""
    def __init__(self,path:Path,allowed_adapters:frozenset[str]):
        need(allowed_adapters and all(isinstance(x,str) for x in allowed_adapters),"USAGE_ADAPTERS")
        self.allowed_adapters=frozenset(ident(x) for x in allowed_adapters);self.lock=threading.RLock()
        self.db=sqlite3.connect(path,check_same_thread=False);self.db.row_factory=sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL");self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,payload TEXT NOT NULL)");self.db.commit()
    def ingest(self,record:dict)->dict:
        r=normalize(record);need(r["adapter"] in self.allowed_adapters,"UNTRUSTED_ADAPTER")
        fp=digest(r);payload=json.dumps(r,sort_keys=True,separators=(",",":"))
        with self.lock:
            row=self.db.execute("SELECT fingerprint FROM events WHERE event_id=?",(r["event_id"],)).fetchone()
            if row:
                need(row[0]==fp,"IDEMPOTENCY_CONFLICT");return {"event_id":r["event_id"],"replayed":True}
            self.db.execute("INSERT INTO events VALUES(?,?,?)",(r["event_id"],fp,payload));self.db.commit()
        return {"event_id":r["event_id"],"replayed":False}
    def summary(self,project:str|None=None,task:str|None=None)->dict:
        if project is not None:ident(project)
        if task is not None:ident(task)
        rows=[json.loads(x[0]) for x in self.db.execute("SELECT payload FROM events")]
        rows=[r for r in rows if (project is None or r["project"]==project) and (task is None or r["task"]==task)]
        def counted(key):
            vals=[r["tokens"][key] for r in rows];known=[v for v in vals if v is not None]
            return {"total":sum(known) if len(known)==len(vals) else None,"observed_sum":sum(known),"missing_events":len(vals)-len(known),"complete":len(known)==len(vals)}
        totals={k:counted(k) for k in COUNTERS}
        unc=[]
        for r in rows:
            i,c=r["tokens"]["input_total"],r["tokens"]["cached_input"];unc.append(None if i is None or c is None else i-c)
        known=[v for v in unc if v is not None]
        totals["uncached_input"]={"total":sum(known) if len(known)==len(unc) else None,"observed_sum":sum(known),"missing_events":len(unc)-len(known),"complete":len(known)==len(unc)}
        tasks={}
        for r in rows:tasks.setdefault(r["task"],[]).append(r)
        by_task=[]
        for name in sorted(tasks)[:32]:
            group=tasks[name]
            stats={}
            for counter in COUNTERS:
                vals=[r["tokens"][counter] for r in group];known=[v for v in vals if v is not None]
                stats[counter]={"total":sum(known) if len(known)==len(vals) else None,
                                "observed_sum":sum(known),"missing_events":len(vals)-len(known),
                                "complete":len(known)==len(vals)}
            unc=[]
            for r in group:
                i,c=r["tokens"]["input_total"],r["tokens"]["cached_input"]
                unc.append(None if i is None or c is None else i-c)
            known=[v for v in unc if v is not None]
            stats["uncached_input"]={"total":sum(known) if len(known)==len(unc) else None,
                                     "observed_sum":sum(known),"missing_events":len(unc)-len(known),
                                     "complete":len(known)==len(unc)}
            by_task.append({"task":name,"events":len(group),"tokens":stats})
        return {"events":len(rows),"project":project,"task":task,"tokens":totals,"estimated_cost":None,
                "source":"trusted_local_adapter","by_task":by_task,"by_task_truncated":len(tasks)>32}
    def close(self):self.db.close()
