from __future__ import annotations
from dataclasses import dataclass, asdict
import hashlib, hmac, json, ntpath, re, time
from typing import Iterable
from .core import Rejected, canonical, digest, need, same_or_child, strict_child, win_abs, HEX

@dataclass(frozen=True)
class Entry:
    relative: str
    kind: str  # file|dir|reparse
    size: int = 0
    sha256: str|None = None
    file_id: str|None = None
    link_target: str|None = None
    mtime_ns: int = 0
    def __post_init__(self):
        need(isinstance(self.relative,str) and self.relative not in ("", ".") and not ntpath.isabs(self.relative), "INVALID_ENTRY")
        need(".." not in self.relative.replace("\\","/").split("/"), "INVALID_ENTRY")
        need(self.kind in {"file","dir","reparse"}, "INVALID_ENTRY")
        need(type(self.size) is int and self.size >= 0, "INVALID_ENTRY")
        need(self.sha256 is None or bool(HEX.fullmatch(self.sha256)), "INVALID_ENTRY")
        need(self.file_id is None or (isinstance(self.file_id,str) and 1 <= len(self.file_id) <= 256), "INVALID_ENTRY")
        need(self.link_target is None or (isinstance(self.link_target,str) and len(self.link_target)<=4096),"INVALID_ENTRY")
        need(self.kind=="reparse" or self.link_target is None,"INVALID_ENTRY")
        need(type(self.mtime_ns) is int and self.mtime_ns >= 0,"INVALID_ENTRY")

@dataclass(frozen=True)
class TreeSnapshot:
    root: str
    root_identity: str
    volume_id: str
    entries: tuple[Entry, ...]
    complete: bool = True
    def __post_init__(self):
        object.__setattr__(self,"root",win_abs(self.root))
        need(isinstance(self.root_identity,str) and self.root_identity, "INVALID_IDENTITY")
        need(isinstance(self.volume_id,str) and self.volume_id, "INVALID_VOLUME")
        need(type(self.complete) is bool,"INVALID_SNAPSHOT")
        keys=[ntpath.normcase(e.relative) for e in self.entries]
        need(len(keys)==len(set(keys)),"DUPLICATE_ENTRY")
    @property
    def fingerprint(self) -> str:
        return digest({"root_identity":self.root_identity,"volume_id":self.volume_id,"complete":self.complete,
                       "entries":[asdict(e) for e in sorted(self.entries,key=lambda x:ntpath.normcase(x.relative))]})

@dataclass(frozen=True)
class Risk:
    code: str
    severity: str
    path: str|None
    detail: str
    def __post_init__(self):
        need(self.severity in {"info","warning","blocker"}, "INVALID_RISK")

_ABS_WIN = re.compile(r"(?i)(?:[A-Z]:\\[^\r\n\"'<>|*?]+)")

def scan_text_risks(source_root: str, files: Iterable[tuple[str,str]], reparse_paths: Iterable[str]=()) -> tuple[Risk,...]:
    """Conservative static relocation risks. No file is executed and no linked target is followed."""
    source = win_abs(source_root)
    source_cf = ntpath.normcase(source)
    out=[]
    for rel in reparse_paths:
        out.append(Risk("REPARSE_PRESENT","warning",rel,"Relocation preserves this link/reparse point without following it; later LocalControl access may reject it."))
    for rel,text in files:
        if not isinstance(text,str): continue
        low = ntpath.normcase(text)
        # Serialized config formats often escape each backslash (for example JSON).
        # Compare both raw and one-level unescaped forms without interpreting arbitrary escapes.
        low_unescaped = low.replace('\\\\', '\\')
        if source_cf in low or source_cf in low_unescaped:
            sev="warning"; code="ABSOLUTE_SOURCE_REFERENCE"
            name=ntpath.basename(rel).casefold()
            if name==".git" or "worktrees" in rel.replace("\\","/").casefold().split("/"):
                sev="blocker";code="GIT_WORKTREE_REFERENCE"
            elif name in {"pyvenv.cfg","activate","activate.bat","activate.ps1"}:
                code="VENV_ABSOLUTE_REFERENCE"
            out.append(Risk(code,sev,rel,"File contains the current absolute project root and may need regeneration or repair after relocation."))
        if ntpath.basename(rel).casefold()==".git" and re.search(r"(?im)^gitdir:\s*[A-Z]:\\",text):
            out.append(Risk("GITDIR_ABSOLUTE","blocker",rel,"Git worktree metadata contains an absolute gitdir pointer; use a Git-aware relocation/repair path."))
        if ntpath.basename(rel).casefold()=="pyvenv.cfg":
            for m in _ABS_WIN.finditer(text):
                if source_cf not in ntpath.normcase(m.group(0)):
                    out.append(Risk("VENV_EXTERNAL_RUNTIME","info",rel,"Virtual environment references an external Python runtime; verify it remains available."));break
    # stable de-dup
    seen=set();result=[]
    for r in out:
        key=(r.code,r.severity,r.path,r.detail)
        if key not in seen: seen.add(key);result.append(r)
    return tuple(result)



def scan_structural_risks(entries:Iterable[Entry])->tuple[Risk,...]:
    out=[]
    paths={e.relative.replace('\\','/').casefold():e for e in entries}
    if any(p=='.git/worktrees' or p.startswith('.git/worktrees/') for p in paths):
        out.append(Risk('GIT_LINKED_WORKTREES','blocker','.git/worktrees','Repository owns linked worktree metadata; move requires a Git-aware repair protocol.'))
    if any(p=='.venv' or p.startswith('.venv/') or p=='venv' or p.startswith('venv/') for p in paths):
        out.append(Risk('VENV_PRESENT','warning','.venv','Virtual environment may embed absolute paths; prefer regeneration after relocation.'))
    if any(p=='node_modules' or p.startswith('node_modules/') for p in paths):
        out.append(Risk('NODE_MODULES_PRESENT','info','node_modules','Dependency cache is relocatable only if its reparse targets are safe; reparse analysis is authoritative.'))
    return tuple(out)

def scan_reparse_risks(source_root:str,entries:Iterable[Entry])->tuple[Risk,...]:
    source=win_abs(source_root);out=[]
    for e in entries:
        if e.kind!='reparse':continue
        target=e.link_target
        if not target:
            out.append(Risk('REPARSE_TARGET_UNKNOWN','blocker',e.relative,'Reparse target could not be proven safe for relocation.'))
            continue
        normalized=target
        if normalized.startswith('\\\\?\\'):normalized=normalized[4:]
        if ntpath.isabs(normalized):
            try:
                local=win_abs(normalized)
            except Rejected:
                out.append(Risk('REPARSE_NONLOCAL_TARGET','blocker',e.relative,'Reparse target uses a non-local/device namespace.'))
                continue
            if same_or_child(local,source):
                out.append(Risk('INTERNAL_ABSOLUTE_REPARSE','blocker',e.relative,'Absolute reparse target points inside the old project root and would become stale after relocation.'))
            else:
                out.append(Risk('EXTERNAL_ABSOLUTE_REPARSE','warning',e.relative,'Absolute reparse target points outside the project; verify the external dependency remains valid.'))
        else:
            out.append(Risk('RELATIVE_REPARSE','info',e.relative,'Relative reparse target is preserved by same-volume relocation.'))
    return tuple(out)

@dataclass(frozen=True)
class MovePlan:
    schema: int
    source_scope: str
    collection: str
    source: str
    destination: str
    source_authority_root: str
    destination_collection_root: str
    source_fingerprint: str
    source_identity: str
    source_volume: str
    destination_parent_volume: str
    destination_absent: bool
    registry_revision: int
    registry_sha256: str
    lease_id: str
    created_ns: int
    expires_ns: int
    risks: tuple[Risk,...]
    def __post_init__(self):
        need(self.schema==1,"PLAN_SCHEMA")
        from .core import ident
        ident(self.source_scope);ident(self.collection)
        object.__setattr__(self,"source",win_abs(self.source));object.__setattr__(self,"destination",win_abs(self.destination))
        object.__setattr__(self,"source_authority_root",win_abs(self.source_authority_root));object.__setattr__(self,"destination_collection_root",win_abs(self.destination_collection_root))
        need(ntpath.normcase(self.source)!=ntpath.normcase(self.destination),"SAME_PATH")
        need(not same_or_child(self.destination,self.source),"DESTINATION_INSIDE_SOURCE")
        need(same_or_child(self.source,self.source_authority_root),"SOURCE_OUTSIDE_AUTHORITY")
        need(strict_child(self.destination,self.destination_collection_root),"DESTINATION_OUTSIDE_COLLECTION")
        need(bool(HEX.fullmatch(self.source_fingerprint)),"INVALID_FINGERPRINT")
        need(self.source_identity and self.source_volume and self.destination_parent_volume,"INVALID_IDENTITY")
        need(type(self.destination_absent) is bool and self.destination_absent,"DESTINATION_EXISTS")
        need(type(self.registry_revision) is int and self.registry_revision>=1,"INVALID_REVISION")
        need(isinstance(self.registry_sha256,str) and bool(HEX.fullmatch(self.registry_sha256)),"INVALID_REGISTRY_BINDING")
        need(isinstance(self.lease_id,str) and self.lease_id.startswith("lease-"),"LEASE_REQUIRED")
        need(type(self.created_ns) is int and type(self.expires_ns) is int and self.expires_ns>self.created_ns,"INVALID_EXPIRY")
        need(self.source_volume==self.destination_parent_volume,"CROSS_VOLUME_UNSUPPORTED")
        need(not any(r.severity=="blocker" for r in self.risks),"MOVE_BLOCKED")
    def body(self):
        d=asdict(self); d["risks"]=[asdict(r) for r in self.risks]; return d
    @property
    def plan_id(self): return "move-"+digest(self.body())[:32]

class MovePlanCodec:
    def __init__(self,key:bytes): need(isinstance(key,bytes) and len(key)>=32,"INVALID_KEY");self.key=key
    def encode(self,plan:MovePlan)->str:
        body=canonical(plan.body()).encode("ascii");sig=hmac.new(self.key,body,hashlib.sha256).hexdigest()
        return canonical({"body":json.loads(body),"hmac_sha256":sig})
    def decode(self,token:str,now_ns:int|None=None)->MovePlan:
        try: outer=json.loads(token)
        except Exception: raise Rejected("INVALID_PLAN") from None
        need(set(outer)=={"body","hmac_sha256"},"INVALID_PLAN")
        body=canonical(outer["body"]).encode("ascii")
        need(hmac.compare_digest(outer["hmac_sha256"],hmac.new(self.key,body,hashlib.sha256).hexdigest()),"INVALID_PLAN")
        d=outer["body"]; d["risks"]=tuple(Risk(**r) for r in d["risks"])
        plan=MovePlan(**d)
        need((time.time_ns() if now_ns is None else now_ns)<plan.expires_ns,"PLAN_EXPIRED")
        return plan

def make_move_plan(snapshot:TreeSnapshot,destination:str,*,destination_parent_volume:str,destination_absent:bool,
                   registry_revision:int,registry_sha256:str='0'*64,lease_id:str,risks:tuple[Risk,...]=(),now_ns:int|None=None,ttl_s:int=300,
                   source_scope:str='projects',source_authority_root:str=r'C:\\Projects',collection:str="projects",destination_collection_root:str=r'C:\\Projects')->MovePlan:
    now=time.time_ns() if now_ns is None else now_ns
    need(type(ttl_s) is int and 1<=ttl_s<=900,"INVALID_TTL")
    need(snapshot.complete,"INCOMPLETE_SNAPSHOT")
    source_authority_root=win_abs(source_authority_root);destination_collection_root=win_abs(destination_collection_root)
    need(same_or_child(snapshot.root,source_authority_root),'SOURCE_OUTSIDE_AUTHORITY')
    need(strict_child(destination,destination_collection_root),'DESTINATION_OUTSIDE_COLLECTION')
    return MovePlan(1,source_scope,collection,snapshot.root,destination,source_authority_root,destination_collection_root,
                    snapshot.fingerprint,snapshot.root_identity,snapshot.volume_id,destination_parent_volume,destination_absent,
                    registry_revision,registry_sha256,lease_id,now,now+ttl_s*1_000_000_000,risks)

class MoveJournal:
    """Append-only state machine. Filesystem adapter owns the actual OS rename/identity checks."""
    ORDER=("PLANNED","PRECHECKED","MOVED","VERIFIED","COMMITTED")
    def __init__(self): self._rows={}
    def begin(self,plan:MovePlan)->dict:
        pid=plan.plan_id
        if pid in self._rows:return dict(self._rows[pid][-1],replayed=True)
        row={"plan_id":pid,"state":"PLANNED","source":plan.source,"destination":plan.destination,"source_identity":plan.source_identity}
        self._rows[pid]=[row];return dict(row,replayed=False)
    def advance(self,plan_id:str,expected_state:str,next_state:str,**evidence)->dict:
        need(plan_id in self._rows,"UNKNOWN_PLAN")
        current=self._rows[plan_id][-1]
        need(current["state"]==expected_state,"JOURNAL_CONFLICT")
        allowed={"PLANNED":"PRECHECKED","PRECHECKED":"MOVED","MOVED":"VERIFIED","VERIFIED":"COMMITTED",
                 "MOVED":"VERIFIED"}
        need(allowed.get(expected_state)==next_state,"INVALID_TRANSITION")
        row={**current,"state":next_state,**evidence};self._rows[plan_id].append(row);return dict(row)
    def mark_rollback_required(self,plan_id:str,reason:str)->dict:
        need(plan_id in self._rows,"UNKNOWN_PLAN")
        current=self._rows[plan_id][-1]
        need(current["state"] in {"MOVED","VERIFIED"},"INVALID_TRANSITION")
        row={**current,"state":"ROLLBACK_REQUIRED","reason":reason};self._rows[plan_id].append(row);return dict(row)
    def mark_rolled_back(self,plan_id:str,evidence:dict)->dict:
        need(plan_id in self._rows,"UNKNOWN_PLAN")
        current=self._rows[plan_id][-1];need(current["state"]=="ROLLBACK_REQUIRED","INVALID_TRANSITION")
        row={**current,"state":"ROLLED_BACK","rollback_evidence":evidence};self._rows[plan_id].append(row);return dict(row)
    def current(self,plan_id:str)->dict:
        need(plan_id in self._rows,"UNKNOWN_PLAN");return dict(self._rows[plan_id][-1])
