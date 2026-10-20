"""LocalControl v0.6 maintenance data plane.

Authority-expanding operations are intentionally absent. Registry publication,
worker/profile provisioning, usage ingestion and health ingestion are operator-
owned local actions. MCP can only act inside the signed registry snapshot.
"""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
import json, ntpath, os, re, stat, sys, time
from pathlib import Path
from typing import Callable

from .errors import require
from .policy import no_links
from .v060.core import Rejected, digest, ident, need, same_or_child, strict_child, win_abs, RESERVED
from .v060.registry import RegistryCodec, RegistrySnapshot, RegistryStore, Workspace, Collection
from .v060.isolation import validate_control_plane_isolation
from .v060.durable_leases import DurableMaintenanceLeases
from .v060.migration import MovePlan, MovePlanCodec, Risk, make_move_plan
from .v060.journal import DurableMoveJournal
from .v060.executor import MoveExecutor
from .v060.windows_move import WindowsMoveAdapter
from .v060.risk_scan import scan_project_risks
from .v060.health_store import DurableHealthStore
from .v060.transactions import TransactionJournal, TransactionService
from .v060.usage_store import DurableUsageStore
from .v060.windows_discovery import MARKER_NAMES

VERSION='0.8.0-rc.1'
V060_FIELDS={
 'workspace_catalog': set(),
 'collection_inventory': {'collection','limit'},
 'project_discovery_candidates': {'limit'},
 'maintenance_begin': {'scopes','purpose','ttl_s','request_id'},
 'maintenance_end': {'lease_id','scope','request_id'},
 'project_move_plan': {'source_scope','source_relative','collection','destination_relative','lease_id','ttl_s'},
 'project_move_apply': {'plan','lease_id','acknowledged_warnings','request_id'},
 'project_move_status': {'plan_id'},
 'project_move_reconcile': {'plan_id','lease_id','request_id'},
 'project_move_rollback': {'plan_id','lease_id','request_id'},
 'task_cleanup_plan': {'task','lease_id','max_files'},
 'task_cleanup_apply': {'plan','lease_id','request_id'},
 'usage_summary': {'task'},
 'health_status': {'since_ns'},
 'transaction_plan': {'operations','ttl_s','mission_id','generation','fence_token'},
 'transaction_apply': {'plan','request_id','mission_id','generation','fence_token'},
 'transaction_status': {'plan_id'},
 'transaction_reconcile': {'plan_id','request_id','strategy'},
 'transaction_rollback': {'plan_id','request_id'},
}
GLOBAL_TOOLS=frozenset({'workspace_catalog','collection_inventory','project_discovery_candidates','maintenance_begin','maintenance_end',
                        'project_move_plan','project_move_apply','project_move_status','project_move_reconcile','project_move_rollback','health_status'})
PROJECT_TOOLS=frozenset({'task_cleanup_plan','task_cleanup_apply','usage_summary'})
TRANSACTION_TOOLS=frozenset({'transaction_plan','transaction_apply','transaction_status','transaction_reconcile','transaction_rollback'})
MUTATING_TOOLS=frozenset({'maintenance_begin','maintenance_end','project_move_apply','project_move_reconcile','project_move_rollback','task_cleanup_apply',
                          'transaction_apply','transaction_reconcile','transaction_rollback'})
MAINTENANCE_PURPOSES=frozenset({'project_move','task_cleanup','maintenance'})
_LEASE_CONTEXT:ContextVar[str|None]=ContextVar('localcontrol_v060_lease',default=None)
_DENIED_REL=frozenset({'.git','.ssh','.aws','.azure','.gnupg','.codex','.npmrc','.pypirc','.netrc','.git-credentials'})
_SECRET_REL=re.compile(r'^(?:\.env(?:\..*)?|credentials(?:\..*)?|id_(?:rsa|ed25519)(?:\..*)?)\Z',re.I)
def _key(path:Path)->bytes:
    no_links(path);need(path.is_file(),'V060_KEY_MISSING');st=path.stat();need(st.st_nlink==1,'UNSAFE_STATE_PATH')
    data=path.read_bytes();need(len(data)==32,'V060_KEY_SIZE');return data

def _safe_relative(value:str, *, allow_empty:bool=False)->str:
    need(isinstance(value,str) and len(value)<=2048,'INVALID_PATH')
    if allow_empty and value in ('','.'):return ''
    need(value and not ntpath.splitdrive(value)[0] and not value.startswith(('/', '\\')),'INVALID_PATH')
    parts=value.replace('\\','/').split('/')
    for p in parts:
        need(p and p not in ('.','..') and not p.endswith((' ','.')),'INVALID_PATH')
        need(not RESERVED.fullmatch(p) and p.casefold() not in _DENIED_REL and not _SECRET_REL.fullmatch(p),'INVALID_PATH')
        need(not any(ord(c)<32 or c in ':*?"<>|\x7f' for c in p),'INVALID_PATH')
    return '\\'.join(parts)

def _plan_from_dict(value:dict)->MovePlan:
    need(isinstance(value,dict),'INVALID_PLAN')
    data=dict(value);risks=data.get('risks');need(isinstance(risks,list),'INVALID_PLAN')
    data['risks']=tuple(Risk(**x) for x in risks)
    return MovePlan(**data)

class V060API:
    def __init__(self,policy,principal:str,next_api,config_path:Path,options:dict,
                 active_jobs:Callable[[],list[dict]], current_health:Callable[[],dict],
                 protected_paths:tuple[str,...]=()):
        need(os.name=='nt','PLATFORM_UNSUPPORTED')
        need(isinstance(options,dict) and set(options)=={'enabled','allowed_usage_adapters'} and options.get('enabled') is True,'V060_CONFIG')
        adapters=options.get('allowed_usage_adapters');need(isinstance(adapters,list) and 1<=len(adapters)<=16,'USAGE_ADAPTERS')
        self.policy,self.principal,self.next=policy,ident(principal),next_api
        self.config_path,self.active_jobs,self.current_health=config_path,active_jobs,current_health
        self.state=policy.state_dir/'v060';need(self.state.is_dir(),'V060_STATE_MISSING');no_links(self.state)
        self.registry=RegistryStore(self.state/'workspace-registry.json',RegistryCodec(_key(self.state/'registry-key.bin')))
        self.plan_codec=MovePlanCodec(_key(self.state/'move-key.bin'))
        self.leases=DurableMaintenanceLeases(self.state/'maintenance-leases.sqlite')
        self.journal=DurableMoveJournal(self.state/'move-journal.sqlite')
        self.health=DurableHealthStore(self.state/'health.sqlite')
        self.usage=DurableUsageStore(self.state/'usage.sqlite',frozenset(ident(x) for x in adapters))
        self.transaction_journal=TransactionJournal(self.state/'transaction-journal.sqlite')
        self.transactions=TransactionService(policy,self.principal,next_api,self.transaction_journal,
                                             registry_provider=self.registry_binding)
        self.adapter=WindowsMoveAdapter(max_entries=250000,max_scan_seconds=30)
        self.executor=MoveExecutor(self.adapter,self.journal,self.leases)
        self.discovery_report=self.state/'discovery-candidates.json'
        self.runtime_root=str(Path(__file__).resolve().parents[1])
        protected=[self.runtime_root,str(Path(sys.executable).resolve()),str(Path(sys.prefix).resolve()),str(Path(sys.base_prefix).resolve())]
        protected.extend(win_abs(x) for x in protected_paths)
        for value in protected:
            no_links(Path(value))
        for spec in policy.workers.values():
            manifest=Path(spec['manifest']);no_links(manifest);protected.append(str(manifest.resolve()))
            try:m=json.loads(manifest.read_text(encoding='utf-8'))
            except Exception:raise Rejected('SANDBOX_CONFIG') from None
            runtime=m.get('runtime');need(isinstance(runtime,str),'SANDBOX_CONFIG');protected.append(win_abs(runtime))
        self.protected_paths=tuple(dict.fromkeys(protected))
        self._load_registry() # fail closed before serving tools

    @staticmethod
    def _entity(snapshot:RegistrySnapshot,name:str):
        ident(name)
        found=[x for x in (*snapshot.workspaces,*snapshot.collections) if x.name.casefold()==name.casefold()]
        need(len(found)==1,'UNKNOWN_SCOPE');return found[0]
    def _load_registry(self)->RegistrySnapshot:
        snapshot=self.registry.load()
        validate_control_plane_isolation(snapshot,runtime_roots=list(self.protected_paths),state_root=str(self.policy.state_dir),config_paths=[str(self.config_path)])
        for entity in (*snapshot.workspaces,*snapshot.collections):no_links(Path(entity.root))
        by_name={w.name.casefold():w for w in snapshot.workspaces}
        expected_exec=self.policy.exec_mode!='disabled'
        for name,spec in self.policy.projects.items():
            w=by_name.get(name.casefold())
            need(w is not None and ntpath.normcase(w.root)==ntpath.normcase(str(spec.root)) and w.writable==spec.writable
                 and w.exec_enabled==expected_exec and not w.maintenance,'REGISTRY_BASE_PROJECT_MISMATCH')
        base_names={name.casefold() for name in self.policy.projects}
        for w in snapshot.workspaces:
            if w.name.casefold() not in base_names:
                need(w.maintenance and not w.exec_enabled,'REGISTRY_AUTHORITY_ESCALATION')
        return snapshot
    def _binding(self,snapshot:RegistrySnapshot)->str:
        base={n:{'root':str(p.root),'writable':p.writable} for n,p in sorted(self.policy.projects.items())}
        return digest({'registry':snapshot.sha256,'base_projects':base,'exec_mode':self.policy.exec_mode,'principal':self.principal})
    def registry_binding(self)->dict:
        s=self._load_registry()
        return {'revision':s.revision,'sha256':s.sha256}
    def _scope_roots(self,snapshot:RegistrySnapshot,names:list[str])->list[tuple[str,str,bool]]:
        out=[]
        for name in names:
            x=self._entity(snapshot,name);out.append((x.name,x.root,x.writable))
        return out
    def _affected_base_projects(self,snapshot:RegistrySnapshot,scopes:list[str])->set[str]:
        roots=[root for _,root,_ in self._scope_roots(snapshot,scopes)];out=set()
        for name,p in self.policy.projects.items():
            proot=str(p.root)
            if any(same_or_child(proot,r) or same_or_child(r,proot) for r in roots):out.add(name)
        return out
    def _running_jobs_for(self,projects:set[str])->list[str]:
        running=[]
        for j in self.active_jobs():
            if j.get('project') in projects and j.get('status') in {'starting','running'}:running.append(j.get('job_id') or j.get('id'))
        return [x for x in running if isinstance(x,str)]
    def _unresolved_scope_names(self)->set[str]:
        names=set()
        for row in self.journal.unresolved():
            try:
                plan=_plan_from_dict(self.journal.get(row['plan_id'])['plan'])
                names.update((plan.source_scope.casefold(),plan.collection.casefold()))
            except Exception:
                names.add('*')
        return names

    def guard_base_mutation(self,project:str)->None:
        snapshot=self._load_registry();root=str(self.policy.projects[project].root);scopes=[]
        for w in snapshot.workspaces:
            if ntpath.normcase(w.root)==ntpath.normcase(root):scopes.append(w.name)
        for c in snapshot.collections:
            if same_or_child(root,c.root):scopes.append(c.name)
        unresolved=self._unresolved_scope_names()
        need('*' not in unresolved and not any(scope.casefold() in unresolved for scope in scopes),'UNRESOLVED_MOVE')
        current=_LEASE_CONTEXT.get()
        for scope in scopes:
            need(self.leases.mutation_allowed(scope,current),'MAINTENANCE_ACTIVE')
    @contextmanager
    def internal_lease(self,lease_id:str):
        token=_LEASE_CONTEXT.set(lease_id)
        try:yield
        finally:_LEASE_CONTEXT.reset(token)
    def current_lease_id(self)->str|None:return _LEASE_CONTEXT.get()

    def workspace_catalog(self)->dict:
        s=self._load_registry()
        work=[]
        for w in s.workspaces:
            work.append({'name':w.name,'root':w.root,'writable':w.writable,'exec_enabled':w.exec_enabled,'maintenance':w.maintenance,'exists':Path(w.root).is_dir()})
        cols=[]
        for c in s.collections:cols.append({'name':c.name,'root':c.root,'writable':c.writable,'exists':Path(c.root).is_dir()})
        return {'version':VERSION,'revision':s.revision,'registry_sha256':s.sha256,'workspaces':work,'collections':cols,
                'authority_mutation_exposed':False,'operator_only_registry':True,'active_leases':self.leases.active(),
                'unresolved_moves':self.journal.unresolved()}

    def collection_inventory(self,collection:str,limit:int=250)->dict:
        need(type(limit)is int and 1<=limit<=500,'INVALID_LIMIT');s=self._load_registry();c=self._entity(s,collection);need(isinstance(c,Collection),'NOT_COLLECTION')
        root=Path(c.root);need(root.is_dir(),'COLLECTION_MISSING');no_links(root)
        entries=[];omitted=0
        try:rows=list(os.scandir(root))
        except OSError:raise Rejected('COLLECTION_UNREADABLE') from None
        for d in sorted(rows,key=lambda x:x.name.casefold()):
            if d.name.casefold() in _DENIED_REL or _SECRET_REL.fullmatch(d.name):omitted+=1;continue
            if len(entries)>=limit:omitted+=1;continue
            try:
                st=d.stat(follow_symlinks=False);reparse=bool(getattr(st,'st_file_attributes',0)&0x400)
                markers=[]
                if d.is_dir(follow_symlinks=False) and not reparse:
                    try:
                        with os.scandir(d.path) as sub:
                            for x in sub:
                                n=x.name.casefold()
                                if n in MARKER_NAMES or n.endswith('.sln') or n.endswith('.csproj'):markers.append(x.name)
                    except OSError:pass
                entries.append({'name':d.name,'is_dir':d.is_dir(follow_symlinks=False),'is_file':d.is_file(follow_symlinks=False),
                                'reparse':reparse,'size':int(st.st_size),'mtime_ns':int(st.st_mtime_ns),'project_markers':sorted(markers)[:32]})
            except OSError:omitted+=1
        return {'collection':c.name,'root':c.root,'entries':entries,'truncated':omitted>0,'omitted':omitted,'content_read':False}

    def discovery_candidates(self,limit:int=200)->dict:
        need(type(limit)is int and 1<=limit<=500,'INVALID_LIMIT')
        if not self.discovery_report.exists():return {'available':False,'candidates':[],'operator_report_required':True}
        no_links(self.discovery_report);raw=self.discovery_report.read_bytes();need(len(raw)<=5_000_000,'DISCOVERY_REPORT_LIMIT')
        try:data=json.loads(raw)
        except Exception:raise Rejected('DISCOVERY_REPORT_CORRUPT') from None
        rows=data.get('candidates') if isinstance(data,dict) else None;need(isinstance(rows,list),'DISCOVERY_REPORT_CORRUPT')
        out=[]
        for row in rows[:limit]:
            need(isinstance(row,dict),'DISCOVERY_REPORT_CORRUPT')
            path=win_abs(row.get('path'));markers=row.get('markers',[]);classification=row.get('classification')
            need(isinstance(markers,(list,tuple)) and len(markers)<=64 and all(isinstance(x,str) and len(x)<=128 for x in markers),'DISCOVERY_REPORT_CORRUPT')
            need(classification in {'top_level','nested_component','ambiguous','likely_vendor'},'DISCOVERY_REPORT_CORRUPT')
            out.append({'path':path,'markers':list(markers),'classification':classification,'parent_project':row.get('parent_project') if isinstance(row.get('parent_project'),str) else None})
        return {'available':True,'candidates':out,'truncated':len(rows)>limit,'content_read':False,'source':'operator_pinned_discovery_adapter'}

    def maintenance_begin(self,scopes:list[str],purpose:str,ttl_s:int=300)->dict:
        need(isinstance(scopes,list) and 1<=len(scopes)<=8,'INVALID_SCOPES');need(purpose in MAINTENANCE_PURPOSES,'INVALID_PURPOSE')
        s=self._load_registry();resolved=self._scope_roots(s,scopes);need(all(w for _,_,w in resolved),'READ_ONLY')
        canonical=tuple(sorted({name for name,_,_ in resolved},key=str.casefold));need(len(canonical)==len(scopes),'DUPLICATE_SCOPE')
        affected=self._affected_base_projects(s,list(canonical));running=self._running_jobs_for(affected);need(not running,'OWNED_JOB_ACTIVE')
        unresolved=self._unresolved_scope_names()
        if purpose!='project_move':need('*' not in unresolved and not any(x.casefold() in unresolved for x in canonical),'UNRESOLVED_MOVE')
        lease=self.leases.begin_many(canonical,self.principal,self._binding(s),purpose,ttl_s)
        return {'lease_id':lease.lease_id,'scopes':list(lease.scopes),'purpose':lease.purpose,'expires_ns':lease.expires_ns,
                'localcontrol_exclusive_only':True,'unrelated_host_processes_not_locked':True}
    def maintenance_end(self,lease_id:str,scope:str)->dict:
        s=self._load_registry();x=self._entity(s,scope);binding=self._binding(s)
        lease=self.leases.verify(lease_id,x.name,self.principal,binding)
        unresolved=self._unresolved_scope_names();need('*' not in unresolved and not any(name.casefold() in unresolved for name in lease.scopes),'LEASE_HAS_UNRESOLVED_MOVE')
        return self.leases.end(lease_id,x.name,self.principal,binding)

    def _is_live_workspace(self,w:Workspace)->bool:
        root=ntpath.normcase(w.root)
        return any(ntpath.normcase(str(spec.root))==root for spec in self.policy.projects.values())

    def _source(self,s:RegistrySnapshot,source_scope:str,source_relative:str|None)->tuple[str,str]:
        x=self._entity(s,source_scope);need(x.writable,'READ_ONLY')
        if isinstance(x,Workspace):
            need(not self._is_live_workspace(x),'LIVE_WORKSPACE_MOVE_REQUIRES_OPERATOR_RECONFIG')
            need(source_relative in (None,'','.'),'WORKSPACE_SOURCE_MUST_BE_ROOT');return x.root,x.root
        rel=_safe_relative(source_relative or '');need(rel,'SOURCE_REQUIRED');source=str(Path(x.root)/rel);need(strict_child(source,x.root),'SOURCE_OUTSIDE_AUTHORITY')
        for spec in self.policy.projects.values():
            need(not same_or_child(str(spec.root),source),'LIVE_WORKSPACE_MOVE_REQUIRES_OPERATOR_RECONFIG')
        return source,x.root
    def _destination(self,s:RegistrySnapshot,collection:str,relative:str)->tuple[Collection,str]:
        c=self._entity(s,collection);need(isinstance(c,Collection),'NOT_COLLECTION');need(c.writable,'READ_ONLY')
        rel=_safe_relative(relative);dest=str(Path(c.root)/rel);need(strict_child(dest,c.root),'DESTINATION_OUTSIDE_COLLECTION');return c,dest
    def _validate_plan_registry(self,p:MovePlan,s:RegistrySnapshot)->None:
        need(p.registry_revision==s.revision and p.registry_sha256==s.sha256,'REGISTRY_CHANGED')
        src=self._entity(s,p.source_scope);dst=self._entity(s,p.collection);need(isinstance(dst,Collection),'NOT_COLLECTION')
        need(ntpath.normcase(src.root)==ntpath.normcase(p.source_authority_root),'REGISTRY_CHANGED')
        need(ntpath.normcase(dst.root)==ntpath.normcase(p.destination_collection_root),'REGISTRY_CHANGED')
        if isinstance(src,Workspace):need(not self._is_live_workspace(src),'LIVE_WORKSPACE_MOVE_REQUIRES_OPERATOR_RECONFIG')
    def move_plan(self,source_scope:str,collection:str,destination_relative:str,lease_id:str,source_relative:str|None=None,ttl_s:int=300)->dict:
        s=self._load_registry();source,authority=self._source(s,source_scope,source_relative);c,dest=self._destination(s,collection,destination_relative)
        binding=self._binding(s);unique=tuple(sorted({source_scope,c.name},key=str.casefold));self.leases.verify_many(lease_id,unique,self.principal,binding)
        unresolved=self._unresolved_scope_names();need('*' not in unresolved and not any(scope.casefold() in unresolved for scope in unique),'UNRESOLVED_MOVE')
        self.adapter.validate_paths(source,dest,authority,c.root);need(not self.adapter.exists(dest),'DESTINATION_EXISTS')
        snap=self.adapter.snapshot(source);need(snap.complete,'INCOMPLETE_SNAPSHOT');scan=scan_project_risks(snap)
        risks=scan['risks'];plan=make_move_plan(snap,dest,destination_parent_volume=self.adapter.parent_volume(dest),destination_absent=True,
             registry_revision=s.revision,registry_sha256=s.sha256,lease_id=lease_id,risks=risks,ttl_s=ttl_s,source_scope=source_scope,
             source_authority_root=authority,collection=c.name,destination_collection_root=c.root)
        warning_codes=sorted({r.code for r in risks if r.severity=='warning'})
        return {'plan_id':plan.plan_id,'plan':self.plan_codec.encode(plan),'source':source,'destination':dest,'source_fingerprint':snap.fingerprint,
                'entries':len(snap.entries),'risks':[r.__dict__ for r in risks],'warning_codes':warning_codes,'warnings_require_acknowledgement':bool(warning_codes),
                'risk_scan':{k:v for k,v in scan.items() if k!='risks'},'same_volume_only':True,'expires_ns':plan.expires_ns}
    def move_apply(self,token:str,lease_id:str,acknowledged_warnings:list[str])->dict:
        need(isinstance(acknowledged_warnings,list) and len(acknowledged_warnings)<=64 and all(isinstance(x,str) for x in acknowledged_warnings),'INVALID_WARNING_ACK')
        p=self.plan_codec.decode(token);need(lease_id==p.lease_id,'LEASE_MISMATCH');s=self._load_registry();self._validate_plan_registry(p,s)
        warnings={r.code for r in p.risks if r.severity=='warning'};need(set(acknowledged_warnings)==warnings,'WARNING_ACK_REQUIRED')
        return self.executor.apply(p,registry_revision=s.revision,registry_sha256=s.sha256,owner=self.principal,binding=self._binding(s),lease_id=lease_id)
    def move_status(self,plan_id:str)->dict:
        ident(plan_id);row=self.journal.get(plan_id);p=_plan_from_dict(row['plan'])
        return {'plan_id':plan_id,'state':row['state'],'source':p.source,'destination':p.destination,'updated_ns':row['updated_ns'],'evidence':row['evidence'],
                'needs_reconciliation':row['state'] in {'PRECHECKED','MOVED','VERIFIED','ROLLBACK_REQUIRED','INDETERMINATE'}}
    def _journal_plan(self,plan_id:str)->MovePlan:
        ident(plan_id);return _plan_from_dict(self.journal.get(plan_id)['plan'])
    def move_reconcile(self,plan_id:str,lease_id:str)->dict:
        p=self._journal_plan(plan_id);s=self._load_registry();self._validate_plan_registry(p,s)
        return self.executor.reconcile(p,owner=self.principal,binding=self._binding(s),lease_id=lease_id)
    def move_rollback(self,plan_id:str,lease_id:str)->dict:
        p=self._journal_plan(plan_id);s=self._load_registry();self._validate_plan_registry(p,s)
        return self.executor.rollback(p,owner=self.principal,binding=self._binding(s),lease_id=lease_id)

    def _cleanup_context(self,project:str,lease_id:str):
        need(project in self.policy.projects,'UNKNOWN_PROJECT');s=self._load_registry();w=self._entity(s,project);need(isinstance(w,Workspace),'NOT_WORKSPACE')
        need(ntpath.normcase(w.root)==ntpath.normcase(str(self.policy.projects[project].root)),'REGISTRY_CHANGED')
        self.leases.verify(lease_id,w.name,self.principal,self._binding(s));return self.next.context(project)
    async def cleanup_plan(self,project:str,task:str,lease_id:str,max_files:int=16)->dict:
        c=self._cleanup_context(project,lease_id);return await self.next.tasks.cleanup_plan(c,task,max_files=max_files)
    async def cleanup_apply(self,project:str,plan:str,lease_id:str)->dict:
        c=self._cleanup_context(project,lease_id)
        with self.internal_lease(lease_id):
            return await self.next.tasks.cleanup_apply(c,plan,verified_exclusive_workspace=True)

    def usage_summary(self,project:str,task:str|None)->dict:
        if project=='*':return self.usage.summary(None,task)
        need(project in self.policy.projects,'UNKNOWN_PROJECT');return self.usage.summary(project,task)
    def health_status(self,since_ns:int|None)->dict:
        return {'telemetry':self.health.summary(since_ns=since_ns),'current_server':self.current_health(),'v060_version':VERSION,
                'supervisor_ingestion_is_operator_only':True}

    async def call(self,tool:str,project:str,args:dict)->dict:
        need(tool in V060_FIELDS,'INVALID_ARGUMENT')
        if tool in GLOBAL_TOOLS:need(project=='*','CATALOG_SCOPE_REQUIRED')
        elif tool in PROJECT_TOOLS:need(project=='*' or project in self.policy.projects,'UNKNOWN_PROJECT')
        if tool=='workspace_catalog':return self.workspace_catalog()
        if tool=='collection_inventory':return self.collection_inventory(args['collection'],args.get('limit',250))
        if tool=='project_discovery_candidates':return self.discovery_candidates(args.get('limit',200))
        if tool=='maintenance_begin':return self.maintenance_begin(args['scopes'],args['purpose'],args.get('ttl_s',300))
        if tool=='maintenance_end':return self.maintenance_end(args['lease_id'],args['scope'])
        if tool=='project_move_plan':return self.move_plan(args['source_scope'],args['collection'],args['destination_relative'],args['lease_id'],args.get('source_relative'),args.get('ttl_s',300))
        if tool=='project_move_apply':return self.move_apply(args['plan'],args['lease_id'],args.get('acknowledged_warnings',[]))
        if tool=='project_move_status':return self.move_status(args['plan_id'])
        if tool=='project_move_reconcile':return self.move_reconcile(args['plan_id'],args['lease_id'])
        if tool=='project_move_rollback':return self.move_rollback(args['plan_id'],args['lease_id'])
        if tool=='task_cleanup_plan':need(project!='*','PROJECT_REQUIRED');return await self.cleanup_plan(project,args['task'],args['lease_id'],args.get('max_files',16))
        if tool=='task_cleanup_apply':need(project!='*','PROJECT_REQUIRED');return await self.cleanup_apply(project,args['plan'],args['lease_id'])
        if tool=='usage_summary':return self.usage_summary(project,args.get('task'))
        if tool=='health_status':return self.health_status(args.get('since_ns'))
        if tool in TRANSACTION_TOOLS:
            need(project!='*' and project in self.policy.projects,'PROJECT_REQUIRED')
            if tool=='transaction_plan':return self.transactions.plan(project,args['operations'],args.get('ttl_s',300))
            if tool=='transaction_apply':return await self.transactions.apply(project,args['plan'],request_id=args['request_id'])
            if tool=='transaction_status':return self.transactions.status(args['plan_id'])
            if tool=='transaction_reconcile':return await self.transactions.reconcile(project,args['plan_id'],request_id=args['request_id'],strategy=args.get('strategy','rollback'))
            if tool=='transaction_rollback':return await self.transactions.rollback(project,args['plan_id'],request_id=args['request_id'])
        raise Rejected('INVALID_ARGUMENT')

    def close(self):
        for x in (self.journal,self.leases,self.health,self.usage,self.transaction_journal):
            try:x.close()
            except Exception:pass


