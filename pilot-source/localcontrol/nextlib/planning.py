"""Read-only recipe preflight and resource admission preview, NOT a scheduler."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
from .core import Context, HEX, digest, ident, integer, need, safe_relative
from .reads import Caller

@dataclass(frozen=True)
class Recipe:
    name: str
    revision: str
    inputs: tuple[tuple[str,str], ...]
    memory_mib: int
    timeout_ms: int
    def __post_init__(self):
        ident(self.name); ident(self.revision)
        integer(self.memory_mib,1,1048576); integer(self.timeout_ms,1,3600000)
        need(isinstance(self.inputs,tuple) and 1<=len(self.inputs)<=32)
        for pair in self.inputs:
            need(isinstance(pair,tuple) and len(pair)==2)
            path,observed=pair
            need(safe_relative(path)==path)
            need(isinstance(observed,str) and bool(HEX.fullmatch(observed)))
        need(len({p.casefold() for p,h in self.inputs})==len(self.inputs),'DUPLICATE_PATH')

    @property
    def fingerprint(self):
        return digest({'name':self.name,'revision':self.revision,'inputs':self.inputs,
                       'memory_mib':self.memory_mib,'timeout_ms':self.timeout_ms})

async def recipe_preflight(c:Context,caller:Caller,catalog:Mapping[str,Recipe],name:str,*,principal:str)->dict:
    # Catalog comes from operator configuration, not a project-supplied plan.
    need(c.principal==ident(principal),'PRINCIPAL_MISMATCH')
    c.authorize('file_read'); ident(name)
    need(name in catalog,'UNKNOWN_RECIPE')
    recipe=catalog[name]
    need(name==recipe.name,'INVALID_RECIPE')
    findings=[]
    for path,expected in recipe.inputs:
        c.authorize('file_read')
        result=await caller('file_read',c.project,{'path':path,'offset':0,'length':1})
        actual=result.get('data',{}).get('sha256') if result.get('ok') is True else None
        findings.append({'path':path,'matches':actual==expected,'observed_sha256':actual})
    return {'recipe':name,'recipe_sha256':recipe.fingerprint,'inputs':findings,
            'inputs_match':all(f['matches'] for f in findings),'execution_started':False,
            'not_a_frozen_snapshot':True,'needs_broker_recipe_binding':True}

def admission_preview(recipe:Recipe,available_mib:int|None,headroom_mib:int,
                      reservations:list[dict],project:str,max_jobs:int=2,per_project:int=1)->dict:
    ident(project); integer(headroom_mib,0,1048576)
    integer(max_jobs,1,128); integer(per_project,1,max_jobs)
    need(isinstance(reservations,list) and len(reservations)<=128)
    for item in reservations:
        need(isinstance(item,dict) and set(item)=={'project','memory_mib','state'})
        ident(item['project']); integer(item['memory_mib'],1,1048576)
        need(item['state'] in ('running','unknown','completed'))
    active=[r for r in reservations if r['state']!='completed']
    reasons=[]
    if len(active)>=max_jobs: reasons.append('GLOBAL_CONCURRENCY')
    if sum(r['project']==project for r in active)>=per_project: reasons.append('PROJECT_CONCURRENCY')
    if any(r['state']=='unknown' for r in active): reasons.append('UNRECONCILED_JOB')
    reserved=sum(r['memory_mib'] for r in active)
    if available_mib is None:
        reasons.append('MEMORY_TELEMETRY_UNAVAILABLE')
    else:
        integer(available_mib,0,1048576)
        if available_mib-reserved-recipe.memory_mib<headroom_mib:
            reasons.append('MEMORY_HEADROOM')
    return {'admit':not reasons,'reasons':reasons,'requested_mib':recipe.memory_mib,
            'reserved_mib':reserved,'headroom_mib':headroom_mib,
            'mode':'advisory_preview_only','os_resource_enforcement':False,
            'accounts_for_gpu':False,'telemetry_freshness_verified':False,
            'may_conservatively_double_count_running_memory':True}
