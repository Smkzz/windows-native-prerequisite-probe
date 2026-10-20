"""Task-created file ownership; all project mutations go through the original broker.

No exec fallback, path-based unlink, recursive deletion, directory deletion, or
permission modification exists in this module. This is not an OS filesystem CAS.
"""
from __future__ import annotations
from .core import Context, Rejected, Signer, digest, integer, need, safe_relative, sha
from .ledger import Ledger
from .reads import Caller

NO_EFFECT = frozenset(('CONFLICT','READ_ONLY','PROTECTED_PATH','INVALID_PATH','OUTSIDE_ROOT',
                      'PRECONDITION_REQUIRED','NOT_FILE','NOT_FOUND',
                      'LINK_FORBIDDEN','HARDLINK_FORBIDDEN','DENIED','UNKNOWN_PROJECT'))

class TaskService:
    def __init__(self, caller:Caller, ledger:Ledger, signer:Signer, *, principal:str):
        from .core import ident
        self.principal=ident(principal)
        self.caller,self.ledger,self.signer=caller,ledger,signer

    @staticmethod
    def backend_id(c:Context,op:str)->str:
        return 'lcnext-'+digest([c.scope,op])

    async def create_file(self,c:Context,task:str,op:str,path:str,content:str)->dict:
        need(c.principal==self.principal,'PRINCIPAL_MISMATCH')
        c.authorize('file_write'); path=safe_relative(path)
        need(isinstance(content,str),'INVALID_TEXT')
        try: encoded=content.encode('utf-8')
        except UnicodeError: raise Rejected('INVALID_TEXT') from None
        need(len(encoded)<=65536,'FILE_LIMIT')
        need(not content.startswith('\ufeff') and '\0' not in content,'INVALID_TEXT')
        observed=sha(content.encode('utf-8'))
        replay=self.ledger.reserve_create(c,task,op,path,observed)
        if replay is not None: return replay
        try:
            result=await self.caller('file_write',c.project,{'path':path,'content':content,
                        'expected_sha256':'absent','request_id':self.backend_id(c,op)})
            need(isinstance(result,dict) and type(result.get('ok')) is bool,'BACKEND_CONTRACT')
            if result['ok']:
                data=result.get('data',{})
                need(data.get('created') is True and data.get('sha256')==observed and
                     safe_relative(data.get('path'))==path,'BACKEND_CONTRACT')
                compact={'ok':True,'data':{'path':path,'sha256':observed,'created':True},
                         'backend_request_id':self.backend_id(c,op)}
                self.ledger.finish_create(c,op,path,compact,True)
                return compact
            code=result.get('error',{}).get('code','BACKEND_ERROR')
            need(code in NO_EFFECT,'INDETERMINATE')
            compact={'ok':False,'error':{'code':code}}
            self.ledger.finish_create(c,op,path,compact,False)
            return compact
        except BaseException as exc:
            # A lost reply may hide a completed write. Do not free its ownership claim.
            try: self.ledger.unknown(c,op)
            except Exception: pass  # Durable pending intent still makes reopening conservative.
            if not isinstance(exc,Exception): raise
            raise Rejected('INDETERMINATE') from None

    async def cleanup_plan(self,c:Context,task:str,*,max_files:int=16)->dict:
        need(c.principal==self.principal,'PRINCIPAL_MISMATCH')
        c.authorize('file_read')
        integer(max_files,1,16)
        handoff=self.ledger.handoff(c,task,max_response_bytes=131072)
        need(not handoff['unknown_requires_reconciliation'],'INDETERMINATE')
        entries=[]
        # Recover original case from the exact task grants; claims use casefold keys.
        originals={p.casefold():p for p in handoff['authorized_exact_paths']}
        candidates=[claim for claim in handoff['owned_files'] if claim['state']!='removed']
        for claim in candidates[:max_files]:
            need(claim['state']=='live','INDETERMINATE')
            path=originals[claim['path']]
            response=await self.caller('file_read',c.project,{'path':path,'offset':0,'length':1})
            need(isinstance(response,dict) and type(response.get('ok')) is bool,'BACKEND_CONTRACT')
            actual=response.get('data',{}).get('sha256') if response['ok'] else None
            entry={'path':path,'generation':claim['generation'],'sha256':claim['sha256'],
                   'ready':response['ok'] and actual==claim['sha256']}
            if not entry['ready']:
                entry['reason']='CHANGED_OR_MISSING'
            entries.append(entry)
        data={'task':task,'entries':entries}
        return {**data,'plan':self.signer.sign(c,'cleanup',data),'atomic':False,
                'requires_exclusive_workspace':True,'deletes_directories':False,
                'remaining_files':max(0,len(candidates)-len(entries))}

    async def cleanup_apply(self,c:Context,plan:str,*,verified_exclusive_workspace:bool=False)->dict:
        need(c.principal==self.principal,'PRINCIPAL_MISMATCH')
        c.authorize('file_delete'); c.authorize('file_read')
        need(type(verified_exclusive_workspace) is bool,'INVALID_ARGUMENT')
        need(c.exclusive_workspace or verified_exclusive_workspace,'EXCLUSIVE_WORKSPACE_REQUIRED')
        data=self.signer.verify(plan,c,'cleanup')
        task=data['task']; entries=data['entries']
        need(all(entry['ready'] for entry in entries),'STALE_PLAN')
        # Validate all claims and current hashes before the first mutation.
        # This is fail-closed preflight, NOT a multi-file transaction.
        for entry in entries:
            claim=self.ledger.claim(c,task,entry['path'])
            need(claim['generation']==entry['generation'] and claim['sha256']==entry['sha256'],'STALE_PLAN')
            need(claim['state'] in ('live','removed'),'INDETERMINATE')
            if claim['state']=='live':
                response=await self.caller('file_read',c.project,{'path':entry['path'],'offset':0,'length':1})
                need(response.get('ok') is True and response.get('data',{}).get('sha256')==entry['sha256'],'STALE_PLAN')
        results=[]
        for entry in entries:
            path=entry['path']; generation=entry['generation']; observed=entry['sha256']
            op='cleanup-'+digest([task,path,generation])
            replay=self.ledger.reserve_delete(c,task,op,path,generation,observed,
                                              verified_exclusive_workspace=verified_exclusive_workspace)
            if replay is not None:
                results.append(replay)
                if not replay['ok']: break
                continue
            try:
                result=await self.caller('file_delete',c.project,{'path':path,'expected_sha256':observed,
                                                               'request_id':self.backend_id(c,op)})
                need(isinstance(result,dict) and type(result.get('ok')) is bool,'BACKEND_CONTRACT')
                if result['ok']:
                    d=result.get('data',{})
                    need(d.get('deleted') is True and d.get('previous_sha256')==observed and
                         safe_relative(d.get('path'))==path,'BACKEND_CONTRACT')
                    compact={'ok':True,'data':{'path':path,'deleted':True,'previous_sha256':observed},
                             'backend_request_id':self.backend_id(c,op)}
                    self.ledger.finish_delete(c,op,path,generation,compact,True)
                else:
                    code=result.get('error',{}).get('code','BACKEND_ERROR')
                    need(code in NO_EFFECT,'INDETERMINATE')
                    compact={'ok':False,'error':{'code':code},'path':path}
                    self.ledger.finish_delete(c,op,path,generation,compact,False)
                results.append(compact)
                if not compact['ok']: break
            except BaseException as exc:
                try: self.ledger.unknown(c,op)
                except Exception: pass
                if not isinstance(exc,Exception): raise
                raise Rejected('INDETERMINATE') from None
        return {'results':results,'not_attempted':len(entries)-len(results),'atomic':False,
                'scope':'recorded task-created files only'}
