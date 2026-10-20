"""Bounded, policy-rechecked read aggregation. Does not cache file contents."""
from __future__ import annotations
from typing import Any, Awaitable, Callable
from .core import Context, Signer, HEX, integer, need, packed, safe_relative, sha, Rejected

Caller = Callable[[str,str,dict], Awaitable[dict]]

class ReadService:
    def __init__(self, caller: Caller, signer: Signer, *, principal: str, min_change_bytes: int = 1024):
        from .core import ident
        self.principal = ident(principal)
        self.min_change_bytes = integer(min_change_bytes,0,1048576)
        self.caller, self.signer = caller, signer
        self.calls = 0
        self.upstream_bytes = 0
        self.output_bytes = 0

    async def _call(self, context: Context, tool: str, args: dict) -> dict:
        need(context.principal == self.principal, 'PRINCIPAL_MISMATCH')
        context.authorize(tool)  # Recheck for EVERY constituent read, even an unchanged one.
        self.calls += 1
        result = await self.caller(tool,context.project,args)
        need(isinstance(result,dict) and type(result.get('ok')) is bool, 'BACKEND_CONTRACT')
        self.upstream_bytes += len(packed(result))
        return result

    async def read_batch(self, context: Context, requests: list[dict],
                         max_response_bytes: int = 65536) -> dict:
        need(context.principal == self.principal, 'PRINCIPAL_MISMATCH')
        context.authorize('file_read')
        need(isinstance(requests,list) and 1<=len(requests)<=32)
        integer(max_response_bytes,2048,131072)
        need(len(packed(requests))<=65536, 'INPUT_LIMIT')
        normalized = []
        # Validate the ENTIRE input before upstream reads.
        for request in requests:
            need(isinstance(request,dict) and set(request)<={'path','offset','length','previous','stat'})
            path = safe_relative(request.get('path'))
            stat = request.get('stat', False)
            need(type(stat) is bool, 'INVALID_ARGUMENT')
            if stat:
                # SHA-only observation: one bounded line is read to obtain the
                # full-file SHA without returning file content.
                need('previous' not in request and 'offset' not in request and 'length' not in request,
                     'INVALID_ARGUMENT')
                normalized.append((path,0,1,None,True))
                continue
            offset = integer(request.get('offset',0),0,100000000)
            length = integer(request.get('length',200),1,2000)
            previous = None
            if 'previous' in request:
                previous = self.signer.verify(request['previous'],context,'read')
                need(previous['range']==[path,offset,length], 'STALE_CURSOR')
            normalized.append((path,offset,length,previous,False))
        rows = []
        for index,(path,offset,length,previous,stat) in enumerate(normalized):
            response = await self._call(context,'file_read',{'path':path,'offset':offset,'length':length})
            row: dict[str,Any] = {'index':index,'path':path}
            if not response['ok']:
                row.update(ok=False,error=response.get('error',{}).get('code','BACKEND_ERROR'))
            elif stat:
                observed = response.get('data',{}).get('sha256')
                need(isinstance(observed,str) and bool(HEX.fullmatch(observed)),'BACKEND_CONTRACT')
                row.update(ok=True,stat=True,sha256=observed,
                           source_truncated=bool(response.get('data',{}).get('truncated',False)))
            else:
                data = response.get('data',{})
                content, observed = data.get('content'),data.get('sha256')
                need(isinstance(content,str) and isinstance(observed,str) and bool(HEX.fullmatch(observed)),
                     'BACKEND_CONTRACT')
                state = {'range':[path,offset,length],'sha256':observed,'content_sha256':sha(content.encode('utf-8')),
                         'source_truncated':bool(data.get('truncated',False))}
                unchanged = previous == state
                token=self.signer.sign(context,'read',state)
                economical=(self.min_change_bytes==0 or
                            len(content.encode('utf-8'))>=max(self.min_change_bytes,len(token)+100))
                row.update(ok=True,sha256=observed,unchanged=unchanged,
                           source_truncated=state['source_truncated'])
                if economical:
                    row['previous']=token
                else:
                    row['change_tracking']='omitted_for_small_read'
                if not unchanged:
                    row['content'] = content
            candidate = {'items':rows+[row],'next_index':index+1 if index+1<len(normalized) else None,
                         'deferred':len(normalized)-index-1,
                         'consistency':'per-file; not a multi-file snapshot'}
            if len(packed(candidate)) > max_response_bytes:
                if not rows:
                    # A too-large first item must not create an unadvanceable empty page.
                    row = {'index':index,'path':path,'ok':False,'error':'RESPONSE_LIMIT',
                           'action':'retry this item with a smaller line range'}
                    rows.append(row)
                break
            rows.append(row)
        answer = {'items':rows,'next_index':len(rows) if len(rows)<len(normalized) else None,
                  'deferred':len(normalized)-len(rows),'consistency':'per-file; not a multi-file snapshot'}
        need(len(packed(answer))<=max_response_bytes, 'RESPONSE_LIMIT')
        self.output_bytes += len(packed(answer))
        return answer

    async def job_delta(self, context: Context, job_id: str, cursor: str | None = None,
                        max_bytes: int = 16384, wait_ms: int = 0) -> dict:
        from .core import ident
        need(context.principal == self.principal, 'PRINCIPAL_MISMATCH')
        context.authorize('job_read'); ident(job_id)
        integer(max_bytes,4,65536); integer(wait_ms,0,25000)
        previous = self.signer.verify(cursor,context,'job') if cursor is not None else None
        if previous is not None:
            need(previous['job']==job_id,'STALE_CURSOR')
        response = await self._call(context,'job_read',{'job_id':job_id,'wait_ms':wait_ms})
        if not response['ok']:
            raise Rejected(response.get('error',{}).get('code','BACKEND_ERROR'))
        data = response['data']
        need(data.get('job_id',job_id)==job_id,'BACKEND_CONTRACT')
        turn = previous.get('turn',0) if previous is not None else 0
        state = {'job':job_id,'turn':1-turn}
        output = {}
        remaining = max_bytes
        pending = False
        # Budget guarantees are for UTF-8 PAYLOAD bytes, not the entire JSON envelope.
        for name in (('stdout','stderr') if turn==0 else ('stderr','stdout')):
            need(isinstance(data.get(name,''),str),'BACKEND_CONTRACT')
            stream = data.get(name,'').encode('utf-8')
            pos = previous[name]['offset'] if previous is not None else 0
            if previous is not None:
                need(0<=pos<=len(stream) and sha(stream[:pos])==previous[name]['prefix_sha256'],
                     'OUTPUT_REPLACED')
            chunk = stream[pos:pos+remaining].decode('utf-8',errors='ignore')
            consumed = len(chunk.encode('utf-8'))
            output[name] = chunk
            pos += consumed
            remaining -= consumed
            pending = pending or pos<len(stream)
            state[name] = {'offset':pos,'prefix_sha256':sha(stream[:pos])}
        result = {'job_id':job_id,'status':data.get('status'),'returncode':data.get('returncode'),
                  **output,'cursor':self.signer.sign(context,'job',state),
                  'more_captured_output':pending,
                  'source_truncated':bool(data.get('stdout_truncated') or data.get('stderr_truncated')),
                  'source_stdout_bytes':data.get('stdout_bytes'),
                  'source_stderr_bytes':data.get('stderr_bytes'),
                  'upstream_reads_full_captured_output':True}
        self.output_bytes += len(packed(result))
        return result

    def metrics(self) -> dict:
        return {'backend_calls':self.calls,'backend_json_bytes':self.upstream_bytes,
                'emitted_json_bytes':self.output_bytes,'model_tokens':None,
                'token_accounting':'unavailable; not inferred from bytes',
                'scope':'this ReadService instance; no content stored'}
