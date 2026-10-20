from __future__ import annotations
from dataclasses import dataclass
import secrets, time
from .core import ident, need

@dataclass(frozen=True)
class Lease:
    lease_id: str
    scopes: tuple[str,...]
    owner: str
    policy_binding: str
    expires_ns: int
    purpose: str

class MaintenanceLeases:
    """LocalControl-owned exclusivity across one or more scopes.

    This never claims to exclude unrelated host processes. Filesystem CAS/identity
    checks remain mandatory. Multi-scope acquisition is atomic inside the server,
    preventing a move from racing another LocalControl mutation at either endpoint.
    """
    def __init__(self, clock_ns=time.time_ns, max_ttl_s: int=900):
        self.clock_ns,self.max_ttl_s,self._by_scope,self._by_id=clock_ns,max_ttl_s,{},{}
    def _active(self, scope: str):
        lease=self._by_scope.get(scope.casefold())
        if lease and lease.expires_ns<=self.clock_ns():self._expire(lease);return None
        return lease
    def _expire(self,lease:Lease):
        for scope in lease.scopes:
            if self._by_scope.get(scope.casefold()) is lease:self._by_scope.pop(scope.casefold(),None)
        self._by_id.pop(lease.lease_id,None)
    def begin_many(self,scopes:tuple[str,...],owner:str,policy_binding:str,purpose:str,ttl_s:int=300)->Lease:
        need(isinstance(scopes,tuple) and 1<=len(scopes)<=8,'INVALID_SCOPES')
        normalized=tuple(sorted({ident(s) for s in scopes},key=str.casefold));need(len(normalized)==len(scopes),'DUPLICATE_SCOPE')
        ident(owner);ident(policy_binding);ident(purpose);need(type(ttl_s)is int and 1<=ttl_s<=self.max_ttl_s,'INVALID_TTL')
        for scope in normalized:need(self._active(scope) is None,'WORKSPACE_BUSY')
        lease=Lease('lease-'+secrets.token_hex(16),normalized,owner,policy_binding,self.clock_ns()+ttl_s*1_000_000_000,purpose)
        for scope in normalized:self._by_scope[scope.casefold()]=lease
        self._by_id[lease.lease_id]=lease;return lease
    def begin(self,workspace:str,owner:str,policy_binding:str,purpose:str,ttl_s:int=300)->Lease:
        return self.begin_many((workspace,),owner,policy_binding,purpose,ttl_s)
    def verify(self,lease_id:str,workspace:str,owner:str,policy_binding:str)->Lease:
        ident(workspace);lease=self._active(workspace);need(lease is not None,'LEASE_REQUIRED')
        need(lease.lease_id==lease_id and lease.owner==owner and lease.policy_binding==policy_binding,'LEASE_MISMATCH');return lease
    def verify_many(self,lease_id:str,scopes:tuple[str,...],owner:str,policy_binding:str)->Lease:
        need(scopes,'INVALID_SCOPES');leases=[self.verify(lease_id,s,owner,policy_binding) for s in scopes]
        need(all(x is leases[0] for x in leases),'LEASE_MISMATCH');return leases[0]
    def end(self,lease_id:str,workspace:str,owner:str,policy_binding:str)->dict:
        lease=self.verify(lease_id,workspace,owner,policy_binding);self._expire(lease);return {'released':True,'scopes':list(lease.scopes)}
    def mutation_allowed(self,workspace:str,lease_id:str|None)->bool:
        lease=self._active(workspace);return lease is None or (lease_id is not None and lease.lease_id==lease_id)
