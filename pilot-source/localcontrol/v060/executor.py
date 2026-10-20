from __future__ import annotations
from typing import Protocol
from .core import Rejected, need
from .leases import MaintenanceLeases
from .migration import MovePlan, TreeSnapshot
from .journal import DurableMoveJournal

class MoveAdapter(Protocol):
    def snapshot(self,path:str)->TreeSnapshot:...
    def exists(self,path:str)->bool:...
    def parent_volume(self,path:str)->str:...
    def validate_paths(self,source:str,destination:str,source_authority_root:str,destination_collection_root:str,*,source_may_be_missing:bool=False)->None:...
    def rename(self,source:str,destination:str)->None:...

class MoveExecutor:
    """Replay-safe same-volume rename coordinator. Adapter must never implement copy/delete fallback."""
    def __init__(self,adapter:MoveAdapter,journal:DurableMoveJournal,leases:MaintenanceLeases):self.a,self.j,self.leases=adapter,journal,leases
    def _precheck(self,p:MovePlan,registry_revision:int,registry_sha256:str,owner:str,binding:str,lease_id:str|None=None):
        current_lease=p.lease_id if lease_id is None else lease_id
        need(registry_revision==p.registry_revision and registry_sha256==p.registry_sha256,'REGISTRY_CHANGED');self.leases.verify_many(current_lease,(p.source_scope,p.collection),owner,binding)
        self.a.validate_paths(p.source,p.destination,p.source_authority_root,p.destination_collection_root)
        need(not self.a.exists(p.destination),'DESTINATION_EXISTS')
        s=self.a.snapshot(p.source);need(s.root_identity==p.source_identity and s.fingerprint==p.source_fingerprint,'SOURCE_CHANGED')
        need(self.a.parent_volume(p.destination)==p.source_volume,'CROSS_VOLUME_UNSUPPORTED')
    def apply(self,p:MovePlan,*,registry_revision:int,registry_sha256:str|None=None,owner:str,binding:str,lease_id:str|None=None)->dict:
        registry_sha256=p.registry_sha256 if registry_sha256 is None else registry_sha256
        row=self.j.begin(p);state=row['state']
        if state=='COMMITTED':return {'plan_id':p.plan_id,'state':'COMMITTED','replayed':True}
        if state in {'ROLLBACK_REQUIRED','ROLLED_BACK','ABORTED','INDETERMINATE'}:raise Rejected('PLAN_NOT_APPLICABLE')
        # PRECHECKED is the durable rename-intent boundary. If we are seeing it
        # from a previous call/process, whether rename occurred is ambiguous and
        # must be reconciled from filesystem identity instead of blindly retried.
        if row.get('replayed') and state=='PRECHECKED':raise Rejected('RECONCILE_REQUIRED')
        if state=='PLANNED':
            try:self._precheck(p,registry_revision,registry_sha256,owner,binding,lease_id)
            except Exception:
                self.j.transition(p.plan_id,'PLANNED','ABORTED',{'reason':'PRECHECK_FAILED'});raise
            self.j.transition(p.plan_id,'PLANNED','PRECHECKED',{'source_identity':p.source_identity});state='PRECHECKED'
        if state=='PRECHECKED':
            # Re-check immediately before the only filesystem mutation.
            self._precheck(p,registry_revision,registry_sha256,owner,binding,lease_id)
            self.a.rename(p.source,p.destination)
            self.j.transition(p.plan_id,'PRECHECKED','MOVED',{'rename_completed':True});state='MOVED'
        if state=='MOVED':
            try:
                need(not self.a.exists(p.source) and self.a.exists(p.destination),'MOVE_VERIFY_FAILED')
                dest=self.a.snapshot(p.destination);need(dest.root_identity==p.source_identity,'MOVE_IDENTITY_CHANGED');need(dest.fingerprint==p.source_fingerprint,'MOVE_CONTENT_CHANGED')
                self.j.transition(p.plan_id,'MOVED','VERIFIED',{'destination_identity':dest.root_identity});state='VERIFIED'
            except Exception:
                self.j.transition(p.plan_id,'MOVED','ROLLBACK_REQUIRED',{'reason':'POST_MOVE_VERIFY_FAILED'})
                return self.rollback(p,owner=owner,binding=binding,lease_id=lease_id)
        if state=='VERIFIED':
            self.j.transition(p.plan_id,'VERIFIED','COMMITTED',{'verified':True});state='COMMITTED'
        return {'plan_id':p.plan_id,'state':state,'replayed':row.get('replayed',False)}
    def reconcile(self,p:MovePlan,*,owner:str,binding:str,lease_id:str|None=None)->dict:
        current_lease=p.lease_id if lease_id is None else lease_id
        state=self.j.get(p.plan_id)['state'];self.leases.verify_many(current_lease,(p.source_scope,p.collection),owner,binding)
        self.a.validate_paths(p.source,p.destination,p.source_authority_root,p.destination_collection_root,source_may_be_missing=True)
        if state=='PRECHECKED':
            src=self.a.exists(p.source);dst=self.a.exists(p.destination)
            # Crash before rename: prove original source still matches, then retire the
            # old plan. A fresh plan is required before any new mutation.
            if src and not dst:
                s=self.a.snapshot(p.source)
                if s.root_identity==p.source_identity and s.fingerprint==p.source_fingerprint:
                    self.j.transition(p.plan_id,'PRECHECKED','ABORTED',{'reason':'RECONCILED_NO_RENAME'});return {'state':'ABORTED','reconciled':True,'rename_observed':False}
            # Crash after rename but before MOVED was journaled: destination identity
            # proves whether the side effect happened. Never repeat the rename.
            if (not src) and dst:
                d=self.a.snapshot(p.destination)
                if d.root_identity==p.source_identity and d.fingerprint==p.source_fingerprint:
                    self.j.transition(p.plan_id,'PRECHECKED','MOVED',{'reconciled_rename':True,'destination_identity':d.root_identity});state='MOVED'
                else:
                    self.j.transition(p.plan_id,'PRECHECKED','INDETERMINATE',{'reason':'DESTINATION_IDENTITY_MISMATCH'});return {'state':'INDETERMINATE','reconciled':False}
            elif state=='PRECHECKED':
                self.j.transition(p.plan_id,'PRECHECKED','INDETERMINATE',{'reason':'PRECHECKED_FILESYSTEM_AMBIGUOUS'});return {'state':'INDETERMINATE','reconciled':False}
        if state=='MOVED':
            if (not self.a.exists(p.source)) and self.a.exists(p.destination):
                d=self.a.snapshot(p.destination)
                if d.root_identity==p.source_identity and d.fingerprint==p.source_fingerprint:
                    self.j.transition(p.plan_id,'MOVED','VERIFIED',{'reconciled':True,'destination_identity':d.root_identity});self.j.transition(p.plan_id,'VERIFIED','COMMITTED',{'reconciled':True});return {'state':'COMMITTED','reconciled':True}
            self.j.transition(p.plan_id,'MOVED','ROLLBACK_REQUIRED',{'reason':'RECONCILE_AMBIGUOUS'});return self.rollback(p,owner=owner,binding=binding,lease_id=current_lease)
        return {'state':state,'reconciled':False}
    def rollback(self,p:MovePlan,*,owner:str,binding:str,lease_id:str|None=None)->dict:
        current_lease=p.lease_id if lease_id is None else lease_id
        self.leases.verify_many(current_lease,(p.source_scope,p.collection),owner,binding);state=self.j.get(p.plan_id)['state'];need(state=='ROLLBACK_REQUIRED','ROLLBACK_NOT_REQUIRED')
        self.a.validate_paths(p.source,p.destination,p.source_authority_root,p.destination_collection_root,source_may_be_missing=True)
        # Rollback is allowed only when destination identity is provably the original source and the old path is absent.
        need(not self.a.exists(p.source) and self.a.exists(p.destination),'ROLLBACK_UNSAFE')
        d=self.a.snapshot(p.destination);need(d.root_identity==p.source_identity and d.fingerprint==p.source_fingerprint,'ROLLBACK_UNSAFE')
        self.a.rename(p.destination,p.source)
        need(self.a.exists(p.source) and not self.a.exists(p.destination) and self.a.snapshot(p.source).root_identity==p.source_identity,'ROLLBACK_VERIFY_FAILED')
        self.j.transition(p.plan_id,'ROLLBACK_REQUIRED','ROLLED_BACK',{'rollback_verified':True})
        return {'plan_id':p.plan_id,'state':'ROLLED_BACK','rollback_verified':True}
