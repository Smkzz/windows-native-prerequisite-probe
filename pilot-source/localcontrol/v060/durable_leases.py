from __future__ import annotations
import json, secrets, sqlite3, threading, time
from pathlib import Path
from .core import ident, need
from .leases import Lease

class DurableMaintenanceLeases:
    """Restart-safe LocalControl mutation leases.

    Leases serialize LocalControl mutations only; they do not claim to lock out
    unrelated host processes. Expired leases are never revived. A new lease may
    be used for recovery of a previously journaled move because the move plan's
    authority and filesystem identity remain independently bound and verified.
    """
    def __init__(self,path:Path,*,clock_ns=time.time_ns,max_ttl_s:int=900):
        self.clock_ns,self.max_ttl_s,self.lock=clock_ns,max_ttl_s,threading.RLock()
        self.db=sqlite3.connect(path,check_same_thread=False,timeout=5);self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS leases(
          lease_id TEXT PRIMARY KEY, owner TEXT NOT NULL, policy_binding TEXT NOT NULL,
          purpose TEXT NOT NULL, expires_ns INTEGER NOT NULL, state TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS lease_scopes(
          lease_id TEXT NOT NULL, scope TEXT NOT NULL, scope_cf TEXT NOT NULL,
          PRIMARY KEY(lease_id,scope_cf));
        CREATE INDEX IF NOT EXISTS idx_lease_scopes_cf ON lease_scopes(scope_cf);
        ''')
        need(self.db.execute('PRAGMA quick_check').fetchone()[0]=='ok','LEASE_STORE_CORRUPT');self.db.commit()
    def _expire(self):
        self.db.execute("UPDATE leases SET state='expired' WHERE state='active' AND expires_ns<=?",(self.clock_ns(),))
    def _load(self,lease_id:str)->Lease:
        # Verification is intentionally read-only. Expiry cleanup happens only in
        # explicit transactional mutation/listing paths; otherwise a harmless
        # verify could leave sqlite inside an implicit transaction and make the
        # next BEGIN IMMEDIATE fail after an early guard rejection.
        row=self.db.execute("SELECT * FROM leases WHERE lease_id=? AND state='active' AND expires_ns>?",(lease_id,self.clock_ns())).fetchone()
        need(row is not None,'LEASE_REQUIRED')
        scopes=tuple(r[0] for r in self.db.execute('SELECT scope FROM lease_scopes WHERE lease_id=? ORDER BY scope_cf',(lease_id,)))
        return Lease(row['lease_id'],scopes,row['owner'],row['policy_binding'],row['expires_ns'],row['purpose'])
    def begin_many(self,scopes:tuple[str,...],owner:str,policy_binding:str,purpose:str,ttl_s:int=300)->Lease:
        need(isinstance(scopes,tuple) and 1<=len(scopes)<=8,'INVALID_SCOPES')
        normalized=tuple(sorted({ident(s) for s in scopes},key=str.casefold));need(len(normalized)==len(scopes),'DUPLICATE_SCOPE')
        ident(owner);ident(policy_binding);ident(purpose);need(type(ttl_s)is int and 1<=ttl_s<=self.max_ttl_s,'INVALID_TTL')
        with self.lock:
            try:
                self.db.execute('BEGIN IMMEDIATE');self._expire()
                q=','.join('?' for _ in normalized)
                conflict=self.db.execute(f'''SELECT 1 FROM lease_scopes s JOIN leases l ON l.lease_id=s.lease_id
                                             WHERE s.scope_cf IN ({q}) AND l.state='active' AND l.expires_ns>? LIMIT 1''',
                                         (*[x.casefold() for x in normalized],self.clock_ns())).fetchone()
                need(conflict is None,'WORKSPACE_BUSY')
                lid='lease-'+secrets.token_hex(16);exp=self.clock_ns()+ttl_s*1_000_000_000
                self.db.execute('INSERT INTO leases VALUES(?,?,?,?,?,?)',(lid,owner,policy_binding,purpose,exp,'active'))
                self.db.executemany('INSERT INTO lease_scopes VALUES(?,?,?)',[(lid,s,s.casefold()) for s in normalized]);self.db.commit()
                return Lease(lid,normalized,owner,policy_binding,exp,purpose)
            except BaseException:self.db.rollback();raise
    def begin(self,workspace:str,owner:str,policy_binding:str,purpose:str,ttl_s:int=300)->Lease:
        return self.begin_many((workspace,),owner,policy_binding,purpose,ttl_s)
    def verify(self,lease_id:str,workspace:str,owner:str,policy_binding:str)->Lease:
        ident(workspace);ident(owner);ident(policy_binding)
        with self.lock:
            lease=self._load(lease_id)
            need(lease.owner==owner and lease.policy_binding==policy_binding,'LEASE_MISMATCH')
            need(workspace.casefold() in {s.casefold() for s in lease.scopes},'LEASE_MISMATCH');return lease
    def verify_many(self,lease_id:str,scopes:tuple[str,...],owner:str,policy_binding:str)->Lease:
        need(isinstance(scopes,tuple) and scopes,'INVALID_SCOPES')
        with self.lock:
            lease=self._load(lease_id);need(lease.owner==owner and lease.policy_binding==policy_binding,'LEASE_MISMATCH')
            have={s.casefold() for s in lease.scopes};need(all(ident(s).casefold() in have for s in scopes),'LEASE_MISMATCH');return lease
    def end(self,lease_id:str,workspace:str,owner:str,policy_binding:str)->dict:
        with self.lock:
            lease=self.verify(lease_id,workspace,owner,policy_binding)
            self.db.execute("UPDATE leases SET state='released' WHERE lease_id=?",(lease_id,));self.db.commit()
            return {'released':True,'scopes':list(lease.scopes)}
    def mutation_allowed(self,workspace:str,lease_id:str|None)->bool:
        ident(workspace)
        with self.lock:
            self._expire();rows=self.db.execute('''SELECT l.lease_id FROM lease_scopes s JOIN leases l ON l.lease_id=s.lease_id
                                                  WHERE s.scope_cf=? AND l.state='active' AND l.expires_ns>?''',
                                               (workspace.casefold(),self.clock_ns())).fetchall()
            self.db.commit()
            return not rows or (lease_id is not None and any(r[0]==lease_id for r in rows))
    def active(self)->list[dict]:
        with self.lock:
            self._expire();rows=self.db.execute("SELECT * FROM leases WHERE state='active' AND expires_ns>? ORDER BY expires_ns",(self.clock_ns(),)).fetchall();self.db.commit()
            out=[]
            for r in rows:
                scopes=[x[0] for x in self.db.execute('SELECT scope FROM lease_scopes WHERE lease_id=? ORDER BY scope_cf',(r['lease_id'],))]
                out.append({'lease_id':r['lease_id'],'scopes':scopes,'owner':r['owner'],'purpose':r['purpose'],'expires_ns':r['expires_ns']})
            return out
    def close(self):self.db.close()
