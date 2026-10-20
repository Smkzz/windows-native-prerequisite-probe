"""Durable metadata-only task/operation ledger with conservative crash recovery.

One owning process per database. A pending operation becomes UNKNOWN on reopen;
this layer never silently retries it or assumes that SQLite and a filesystem
mutation were one atomic transaction. State paths are supplied by the operator.
"""
from __future__ import annotations
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from .core import Context, Rejected, digest, ident, integer, need, packed, safe_relative

class StateLease:
    def __init__(self, path: Path):
        self.fd = None
        # Caller must provision a trusted parent. Do not create directories implicitly.
        for target in (path.parent,path):
            try:
                info=target.lstat()
            except FileNotFoundError:
                continue
            need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,
                 'UNSAFE_STATE_PATH')
            if stat.S_ISREG(info.st_mode):
                need(info.st_nlink==1,'UNSAFE_STATE_PATH')
        flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)
        fd=os.open(path,flags,0o600)
        try:
            need(os.fstat(fd).st_nlink==1,'UNSAFE_STATE_PATH')
            if os.fstat(fd).st_size==0:
                os.write(fd,b'0')
            os.lseek(fd,0,0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.fd=fd
        except OSError:
            os.close(fd)
            raise Rejected('STATE_IN_USE') from None
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd=None

class Ledger:
    def __init__(self, path: str | Path, max_tasks: int=200, max_operations: int=10000):
        integer(max_tasks,1,10000); integer(max_operations,1,1000000)
        self.max_tasks,self.max_operations=max_tasks,max_operations
        self.lock=threading.RLock()
        self.lease=None
        self.db=None
        self.closed=False
        if str(path)!=':memory:':
            p=Path(path)
            need(p.parent.is_dir(),'STATE_PARENT_MISSING')
            for candidate in (p,p.with_name(p.name+'-journal')):
                if candidate.exists() or candidate.is_symlink():
                    s=candidate.lstat()
                    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and
                         not getattr(s,'st_file_attributes',0)&0x400,'UNSAFE_STATE_PATH')
            self.lease=StateLease(p.with_name(p.name+'.lock'))
        try:
            self.db=sqlite3.connect(str(path),isolation_level=None,timeout=5,check_same_thread=False)
            self.db.row_factory=sqlite3.Row
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tasks(
                  scope TEXT NOT NULL, task TEXT NOT NULL, binding TEXT NOT NULL,
                  paths TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0,
                  notes TEXT NOT NULL DEFAULT '{"inferences":[],"untested":[]}',
                  status TEXT NOT NULL DEFAULT 'active', PRIMARY KEY(scope,task));
                CREATE TABLE IF NOT EXISTS operations(
                  scope TEXT NOT NULL, op TEXT NOT NULL, task TEXT NOT NULL, kind TEXT NOT NULL,
                  fingerprint TEXT NOT NULL, state TEXT NOT NULL, result TEXT,
                  PRIMARY KEY(scope,op), FOREIGN KEY(scope,task) REFERENCES tasks(scope,task));
                CREATE TABLE IF NOT EXISTS claims(
                  scope TEXT NOT NULL,path TEXT NOT NULL,task TEXT NOT NULL,generation TEXT NOT NULL,
                  sha256 TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(scope,path),
                  FOREIGN KEY(scope,task) REFERENCES tasks(scope,task));
            ''')
            with self.tx():
                version=self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
                need(version is None or version['value']=='1','STATE_VERSION')
                self.db.execute("INSERT OR IGNORE INTO meta VALUES('schema','1')")
                self.db.execute("UPDATE operations SET state='unknown' WHERE state='pending'")
                self.db.execute("UPDATE claims SET state='unknown' WHERE state='pending'")
        except BaseException:
            if self.db is not None: self.db.close()
            if self.lease: self.lease.close()
            raise

    @contextmanager
    def tx(self):
        with self.lock:
            need(not self.closed,'STATE_CLOSED')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise

    def close(self):
        with self.lock:
            if not self.closed:
                self.db.close()
                if self.lease: self.lease.close()
                self.closed=True

    def _task(self,c:Context,task:str):
        ident(task)
        row=self.db.execute('SELECT * FROM tasks WHERE scope=? AND task=?',(c.scope,task)).fetchone()
        need(row is not None,'UNKNOWN_TASK')
        need(row['binding']==c.binding,'POLICY_CHANGED')
        return row

    def begin_task(self,c:Context,task:str,paths:list[str])->dict:
        c.authorize('file_write'); ident(task)
        need(isinstance(paths,list) and 1<=len(paths)<=64)
        paths=[safe_relative(p) for p in paths]
        need(len(set(p.casefold() for p in paths))==len(paths),'DUPLICATE_PATH')
        paths=sorted(paths)
        need(len(packed(paths))<=16384,'INPUT_LIMIT')
        with self.tx():
            old=self.db.execute('SELECT * FROM tasks WHERE scope=? AND task=?',(c.scope,task)).fetchone()
            if old is not None:
                need(old['binding']==c.binding and json.loads(old['paths'])==paths,'IDEMPOTENCY_CONFLICT')
                return {'task':task,'replayed':True}
            count=self.db.execute('SELECT count(*) FROM tasks').fetchone()[0]
            need(count<self.max_tasks,'TASK_CAPACITY')
            self.db.execute('INSERT INTO tasks(scope,task,binding,paths) VALUES(?,?,?,?)',
                            (c.scope,task,c.binding,packed(paths).decode()))
        return {'task':task,'replayed':False}

    def handoff(self,c:Context,task:str,*,limit:int=50,after_sequence:int=0,
                snapshot_max_sequence:int|None=None,max_response_bytes:int=65536)->dict:
        c.authorize('file_read')
        integer(limit,1,200); integer(after_sequence,0,2**63-1)
        integer(max_response_bytes,32768,131072)
        if snapshot_max_sequence is not None: integer(snapshot_max_sequence,0,2**63-1)
        with self.lock:
            row=self._task(c,task)
            maximum=self.db.execute('SELECT coalesce(max(rowid),0) FROM operations WHERE scope=? AND task=?',
                                    (c.scope,task)).fetchone()[0]
            maximum=maximum if snapshot_max_sequence is None else min(maximum,snapshot_max_sequence)
            records=self.db.execute('SELECT rowid AS sequence,op,kind,state,result FROM operations '
                                    'WHERE scope=? AND task=? AND rowid>? AND rowid<=? ORDER BY rowid LIMIT ?',
                                    (c.scope,task,after_sequence,maximum,limit+1)).fetchall()
            claims=[dict(r) for r in self.db.execute(
                'SELECT path,generation,sha256,state FROM claims WHERE scope=? AND task=? ORDER BY path',(c.scope,task))]
            unknown=bool(self.db.execute("SELECT 1 FROM operations WHERE scope=? AND task=? AND state='unknown' LIMIT 1",
                                        (c.scope,task)).fetchone())
            answer={'task':task,'revision':row['revision'],'status':row['status'],
                    'authorized_exact_paths':json.loads(row['paths']),
                    'agent_notes':json.loads(row['notes']),'recorded_operations':[],
                    'owned_files':claims,'observations_are_broker_receipts_not_goal_completion':True,
                    'unknown_requires_reconciliation':unknown,
                    'snapshot_max_sequence':maximum,'next_sequence':None,'operations_truncated':False,
                    'receipt_statuses_may_change_between_pages':True}
            need(len(packed(answer))<=max_response_bytes,'RESPONSE_LIMIT')
            for record in records[:limit]:
                op=dict(record);op['result']=json.loads(op['result']) if op['result'] else None
                candidate={**answer,'recorded_operations':answer['recorded_operations']+[op],
                           'next_sequence':op['sequence'],'operations_truncated':True}
                if len(packed(candidate))>max_response_bytes:
                    need(bool(answer['recorded_operations']),'RESPONSE_LIMIT')
                    break
                answer['recorded_operations'].append(op)
            count=len(answer['recorded_operations'])
            if count<len(records):
                answer['operations_truncated']=True
                answer['next_sequence']=answer['recorded_operations'][-1]['sequence']
            return answer

    def checkpoint(self,c:Context,task:str,expected_revision:int,notes:dict)->dict:
        c.authorize('file_write'); integer(expected_revision,0,100000000)
        lists={'inferences','untested','decisions','completed','blocked_checks','blockers','open_questions'}
        texts={'objective','phase','next_action'}
        need(isinstance(notes,dict) and bool(notes) and not (set(notes)-lists-texts-{'vcs'}),'INVALID_ARGUMENT')
        for key in lists & set(notes):
            value=notes[key]
            need(isinstance(value,list) and len(value)<=16)
            need(all(isinstance(s,str) and len(s)<=1024 for s in value))
        for key in texts & set(notes):
            need(isinstance(notes[key],str) and 0<len(notes[key])<=2048)
        if 'vcs' in notes:
            vcs=notes['vcs']
            need(isinstance(vcs,dict) and bool(vcs) and not (set(vcs)-{'kind','worktree','commit','branch'}))
            need(all(isinstance(v,str) and 0<len(v)<=512 for v in vcs.values()))
        need(len(packed(notes))<=12000,'INPUT_LIMIT')
        with self.tx():
            row=self._task(c,task)
            need(row['status']=='active','TASK_CLOSED')
            need(row['revision']==expected_revision,'CONFLICT')
            self.db.execute('UPDATE tasks SET revision=revision+1,notes=? WHERE scope=? AND task=?',
                            (packed(notes).decode(),c.scope,task))
        return {'task':task,'revision':expected_revision+1}

    def _reserve(self,c:Context,task:str,op:str,kind:str,meta:dict)->dict|None:
        """Called in one transaction with claim reservation, not exposed to model."""
        ident(op)
        row=self._task(c,task)
        need(row['status']=='active','TASK_CLOSED')
        fingerprint=digest({'task':task,'kind':kind,'meta':meta})
        old=self.db.execute('SELECT * FROM operations WHERE scope=? AND op=?',(c.scope,op)).fetchone()
        if old is not None:
            need(old['fingerprint']==fingerprint,'IDEMPOTENCY_CONFLICT')
            need(old['state']!='unknown','INDETERMINATE')
            need(old['state']!='pending','IN_PROGRESS')
            return {**json.loads(old['result']),'replayed':True}
        need(self.db.execute('SELECT count(*) FROM operations').fetchone()[0]<self.max_operations,
             'OPERATION_CAPACITY')
        self.db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,NULL)',
                        (c.scope,op,task,kind,fingerprint,'pending'))
        return None

    def reserve_create(self,c:Context,task:str,op:str,path:str,content_sha256:str)->dict|None:
        c.authorize('file_write'); path=safe_relative(path)
        with self.tx():
            row=self._task(c,task)
            need(path in json.loads(row['paths']),'OUTSIDE_TASK')
            prior=self._reserve(c,task,op,'create',{'path':path,'sha256':content_sha256})
            if prior is not None: return prior
            # Case-folding is intentionally conservative on POSIX too.
            current=self.db.execute('SELECT * FROM claims WHERE scope=? AND path=?',
                                    (c.scope,path.casefold())).fetchone()
            need(current is None or current['state']=='removed','PATH_ALREADY_OWNED')
            self.db.execute('INSERT OR REPLACE INTO claims VALUES(?,?,?,?,?,?)',
                            (c.scope,path.casefold(),task,op,content_sha256,'pending'))
        return None

    def _finish(self,c:Context,op:str,result:dict):
        need(len(packed(result))<=16384,'RECEIPT_LIMIT')
        cur=self.db.execute("UPDATE operations SET state='complete',result=? WHERE scope=? AND op=? AND state='pending'",
                            (packed(result).decode(),c.scope,op))
        need(cur.rowcount==1,'OPERATION_STATE')

    def finish_create(self,c:Context,op:str,path:str,result:dict,created:bool):
        with self.tx():
            self._finish(c,op,result)
            if created:
                self.db.execute("UPDATE claims SET state='live' WHERE scope=? AND path=? AND generation=?",
                                (c.scope,path.casefold(),op))
            else:
                self.db.execute("DELETE FROM claims WHERE scope=? AND path=? AND generation=? AND state='pending'",
                                (c.scope,path.casefold(),op))

    def unknown(self,c:Context,op:str):
        with self.tx():
            self.db.execute("UPDATE operations SET state='unknown' WHERE scope=? AND op=? AND state='pending'",(c.scope,op))
            self.db.execute("UPDATE claims SET state='unknown' WHERE scope=? AND generation=? AND state='pending'",(c.scope,op))

    def claim(self,c:Context,task:str,path:str)->dict:
        with self.lock:
            self._task(c,task)
            row=self.db.execute('SELECT * FROM claims WHERE scope=? AND path=?',(c.scope,path.casefold())).fetchone()
            need(row is not None and row['task']==task,'NOT_OWNED')
            return dict(row)

    def reserve_delete(self,c:Context,task:str,op:str,path:str,generation:str,observed:str,*,verified_exclusive_workspace:bool=False)->dict|None:
        c.authorize('file_delete')
        need(type(verified_exclusive_workspace) is bool,'INVALID_ARGUMENT')
        need(c.exclusive_workspace or verified_exclusive_workspace,'EXCLUSIVE_WORKSPACE_REQUIRED')
        with self.tx():
            prior=self._reserve(c,task,op,'delete',{'path':path,'generation':generation,'sha256':observed})
            if prior is not None: return prior
            claim=self.claim(c,task,path)
            need(claim['generation']==generation and claim['sha256']==observed and claim['state']=='live','STALE_PLAN')
        return None

    def finish_delete(self,c:Context,op:str,path:str,generation:str,result:dict,deleted:bool):
        with self.tx():
            self._finish(c,op,result)
            if deleted:
                cur=self.db.execute("UPDATE claims SET state='removed' WHERE scope=? AND path=? AND generation=? AND state='live'",
                                    (c.scope,path.casefold(),generation))
                need(cur.rowcount==1,'OWNERSHIP_CHANGED')
