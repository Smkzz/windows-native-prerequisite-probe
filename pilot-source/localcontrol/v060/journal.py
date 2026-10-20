from __future__ import annotations
import json, sqlite3, threading, time
from pathlib import Path
from .core import canonical, need
from .migration import MovePlan

NORMAL={"PLANNED":"PRECHECKED","PRECHECKED":"MOVED","MOVED":"VERIFIED","VERIFIED":"COMMITTED"}
TERMINAL=frozenset({"COMMITTED","ROLLED_BACK","ABORTED"})

class DurableMoveJournal:
    def __init__(self,path:Path):
        self.lock=threading.RLock();self.db=sqlite3.connect(path,check_same_thread=False,timeout=5);self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS moves(plan_id TEXT PRIMARY KEY, plan TEXT NOT NULL, state TEXT NOT NULL, evidence TEXT NOT NULL, updated_ns INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS move_events(seq INTEGER PRIMARY KEY AUTOINCREMENT, plan_id TEXT NOT NULL, state TEXT NOT NULL, evidence TEXT NOT NULL, time_ns INTEGER NOT NULL);
        ''')
        need(self.db.execute('PRAGMA quick_check').fetchone()[0]=='ok','JOURNAL_CORRUPT');self.db.commit()
    def _tx(self,fn):
        with self.lock:
            try:self.db.execute('BEGIN IMMEDIATE');out=fn();self.db.commit();return out
            except BaseException:self.db.rollback();raise
    def begin(self,plan:MovePlan)->dict:
        def op():
            row=self.db.execute('SELECT * FROM moves WHERE plan_id=?',(plan.plan_id,)).fetchone()
            if row:return {'plan_id':plan.plan_id,'state':row['state'],'replayed':True}
            now=time.time_ns();body=canonical(plan.body());e='{}'
            self.db.execute('INSERT INTO moves VALUES(?,?,?,?,?)',(plan.plan_id,body,'PLANNED',e,now))
            self.db.execute('INSERT INTO move_events(plan_id,state,evidence,time_ns) VALUES(?,?,?,?)',(plan.plan_id,'PLANNED',e,now))
            return {'plan_id':plan.plan_id,'state':'PLANNED','replayed':False}
        return self._tx(op)
    def get(self,plan_id:str)->dict:
        with self.lock:row=self.db.execute('SELECT * FROM moves WHERE plan_id=?',(plan_id,)).fetchone()
        need(row is not None,'UNKNOWN_PLAN');return {'plan_id':plan_id,'state':row['state'],'plan':json.loads(row['plan']),'evidence':json.loads(row['evidence']),'updated_ns':row['updated_ns']}
    def transition(self,plan_id:str,expected:str,next_state:str,evidence:dict|None=None)->dict:
        evidence={} if evidence is None else evidence;need(type(evidence)is dict,'INVALID_EVIDENCE')
        def op():
            row=self.db.execute('SELECT state FROM moves WHERE plan_id=?',(plan_id,)).fetchone();need(row is not None,'UNKNOWN_PLAN');need(row['state']==expected,'JOURNAL_CONFLICT')
            allowed=NORMAL.get(expected)==next_state or (expected in {'MOVED','VERIFIED'} and next_state=='ROLLBACK_REQUIRED') or (expected=='ROLLBACK_REQUIRED' and next_state=='ROLLED_BACK') or (expected in {'PLANNED','PRECHECKED'} and next_state=='ABORTED') or (expected=='PRECHECKED' and next_state=='INDETERMINATE')
            need(allowed,'INVALID_TRANSITION');now=time.time_ns();e=canonical(evidence)
            self.db.execute('UPDATE moves SET state=?,evidence=?,updated_ns=? WHERE plan_id=?',(next_state,e,now,plan_id))
            self.db.execute('INSERT INTO move_events(plan_id,state,evidence,time_ns) VALUES(?,?,?,?)',(plan_id,next_state,e,now))
            return {'plan_id':plan_id,'state':next_state,'evidence':evidence}
        return self._tx(op)
    def unresolved(self)->list[dict]:
        with self.lock:rows=self.db.execute("SELECT plan_id,state,updated_ns FROM moves WHERE state NOT IN ('COMMITTED','ROLLED_BACK','ABORTED') ORDER BY updated_ns").fetchall()
        return [dict(r) for r in rows]
    def events(self,plan_id:str)->list[dict]:
        with self.lock:rows=self.db.execute('SELECT seq,state,evidence,time_ns FROM move_events WHERE plan_id=? ORDER BY seq',(plan_id,)).fetchall()
        return [{'seq':r['seq'],'state':r['state'],'evidence':json.loads(r['evidence']),'time_ns':r['time_ns']} for r in rows]
    def close(self):self.db.close()
