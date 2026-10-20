from __future__ import annotations
import json,sqlite3,threading,time
from pathlib import Path
from .core import canonical,need
from .health import HealthBook,HealthSample

class DurableHealthStore:
    """Protected supervisor telemetry. Ingest is operator-only; health summary may be MCP read-only."""
    def __init__(self,path:Path,max_samples:int=100000):
        need(type(max_samples)is int and 100<=max_samples<=1_000_000,'INVALID_LIMIT');self.max_samples=max_samples;self.lock=threading.RLock()
        self.db=sqlite3.connect(path,check_same_thread=False,timeout=5);self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS samples(time_ns INTEGER PRIMARY KEY,payload TEXT NOT NULL)');need(self.db.execute('PRAGMA quick_check').fetchone()[0]=='ok','HEALTH_STORE_CORRUPT');self.db.commit()
    def ingest(self,s:HealthSample)->dict:
        need(isinstance(s,HealthSample),'INVALID_SAMPLE');payload=canonical(s.__dict__)
        with self.lock:
            old=self.db.execute('SELECT payload FROM samples WHERE time_ns=?',(s.time_ns,)).fetchone()
            if old:
                need(old[0]==payload,'HEALTH_IDEMPOTENCY_CONFLICT');return {'time_ns':s.time_ns,'replayed':True}
            count=self.db.execute('SELECT count(*) FROM samples').fetchone()[0];need(count<self.max_samples,'HEALTH_CAPACITY')
            self.db.execute('INSERT INTO samples VALUES(?,?)',(s.time_ns,payload));self.db.commit();return {'time_ns':s.time_ns,'replayed':False}
    def summary(self,*,since_ns:int|None=None)->dict:
        since_ns=0 if since_ns is None else since_ns;need(type(since_ns)is int and since_ns>=0,'INVALID_TIME')
        with self.lock:rows=self.db.execute('SELECT payload FROM samples WHERE time_ns>=? ORDER BY time_ns',(since_ns,)).fetchall()
        book=HealthBook(max_samples=max(24,len(rows) or 24))
        for r in rows:book.add(HealthSample(**json.loads(r[0])))
        return book.summary()
    def close(self):self.db.close()
