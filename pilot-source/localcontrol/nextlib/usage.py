"""Bounded usage accounting supplied by a trusted adapter; no API, prices or inference.

Normalized schema contract: input_total INCLUDES cached_input; output_total INCLUDES
reasoning_output. These subset counters must not be added again. Only finalized,
per-request events are accepted; adapter authors must normalize vendor-specific
semantics before importing. A source hash is provenance, not an attestation that
counts were extracted correctly. No raw prompts, logs or credentials are stored.
This is an in-memory component, not durable telemetry or a registered MCP tool.
"""
from __future__ import annotations
from collections import defaultdict
from copy import deepcopy
import threading
from .core import Context, HEX, digest, ident, integer, need, packed

COUNTERS = ('input_total','cached_input','output_total','reasoning_output')
STAGES = frozenset(('planning','implementation','validation','review','orchestration','other'))
FIELDS = frozenset(('schema','event_id','task','model','stage','basis','finalized','tokens','evidence_sha256'))


def normalize(record: dict) -> dict:
    need(type(record) is dict and set(record) == FIELDS, 'USAGE_SCHEMA')
    need(type(record['schema']) is int and record['schema'] == 1, 'USAGE_SCHEMA')
    ident(record['event_id']);ident(record['task']);ident(record['model'])
    need(isinstance(record['stage'],str) and record['stage'] in STAGES, 'USAGE_STAGE')
    need(record['basis'] == 'per_request' and record['finalized'] is True, 'USAGE_NOT_FINAL_PER_REQUEST')
    counts = record['tokens']
    need(type(counts) is dict and set(counts) == set(COUNTERS), 'USAGE_COUNTERS')
    for value in counts.values():
        if value is not None:integer(value,0,10**12)
    for total,part in (('input_total','cached_input'),('output_total','reasoning_output')):
        need(counts[total] is None or counts[part] is None or counts[part] <= counts[total], 'USAGE_SUBSET_EXCEEDS_TOTAL')
    need(isinstance(record['evidence_sha256'],str) and bool(HEX.fullmatch(record['evidence_sha256'])), 'USAGE_EVIDENCE_HASH')
    need(len(packed(record))<=4096,'USAGE_RECORD_LIMIT')
    return deepcopy(record)


def counted(values):
    known = [v for v in values if v is not None]
    return {'total':sum(known) if len(known)==len(values) else None,
            'observed_sum':sum(known),'missing_events':len(values)-len(known),
            'complete':len(known)==len(values)}


def aggregate(rows: list[dict]) -> dict:
    data = {key:counted([r['tokens'][key] for r in rows]) for key in COUNTERS}
    uncached=[];totals=[]
    for row in rows:
        t=row['tokens'];i,c,o=t['input_total'],t['cached_input'],t['output_total']
        uncached.append(i-c if i is not None and c is not None else None)
        totals.append(i+o if i is not None and o is not None else None)
    data['uncached_input']=counted(uncached)
    data['input_plus_output']=counted(totals)
    return {'events':len(rows),'tokens':data}


class UsageBook:
    def __init__(self, *, principal: str, project: str, allowed_tasks: frozenset[str],
                 adapter: str, max_events: int=10000, max_models: int=32):
        self.principal=ident(principal);self.project=ident(project);self.adapter=ident(adapter)
        need(isinstance(allowed_tasks,frozenset) and 1<=len(allowed_tasks)<=200,'USAGE_TASK_GRANTS')
        for task in allowed_tasks:ident(task)
        self.allowed_tasks=allowed_tasks
        self.max_events=integer(max_events,1,100000)
        self.max_models=integer(max_models,1,128)
        self._events={};self._models=set();self._binding=None;self._lock=threading.RLock()

    def _authorize(self, context: Context, tool: str):
        need(context.principal==self.principal and context.project==self.project,'USAGE_SCOPE')
        context.authorize(tool)
        need(self._binding is None or context.binding==self._binding,'POLICY_CHANGED')

    def ingest(self, context: Context, record: dict) -> dict:
        # Caller supplies authenticated context, not a field in the imported record.
        with self._lock:
            self._authorize(context,'file_write')
            normalized=normalize(record)
            need(normalized['task'] in self.allowed_tasks,'OUTSIDE_TASK')
            event=normalized['event_id'];fingerprint=digest(normalized)
            old=self._events.get(event)
            if old is not None:
                need(digest(old)==fingerprint,'IDEMPOTENCY_CONFLICT')
                return {'event_id':event,'replayed':True}
            need(len(self._events)<self.max_events,'USAGE_CAPACITY')
            need(normalized['model'] in self._models or len(self._models)<self.max_models,'USAGE_MODEL_CAPACITY')
            self._binding=context.binding
            self._events[event]=normalized;self._models.add(normalized['model'])
            return {'event_id':event,'replayed':False}

    def summary(self, context: Context, *, task: str|None=None, max_response_bytes: int=65536) -> dict:
        with self._lock:
            self._authorize(context,'file_read');integer(max_response_bytes,2048,131072)
            if task is not None:
                ident(task);need(task in self.allowed_tasks,'OUTSIDE_TASK')
            rows=[r for r in self._events.values() if task is None or r['task']==task]
            groups=defaultdict(list)
            for row in rows:groups[(row['model'],row['stage'])].append(row)
            answer={'project':self.project,'task_filter':task,'usage_adapter':self.adapter,
                'scope':'imported finalized per-request events only; completeness of external logs not established',
                'adapter_assertions_independently_verified':False,'inferred_from_tool_bytes':False,
                'estimated_cost':None,'durable_storage':False,'totals':aggregate(rows),
                'distribution':[{'model':model,'stage':stage,**aggregate(group)}
                                for (model,stage),group in sorted(groups.items())]}
            need(len(packed(answer))<=max_response_bytes,'RESPONSE_LIMIT')
            return answer
