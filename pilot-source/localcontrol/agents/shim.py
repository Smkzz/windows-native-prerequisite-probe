"""In-child delegation bridge: the ONLY path a delegated agent can use to
create or control further agents.

Runs as an MCP stdio server inside the codex app-server's process tree (MCP
servers run in the host context — the codex command sandbox applies to the
agent's shell commands, not to this process). Authority = the delegation
token bound to this agent's store row PLUS verified process ancestry: the
shim must be a descendant of the provider process recorded at spawn.

Writes are never made to agent rows directly: mutations are queued as
delegation_intents which the manager drains, re-validates and executes.
Reads are scoped to this agent's own subtree.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

MAX_FRAME = 1024 * 1024
MAX_READ = 64
READ_OPS = frozenset({'lc_agent_status', 'lc_agent_wait', 'lc_agent_result',
                      'lc_agent_events', 'lc_agent_list'})
INTENT_OPS = {'lc_agent_spawn': 'spawn', 'lc_agent_send': 'send', 'lc_agent_cancel': 'cancel'}
AWAITABLE = frozenset({'idle', 'completed', 'failed', 'cancelled', 'interrupted', 'orphaned'})

TOOL_DEFS = [
    {'name': 'lc_agent_spawn',
     'description': 'Create a delegated child agent under LocalControl. Returns '
                    'agent_id immediately; the child runs independently.',
     'inputSchema': {'type': 'object', 'properties': {
         'task': {'type': 'string'}, 'request_key': {'type': 'string'},
         'profile': {'type': 'string'}, 'model': {'type': 'string'},
         'effort': {'type': 'string'}, 'output_schema': {'type': 'object'},
         'workspace_path': {'type': 'string'}},
         'required': ['task', 'request_key']}},
    {'name': 'lc_agent_send',
     'description': 'Send input to an agent in this agent\'s delegation subtree.',
     'inputSchema': {'type': 'object', 'properties': {
         'agent_id': {'type': 'string'}, 'input': {'type': 'string'},
         'request_key': {'type': 'string'}},
         'required': ['agent_id', 'input', 'request_key']}},
    {'name': 'lc_agent_cancel',
     'description': 'Cancel an agent in this agent\'s delegation subtree.',
     'inputSchema': {'type': 'object', 'properties': {
         'agent_id': {'type': 'string'}, 'request_key': {'type': 'string'}},
         'required': ['agent_id', 'request_key']}},
    {'name': 'lc_agent_status',
     'description': 'Read state for self or a descendant agent.',
     'inputSchema': {'type': 'object', 'properties': {'agent_id': {'type': 'string'}},
                     'required': ['agent_id']}},
    {'name': 'lc_agent_wait',
     'description': 'Wait until a descendant agent reaches a result-bearing state.',
     'inputSchema': {'type': 'object', 'properties': {
         'agent_id': {'type': 'string'}, 'wait_s': {'type': 'integer'}},
         'required': ['agent_id']}},
    {'name': 'lc_agent_result',
     'description': 'Read the result payload of a descendant agent.',
     'inputSchema': {'type': 'object', 'properties': {'agent_id': {'type': 'string'}},
                     'required': ['agent_id']}},
    {'name': 'lc_agent_events',
     'description': 'Read lifecycle events for a descendant agent.',
     'inputSchema': {'type': 'object', 'properties': {
         'agent_id': {'type': 'string'}, 'after_seq': {'type': 'integer'},
         'limit': {'type': 'integer'}},
         'required': ['agent_id']}},
    {'name': 'lc_agent_list',
     'description': 'List agents in this agent\'s delegation subtree.',
     'inputSchema': {'type': 'object', 'properties': {}, 'required': []}},
]


def _stderr(text: str) -> None:
    try:
        sys.stderr.write(text[:400] + '\n')
        sys.stderr.flush()
    except Exception:
        pass


def _parent_chain() -> list[int]:
    """pid ancestry via Toolhelp snapshot; [] on non-Windows."""
    if os.name != 'nt':
        return []
    import ctypes
    k = ctypes.windll.kernel32
    snap = k.CreateToolhelp32Snapshot(0x2, 0)
    if snap == -1 or snap is None:
        return []
    try:
        class PE(ctypes.Structure):
            _fields_ = [('dwSize', ctypes.c_ulong), ('cntUsage', ctypes.c_ulong),
                        ('th32ProcessID', ctypes.c_ulong),
                        ('th32DefaultHeapID', ctypes.c_void_p),
                        ('th32ModuleID', ctypes.c_ulong), ('cntThreads', ctypes.c_ulong),
                        ('th32ParentProcessID', ctypes.c_ulong),
                        ('pcPriClassBase', ctypes.c_long), ('dwFlags', ctypes.c_ulong),
                        ('szExeFile', ctypes.c_wchar * 260)]
        pe = PE()
        pe.dwSize = ctypes.sizeof(PE)
        parents = {}
        if k.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                parents[pe.th32ProcessID] = pe.th32ParentProcessID
                if not k.Process32NextW(snap, ctypes.byref(pe)):
                    break
        chain = []
        pid = os.getppid()
        for _ in range(8):
            if not pid or pid in chain:
                break
            chain.append(pid)
            pid = parents.get(pid, 0)
        return chain
    finally:
        k.CloseHandle(snap)


def _exe_of(pid: int) -> str | None:
    if os.name != 'nt':
        return None
    import ctypes
    k = ctypes.windll.kernel32
    handle = k.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = ctypes.c_ulong(1024)
        if not k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return None
        return str(Path(buf.value).resolve())
    finally:
        k.CloseHandle(handle)


def _shim_authorizer(action, arg1, arg2, dbname, source):
    """Defense in depth: even with a stolen token a shim process can only
    read rows and enqueue intents — never update agent records directly."""
    SELECT, INSERT, TRANSACTION, PRAGMA, READ, FUNCTION = 21, 18, 22, 19, 20, 31
    if action in (SELECT, TRANSACTION, READ, FUNCTION):
        return sqlite3.SQLITE_OK
    if action == PRAGMA:
        return sqlite3.SQLITE_OK if arg1 in ('busy_timeout', 'journal_mode',
                                           'synchronous', 'foreign_keys',
                                           'table_info') else sqlite3.SQLITE_DENY
    if action == INSERT:
        return sqlite3.SQLITE_OK if arg1 == 'delegation_intents' else sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY


class Shim:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.agent_id = os.environ.get('LOCALCONTROL_AGENT_ID', '')
        self.token = os.environ.get('LOCALCONTROL_DELEGATE_TOKEN', '')
        db_path = state_dir / 'v110' / 'agents.sqlite'
        self.db = sqlite3.connect(str(db_path), timeout=30)
        self.db.execute('PRAGMA busy_timeout=30000')
        self.db.set_authorizer(_shim_authorizer)

    # ---------- authority ----------

    def _self(self) -> dict | None:
        # Deliberately re-read every call: the manager binds delegation_pid
        # right before thread/start and revokes the token on cancel — the shim
        # must observe both without a stale cache.
        row = self.db.execute(
            'SELECT agent_id,state,delegation_token_sha256,delegation_pid,delegation_exe '
            'FROM agents WHERE agent_id=?', (self.agent_id,)).fetchone()
        if row is None:
            return None
        return {'agent_id': row[0], 'state': row[1],
                'token_sha256': row[2], 'pid': row[3], 'exe': row[4]}

    def _authorized(self) -> tuple[bool, str]:
        me = self._self()
        if me is None:
            return False, 'agent record missing'
        import hashlib
        if not self.token or hashlib.sha256(self.token.encode()).hexdigest() != me['token_sha256']:
            return False, 'delegation token mismatch'
        if me['state'] in ('cancelled', 'orphaned'):
            return False, 'delegation revoked'
        expected = me['pid']
        if expected is None:
            return False, 'no provider pid bound'
        chain = _parent_chain()
        if expected not in chain:
            return False, 'provider ancestry not proven'
        exe = me['exe']
        if exe:
            actual = _exe_of(expected)
            if actual is None or str(Path(exe).resolve()) != actual:
                return False, 'provider exe mismatch'
        return True, ''

    def _subtree_ok(self, agent_id: str) -> dict | None:
        row = self.db.execute('SELECT lineage_json FROM agents WHERE agent_id=?',
                              (agent_id,)).fetchone()
        if row is None:
            return None
        if agent_id == self.agent_id:
            return {}
        try:
            lineage = json.loads(row[0] or '[]')
        except ValueError:
            return None
        return {} if self.agent_id in lineage else None

    # ---------- reads ----------

    def _row_dict(self, agent_id: str) -> dict | None:
        row = self.db.execute(
            'SELECT agent_id,project,state,revision,profile,model,depth,parent_agent_id,'
            'turns_completed,tool_denials,created_ns,updated_ns,terminal_ns,'
            'provider_json,result_json,token_usage_json,files_changed_json,status_detail_json '
            'FROM agents WHERE agent_id=?', (agent_id,)).fetchone()
        if row is None:
            return None
        provider = json.loads(row[13] or '{}')
        return {'agent_id': row[0], 'project': row[1], 'state': row[2], 'revision': row[3],
                'profile': row[4], 'model': row[5], 'depth': row[6], 'parent_agent_id': row[7],
                'turns_completed': row[8], 'tool_denials': row[9], 'created_ns': row[10],
                'updated_ns': row[11], 'terminal_ns': row[12],
                'thread_id': provider.get('thread_id'),
                'has_result': row[14] is not None,
                'result': json.loads(row[14]) if row[14] else None,
                'token_usage': json.loads(row[15]) if row[15] else None,
                'files_changed': json.loads(row[16]) if row[16] else [],
                'status_detail': json.loads(row[17] or '{}')}

    def _read(self, name: str, args: dict) -> dict:
        if name == 'lc_agent_list':
            rows = self.db.execute(
                'SELECT agent_id,state,depth,created_ns,task,profile FROM agents '
                'WHERE agent_id=? OR parent_agent_id=? OR lineage_json LIKE ? ORDER BY created_ns LIMIT ?',
                (self.agent_id, self.agent_id, f'%"{self.agent_id}"%', MAX_READ)).fetchall()
            agents = [{'agent_id': r[0], 'state': r[1], 'depth': r[2],
                       'created_ns': r[3], 'task': (r[4] or '')[:160], 'profile': r[5]}
                      for r in rows if r[0] == self.agent_id or self._subtree_ok(r[0]) is not None]
            return {'agents': agents}
        agent_id = args.get('agent_id')
        if not isinstance(agent_id, str) or not agent_id:
            return {'error': 'agent_id required'}
        if self._subtree_ok(agent_id) is None:
            return {'error': 'agent is outside this delegation subtree'}
        if name == 'lc_agent_wait':
            wait_s = args.get('wait_s', 120)
            if not isinstance(wait_s, int) or not 0 <= wait_s <= 600:
                return {'error': 'wait_s must be an integer 0..600'}
            deadline = time.monotonic() + wait_s
            while True:
                data = self._row_dict(agent_id)
                if data is None:
                    return {'error': 'agent not found'}
                if data['state'] in AWAITABLE or time.monotonic() >= deadline:
                    data.pop('result', None)
                    return data
                time.sleep(0.5)
        if name == 'lc_agent_events':
            if self._subtree_ok(agent_id) is None:
                return {'error': 'agent is outside this delegation subtree'}
            after = args.get('after_seq', 0)
            limit = args.get('limit', 64)
            if not isinstance(after, int) or after < 0 or not isinstance(limit, int) \
                    or not 1 <= limit <= 256:
                return {'error': 'invalid cursor/limit'}
            rows = self.db.execute(
                'SELECT seq,kind,payload_json,time_ns FROM agent_events '
                'WHERE agent_id=? AND seq>? ORDER BY seq LIMIT ?',
                (agent_id, after, limit)).fetchall()
            return {'events': [{'seq': r[0], 'kind': r[1],
                                'payload': json.loads(r[2]), 'time_ns': r[3]} for r in rows]}
        data = self._row_dict(agent_id)
        if data is None:
            return {'error': 'agent not found'}
        if name == 'lc_agent_status':
            data.pop('result', None)
            return data
        return data  # lc_agent_result

    # ---------- intents ----------

    def _intent(self, name: str, args: dict) -> dict:
        request_key = args.get('request_key')
        if not isinstance(request_key, str) or not 8 <= len(request_key) <= 128:
            return {'error': 'request_key required (8..128 chars)'}
        op = INTENT_OPS[name]
        if op == 'spawn':
            payload = {k: args.get(k) for k in
                       ('task', 'profile', 'model', 'effort', 'output_schema',
                        'workspace_path') if args.get(k) is not None}
            if not isinstance(payload.get('task'), str) or not payload['task']:
                return {'error': 'task required'}
            wait_s = 300
        elif op == 'send':
            payload = {'agent_id': args.get('agent_id'), 'input': args.get('input')}
            if not isinstance(payload['agent_id'], str) or \
                    not isinstance(payload['input'], str) or not payload['input']:
                return {'error': 'agent_id and input required'}
            wait_s = 120
        else:
            payload = {'agent_id': args.get('agent_id')}
            if not isinstance(payload['agent_id'], str):
                return {'error': 'agent_id required'}
            wait_s = 60
        import hashlib
        existing = self.db.execute(
            'SELECT intent_id FROM delegation_intents '
            'WHERE parent_agent_id=? AND request_key=?',
            (self.agent_id, request_key)).fetchone()
        if existing is not None:
            intent_id = existing[0]
        else:
            try:
                cur = self.db.execute(
                    'INSERT INTO delegation_intents(parent_agent_id,request_key,op,payload_json,'
                    'status,created_ns,token_sha256) VALUES(?,?,?,?,?,?,?)',
                    (self.agent_id, request_key, op,
                     json.dumps(payload, separators=(',', ':'), ensure_ascii=True),
                     'queued', time.time_ns(),
                     hashlib.sha256(self.token.encode()).hexdigest()))
                self.db.commit()
                intent_id = int(cur.lastrowid)
            except sqlite3.IntegrityError:
                intent_id = self.db.execute(
                    'SELECT intent_id FROM delegation_intents WHERE parent_agent_id=? AND request_key=?',
                    (self.agent_id, request_key)).fetchone()[0]
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            row = self.db.execute(
                'SELECT status,result_json FROM delegation_intents WHERE intent_id=?',
                (intent_id,)).fetchone()
            if row is None:
                return {'error': 'intent lost'}
            if row[0] == 'done':
                return json.loads(row[1] or '{}')
            if row[0] == 'rejected':
                try:
                    detail = json.loads(row[1] or '{}')
                except ValueError:
                    detail = {}
                return {'error': detail.get('code') or 'rejected'}
            time.sleep(0.2)
        return {'error': 'intent timeout', 'intent_id': intent_id, 'status': 'pending'}

    # ---------- JSON-RPC ----------

    def serve(self) -> int:
        stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
        while True:
            line = stdin.readline(MAX_FRAME + 1)
            if not line:
                return 0
            if len(line) > MAX_FRAME:
                return 1
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            reply = self._handle(msg)
            if reply is not None:
                data = (json.dumps(reply, separators=(',', ':'), ensure_ascii=True)
                        + '\n').encode('utf-8')
                if len(data) <= MAX_FRAME:
                    try:
                        stdout.write(data)
                        stdout.flush()
                    except (OSError, ValueError):
                        return 1

    def _handle(self, msg: dict) -> dict | None:
        method = msg.get('method')
        rid = msg.get('id')
        if method == 'initialize':
            return {'jsonrpc': '2.0', 'id': rid,
                    'result': {'protocolVersion': msg.get('params', {}).get('protocolVersion',
                                                                          '2025-03-26'),
                               'capabilities': {'tools': {'listChanged': False}},
                               'serverInfo': {'name': 'localcontrol-delegation',
                                              'version': '1.1.0'}}}
        if method in ('notifications/initialized', 'initialized', 'notifications/cancelled'):
            return None
        if method == 'ping':
            return {'jsonrpc': '2.0', 'id': rid, 'result': {}}
        if method == 'tools/list':
            return {'jsonrpc': '2.0', 'id': rid, 'result': {'tools': TOOL_DEFS}}
        if method == 'tools/call':
            params = msg.get('params') or {}
            name = params.get('name')
            args = params.get('arguments') or {}
            # Authority is re-verified per call: the manager revokes the token
            # and binds/rebinds the provider pid, and the shim must observe
            # both immediately — never a startup-time snapshot.
            authorized, reason = self._authorized()
            if not authorized:
                return self._result(rid, {'error': 'delegation not authorized',
                                          'detail': reason}, True)
            if not isinstance(args, dict):
                return self._result(rid, {'error': 'invalid arguments'}, True)
            try:
                if name in READ_OPS:
                    return self._result(rid, self._read(name, args), False)
                if name in INTENT_OPS:
                    return self._result(rid, self._intent(name, args), False)
                return self._result(rid, {'error': f'unknown tool {name}'}, True)
            except sqlite3.OperationalError:
                return self._result(rid, {'error': 'store busy'}, True)
            except Exception:
                return self._result(rid, {'error': 'internal error'}, True)
        if rid is not None:
            return {'jsonrpc': '2.0', 'id': rid,
                    'error': {'code': -32601, 'message': 'method not found'}}
        return None

    @staticmethod
    def _result(rid, data: dict, is_error: bool) -> dict:
        return {'jsonrpc': '2.0', 'id': rid,
                'result': {'content': [{'type': 'text',
                                        'text': json.dumps(data, ensure_ascii=True)}],
                           'isError': is_error or 'error' in data}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', required=True, type=Path)
    args = parser.parse_args()
    try:
        code = Shim(args.state_dir.resolve()).serve()
    except Exception as error:
        _stderr(f'lc-shim: fatal {type(error).__name__}')
        code = 1
    raise SystemExit(code)


if __name__ == '__main__':
    main()
