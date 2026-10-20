"""Codex app-server adapter: one owned process tree per delegated agent.

Speaks the `codex app-server --listen stdio://` JSONL JSON-RPC protocol
(schema generated from the pinned executable; see CODEX_PROTOCOL). The
session is a plain subprocess owned by a Windows Job Object with
KILL_ON_JOB_CLOSE — no same-user fallback, no PID reuse, no orphan tree.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import subprocess
import threading
import time
from pathlib import Path

from ..errors import ControlError, require
from ..nextlib.core import need

MAX_FRAME_BYTES = 1024 * 1024
MAX_STDERR_BYTES = 65536
VERSION_RE = re.compile(rb'codex-cli\s+(\d+)\.(\d+)\.(\d+)')
SUPPORTED_CODEX = (0, 153, 4)
PROTOCOL_NOTE = 'codex app-server 0.153.4 generated-schema protocol (ClientRequest/ServerRequest/ServerNotification unions)'

# Every server->client request method in the 0.153.4 schema and our policy
# response. Anything not listed is answered with a JSON-RPC error.
DENY_APPROVAL = {'decision': 'decline'}            # current API: agent continues
DENY_APPROVAL_CANCEL = {'decision': 'cancel'}      # current API: deny + interrupt
DENY_LEGACY = {'decision': {'denied': {'rejection': 'denied by LocalControl delegation policy'}}}
DENY_ELICITATION = {'action': 'decline'}
DENY_TOOL_CALL = {'success': False, 'contentItems': [{'type': 'inputText',
                                                    'text': 'denied by LocalControl delegation policy'}]}


class ProtocolViolation(Exception):
    """Malformed/oversized/unexpected traffic from the provider."""


class Session:
    """One codex app-server process. All public methods are thread-safe."""

    def __init__(self, agent_id: str, exe: str, home: Path, cwd: Path, env: dict,
                 on_event, on_exit, on_request):
        self.agent_id = agent_id
        self.exe, self.home, self.cwd, self.env = exe, home, cwd, env
        self.on_event, self.on_exit, self.on_request = on_event, on_exit, on_request
        self.p = None
        self.job = None
        self._wlock = threading.Lock()
        self._pending = {}
        self._pending_lock = threading.Lock()
        self._next_id = 1
        self._closed = threading.Event()
        self._dispatch_q = queue.Queue(maxsize=4096)
        self._stderr_tail = bytearray()
        self.protocol_violations = 0
        self.started_ns = time.time_ns()

    # ---------- lifecycle ----------

    def start(self) -> None:
        creation = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        job = None
        if os.name == 'nt':
            from ..windows_job import WindowsJob
            job = WindowsJob({})
        try:
            self.p = subprocess.Popen(
                [self.exe, 'app-server', '--listen', 'stdio://'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self.env, cwd=str(self.cwd), bufsize=0,
                creationflags=creation,
                start_new_session=(os.name != 'nt'))
            if job is not None:
                job.assign(self.p)
        except BaseException:
            if job is not None:
                job.close()
            raise ControlError('PROVIDER_SPAWN_FAILED', 'Could not start the codex app-server process')
        self.job = job
        threading.Thread(target=self._read_loop, daemon=True, name=f'lc-agent-rx-{self.agent_id}').start()
        threading.Thread(target=self._err_loop, daemon=True, name=f'lc-agent-err-{self.agent_id}').start()
        threading.Thread(target=self._dispatch_loop, daemon=True, name=f'lc-agent-dx-{self.agent_id}').start()

    @property
    def pid(self) -> int | None:
        return self.p.pid if self.p else None

    def alive(self) -> bool:
        return self.p is not None and self.p.poll() is None and not self._closed.is_set()

    def kill(self) -> None:
        """Deterministic teardown of the whole owned process tree."""
        self._closed.set()
        if self.job is not None:
            try:
                self.job.stop()          # kills the tree
            except Exception:
                pass
            try:
                self.job.close()         # KILL_ON_JOB_CLOSE backstop
            except Exception:
                pass
        elif self.p is not None and self.p.poll() is None:
            # No Job Object off Windows: the process was started in a new
            # session, so kill the whole group (provider children included).
            try:
                import signal
                os.killpg(os.getpgid(self.p.pid), signal.SIGKILL)
            except (OSError, AttributeError, PermissionError):
                try:
                    self.p.kill()
                except OSError:
                    pass
        if self.p is not None:
            try:
                self.p.wait(timeout=5)
            except Exception:
                pass
        for stream_name in ('stdin', 'stdout', 'stderr'):
            try:
                getattr(self.p, stream_name).close()
            except Exception:
                pass
        self._fail_pending(ControlError('PROVIDER_LOST', 'Provider session closed'))
        try:
            self._dispatch_q.put_nowait(None)
        except queue.Full:
            pass

    # ---------- wire ----------

    def _read_loop(self) -> None:
        buf = bytearray()
        try:
            while not self._closed.is_set():
                chunk = os.read(self.p.stdout.fileno(), 65536)
                if not chunk:
                    break
                buf.extend(chunk)
                while True:
                    nl = buf.find(b'\n')
                    if nl < 0:
                        break
                    line = bytes(buf[:nl]); del buf[:nl + 1]
                    self._handle_line(line)
                if len(buf) > MAX_FRAME_BYTES:
                    raise ProtocolViolation('frame exceeds limit')
        except ProtocolViolation:
            self.protocol_violations += 1
            self._safe_event({'method': 'localcontrol/protocolViolation',
                            'params': {'detail': 'oversized frame'}})
        except (OSError, ValueError):
            pass
        finally:
            self._closed.set()
            self._fail_pending(ControlError('PROVIDER_LOST', 'Provider stream closed'))
            try:
                self._dispatch_q.put_nowait(('__exit__', self.p.poll() if self.p else None))
            except queue.Full:
                pass

    def _err_loop(self) -> None:
        try:
            while True:
                chunk = self.p.stderr.read(4096)
                if not chunk:
                    return
                if len(self._stderr_tail) < MAX_STDERR_BYTES:
                    self._stderr_tail.extend(chunk[:MAX_STDERR_BYTES - len(self._stderr_tail)])
        except (OSError, ValueError):
            pass

    def stderr_tail(self) -> str:
        return bytes(self._stderr_tail).decode('utf-8', 'replace')[-2048:]

    def _handle_line(self, line: bytes) -> None:
        line = line.rstrip(b'\r')
        if not line:
            return
        try:
            msg = json.loads(line)
        except ValueError:
            self.protocol_violations += 1
            self._safe_event({'method': 'localcontrol/protocolViolation',
                            'params': {'detail': 'malformed json', 'bytes': len(line)}})
            return
        if not isinstance(msg, dict):
            self.protocol_violations += 1
            return
        try:
            self._dispatch_q.put_nowait(msg)
        except queue.Full:
            self.protocol_violations += 1
            self._safe_event({'method': 'localcontrol/protocolViolation',
                            'params': {'detail': 'dispatch queue saturated'}})

    def _dispatch_loop(self) -> None:
        while True:
            item = self._dispatch_q.get()
            if item is None:
                return
            if isinstance(item, tuple) and item[0] == '__exit__':
                try:
                    self.on_exit(item[1])
                except Exception:
                    pass
                return
            try:
                self._dispatch(item)
            except Exception:
                pass

    def _dispatch(self, msg: dict) -> None:
        if 'id' in msg and 'method' in msg:
            self._answer_server_request(msg)
        elif 'id' in msg:
            with self._pending_lock:
                slot = self._pending.pop(msg['id'], None)
            if slot is not None:
                slot['response'] = msg
                slot['event'].set()
        elif 'method' in msg:
            self._safe_event(msg)

    def _safe_event(self, msg: dict) -> None:
        try:
            self.on_event(msg)
        except Exception:
            pass

    def _answer_server_request(self, msg: dict) -> None:
        try:
            result = self.on_request(msg.get('method'), msg.get('params') or {})
            self._write({'id': msg['id'], 'result': result})
        except DeniedByPolicy as error:
            self._write({'id': msg['id'], 'error': {'code': -32601,
                                                  'message': str(error)[:200]}})
        except Exception:
            self._write({'id': msg['id'], 'error': {'code': -32000,
                                                  'message': 'client handler failure'}})

    def _write(self, msg: dict) -> None:
        data = (json.dumps(msg, separators=(',', ':'), ensure_ascii=True) + '\n').encode('utf-8')
        if len(data) > MAX_FRAME_BYTES:
            raise ControlError('FRAME_LIMIT', 'Outbound frame exceeds limit')
        with self._wlock:
            self.p.stdin.write(data)
            self.p.stdin.flush()

    def request(self, method: str, params: dict | None = None, timeout: float = 30.0) -> dict:
        if not self.alive():
            raise ControlError('PROVIDER_LOST', 'Provider session is not running')
        with self._pending_lock:
            rid = self._next_id
            self._next_id += 1
            slot = {'event': threading.Event(), 'response': None}
            self._pending[rid] = slot
        msg = {'method': method, 'id': rid}
        if params is not None:
            msg['params'] = params
        try:
            self._write(msg)
        except (OSError, ValueError, ControlError) as error:
            with self._pending_lock:
                self._pending.pop(rid, None)
            raise ControlError('PROVIDER_IO', 'Write to provider failed',
                               {'detail': type(error).__name__})
        if not slot['event'].wait(timeout):
            with self._pending_lock:
                self._pending.pop(rid, None)
            raise ControlError('PROVIDER_TIMEOUT', f'{method} did not respond in time')
        response = slot['response']
        if 'error' in response:
            err = response['error'] or {}
            raise ProviderError(err.get('code'), str(err.get('message', 'provider error'))[:512],
                                err.get('data'))
        return response.get('result') or {}

    def _fail_pending(self, error: Exception) -> None:
        with self._pending_lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for slot in pending:
            slot['response'] = {'error': {'code': -32001, 'message': str(error)}}
            slot['event'].set()

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {'method': method}
        if params is not None:
            msg['params'] = params
        try:
            self._write(msg)
        except (OSError, ValueError, ControlError):
            pass

    # ---------- protocol convenience ----------

    def handshake(self, client_name: str, timeout: float = 20.0) -> dict:
        result = self.request('initialize', {
            'clientInfo': {'name': client_name, 'version': '1.1.0'},
            'capabilities': {'experimentalApi': False}}, timeout=timeout)
        self.notify('initialized')
        return result


class ProviderError(ControlError):
    """A well-formed JSON-RPC error response from the provider."""


class DeniedByPolicy(Exception):
    """Raised by the server-request handler when policy cannot express a denial."""


def discover_executable(configured: str | None) -> dict:
    """Resolve a trusted codex.exe. Never uses a bare PATH lookup result
    unverified: candidates are absolute paths verified by --version output."""
    candidates = []
    if configured:
        candidates.append(Path(configured))
    else:
        candidates += [
            Path(os.environ.get('LOCALCONTROL_CODEX_EXE', 'nonexistent')),
            Path(r'C:\nvm4w\nodejs\node_modules\@openai\codex\node_modules'
                 r'\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe'),
            Path.home() / 'AppData/Local/Programs/OpenAI/Codex/bin/codex.exe',
        ]
        import shutil
        shim = shutil.which('codex')
        if shim:
            candidates.append(Path(shim))
    seen = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_file():
            continue
        seen.add(resolved)
        info = probe_version(resolved)
        if info is not None:
            return info
    raise ControlError('PROVIDER_UNAVAILABLE',
                       'No usable codex executable found (checked configured path, '
                       'LOCALCONTROL_CODEX_EXE, npm vendor dir, app install dir, PATH)')


def probe_version(exe: Path, timeout: float = 15.0) -> dict | None:
    try:
        out = subprocess.run([str(exe), '--version'], capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = VERSION_RE.search(out.stdout + out.stderr)
    if not match:
        return None
    version = tuple(int(x) for x in match.groups())
    sha = hashlib.sha256()
    try:
        with open(exe, 'rb') as handle:
            while chunk := handle.read(1 << 20):
                sha.update(chunk)
        digest = sha.hexdigest()
    except OSError:
        digest = None
    return {'path': str(exe), 'version': '.'.join(str(x) for x in version),
            'version_tuple': version, 'sha256': digest,
            'supported': version >= SUPPORTED_CODEX}
