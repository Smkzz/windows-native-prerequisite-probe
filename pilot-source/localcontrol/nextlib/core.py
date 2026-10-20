"""Small policy-bound building blocks. No processes, network or project I/O here."""
from __future__ import annotations
import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import ntpath
import re
import time
from typing import Any, Callable, FrozenSet, Mapping

VERSION = '0.5.0-lab.2'
BASE_TOOLS = frozenset(('localcontrol_context','system_info','file_read','file_write','file_patch','file_delete',
                       'file_list','file_search','exec','job_read','job_input','job_stop','archive_terminal_jobs','process_list'))
MUTATING = frozenset(('file_write','file_patch','file_delete','exec','job_input','job_stop'))
HEX = re.compile(r'^[0-9a-f]{64}$')
IDENT = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')
DENIED = frozenset(('.git','.codex','.ssh','.aws','.azure','.gnupg','.npmrc',
                    '.pypirc','.netrc','.git-credentials'))
SECRET = re.compile(r'^(\.env(?:\..*)?|credentials(?:\..*)?|id_(?:rsa|ed25519)(?:\..*)?)$',re.I)
RESERVED = re.compile(r'^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?$',re.I)

class Rejected(Exception):
    """Stable, non-secret public error code with optional bounded details."""
    def __init__(self, code: str, details: dict | None = None):
        self.code = code
        self.details = details
        super().__init__(code)

def need(condition: bool, code: str = 'INVALID_ARGUMENT') -> None:
    if not condition:
        raise Rejected(code)

def packed(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')

def digest(value: Any) -> str:
    return hashlib.sha256(packed(value)).hexdigest()

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def ident(value: str) -> str:
    need(isinstance(value, str) and bool(IDENT.fullmatch(value)))
    return value

def integer(value: int, lo: int, hi: int) -> int:
    need(type(value) is int and lo <= value <= hi)
    return value

def safe_relative(value: str) -> str:
    """Conservative input validation, NOT filesystem authorization or race protection."""
    need(isinstance(value, str) and 0 < len(value) <= 1024, 'INVALID_PATH')
    need(not ntpath.splitdrive(value)[0] and not value.startswith(('/', '\\')), 'INVALID_PATH')
    try:
        value.encode('utf-8')
    except UnicodeError:
        raise Rejected('INVALID_PATH') from None
    parts = value.replace('\\', '/').split('/')
    for part in parts:
        need(bool(part) and part not in ('.','..') and not part.endswith((' ','.')), 'INVALID_PATH')
        need(not any(ord(c) < 32 or c in ':*?"<>|\x7f' for c in part), 'INVALID_PATH')
        need(not RESERVED.fullmatch(part), 'INVALID_PATH')
        need(part.casefold() not in DENIED and not SECRET.fullmatch(part), 'PROTECTED_PATH')
    return '/'.join(parts)

@dataclass(frozen=True)
class Context:
    """SERVER-supplied authority. Never construct this from model arguments.

    policy_revision must change for root, grants, sandbox or identity-binding changes.
    exclusive_workspace is operator assurance, NOT a lock acquired by this library.
    """
    principal: str
    project: str
    policy_revision: str
    allowed_tools: FrozenSet[str]
    writable: bool = False
    security_sandbox: bool = False
    execution_mode: str = 'disabled'
    exclusive_workspace: bool = False

    def __post_init__(self):
        ident(self.principal); ident(self.project); ident(self.policy_revision)
        need(isinstance(self.allowed_tools, frozenset) and self.allowed_tools <= BASE_TOOLS)
        need(all(type(v) is bool for v in (self.writable,self.security_sandbox,self.exclusive_workspace)))
        need(self.execution_mode in ('disabled','appcontainer','recipes','trusted_local'))

    @property
    def scope(self) -> str:
        return digest([self.principal, self.project])

    @property
    def binding(self) -> str:
        # Bind actual grants as well as the operator's policy epoch.
        return digest([self.scope,self.policy_revision,sorted(self.allowed_tools),self.writable,
                       self.security_sandbox,self.execution_mode,self.exclusive_workspace])

    def authorize(self, tool: str) -> None:
        need(tool in self.allowed_tools, 'DENIED')
        if tool in MUTATING:
            need(self.writable, 'READ_ONLY')
            need(self.security_sandbox and self.execution_mode == 'appcontainer', 'SANDBOX_REQUIRED')

class Signer:
    """HMAC cursors are scoped, expiring integrity tokens, NOT encryption or authority."""
    def __init__(self, key: bytes, clock: Callable[[], float] = time.time):
        need(isinstance(key,bytes) and len(key) >= 32, 'INVALID_KEY')
        self.key, self.clock = key, clock

    def sign(self, context: Context, kind: str, data: Any, ttl: int = 300) -> str:
        ident(kind); integer(ttl,1,3600)
        body = packed({'v':1,'binding':context.binding,'kind':kind,
                       'exp':int(self.clock())+ttl,'data':data})
        need(len(body) <= 32768, 'CURSOR_LIMIT')
        return base64.urlsafe_b64encode(body).decode().rstrip('=') + '.' + hmac.new(self.key,body,'sha256').hexdigest()

    def verify(self, token: str, context: Context, kind: str) -> Any:
        try:
            need(isinstance(token,str) and 1 <= len(token) <= 44000, 'INVALID_CURSOR')
            enc, sig = token.split('.')
            need(bool(HEX.fullmatch(sig)), 'INVALID_CURSOR')
            body = base64.b64decode(enc + '=' * (-len(enc)%4),altchars=b'-_',validate=True)
            need(hmac.compare_digest(sig,hmac.new(self.key,body,'sha256').hexdigest()), 'INVALID_CURSOR')
            item = json.loads(body)
            need(set(item)=={'v','binding','kind','exp','data'} and item['v']==1, 'INVALID_CURSOR')
            need(item['kind']==kind and item['binding']==context.binding, 'STALE_CURSOR')
            need(type(item['exp']) is int and int(self.clock()) < item['exp'], 'CURSOR_EXPIRED')
            return item['data']
        except Rejected:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise Rejected('INVALID_CURSOR') from None

def capabilities(context: Context, registered: Mapping[str, Any], version: str,
                 client_observed: list[str] | None = None) -> dict:
    context.authorize('system_info')
    need(isinstance(version,str) and len(version)<=128)
    names = sorted(registered)
    for name in names: ident(name)
    enabled = sorted(name for name in names if name in context.allowed_tools and
                     (name not in MUTATING or (context.writable and context.security_sandbox
                                              and context.execution_mode=='appcontainer')))
    result = {'server_version':version,'extension_version':VERSION,'registered':names,
              'enabled':enabled,'schema_sha256':digest(registered),'policy_binding':context.binding,
              'security_sandbox_reported':context.security_sandbox,'execution_mode':context.execution_mode,
              'client_visibility':'unknown','client_observation_is_attestation':False}
    if client_observed is not None:
        need(isinstance(client_observed,list) and len(client_observed)<=128)
        for name in client_observed: ident(name)
        need(len(set(client_observed))==len(client_observed))
        result.update(client_visibility='matches' if set(enabled)==set(client_observed) else 'mismatch',
                      client_reported=sorted(client_observed),
                      missing_from_client=sorted(set(enabled)-set(client_observed)),
                      unexpected_at_client=sorted(set(client_observed)-set(enabled)))
    return result
