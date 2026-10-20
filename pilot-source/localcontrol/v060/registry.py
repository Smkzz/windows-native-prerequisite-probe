from __future__ import annotations
from dataclasses import dataclass, asdict
import hmac, hashlib, json, os, threading
from contextlib import contextmanager
from pathlib import Path
from .core import Rejected, canonical, digest, ident, need, same_or_child, strict_child, win_abs

@dataclass(frozen=True)
class Workspace:
    name: str
    root: str
    writable: bool = True
    exec_enabled: bool = True
    maintenance: bool = False
    def __post_init__(self):
        ident(self.name); object.__setattr__(self, "root", win_abs(self.root))
        need(type(self.writable) is bool and type(self.exec_enabled) is bool and type(self.maintenance) is bool)
        if self.maintenance:
            need(not self.exec_enabled, "MAINTENANCE_EXEC_FORBIDDEN")

@dataclass(frozen=True)
class Collection:
    name: str
    root: str
    writable: bool = False
    def __post_init__(self):
        ident(self.name); object.__setattr__(self, "root", win_abs(self.root))
        need(type(self.writable) is bool)

@dataclass(frozen=True)
class RegistrySnapshot:
    revision: int
    workspaces: tuple[Workspace, ...]
    collections: tuple[Collection, ...] = ()
    def __post_init__(self):
        need(type(self.revision) is int and self.revision >= 1, "INVALID_REVISION")
        names = [x.name.casefold() for x in (*self.workspaces, *self.collections)]
        need(len(names) == len(set(names)), "DUPLICATE_NAME")
        roots = [w.root for w in self.workspaces]
        for i, a in enumerate(roots):
            for b in roots[i+1:]:
                need(not same_or_child(a,b) and not same_or_child(b,a), "OVERLAPPING_WORKSPACES")
        # Collections MAY contain workspaces; they are never ordinary exec/file scopes.
        # Collection roots themselves may not overlap, and a workspace may belong to at most one.
        cols=[c.root for c in self.collections]
        for i,a in enumerate(cols):
            for b in cols[i+1:]:
                need(not same_or_child(a,b) and not same_or_child(b,a), "OVERLAPPING_COLLECTIONS")
        for w in self.workspaces:
            owners=[]
            for col in self.collections:
                if same_or_child(w.root, col.root):
                    need(strict_child(w.root, col.root), "COLLECTION_EQUALS_WORKSPACE")
                    owners.append(col.name)
            need(len(owners)<=1, "AMBIGUOUS_COLLECTION")
    def body(self) -> dict:
        return {"schema": 1, "revision": self.revision,
                "workspaces": [asdict(x) for x in self.workspaces],
                "collections": [asdict(x) for x in self.collections]}
    @property
    def sha256(self) -> str: return digest(self.body())

class RegistryCodec:
    """Integrity codec for an operator-owned manifest. HMAC is defense-in-depth; ACL ownership remains authoritative."""
    def __init__(self, key: bytes):
        need(isinstance(key, bytes) and len(key) >= 32, "INVALID_KEY")
        self.key = key
    def encode(self, snapshot: RegistrySnapshot) -> bytes:
        body = canonical(snapshot.body()).encode("ascii")
        sig = hmac.new(self.key, body, hashlib.sha256).hexdigest()
        return canonical({"body": json.loads(body), "hmac_sha256": sig}).encode("ascii")
    def decode(self, raw: bytes) -> RegistrySnapshot:
        need(isinstance(raw, bytes) and len(raw) <= 1024*1024, "REGISTRY_SIZE")
        try: outer = json.loads(raw)
        except Exception: raise Rejected("REGISTRY_CORRUPT") from None
        need(set(outer) == {"body","hmac_sha256"}, "REGISTRY_CORRUPT")
        body = canonical(outer["body"]).encode("ascii")
        need(hmac.compare_digest(outer["hmac_sha256"], hmac.new(self.key, body, hashlib.sha256).hexdigest()), "REGISTRY_SIGNATURE")
        d = outer["body"]
        need(set(d) == {"schema","revision","workspaces","collections"} and d["schema"] == 1, "REGISTRY_SCHEMA")
        return RegistrySnapshot(d["revision"], tuple(Workspace(**x) for x in d["workspaces"]), tuple(Collection(**x) for x in d["collections"]))

class RegistryStore:
    """Crash-safe monotonic registry file with serialized local publication.

    The data plane only reads this artifact. The admin process owns publication.
    A platform file lock prevents two local admin processes from publishing from
    the same expected revision; atomic replace prevents torn readers.
    """
    def __init__(self, path: Path, codec: RegistryCodec):
        self.path, self.codec, self._thread_lock = path, codec, threading.RLock()
        self.lock_path = path.with_name(path.name + '.lock')
    @contextmanager
    def _publish_lock(self):
        self.lock_path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(self.lock_path,os.O_RDWR|os.O_CREAT,0o600)
        try:
            if os.fstat(fd).st_size==0: os.write(fd,b'0');os.fsync(fd)
            if os.name=='nt':
                import msvcrt;os.lseek(fd,0,os.SEEK_SET);msvcrt.locking(fd,msvcrt.LK_LOCK,1)
                try: yield
                finally: os.lseek(fd,0,os.SEEK_SET);msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
            else:
                import fcntl;fcntl.flock(fd,fcntl.LOCK_EX)
                try: yield
                finally: fcntl.flock(fd,fcntl.LOCK_UN)
        finally: os.close(fd)
    def load(self) -> RegistrySnapshot:
        return self.codec.decode(self.path.read_bytes())
    def replace(self, expected_revision: int, next_snapshot: RegistrySnapshot) -> dict:
        with self._thread_lock, self._publish_lock():
            current = self.load()
            need(current.revision == expected_revision, "REVISION_CONFLICT")
            need(next_snapshot.revision == current.revision + 1, "REVISION_GAP")
            raw = self.codec.encode(next_snapshot)
            tmp = self.path.with_name(self.path.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
            flags = os.O_WRONLY|os.O_CREAT|os.O_EXCL
            fd = os.open(tmp, flags, 0o600)
            try:
                written=os.write(fd, raw);need(written==len(raw),'REGISTRY_WRITE_FAILED');os.fsync(fd)
            finally: os.close(fd)
            os.replace(tmp, self.path)
            return {"revision": next_snapshot.revision, "sha256": next_snapshot.sha256}
