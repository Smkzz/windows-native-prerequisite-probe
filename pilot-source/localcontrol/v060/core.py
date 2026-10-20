from __future__ import annotations
import hashlib, json, ntpath, re
from pathlib import PureWindowsPath

IDENT = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?$", re.I)

class Rejected(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)

def need(cond: bool, code: str = "INVALID_ARGUMENT") -> None:
    if not cond:
        raise Rejected(code)

def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)

def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()

def ident(value: str) -> str:
    need(isinstance(value, str) and bool(IDENT.fullmatch(value)), "INVALID_IDENTIFIER")
    return value

def win_abs(value: str) -> str:
    need(isinstance(value, str) and 3 <= len(value) <= 4096, "INVALID_PATH")
    need("\x00" not in value and ntpath.isabs(value), "INVALID_PATH")
    # v0.6 managed roots are local drive-letter paths only. UNC, device and extended paths
    # would widen the trust boundary into remote/device namespaces and are intentionally excluded.
    need(bool(re.match(r"^[A-Za-z]:[\\/]", value)), "LOCAL_DRIVE_REQUIRED")
    p = PureWindowsPath(value)
    parts = p.parts
    need(len(parts) >= 2, "INVALID_PATH")
    for part in parts[1:]:
        need(part not in (".", "..") and not part.endswith((" ", ".")), "INVALID_PATH")
        need(not RESERVED.fullmatch(part), "INVALID_PATH")
        need(not any(ord(c) < 32 or c in '*?"<>|\x7f' for c in part), "INVALID_PATH")
    return str(p)

def same_or_child(child: str, parent: str) -> bool:
    c, p = ntpath.normcase(win_abs(child)), ntpath.normcase(win_abs(parent))
    try:
        return ntpath.commonpath([c, p]) == p
    except ValueError:
        return False

def strict_child(child: str, parent: str) -> bool:
    return same_or_child(child, parent) and ntpath.normcase(win_abs(child)) != ntpath.normcase(win_abs(parent))
