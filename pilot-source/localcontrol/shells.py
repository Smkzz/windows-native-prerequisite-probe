"""Governed shell-executable discovery and identity for capability reporting.

Discovery never trusts PATH: only fixed well-known absolute locations are
probed, and the operator may pin the executable (and its SHA-256) in policy.
Identity (path, version, SHA-256, architecture) is provenance for audit and
client launch hints, NOT a security boundary. The AppContainer, workspace
ACLs and the owned Job Object remain the boundary for anything executed.
"""
from __future__ import annotations
import hashlib
import json
import os
import struct
from pathlib import Path
from .errors import ControlError, require
from .policy import no_links

EXECUTION_CLASS = {'disabled': 'disabled', 'recipes': 'recipes',
                   'trusted_local': 'trusted_host', 'appcontainer': 'project_sandbox'}
# Fixed preference order. Inbox Windows PowerShell is canonical: OS-serviced,
# always present, and version-locked to the host. A real PowerShell 7 install
# (never the WindowsApps alias stub) is reported as an alternate; the operator
# may pin either through policy.
CANDIDATES = (
    ('powershell', lambda: [Path(os.environ.get('SystemRoot', r'C:\Windows'))
                            / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe']),
    ('pwsh', lambda: [Path(os.environ.get('ProgramFiles', r'C:\Program Files'))
                      / 'PowerShell' / '7' / 'pwsh.exe']),
)
LAUNCH_FLAGS = ('-NoLogo', '-NoProfile', '-NonInteractive', '-Command')
_ARCH = {0x014c: 'x86', 0x8664: 'amd64', 0xaa64: 'arm64', 0x0200: 'ia64'}
_MAX_IDENTITY_BYTES = 512 * 1024 * 1024


def _pe_arch(path: Path) -> str:
    with path.open('rb') as stream:
        data = stream.read(4096)
    require(len(data) >= 0x40 and data[:2] == b'MZ', 'INVALID_EXECUTABLE', 'Not a PE executable')
    offset = struct.unpack_from('<I', data, 0x3C)[0]
    require(offset + 6 <= len(data) and data[offset:offset + 4] == b'PE\0\0',
            'INVALID_EXECUTABLE', 'Not a PE executable')
    return _ARCH.get(struct.unpack_from('<H', data, offset + 4)[0], 'unknown')


def _file_version(path: Path) -> str | None:
    if os.name != 'nt':
        return None
    import ctypes as c
    from ctypes import wintypes as w
    ver = c.WinDLL('version', use_last_error=True)
    size = ver.GetFileVersionInfoSizeW(str(path), None)
    if not size:
        return None
    buf = c.create_string_buffer(size)
    if not ver.GetFileVersionInfoW(str(path), 0, size, buf):
        return None
    value = c.c_void_p()
    length = w.UINT()
    if not ver.VerQueryValueW(buf, '\\', c.byref(value), c.byref(length)) or not value:
        return None
    # VS_FIXEDFILEINFO: signature 0xFEEF04BD; dwFileVersionMS/LS at offsets 8, 12.
    raw = c.string_at(value.value, min(int(length.value), 52))
    if len(raw) < 16 or struct.unpack_from('<I', raw, 0)[0] != 0xFEEF04BD:
        return None
    ms, ls = struct.unpack_from('<II', raw, 8)
    return f'{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}'


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def identify(path: Path, kind: str, *, pinned: bool = False) -> dict:
    info = {'kind': kind, 'path': str(path), 'arch': _pe_arch(path),
            'version': _file_version(path), 'pinned': pinned}
    if path.stat().st_size <= _MAX_IDENTITY_BYTES:
        info['sha256'] = sha256_file(path)
    else:
        info['sha256'] = None
        info['sha256_skipped'] = 'size'
    return info


def _check_host_path(path: Path, policy) -> Path:
    path = path.resolve()
    require(path.is_absolute() and path.is_file(), 'INVALID_CONFIG',
            'Pinned executable must be an existing absolute file path')
    no_links(path, allow_hardlinks=True)
    require(not any(path.is_relative_to(p.root) for p in policy.projects.values()),
            'INVALID_CONFIG', 'Governed executables cannot be edited through project tools')
    return path


def resolve(policy) -> dict | None:
    """Resolve the governed shell executable. Returns identity or None.

    Operator pin wins. Otherwise the first existing fixed candidate is
    canonical; remaining real installs are listed as alternates. A bad pin is
    a hard configuration failure, never a silent fallback.
    """
    spec = policy.powershell or {}
    require(set(spec) <= {'executable', 'sha256'}, 'INVALID_CONFIG', 'Unknown powershell setting')
    pin = spec.get('executable')
    require(pin is not None or spec.get('sha256') is None, 'INVALID_CONFIG',
            'powershell.sha256 requires a pinned executable')
    if pin is not None:
        require(isinstance(pin, str), 'INVALID_CONFIG', 'powershell.executable must be a path string')
        path = _check_host_path(Path(pin), policy)
        info = identify(path, _kind_of(path), pinned=True)
        expected = spec.get('sha256')
        if expected is not None:
            require(isinstance(expected, str) and len(expected) == 64
                    and all(c in '0123456789abcdefABCDEF' for c in expected),
                    'INVALID_CONFIG', 'powershell.sha256 must be a SHA-256 hex digest')
            require(info['sha256'] is not None and info['sha256'].lower() == expected.lower(),
                    'SANDBOX_CONFIG', 'Pinned shell executable does not match the recorded SHA-256')
        return info
    for kind, locations in CANDIDATES:
        for path in locations():
            try:
                if path.is_file():
                    path = _check_host_path(path, policy)
                    info = identify(path, kind)
                    info['alternates'] = _alternates(policy, exclude=path)
                    return info
            except (OSError, ControlError):
                continue
    return None


def _alternates(policy, exclude: Path) -> list:
    out = []
    for kind, locations in CANDIDATES:
        for path in locations():
            if path == exclude or not path.is_file():
                continue
            try:
                path = _check_host_path(path, policy)
                out.append(identify(path, kind))
            except (OSError, ControlError):
                continue
    return out


def _kind_of(path: Path) -> str:
    name = path.name.casefold()
    if name == 'powershell.exe':
        return 'powershell'
    if name == 'pwsh.exe':
        return 'pwsh'
    return 'custom'


def _python_project_surface(policy, project: str) -> dict:
    """Return the worker-bound Python runtime for one AppContainer project.

    The Windows py.exe launcher is deliberately not used: it may resolve to a
    host interpreter outside the worker ACL and fail only after the launcher
    starts. The enrolled worker manifest is operator-owned and points at the
    runtime copy already granted RX to this AppContainer SID.
    """
    sandboxed = policy.exec_mode == 'appcontainer'
    base = {
        'available': False,
        'autonomous': False,
        'sandboxed': sandboxed,
        'workspace_scoped': sandboxed,
        'network': False,
        'child_processes': sandboxed,
        'executable': None,
        'launch': None,
        'windows_launcher_supported': False,
        'launcher_note': ('Use this manifest-bound python.exe directly; do not use '
                          r'C:\Windows\py.exe inside the AppContainer.'),
    }
    if not sandboxed:
        return base
    worker = (policy.workers or {}).get(project)
    if not isinstance(worker, dict) or not isinstance(worker.get('manifest'), str):
        return base
    try:
        manifest_path = Path(worker['manifest']).resolve()
        raw = json.loads(manifest_path.read_text(encoding='utf-8'))
        runtime = Path(raw['runtime']).resolve()
        python = Path(raw['python']).resolve()
        workspace = Path(raw['workspace']).resolve()
        no_links(manifest_path)
        no_links(runtime)
        no_links(python, allow_hardlinks=True)
        require(workspace == policy.projects[project].root.resolve(), 'SANDBOX_CONFIG',
                'Worker manifest workspace does not match project root')
        require(python.is_file() and python.is_relative_to(runtime), 'SANDBOX_CONFIG',
                'Worker Python must be an existing file inside the worker runtime')
        info = identify(python, 'python')
        info['manifest_bound'] = True
        base.update({
            'available': True,
            'autonomous': True,
            'executable': info,
            'launch': [info['path']],
            'runtime': str(runtime),
        })
        return base
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, ControlError):
        return base


def surface(policy) -> dict:
    """Truthful execution capability block for system_info/capabilities/context."""
    info = resolve(policy)
    sandboxed = policy.exec_mode == 'appcontainer'
    python_by_project = {
        name: _python_project_surface(policy, name)
        for name in sorted(policy.projects)
    }
    return {
        'execution_class': EXECUTION_CLASS[policy.exec_mode],
        'powershell': {
            'available': info is not None,
            'autonomous': sandboxed and info is not None,
            'sandboxed': sandboxed,
            'elevation': False,
            'workspace_scoped': sandboxed,
            'network': False,
            'executable': info,
            'launch': ([info['path'], *LAUNCH_FLAGS] if info else None),
            'per_command_approval': ('none' if policy.exec_mode in {'appcontainer', 'trusted_local'}
                                     else 'not_applicable'),
            'approval_boundary': ('operator_acknowledgement_at_server_start'
                                  if policy.exec_mode == 'trusted_local' else 'none'),
        },
        'python_by_project': python_by_project,
    }
