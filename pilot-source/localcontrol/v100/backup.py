"""Disaster recovery: verified backups, staged restore and crash-safe apply.

Authoritative state is the SQLite/keys/journal set under the service state
directory. Backups snapshot SQLite through the native online backup API, hash
every file, and verify integrity. Restores are staged and verified, then applied
idempotently at the next LocalControl start before any store is opened.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path

from ..nextlib.core import Rejected, digest, ident, need, packed

SCHEMA = 1
MAX_BACKUPS = 32
SQLITE_SUFFIX = '.sqlite'
AUTHORITATIVE_ROOTS = ('v060', 'v080', 'v100', 'v110')
AUTHORITATIVE_FILES = ('receipts.sqlite', 'next_tasks.sqlite')
COPY_FILES = ('registry-key.bin', 'move-key.bin', 'run-key.bin', 'mission-key.bin',
              'workspace-registry.json', 'discovery-candidates.json')
NON_AUTHORITATIVE = ('recovery', 'backups', 'restore-pending.json', 'restore-receipt.json')


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def authoritative_files(state_dir: Path) -> list[str]:
    files = []
    for name in AUTHORITATIVE_FILES:
        if (state_dir / name).is_file():
            files.append(name)
    for root in AUTHORITATIVE_ROOTS:
        base = state_dir / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob('*')):
            if not path.is_file():
                continue
            if path.suffix in ('.sqlite', '.bin', '.json') and not path.name.endswith(('-wal', '-shm')):
                rel = path.relative_to(state_dir).as_posix()
                if root == 'v100' and (rel.startswith('v100/backups/') or rel.startswith('v100/recovery/')):
                    continue
                # v110: agents.sqlite and agent-key.bin are authoritative, but
                # delegated CODEX_HOMEs (auth.json links!) and managed git
                # worktrees must NEVER enter a backup.
                if root == 'v110' and (rel.startswith('v110/agents/')
                                       or rel.startswith('v110/worktrees/')
                                       or rel.startswith('v110/model-probe-home')):
                    continue
                if path.name in ('restore-pending.json', 'restore-receipt.json'):
                    continue
                files.append(rel)
    return sorted(set(files))


def _snapshot_sqlite(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(f'file:{source.as_posix()}?mode=ro', uri=True)
    try:
        dst = sqlite3.connect(target)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def create(state_dir: Path, backup_root: Path, *, label: str = 'manual', metadata: dict | None = None,
           now_ns=time.time_ns) -> dict:
    need(isinstance(label, str) and 0 < len(label) <= 128, 'INVALID_LABEL')
    backup_id = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now_ns() / 1e9)) + '-' + uuid.uuid4().hex[:8]
    target_dir = backup_root / ('backup-' + backup_id)
    need(not target_dir.exists(), 'BACKUP_EXISTS')
    target_dir.mkdir(parents=True)
    files = []
    for rel in authoritative_files(state_dir):
        source = state_dir / rel
        target = target_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.suffix == SQLITE_SUFFIX:
            _snapshot_sqlite(source, target)
            kind = 'sqlite'
        else:
            target.write_bytes(source.read_bytes())
            kind = 'file'
        files.append({'path': rel, 'sha256': sha256_file(target), 'bytes': target.stat().st_size, 'kind': kind})
    manifest = {'schema': SCHEMA, 'backup_id': backup_id, 'label': label, 'created_ns': now_ns(),
                'source_state_dir': str(state_dir), 'files': files,
                'metadata': metadata if isinstance(metadata, dict) else {},
                'policy_binding': (metadata or {}).get('policy_binding')}
    (target_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    receipt = verify(target_dir)
    return {**receipt, 'backup_dir': str(target_dir)}


def verify(backup_dir: Path) -> dict:
    manifest_path = backup_dir / 'manifest.json'
    need(manifest_path.is_file(), 'BACKUP_MANIFEST_MISSING')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    need(isinstance(manifest, dict) and manifest.get('schema') == SCHEMA, 'BACKUP_MANIFEST_INVALID')
    checks = []
    ok = True
    for entry in manifest.get('files', []):
        rel = entry.get('path', '')
        need(isinstance(rel, str) and rel and '..' not in rel and not rel.startswith('/'), 'BACKUP_MANIFEST_INVALID')
        target = backup_dir / rel
        exists = target.is_file()
        entry_ok = exists and sha256_file(target) == entry.get('sha256')
        integrity = None
        if exists and entry.get('kind') == 'sqlite':
            try:
                conn = sqlite3.connect(f'file:{target.as_posix()}?mode=ro', uri=True)
                try:
                    integrity = conn.execute('PRAGMA integrity_check').fetchone()[0]
                finally:
                    conn.close()
            except sqlite3.Error as exc:
                integrity = f'error:{type(exc).__name__}'
            entry_ok = entry_ok and integrity == 'ok'
        ok = ok and entry_ok
        checks.append({'path': rel, 'ok': entry_ok, 'integrity': integrity})
    receipt = {'schema': SCHEMA, 'ok': ok, 'backup_id': manifest.get('backup_id'),
               'verified_ns': time.time_ns(), 'file_count': len(checks), 'files': checks,
               'manifest_sha256': sha256_file(manifest_path), 'manifest': manifest}
    (backup_dir / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return receipt


def list_backups(backup_root: Path, limit: int = 20) -> list[dict]:
    need(type(limit) is int and 1 <= limit <= MAX_BACKUPS, 'INVALID_LIMIT')
    out = []
    if backup_root.is_dir():
        for path in sorted(backup_root.glob('backup-*'), reverse=True)[:limit]:
            receipt_path = path / 'receipt.json'
            entry = {'backup_dir': str(path), 'backup_id': path.name.split('backup-', 1)[1]}
            if receipt_path.is_file():
                try:
                    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
                    entry.update({'ok': receipt.get('ok'), 'verified_ns': receipt.get('verified_ns'),
                                  'file_count': receipt.get('file_count'),
                                  'label': (receipt.get('manifest') or {}).get('label')})
                except (json.JSONDecodeError, OSError):
                    entry.update({'ok': None, 'error': 'receipt unreadable'})
            else:
                entry.update({'ok': None, 'error': 'not verified'})
            out.append(entry)
    return out


def stage_restore(state_dir: Path, backup_dir: Path, *, confirm: str, now_ns=time.time_ns) -> dict:
    receipt = verify(backup_dir)
    need(receipt['ok'], 'BACKUP_INVALID')
    need(isinstance(confirm, str) and confirm == receipt['backup_id'], 'RESTORE_CONFIRM_MISMATCH')
    stage_dir = state_dir / 'v100' / 'recovery' / receipt['backup_id']
    stage_dir.mkdir(parents=True, exist_ok=True)
    staged = []
    for entry in receipt['manifest'].get('files', []):
        source = backup_dir / entry['path']
        target = stage_dir / entry['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        need(sha256_file(target) == entry['sha256'], 'RESTORE_STAGE_HASH_MISMATCH')
        staged.append({'path': entry['path'], 'sha256': entry['sha256'], 'kind': entry.get('kind')})
    marker = {'schema': SCHEMA, 'backup_id': receipt['backup_id'], 'staged_ns': now_ns(),
              'stage_dir': str(stage_dir), 'files': staged,
              'manifest_sha256': receipt['manifest_sha256'],
              'policy_binding': (receipt.get('manifest') or {}).get('policy_binding')}
    pending = state_dir / 'v100' / 'restore-pending.json'
    tmp = pending.with_suffix('.tmp')
    tmp.write_text(json.dumps(marker, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.replace(tmp, pending)
    return {'staged': True, 'backup_id': receipt['backup_id'], 'files': len(staged), 'pending': str(pending)}


def pending_status(state_dir: Path) -> dict:
    pending = state_dir / 'v100' / 'restore-pending.json'
    if not pending.is_file():
        return {'pending': False}
    try:
        marker = json.loads(pending.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return {'pending': True, 'valid': False}
    return {'pending': True, 'valid': isinstance(marker, dict),
            'backup_id': marker.get('backup_id'), 'files': len(marker.get('files', [])),
            'staged_ns': marker.get('staged_ns')}


def apply_pending_restore(state_dir: Path, *, now_ns=time.time_ns) -> dict:
    """Apply a staged restore. Runs at startup before any store opens.

    Idempotent: the pending marker is removed only after every file is in place
    and verified; an interrupted apply is retried on the next start.
    """
    pending = state_dir / 'v100' / 'restore-pending.json'
    if not pending.is_file():
        return {'applied': False}
    marker = json.loads(pending.read_text(encoding='utf-8'))
    need(isinstance(marker, dict) and marker.get('schema') == SCHEMA, 'RESTORE_MARKER_INVALID')
    stage_dir = Path(marker['stage_dir'])
    need(stage_dir.is_dir(), 'RESTORE_STAGE_MISSING')
    applied = []
    for entry in marker.get('files', []):
        rel = entry['path']
        source = stage_dir / rel
        need(source.is_file() and sha256_file(source) == entry['sha256'], 'RESTORE_STAGE_CORRUPT')
        target = state_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + '.restore-tmp')
        tmp.write_bytes(source.read_bytes())
        os.replace(tmp, target)
        if entry.get('kind') == 'sqlite':
            for suffix in ('-wal', '-shm'):
                side = Path(str(target) + suffix)
                if side.exists():
                    side.unlink()
        applied.append(rel)
    receipt = {'schema': SCHEMA, 'ok': True, 'applied_ns': now_ns(), 'backup_id': marker.get('backup_id'),
               'files': applied, 'manifest_sha256': marker.get('manifest_sha256'),
               'policy_binding': marker.get('policy_binding')}
    receipt_path = state_dir / 'v100' / 'restore-receipt.json'
    tmp_receipt = receipt_path.with_suffix('.tmp')
    tmp_receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.replace(tmp_receipt, receipt_path)
    pending.unlink()
    return {'applied': True, **{k: receipt[k] for k in ('backup_id', 'files', 'applied_ns')}}


def restore_receipt(state_dir: Path) -> dict | None:
    path = state_dir / 'v100' / 'restore-receipt.json'
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return {'ok': False, 'error': 'receipt unreadable'}
