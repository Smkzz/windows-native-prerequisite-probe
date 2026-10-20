"""Crash-safe v1.0.1 -> v1.0.2 state migration.

The original v1.0 migration remains historical in migration.json. The
autonomy-closure migration is additive and records its own receipt, creates a
verified backup before changing an existing mission database, and leaves a
durable pending marker until the receipt is committed. That makes an
interrupted migration resumable without silently discarding active missions.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

from ..nextlib.core import Rejected, need

SCHEMA = 2
FROM_VERSION = '1.0.1'
TO_VERSION = '1.0.2'
LEGACY_FROM_VERSION = '0.8.0-rc.1'
RECEIPT_NAME = 'migration-v102.json'
PENDING_NAME = 'migration-v102-pending.json'
OBSERVED = ('receipts.sqlite', 'next_tasks.sqlite', 'v060/transaction-journal.sqlite',
            'v060/move-journal.sqlite', 'v080/telemetry.sqlite', 'v080/runs.sqlite')

MIGRATION_COLUMNS = {
    'missions': {
        'recovery_reason': 'TEXT',
        'recovery_action': 'TEXT',
        'recovery_next_ns': 'INTEGER',
        'recovery_attempts': 'INTEGER NOT NULL DEFAULT 0',
        'recovery_stuck_since_ns': 'INTEGER',
        'recovery_last_ns': 'INTEGER',
        'generation': 'INTEGER NOT NULL DEFAULT 1',
        'fence_token_sha256': 'TEXT',
        'resource_keys_json': "TEXT NOT NULL DEFAULT '[]'",
        'dedupe_key': 'TEXT',
        'intent_sha256': 'TEXT',
        'superseded_by': 'TEXT',
        'dispatch_id': 'TEXT',
    },
    'schedules': {
        'dispatch_id': 'TEXT',
        'dispatch_claim_ns': 'INTEGER',
        'dispatch_generation': 'INTEGER NOT NULL DEFAULT 0',
        'resource_keys_json': "TEXT NOT NULL DEFAULT '[]'",
        'dedupe_key': 'TEXT',
        'supersedes_mission_id': 'TEXT',
    },
}


def _sha(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def status(state_dir: Path) -> dict | None:
    path = state_dir / 'v100' / RECEIPT_NAME
    if not path.is_file():
        # The v1.0 receipt is intentionally preserved as historical evidence.
        path = state_dir / 'v100' / 'migration.json'
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return {'schema': SCHEMA, 'ok': False, 'error': 'receipt unreadable'}


def _write_json(path: Path, value: dict) -> None:
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.replace(tmp, path)


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')}


def _migrate_missions_db(path: Path, *, fail_at: str | None = None) -> dict:
    """Apply only additive changes and commit them as one SQLite transaction."""
    if not path.is_file():
        return {'path': str(path), 'present': False, 'columns_added': [], 'tables_added': []}
    conn = sqlite3.connect(path, timeout=10)
    columns_added: list[str] = []
    tables_added: list[str] = []
    try:
        integrity = conn.execute('PRAGMA integrity_check').fetchone()[0]
        need(integrity == 'ok', 'MIGRATION_STATE_CORRUPT')
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.execute('BEGIN IMMEDIATE')
        if 'missions' in tables:
            existing = _table_columns(conn, 'missions')
            for name, declaration in MIGRATION_COLUMNS['missions'].items():
                if name not in existing:
                    conn.execute(f'ALTER TABLE missions ADD COLUMN "{name}" {declaration}')
                    columns_added.append('missions.' + name)
        if 'schedules' in tables:
            existing = _table_columns(conn, 'schedules')
            for name, declaration in MIGRATION_COLUMNS['schedules'].items():
                if name not in existing:
                    conn.execute(f'ALTER TABLE schedules ADD COLUMN "{name}" {declaration}')
                    columns_added.append('schedules.' + name)
        if fail_at == 'after_columns':
            raise Rejected('MIGRATION_INTERRUPTED')
        # Do not use executescript here: sqlite3 implicitly commits before
        # executescript, which would make an interrupted additive migration
        # impossible to roll back as one unit.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mission_fences(
                fence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_key TEXT NOT NULL,
                mission_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                fence_token_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                acquired_ns INTEGER NOT NULL,
                released_ns INTEGER,
                superseded_by TEXT
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS mission_active_resource_fence "
                     "ON mission_fences(resource_key) WHERE state='ACTIVE'")
        conn.execute("CREATE INDEX IF NOT EXISTS mission_fences_mission "
                     "ON mission_fences(mission_id, state)")
        if 'missions' in tables:
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS mission_active_dedupe "
                         "ON missions(project, dedupe_key) WHERE dedupe_key IS NOT NULL")
            conn.execute("CREATE INDEX IF NOT EXISTS missions_recovery_due "
                         "ON missions(state, recovery_next_ns)")
            conn.execute("CREATE INDEX IF NOT EXISTS missions_dispatch "
                         "ON missions(dispatch_id)")
        if 'schedules' in tables:
            conn.execute("CREATE INDEX IF NOT EXISTS schedules_dispatch "
                         "ON schedules(dispatch_id)")
        if 'mission_fences' not in tables:
            tables_added.append('mission_fences')
        if 'mission_meta' in tables:
            conn.execute("INSERT OR REPLACE INTO mission_meta(key,value) VALUES('schema','2')")
            conn.execute("INSERT OR REPLACE INTO mission_meta(key,value) VALUES('migration_origin','1.0.1')")
        conn.commit()
        return {'path': str(path), 'present': True, 'columns_added': columns_added,
                'tables_added': tables_added}
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize(state_dir: Path, *, policy_binding: str | None = None, now_ns=time.time_ns,
               fail_at: str | None = None) -> dict:
    state = state_dir / 'v100'
    state.mkdir(parents=True, exist_ok=True)
    existing = status(state_dir)
    if (existing is not None and existing.get('ok') is not False and
            existing.get('to_version') == TO_VERSION and existing.get('schema') == SCHEMA):
        return {**existing, 'idempotent': True}
    pending_path = state / PENDING_NAME
    pending = None
    if pending_path.is_file():
        try:
            pending = json.loads(pending_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            raise Rejected('MIGRATION_PENDING_CORRUPT') from None
        need(pending.get('schema') == SCHEMA and pending.get('to_version') == TO_VERSION,
             'MIGRATION_PENDING_INVALID')
    legacy = None
    legacy_path = state / 'migration.json'
    if legacy_path.is_file():
        try:
            legacy = json.loads(legacy_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            raise Rejected('MIGRATION_ORIGIN_CORRUPT') from None
    observed = [{'path': rel, 'sha256': _sha(state_dir / rel)} for rel in OBSERVED]
    backup_receipt = None
    if pending is None:
        from . import backup as backup_mod
        backup_root = state / 'backups'
        backup_receipt = backup_mod.create(
            state_dir, backup_root, label='migration-1-to-2',
            metadata={'migration': TO_VERSION, 'policy_binding': policy_binding})
        need(backup_receipt.get('ok') is True, 'MIGRATION_BACKUP_INVALID')
        pending = {'schema': SCHEMA, 'from_version': FROM_VERSION, 'to_version': TO_VERSION,
                   'created_ns': now_ns(), 'backup_id': backup_receipt['backup_id'],
                   'backup_dir': backup_receipt['backup_dir'],
                   'backup_manifest_sha256': backup_receipt['manifest_sha256']}
        _write_json(pending_path, pending)
        if fail_at in ('after_backup', 'before_schema'):
            raise Rejected('MIGRATION_INTERRUPTED')
    else:
        from . import backup as backup_mod
        backup_dir = Path(pending.get('backup_dir', ''))
        backup_root = (state / 'backups').resolve()
        try:
            backup_dir.resolve().relative_to(backup_root)
        except ValueError:
            raise Rejected('MIGRATION_BACKUP_INVALID') from None
        backup_receipt = backup_mod.verify(backup_dir)
        need(backup_receipt.get('ok') is True, 'MIGRATION_BACKUP_INVALID')
    db_result = _migrate_missions_db(state / 'missions.sqlite', fail_at=fail_at)
    if fail_at == 'before_receipt':
        raise Rejected('MIGRATION_INTERRUPTED')
    receipt = {'schema': SCHEMA, 'ok': True, 'from_version': FROM_VERSION, 'to_version': TO_VERSION,
               'migration_origin': (legacy or {}).get('to_version', LEGACY_FROM_VERSION),
               'initialized_ns': pending['created_ns'], 'completed_ns': now_ns(),
               'observed_prior_state': observed,
               'observed_files_present': sum(1 for item in observed if item['sha256']),
               'policy_binding': policy_binding,
               'pre_migration_backup_id': pending.get('backup_id'),
               'pre_migration_backup_manifest_sha256': pending.get('backup_manifest_sha256'),
               'database': db_result,
               'idempotent': False,
               'note': 'additive v1.0.1 to v1.0.2 migration; prior stores and the v1.0 receipt remain readable'}
    _write_json(state / RECEIPT_NAME, receipt)
    try:
        pending_path.unlink()
    except FileNotFoundError:
        pass
    return receipt
