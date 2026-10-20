"""Workspace identity evidence and divergence classification.

Identity is best-effort evidence, never authorization: Git is used when present
but is never required, and a classification of "same" never grants new
authority. Reads are bounded, use argv arrays (no shell), and never write to
the workspace or to Git state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from ..nextlib.core import Rejected, digest, need, safe_relative, sha

SCHEMA = 1
MAX_WATCH_PATHS = 32
MAX_WATCH_FILE_BYTES = 4 * 1024 * 1024
MAX_WATCH_TOTAL_BYTES = 16 * 1024 * 1024
MAX_DIRTY_SAMPLE = 16
MAX_GIT_BYTES = 262144
GIT_TIMEOUT = 10
FINGERPRINT_ENTRIES = 200
CLASSIFICATIONS = frozenset({
    'same', 'advanced', 'rewound', 'diverged', 'branch_changed', 'dirty_changed', 'files_changed',
    'different_repo', 'missing', 'replaced', 'no_git_changed',
})


def _git_env() -> dict:
    env = dict(os.environ)
    env.update({'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0', 'GIT_PAGER': 'cat',
                'GIT_CONFIG_NOSYSTEM': '1', 'LC_ALL': 'C'})
    return env


def _git(root: Path, *args: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(['git', '-C', str(root), *args], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_git_env(),
                              timeout=GIT_TIMEOUT, shell=False)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return 127, ''
    out = proc.stdout[:MAX_GIT_BYTES].decode('utf-8', errors='replace').strip()
    return proc.returncode, out


def root_identity(root: Path) -> dict:
    """Stable identity of the root directory itself (volume + file index)."""
    try:
        info = root.lstat()
    except FileNotFoundError:
        return {'path': str(root), 'exists': False}
    except OSError:
        return {'path': str(root), 'exists': None}
    reparse = bool(getattr(info, 'st_file_attributes', 0) & 0x400)
    is_dir = stat.S_ISDIR(info.st_mode)
    file_id = getattr(info, 'st_ino', 0)
    volume = getattr(info, 'st_dev', 0)
    return {'path': str(root), 'exists': True, 'is_dir': is_dir, 'reparse': reparse,
            'volume': volume, 'file_id': file_id, 'mtime_ns': info.st_mtime_ns}


def _ancestor(repo: Path, older: str, newer: str) -> str:
    if not older or not newer:
        return 'unknown'
    code, _ = _git(repo, 'merge-base', '--is-ancestor', older, newer)
    if code == 0:
        return 'ahead'
    code, _ = _git(repo, 'merge-base', '--is-ancestor', newer, older)
    if code == 0:
        return 'behind'
    return 'diverged' if code == 1 else 'unknown'


def git_identity(root: Path) -> dict:
    code, toplevel = _git(root, 'rev-parse', '--show-toplevel')
    if code != 0 or not toplevel:
        return {'present': False}
    repo = Path(toplevel)
    head_code, head = _git(repo, 'rev-parse', '--verify', 'HEAD')
    branch_code, branch = _git(repo, 'symbolic-ref', '-q', 'HEAD')
    detached = branch_code != 0
    status_code, status = _git(repo, 'status', '--porcelain=v1', '-z', '--untracked-files=no')
    dirty_paths = []
    if status_code == 0 and status:
        for entry in status.split('\0'):
            if not entry:
                continue
            candidate = entry[3:] if len(entry) > 3 else entry
            try:
                dirty_paths.append(safe_relative(candidate.replace('\\', '/')))
            except Rejected:
                dirty_paths.append('<protected>')
    return {'present': True, 'repo_root': str(repo), 'head': head if head_code == 0 else None,
            'branch': None if detached else (branch or None), 'detached': detached,
            'dirty': bool(dirty_paths), 'dirty_count': len(dirty_paths),
            'dirty_sample': dirty_paths[:MAX_DIRTY_SAMPLE]}


def tree_fingerprint(root: Path, limit: int = FINGERPRINT_ENTRIES) -> str:
    """Bounded fingerprint of direct children; catches recreated/changed roots
    without walking an unbounded tree."""
    entries = []
    try:
        with os.scandir(root) as scan:
            for entry in scan:
                if len(entries) >= limit:
                    break
                try:
                    info = entry.stat(follow_symlinks=False)
                    entries.append([entry.name, entry.is_dir(follow_symlinks=False),
                                    int(getattr(info, 'st_size', 0)), int(getattr(info, 'st_mtime_ns', 0))])
                except OSError:
                    entries.append([entry.name, None, None, None])
    except OSError:
        return 'unreadable'
    entries.sort(key=lambda row: str(row[0]).casefold())
    return digest(entries)


def watch_fingerprints(root: Path, paths: list[str]) -> dict:
    need(isinstance(paths, list) and len(paths) <= MAX_WATCH_PATHS, 'INVALID_WATCH_PATHS')
    out = {}
    total = 0
    for raw in paths:
        rel = safe_relative(raw)
        target = root.joinpath(*rel.split('/'))
        try:
            info = target.lstat()
        except FileNotFoundError:
            out[rel] = None
            continue
        except OSError:
            raise Rejected('WATCH_PATH_UNREADABLE') from None
        attributes = getattr(info, 'st_file_attributes', 0)
        need(not stat.S_ISLNK(info.st_mode) and not (attributes & 0x400), 'WATCH_PATH_LINK')
        need(stat.S_ISREG(info.st_mode), 'WATCH_PATH_NOT_FILE')
        need(info.st_size <= MAX_WATCH_FILE_BYTES, 'WATCH_PATH_TOO_LARGE')
        total += info.st_size
        need(total <= MAX_WATCH_TOTAL_BYTES, 'WATCH_PATH_TOO_LARGE')
        with target.open('rb') as stream:
            out[rel] = sha(stream.read())
    return out


def build_identity(policy, project: str, watch_paths: list[str] | None = None) -> dict:
    root = Path(policy.projects[project].root)
    record = {'schema': SCHEMA, 'project': project, 'root': str(root), 'root_id': root_identity(root),
              'git': git_identity(root), 'tree': tree_fingerprint(root),
              'watched': watch_fingerprints(root, list(watch_paths or []))}
    record['digest'] = digest({k: v for k, v in record.items() if k != 'digest'})
    return record


def _differences(stored: dict, current: dict) -> list[str]:
    differences = []
    stored_root, current_root = stored.get('root_id', {}), current.get('root_id', {})
    if not current_root.get('exists'):
        differences.append('root_missing')
    elif not stored_root.get('exists'):
        differences.append('root_reappeared')
    elif stored_root.get('volume') != current_root.get('volume') or stored_root.get('file_id') != current_root.get('file_id'):
        differences.append('root_replaced')
    if stored.get('root') != current.get('root'):
        differences.append('root_path_changed')
    stored_git, current_git = stored.get('git', {}), current.get('git', {})
    if stored_git.get('present') != current_git.get('present'):
        differences.append('git_presence_changed')
    elif stored_git.get('present'):
        if stored_git.get('repo_root') != current_git.get('repo_root'):
            differences.append('repo_root_changed')
        elif stored_git.get('head') != current_git.get('head'):
            relationship = _ancestor(Path(current_git['repo_root']), stored_git.get('head'), current_git.get('head'))
            differences.extend([f'commit_changed:{relationship}'])
        if stored_git.get('detached') != current_git.get('detached'):
            differences.append('detached_state_changed')
        elif stored_git.get('branch') != current_git.get('branch'):
            differences.append('branch_changed')
        if bool(stored_git.get('dirty')) != bool(current_git.get('dirty')):
            differences.append('dirty_state_changed')
        elif stored_git.get('dirty_sample') != current_git.get('dirty_sample'):
            differences.append('dirty_paths_changed')
    else:
        if stored.get('tree') != current.get('tree'):
            differences.append('tree_changed')
    stored_watched, current_watched = stored.get('watched', {}), current.get('watched', {})
    for rel, value in stored_watched.items():
        if current_watched.get(rel) != value:
            differences.append('watched_file_changed:' + rel)
    return differences


def classify(stored: dict, current: dict) -> dict:
    """Classify divergence. Any non-'same' result requires explicit acceptance."""
    for record in (stored, current):
        need(isinstance(record, dict) and record.get('schema') == SCHEMA, 'INVALID_IDENTITY')
        need(isinstance(record.get('root'), str) and isinstance(record.get('root_id'), dict)
             and isinstance(record.get('git'), dict) and isinstance(record.get('watched'), dict),
             'INVALID_IDENTITY')
    differences = _differences(stored, current)
    if not differences:
        classification = 'same'
    elif 'root_missing' in differences:
        classification = 'missing'
    elif 'root_replaced' in differences:
        classification = 'replaced'
    elif 'git_presence_changed' in differences or 'repo_root_changed' in differences:
        classification = 'different_repo'
    elif any(d.startswith('commit_changed:') for d in differences):
        relationship = next(d.split(':', 1)[1] for d in differences if d.startswith('commit_changed:'))
        classification = {'ahead': 'advanced', 'behind': 'rewound', 'diverged': 'diverged'}.get(relationship, 'diverged')
    elif 'branch_changed' in differences or 'detached_state_changed' in differences:
        classification = 'branch_changed'
    elif 'dirty_state_changed' in differences or 'dirty_paths_changed' in differences:
        classification = 'dirty_changed'
    elif any(d.startswith('watched_file_changed:') for d in differences) or 'tree_changed' in differences:
        classification = 'files_changed'
    else:
        classification = 'no_git_changed'
    return {'classification': classification, 'differences': differences,
            'requires_acceptance': classification != 'same',
            'stored_digest': stored.get('digest'), 'current_digest': current.get('digest')}
