"""Delegated CODEX_HOME construction.

Every delegated agent gets an isolated Codex home under LocalControl state:
a rendered minimal config.toml (no inherited MCP servers, plugins, hooks or
multi-agent features) and a HARD LINK to the operator's existing
~/.codex/auth.json — never a copy, never logged, never in a project root.
Thread rollout data lands in this home, which is what makes thread/resume
work after a provider process or daemon restart.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
import tomllib

from ..errors import ControlError, require
from ..nextlib.core import need

# Literal secrets must never be copied into a delegated home: env_key and
# env_http_headers carry env-var NAMES (safe), everything else matching this
# pattern is a potential secret value and is dropped.
SENSITIVE_KEY = re.compile(r'secret|token|password|credential|authorization|api[-_]?key',
                           re.IGNORECASE)
SAFE_KEY_NAMES = frozenset({'env_key', 'env_http_headers'})
BUILTIN_MODEL_PROVIDERS = frozenset({'openai'})


def _sensitive(key: str) -> bool:
    return key not in SAFE_KEY_NAMES and bool(SENSITIVE_KEY.search(key))


def read_provider_table(user_config: Path, provider_name: str) -> str:
    """Extract exactly one [model_providers.<name>] table from the operator's
    codex config.toml, re-rendered. Provider defs carry no secret material
    (env_key names, not values); anything secret stays in auth.json."""
    need(isinstance(provider_name, str) and 0 < len(provider_name) <= 64
         and provider_name.replace('_', '').replace('-', '').isalnum(), 'PROVIDER_CONFIG')
    if provider_name in BUILTIN_MODEL_PROVIDERS:
        return ''
    try:
        data = tomllib.loads(user_config.read_text(encoding='utf-8'))
    except (OSError, tomllib.TOMLDecodeError):
        raise ControlError('PROVIDER_CONFIG', 'Cannot read the operator codex config')
    providers = data.get('model_providers') or {}
    spec = providers.get(provider_name)
    if spec is None:
        raise ControlError('PROVIDER_CONFIG',
                           f'Model provider {provider_name!r} not found in the operator codex config')
    require(isinstance(spec, dict), 'PROVIDER_CONFIG', 'Provider definition must be a table')
    lines = [f'[model_providers.{provider_name}]']
    for key, value in spec.items():
        if _sensitive(key):
            continue
        if isinstance(value, bool):
            lines.append(f'{key} = {"true" if value else "false"}')
        elif isinstance(value, (int, float)):
            lines.append(f'{key} = {value}')
        elif isinstance(value, str):
            lines.append(f'{key} = {_toml_str(value)}')
        elif isinstance(value, dict):
            # nested table (e.g. http_headers): render one level only, strings/numbers only
            for sub_key, sub_val in value.items():
                if _sensitive(sub_key):
                    continue
                if isinstance(sub_val, str):
                    lines.append(f'{key}.{sub_key} = {_toml_str(sub_val)}')
                elif isinstance(sub_val, (int, float)) and not isinstance(sub_val, bool):
                    lines.append(f'{key}.{sub_key} = {sub_val}')
        # lists/other shapes are dropped deliberately: nothing provider-critical uses them
    return '\n'.join(lines)


def _toml_str(value: str) -> str:
    import json
    return json.dumps(value, ensure_ascii=True)


def build_home(home: Path, *, auth_source: Path, provider_table: str, model: str | None,
               model_provider: str, sandbox_mode: str, model_catalog: str | None,
               windows_sandbox: str, shim: dict | None) -> Path:
    """Create the delegated home. Returns the home path. Fails closed on any
    link/config problem — a partially built home is never used."""
    home.mkdir(parents=True, exist_ok=True)
    for name in ('config.toml', 'auth.json'):
        target = home / name
        if target.exists() or target.is_symlink():
            target.unlink()

    auth_dst = home / 'auth.json'
    try:
        os.link(auth_source, auth_dst)
    except OSError as error:
        raise ControlError('AUTH_PREREQUISITE',
                           'Cannot hard-link codex auth.json into the delegated home '
                           '(same-volume requirement)', {'detail': type(error).__name__})

    sandbox_cfg = {'read_only': 'read-only', 'workspace_write': 'workspace-write',
                   'danger_full_access': 'danger-full-access'}[sandbox_mode]
    parts = [
        f'model_provider = {_toml_str(model_provider)}',
        'approval_policy = "never"',
        f'sandbox_mode = {_toml_str(sandbox_cfg)}',
    ]
    if model:
        parts.insert(0, f'model = {_toml_str(model)}')
    if model_catalog:
        parts.append(f'model_catalog_json = {_toml_str(model_catalog)}')
    parts += [
        '',
        '[windows]',
        f'sandbox = {_toml_str(windows_sandbox)}',
        '',
        '[features]',
        'plugins = false',
        'multi_agent = false',
        '',
        provider_table,
    ]
    if shim is not None:
        parts += [
            '',
            '[mcp_servers.localcontrol]',
            f'command = {_toml_str(shim["command"])}',
            'args = [' + ', '.join(_toml_str(a) for a in shim['args']) + ']',
            'startup_timeout_sec = 30',
            # The child runs under approval_policy = "never": Codex's local
            # approval gate would auto-deny every lc_agent_* call. The shim's
            # own token + ancestry + subtree authorization is the real
            # boundary, so the LocalControl-owned server is pre-approved.
            'default_tools_approval_mode = "approve"',
            '',
            '[mcp_servers.localcontrol.env]',
            f'LOCALCONTROL_DELEGATE_TOKEN = {_toml_str(shim["token"])}',
            f'LOCALCONTROL_AGENT_ID = {_toml_str(shim["agent_id"])}',
            f'PYTHONPATH = {_toml_str(shim["pythonpath"])}',
        ]
    tmp = home / 'config.toml.tmp'
    tmp.write_text('\n'.join(parts) + '\n', encoding='utf-8')
    os.replace(tmp, home / 'config.toml')
    return home


def child_env() -> dict[str, str]:
    """Bounded environment for provider processes. No caller-supplied values,
    no secrets: auth lives in CODEX_HOME files, not env."""
    allowed = {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT', 'TEMP', 'TMP',
               'LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'PROGRAMDATA', 'USERNAME',
               'SYSTEMDRIVE', 'HOMEDRIVE', 'HOMEPATH', 'LANG', 'LC_ALL',
               'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS'}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env['PYTHONUTF8'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'
    return env
