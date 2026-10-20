"""Independent deterministic completion verifier.

The verifier never trusts mission notes or claimed status. It re-reads actual
files through the operator policy, re-builds workspace identity, can execute
declared verification commands through the owned job system, and checks budget
and policy compliance. Only a fully passing verification may commit SUCCEEDED.
"""
from __future__ import annotations

import time
from pathlib import Path

from ..nextlib.core import Rejected, digest, need, packed, safe_relative
from ..v080 import identity as identity_mod

VERIFIER = 'deterministic-v1'
SCHEMA = 2
CONTRACT_SCHEMAS = frozenset({1, 2})
MAX_REQUIRED_FILES = 64
MAX_FORBIDDEN_FILES = 64
MAX_COMMANDS = 8
MAX_COMMAND_MS = 600000
CONTRACT_KEYS = frozenset({'schema', 'workspace_identity_sha256', 'required_files', 'forbidden_files',
                           'commands', 'git_head', 'git_branch'})
COMMAND_KEYS_V1 = frozenset({'recipe', 'argv', 'expect_returncode', 'timeout_ms'})
COMMAND_KEYS_V2 = COMMAND_KEYS_V1 | {'working_directory'}
BLOCKING_IDENTITY_DIFFERENCES = frozenset({'root_missing', 'root_replaced', 'root_path_changed', 'different_repo',
                                           'repo_root_changed', 'git_presence_changed'})
RUNTIME_BUDGET_KEYS = frozenset({'max_jobs', 'max_transactions', 'max_tool_calls', 'max_output_bytes', 'max_wall_ms',
                                 'max_job_memory_bytes', 'max_job_cpu_ms', 'max_job_processes'})


def validate_contract(contract: dict) -> dict:
    need(isinstance(contract, dict), 'INVALID_CONTRACT')
    need(set(contract) <= CONTRACT_KEYS, 'INVALID_CONTRACT')
    clean: dict = {}
    schema = contract.get('schema', 1)
    need(schema in CONTRACT_SCHEMAS, 'INVALID_CONTRACT')
    clean['schema'] = schema
    command_keys = COMMAND_KEYS_V2 if schema >= 2 else COMMAND_KEYS_V1
    expected = contract.get('workspace_identity_sha256')
    if expected is not None:
        need(isinstance(expected, str) and len(expected) == 64, 'INVALID_CONTRACT')
        clean['workspace_identity_sha256'] = expected
    for key in ('git_head', 'git_branch'):
        value = contract.get(key)
        if value is not None:
            need(isinstance(value, str) and 0 < len(value) <= 256, 'INVALID_CONTRACT')
            clean[key] = value
    required = contract.get('required_files', [])
    need(isinstance(required, list) and len(required) <= MAX_REQUIRED_FILES, 'INVALID_CONTRACT')
    clean_required = []
    for item in required:
        need(isinstance(item, dict) and set(item) <= {'path', 'sha256'}, 'INVALID_CONTRACT')
        rel = safe_relative(item.get('path', ''))
        entry = {'path': rel}
        if item.get('sha256') is not None:
            need(isinstance(item['sha256'], str) and len(item['sha256']) == 64, 'INVALID_CONTRACT')
            entry['sha256'] = item['sha256']
        clean_required.append(entry)
    clean['required_files'] = clean_required
    forbidden = contract.get('forbidden_files', [])
    need(isinstance(forbidden, list) and len(forbidden) <= MAX_FORBIDDEN_FILES, 'INVALID_CONTRACT')
    clean['forbidden_files'] = [safe_relative(p) for p in forbidden]
    commands = contract.get('commands', [])
    need(isinstance(commands, list) and len(commands) <= MAX_COMMANDS, 'INVALID_CONTRACT')
    clean_commands = []
    for item in commands:
        need(isinstance(item, dict) and set(item) <= command_keys, 'INVALID_CONTRACT')
        need(('recipe' in item) != ('argv' in item), 'INVALID_CONTRACT')
        entry = {}
        if 'recipe' in item:
            need(isinstance(item['recipe'], str) and 0 < len(item['recipe']) <= 128, 'INVALID_CONTRACT')
            entry['recipe'] = item['recipe']
        else:
            argv = item['argv']
            need(isinstance(argv, list) and 1 <= len(argv) <= 64
                 and all(isinstance(x, str) and 0 < len(x) <= 4096 for x in argv), 'INVALID_CONTRACT')
            entry['argv'] = list(argv)
        expected_code = item.get('expect_returncode', 0)
        need(type(expected_code) is int and 0 <= expected_code <= 255, 'INVALID_CONTRACT')
        entry['expect_returncode'] = expected_code
        timeout = item.get('timeout_ms', 300000)
        need(type(timeout) is int and 1 <= timeout <= MAX_COMMAND_MS, 'INVALID_CONTRACT')
        entry['timeout_ms'] = timeout
        if 'working_directory' in item:
            need(type(item['working_directory']) is str, 'INVALID_CONTRACT')
            entry['working_directory'] = safe_relative(item['working_directory'])
        clean_commands.append(entry)
    clean['commands'] = clean_commands
    return clean


def measure(*, mission: dict, chain_ok: bool, current_identity: dict, current_binding: str,
            read_sha, run_command, budget_state: dict, now_ns=time.time_ns) -> dict:
    gates = []

    def gate(name: str, ok: bool, detail) -> None:
        gates.append({'name': name, 'ok': bool(ok), 'detail': detail})

    contract = mission['success_contract']
    stored = mission['workspace_identity']
    classification = identity_mod.classify(stored, current_identity)
    blocking = [d for d in classification['differences'] if d in BLOCKING_IDENTITY_DIFFERENCES]
    identity_ok = not blocking
    gate('workspace_identity', identity_ok, {'classification': classification['classification'],
                                             'blocking': blocking,
                                             'differences': classification['differences'][:16]})
    expected_digest = contract.get('workspace_identity_sha256')
    if expected_digest is not None:
        gate('workspace_identity_digest', current_identity.get('digest') == expected_digest,
             {'expected': expected_digest, 'observed': current_identity.get('digest')})
    expected_head = contract.get('git_head')
    if expected_head is not None:
        git = current_identity.get('git', {})
        gate('git_head', git.get('present') is True and git.get('head') == expected_head,
             {'expected': expected_head, 'observed': git.get('head'), 'present': git.get('present')})
    expected_branch = contract.get('git_branch')
    if expected_branch is not None:
        git = current_identity.get('git', {})
        gate('git_branch', git.get('present') is True and git.get('branch') == expected_branch,
             {'expected': expected_branch, 'observed': git.get('branch'), 'present': git.get('present')})
    for entry in contract.get('required_files', []):
        exists, observed, size = read_sha(entry['path'])
        ok = bool(exists)
        detail = {'path': entry['path'], 'exists': exists, 'bytes': size}
        if ok and 'sha256' in entry:
            ok = observed == entry['sha256']
            detail['expected_sha256'] = entry['sha256']
            detail['observed_sha256'] = observed
        gate('required_file:' + entry['path'], ok, detail)
    for rel in contract.get('forbidden_files', []):
        exists, _, size = read_sha(rel)
        detail = {'path': rel, 'exists': exists, 'bytes': size}
        if exists is None:
            detail['error'] = 'read_inconclusive'
        gate('forbidden_file:' + rel, exists is False, detail)
    for index, spec in enumerate(contract.get('commands', [])):
        result = run_command(spec)
        if isinstance(result, dict):
            expected = spec.get('expect_returncode', 0)
            observed = result.get('returncode')
            ok = result.get('ok') is True and observed == expected
            detail = {'spec': spec.get('recipe') or spec.get('argv'), 'expect_returncode': expected,
                      'observed_returncode': observed, 'job_id': result.get('job_id'),
                      'timed_out': result.get('timed_out'), 'output_bytes': result.get('output_bytes'),
                      'working_directory': spec.get('working_directory'),
                      'cwd': result.get('cwd'), 'scratch': result.get('scratch'),
                      'execution': result.get('execution')}
            if result.get('error'):
                detail['error'] = result['error']
        else:
            ok = False
            detail = {'spec': spec.get('recipe') or spec.get('argv'), 'error': 'command runner unavailable'}
        gate(f"command_{index}", ok, detail)
    budgets = mission['budgets']
    # Time accounting: durable per-state accumulators plus the in-flight
    # interval in the current state. Legacy rows may lack a basis
    # (time_accounting='partial'); their accumulators are reported honestly
    # but only elapsed/deadline caps can be enforced against them.
    now = now_ns()
    elapsed_ms = int((now - mission['created_ns']) / 1_000_000)
    inflight = max(0, now - (mission['state_since_ns'] or mission['created_ns']))
    state = mission['state']
    active_ns = (mission['active_ns'] or 0) + (inflight if state in {'RUNNING', 'VERIFYING'} else 0)
    suspended_ns = (mission['suspended_ns'] or 0) + (
        inflight if state in {'WAITING', 'BLOCKED', 'RECOVERING'} else 0)
    ready_ns = (mission['ready_ns'] or 0) + (inflight if state == 'READY' else 0)
    queue_ms = None
    if mission['first_running_ns'] is not None:
        queue_ms = int((mission['first_running_ns'] - mission['created_ns']) / 1_000_000)
    budget_details = {
        'jobs': {'used': budget_state['jobs'], 'limit': budgets.get('max_jobs')},
        'transactions': {'used': budget_state['transactions'], 'limit': budgets.get('max_transactions')},
        'tool_calls': {'used': budget_state['tool_calls'], 'limit': budgets.get('max_tool_calls')},
        'output_bytes': {'used': budget_state['output_bytes'], 'limit': budgets.get('max_output_bytes')},
        'wall_ms': {'used': elapsed_ms, 'limit': budgets.get('max_wall_ms')},
        'active_ms': {'used': int(active_ns / 1_000_000), 'limit': budgets.get('max_active_ms')},
        'suspended_ms': {'used': int(suspended_ns / 1_000_000), 'limit': None},
        'ready_ms': {'used': int(ready_ns / 1_000_000), 'limit': None},
        'deadline_ms': {'used': elapsed_ms, 'limit': budgets.get('max_deadline_ms')},
        'queue_ms': queue_ms,
        'accounting_basis': mission['time_accounting'] or 'partial',
        'accounted_ms': int((active_ns + suspended_ns + ready_ns) / 1_000_000),
        'elapsed_ms': elapsed_ms,
    }
    budget_ok = all(
        (v['limit'] is None or v['used'] <= v['limit']) for v in budget_details.values()
        if isinstance(v, dict))
    gate('budget', budget_ok, budget_details)
    gate('policy_binding', current_binding == mission['policy_binding'],
         {'expected': mission['policy_binding'], 'observed': current_binding})
    gate('mission_chain', bool(chain_ok), {'chain_ok': bool(chain_ok)})
    verdict = all(g['ok'] for g in gates)
    record = {'verifier': VERIFIER, 'schema': SCHEMA, 'ok': verdict, 'gates': gates,
              'mission_id': mission['mission_id'], 'state_at_verification': mission['state'],
              'workspace_root': mission['workspace_root'], 'verified_ns': now_ns(),
              'policy_binding': mission['policy_binding']}
    record['digest'] = digest({k: v for k, v in record.items() if k != 'digest'})
    return record
