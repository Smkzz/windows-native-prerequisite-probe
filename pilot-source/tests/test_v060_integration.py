from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import sys

from localcontrol.facade import Facade
from localcontrol.nextlib.core import Rejected as NextRejected
from localcontrol.policy import Policy, Project
from localcontrol.server import V060_SCHEMAS
from localcontrol.v060.admin import validate_publish
from localcontrol.v060.core import Rejected
from localcontrol.v060.executor import MoveExecutor
from localcontrol.v060.migration import TreeSnapshot
from localcontrol.v060.registry import Collection, RegistryCodec, RegistrySnapshot, Workspace
from tests.fake_backend import FakeBackend


MUTATING_V060 = {
    "maintenance_begin", "maintenance_end", "project_move_apply",
    "project_move_reconcile", "project_move_rollback", "task_cleanup_apply",
}


class DummyBackend:
    async def call(self, project, tool, args):
        raise AssertionError(f"unexpected backend call: {project}/{tool}")


class FakeMoveAdapter:
    def __init__(self, source: str, volume: str = "vol-test"):
        self.source = source
        self.destination = None
        self.volume = volume
        self.identity = "vol-test:0123456789abcdef"
        self.state = "source"

    def snapshot(self, path: str):
        expected = self.source if self.state == "source" else self.destination
        if path != expected:
            raise Rejected("NOT_FOUND")
        return TreeSnapshot(path, self.identity, self.volume, (), complete=True)

    def exists(self, path: str) -> bool:
        return path == (self.source if self.state == "source" else self.destination)

    def parent_volume(self, path: str) -> str:
        return self.volume

    def validate_paths(self, source, destination, source_authority_root,
                       destination_collection_root, *, source_may_be_missing=False):
        self.destination = destination

    def rename(self, source: str, destination: str) -> None:
        if self.state == "source" and source == self.source:
            self.destination = destination
            self.state = "destination"
            return
        if self.state == "destination" and source == self.destination and destination == self.source:
            self.state = "source"
            return
        raise Rejected("RENAME_STATE")


class V060Integration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="localcontrol-v060-integration-")
        root = Path(self.tmp.name).resolve()
        self.collection = root / "collection"
        self.live = self.collection / "live"
        self.external = root / "external"
        self.state = root / "state"
        self.v060_state = self.state / "v060"
        self.control = root / "control"
        for path in (self.live, self.external, self.v060_state, self.control):
            path.mkdir(parents=True, exist_ok=False)
        self.config = self.control / "localcontrol.json"
        self.config.write_text("{}", encoding="utf-8")
        self.worker_manifest = self.control / "worker.json"
        self.worker_manifest.write_text(json.dumps({
            "workspace": str(self.live), "network_capabilities": [],
            "profile_name": "LocalControl.V060Integration",
            "runtime": str(Path(sys.executable).resolve().parent),
        }), encoding="utf-8")
        key = os.urandom(32)
        (self.v060_state / "registry-key.bin").write_bytes(key)
        (self.v060_state / "move-key.bin").write_bytes(os.urandom(32))
        self.registry_snapshot = RegistrySnapshot(
            1,
            (
                Workspace("live", str(self.live), writable=True, exec_enabled=True, maintenance=False),
                Workspace("external", str(self.external), writable=True, exec_enabled=False, maintenance=True),
            ),
            (Collection("projects", str(self.collection), writable=True),),
        )
        self.registry_path = self.v060_state / "workspace-registry.json"
        self.registry_codec = RegistryCodec(key)
        self.registry_path.write_bytes(self.registry_codec.encode(self.registry_snapshot))
        policy = Policy({"live": Project(self.live, True)}, self.state, exec_mode="appcontainer",
                        workers={"live": {"manifest": str(self.worker_manifest)}})
        self.facade = Facade(policy, FakeBackend(),
                             v060_options={"enabled": True, "allowed_usage_adapters": ["codex"]},
                             config_path=self.config)

    def tearDown(self):
        self.facade.close()
        self.tmp.cleanup()

    @staticmethod
    def run_async(coro):
        return asyncio.run(coro)

    def assertError(self, result, code):
        self.assertFalse(result.get("ok"), result)
        self.assertEqual(result.get("error", {}).get("code"), code, result)

    def test_all_v060_mutations_require_request_id_at_mcp_boundary(self):
        for name in MUTATING_V060:
            with self.subTest(name=name):
                properties, required = V060_SCHEMAS[name][1], V060_SCHEMAS[name][2]
                self.assertIn("request_id", properties)
                self.assertIn("request_id", required)

    def test_catalog_preserves_22_plus_19_and_registry_is_model_read_only(self):
        result = self.run_async(self.facade.call("system_info", "*", {}))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["data"]["tool_count"], 41)
        catalog = self.run_async(self.facade.call("workspace_catalog", "*", {}))
        self.assertTrue(catalog["ok"], catalog)
        self.assertFalse(catalog["data"]["authority_mutation_exposed"])
        self.assertTrue(catalog["data"]["operator_only_registry"])

    def test_registry_cannot_redefine_base_project_or_add_exec_authority(self):
        original = self.registry_path.read_bytes()
        try:
            wrong_root = self.external.parent / "wrong-live"
            wrong_root.mkdir()
            bad = RegistrySnapshot(
                2,
                (
                    Workspace("live", str(wrong_root), writable=True, exec_enabled=True),
                    Workspace("external", str(self.external), writable=True, exec_enabled=False, maintenance=True),
                ),
                (Collection("projects", str(self.collection), writable=True),),
            )
            self.registry_path.write_bytes(self.registry_codec.encode(bad))
            self.assertError(self.run_async(self.facade.call("workspace_catalog", "*", {})),
                             "REGISTRY_BASE_PROJECT_MISMATCH")
            evil = self.external.parent / "evil"
            evil.mkdir()
            bad2 = RegistrySnapshot(
                3,
                (
                    Workspace("live", str(self.live), writable=True, exec_enabled=True),
                    Workspace("evil", str(evil), writable=True, exec_enabled=True, maintenance=False),
                ),
                (Collection("projects", str(self.collection), writable=True),),
            )
            self.registry_path.write_bytes(self.registry_codec.encode(bad2))
            self.assertError(self.run_async(self.facade.call("workspace_catalog", "*", {})),
                             "REGISTRY_AUTHORITY_ESCALATION")
        finally:
            self.registry_path.write_bytes(original)

    def test_operator_registry_publish_blocks_unresolved_move_state(self):
        with self.assertRaises(Rejected) as rejected:
            validate_publish(self.registry_snapshot,
                             runtime_roots=[str(self.control)],
                             state_root=str(self.state),
                             config_paths=[str(self.config)],
                             unresolved_moves=[{"plan_id": "move-pending"}])
        self.assertEqual(rejected.exception.code, "UNRESOLVED_MOVE")

    def test_maintenance_begin_end_are_receipt_idempotent_and_freeze_mutations(self):
        begin_args = {"scopes": ["external", "projects"], "purpose": "project_move", "ttl_s": 300,
                      "request_id": "v060-test-lease-begin-001"}
        first = self.run_async(self.facade.call("maintenance_begin", "*", dict(begin_args)))
        replay = self.run_async(self.facade.call("maintenance_begin", "*", dict(begin_args)))
        self.assertTrue(first["ok"], first)
        self.assertTrue(replay["ok"], replay)
        self.assertTrue(replay.get("replayed"), replay)
        self.assertEqual(first["data"]["lease_id"], replay["data"]["lease_id"])
        conflict = dict(begin_args)
        conflict["purpose"] = "maintenance"
        self.assertError(self.run_async(self.facade.call("maintenance_begin", "*", conflict)),
                         "IDEMPOTENCY_CONFLICT")
        self.assertError(self.run_async(self.facade.call("file_write", "live", {
            "path": "blocked.txt", "content": "x", "expected_sha256": "absent",
            "request_id": "v060-test-blocked-write-001"})), "MAINTENANCE_ACTIVE")
        self.assertError(self.run_async(self.facade.call("task_create_file", "live", {
            "task": "task", "op": "op", "path": "blocked-task.txt", "content": "x"})),
            "MAINTENANCE_ACTIVE")
        lease = first["data"]["lease_id"]
        end_args = {"lease_id": lease, "scope": "projects", "request_id": "v060-test-lease-end-001"}
        ended = self.run_async(self.facade.call("maintenance_end", "*", dict(end_args)))
        ended_replay = self.run_async(self.facade.call("maintenance_end", "*", dict(end_args)))
        self.assertTrue(ended["ok"], ended)
        self.assertTrue(ended_replay.get("replayed"), ended_replay)
        self.assertEqual(ended["data"], ended_replay["data"])

    def test_missing_request_id_fails_closed(self):
        self.assertError(self.run_async(self.facade.call("maintenance_begin", "*", {
            "scopes": ["external", "projects"], "purpose": "project_move"})),
            "INVALID_REQUEST_ID")

    def test_signed_move_commits_and_apply_replays_without_second_rename(self):
        lease_result = self.run_async(self.facade.call("maintenance_begin", "*", {
            "scopes": ["external", "projects"], "purpose": "project_move", "ttl_s": 300,
            "request_id": "v060-test-move-lease-001"}))
        self.assertTrue(lease_result["ok"], lease_result)
        lease = lease_result["data"]["lease_id"]
        fake = FakeMoveAdapter(str(self.external))
        self.facade.v060.adapter = fake
        self.facade.v060.executor = MoveExecutor(fake, self.facade.v060.journal, self.facade.v060.leases)
        plan = self.run_async(self.facade.call("project_move_plan", "*", {
            "source_scope": "external", "collection": "projects", "destination_relative": "ImportedProject",
            "lease_id": lease, "ttl_s": 300}))
        self.assertTrue(plan["ok"], plan)
        apply_args = {"plan": plan["data"]["plan"], "lease_id": lease,
                      "acknowledged_warnings": [], "request_id": "v060-test-move-apply-001"}
        applied = self.run_async(self.facade.call("project_move_apply", "*", dict(apply_args)))
        replay = self.run_async(self.facade.call("project_move_apply", "*", dict(apply_args)))
        self.assertTrue(applied["ok"], applied)
        self.assertEqual(applied["data"]["state"], "COMMITTED")
        self.assertTrue(replay.get("replayed"), replay)
        self.assertEqual(applied["data"], replay["data"])
        self.assertEqual(fake.state, "destination")

    def test_prechecked_crash_freezes_scope_then_new_lease_can_reconcile_after_expiry(self):
        lease_result = self.run_async(self.facade.call("maintenance_begin", "*", {
            "scopes": ["external", "projects"], "purpose": "project_move", "ttl_s": 1,
            "request_id": "v060-test-crash-lease-001"}))
        self.assertTrue(lease_result["ok"], lease_result)
        lease = lease_result["data"]["lease_id"]
        fake = FakeMoveAdapter(str(self.external))
        self.facade.v060.adapter = fake
        self.facade.v060.executor = MoveExecutor(fake, self.facade.v060.journal, self.facade.v060.leases)
        plan_result = self.run_async(self.facade.call("project_move_plan", "*", {
            "source_scope": "external", "collection": "projects", "destination_relative": "CrashProject",
            "lease_id": lease, "ttl_s": 300}))
        self.assertTrue(plan_result["ok"], plan_result)
        # Lease verification must remain read-only; otherwise an early unresolved-
        # move rejection can strand sqlite inside an implicit transaction and make
        # the later recovery lease fail with BEGIN-within-transaction.
        self.assertFalse(self.facade.v060.leases.db.in_transaction)
        plan = self.facade.v060.plan_codec.decode(plan_result["data"]["plan"])
        self.facade.v060.journal.begin(plan)
        self.facade.v060.journal.transition(plan.plan_id, "PLANNED", "PRECHECKED", {"synthetic_crash": True})
        self.assertError(self.run_async(self.facade.call("file_write", "live", {
            "path": "blocked-unresolved.txt", "content": "x", "expected_sha256": "absent",
            "request_id": "v060-test-unresolved-write-001"})), "UNRESOLVED_MOVE")
        time.sleep(1.1)
        maintenance = self.run_async(self.facade.call("maintenance_begin", "*", {
            "scopes": ["external", "projects"], "purpose": "maintenance", "ttl_s": 300,
            "request_id": "v060-test-wrong-recovery-purpose-001"}))
        self.assertError(maintenance, "UNRESOLVED_MOVE")
        recovery = self.run_async(self.facade.call("maintenance_begin", "*", {
            "scopes": ["external", "projects"], "purpose": "project_move", "ttl_s": 300,
            "request_id": "v060-test-recovery-lease-001"}))
        self.assertTrue(recovery["ok"], recovery)
        recovery_lease = recovery["data"]["lease_id"]
        self.assertError(self.run_async(self.facade.call("project_move_plan", "*", {
            "source_scope": "external", "collection": "projects", "destination_relative": "AnotherProject",
            "lease_id": recovery_lease, "ttl_s": 300})), "UNRESOLVED_MOVE")
        self.assertError(self.run_async(self.facade.call("maintenance_end", "*", {
            "lease_id": recovery_lease, "scope": "projects", "request_id": "v060-test-early-recovery-end-001"})),
            "LEASE_HAS_UNRESOLVED_MOVE")
        reconciled = self.run_async(self.facade.call("project_move_reconcile", "*", {
            "plan_id": plan.plan_id, "lease_id": recovery_lease,
            "request_id": "v060-test-reconcile-001"}))
        self.assertTrue(reconciled["ok"], reconciled)
        self.assertEqual(reconciled["data"]["state"], "ABORTED")
        self.assertFalse(reconciled["data"]["rename_observed"])
        ended = self.run_async(self.facade.call("maintenance_end", "*", {
            "lease_id": recovery_lease, "scope": "projects", "request_id": "v060-test-recovery-end-002"}))
        self.assertTrue(ended["ok"], ended)

    def test_cleanup_uses_verified_lease_without_relaxing_context_binding(self):
        base_context = self.facade.next.context("live")
        self.assertNotEqual(base_context.binding, replace(base_context, exclusive_workspace=True).binding)
        begun = self.run_async(self.facade.call("task_begin", "live", {"task": "cleanup-task", "paths": ["owned.txt"]}))
        self.assertTrue(begun["ok"], begun)
        created = self.run_async(self.facade.call("task_create_file", "live", {
            "task": "cleanup-task", "op": "create-owned", "path": "owned.txt", "content": "owned"}))
        self.assertTrue(created["ok"], created)
        lease_result = self.run_async(self.facade.call("maintenance_begin", "*", {
            "scopes": ["live"], "purpose": "task_cleanup", "ttl_s": 300,
            "request_id": "v060-test-cleanup-lease-001"}))
        self.assertTrue(lease_result["ok"], lease_result)
        lease = lease_result["data"]["lease_id"]
        plan = self.run_async(self.facade.call("task_cleanup_plan", "live", {
            "task": "cleanup-task", "lease_id": lease, "max_files": 16}))
        self.assertTrue(plan["ok"], plan)
        with self.assertRaises(NextRejected) as rejected:
            self.run_async(self.facade.next.tasks.cleanup_apply(base_context, plan["data"]["plan"]))
        self.assertEqual(rejected.exception.code, "EXCLUSIVE_WORKSPACE_REQUIRED")
        args = {"plan": plan["data"]["plan"], "lease_id": lease,
                "request_id": "v060-test-cleanup-apply-001"}
        applied = self.run_async(self.facade.call("task_cleanup_apply", "live", dict(args)))
        self.assertTrue(applied["ok"], applied)
        self.assertFalse((self.live / "owned.txt").exists())
        replay = self.run_async(self.facade.call("task_cleanup_apply", "live", dict(args)))
        self.assertTrue(replay.get("replayed"), replay)
        self.assertEqual(applied["data"], replay["data"])
        ended = self.run_async(self.facade.call("maintenance_end", "*", {
            "lease_id": lease, "scope": "live", "request_id": "v060-test-cleanup-end-001"}))
        self.assertTrue(ended["ok"], ended)

    def test_collection_source_cannot_move_live_workspace_root_or_parent(self):
        lease = self.run_async(self.facade.call("maintenance_begin", "*", {
            "scopes": ["projects"], "purpose": "project_move", "ttl_s": 300,
            "request_id": "v060-test-live-root-lease-001"}))
        self.assertTrue(lease["ok"], lease)
        lease_id = lease["data"]["lease_id"]
        direct = self.run_async(self.facade.call("project_move_plan", "*", {
            "source_scope": "projects", "source_relative": "live", "collection": "projects",
            "destination_relative": "moved-live", "lease_id": lease_id, "ttl_s": 300}))
        self.assertError(direct, "LIVE_WORKSPACE_MOVE_REQUIRES_OPERATOR_RECONFIG")


if __name__ == "__main__":
    unittest.main()
