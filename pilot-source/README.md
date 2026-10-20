# LocalControl bounded ownership pilot (approval pending)

This directory is a selected-source pilot, not a complete LocalControl distribution.
The ten localcontrol/*.py files are exact bytes from commit e071dd2d099577e3ded081f1ffefd7c2bf22e3a8,
tree 2afd017548b4ace8e2a7c67adebb6a5a9baeaf10. No server, MCP transport, provider adapter,
production configuration, database, audit log, credentials, protected backup or Git history is included.

The coordinator uses only the Python standard library and the hosted Windows .NET Framework compiler.
It does not install pytest, mcp, pywin32 or any other package. This packet does not run the previously
qualified 114 synthetic tests, and it cannot replace full release qualification.

Four fail-closed native cases:

1. N01: real Policy/Store/JobManager admission, zero-capability AppContainer, positive allowed-file read,
   protected-file read/write error 5, durable terminal record, fresh Store/Manager reopen, unchanged audit count.
2. N02: real worker and descendant in the exact candidate-owned Job Object, stop before natural expiry,
   descendant exit, durable stopped receipt and fresh reopen without replay.
3. N03: one intentionally injected SQLite owned-transition failure. A real suspended process exists and
   starting ownership must still be registered at the failing commit. The command must not execute;
   cleanup must produce a durable start_failed receipt and survive a fresh reopen.
4. N04: intentional rejection through the documented pre_resume_check callback after real native sandbox
   verification. Custody must retain the suspended process, prove process exit and Job zero, and close checked handles.

Native APIs, tokens, Job Objects, process creation, access denial, SQLite and instance leases are real.
Only the explicitly listed fault injections are synthetic. No restart attestor, scope override, replay,
PID-based termination, service, scheduled task or host installation is used.

The workflow is manual-only, permissions {}, standard windows-2025, one job, timeout five minutes,
coordinator timeout 180 seconds. It fetches only the exact allowlist at its immutable workflow commit,
checks SHA-256, strips the coordinator environment to explicit Windows/Python essentials, and
creates all mutable state beneath a new C:\\LocalControlOwnershipPilot-<GUID> directory in the disposable runner.
Its AppContainer profiles are unique LocalControl.Pilot.<GUID> profiles with zero capabilities.
ACL changes are confined to this new fixture and profile cleanup is required. The hosted VM already
uses an administrator coordinator account; the workflow requests no elevation and changes no UAC setting.

Runner-only test policy: one active job, one queued job, 20-second worker lifetime, at most four
processes and 256 MiB per job, 1 GiB free-memory and 1 GiB free-disk admission floors. Those values
exist only in the disposable fixture Policy object; no installed/shared/production threshold changes.
Workers have no network capability. The hosted coordinator retains the normal hosted runner network
for pinned source fetches; this is not an offline VM or an independent protected custody environment.

The workflow uploads no artifacts or caches and uses no checkout or third-party action. Only bounded
synthetic receipts and source/runtime identities appear in logs. Failure or unavailable telemetry blocks
the pilot; no security fallback or host execution is allowed for the worker.

PASS_BOUNDED_PILOT_ONLY is evidence for these four cases on this exact source and runner image.
It is not production authorization, full restart/crash recovery qualification, independent backup custody,
a WW2 root-cause finding or approval for the experimental v1.2 route pilot.

Publishing this directory discloses the selected LocalControl source publicly and durably in repository
history. Explicit owner approval of the external allowlist manifest is required before publication.

