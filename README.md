# Generic Windows native boundary probe

A manual-only, five-minute probe on the free standard GitHub-hosted windows-2025 runner. No application source, private configuration, credentials, third-party actions, checkout, cache or artifact uploads are included. Token permissions are empty (GitHub still supplies metadata-read permission).

The original prerequisite run succeeded. This extension performs real Windows calls:

- Launch a new helper with zero-capability AppContainer token, suspended first, assign its exact Job Object, verify the token/SID before resume, and verify the same token inside the child. A read-allowed synthetic file must succeed. A protected synthetic file must return Win32 ERROR_ACCESS_DENIED (5) for both read and write. The unrestricted coordinator must be able to access that same file. Only newly created fixture ACLs are adjusted.
- Put a child and its descendant into one kill-on-close Job Object. Verify exact membership using handles, prove both survive closing a nonfinal job handle, then prove both exit after the last handle closes.
- Let a synthetic owner create a separate kill-on-close job and child. Borrow a query handle only to verify exact membership, close that borrowed handle, terminate only the owned synthetic owner, and prove its child exits.

Only fixed helper modes execute. Children have a minimal environment, no inherited handles and no inherited GitHub tokens. Holding processes self-expire after 30 seconds. The coordinator uses bounded waits and cleans only exact owned fixture handles, profile and directory. The outer CI job has a five-minute timeout. Failed execution or cleanup fails the job; no success is inferred from mere process creation.

These are generic environment tests, not application qualification. They do not prove application ownership persistence, request replay, database atomicity, full crash recovery, production rollback, or production OS parity. Network-denial testing is not included, and the hosted runner retains network access to GitHub. No application candidate or native pilot runs.

The public standard runner class is documented as free. Larger runners, paid services, billing changes, repository secrets and private source publication are outside scope.

