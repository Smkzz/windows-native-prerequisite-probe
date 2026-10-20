# Windows native prerequisite probe

Prepared locally only. No repository has been created and no workflow has run.

This proposed public repository contains only this README and an original inline GitHub Actions workflow. It contains no application source, deployed settings, production credentials, state databases, runtime bundles or private evidence.

After explicit publication/dispatch approval, run the workflow manually on the standard windows-2025 runner. It has a five-minute timeout, no checkout/action dependencies, no secrets references, empty token permissions, no artifact uploads, caches, deployment steps or automatic triggers. Output is small JSON in the job log and summary. It creates and cleans one temporary file/directory, one empty Job Object, and one unique AppContainer profile only on the ephemeral hosted runner. It never launches an AppContainer process or application candidate. Cleanup failure fails the probe.

The probe checks C: metadata and temporary write/read plus basic Windows API capability. A successful result is explicitly NOT native application qualification. The runner has network access to GitHub; it does not meet a whole-VM no-NIC rule. Before any later candidate run, its hosted-runner isolation contract and authority must be approved separately and genuine denial/ownership tests must pass.

Standard hosted runners in public repositories are currently free according to GitHub. Use no larger runners, cache/artifact storage or secrets. Do not publish private application code to obtain free execution. Private candidate testing would require verified included quota and a genuine no-overage control, or another approved free target; neither is verified here.

No account billing/settings change, repository publication or workflow dispatch is authorized by this file.

