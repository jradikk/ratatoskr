# Release checks

Releases are built and published by `.github/workflows/release.yaml` from a
reviewed version tag. Its reusable CI validation must succeed before publication;
the workflow builds multi-platform component/plugin images, matching binaries
and a Helm chart. Repository-local release builders and the permanently blocked
staging command have been removed. Do not interpret a locally generated archive
or a partial e2e result as approval to tag or publish. Release credentials belong
only in GitHub Actions secrets; never paste them into fixture reports.

`artifact_manifest.py` verifies a narrowly defined, already-reviewed manifest
and bounded regular files by SHA-256. `archive_contents.py` checks an already-open
uncompressed ustar OCI archive with a strict two-platform/index/layer policy.
Neither validates trusted provenance, a signature, publication authorization or
full compatibility. Unsupported formats and extra attestations fail closed;
these validators do not extract or execute images. `test_github_workflow.py`
checks the checked-in Actions workflow without publishing.

Run local offline checks (no registry, cluster, or artifact build):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/release -p 'test_*.py'
```

Acceptance remains independent of packaging: skipped or missing scenarios are
**INCOMPLETE**, not waived. Publishing is never authorized merely by tests in
this directory.
