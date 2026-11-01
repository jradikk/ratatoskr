# Release preparation guard — intentionally blocked

`hack/prepare-release.py` is an **offline, no-artifact readiness guard**, not a
release or staging implementation. Default invocation and `--execute` currently
return `BLOCKED` / exit 4. It never creates an output directory, invokes Helm,
Docker, a registry, a Kubernetes API, or a signing command.

The guard first reads the checked-in M9 acceptance ledger and calls the
independent `test/e2e/matrix/release_acceptance.py:assess` with exactly the
25 scenario IDs from `coverage.json` plus four fixed release gates. Any OPEN,
PARTIAL, missing, duplicate, empty-evidence, remaining-gap or unknown gate
blocks **before an artifact path is inspected or anything is written**. At
present the ledger is incomplete, so nothing can be staged. If every gate is
later independently reviewed as PASSED, execution still requires explicit
`--execute`, an exact clean current 40-character source SHA, a canonical
reviewed version (`X.Y.Z` or `X.Y.Z-rc.N`), and an absolute `--output` path.
Even then it unconditionally blocks because artifact verification is not
implemented. The output path is never created or read.

A future separately reviewed implementation needs an exact artifact allowlist,
independent provenance/manifest verification, immutable digest bindings,
secret/symlink/path safety, collision-safe private staging, and a release
security review. Neither this guard nor manually editing gate statuses proves
a build/release is trustworthy. Do not supply credentials or live provider
input to this tool. No images, chart packages, version tags, SBOMs, signatures,
PRs or publication are produced by it.

Local, cluster-free tests: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest
discover -s test/e2e/release -p 'test_*.py'`.
