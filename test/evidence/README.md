# Test evidence

This directory preserves historical implementation and runtime observations for
maintainers reviewing regressions and security behavior. Records under `history/`
are snapshots, not installation instructions or certification of current builds.
Earlier failures may have been resolved by subsequent entries.

The machine-readable acceptance checklist is
[`../e2e/release/acceptance.json`](../e2e/release/acceptance.json). Its status is
assessed by `test/e2e/matrix/release_acceptance.py`; authored records do not
substitute for independently reviewed runtime evidence.

For installation and configuration, use the [project README](../../README.md)
and [Helm chart guide](../../charts/ratatoskr/README.md). For running tests, see
[CONTRIBUTING.md](../../CONTRIBUTING.md).
