# External Linux 5.10 component-only platform gate

**Default is inert.** This standalone runner is not called by CI, `make e2e`,
`make e2e-live`, chart release or the M8 coverage matrix. It neither creates a
cluster nor provisions a VM, installs packages, builds/publishes images, reads
credentials, changes a release, or claims packet/CNI acceptance. The operator
provides an already-approved Linux 5.10.x host (`amd64`/`arm64`), matching clean
source checkout and preinstalled Go, make, sudo plus privileged-test dependencies.

The operator alone may choose to run, from that checkout:

```sh
RATATOSKR_E2E_FINAL_GATE=1 RATATOSKR_E2E_PLATFORM_510=1 \
  python3 test/e2e/platform/runner.py --execute --source-sha <40-character-current-git-HEAD>
```

The full SHA is mandatory and must match current `git rev-parse HEAD`; any
tracked or untracked checkout change blocks before privileged tests. A host not
actually reporting `uname` Linux `5.10.<patch>` (optional distro suffix), or
not reporting `x86_64`/`aarch64`, blocks; a newer kernel does **not** establish
5.10 compatibility. The preinstalled native `go version` must match its
architecture. Only then does the runner call the existing
`make test-privileged` target once under a 900-second bound; sudo is the existing
Makefile contract, not new authority. stdout/stderr of tools and tests are
suppressed. Reports contain only fixed outcome categories and public exact SHA,
kernel release, architecture and compiler version. Errors and timeouts block.

Even successful component tests yield **INCOMPLETE / exit 4**: gateway images,
CNI/mesh and packet-correlated traffic on Linux 5.10 remain separate final-gate
acceptance work. Do not mark `test/e2e/matrix/coverage.json` or the release ledger
PASSED from this component tier. No release artifact or PR is created.

Offline authoring checks (do not invoke the executable tier):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/platform -p 'test_*.py'
```
