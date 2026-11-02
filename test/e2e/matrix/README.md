# Compatibility inventory and selective runners

`coverage.json` declares five axes (CNI, mesh, driver, datapath, encryption),
25 traffic scenarios and six separate API scenarios. `applicability.py` is a
pure, non-certifying contract: 96 identities per fake/live mode; eBPF+WireGuard
requires *refusal* evidence, not traffic or a waiver. The other cells are
candidates, **not** declared supported. `run.py` defaults to a static JSON and
Markdown inventory outside the checkout, without cluster or credential access.
The checked-in matrix executes only two direct-config flannel/no-mesh/init/none
cells. Separately gated agent/WireGuard/HA/Calico fixtures do **not** silently
promote matrix cells. Missing or skipped evidence leaves status **INCOMPLETE**
and exit **4**; failure returns 1, invalid/unauthorized invocation returns 2.
A passing selected subset never makes the entire matrix green.

Offline validation:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test/e2e/matrix/static-check.py
PYTHONDONTWRITEBYTECODE=1 python3 test/e2e/matrix/admission-static-check.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/matrix -p 'test_*.py'
```

Explicit execution requires an operator-approved existing release, context and
images plus `RATATOSKR_E2E_FINAL_GATE=1` and `--execute`. The fake/live wrappers
forward options to `run.py`: repeated `--cell=<id>`, `--report-dir=<new path
outside checkout>`, `--no-import`, `--no-build`, `--skip`,
`--api-admission-only` or `--with-api-admission`. Image/build provenance is a
separate approval; absence of a live OpenVPN profile is SKIPPED, not success.
Runs are serialized under a process lock; a failed cell stops the sequence.
`hack/m1-proof.sh` uses the established k3d lifecycle for the two direct-config
cells, verifies prerequisites, and cleans up private input and owned resources.
Never paste VPN profiles, Secret data, token-bearing URLs, raw API errors or
packet payloads into reports. SIGKILL/API outage requires operator orphan
inspection; cleanup failure cannot count as a pass.

`admission.py` tests the release/webhook/API path without a healthy VPN. It
requires approved immutable controller/webhook runtime image IDs. The Gateway
uses a deliberately absent Secret; workload CREATE and policy are server-dry-
run except one inert scheduling-gated UPDATE-validation Pod. That Pod must have
an exact never-matching nodeSelector, no execution/PodIP, UID-pinned metadata-
only dry-run updates and verified deletion before namespace cleanup. See
`admission-report.md` for the independent API-only contract; its result is
recorded in `apiAdmission`, **not** as traffic/CNI/mesh coverage.

The inventory's named scenario and API identities are stable review boundaries;
legacy inner checkpoint IDs such as `m8-*` remain protocol identifiers. An
untested CNI/mesh combination, provider request, PMTU case or kernel runtime
must be reported as missing evidence, never inferred from another cell.
