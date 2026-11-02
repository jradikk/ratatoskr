# Controller-created synthetic OpenVPN fixture

This fixture builds a **local, real OpenVPN server**, not the direct-config HTTP
fake. `server/` and `witness/` are separate images; `app/` is a restricted
selected workload helper. `prepare.py` generates a one-day private CA and
separate server/client/witness identities only inside a mode-0700 temporary
directory owned by `lifecycle.py`. Secrets contain `client.ovpn` and are confined
to disposable namespaces. No key, profile, raw API response, Pod log or packet
payload belongs in git or a report. Parent/operator builds and imports approved
local images, verifies immutable `EXPECTED_<COMPONENT>_IMAGE_ID` values, and
preflights an existing three-node flannel/no-mesh release with operator-only
`dns.upstreamProbeURL=http://10.88.0.1:8080/exit`. These scripts never install
or roll that release.

`run.py` defaults to read-only preflight. It requires `--execute`,
`RATATOSKR_E2E_FINAL_GATE=1`, and the corresponding explicitly gated mode:

- `--allow-partial-vpn-smoke --execute-partial-gateway` with
  `RATATOSKR_E2E_PARTIAL_VPN_SMOKE=1`: controller-owned Gateway graph, real VPN
  session, healthy restricted one-shot app marker and direct API/DNS path.
- `--allow-partial-vpn-smoke --execute-agent-outage` additionally requires
  `RATATOSKR_E2E_AGENT_OUTAGE=1`: long-lived selected workload, independent
  cert-bound witness, probe-only ConfigMap CAS outage/restoration, Gateway
  endpoint withdrawal and recovered marker. A timeout alone is **not** fail-
  close evidence: a UID/CRI/netns-bound, header-only capture requires an owned
  unreachable fallback, marked RPDB selector, direct-API SYN positive control
  and zero selected-destination SYN. Root helpers use fixed args and fail closed
  if host tools/permissions are unavailable; no workload capability changes.
- `--allow-partial-vpn-smoke --execute-init-smoke --execute-init-traffic`
  additionally requires `RATATOSKR_E2E_INIT_SMOKE=1` and
  `RATATOSKR_E2E_INIT_TRAFFIC=1`. The operator must independently roll and then
  restore the init-driver release. Its disposable apps namespace is privileged
  for the NET_ADMIN init; this is **not** PSA-restricted agent coverage.

Every mutation uses fresh owned namespaces, exact CREATE-return UIDs, bounded
per-call/deadline checks and verified cleanup. A lost CREATE response, changed
owner UID, unexpected runtime image or uncertain cleanup blocks. SIGKILL/API
outage requires operator remediation. Even a completed fixture returns **4 /
INCOMPLETE**; it does not mark matrix `coverage.json` or prove other CNI/mesh,
provider, WireGuard or HA modes. `test/e2e/advanced/` owns separate gated modes.

`environment.py` pins known flannel/Calico context/node identities.
`calico_healthy.py` and `calico_outage.py` are separately gated existing-Calico
subsets; neither provisions Calico or substitutes for full matrix coverage.
Offline checks only:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test/e2e/matrix/synthetic/static-check.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/matrix/synthetic -p 'test_*.py'
sh -n test/e2e/matrix/synthetic/server/start.sh
```
