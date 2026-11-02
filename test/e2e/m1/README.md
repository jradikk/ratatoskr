# Direct-config fake and provider traffic subset

`hack/m1-proof.sh` wraps `test/e2e/m1/run.sh` with a total deadline and bounded
cleanup. This is a direct-config **subset**, not controller-created Gateway
selection or the compatibility matrix. The matrix's two implemented cells use
flannel/no mesh with client and gateway on different k3d agents; creation goes
through the existing `hack/k3d-up.sh` resource/module preflight. A reused
cluster survives cleanup; one created by this run is removed. No VM provisioning
or registry push is done by this harness.

After operator authorization and local image import, use `--mode=fake` or
`--mode=live`, optional `--datapath=iproute|ebpf`, `--extended`, `--no-import`
and `--report-dir=<new outside-checkout directory>`. Extended/eBPF paths require
`RATATOSKR_E2E_FINAL_GATE=1`. Reports list actual checkpoints and distinguish
passed, failed, skipped and inconclusive; subset status never upgrades missing
matrix cells. `--skip` is an explicit skip, not proof.

The fake endpoint verifies selected tunnel path, ordinary DNS/API/ClusterIP
preservation and controlled outage/recovery. `--extended` also checks CIDR/port
selection, large payload integrity, measured MTU/MSS and private health state.
The provider path requires `RATATOSKR_E2E_OVPN` as an absolute profile path
outside the checkout; optional `_AUTH`, `_CA`, `_CERT`, `_KEY` paths (same prefix),
`IPINFO_TOKEN` and `RATATOSKR_E2E_EXPECT_COUNTRY` must be supplied privately.
Missing profile skips before cluster access. `bundle.py` bounds and sanitizes
explicit file inputs and writes private mode-0600 copies. Never put credentials
or provider output into git, CLI argv or reports. External HTTP failures,
including persistent 429, are inconclusive rather than a tunnel pass.

Namespace/Secret/private-file cleanup is required on ordinary exit and signals;
SIGKILL or API failure needs operator orphan inspection. This harness does not
relax workload capability, TUN or provider-probe requirements. Offline checks:

```sh
for s in hack/m1-proof.sh test/e2e/m1/run.sh test/e2e/ci/run.sh test/e2e/live/run.sh; do bash -n "$s"; done
sh -n test/e2e/m1/ipinfo.sh
PYTHONDONTWRITEBYTECODE=1 python3 test/e2e/m1/static-check.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/m1 -p 'test_*.py'
```
