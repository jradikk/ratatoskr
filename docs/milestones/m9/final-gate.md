# M9 release gate — blocked (October 30, 2026)

**Release status: NOT READY.** This is an evidence report, not a release announcement.
No version tag, published chart/image, registry push, signature or pull request was
created. The checked-in chart intentionally remains `0.0.0-dev` / `dev`.

## Checks completed at the final project gate

- Local CI-equivalent checks passed on the final code before the traffic attempt:
  `go mod tidy` produced no changes; gofmt, `make test` (race), `make lint`
  (0 issues), `make vet`, `make build`, `make test-privileged`, M8 static
  checks and chart packaging/static checks passed. A later isolated
  bidirectional gateway regression test also passed under
  `sudo go test -tags privileged ./pkg/datapath/iproute`.
- Five component images, the OpenVPN plugin image and refreshed local fake
  upstream/client-tools test images were built for the final gate. The first
  client-tools build failed because its Dockerfile omitted the new local API
  package; `30be33d` fixed the build, which then passed. No image was pushed.
- The live VPN input `RATATOSKR_E2E_OVPN` was **unset**. The guarded final
  live matrix returned exit 4 (`SKIPPED_MISSING_LIVE_PROFILE`, incomplete),
  with no provider Secret, token, external request or live VPN tunnel created.
  **This is a skip, not a pass.** Never print or copy live inputs into evidence.
- The guarded fake flannel/no-mesh/init/iproute subset was executed at the
  final gate and **FAILED**, not passed. The first attempt encountered a
  kube-proxy Service VIP convergence race during baseline startup; `32f660e`
  added a bounded 45-second wait, after which baseline, gateway readiness,
  client programming, cluster-path preservation, measured MTU and private
  health metric checks passed. The steered HTTP echo to fake upstream
  `198.19.0.1:8080` then timed out. The matrix exited 1 and safely deleted
  its ephemeral namespace; other 95 cells per mode were not executed.

## Evidence and unresolved root cause

Disposable k3d diagnostics (no credentials, no raw application payload stored)
showed client `rtk0` transmit packets but zero receive packets. Gateway `gnv0`
received GENEVE from the client's PodIP; its source/VNI flower allowed selected
packets. The gateway's nft forward accepted requests from `gnv0` to `upstream0`
and established replies from `upstream0` toward `gnv0`, with default-drop count
zero. Gateway `gnv0` TX-drop counter increased; a header-only node capture saw
a return GENEVE UDP packet on the gateway pod veth and node `cni0`, but no
return GENEVE packet at the client node capture point. The return's UDP source
port differs from the request's source port by normal GENEVE behavior; this
alone does not prove a conntrack drop. Node route and flannel neighbor were
present. **The exact loss point is not proven.** A three-namespace cross-subnet
TCP/UDP regression test (`b8553e1`) passes with gateway forwarding/SNAT and
return encapsulation; it does not resolve the k3d failure. No speculative
production route/firewall relaxation was applied.

The current M8 matrix still implements only two direct-config flannel subsets;
Cilium, Cilium-WireGuard, Calico, mesh, admission/CRD, restricted agent,
WireGuard registration, HA failover and full observability scenarios remain
**SKIPPED / not covered**. Linux 5.10 actual runtime was not tested (this host
runs kernel 7.0). eBPF + WireGuard is explicitly unsupported, not a pending
positive cell. The exact requested live steps 1–13 were unavailable and have
not been invented. A working live VPN profile and an approved exact checklist
are prerequisites before live acceptance.

## Release blockers / next gate

1. Identify and fix the flannel cross-node GENEVE return loss without weakening
   fail-close, then rerun the fake traffic subset and verify packet-level echo,
   payload, policy, loss/recovery, DNS/metadata and both datapaths.
2. Implement and run the missing CNI/mesh/agent/WireGuard/HA compatibility
   scenarios under the existing mandatory resource preflight. Skipped cells
   must never be represented as passed.
3. Obtain live VPN input and the exact requested live checklist; only then run
   the live tests, validate exit IP/country without exposing credentials, and
   record any unavailable external checks as inconclusive.
4. Re-run full CI (including multiarch, artifact provenance/signing policy)
   against the *final* release commit and review security/metrics limitations.
   Until then, do not publish or sign a production release.
