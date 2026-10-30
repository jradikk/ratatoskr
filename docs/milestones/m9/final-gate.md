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
- The first guarded fake flannel/no-mesh/init/iproute subset **FAILED**. A
  bounded kube-proxy VIP convergence wait (`32f660e`) resolved baseline timing;
  the steered HTTP echo still timed out. Header-only capture and kernel
  `skb:kfree_skb` trace showed return GENEVE packets left the gateway pod with
  outer TTL **zero**; forwarding discarded them. `a6a1c4d` explicitly sets
  LWT GENEVE return TTL 64. With the rebuilt/imported gateway image, the
  direct-config M1 fake suite **PASSED**: cluster-path preservation, fake
  tunneled echo, upstream fail-close and recovery. The extended fake matrix
  then passed baseline, gateway readiness, client programming, MTU, private
  metric, tunneled echo and **4.5 MiB payload integrity**, but **FAILED** at
  selective CIDR/TCP-port policy. Thus the full matrix remains failed.
- The original selective fixture selected the remote PodIP, which is also the
  IPIP outer peer. That SYN-ACK reaches client `rtk0` but is discarded under
  reverse-path validation. The fixture was corrected to keep pod-CIDR
  exclusions and select the distinct IPIP *inner* HTTP address
  `198.19.0.1/32`. The corrected selector still **FAILED** on selected TCP
  return, exposing a separate production constraint detailed below. Wrong-port,
  wrong-CIDR and exclude negatives use tunnel TX counters plus direct PodIP
  probes rather than claiming the inner-only address is ordinarily reachable.

## Evidence and current hard blocker

The original cross-node loss was diagnosed, not merely worked around. The
kernel drop trace identified `SKB_DROP_REASON_IP_INHDR` in `ip_forward` for
`gatewayPodIP → clientPodIP` with TTL=0. An isolated regression test had passed
because it did not include a forwarding hop between the gateway and client.
The return LWT tunnel now sets TTL=64, with attribute and privileged regression
checks. A full-tunnel fake request and 4.5 MiB payload traversed flannel k3d
after rebuilding the gateway image.

**Selective port-qualified return remains blocked.** In a three-namespace
reproduction, outbound nft route/output marks a TCP request for the gateway;
its SYN-ACK returns unmarked on `rtk0`. In a disposable-netns kernel trace
with effective loose `rp_filter=2` and default `src_valid_mark=0`, that
`198.19.0.1 → clientPodIP` SYN-ACK had skb mark 0; `fib_validate_source`
returned `-16` and `skb:kfree_skb` reported `SKB_DROP_REASON_IP_RPFILTER` on
`rtk0` for seven packets. The reverse FIB cannot use the outbound
port-qualified mark, so TCP never ACKs. Marking
incoming `rtk0` packets and setting `src_valid_mark=1` made an isolated test
pass *without disabling rp_filter*, but a production init Pod has read-only
`/proc/sys` even with NET_ADMIN: trying to set `src_valid_mark` failed with
`read-only file system` and blocked **all** client programming. That attempted
change (`e698c2b`) was reverted (`2fcb8fe`), and the rebuilt NET_ADMIN-only
client image restored the direct full-tunnel fake pass. An `iif rtk0` RPDB
rule did not rescue reverse lookup; a broad unmarked destination rule did,
but improperly steered all ports, violating selective policy. A narrow
`RTN_THROW` experiment preserved the ordinary route but did not rescue the
reply either. No SYS_ADMIN,
privileged init, global rp_filter disable, broad routing rule or host sysctl
workaround was introduced. A reviewed alternative architecture/runtime
permission model is needed; **M8 selective traffic still fails**.

**The independent eBPF fake subset also FAILED** at its first steered echo.
Its client init, baseline cluster paths, gateway readiness, MTU and private
metric checks passed, but the fake tunneled request timed out. A bounded
isolated two-netns eBPF-client → iproute-gateway reproduction showed client
external `gnv0` transmit drops with no gateway `gnv0` receive packets or TC
flower hits; the client underlay route and BPF helper return counters were
healthy. A `geneve_xmit` probe observed a transmit attempt without
`DST_METADATA` tunnel information (`dst.flags=0`, mode/remote zero), so the
collect_md GENEVE device discarded it before emitting outer UDP. Linux 5.10
source confirms that the tunnel-key helper installs skb metadata and the
GENEVE driver requires it, but **does not prove where it is lost** between the
helpers and transmit on this kernel. Removing the TLV helper and MAC rewrite
or trying clone redirect in disposable diagnostic builds did not repair this.
Those diagnostic changes were discarded; there is **no verified production
fix**, and the earlier isolated `gnv0` counter check
was not proof of end-to-end gateway ingress. eBPF may not be represented as a
passing second datapath.

A follow-up **disposable-netns tc-ingress experiment** on kernel 7.0 used the
same BPF program and successfully emitted outer UDP/6081 with expected VNI
and identity TLV; the gateway received it. That contrast narrows the problem
to the current tc-egress attachment path, but is **not a production fix**:
locally generated Pod traffic does not traverse the proposed eth0 ingress
hook. Any change needs a reviewed routing/attachment topology that preserves
local OUTPUT policy and fail-close, plus real multi-pod and Linux 5.10 packet
evidence. No scratch implementation was retained.

The current M8 matrix still implements only two direct-config flannel subsets;
Cilium, Cilium-WireGuard, Calico, mesh, admission/CRD, restricted agent,
WireGuard registration, HA failover and full observability scenarios remain
**SKIPPED / not covered**. Linux 5.10 actual runtime was not tested (this host
runs kernel 7.0). eBPF + WireGuard is explicitly unsupported, not a pending
positive cell. The exact requested live steps 1–13 were unavailable and have
not been invented. A working live VPN profile and an approved exact checklist
are prerequisites before live acceptance.

## Publication safety gate

The original `.github/workflows/ci.yaml` pushed and signed component images
on any `v*` tag after local lint/test jobs, even though the full traffic and
compatibility gates were absent. CI has now been made build-only (`push: false`,
no registry login, package-write or signing identity). Tags no longer trigger
an automatic publication. A future **separately reviewed, explicitly gated**
release workflow is required before any release tag can publish images, chart,
SBOM or signature. This is a safety guard, not completion of M9.

## Release blockers / next gate

1. Resolve selective port-qualified return with a verified fail-closed design
   that operates in restricted init Pods without weakening reverse-path
   validation. Separately repair eBPF metadata delivery to collect_md GENEVE
   and verify actual gateway ingress, not only BPF helper success. Rerun the
   extended fake subset, policy/metadata/DNS and both datapaths. The basic
   iproute full-tunnel return TTL problem is fixed and its direct fake suite
   passed, but it does not imply selective/eBPF/HA acceptance.
2. Implement and run the missing CNI/mesh/agent/WireGuard/HA compatibility
   scenarios under the existing mandatory resource preflight. Skipped cells
   must never be represented as passed.
3. Obtain live VPN input and the exact requested live checklist; only then run
   the live tests, validate exit IP/country without exposing credentials, and
   record any unavailable external checks as inconclusive.
4. Re-run full CI (including multiarch, artifact provenance/signing policy)
   against the *final* release commit and review security/metrics limitations.
   Until then, do not publish or sign a production release.
