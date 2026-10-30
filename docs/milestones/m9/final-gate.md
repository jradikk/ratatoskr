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
metric checks passed, but the fake tunneled request timed out. An early
isolated two-netns attempt observed client `gnv0` transmit drops and no
gateway GENEVE reception. An uncorrelated `geneve_xmit` probe saw an skb with
`dst.flags=0`; **it was not proven to be the selected IPv4 packet**, and may
have been ARP/IPv6 noise. The initial conclusion that production tc egress
intrinsically lost metadata was incorrect.

A later fresh disposable-netns test loaded the **unchanged production bpf2go
program and maps** (tag `dd6261f9ac61fee5`), emitted outer UDP/6081 with VNI
7 and identity TLV, and the actual gateway `gnv0`/source-and-VNI flower
accepted the selected packet. Selected-packet probes observed `DST_METADATA`
at `geneve_xmit`. A separate disposable **flannel Pod** reproduction with the
same program tag likewise saw gateway flower acceptance and GENEVE RX, return
outer UDP delivered to the client node, and client `gnv0` RX, yet the client
socket timed out. Thus the **forward path works in the reproduced case**.

A subsequent healthy **three-netns production-component fixture** generated
actual fake-upstream TCP SYN/SYN-ACK replies using unchanged binaries. On the
client's `gnv0`, three packet-correlated `198.19.0.1 → clientPodIP` SYN-ACK
skbs had mark 0; `fib_validate_source` returned `-16`, followed by
`skb:kfree_skb` **reason 16 (`SKB_DROP_REASON_IP_RPFILTER`) for the same skb
pointers**. Client all/eth0/gnv0 `rp_filter=2`, `src_valid_mark=0` were read
without alteration. Gateway flower accepted the forward packets and the
client received the outer return tunnel, but TCP connect timed out. This
establishes the eBPF **return-path RPF failure** in the disposable fixture,
not a generic tc-egress metadata problem. No safe correction or Linux 5.10
runtime pass is established; eBPF remains unaccepted.

A follow-up **disposable-netns tc-ingress experiment** on kernel 7.0 used the
same BPF program and successfully emitted outer UDP/6081 with expected VNI
and identity TLV; the gateway received it. An additional minimal tc-egress
packet test also emitted valid outer GENEVE, so the earlier inference that
tc-egress attachment itself was the cause was **too broad**. Neither isolated
proof is a production fix:
locally generated Pod traffic does not traverse the proposed eth0 ingress
hook. Any change needs a reviewed routing/attachment topology that preserves
local OUTPUT policy and fail-close, plus real multi-pod and Linux 5.10 packet
evidence. No scratch implementation was retained.

A second disposable-netns experiment connected locally generated OUTPUT to
that tc-ingress hook using a same-namespace veth pair and a selected-route
table. On kernel 7.0 it emitted the expected outer UDP/VNI/TLV, passed the
gateway flower verifier, and reached the fake upstream with SNAT. The reply
returned through GENEVE, but the client socket timed out under the default
reverse-path validation. Disabling `rp_filter` **only in the isolated test**
proved the cause, not an acceptable production remedy. This topology therefore
resolves the forward metadata symptom in isolation but **does not satisfy the
restricted-Pod return-path or Linux 5.10 acceptance gates**. No production
implementation was retained and no host/cluster sysctl was modified.

A later bounded Linux-7 disposable-netns RPDB experiment found that an
exact remote /32, TCP/UDP and `dport 8080` rule let selected replies pass with
`rp_filter=2` and `src_valid_mark=0`. An initial inference of wrong-port TCP
leakage from `rtk0` aggregate TX counters was **incorrect**: packet capture
identified those increments as IPv6 multicast noise, not wrong-port TCP. With
an nft route/OUTPUT bypass mark and higher-priority MAIN rule, the tested TCP
SYN bound to **source** port 8080 and targeting **destination** port 9090 was
captured only on `eth0`; nft bypass and marked-FIB counters supported direct
routing. This does **not** yet establish that all policy/exclusion, fail-closed,
transition or Linux 5.10 cases pass. The candidate remains unimplemented and
unaccepted pending packet-level negative/positive verification. No sysctl or
security relaxation was used.

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

## October 30, 2026 — rerun after reported network repair

After the reported network repair, both guarded final-gate fake subsets were
rerun **serially** against the existing Ready flannel k3d nodes and already
imported local images (no VM provisioning, preflight bypass, registry pull,
Secret, or live VPN input). The iproute cell remained **FAILED** at
`m8-selective-policy`: direct baseline, gateway readiness, client programming,
cluster preservation, measured MTU, private metric, fake-tunnel echo, and
4.5 MiB payload integrity passed first. The eBPF cell remained **FAILED** at
`fake-tunnel-echo` after the same baseline, readiness, programming, cluster,
MTU and private-metric checks passed. Both runners reported namespace cleanup
passed; no diagnostic namespace remained. Evidence directories outside the
repository: `/tmp/ratatoskr-m8-fake-z713hmse` (iproute) and
`/tmp/ratatoskr-m8-fake-njoqvbjl` (eBPF). The network repair does **not**
resolve either documented datapath blocker; skipped matrix cells remain
untested, and the unset live profile is still a **skip**, not a pass.

## October 30, 2026 — numbered GENEVE and guarded-update rerun

Later commits `0e0b03e` and `508091c` assign an owned
`169.254.64.2/32` to the iproute `rtk0` and eBPF collect-md `gnv0`
interfaces before link-up. This addresses the unnumbered-ingress reverse-FIB
case without disabling `rp_filter`, writing `src_valid_mark`, changing the
pod's main default route or granting the programming init extra privileges.
`8ca9186` replaces eBPF update-time program/map-by-ID access (denied by the
NET_ADMIN+BPF+PERFMON-only k3d client) with an owned priority-419 tc drop
guard installed before fallible replacement and removed only after the new
selector attaches. Privileged namespace tests cover ownership, conflict,
failed-update drops and restart verification; repository-wide race tests,
lint, vet, build, privileged tests, Helm/chart and static inventory checks
passed after these changes.

With refreshed local client images on the existing flannel k3d cluster,
**each direct-config fake subset ran to completion independently**: iproute
`/tmp/ratatoskr-m8-fake-w0a8iv73`, eBPF
`/tmp/ratatoskr-m8-fake-zvwnivar`. Matching inner TCP/8080 reached the fake
upstream; ordinary outer PodIP and cluster paths remained reachable, payload
size/SHA256, private metrics and upstream down/recovery checks passed. Both
inner reports said `passed`, but the outer M8 inventory correctly returned
**INCOMPLETE / exit 4** because other CNI/mesh/agent/WireGuard/HA cells and
scenarios were not covered.

A subsequent **serial two-cell** run exposed a false assertion: the original
negative-selector test compared aggregate GENEVE TX packets, which also count
unrelated IPv6 multicast, ARP and delayed TCP. A proposed nft postrouting
counter did not prove ordinary emission (and postrouting occurs before the
eBPF tc-egress verdict). The harness was corrected in `771854a` to record
matching selector success separately while marking wrong-port/CIDR/exclude
negative-path emission **INCONCLUSIVE**, not passed. The serial rerun at
`/tmp/ratatoskr-m8-fake-341b9kdd` returned **INCOMPLETE / exit 4**, with
both inner runs `inconclusive`: their positive fake tunnel, 4.5 MiB payload,
matching selector, cluster-path, gateway health, failure/recovery and cleanup
checks passed; negative inner-only requests failed but no five-tuple-correlated
ordinary-path versus drop proof exists. The no-endpoint inner-only failure is
also **not** evidence by itself that a reachable ordinary path was blocked.
This is a successful component/positive-traffic step, **not M8 or M9 acceptance**.
No new live VPN inputs were available; live remains skipped. Neither a
Linux-5.10 runtime pass nor alternate-CNI/mesh acceptance is claimed.

## Release blockers / next gate

1. Complete five-tuple-correlated **negative** selector and no-endpoint
   fail-close proofs on both datapaths, including a controlled reachable
   ordinary path, without treating a timeout or aggregate link counter as
   proof. Recheck restricted agent-mode traffic and Linux 5.10 runtime. The
   earlier iproute and eBPF return-path component failures were resolved for
   the flannel/init positive-flow subset, not the full policy contract.
2. Implement and run the missing CNI/mesh/agent/WireGuard/HA compatibility
   scenarios under the existing mandatory resource preflight. Skipped cells
   must never be represented as passed.
3. Obtain live VPN input and the exact requested live checklist; only then run
   the live tests, validate exit IP/country without exposing credentials, and
   record any unavailable external checks as inconclusive.
4. Re-run full CI (including multiarch, artifact provenance/signing policy)
   against the *final* release commit and review security/metrics limitations.
   Until then, do not publish or sign a production release.
