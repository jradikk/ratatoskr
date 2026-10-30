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

## October 30, 2026 — same-destination direct versus steered validation

After the numbered-interface and guarded-update fixes, the selector fixture
was further corrected to make the **same remote PodIP:8080** reachable by both
CNI direct routing and the fake upstream; only its /32 was removed from the
cluster Pod-CIDR exclusions. A disposable flannel Pod test established both
routes for each backend before changing the harness. The HTTP echo identifies
the actual remote peer: **client PodIP** for ordinary direct traffic and
**198.19.0.2** for steered traffic. This avoids inferring routing from link
counters, nft postrouting (which precedes the eBPF tc-egress verdict), or a
timeout to an inner-only address.

The guarded final-gate matrix then executed its two flannel/no-mesh/init/none
cells **serially**. Both inner direct-config fake suites reported **passed**:
matching CIDR/TCP-port requests reached the fake upstream; wrong port, wrong
CIDR and exclude cases returned through the ordinary CNI with the client
PodIP; endpoint withdrawal blocked the *otherwise directly reachable*
selected destination, while DNS/API remained usable and the full tunnel
recovered. Payload integrity, private metric health transitions, upstream
failure/recovery and ephemeral namespace cleanup also passed. Evidence:
`/tmp/ratatoskr-m8-fake-_cj0w5sf/`. The outer 96-cell inventory correctly
returned **INCOMPLETE / exit 4**, because CRD/admission, restricted agent,
WireGuard, HA, alternate CNI/mesh, full observability and Linux-5.10/runtime
coverage remain untested. Live VPN remains **skipped** (profile unset). These
two direct-config passes do **not** constitute M8/M9 release acceptance.

## October 30, 2026 — bounded existing-release API/admission tier

A separate final-gate API-only scaffold (`05a7b47`) checked **immutable
expected controller/webhook runtime image IDs** and fully Available
Deployments before contacting admission. The existing flannel operator
components were rebuilt/imported and explicitly rolled so reused mutable
`:dev` tags could not masquerade as current code. Four serial release modes
(`agent`/`init` × `iproute`/`ebpf`) were exercised via Helm updates, then
the previous `agent/iproute` dev release was restored; controller/webhook
were 1/1 Available and the agent DaemonSet 3/3 Ready afterward.

All four API-only runs passed server dry-run of both checked-in CRDs and
complete Gateway/Policy objects, authorized Pod CREATE mutation plus
configured CREATE validation, injected init/waiter security and fail-closed
pending state, four expected unauthorized CREATE denials, and cleanup of
non-secret fixture namespaces/Gateways. **No workload Pod was persisted, no
healthy VPN/gateway was provisioned, and no Secret contents were read.**
On the two eBPF releases the controller also reported unsupported
`ebpf+wireguard` before creating a Deployment; this particular assertion
was **SKIPPED** on iproute releases rather than inferred. Independent
validator tamper/UPDATE and healthy Gateway reconciliation are still untested.
Evidence directories outside the repository: agent/iproute
`/tmp/ratatoskr-m8-fake-_2ndp2dz`, agent/eBPF
`/tmp/ratatoskr-m8-fake-zu7sy5zj`, init/iproute
`/tmp/ratatoskr-m8-fake-w6_965a0`, init/eBPF
`/tmp/ratatoskr-m8-fake-yy1u47z5`. The **outer matrix remained
INCOMPLETE / exit 4** for each run; no API assertions were counted as
traffic/CNI/mesh compatibility. Live VPN remains skipped.

## October 30, 2026 — independent Pod UPDATE admission validation

Follow-up scaffold `bcf6ba2` added a real API-server validating-UPDATE tier
without starting a workload. It first server-dry-runs and verifies an
**inert, scheduling-gated Pod** with a never-match node selector under the
existing missing-Secret Gateway. Only after both barriers, security fields,
no node assignment and no container execution are checked is the inert Pod
persisted. A benign annotation UPDATE server-dry-run must succeed; three
separate gateway-label, gateway-namespace and client-config annotation
changes must receive the exact Ratatoskr validating-webhook immutability
denials. The fixture is re-read unchanged, then the exact Pod is deleted and
its absence verified **before** namespace cleanup. No scheduling barrier is
removed, and no workload or VPN traffic is generated.

The parent ran this final-gate tier in all four existing release modes with
fresh immutable controller/webhook image-ID preflight: agent/iproute
`/tmp/ratatoskr-m8-fake-ccg0q9yi`, agent/eBPF
`/tmp/ratatoskr-m8-fake-jm4snbqn`, init/iproute
`/tmp/ratatoskr-m8-fake-9kx_0y2s`, init/eBPF
`/tmp/ratatoskr-m8-fake-iutq0xom`. **Independent UPDATE validation PASSED**
in every mode, alongside the earlier CREATE/security/denial and cleanup
checks. eBPF+WireGuard controller rejection remained **SKIPPED** on the two
iproute releases and passed on the two eBPF releases. The chart was restored
to the prior `agent/iproute` dev mode; controller/webhook were 1/1 Available
and the agent DaemonSet 3/3 Ready. Each outer inventory remained
**INCOMPLETE / exit 4** because API evidence does not establish healthy VPN,
agent-managed traffic, other CNI/mesh variants, HA, or live acceptance.

## October 30, 2026 — operator-only probe and unexecuted synthetic fixture

An operator-only `dns.upstreamProbeURL` Helm value (`67d9634`) now passes a
literal unicast IPv4 HTTP(S) URL to the OpenVPN plugin's existing
`--probe-url` flag. Empty preserves the external HTTPS default. The controller
rejects credentials, hostnames, queries, fragments and malformed ports;
workloads cannot set this value in the CRD. The plugin retains its tunnel-bound,
marked socket and rejects non-tunnel fallback. Controller render tests, full
Go race/lint/vet/build and chart checks passed; **no new images were rolled or
VPN requests run**.

The non-executing `test/e2e/matrix/synthetic/` scaffold (`5bb6205`, followed by
Pod-local TUN isolation `d4c3f53`) defines real OpenVPN server and ephemeral
PKI/Secret/manifest helpers plus static contract tests. The server uses only
NET_ADMIN/MKNOD and an emptyDir TUN device, not a host device mount; the
restricted client declares no added capabilities or credentials. Synthetic
private keys, even generated only for tests, are sensitive material. Only
static, shell-syntax and matrix/admission-static checks passed; **no PKI,
server image, Secret, Gateway, Pod or tunnel was created and no e2e passed**.
A bounded runner with immutable image provenance, release probe verification,
owner-chain/agent/traffic/negative-path assertions and verified cleanup remains
required before healthy controller-created Gateway acceptance. The two direct-
config fake cells and four-mode API admission checks do not establish it.

A subsequent **read-only** synthetic preflight (`75850f0`) requires both explicit
final-gate switches and seven immutable expected runtime image IDs before
querying an existing cluster. It verifies the three-node flannel/no-mesh
release, fail-closed admission, controller/webhook/agent owner chains, readiness
and runtime IDs, and the configured private probe. Even on success it exits
**INCOMPLETE / 4**: gateway/plugin/server/tools image IDs are not compared to
running Pods; no PKI, Secret, Gateway, synthetic Pod, tunnel, agent marker,
withdrawal/recovery or cleanup was exercised. A follow-up hardening
(`db49a6b`) requires updated ready rollout replicas, local image pull policies
and aligned admission configuration. Five
cluster-free tests and synthetic/matrix/admission static checks passed. This
read-only check does **not** complete the bounded execution runner or count
toward M8 compatibility.

A reusable, **unwired** namespace/PKI lifecycle helper (`ebe57dd`) now provides
random namespace prechecks, server-returned UID ownership, UID-conditional
DELETE, verified absence, a private 0700 directory and bounded SIGINT/SIGTERM
cleanup. Eighteen cluster-free tests cover error/race/cleanup paths, but the
raw UID-conditional kubectl transport has **not been validated against this
cluster**. It is not invoked by the read-only preflight, and neither actual
credentials nor Kubernetes objects were created in authoring. An ambiguous
CREATE without a returned UID cannot be safely deleted automatically; this
requires operator orphan inspection and cannot count as a PASS. Full runtime
traffic and fail-close evidence remains unimplemented.

Pure evidence assertions (`c4ce59c`) and a bounded, allowlisted fixture adapter
(`4008701`) now have **32 cluster-free tests**. They check synthetic ownership,
Gateway MTU and status, runtime image IDs, restricted-client fields, GENEVE
identity/counter changes, direct-path evidence and withdrawal/recovery contracts;
the adapter rechecks namespace UIDs, sends JSON on stdin and bounds commands,
output and time. Neither is called by `run.py`. `kubectl exec` has no server-side
Pod-UID precondition, so the adapter's before/after UID checks cannot rule out
an intervening Pod replacement; there is no TLS session provenance or safe
server-interruption collector. The matrix stays INCOMPLETE, and no new cluster,
PKI, synthetic workload or traffic was executed for these assertions.

Further **unwired, cluster-free** fixture contracts (`12b2e35`, `35fa185`,
`08df89e`, `9d0ae4c`) added bounded Gateway/agent/GENEVE collection, a
sanitized OpenVPN 2.6 server status-v3 reader backed by a private Pod-local
memory volume, and a public-CA-verified anonymous Kubernetes API TLS/direct
route check from the restricted client. The status parser's certificate-only
username and Client ID fields were checked against upstream OpenVPN 2.6 source;
**47 fake-only unit tests passed**, but the actual server image/status output,
TLS session, public CA/anonymous policy and traffic remain unverified on this
cluster. `run.py` remains read-only and always reports INCOMPLETE.

A read-only outage-design audit found that deleting the sole VPN server Pod
also removes its sole marker listener, so a failed selected request would not
by itself prove fail-closed steering. An independent echo PodIP would be
covered by mandatory node PodCIDR exclusions and bypass the VPN even while
healthy; routing VPN traffic to it also needs forwarding and return NAT inside
the synthetic server Pod. No server interruption/recovery API or direct-route
exception was added, no Pod/Secret/PKI was created, and **no negative-path or
recovery pass is claimed**. The full runtime gate and M8/M9 release remain
blocked until a reachable same-destination outage proof and bounded verified
orchestration can be designed and executed.

A subsequent **design only** observation suggests a more discriminating outage
fixture: leave the synthetic VPN server, authenticated session and tunnel-bound
`/marker` active, but make only its private `/exit` readiness probe return 503
under a non-secret, operator-owned ConfigMap flag. The plugin/controller should
then withdraw the healthy endpoint while the marker remains reachable through
the VPN from the gateway namespace. This requires a UID/resourceVersion-guarded
flag update/restore and independent proof of marker reachability during
withdrawal; neither has yet been executed. No traffic or fail-close PASS is
claimed on this basis.

A non-secret Pod-local ConfigMap projection (`02e7ac8`) now makes `/exit`
return 503 while leaving `/marker` and OpenVPN untouched. Its scoped API
helper uses ConfigMap UID/resourceVersion checks and a guarded restoration;
`92048c0` additionally refuses to overwrite an intervening writer during
outage. **59 cluster-free synthetic tests** passed. None of these helpers is
wired into `run.py` or exercised against the Kubernetes API. Server-session
counter growth cannot independently prove `/marker` remained reachable:
keepalives and failed probes can also move counters. A second, separately
certified tunnel witness is required to establish reachability while the
selected client is blocked; it is not yet implemented or validated.

Follow-up **test-only** fixture commits (`04f35b7`, `c0592e3`, `7b6b5b9`,
`194721a`, `5e25c20`) added a distinct ephemeral OpenVPN witness credential,
independently tunnel-bound `/marker` request, bounded request deadline and
outage-end timestamp, and three restricted one-shot selected Pod variants for
healthy, withdrawal and recovery phases. The selected helper returns exit 42
only on kernel network-unreachable errors after verified public-CA API direct
paths; generic HTTP/network failures do **not** count as fail-close. A fixed
CREATE output now captures only server-returned object UID/identity (never
Secret contents), quarantines ambiguous attempts, and read-only preflight
requires **nine** immutable expected image IDs including witness and helper.
**75 cluster-free tests and static contracts passed**, not runtime e2e. The
runner still does not create any resource or award PASS. Fixture images,
OpenVPN/TUN, API TLS/ConfigMap projection, agent programming, same-interval
witness and outage/recovery sequencing remain unverified in the cluster;
M8/M9 stay INCOMPLETE.

`f07cba3` added an import-only, no-PASS dry-run checkpoint planner for the
nine-image fixture and ordered healthy→withdrawal→witness→recovery→cleanup
sequence. Local synthetic server, independent witness and restricted one-shot
client images were built on this VM without pushing or importing them into the
cluster. The server image reports OpenVPN 2.6.14 and Python 3.13.5; the client
image contains `getent`. All three local builds passed after an intentionally
offline build failed because Debian package indexes were unavailable without
network access. Docker image creation is **not** a Kubernetes runtime test:
there was no PKI generation, Secret, Gateway, Pod, VPN session or traffic in
this step. The planner still raises INCOMPLETE and real status-format/device,
TLS, projected ConfigMap and cleanup behavior remain unverified.

`26bbe3e` removed an obsolete hour-long selected Pod from the synthetic
manifest generator. The static check now matches the eight initial fixture
CREATE identities expected by the planner; selected phase Pods are generated
separately. Upstream OpenVPN 2.6 source confirms the parser's status-v3 header,
certificate-only `UNDEF` username and optional Client ID fields. **80 fake-only
unit tests and the synthetic static contract passed** after this correction.
Read-only cluster inspection showed the existing operator release still has
no `GATEWAY_UPSTREAM_PROBE_URL` value; even with local synthetic images built,
it is not yet the current operator probe configuration. No Secret/Pod/VPN
runtime fixture was started and no acceptance was awarded.

`ddb0ddf` added a second zero-label, loopback-only gateway gauge for measured
effective MTU (0 when unready/unknown). Focused race tests, lint and vet
passed; flow counts, live peers, handshake age and external scraping remain
unimplemented, so this does not finish M7/M8 observability acceptance.

## Release blockers / next gate

1. The two flannel/init direct-config cells now distinguish selected from
   nonselected TCP/8080 using the **same reachable destination**, and
   withdrawal blocks that destination. Extend this packet-level proof to
   UDP, multi-policy transitions and controller-created workloads, then
   recheck restricted agent-mode traffic and Linux 5.10 runtime. Earlier
   iproute/eBPF return-path failures were resolved for the two flannel/init
   subsets, not the full CNI/mesh/HA/WireGuard contract.
2. Implement and run the missing CNI/mesh/agent/WireGuard/HA compatibility
   scenarios under the existing mandatory resource preflight. Skipped cells
   must never be represented as passed.
3. Obtain live VPN input and the exact requested live checklist; only then run
   the live tests, validate exit IP/country without exposing credentials, and
   record any unavailable external checks as inconclusive.
4. Re-run full CI (including multiarch, artifact provenance/signing policy)
   against the *final* release commit and review security/metrics limitations.
   Until then, do not publish or sign a production release.
