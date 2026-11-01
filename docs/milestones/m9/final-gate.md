# M9 release gate — blocked (October 30, 2026)

**Release status: NOT READY.** This is an evidence report, not a release announcement.
No version tag, published chart/image, registry push, signature or pull request was
created. The checked-in chart intentionally remains `0.0.0-dev` / `dev`.

## October 31, 2026 — encrypted agent lifecycle repaired (scoped evidence)

The existing three-node flannel/no-mesh agent/iproute release completed the
explicitly gated synthetic WireGuard startup and peer-lifecycle runner after
these fixes:

- Raw UID-precondition DELETE responses are bounded and drained without
  retaining Gateway/Secret response bodies. Fixture termination grace and
  registration/cleanup phase deadlines are independently bounded.
- TCP 9443 registration is reachable from host-network node agents; TLS and
  Pod-bound TokenReview authorization are unchanged. UDP 51820 remains
  restricted to authorized selected workload namespace/Pod selectors.
- Gateway `gnv0` has a strictly owned `169.254.64.3/32` address, avoiding the
  authenticated GENEVE ingress reverse-path-validation failure. Gateway peer
  routes apply only to locally generated outer traffic (`iif lo`), so forwarded
  upstream replies take table-101 LWT GENEVE rather than bypassing encapsulation.

On datapath commit `c406e07` with test-only follow-up `8e04bab`, the runtime
runner observed encrypted workload startup, the exact synthetic marker and
preserved direct API checks, a registered/handshaken peer with RX/TX growth,
UID-conditional selected Pod deletion, and kernel peer removal. It returned
**4 / INCOMPLETE**, not failure and not full M8 PASS. The run's namespace/private
PKI and operator-fixture cleanup completed. Earlier failed runs left two
historical operator-namespace Gateway objects; they were not adopted or deleted
by name because this run does not retain their CREATE-authorized cleanup state.
They remain a separate cleanup issue, not evidence of this run's success.

Integrated validation passed full Go race tests, vet, lint (0 issues), binary
builds, privileged component tests, 30 repeats of the decrypted-INPUT observer,
and 230 offline Python tests. The encrypted bidirectional namespace regression
also passed 20 repetitions. No host runtime/seccomp or capabilities were relaxed.
Only local controller/agent/gateway development images were refreshed; nothing
was published. Plaintext rejection, independent TokenReview evidence, the wider
compatibility matrix and release provenance remain unverified acceptance gates.

## October 31, 2026 — continued HA, outage and independent token checks

The existing flannel/no-mesh agent/iproute development cluster completed two
additional explicitly gated synthetic runtime subsets, both returning
**4 / INCOMPLETE**, never full-matrix PASS:

- Two-replica HA: fresh selected marker traffic and the direct API path succeeded
  before and after exact UID-preconditioned deletion of the chosen gateway
  replica. Established-flow continuity, distinct exit addresses and encrypted HA
  were not asserted.
- Witnessed outage/recovery, at `56ce37d`: the independent VPN witness observed
  the upstream health-switch projection and retained its independent marker
  during Gateway withdrawal. The long-lived selected Pod retained its UID,
  cluster DNS and pinned direct API access. Root-owned, pinned-netns header-only
  capture observed direct API SYNs and no selected-destination SYNs while exact
  owned unreachable-route and marked-rule checks held. Selected marker delivery
  recovered after probe restoration. Namespace/private fixture cleanup completed.

Two production defects were repaired during this work: zero measured MTU when no
endpoint is healthy had incorrectly triggered irreversible authorization
quarantine, and decoded explicit `0.0.0.0/0` routes had escaped nil-only default
withdrawal. Closed configurations now use a conservative MTU only without a
healthy endpoint; owned default-route withdrawal recognizes both encodings.
Healthy missing-MTU configurations and foreign routes remain protected.

TCP connect timeout is not independently accepted as fail-close evidence. The
new collector requires separately verified source identity, exact closed routing,
positive direct-API packet control and absence of selected SYN egress. It uses
existing bounded host sudo diagnostics; no workload capability, runtime/seccomp,
VM setting or sudo policy was changed. Numeric iproute output, separate mark/mask
fields and harmless blank tcpdump separators were measured and strictly parsed.

A separate memory-only TokenRequest/TokenReview diagnostic during an owned
WireGuard lifecycle verified the current Pod UID, ServiceAccount and audience,
including a rejected wrong-audience review. This verifies Kubernetes token
binding, **not** that the gateway made its own TokenReview call. Plaintext GENEVE
rejection and actual gateway-call evidence remain unverified runtime gates.

Final integrated validation passed full Go race tests, vet, lint (0 issues),
binary builds, privileged component tests and **252 offline Python tests**.
No release artifact was published or signed; the wider compatibility matrix and
release gate remain incomplete.

## November 1, 2026 — completion audit and plaintext-denial probe

Overall engineering implementation is estimated at **roughly 75%** (a subjective
70–80% range), not release readiness or a measured compatibility pass rate.
Core M0–M7 work is largely built; M8 still has substantial unexecuted CNI/mesh,
packet-security and platform coverage, and M9 has no published/signed release.
The README and M8 summaries now distinguish historical failures from verified
scoped runtime results without upgrading full matrix coverage.

A separately gated plaintext GENEVE negative-test collector was implemented.
It checks both owned Pod/CRI identities, pins network namespace FDs in an existing
bounded root diagnostic, and sends exactly three fixed synthetic frames through
source `eth0` using a verified route/neighbor and AF_PACKET. It changes no
production NetworkPolicy, workload capability or runtime setting. The sender's
sentinel-FD, list-shaped neighbor state and omitted query-bound interface handling
were corrected against measured output with regression tests.

At `b022e3d`, the runtime collector recorded **sent=3, gateway eth0 ingress=0,
GENEVE ingress delta=0, INPUT guard counter before=0/after=0**. The runner
returned failure at `plaintext-denial`, with its UID-owned cleanup completed.
This proves neither arrival nor the gateway nft drop and is **not a plaintext
rejection acceptance pass**. Earlier network-path filtering is a possible cause;
production policy was not relaxed to manufacture an nft-counter result.

Full integrated Go race tests, vet, lint (0 issues), binary builds, privileged
component tests and **261 offline Python tests** passed. The plaintext runtime
acceptance gap remains open; the prior encrypted, HA and witnessed-recovery
scoped evidence remains separate. No release artifacts were published.

## Continued release goal — direct gateway rejection and programming metrics

At `9c6937b`, the separately opted-in, UID-owned encrypted fixture completed
wrong-audience gateway rejection, unchanged public peer-key fingerprint and
kernel peer counts, fresh authenticated marker delivery, and peer revocation.
The request used the verified node-host network namespace, matching the agent,
with TLS 1.3, the published CA and exact numeric gateway IP. The helper dropped
UID/GID before HTTPS; bearer material remained bounded stdin/memory only. This
is gateway boundary evidence, not an independent audit of its TokenReview call.
The runner returned 4 / INCOMPLETE and does not award full matrix acceptance.

Gateway programming metrics were added at `88e926a`: process-lifetime totals
for completed ApplyGateway attempts and returned errors, plus a fixed-bucket
latency histogram. Startup, refresh and fail-closed applications share the
wrapper. Metrics remain zero-label and loopback-only; a panic propagates and is
not miscounted as a completed success. This is partial observability, not full
traffic/flow/drop telemetry. The new metrics have component validation but have
not yet been runtime-accepted in a newly deployed gateway image.

The mandatory 29-gate acceptance ledger remains OPEN/PARTIAL. No versioned
release candidate or publication is authorized by these scoped results alone.

## Programming metric reader and deployed-gateway integration follow-up

At `e0fa2ea`, the encrypted runtime fixture completed with a rebuilt local gateway
containing the programming metrics and the opted-in wrong-audience rejection
check. The strict loopback metric reader accepted the emitted zero-label counters
and fixed-bucket histogram while preserving its original WireGuard sample schema.
Encrypted marker traffic, rejection with unchanged peer fingerprint, revocation,
and owned cleanup completed; the runner returned 4 / INCOMPLETE, not full M8 PASS.

Reader tests reject foreign labels, duplicate or unknown buckets, nonfinite values
and inconsistent programming samples; legacy gateways without those metrics
remain readable. Diagnostic root helpers disable Python bytecode creation before
repository imports. Validation included 75 advanced and 156 synthetic Python
tests, gateway/observability race tests and vet, lint (0 issues), matrix static
checks and diff checks. The combined shell-validation task reported signal 143
after emitting all check results, so its aggregate exit is not recorded as a
clean full validation pass. Separate runtime and fixture test tasks completed.

Full observability, plaintext ingress proof and remaining release gates are still
open; this follow-up does not change their acceptance status.

## Continued release goal — link telemetry and packet-level negative checks

At `15a3bcc`, the existing flannel/no-mesh agent/iproute encrypted fixture
completed with a source-verified, rebuilt gateway containing fixed-role link
telemetry. The strict reader accepted geneve/upstream/wireguard sample status
and RX/TX byte/packet gauges. Wrong-audience rejection, unchanged public peer
fingerprint, authenticated marker delivery, revocation and owned cleanup
completed; the runner returned **4 / INCOMPLETE**, not full M8 acceptance.
The local image binary was compared byte-for-byte with the current source build
before import; no registry publication or signing occurred.

Link traffic values are resettable kernel gauges, not monotonic counters or
flow estimates. Failed/timed-out samples omit traffic values and report
sample_ok=0. One in-flight kernel reader prevents unbounded stalled readers;
labels are restricted to three fixed device roles. Per-workload flow/drop
telemetry and full observability remain incomplete.

Component packet tests now use a reachable controlled metadata endpoint only
in disposable sibling namespaces, proving TCP/UDP prohibition under full and
selective policies, direct-path preservation, and explicit metadata bypass.
Local UDP/TCP DNS servers exercise cluster/reverse forwarding, healthy external
forwarding and external SERVFAIL without fallback. These do not establish live
CNI/mesh metadata/DNS acceptance or gateway upstream-interface binding.

Full Go race tests, vet, lint, binary builds, privileged tests and **281 offline
Python tests** passed after integration. The image-build wrapper reported signal
143 after its build output; a separate byte-for-byte binary comparison verified
its actual image contents. Namespace cleanup was verified. The mandatory release
ledger remains OPEN/PARTIAL; Linux 5.10, wider compatibility and other packet
and provenance requirements remain outstanding.

## Continued release goal — spoof packets and same-workload replacement

The isolated GENEVE spoof regression at `a0b267b` first observed an authorized
packet arriving on gateway eth0 and passing the flower verifier, then separately
observed wrong outer-source, inner-source and VNI packets and required default
rejection without an acceptance-counter increase. Targeted privileged, race,
vet and lint checks passed. This is controlled component packet evidence, not
full-CNI runtime spoof acceptance.

At `9e005ae`, the separately gated singleton gateway replacement fixture returned
4 / PARTIAL after preserving the existing selected workload Pod UID, deleting
only the owned old gateway Pod UID, observing a new acknowledged gateway Pod
UID/IP, and verifying fresh healthy marker traffic. Owner-chain, applied-byte
hash and selected identity checks remained mandatory; namespace cleanup completed.
The earlier generic failure is retained as a failed attempt, not overwritten as
success. Fixed safe diagnostics and default-adapter regression coverage were
added before the successful rerun.

Agent restart and established-flow continuity were not tested by this fixture.
The full agent lifecycle and compatibility release gates remain incomplete.
Validation after integration included 85 advanced Python tests, 156 synthetic
Python tests, Go advanced tests and diff checks; full component validation before
the diagnostic-only follow-up passed Go race/vet/lint/build and privileged tests.

## Continued release goal — externally coordinated agent restart and low MTU

The separately opted-in lifecycle fixture at `a146d7e`, with the integrated
low-MTU tests through `0793c61`, completed gateway replacement and subsequent
externally coordinated agent Pod replacement. The parent revalidated the exact
agent Pod UID, same-node placement, DaemonSet owner UID and runtime image before
one UID-preconditioned DELETE. The fixture itself performed no release or
DaemonSet mutation. A different Ready agent Pod on that node was observed, while
the selected workload retained its UID and acknowledged gateway endpoint, and
fresh healthy marker traffic succeeded. Namespace cleanup completed. The runner
returned **4 / PARTIAL**, not full acceptance or established-flow continuity.

A disposable three-namespace low-MTU regression uses a 900-byte carrier,
750-byte upstream link and 700-byte inner MTU. It verifies byte-for-byte 16 KiB
TCP request/response delivery, oversized selected IPv4-DF UDP rejection with
EMSGSIZE and no matching plaintext client-eth0 packet, and refusal of client and
gateway MTUs below 576 before GENEVE creation. This is component evidence, not
full-CNI PMTU or ICMP blackhole acceptance.

Integrated Go race tests, vet, lint, binary builds and privileged components
passed, together with **297 offline Python tests** (92 advanced, 156 synthetic,
29 M1 and 20 matrix). Targeted low-MTU tests also passed repeated and race runs.
No runtime/seccomp/sudo settings or workload capabilities were changed. The
mandatory release ledger remains incomplete; plaintext ingress, Linux 5.10,
wider compatibility and artifact provenance are still open.

## Continued release goal — private node-agent programming metrics

At `4049848`, the agent records completed usable/closed/cleanup datapath calls
with fixed-operation attempt/error counters and duration histograms. API/CRI
checks, registration and Pod patches are outside that programming boundary.
Metrics bind only to node loopback `127.0.0.1:9903`; no chart port, Service, RBAC
or capability was added. The current-source binary was compared byte-for-byte
with the locally built agent image before import and an existing DaemonSet
rollout. All three nodes exposed the expected loopback programming series with
no Pod/IP/token labels.

Full Go race/vet/lint/build and privileged components passed, together with
302 offline Python tests (92 advanced, 156 synthetic, 29 M1, 20 matrix and five
platform tests). The same-workload restart fixture emitted its PARTIAL success
message, but its encompassing image-verification/runtime shell ended with signal
143. That wrapper is therefore not recorded as a clean aggregate runtime pass.
Separate subsequent reads verified owned namespace cleanup and three updated
Ready agents. Earlier independently completed lifecycle evidence remains valid;
this follow-up records metrics presence rather than manufacturing a new full
restart acceptance pass.

Full workload traffic/flow/drop observability, Linux 5.10, broader compatibility
and plaintext ingress acceptance remain open. No release artifact was published.

## Continued release goal — late IPv6 packets and immutable CNI context

At `6f68157`, a disposable veth regression positively observes IPv4 and IPv6
traffic before enforcing the IPv6 guard. Late global IPv6 assignment then
requires persistent IPv4 quarantine, readiness-marker removal and no IPv4/IPv6
packet delivery. Removing the address does not clear quarantine. This is
component packet evidence, not live-CNI acceptance.

At `2c752de` and `9f4be71`, read-only preflight and fixture namespace/API operations
accept an immutable flannel/Calico environment. API calls, direct probe exec and
UID-preconditioned cleanup use the owner environment; mixed contexts are refused.
Flannel defaults remain unchanged. Calico CLI dispatch, node image/CRI inspection
and advanced fixtures are not completely wired, so no Calico traffic execution
or compatibility acceptance is claimed. The existing cluster was not deleted,
reconfigured or duplicated.

Full Go race tests, vet, lint, builds and privileged components passed, alongside
309 offline Python tests (92 advanced, 163 synthetic, 29 M1, 20 matrix, five
platform). Actual alternate-CNI execution remains pending completion of plumbing
and an approved serial cluster replacement/restoration procedure. The Linux
5.10 runner requirement and other mandatory release gates remain open.

## Continued release goal — immutable node CRI verification

At `3f401a3`, read-only node image verification accepts the same immutable
Environment as preflight and fixture APIs. Non-default environments require the
exact preflighted node tuple before Docker/CRI calls; immutable image IDs are
checked on all three nodes. Default flannel behavior is unchanged. Advanced
fixture node helpers and public CLI dispatch remain flannel-only, so this does
not enable or accept Calico traffic.

The existing flannel same-workload gateway replacement and externally coordinated
agent restart fixture completed with exit 4 / PARTIAL after this seam was added,
with fresh healthy traffic and owned cleanup. Full Go race/vet/lint/build and
privileged checks passed, alongside 310 offline Python tests (92 advanced,
164 synthetic, 29 M1, 20 matrix, five platform). No cluster topology, CNI,
capabilities or runtime settings were changed. Actual alternative-CNI acceptance
still requires complete fixture plumbing and an approved serial environment run.

## Continued release goal — existing-Calico healthy-only entrypoint

At `3584e77`, a standalone, separately opted-in Calico/no-mesh agent/iproute
healthy-only synthetic runner is available for an already approved existing
Calico cluster. It requires exact context/Ready-node/CNI-marker/release/image
preflight before UID-owned fixture writes, passes one immutable environment
through API/CRI/lifecycle operations, and returns 4 / INCOMPLETE even after its
scoped healthy traffic and cleanup succeed. It does not create clusters, install
Calico, change a release, run outage/WireGuard/init variants, or award matrix PASS.

No Calico runtime was executed on this host. The existing flannel cluster was
preserved. Its same-workload gateway replacement and externally coordinated
agent restart runtime passed after the change, with cleanup. Integrated Go
race/vet/lint/build and privileged tests passed; 315 Python tests passed (92
advanced, 169 synthetic, 29 M1, 20 matrix, five platform), alongside static matrix
and synthetic contracts.

Actual Calico execution requires a deliberate operator-approved serial removal
of the current flannel cluster, verified fixture cleanup, pinned install inputs,
resource/module preflight and a restoration plan. Linux 5.10 and the remaining
mandatory release gates are still outstanding; no compatibility pass is inferred
from this new runner or its fake tests.

## Continued release goal — non-certifying compatibility applicability

At `934915c`, a pure applicability contract preserves all 96 configuration
identities per fake/live mode. The 24 eBPF-plus-WireGuard combinations require
explicit refusal evidence; the other 72 are traffic-evidence candidates, not
verified compatible configurations. Scenario applicability follows the declared
mode and driver/datapath/encryption constraints. Every decision explicitly
returns accepted=false and does not evaluate or manufacture runtime evidence.

All 23 offline matrix tests, static inventory checks and diff checks passed.
No runner, coverage status, cluster topology or production setting was changed.
The existing flannel cluster remains preserved pending explicit approval for a
serial Calico replacement/run/restoration procedure. Baseline Linux 5.10 and
all outstanding release acceptance requirements remain open.

## Continued release goal — valid plaintext probe packet correction

At `67d5a6a`, the fixed plaintext GENEVE diagnostic now has a valid inner IPv4
header checksum, nonzero UDP ports and correct UDP/IP lengths. Tests validate
both inner and outer checksums/lengths and the fixed 92-byte frame. The payload
is a UDP diagnostic addressed to the owned gateway, not an HTTP marker request;
no marker-delivery conclusion follows from this packet alone.

With unchanged production guards and NetworkPolicy, the serial encrypted fixture
again measured sent=3, gateway eth0 ingress=0, gnv0 ingress delta=0 and INPUT guard
counter delta=0. The runtime failed at plaintext-denial and performed owned
cleanup. It remains an unverified gateway-ingress/drop gate, not a successful
rejection proof. No policy, capability, runtime or cluster topology was changed.
All 93 advanced and 169 synthetic Python tests and diff checks passed. The prior
malformed test payload is corrected, but no mandatory gate is promoted to PASS.

## Continued release goal — production DNS socket proof and staging refusal

At `2f64ee7`, privileged disposable-namespace tests call the production DNS
exchange path over UDP and TCP. External queries use the marked upstream0
socket path; cluster queries use a separate path. Removing upstream0 does not
cause external fallback to a foreign route or cluster resolver. No production
code or host/cluster settings changed. This is component socket evidence, not
full live-CNI gateway DNS acceptance.

At `ea67063`, hack/prepare-release.py is a deliberately non-writing preparation
guard. It checks the mandatory ledger before artifact/output operations and
currently returns BLOCKED because release acceptance is incomplete. Even an
all-PASSED synthetic ledger cannot stage artifacts: reviewed artifact verification
is not implemented. This tool is not a completed staging implementation and
must not be counted as release-artifact provenance acceptance. No chart version,
release status, artifact, signature, tag, publication or PR was created.

Full Go race/vet/lint/build and privileged components passed, alongside 325
offline Python tests (93 advanced, 169 synthetic, 29 M1, 23 matrix, five platform,
six release-guard tests). Diff checks passed and the source tree is clean.
Outstanding runtime compatibility, Linux 5.10, plaintext ingress and artifact
verification requirements remain open; cluster replacement approval is pending.

## Continued release goal — read-only candidate artifact integrity

At `0f9283a` and `502486e`, the offline artifact validator checks an exact
29-role candidate manifest: ten architecture-specific component binaries, one
chart, six multiarch OCI archive names, and paired SBOM/provenance claim files.
It binds source/version and optional independently reviewed manifest digest,
checks bounded file sizes and streaming SHA256 through no-follow regular-file
FDs, rejects unsafe paths/symlinks/hardlinks and in-place mutations, and validates
structural claim subjects. Duplicate JSON keys and nonstandard numeric constants
are refused, including nested provenance claims.

This verifies metadata and file-byte agreement only, not OCI contents, signature
trust, build provenance or release readiness. The validator does not copy,
extract, build, stage, publish, sign or push anything. The preparation guard
remains blocked on incomplete acceptance and unimplemented reviewed attestation
policy; no real candidate artifacts were generated during this slice.

Full Go race/vet/lint/build and privileged checks passed with 334 offline Python
tests (93 advanced, 169 synthetic, 29 M1, 23 matrix, five platform, 15 release).
The working tree is clean. Actual Calico execution approval, an external Linux
5.10 runner, plaintext ingress and remaining release acceptance are still open.

## Continued release goal — strict read-only OCI archive verification

At `fe17d81` and `04c83d5`, the offline OCI archive verifier checks bounded
uncompressed ustar structure, canonical member paths, regular files only,
header checksums, exact two-platform Linux amd64/arm64 descriptors, blob SHA256
and sizes, config/platform consistency and complete referenced-blob membership.
Duplicate or nonstandard JSON claims are rejected. Links, extended/sparse/device
entries, unknown platforms and unreferenced blobs are refused under this
conservative policy. No archive is extracted or executed.

This is structural/content-addressed verification, not signature trust or build
provenance. The accepted layer descriptors remain opaque blob contents; validating
layer filesystem contents and OCI rootfs diffIDs requires additional reviewed
policy. The verifier is not wired into staging, and no real candidate artifact
was created, copied, signed, tagged or published. Mandatory acceptance remains
OPEN/PARTIAL and the release guard still blocks.

Full Go race/vet/lint/build and privileged components passed, alongside 342
Python tests (93 advanced, 169 synthetic, 29 M1, 23 matrix, five platform,
23 release). Diff checks passed and the working tree is clean. Calico runtime
replacement approval, external Linux 5.10 resources and plaintext ingress
acceptance remain pending.

## Continued release goal — bounded layer streams and rootfs binding

At `6cf75fb` and `55bf650`, OCI verification additionally hashes exact
uncompressed tar layer streams and checks positional config rootfs diffIDs.
Expanded bytes and member counts are bounded; malformed gzip, negative sizes,
unsafe paths, duplicate members, links, devices and extended tar headers are
rejected. Empty regular files and directories are permitted. This conservative
policy supports uncompressed/gzip layers only; zstd and link-containing images
remain refused pending reviewed support. Some legitimate image layouts may
therefore be rejected, not falsely certified.

Full Go race/vet/lint/build and privileged checks passed alongside 346 Python
tests (93 advanced, 169 synthetic, 29 M1, 23 matrix, five platform, 27 release).
Chart packaging/security checks also passed. No archive was extracted or staged;
no signature or trusted build-provenance verification is claimed. Runtime
compatibility approvals, Linux 5.10 resources and plaintext ingress remain open.

## Continued release goal — sanitized failure-transition Events

At `65a33ac`, controller reconcile failure reporting uses fixed authored reasons
and public messages instead of underlying error text in Events, status conditions
and logs. Unknown reason inputs map to a generic category. Warning Events emit
only after successful status persistence for a new failure transition; identical
resyncs do not produce additional Events. Tests cover changed reasons, recovery
followed by failure, private-text exclusion, failed status writes and ordinary
pending health behavior. No runtime resource or privilege changes were made.

Full Go race/vet/lint/build and privileged checks passed alongside 346 Python
tests. This is component validation; the updated controller image has not been
runtime-deployed in this slice. It does not complete all failure Events or the
full observability gate. Remaining compatibility approvals, Linux 5.10 resources,
plaintext ingress and trusted release artifact verification are still open.

## Continued release goal — deployed sanitized controller verification

The authored controller failure callsites were audited against the fixed safe
reason vocabulary; all existing block/failure categories remain represented.
A current-source controller binary containing `65a33ac` was compared with the
local image before import and an existing Deployment rollout. The unchanged
flannel same-workload gateway replacement fixture then completed with exit
4 / PARTIAL, fresh healthy traffic and verified owned namespace cleanup.
Controller race/vet/lint and 93 advanced tests passed after deployment.

The image-build wrapper emitted its successful binary comparison but ended with
signal 143; it is not recorded as a clean aggregate build-task exit. The separate
Deployment rollout and runtime fixture completed normally. This confirms the
privacy-safe controller preserved this scoped runtime path, not every failure
Event or full compatibility. No topology/security changes or release artifacts
were made; mandatory gates and pending approvals remain unchanged.

## Continued release goal — outage environment and deterministic metadata control

At `bb79cb9`, the outage fixture and source no-egress collector accept the same
immutable owner Environment. Mixed owner/API contexts and nodes are rejected
before Docker or root-helper operations. Flannel remains the default; no public
Calico outage runner or alternate-CNI acceptance was enabled.

The existing flannel witnessed healthy/outage/recovery runner completed with
exit 4 / INCOMPLETE and verified cleanup. Full validation initially failed at
an unprogrammed metadata-fixture DNS positive control. The disposable veth test
now pins both neighbor entries (`e432c0a`), eliminating initial ARP resolution
as a timing dependency. The exact cause of that single timeout is not proven;
no production networking behavior was changed. Ten metadata-test repetitions
and the subsequent full privileged suite passed.

Final Go race/vet/lint/build and privileged checks passed, together with 352
Python tests (93 advanced, 174 synthetic, 29 M1, 23 matrix, five platform,
28 release). Calico replacement approval, external Linux 5.10 resources,
plaintext ingress proof and artifact trust requirements remain open. No cluster
was replaced and no release artifact was staged or published.

## Continued release goal — existing-Calico witnessed-outage entrypoint

At `18ebcea`, a separate explicit opt-in entrypoint reuses the reviewed
existing-Calico preflight and invokes the environment-bound UID-owned witnessed
outage/recovery fixture. It never provisions or replaces a cluster, installs a
CNI, changes a release or awards full matrix acceptance. The healthy Calico CLI
and default flannel behavior remain unchanged. Its success exit is 4 / INCOMPLETE.

All 178 synthetic and 93 advanced offline tests, static synthetic contracts and
diff checks passed. No Calico runtime was executed; current flannel resources
were preserved. Actual compatibility acceptance still requires explicit approval
for the serial cluster replacement/restoration plan and a successful runtime.
Linux 5.10, plaintext ingress and trusted artifact requirements remain open.

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

## October 30, 2026 — bounded real synthetic OpenVPN Gateway, partial only

On the existing three-node flannel/no-mesh cluster, the operator's locally
built controller image was imported and rolled to the trusted private
`GATEWAY_UPSTREAM_PROBE_URL=http://10.88.0.1:8080/exit`; the running controller
was 1/1 Ready and agent DaemonSet 3/3 Ready. Three locally built fixture images
(server, independent witness, restricted selected helper) and the required
local plugin/tools images were imported into **all three existing nodes**.
The guarded read-only preflight compared exact container runtime config IDs
for six fixture/gateway/plugin tags on every node, plus immutable running
controller/webhook/agent image IDs; it returned INCOMPLETE without mutation.
No registry push, host VM change, new cluster or public probe was used.

The separate **four-gate**, UID-scoped partial smoke then generated fresh
short-lived synthetic CA/server/client/witness keys under an outside-repo 0700
private directory and created only eight base resources in two fresh namespaces:
three Secret fixtures, non-secret probe ConfigMap, actual OpenVPN server Pod,
UDP-only Service, controller-created EgressGateway and EgressPolicy. Early
bounded runs failed while exact fixture assertions were repaired; each run
removed both namespaces and private PKI. Runtime sampling exposed the real
server and upstream containers becoming Ready, measured Gateway MTU conditions
and an owned gateway Deployment; the harness, not the production datapath,
incorrectly expected `PodList`/`EndpointSliceList` whereas `kubectl get -o json`
returned `List`. `09a987b` fixed those strict, still owner-verified checks.

With rebuilt/imported trusted images and the corrected harness, the final
partial smoke **PASSED its own bounded assertions** in 48 seconds but returned
**INCOMPLETE / exit 4 by design**: it verified exact CREATE-returned UIDs,
real server Pod/UDP EndpointSlice target identity, controller-managed
Gateway→Deployment→ReplicaSet→Pod and owned Service/ConfigMap/NetworkPolicy,
Gateway Ready/current generation/measured MTU/healthy endpoint, exact private
plugin probe args, immutable gateway/plugin/server runtime image IDs, and a
sanitized authenticated OpenVPN server session for the gateway's distinct
synthetic client with positive received/sent bytes. Both UID-owned namespaces
and the temporary private PKI directory were confirmed absent afterward.
No selected workload or witness Pod was created by this partial smoke, so
**restricted agent traffic, fail-close, recovery, DNS/API preservation, full
M8 compatibility, and release readiness remain untested**. Actual live VPN
profile is still unset and remains SKIPPED, not passed.

## October 30, 2026 — restricted agent runtime blocked by sandbox netns access

The guarded partial smoke was extended with a **single restricted one-shot
selected Pod** (`34f5d65`). It uses the production capability-free wait-init,
locally imported immutable helper image, public CA-only API TLS checks, and
CREATE-returned Pod UID. The real synthetic OpenVPN server and controller-
created Gateway again reached healthy/Ready with measured MTU, but the selected
Pod remained **Pending** with its wait-init running, `datapath-ready=pending`
and no agent configuration; no selected traffic or helper exit was observed.
Every attempt verified deletion of both temporary namespaces and private PKI.

Without changing permissions, `816ad5a` and `b65c99f` added fixed operation
labels around agent sandbox/guard/programming errors. The existing three-node
agent DaemonSet remained 3/3 Ready after the updated image was imported and
rolled. A subsequent bounded run still failed its selected-Pod checkpoint;
agent errors were classified, without printing Pod identity, CRI info or
credentials, as **`verify sandbox network namespace: open verified sandbox
netns: open sandbox PID network namespace: permission denied`**. This is the
`/proc/<CRI sandbox PID>/ns/net` open in `pkg/agent/sandbox_linux.go`; it occurs
after the CRI UID/IP and cgroup UID checks and before any selected-netns
programming or readiness marker. A healthy Gateway therefore does **not** imply
agent-mode workload traffic works on this host/runtime.

A reviewed fallback to `stat` on that proc namespace symlink was **rejected**:
its dereference is subject to the same access check, while `lstat` does not
identify the network namespace. Adopting the separate CRI-reported netns path
without independently proving its identity against the sandbox PID and
excluding host/self namespaces would weaken the agent's fail-closed ownership
contract. No `SYS_PTRACE`, privileged Pod, host permission change, cgroup
bypass, unverified netns adoption or guessed readiness was introduced. Agent
traffic, fail-close, recovery, WireGuard runtime and M8/M9 remain **blocked**
until a safe, race-resistant identity/access model is designed and tested on
the required runtime/kernel matrix. Live provider profile remains absent and
SKIPPED.

## October 30, 2026 — pidfd sandbox proof and remaining host-PID1 guard blocker

An isolated, disposable Go probe on both existing k3d agent nodes confirmed
that the current kernel can `pidfd_open` a CRI sandbox, transiently
`setns(pidfd, CLONE_NEWNET)`, match the calling thread's namespace inode to
an open, contained CRI netns path, and restore the original thread namespace.
`d391d50` implemented this as a **fail-closed agent alternative** to opening
`/proc/<sandbox PID>/ns/net`, without increasing chart capabilities or adopting
a path on trust alone. Scoped race/lint/vet/build and privileged component
checks passed. No Linux 5.10 runtime result is claimed.

A real, four-gate selected-Pod smoke after the imported agent rollout remained
**FAILED**: the Gateway/server still reached Ready and authenticated OpenVPN,
but the capability-free wait-init did not complete and the selected Pod stayed
Pending. Fixed-category errors narrowed the next denied operation to the
separate **host PID1 namespace** guard, which still needed proof that the CRI
path was not the host network namespace. `26799a4` replaced direct
`/proc/1/ns/net` dereference with a pinned PID1 transient namespace comparison,
again with locked-thread restoration and no privilege expansion. Its unit and
privileged component checks passed, but a further real smoke still **FAILED**:
`setns(pidfd(PID1), CLONE_NEWNET)` was denied by this runtime, before agent
programming. Every attempted fixture was removed with both namespaces and
private PKI absent afterward; the existing operator controller/webhook and
agent DaemonSet remained healthy. No selected traffic PASS is claimed.

A security review found only a **conditional** route past that guard: pin the
agent's own startup host-network namespace and verify its own Pod UID,
namespace/name, node, ServiceAccount, `hostNetwork=true` and `hostPID=true`
through trusted kubelet/API identity before treating that pinned namespace as
the host namespace. This is a *trust-model change*, not an independent kernel
measurement of PID1. If the runtime violates hostNetwork semantics or an
untrusted privileged deployment exists, it is not equivalent to the current
PID1 check. Do not silently remove the guard or add `SYS_PTRACE`/privileged
mode. The restricted agent runtime gate remains **BLOCKED** pending an approved,
explicit host-namespace trust contract (or another safely accessible trusted
host-netns handle), tests on the deployed runtime and Linux 5.10, then full
selected/fail-close/recovery validation.

## October 30, 2026 — authenticated self-anchor tested; sandbox pidfd still denied

The agent's own Pod is now bound to Downward API namespace/name/UID/node and
verified by an uncached API GET with the expected ServiceAccount, hostPID,
hostNetwork and non-deleting identity (`4b3a00c`). A pinned startup thread
netns replaces the PID1 check **only under the explicitly documented trusted
kubelet/API hostNetwork contract**; it is not independent PID1 kernel
attestation. Every candidate remains openat2-confined, rejects the pinned host
namespace and must match the pinned sandbox PID via transient pidfd `setns`;
there is no path-only adoption, chart capability expansion or bypass.
Privileged tests initially exposed an unanchored old test setup and were
corrected in `8ae745d`. Race, lint, vet, build, chart and privileged component
checks passed. The updated image was imported and the same-privilege agent
DaemonSet rolled 3/3 Ready with all four identity fieldRefs.

A bounded real final-gate retry nevertheless **FAILED** after the healthy
controller-created synthetic OpenVPN Gateway and authenticated session:
selected restricted Pod stayed Pending with wait-init running. The agent's
fixed-category errors now pinpoint `corroborate CRI path with pinned sandbox
PID: enter pinned process network namespace: operation not permitted`.
The current kernel's pidfd `setns` validates ptrace read access to the target
process; the actual agent lacks that access despite existing NET_ADMIN and
SYS_ADMIN. A node-container probe working outside the production container
security context was therefore **not** proof that this operation was allowed
inside the agent. Do not grant SYS_PTRACE, disable seccomp, trust an uncorroborated
CRI path, fake readiness or claim selected traffic. Both fixture namespaces and
private PKI were removed after the failed run; controller/webhook were 1/1
Available and agent 3/3 Ready. A revised, independently verifiable namespace
identity design—or a separately reviewed privilege policy—is required before
M5 agent traffic, M8 compatibility or M9 release can pass.

A further read-only Linux API review found **no independent PID→network-namespace
comparison available to this agent under the observed access policy**. Opening
or dereferencing `/proc/<sandbox PID>/ns/net` requires the denied ptrace-read
check; `setns(pidfd, CLONE_NEWNET)` was denied in the actual agent; `pidfd_getfd`
needs a stronger ptrace-attach check. nsfs and rtnetlink can characterize an
already-open CRI namespace FD but cannot establish that the sandbox PID belongs
to it. The remaining choices are to retain fail-closed rejection, review a
permission/runtime change, or explicitly authorize a **different trust
contract** in which the node's CRI asserts sandbox-ID→netns-path ownership.
That last option must not be described as independent PID corroboration; it
would require strict READY sandbox UID/IP and cgroup checks, exactly one
openat2-confined network namespace FD (validated with nsfs type), host-anchor
exclusion, PID liveness and in-netns Pod-IP/link validation, plus targeted
adversarial tests. No such trust-contract switch has been implemented or used
to award traffic coverage.

`ddb0ddf` added a second zero-label, loopback-only gateway gauge for measured
effective MTU (0 when unready/unknown). Focused race tests, lint and vet
passed; flow counts, live peers, handshake age and external scraping remain
unimplemented, so this does not finish M7/M8 observability acceptance.

## October 30, 2026 — separate init-driver runtime remains blocked

A separately gated, **nonrestricted init-driver** partial smoke was run on the
existing flannel/no-mesh cluster with the release temporarily rolled to
`driver=init`, `datapath=iproute`. The synthetic OpenVPN server and
controller-owned Gateway again reached the healthy baseline, but the selected
Pod's production `ratatoskr-init` container exited **1** before its application
started. This is not a selected-traffic PASS. The runner reported FAILED, not
INCOMPLETE-as-success, then removed both UID-owned namespaces and temporary
PKI. The operator release was restored to `driver=agent`: controller and webhook
were 1/1 Available and agent 3/3 Ready; no synthetic namespace remained.

A follow-up with an init image containing **only fixed-stage error labels**
repeated the bounded, explicitly gated partial test. An independent observer
read the failing init container's output privately and emitted only allowlisted
categories: `init exit 1` and **`client fallback`**. This places the observed
`operation not permitted` at the first `RouteReplace` of a fail-closed
unreachable route in the selected Pod's private policy table, before nft,
GENEVE, the marker request, or application startup. The immutable diagnostic
image ID was checked in the runtime preflight; it has not been promoted to a
release image. The diagnostic test also failed and cleaned up; release
restoration again yielded controller/webhook 1/1 and agent 3/3. The image's
configured user is 65532; the webhook grants the init container `NET_ADMIN`
but does not override that image user. The exact kernel/container-runtime
reason `RouteReplace` is denied has **not** been independently proved. No
privilege, capability, sysctl, seccomp or Pod security context was loosened
as a speculative remedy. Separately reviewing a tightly scoped init execution
identity change would be necessary before rerunning this coverage; it cannot
resolve the distinct agent sandbox-pidfd blocker or substitute for restricted
workload traffic. M8 and M9 remain blocked, and the absent live VPN profile
remains SKIPPED.

## October 31, 2026 — user-reported runtime change retested, not yet effective

Following the user's report that the blocker was fixed, a fresh read-only
preflight confirmed the **existing** three-node flannel cluster, Ready
controller/webhook (1/1 each), agent DaemonSet (3/3), agent/iproute chart
values, and all nine explicit release/fixture image IDs including exact CRI
config-digest mappings on every node. The checkout was unchanged; no agent
privilege or trust-contract change was made. The guarded, UID-owned real
synthetic OpenVPN smoke was retried with the same partial-only admission and
image gates. Gateway baseline again advanced far enough to CREATE the selected
Pod, but the selected Pod did **not** reach successful one-shot traffic; the
runner failed at `selected-pod-status` and returned exit 1 after attempting
UID-owned cleanup. Both synthetic namespaces and private PKI were verified
absent afterward, and controller/webhook remained 1/1 with agent 3/3.

A bounded read-only classification of recent agent logs, never displaying raw
logs, found the unchanged failure on the server node: 90 recent instances
of `corroborate CRI path with pinned sandbox PID` / `enter pinned process
network namespace: operation not permitted`. The other two agent nodes had
none in the same recent sample. This **does not prove** what host/runtime
change the user attempted, but it proves the existing production agent
security context still cannot pass this particular selected-Pod namespace
check on the observed node. Until an effective, independently verified runtime
change or an explicitly approved trust-contract revision exists, no selected
traffic, M5 runtime acceptance, M8 compatibility, or M9 release PASS is
claimed. The live VPN profile remains absent/SKIPPED.

## October 31, 2026 — stock RuntimeDefault CRI authority experiment remains inconclusive

The user clarified that their prior change only allowed firewall traffic. On the
unchanged-security production DaemonSet, `setns(pidfd, CLONE_NEWNET)` still
requires a target-process access check and cannot be fixed by packet egress
permissions. To test a stock-runtime path, `fcd75cf` changed the agent to
**explicitly trust the authenticated node CRI's sandbox-ID→netns-path mapping**,
not to claim the former independent PID→netns kernel proof. The candidate path
must be an exactly-one, openat2-confined, nonhost nsfs network-namespace FD;
the READY sandbox ID, namespace/name/UID/PodIP, live PID, Pod-UID cgroup, path
and FD inode are rechecked, and target `eth0` must uniquely own that IPv4
before programming. Full Go race/lint/vet/build and privileged component checks
passed. The built agent was imported locally and rolled 3/3 Ready under the
**same** NET_ADMIN/SYS_ADMIN, nonprivileged RuntimeDefault context. This is a
change in trust boundary: a compromised CRI that consistently lies about the
sandbox-to-path mapping remains outside the agent's independent proof. Linux
5.10 and other CNI/runtime semantics are not yet accepted.

The first guarded real selected-Pod retry on that image failed with `CRI path
does not name an nsfs namespace` on its assigned node; the positive Gateway
baseline ran but no selected application traffic passed. Node-side existing
namespace mounts reported nsfs. This did not establish what a freshly created
sandbox path looked like inside the long-lived agent mount namespace. The chart
previously mounted `/var/run/netns` read-only without child mount propagation.
A chart-only experiment added **one-way HostToContainer** propagation solely to
that read-only mount (no capabilities or privileged mode), rendered with static
security assertions, and rolled the agent 3/3 Ready. An initial retry raced
that rollout and was blocked at the immutable-image preflight without creating
fixture resources. A settled, preflighted retry again failed at selected-Pod
status and cleaned both UID-owned namespaces/private PKI. Subsequent bounded
agent log classification saw `matching ready sandbox unavailable` while the
fixture was already removed; it did not capture the precise fresh-namespace
error. Existing child nsfs mounts are visible in the current agent mountinfo,
but that does **not** prove propagation for a new child created after startup.
The one-way chart change must not be counted as a traffic fix without a
correlated fresh-sandbox observation. Controller/webhook remain 1/1 Available,
agent 3/3 Ready, and the release remains agent/iproute. M8/M9 are incomplete;
live VPN input is absent/SKIPPED.

## October 31, 2026 — fresh namespace propagated; agent Pod starts app, traffic still fails

A subsequent fresh UID-owned retry was observed while the selected sandbox
existed. The same selected Pod had **one matching READY CRI sandbox**; both node
and current agent mount namespaces reported `nsfs` magic `6e736673` for its
single reported network namespace bind mount. This supports that the chart's
one-way propagation exposed that *fresh* child on this k3d node, without
relaxing the nsfs/type guard. The Pod progressed `Pending → Running → Failed`.
A tightened status-only fixture then retried once more, returning within the
bounded run with **`selected-pod-status-app-failed`**: the restricted wait-init
completed sufficiently for the nonroot/capability-free application to run, but
the application exited nonzero. The exact application subcheck (marker versus
DNS/API TLS/direct route) was deliberately not logged and remains **unknown**.
The agent logs inspected after namespace cleanup contained only stale
`matching ready sandbox unavailable` retries, not reliable attribution for the
live packet failure. It would be incorrect to claim selected VPN traffic or
fail-close from a running or failed app. Both fixture namespaces and private
PKI were removed, the existing release remained agent/iproute and agent 3/3
Ready. Full component tests, chart/static checks and 118 synthetic fake tests
passed for this code; M8/M9 acceptance and live VPN input remain incomplete.

## October 31, 2026 — selected traffic diagnostic, not a PASS

Further gated, UID-owned restricted-agent retries on the same three-node
flannel cluster with unchanged security context advanced the synthetic
selected Pod through the capability-free wait-init and into its nonroot app.
The initially strict direct Kubernetes API check failed **before** the tunnel
marker: public-CA-verified TLS connected, but the API returned HTTP **401**
for a tokenless request instead of fixture-required 403. Kubernetes permits
401 when anonymous authentication is disabled; the helper now accepts **only
exact 401 Unauthorized or 403 Forbidden** after CA/SNI verification, without
projecting an API token or treating any successful response as proof. Follow-up
real selected Pods then passed that direct check but still **failed** the
selected marker check. Fixed exit categories (no request bodies, profile,
errors or Pod logs) narrowed this to a **TCP connect timeout** to the tunnel
marker `10.88.0.1:8080`, before any HTTP response. This is not a verified
healthy VPN flow and not a fail-close proof. A bounded independent observation
saw the controller-managed gateway's selected-client allowlist grow from
zero to one, with the Pod's agent readiness progressing from pending to true;
those facts do not establish GENEVE delivery, gateway anti-spoof acceptance,
return-path routing or marker reachability. Later count-only packet sampling
was inconclusive and no route, firewall, privilege or probe bypass was made.
Both fixture namespaces/private PKI were verified removed after each run;
the release stayed agent/iproute with agent 3/3 Ready. The updated no-leak
fixture passed 123 fake tests plus chart/YAML/matrix static checks; full Go
race, lint, vet, build and privileged checks passed. The 96-cell M8 matrix
and live VPN tier remain incomplete/SKIPPED respectively, and M9 publication
remains withheld.

## October 31, 2026 — selected GENEVE egress observed, return remains unproved

A test-only, nonroot and capability-free helper added a **read-only**, capped
counter check for `/sys/class/net/rtk0/statistics/tx_packets` around its
selected marker TCP connect. Exact immutable image IDs were rechecked on all
existing nodes for each guarded real retry. The helper reported a **positive
GENEVE TX delta while its TCP connect timed out**. This proves the attempt
reached the selected GENEVE link, not that a packet reached or passed the
gateway, traversed the VPN or returned. The exact marked client FIB lookup
resolved to `rtk0`, while the unmarked lookup for the same target resolved to
`eth0` as expected for inclusion-only policy; the public-CA direct API path
still completed. The controller-managed Gateway ConfigMap's allowlist grew
from zero to one client and the UDP6081 NetworkPolicy's selector matched that
selected namespace/Pod. No security restriction was disabled.

During one status-only gateway sample, `gnv0` TX *drop* counters increased
while RX packets remained zero. An early read of return table 101 saw only
the fail-closed unreachable fallback; repeated external observations did **not**
capture a trustworthy post-allowlist return-route state before fixture cleanup.
These counters are not synchronized same-packet proof and must not be used to
attribute a specific drop to the selected flow. Host TC/outer UDP header
sampling was inconclusive. An 8-second **test-only** failed-app hold was
tried solely for read-only inspection and then removed; the helper again exits
promptly with its original nonzero failure code. Neither a speculative route,
firewall, privilege nor overlay change was made. Both UID-owned namespaces
and private PKI were verified removed, release remained agent/iproute with
agent 3/3 Ready. A deterministic return-route/flower/outer-header trace tied
to the *same selected packet* is required before a datapath correction or
M8/M9 claim. The live VPN profile is still absent/SKIPPED.

## October 31, 2026 — packet capture and applied-configuration startup fix

A bounded passive tcpdump-equivalent investigation used existing host tools
inside the existing k3d node network namespaces. Only UDP6081 header summaries
were parsed in capped memory; no pcap or packet bodies were retained. The exact
selected-client → gateway tuple was observed 15 times on both source and gateway
nodes, with no reverse tuple in that capture. A later same-fixture gateway
sample observed `gnv0` RX grow from 0 to 5. This disproved a blanket claim that
Flannel or the external firewall prevented all delivery. The controller's API
ConfigMap then contained one client, but the **actual gateway container's**
projected `/config/gateway.json` still contained zero and return table 101 had
only its unreachable fallback. The agent's local ready marker was premature:
upstream health does not acknowledge that a newly selected client is installed.
A temporary fixed sleep was tested and removed; no production sleeps or runtime
patches were used as a remedy.

The integrated startup protocol now hashes the exact validated bytes read from
one gateway ConfigMap file descriptor and publishes that digest only after a
successful datapath application. Read/probe/apply failure revokes the proof;
failed application retries even when desired bytes are unchanged. The controller
binds `/info.podUID` to its verified Pod→ReplicaSet→Deployment→Gateway ownership
chain and publishes endpoint-specific `podUID` and `appliedClientConfigHash`
only when the applied hash matches its current desired ConfigMap. Upstream health
and measured MTU remain independent of a missing client acknowledgement. The
agent uses existing live Pod GETs plus newly documented ConfigMap GET permission
to check exact endpoint UID, owner-controlled ConfigMap, raw digest and its PodIP
membership. While acknowledgement is missing or stale it applies the unreachable
client path, removes the ready marker and leaves the workload pending; ordinary
projection lag does not make the DaemonSet unready. No additional Linux capability,
privileged mode, workload API token, or runtime/seccomp change was introduced.

After locally rebuilding/importing gateway/controller/agent images, updating the
optional CRD status schema and completing the operator rollouts, a restricted
selected workload progressed Pending → Running → Succeeded. Initial harness
rejection was independently traced solely to Kubernetes defaulting
`fieldRef.apiVersion` to `v1`; the assertion now accepts omitted or exact `v1`
while rejecting any other version or field path. The final guarded partial
OpenVPN smoke passed its inner owner/status/session and selected one-shot checks:
exact tunnel-only marker, public-CA anonymous API TLS denial and direct DNS/API
route checks, exit 0, current agent routing configuration, and supporting server
session counter growth. It deliberately returned **4 / INCOMPLETE**, not a full
M8 PASS: counter growth alone is not packet attribution, and witness, withdrawal,
recovery, WireGuard, HA, other CNI/mesh cells and Linux 5.10 remain unaccepted.
Both UID-owned namespaces and private PKI were verified removed. Full integrated
Go race/lint/vet/build/privileged checks passed before deployment; the updated
synthetic evidence suite passed 125 fake tests. The live VPN profile remains
absent/SKIPPED and no release was published or signed.

## October 31, 2026 — supplied live VPN, tokenless Germany subset passed

The operator supplied external `openvpn.ovpn`, CA/client certificates, matching
private key and two-line login file. Private preflight verified certificate
validity, client key matching and CA verification without printing material.
The live bundle normalizer staged five fixed-name files under an outside-repo
0700 directory with 0600 permissions, leaving the originals untouched. No
IPinfo token was supplied or used; expected country was normalized to **DE**.
The M1 live lifecycle now uses independent random namespace/owner identifiers,
a single CREATE-returned UID and UID-preconditioned cleanup, rather than
name-only adoption/deletion. Offline race and replacement tests passed.

On the existing three-node flannel/no-mesh cluster, the explicitly authorized
final-gate **direct-config init/iproute live subset** passed: mandatory lifecycle
preflight/topology, secret creation, direct baseline, gateway readiness, client
steering, cluster-path preservation, measured MTU, private healthy metric and
public exit/country check. Tokenless IPinfo returned usable evidence and the
DE country assertion passed; raw provider/credential logs were suppressed.
The inner runner exited 0 with status passed, and namespace/Secrets cleanup
passed. This is NOT the full M8 matrix or the exact original live checklist:
live failure injection was explicitly SKIPPED; no HA, mesh, alternate CNI,
WireGuard, provider disruption or complete release acceptance is inferred.
The prior missing-input skip no longer applies to this supplied-profile subset.

Additional component commits add bounded kernel-measured WireGuard aggregate
peer/handshake/byte gauges with explicit unavailable sampling, root-UID only
for the NET_ADMIN programming init (restricted agent wait-init unchanged),
authenticated writers for agent-owned annotations, and CRI-verified sandbox
quarantine on failed authorization reads. These component fixes require final
integrated runtime acceptance; they are not substitutes for those tests.

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
