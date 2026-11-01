# Advanced M4/M7 acceptance authoring (offline)

This directory adds a **cluster-free** strict acceptance predicate for one
`driver=agent`, `datapath=iproute`, `encryption=wireguard` lifecycle and a Go
unit contract for sticky endpoint choice across 1–3 healthy replicas. Neither
runs a workload, uses credentials, reads Secrets, changes a cluster, or provides
traffic-gate evidence. No matrix cell is marked covered by these synthetic tests.

Run offline only:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/advanced -p 'test_*.py'
go test ./test/e2e/advanced
```

## Existing selected Pod after singleton Gateway Pod replacement (authored, not executed)

`agent_lifecycle.py` is a separate, explicit final-gate **partial** fixture for
`driver=agent`, one plaintext gateway replica and one long-lived restricted
selected Pod. Its import and ungated CLI never access the cluster. A parent
operator must first preflight the same locally built images, release and flannel
context as the existing synthetic fixture; no DaemonSet restart or Helm change
is made by the runner. Only with parent approval, the immutable image-ID
preflight, and both `RATATOSKR_E2E_FINAL_GATE=1` and
`RATATOSKR_E2E_AGENT_GATEWAY_REPLACEMENT=1`, invoke
the following command:

```sh
python3 test/e2e/advanced/agent_lifecycle.py --execute --execute-agent-gateway-replacement
```

The runner creates disposable UID-owned namespaces and exact synthetic objects,
checks owner-linked one-replica Gateway status, the exact applied
`gateway.json` hash and selected Pod UID/config, executes the fixed healthy
direct-API/marker probe, and performs **one** five-second-grace,
UID-preconditioned delete of that verified fixture Gateway Pod. It waits for a
new Gateway Pod UID **and IP** with a fresh applied-config hash and the
unchanged selected Pod UID, updated endpoint, UP marker and fixed healthy
probe. Missing/stale acknowledgements and replaced selected Pods cannot qualify.
It always returns partial/incomplete, not full matrix PASS, and makes no
assertion about established-flow continuity, WireGuard or agent restart.

The gate reports only fixed non-secret checkpoint labels on failure, such as
`gateway-baseline/gateway-owner`, `gateway-baseline/gateway-applied-hash`,
`selected-ready/selected-readiness`, `gateway-delete/blocked`, or
`replacement-ready/gateway-applied-hash`. These identify the last bounded
observation, **not** the underlying Kubernetes response or a successful
runtime verification. Errors and private API responses remain suppressed;
cleanup failure still prevents a partial result.

### Optional passive agent Pod restart observation (authored, not executed)

With the same parent-approved release and Gateway fixture, set
`RATATOSKR_E2E_AGENT_RESTART=1` and add `--wait-external-agent-restart` to the
command above. After the Gateway replacement has passed, the runner verifies
that the still-running selected Pod is on an approved node and that exactly one
Ready release agent Pod on that node is owned by the preflight-pinned DaemonSet
UID and runs the pinned agent image. It then prints the fixed, flushed `READY:`
line.
**The runner does not delete any agent Pod or change the release.** Only the
parent, under its separate authorization, may perform an exact-UID,
preconditioned deletion of the verified agent Pod. The runner waits at most
150 seconds within the owned fixture deadline for a different, Ready agent Pod
UID on that same node, still owned by the same DaemonSet UID and running the
same immutable image. It then rechecks the selected Pod UID, Gateway endpoint,
applied-config hash and fresh fixed healthy marker/direct-API probe before
reporting the separate `agentRestartObserved` partial result. If no external
restart happens, or any required identity/probe fails, no restart claim is
awarded. No established-flow continuity is asserted.

## M4/M5 integration contract (not an executable live runner)

A future **parent-authorized final-gate collector** must construct a dictionary
for `wireguard.validate(evidence)`. Its four ordered stage objects are
`registered`, `plain`, `authenticated`, and `revoked`; see `test_wireguard.sample`
for the complete schema. The identity object binds the exact selected client
Pod UID/PodIP, gateway Pod UID/PodIP and GatewayID. Every stage must be measured
against that same identity and a fresh marked attempt, and the collector must
record packet identity (not counters alone) to prevent unrelated traffic from
satisfying checks. Samples in unit tests are fabricated and MUST NOT be reused
as evidence. Never serialize tokens, private keys, raw TLS material, packet
payloads, or provider logs in evidence.

The final-gate owner must explicitly approve a compatible existing release,
agent/iproute driver, CNI/network policy, a disposable selected Pod and a
gateway with a safe fake upstream or separately approved profile. It must
verify Pod-bound TokenReview audience/UID, authenticated TLS with pinned
controller-attested gateway identity, `/32` WG peers/routes and agent marker;
in a **controlled forged-packet test** prove that plaintext outer GENEVE UDP/6081
arrives on gateway eth0 and is dropped before gnv0/delivery; then prove a
separate authenticated selected marker travels over WG with peer counters and
no plaintext UDP/6081 on the underlay; finally opt out/delete the disposable
Pod or exercise TTL and verify peer removal, route withdrawal, unreachable
fallback and failure of a fresh selected attempt without baseline escape.
A forged plaintext packet must never be sent outside this explicitly approved
isolated fixture; passive observation alone cannot prove rejection. Match the
outer PodIPs, VNI/inner source, protocol, interface, and marker correlation in
the collector—the predicate is not a capture parser. Capture must be header-only.

Later, separately gated flannel/no-mesh agent/iproute fixtures observed a
UID-owned synthetic WireGuard peer lifecycle, fresh-connection two-replica HA,
and witnessed outage/recovery with header-only selected-destination capture.
An independent memory-only TokenRequest/TokenReview diagnostic verified the
owned Pod's UID, ServiceAccount and audience; it does **not** observe the
production gateway making its own TokenReview call. The full `wireguard.validate`
contract still lacks plaintext GENEVE packet-denial and actual gateway-call
proof, and broader CNI/mesh/Linux 5.10 traffic acceptance is outstanding.
These partial fixtures do not mark the scenario **COVERED**;
`test/e2e/matrix/coverage.json` remains unchanged. See the dated runtime
observations in `test/evidence/history/runtime-validation.md`.

## Explicit-gated read-only HA observer (live, NOT run during authoring)

`ha_live.py` is an executable bounded **read-only** collector against an
already-approved agent/iproute release with 2–3 healthy replicas, one selected
client Pod and a controller-owned Gateway. It reads only GETs of the named
Gateway, its Deployment, owned ReplicaSets/Pods and the selected Pod. Every
GET is deadline/output bounded; CLI stderr and raw API JSON never enter the
report. It validates UID owner chains, Gateway readiness and applied-config
acknowledgements, the selected Pod's agent config/hash and its pinned gateway
PodIP. It waits up to 90 seconds for an **external operator-owned** withdrawal
of precisely the replica that client chose, and verifies the client reselects
one remaining healthy gateway in two consecutive snapshots. It never scales,
deletes, patches, opens a VPN profile, executes in Pods or accesses a Secret.

The parent/operator must first approve exact existing context, namespace/name
and Pod UID, verify the release, network and safe failover procedure, then
coordinate the replica failure **outside** this collector. No automated failure
injection is provided. Only after that approval, invoke explicitly:

```sh
RATATOSKR_E2E_FINAL_GATE=1 python3 test/e2e/advanced/ha_live.py --execute \\
  --context CONTEXT --gateway-namespace GATEWAY_NS --gateway-name GATEWAY_NAME \\
  --pod-namespace CLIENT_NS --pod-name CLIENT_NAME
```

If the chosen replica does not disappear within the bound or any UID/gateway
identity changes, this exits nonzero. The sole positive report explicitly says
`traffic: not-tested` and `establishedFlowContinuity: not-asserted`; it is **not**
a network/marker/VPN or WireGuard acceptance pass. A full M7 gate still needs
fresh post-failover selected marker delivery and exit-IP evidence from a new
connection, plus a no-endpoint fail-close check. Parent must not award coverage
from this observer alone. The collector does not create/own the Gateway, so
live cleanup and subsequent recovery remain solely with the parent/operator.

## UID-owned two-replica HA traffic fixture (live; never run during authoring)

`ha_fixture.py` is the **separate** executable fixture for an approved existing
three-node flannel/no-mesh agent/iproute release. Unlike `ha_live.py`, it
creates two UUID-named namespaces through the synthetic Lifecycle, generates
fixture PKI in a private 0700 directory, creates one synthetic OpenVPN server,
a synthetic-client Secret, an EgressGateway with **two replicas**, its Policy,
and one long-lived selected Pod. Only the ephemeral fixture server profile adds
`duplicate-cn` so two controller-created gateway replicas can authenticate
concurrently with the same fixture-only client certificate. Production/plugin
images, chart privileges and CNI are not changed. It reuses the same approved
local server and restricted selected app images, the existing release/node
image-ID preflight, `prepare.running_probe_pod`, and `FixtureAPI.probe_running`
from `matrix/synthetic` (requires that shared outage fixture commit).

After two UID-verified controller-owned, healthy and config-acknowledged
replicas are observed, it opens one fresh selected marker TCP connection via
the fixed, output-discarding `probe_running` command. The runner deletes **only
the exact chosen fixture gateway Pod** through the Kubernetes UID-preconditioned
raw DELETE API after rechecking Pod, owner chain and same selected Pod UID.
The exact gateway Pod UID DELETE uses a five-second grace and discards (but
bounds) the API's potentially full Pod response; it never logs or retries an
ambiguous deletion. A subsequent owner/status snapshot must prove the chosen
endpoint gone. Deployment may replace it, but the client's agent config must
select a *previously healthy surviving replica*, and a second fresh marker TCP
connection plus direct API/DNS/TLS checks must pass after stable reselection.
The same synthetic VPN source Pod UID and approved runtime image are checked
before and after the probes. The old established connection is never claimed
to survive and no distinct VPN exit IP is inferred from the shared synthetic
OpenVPN upstream. Initial or post-failover connectivity failure is not a pass.
Both UUID namespace deletions and private-PKI removal are required by the
Lifecycle before the runner can return its **partial** result.

Parent execution is **not approved by this file**. After explicit operator
approval of the existing release and disposable fixture, rebuilt/imported
approved images on all nodes, and immutable image IDs, invoke only:

```sh
RATATOSKR_E2E_FINAL_GATE=1 RATATOSKR_E2E_HA_FIXTURE=1 \\
  EXPECTED_CONTROLLER_IMAGE_ID=... EXPECTED_WEBHOOK_IMAGE_ID=... \\
  EXPECTED_AGENT_IMAGE_ID=... EXPECTED_GATEWAY_IMAGE_ID=... \\
  EXPECTED_PLUGIN_IMAGE_ID=... EXPECTED_SERVER_IMAGE_ID=... \\
  EXPECTED_TOOLS_IMAGE_ID=... EXPECTED_WITNESS_IMAGE_ID=... \\
  EXPECTED_SELECTED_IMAGE_ID=... \\
  python3 test/e2e/advanced/ha_fixture.py --execute --execute-ha-fixture
```

Expected values must be **actual parent-approved immutable runtime image IDs**;
never paste placeholders into a real run. Missing gates exit 2 before API
access; unsafe setup, timeout or unverified cleanup exits 1; successful
*partial* HA traffic evidence exits 4, never full M8 coverage. The runner
requires a parent-monitored 650-second lifecycle plus a bounded cleanup grace;
SIGKILL, API loss or node failure may still need manual orphan inspection.
WireGuard registration, plaintext rejection and peer revoke are **not tested**
by this plaintext synthetic HA fixture.

## HA boundary

The Go test checks deterministic 1–3 endpoint selection, reordering stability,
absence-of-endpoint error and new endpoint selection after removing a chosen
replica. It **does not** establish live endpoint status publication, agent
reprogramming or continued traffic. A future live HA gate must bind each
selected Pod UID to the actual ready PodIP/exit identity, remove one endpoint
under approved fixture ownership, prove that only clients of the failed
replica reselect and can establish **new** connections with the replacement
exit IP, and observe that old connections may break. It must separately verify
fail-closed behavior when no endpoint is healthy. Never assert established-flow
continuity across replica failover.

## Optional plaintext GENEVE denial (separate final-gate opt-in)

`RATATOSKR_E2E_WG_PLAINTEXT=1` is evaluated **only** inside the explicitly
gated `wg_fixture.py --execute` run (also requires `RATATOSKR_E2E_FINAL_GATE=1`
and `RATATOSKR_E2E_WG_SYNTHETIC=1`). It occurs after healthy encrypted marker,
registered peer and independent optional TokenReview, before exact selected-Pod
UID deletion. The checked-in fixed root helper pins the selected and gateway
READY CRI sandboxes to exact Pod namespace/name/UID/IP/PID and nsfs netns FDs,
then transmits exactly three synthetic AF_PACKET Ethernet/IPv4/UDP6081
GENEVE/TEB frames (no user-supplied packet payload) from the selected eth0 to the owned
gateway PodIP. It requires positive gateway `eth0` ingress headers, a strict
`ratatoskr_wg` INPUT UDP6081 DROP counter increase and no `gnv0` RX packet
increase, then the parent rechecks both Pods/CRI identities and makes a fresh
healthy **encrypted** marker request. The controller's encrypted NetworkPolicy
intentionally does not permit UDP6081. If CNI denies packets before gateway
`eth0`, this test reports a blocked/inconclusive plaintext *nft* assertion;
**never** broaden production NetworkPolicy just to manufacture ingress.

No alternate shell, Pod capability, VM/sudo policy, pcap, full packet bytes,
Secret or token logs are introduced. The root-only sender uses a kernel-selected marked-route next hop and verified
unicast eth0 neighbor MAC. AF_PACKET intentionally bypasses the client OUTPUT
guard for this negative test; ordinary workloads gain no new capabilities.
Missing root helper privileges, source route/neighbor, traffic, strict nft
shape or stable gnv0 counter fail closed.
The result remains **4/INCOMPLETE** even if the scoped plaintext check runs;
it does not certify all M8 encrypted-mode requirements. During authoring only
fake/unit tests were run, **not** the root helper, Kubernetes or VM operations.
