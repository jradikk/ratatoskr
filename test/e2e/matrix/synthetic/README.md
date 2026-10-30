# Synthetic OpenVPN — input scaffold, NOT an executed e2e

## Guarded read-only preflight (still NOT a final-gate e2e)

`run.py` is an explicitly incomplete guard, not a traffic runner. Without **both**
`RATATOSKR_E2E_FINAL_GATE=1` and `--execute`, it exits 2 without calling kubectl.
With both guards and seven `EXPECTED_{CONTROLLER,WEBHOOK,AGENT,GATEWAY,PLUGIN,SERVER,TOOLS}_IMAGE_ID`
values (each an immutable runtime SHA-256 ID), it makes only bounded, read-only
requests against `k3d-ratatoskr-flannel`. It checks the existing three Ready
flannel/no-mesh nodes, fail-closed admission registration, current
Deployment→ReplicaSet→Pod and DaemonSet→Pod runtime IDs for the three release
components, aligned agent/iproute config, and the exact trusted probe URL in
controller configuration. It deliberately exits **4 / INCOMPLETE** even after
this preflight succeeds: the other four IDs are required but **not verified**
against runtime Pods, and no fixture, PKI, traffic, cleanup or TLS proof occurs.
Failure exits 1 with no raw Kubernetes object/error printing. It does not
build/import images, create resources, provision hosts or upgrade a release.

**Do not use preflight success as authorization to claim e2e coverage.** A full
runner must additionally verify *all seven* actual image IDs including new
fixture Pod runtime IDs, tunnel identity/bytes, ownership/status, restricted
agent behavior, direct DNS/API routing, fail-close and recovery, and both unique
namespace deletions before ever reporting PASS. This remains a deliberately
blocked boundary rather than a partial positive traffic test. In particular,
there is no unsafe namespace create with unverified cleanup and no persistent
secret manifest in this preflight.

**Unresolved full-gate blockers:** The existing fixture has no lifecycle/cleanup
owner, and the current runner does not create or contain temporary mode-0700
PKI, two UUID namespaces, API-side UID-scoped deletion, signal handling or
verified post-delete absence. It cannot compare the four fixture/runtime image
IDs until trusted, externally built/imported Pods are created. It checks the
controller's literal configured probe but cannot establish operator chart
release provenance or inspect a rendered plugin's `--probe-url` without first
creating a Gateway. There is no implemented evidence collector for the exact
Gateway→Deployment→ReplicaSet→Pod ownership and status/MTU, wait-init and agent
marker, independent tunnel-byte/route proof, direct ClusterIP DNS/API paths, or
server interruption with endpoint withdrawal and recovery. An HTTP marker alone
is insufficient; without reliable tunnel proof and both namespace/PKI teardown,
executing even the partial fixture would risk a false pass and leave credentials.
Therefore no full-gate invocation or e2e PASS path is present.

Cluster-free validation:

```sh
python3 -m unittest discover -s test/e2e/matrix/synthetic -p test_run.py
python3 test/e2e/matrix/synthetic/static-check.py
sh -n test/e2e/matrix/synthetic/server/start.sh
```

**Not wired into the matrix runner and not awarded coverage.** Static-only fixture checks
exercise safe manifest structure without generating PKI, invoking Docker/openssl,
reading credentials or contacting a cluster. The separate read-only preflight above
can contact a cluster only with both explicit guards; a complete final-gate runner,
evidence checks and cleanup are still required before a pass can be asserted. This
scaffold alone does not verify owner chain, agent marker, DNS/API, fail-close,
recovery or traffic. Do not `kubectl apply` these objects manually as a proof.

At the authorized final gate only, build `server/Dockerfile` into a **local**
`ratatoskr-synthetic-openvpn:local` image and import it plus the locally built
upstream/tools/gateway/agent/controller/webhook images into a *preflighted*
existing three-node cluster; no registry pulls. The local server runs actual
OpenVPN over UDP1194 with a Pod-local emptyDir TUN device and NET_ADMIN/MKNOD (no host device mount); it serves a fixed marker
and exit IPv4 at `http://10.88.0.1:8080/marker` and `/exit`, bound exclusively
on its tunnel endpoint. This is *not* the older HTTP fakeupstream. Its Pod must
run in a separate privileged-labeled namespace; only the app namespace enforces
PSA restricted. Avoid exposing the marker/exit HTTP port as a Kubernetes Service.

`prepare.py` deliberately has **no executable entrypoint**. Its helper builds
complete Secret/Pod/Service/Gateway/Policy/workload JSON objects and can generate
one-day self-signed CA plus distinct server/client 2048-bit RSA private keys
with locally installed OpenSSL. A future runner must own a mode-0700 tempdir
outside the repository, invoke these helpers only inside it, and remove the
private material on every ordinary exit. Never print, commit or collect the
keys, raw manifests, OpenVPN logs or profiles in CI artifacts. Do not use
`kubectl -v` or shell tracing. Supply
`GATEWAY_UPSTREAM_PROBE_URL=http://10.88.0.1:8080/exit` via the parent-owned,
operator-only chart seam (not the CRD); verify the running plugin received the
override without exposing private data. If that seam is missing or the release
is stale, **stop**; never use the default public probe.

A future runner must require final-gate authorization, verified immutable
controller/webhook/agent runtime image IDs and an existing healthy flannel agent
release; fail closed on mismatch. It must enforce a total deadline and per-call
budgets, check generated namespaces do not exist first, resource ownerRefs
Gateway→Deployment→ReplicaSet→Pod (and owned Service/ConfigMap/NetworkPolicy),
exact Gateway UID/status healthy endpoint and measured MTU, source Service→server
Pod, and release/Pod/Secret isolation. It must verify the restricted app Pod has
only a capability-free production-injected wait-init, no workload credentials,
`rtk-ready` marker (via the agent), successful wait-init exit and readiness
annotation; then require the marker reachable **from the workload through VPN**
with no direct fallback. Test direct cluster DNS/API through known excluded
ClusterIPs independently, then loss and restoration of the synthetic server
with healthy endpoint withdrawal, blocked selected marker traffic and recovered
agent routing. Marker alone (or generated manifests alone) is no evidence of
tunnel traversal: verify tunnel bytes/identity or independent destination
reachability and absence of a direct route. The currently generated policy
selects only TCP8080 to 10.88.0.1, while ordinary ClusterIP traffic remains
outside the selected rule. Confirm actual exclusions before traffic.

On every exit and signal, a future runner must delete **both** unique namespaces
and private input directory, verify absence and report cleanup failure. SIGKILL,
node loss or API outage requires explicit operator orphan/secret remediation;
never report passed if cleanup cannot be confirmed. No host VM provisioning or
cluster lifecycle bypass belongs here. This document is a checklist of missing
evidence requirements, not an assertion that they ran.

Local validation only:

```sh
python3 test/e2e/matrix/synthetic/static-check.py
sh -n test/e2e/matrix/synthetic/server/start.sh
```
