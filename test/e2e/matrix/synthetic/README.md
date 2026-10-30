# Synthetic OpenVPN — input scaffold, NOT an executed e2e

**Not wired into the matrix runner and not awarded coverage.** Static-only checks
exercise safe manifest structure without generating PKI, invoking Docker/openssl,
reading credentials or contacting a cluster. Execution requires a separate final-
gate runner, evidence checks and cleanup before a pass can be asserted. This
scaffold alone does not verify owner chain, agent marker, DNS/API, fail-close,
recovery or traffic. Do not `kubectl apply` these objects manually as a proof.

At the authorized final gate only, build `server/Dockerfile` into a **local**
`ratatoskr-synthetic-openvpn:local` image and import it plus the locally built
upstream/tools/gateway/agent/controller/webhook images into a *preflighted*
existing three-node cluster; no registry pulls. The local server runs actual
OpenVPN over UDP1194 with `/dev/net/tun` and NET_ADMIN; it serves a fixed marker
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
