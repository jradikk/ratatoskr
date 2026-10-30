# Synthetic OpenVPN — input scaffold, NOT an executed e2e

## Isolated no-PASS evidence collector

`collector.py` accepts only an active, owned `Lifecycle` and its `FixtureAPI`.
It bounds Gateway status polling, validates UID-pinned fixture server/client
images and owner-linked evidence, parses actual iproute2 single-object JSON
(`linkinfo.info_data.id`/`remote`, `stats64.tx.bytes`) from fixed client
commands, requires stable GENEVE link identity and idle TX counter before
checking a selected marker request increased its TX bytes, and compares DNS
answers with the excluded API ClusterIP. Its `final_result()` **always raises
INCOMPLETE**. There is no CLI, resource creation, PKI invocation, report PASS,
server-side exec or change to `run.py`. The module does *not* observe an
authenticated OpenVPN TLS session, perform a direct API TLS request, interrupt
or restart the server, prove endpoint withdrawal/recovery, or eliminate the
kubectl exec UID race. These remain hard blockers; a marker and counter delta
are not independently sufficient for full VPN e2e. Pure fake-adapter tests only.

## Bounded fixture adapter (not wired into execution)

`adapter.py` is a **building block only**, not a runner and not an e2e PASS
path. It accepts only a currently active `Lifecycle`, re-reads its exact
namespace UID/ownership before each request, rejects other namespaces,
resource names, container names and arbitrary commands, and uses fixed
`kubectl --context k3d-ratatoskr-flannel` argv. Complete allowlisted fixture
JSON objects (including Secrets) travel only by stdin; nothing is written to
a manifest file, shell, Pod logs or user-visible stdout. The local process
transport caps output and time (including blocked stdin), discards stderr,
kills its process group on failure, and sanitizes exceptions. Pod runtime image
lookup requires the caller's verified Pod UID; client exec additionally
requires an explicit expected immutable runtime image ID and fixed command ID,
checks the UID before and after, and refuses to exec the server Pod holding PKI.
An API read, CREATE, or exec may still race a deletion/replacement between
operations: the adapter fails closed on a changed observed UID, while *true*
server-side compare-and-exec is unavailable through kubectl. Before any live
fixture use, the operator must also validate Secret retention/cleanup,
EndpointSlice/owner graph, TLS and tunnel proofs, and server fail-close/recovery.
This adapter is not imported by `run.py` and cannot award traffic coverage.

## Pure traffic evidence contracts (not an execution path)

`evidence.py` contains cluster-free, unit-tested **assertions only** for the
future bounded runner: exact Gateway→Deployment→ReplicaSet→Pod and owned
Service/ConfigMap/NetworkPolicy identity, measured MTU and current endpoint,
all rendered gateway/plugin/server/tools runtime IDs, rendered private plugin
probe, restricted agent wait-init, marker plus independently measured GENEVE
link identity and **increasing selected-request egress bytes**, direct excluded
DNS/API ClusterIPs, endpoint withdrawal and failure of selected traffic, and
post-recovery status and bytes. Synthetic positive and tampered objects test
these contracts without any API access. The collector, TLS session provenance,
controlled server interruption/recovery and namespace/PKI orchestration are
**not** implemented. No standalone PASS path exists; `run.py` continues to
return INCOMPLETE and does not call these assertions.

## Private lifecycle building block (no traffic or e2e assertion)

`lifecycle.py` exports `Lifecycle` as a reusable context manager; `run.py` is
**not changed to call it**. The operator must complete preflight and explicitly
opt in *before* creating a Lifecycle. On entry it owns a new outside-repository
mode-0700 temporary directory and installs SIGINT/SIGTERM cleanup handlers.
`create_namespaces()` checks that **both** random names are absent before any
create and records server-returned namespace UIDs. Avoid any fixture Secret
creation before both namespaces have been confirmed; on ambiguous CREATE with
no returned UID, the module refuses deletion and requires operator remediation.
Exit deletes only those confirmed matching UIDs using an atomic Kubernetes
DeleteOptions UID precondition, checks both absences, removes the temporary
directory, and restores the signal handlers. Cleanup has a bounded grace
independent of the normal monotonic total deadline. Cleanup failure raises,
overriding a successful body; a timed-out CREATE without a verified UID
deliberately leaves an orphan for operator remediation rather than risk deleting
a raced, preexisting object.
SIGKILL, machine loss, an unavailable API or finalizers can still prevent
confirmed cleanup; no PASS can be claimed in those cases.

`generate_pki()` is optional and **must only be called in an authorized final
gate**: it invokes the existing scaffold's OpenSSL helper with a monotonic
deadline and per-call timeout, under umask 077, validates all key files are
mode 0600, and leaves all inputs inside the private directory for removal on
exit. It never prints key bytes or raw Kubernetes output. The lifecycle does
not provision a cluster, build/import images, create Secret fixtures or award
coverage. This module is statically/unit tested with fake APIs and fake PKI;
no cluster, OpenSSL or real private keys were used during authoring.

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

**Unresolved full-gate blockers:** The lifecycle helper is not wired to the
read-only runner or proven on this cluster; its UID-conditional raw kubectl
DELETE transport still needs live verification before resource creation. The
runner creates no PKI, namespace, Secret or Pod, and cannot compare the four
fixture runtime image IDs against trusted, externally built/imported Pods. It
checks the configured controller probe, not chart release provenance or rendered
plugin args. The pure assertions above do not collect ownership/status/MTU,
agent marker, independent link-byte and route evidence, direct ClusterIP
DNS/API paths, TLS session provenance, or controlled server interruption and
recovery. An HTTP marker alone is insufficient: without a bounded, secret-safe
collector and verified namespace/PKI teardown, executing a partial fixture
risks a false pass or orphaned credentials. No full-gate e2e PASS path exists.

Cluster-free validation:

```sh
python3 -m unittest discover -s test/e2e/matrix/synthetic -p 'test_*.py'
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
