# Synthetic OpenVPN — input scaffold, NOT an executed e2e

Runtime status (October 30, 2026): the guarded init-driver partial smoke was
executed twice against the existing cluster after a parent-managed release
switch. The real Gateway and OpenVPN session reached the healthy baseline, but
`ratatoskr-init` exited 1 on `client fallback` route installation with
`operation not permitted`; the application never ran. Both fixture namespaces
and private PKI were cleaned up, and the release was restored to agent mode.
This is a **FAILED** partial traffic test, not M8 acceptance. The separate
restricted-agent sandbox-pidfd blocker remains. See `docs/milestones/m9/final-gate.md`.
The runner now stops polling as soon as the UID-pinned one-shot Pod reports
`phase=Failed`. It emits only `init-failed`, `app-failed` or
`pod-failed-unknown`, then attempts the same UID-owned cleanup; waiting or
transient API errors remain bounded and cannot become success evidence.
In the separate agent partial smoke, a selected Pod which reaches `Failed`
now also stops immediately with an allowlisted wait-init/app subcheck category
(or `pod-failed-unknown`); a nonzero app exit is **not** selected tunnel evidence.
The UID-owned namespace and private PKI cleanup still run on that path.
Recent guarded agent retries (October 31, 2026) reached the restricted wait-init
and nonroot app but **did not pass marker traffic**. A tokenless public-CA API
probe correctly accepts only exact 401 Unauthorized or 403 Forbidden. The
selected marker then timed out during TCP connect. Test-only exit codes
identify fixed DNS/route/TLS/marker subchecks without logging bodies, errors
or credentials; no timeout or arbitrary failure counts as fail-closed evidence.

## Separately gated init-driver/nonrestricted partial traffic (never M8 PASS)

Only `run.py --execute --allow-partial-vpn-smoke --execute-init-smoke
--execute-init-traffic` with **all four** explicit environment opt-ins:
`RATATOSKR_E2E_FINAL_GATE=1`, `RATATOSKR_E2E_PARTIAL_VPN_SMOKE=1`,
`RATATOSKR_E2E_INIT_SMOKE=1` and `RATATOSKR_E2E_INIT_TRAFFIC=1` can enter
`init_traffic.py`. The parent/operator must **first** roll an already existing
controller/webhook release to aligned DRIVER=init DATAPATH=iproute and later
restore the agent release independently; the fixture never runs Helm or
changes the release. Before mutation it verifies immutable IDs for controller,
webhook and the **tenth** `EXPECTED_INIT_IMAGE_ID` as well as six fixed local
images via read-only CRI on all three nodes, exact private controller probe,
fail-closed webhook rules and absence of the agent DaemonSet. Missing gates
exit 2 without cluster access; stale mode/images fail before namespace/PKI.

The init runner uses `Lifecycle(apps_psa="privileged")` **only for the apps
namespace in its fresh disposable pair**, because production init injects NET_ADMIN,
which PSA restricted does not allow. The default agent runner remains
restricted and unchanged. It creates exactly eight base server/Gateway
objects, observes real Gateway Ready/MTU/owner graph and server OpenVPN TLS
session, then creates only `synthetic-probe-healthy` with an exact CREATE-
returned UID. Bounded Pod-status polling requires the production-injected
`ratatoskr-init` image/tag, approved **actual initContainerStatuses.imageID**,
NET_ADMIN-only programming init, read-only Downward-API annotation projection
and identity fieldRefs, successful init exit 0 and controller readiness=true.
At CREATE admission the projected config intentionally omits UID/PodIP/MTU;
`cmd/init` fills them after CNI using Downward API. The one-shot **application
container** remains nonroot/capability-free and must use the approved selected
helper imageID and exit 0 after exact marker and public-CA anonymous API
TLS/DNS/direct path checks; server/Gateway Pod UID and endpoint stay unchanged,
with independent authenticated session identity/counter growth as supporting
local-only evidence (normal probe traffic may also grow those counters).
No selected Pod exec, logs, Secret GET, host provision, Helm mutation,
fail-close, witness or WireGuard. Both namespaces/private PKI must be verified
removed on all ordinary exits; any uncertainty returns failure with sanitized
diagnostics. Even after success the runner returns **4 / INCOMPLETE**, labeled
*init-driver/nonrestricted* and **never** restricted-agent or M8 PASS.
The initial fixture checks used fake APIs/PKI. The later parent-rolled init
release and restoration were exercised as noted above; the partial traffic
assertions did not pass.

## Init-driver/nonrestricted scaffold (fifth gate; NO resource execution)

`run.py --execute --allow-partial-vpn-smoke --execute-init-smoke` additionally
requires `RATATOSKR_E2E_INIT_SMOKE=1` together with the existing final-gate and
partial-smoke environment opt-ins. This branch remains **read-only**: checks
exact existing flannel/no-mesh three nodes, fail-closed webhook registration,
parent-rolled controller/webhook Deployment→ReplicaSet→Pod ownership and
approved runtime image IDs, aligned `DRIVER=init`/`DATAPATH=iproute`, exact
operator private probe and locally imported gateway/plugin image references,
absent agent DaemonSet and six fixed per-node CRI config IDs. On success it
returns **4 / INCOMPLETE before namespace, PKI, Secret or Pod creation**;
it never changes a Helm release, provisions a host, or claims restricted/agent
coverage. The init release and subsequent **restoration to agent mode** must
be performed and re-preflighted separately by the parent/operator; this
scaffold does not own or automate that lifecycle.

A pure `init_evidence.assert_init_pod` contract verifies a future fresh
selected Pod's CREATE UID, exact production-injected `NET_ADMIN` programming
init image/args/Downward-API identity/projection, successful init termination
and controller `datapath-ready=true`, UID/Gateway PodIP/policy binding, and
capability-free nonroot one-shot app with approved image and exit 0.
`Lifecycle(apps_psa="privileged")` is **explicitly** required to construct
the *disposable apps namespace* in a future init-only fixture: its NET_ADMIN
init cannot be admitted under restricted PSA. This does not downgrade the
production chart, server namespace or default agent-mode `Lifecycle` (whose
apps namespace remains restricted). No init workload is created yet, and
there is no init-driver traffic e2e or M8 PASS claim. The blocked state is
intentional until bounded init-specific mutation/cleanup and release
restoration have a verified operator contract.

## Healthy restricted agent one-shot traffic extension (still INCOMPLETE)

The same quadruple-opt-in partial smoke now adds **only** the
`synthetic-probe-healthy` one-shot Pod *after* real Gateway Ready, owned graph,
measured MTU, plugin args/imageIDs and authenticated server session are
observed. Before Lifecycle/PKI mutation it reads the known `default/kubernetes`
Service ClusterIP from the existing API, validates IPv4, and supplies it to
the fixed `prepare.selected_probe_pod` helper. The fixture's app namespace
carries the exact Gateway namespace selector label. `FixtureAPI.create`
returns the new Pod UID from the API CREATE response; no guessed name-based
adoption, selected Pod exec, container logs or Secret GET occurs. Bounded
polling requires production webhook's capability-free `-wait-agent` init to
exit 0, agent readiness annotation plus UID/PodIP/Gateway endpoint/selector
policy config, the **approved selected imageID**, and a Succeeded Pod whose
helper exited 0 after exact tunnel marker plus public-CA anonymous API TLS
403/DNS and direct route checks. The Gateway and server UIDs/endpoint must
remain the same; an authenticated `synthetic-client` session with the same
identity must have increased both byte counters. Because routine upstream
health probes can also increment session bytes, this correlation is **local
supporting evidence, not independent packet-level attribution**. The smoke
returns **4 / INCOMPLETE** after verified namespace/PKI cleanup; it does not
create the outage/witness/recovery Pods or assert fail-close, full tunnel
proof, or M8 PASS. Any timeout, stale image/UID, admission mismatch or cleanup
failure exits 1 with sanitized diagnostics. Only fake APIs were used during
authoring, not a cluster.

## Explicit fourth-gate partial Gateway smoke (NOT an M8 e2e PASS)

Only `run.py --execute --allow-partial-vpn-smoke --execute-partial-gateway`
with both `RATATOSKR_E2E_FINAL_GATE=1` and
`RATATOSKR_E2E_PARTIAL_VPN_SMOKE=1` can enter `partial_gateway.py`. Without
these guards, no cluster access or mutation occurs. Existing healthy three-node
flannel, controller/webhook/agent immutable runtime IDs, aligned agent/iproute
release and exact private probe, plus all six fixed local images' matching
node CRI config IDs are checked **before** generating PKI or namespaces. The
runner never builds/imports images, upgrades a release, provisions VMs or
changes CNI. This is intentionally separate from full M8 traffic coverage.

`Lifecycle` owns two UUID namespaces, a 0700 outside-repo PKI directory, and
bounded signal/failure cleanup. Eight allowlisted base resources are created
using UID-returned stdin-only JSON: server/client/witness Secrets, private
exit-health ConfigMap, actual synthetic OpenVPN server Pod, UDP1194-only
Service, real controller EgressGateway and EgressPolicy. After positive
Gateway proof, one healthy restricted selected workload Pod is also created.
Neither witness nor outage/recovery Pod is created. The observer polls only API objects, checks
server UID/runtime image, Service EndpointSlice target UID/IP, Gateway Ready
observed generation and measured MTU, controlled Gateway→Deployment→RS→Pod
owner chain plus owned Service/ConfigMap/NetworkPolicy, exact plugin probe
args and gateway/plugin runtime images, and sanitized authenticated server
OpenVPN session from a fixed UID/image-checked reader. All polls, CLI calls,
PKI steps and cleanup are bounded. No profile, Secret, raw manifest, Pod log
or OpenVPN status is printed or persisted as an artifact. The smoke exits
**4 / INCOMPLETE** even if all assertions and both-namespace deletion pass.
An ambiguous CREATE, stale release/image, missing endpoint/status/session,
API timeout or unverified cleanup exits **1 / FAILED** with sanitized output;
SIGKILL, API loss or node failure still require operator orphan remediation.
This smoke does **not** establish fail-close, witness, recovery or
full M8 tunnel attribution/PASS; selected marker and direct API/DNS checks
are healthy-path only.

During authoring, only fake API/PKI tests were run. Parent/operator must
confirm actual Kubernetes admission, OpenVPN TUN/device behavior, image
runtime IDs and Secret cleanup at an explicitly authorized final gate.

## Triple-opt-in partial smoke preflight remains read-only

`run.py --execute --allow-partial-vpn-smoke` additionally requires both
`RATATOSKR_E2E_FINAL_GATE=1` and `RATATOSKR_E2E_PARTIAL_VPN_SMOKE=1`.
Without all three gates it exits 2 **without cluster access**. With them it
checks the existing release, then runs a bounded read-only `/bin/crictl images
-o json` query in exactly the three preflighted k3d node containers using
fixed `docker exec` argv (no shell). For each of six local tags—gateway,
plugin, server, tools, witness and selected helper—it requires exactly one
CRI config `sha256:` ID identical to the parent-approved expected value on
**every node**. Duplicate tags, missing imports, mismatched or malformed IDs,
CLI failure, oversized JSON or deadline expiry fail closed. Controller,
webhook and agent runtime IDs are already verified on running Pods. These
config digests establish current per-node tag resolution, not source-build
provenance or a guarantee that a future Pod cannot race with an image change.
After successful checks the preflight still returns **4 / INCOMPLETE** before
PKI, namespace, Secret or Pod creation. It does not execute a partial smoke,
create/import images, mutate a release, award matrix coverage or return PASS.

## Pure dry-run execution plan (no cluster mutation or PASS)

`plan.py` is an import-only, cluster-free evidence state machine. It validates
nine immutable expected runtime IDs and an active `Lifecycle` whose two
namespaces have confirmed, unchanged CREATE-returned UIDs. `manifest_order`
computes only non-secret `(kind, namespace, name)` tuples: server/client/
witness Secrets, probe-only ConfigMap, server Pod and Service, Gateway,
Policy, then distinct healthy, outage, witness and recovery Pods. It never
calls `prepare.manifests`, generates PKI, or runs kubectl. Its 15 strictly
ordered checkpoints require release image preflight, healthy Gateway and
selected-client evidence, UID/CAS probe disable and endpoint withdrawal,
fail-closed selected Pod with independent witness and preserved direct paths,
restoration, recovery, and verified namespace/PKI absence. Wrong order,
missing checkpoint, image/UID mismatch, expiry or cleanup failure is
INCOMPLETE. **Even a fully populated fake checklist cannot award PASS:**
`final_result()` always raises, and `run.py` does not import this module.
Live evidence collection, trustworthy ConfigMap projection observation,
actual OpenVPN/POSIX tunnel behavior, exhaustive runtime image verification,
and both-namespace cleanup are still required before integration.

## Immutable image expectations and exact fixture CREATE identity

The read-only opt-in preflight now requires **nine** parent-approved immutable
runtime image IDs: controller, webhook, agent, gateway, plugin, server, tools,
witness, and selected helper. Its cluster access remains read-only; only the
first three existing release components can be runtime-compared until fixtures
are actually created. `FixtureAPI.create` accepts one allowlisted fixture JSON
per exact `(kind, namespace, name)` and sends it by stdin to `kubectl create`
with a fixed identity-only JSONPath (`apiVersion`, `kind`, `namespace`, `name`,
`UID`) and a 256-byte capture cap. Even a Secret CREATE's data is **never
printed, captured or returned**. It returns only the
API-server-created kind, namespace, name, and immutable UID after exact
response validation, not a guessed name-only GET. A timeout, malformed/error
response, changed identity or ambiguous CREATE permanently quarantines that
name in the adapter; it is not retried or adopted. Such an object may need
operator orphan remediation if namespace cleanup fails. These helpers remain
unwired to `run.py` and **cannot award PASS**.

## Selected restricted one-shot application helper (unexecuted)

`app/Dockerfile` is a **locally built, test-only, nonroot UID 65532** image
with fixed Python entrypoint; `app/check.py` uses no shell, exec, API token,
credential or secret, and prints no result or error. `prepare.selected_probe_pod`
returns three distinctly named Pods in the restricted app namespace:
`synthetic-probe-healthy`, `-outage`, and `-recovery`. All opt into the same
production EgressPolicy/Gateway labels; the webhook must inject its
capability-free `-wait-agent` init, and the node agent must program the netns
before the app starts. Each Pod has `restartPolicy: Never`, a 120-second Pod
active deadline, no added capability, only the public read-only API CA
ConfigMap, and a fixed mode plus parent-approved API ClusterIP argument.
Its own PodIP comes from a Downward-API environment field.

The helper verifies exact anonymous **HTTPS 403** at the known API ClusterIP
using the public CA and hostname SAN (no `-k` or token), DNS answer and
direct `eth0` source route **before and after** an exact `/marker` request.
Healthy/recovery exit 0 only for the exact marker response; outage exit **42**
only for kernel `ENETUNREACH`/`EHOSTUNREACH` to the same destination. Any
refusal, timeout, 503, DNS/CA/API error or malformed reply exits 1, **never**
fail-close. The Pod's UID/imageID, production init exit and Pod termination
status/timestamps are the sole application evidence, not `kubectl exec` or
container logs. `evidence.assert_selected_probe` performs pure Pod-status
checks; the selected helper's absence of privileges and credentials must
remain enforced by admission and validation. A distinct outage Pod succeeds as
a negative test only when `exit42` lies inside verified endpoint withdrawal
and a separate authenticated witness simultaneously proves `/marker` remains
reachable through its own VPN. Three static/fake-only phases do **not**
orchestrate such a test. **`run.py` remains read-only and INCOMPLETE.**
The ninth local image (selected helper) has an explicit expected immutable ID,
but its runtime ID and all packet/agent/exclusion proofs still require a parent
preflight;
Pod exit alone is not standalone tunnel evidence.

## Independent one-shot OpenVPN marker witness (unexecuted)

`prepare.py` now requires **distinct** client and witness certificates/private
keys from the same one-day ephemeral CA; the witness CN is
`synthetic-witness`, not `synthetic-client`. `Lifecycle.generate_pki()` checks
the added private `witness.key` is mode 0600 under umask 077. The fixture adds
one witness-only Secret and Pod to the temporary **privileged** server namespace,
without Ratatoskr gateway labels, host mounts, service-account token, or any
new host capability. Its separate test-only local image runs fixed Python and
OpenVPN argv (no shell); it creates a Pod-local TUN and binds every marker
request explicitly to `tun0` with SO_BINDTODEVICE. It exits 0 only after the
*exact* tunnel-bound `/marker` body stays reachable over a bounded interval;
all process output is discarded, and no profiles or private keys are printed.
A final-gate caller must create this one-shot Pod **after** the probe switch
has made `/exit` unhealthy and Gateway Ready=False/endpoints withdrawn, while
the selected restricted client fails its *same* `/marker` request. These
ordering and outage assertions are **not yet orchestrated**.

The private server status reader now rejects unknown/duplicate CNs, duplicate
virtual addresses and malformed rows, and emits only sanitized counters and
identity for at most the two fixed CNs; no real addresses, usernames, status
text, certs or keys leave its Pod. Collector binds the distinct authenticated
witness session to the exact Running Pod UID, approved image ID and trusted
outage start time; the witness briefly keeps its tunnel alive for this bounded
status read and continues checking the marker. Then require Succeeded/exit 0
timestamps within the trusted outage interval for the same UID. Successful
Pod termination means OpenVPN has exited, so the session must be sampled
*before* completion. Unit tests use fake
subprocess/socket/API/status only. **No runtime status format, TUN access,
CA/client handshake or Pod scheduling has been validated against a cluster.**
`run.py` is still read-only and returns INCOMPLETE; no e2e PASS path exists.
A future operator must additionally approve the witness runtime image ID;
`run.py` and `collector.py` now require nine explicit expected image IDs,
but only three existing release components are runtime-verified at preflight. No execution or coverage is awarded
until that preflight, Pod timing, exact status-v3 shape and Kubernetes cleanup
are implemented and verified. The witness container's Pod-local device node
and `SO_BINDTODEVICE` behavior also require real Linux cluster validation.

## Probe-only synthetic failure switch (not an executed outage)

The input scaffold now includes a **non-secret** `synthetic-exit-health`
ConfigMap bound to the Lifecycle token. Its single `exit-enabled` key is
projected read-only into the synthetic server Pod; no credentials, host
mounts, capabilities or HTTP control endpoint are added. The server listener
stays bound solely to tunnel address `10.88.0.1:8080`. `/exit` returns 503
without a body if the projection is missing, malformed or `false`, while
`/marker` continues to serve its fixed response from the same process.
OpenVPN itself is not signaled or restarted. ConfigMap projection can lag,
so an API update alone is **not** evidence that the server has observed the
new value or that the gateway withdrew its endpoint.

`FixtureAPI.exit_health_outage()` requires an already-owned ConfigMap UID,
valid resourceVersion, exact lifecycle label and initial `true`; a complete
non-secret ConfigMap is sent through stdin using raw PUT with UID and
resourceVersion. The server-returned UID/version/state are checked, and the
same pinned object is re-read. On ordinary body error or signal, the context
manager attempts restoration to `true`; an ambiguous timed-out PUT is
re-read first and a changed UID/label is **never overwritten**. Any failed
or unverified restoration raises, forbidding PASS. Lifecycle namespace
cleanup remains a separate last resort when the API cannot restore.

**Hard evidence gap:** with the endpoint withdrawn, the restricted client
must fail the selected `/marker` request; that same request cannot prove the
marker remains *reachable via VPN*. The current plugin container has no
safe fixed, UID-atomic, independent in-tunnel HTTP observer, and a local
server-container request would not traverse OpenVPN. Before a final gate
could claim fail-close, an independently authenticated tunnel-side marker
witness during the outage must be designed and bounded. No live outage or
PASS path is enabled; `run.py` is unchanged.

## Public-CA verified direct Kubernetes API TLS path (no PASS)

The restricted app Pod now mounts **only** the namespace-managed public
`kube-root-ca.crt` ConfigMap key `ca.crt`, read-only at
`/var/run/ratatoskr/api-ca/ca.crt`; `automountServiceAccountToken: false`
remains enforced. The production-injected wait-init retains only its
isolated emptyDir token-shadow mount. No Secret, token, client key or host path
is mounted into the workload. The fixed exec command calls curl with
`--disable` first (ignores curlrc), `--cacert` at that public CA, IPv4,
`--proto =https`, no proxy, no redirects, no insecure mode or auth header;
only remote IP and HTTP status are returned, never the API body. It queries
an anonymous Pods list requiring **403**, with verified TLS hostname
`kubernetes.default.svc.cluster.local`. The collector requires DNS resolve
to the *known* API Service ClusterIP, curl's actual remote IP to match, and
an `ip -j -4 route get ... ipproto tcp dport 443` result sourced from the
client PodIP via `eth0` (not `rtk0`). Both the DNS and API ClusterIPs must
belong to reported gateway exclusions. If the cluster lacks the public CA
ConfigMap, the API SAN, or anonymous 403 policy, this check fails closed—never
fallback to `-k`, an SA token, a credential or a hardcoded CA. No cluster was
queried during authoring. `run.py` remains untouched and INCOMPLETE.

## Authenticated server-side OpenVPN session evidence (no PASS)

The synthetic server writes OpenVPN **status-version 3** to
`/run/synthetic/openvpn.status` every second on a dedicated Pod-local
memory `emptyDir` (mode 0700 directory, mode 0600 status file), never the
Secret volume, Kubernetes Service, logs or artifacts. `server/session.py`
reads only a no-symlink, private-mode, bounded status file and parses exactly
one authenticated client session whose common name is `synthetic-client`,
whose virtual IPv4 is in `10.88.0.0/24`, with an approved data cipher,
nonnegative counters and a fresh status timestamp. It prints **only** a
minimal whitelisted JSON identity and counters; raw status, peer real address,
profile, keys and all errors are suppressed. The adapter permits only fixed
`python3 /usr/local/bin/session.py` exec in the UID/image-pinned server Pod,
not arbitrary server exec. The collector requires stable CN/peer/session and
both OpenVPN received/sent counters to increase across the same selected
marker request, **independent** of client GENEVE TX growth. Fake-only tests
cover zero/wrong/duplicate sessions, stale or malformed counters, unsafe status
paths, tampered output and non-disclosure. This is *not* a TLS packet capture or
a final gate assertion: the source is the server's OpenVPN status after its
certificate-authenticated TLS setup, and no live OpenVPN test ran here.

`run.py` remains read-only and INCOMPLETE. No server outage/recovery,
live image/runtime proof or atomic Pod-UID exec binding is implemented; no
e2e PASS can be awarded.

## Isolated no-PASS evidence collector

`collector.py` accepts only an active, owned `Lifecycle` and its `FixtureAPI`.
It bounds Gateway status polling, validates UID-pinned fixture server/client
images and owner-linked evidence, parses iproute2 single-object JSON
(`linkinfo.info_data.id`/`remote`, `stats64.tx.bytes`) from fixed client
commands, requires stable GENEVE link identity and idle TX counter before
checking a selected marker request increased its TX bytes. Its separate
session correlation and direct-API-TLS collectors are described above.
`final_result()` **always raises INCOMPLETE**. There is no CLI, resource
creation, PKI invocation, report PASS or change to `run.py`. No controlled
server interruption/restart, endpoint withdrawal/recovery or atomic kubectl
exec Pod-UID binding exists; these remain hard blockers. Pure fake-adapter
tests only.

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
With both guards and nine `EXPECTED_{CONTROLLER,WEBHOOK,AGENT,GATEWAY,PLUGIN,SERVER,TOOLS,WITNESS,SELECTED}_IMAGE_ID`
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
runner must additionally verify *all nine* actual image IDs including new
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
