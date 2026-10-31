# Ratatoskr Helm chart (M6 eBPF / iproute modes)

**Pre-alpha, not release-ready.** Numbered client GENEVE links resolved the
observed reverse-path failures on this kernel; both iproute and eBPF passed
the bounded flannel/no-mesh/init/none direct-config fake subsets. Controller-
created VPN gateways, restricted agent traffic, other CNIs/meshes, WireGuard
runtime and Linux 5.10 remain unverified. This chart must not be represented
as production validated. See `docs/milestones/m9/final-gate.md` for exact evidence
and skipped compatibility/live cells; no image/chart has been published or signed.

Install into one namespace (for example `helm upgrade --install ratatoskr
charts/ratatoskr --namespace ratatoskr-system --create-namespace`).
`operatorNamespace`, if set, must equal the Helm release namespace. The chart
installs the controller, admission webhook, ServiceAccounts, RBAC, and a
portable webhook ingress NetworkPolicy. The controller creates gateway
Deployments, ConfigMaps, and Services in EgressGateway namespaces at runtime;
**the chart does not create a gateway pod or gateway Service**.

The chart defaults to `driver: agent`, `datapath: iproute`; `driver: init`
remains the local `hack/dev-values.yaml` default. M6 permits opt-in
`datapath: ebpf` with either driver. Helm sends `DATAPATH` to the controller,
webhook and node agent; the controller/webhook must also propagate this mode
into dynamically created gateways and client init containers. Agent mode
installs a DaemonSet; init mode does not. Agent-mode labeled workloads receive
a capability-free wait-init; init-mode client programming requires `NET_ADMIN`.
Gateway containers need `NET_ADMIN`, while the OpenVPN upstream needs
`NET_ADMIN`, `MKNOD`, `/dev/net/tun`, and memory-backed `/run/ratatoskr`. The
Go controller/webhook own that dynamic pod-spec construction, not the chart.
`exclusions.serviceCIDRs` is for
clusters whose service CIDR cannot be discovered reliably; `podCIDRs` optionally
provides explicit cluster pod ranges and `extraCIDRs` adds direct-route
exclusions. The chart passes CIDRs as comma-joined environment values. It sets
`GATEWAY_IMAGE` and `OPENVPN_IMAGE` to the matching chart image tag and forwards
`IMAGE_PULL_POLICY` so dynamically managed gateway workloads can use the same
local-image policy as the operator.

**Operator-only upstream probe:** `dns.upstreamProbeURL` defaults to empty, so
the OpenVPN plugin retains its external HTTPS exit-IP probe. For an isolated
synthetic tunnel fixture an operator may set a private literal unicast IPv4
HTTP(S) endpoint returning the observed exit IPv4. The controller rejects
credentials, queries, fragments, invalid ports and hostnames, and passes the
URL only as the plugin's `--probe-url` argument; workloads cannot set it in a
Gateway CRD. The plugin independently binds and marks the probe socket to
`upstream0` (no direct-network fallback). Do not include tokens or keys in
this chart value; changing it rolls the controller and managed gateways.

**Agent security and host compatibility:** In agent mode, each node runs a
root-UID, `hostPID: true`, `hostNetwork: true` DaemonSet container with
`NET_ADMIN` and `SYS_ADMIN` (all other capabilities dropped in iproute mode),
`allowPrivilegeEscalation: false`, `privileged: false`, and RuntimeDefault
seccomp. With `datapath: ebpf` the agent additionally receives `BPF` and
`PERFMON`; the backend uses fd-backed maps and tc filters, so Helm does not
mount the host bpffs. No other chart workload gets BPF capabilities. Confirm
that the node's RuntimeDefault seccomp profile permits `bpf(2)` and netlink
operations before enabling this mode. The agent mounts the node CRI Unix
socket at `agent.criSocket` (default
`/run/containerd/containerd.sock`; `hack/dev-values.yaml` supplies the k3d/k3s
`/run/k3s/containerd/containerd.sock`) and read-only `/var/run/netns`.
The netns mount uses one-way `HostToContainer` propagation: a CNI may create
per-Pod nsfs bind mounts **after** the DaemonSet starts, and without this option
the agent can see a regular placeholder instead of the namespace FD and safely
refuse programming. This does not propagate agent mounts back to the host.
The agent Pod mounts its own Kubernetes ServiceAccount token for API access;
no chart-managed workload/gateway receives CRI or netns hostPath mounts.
**Treat this DaemonSet as node-root-equivalent:** access to the CRI socket and
host PID namespaces is highly privileged despite the bounded Linux capability
list. BPF mode expands kernel-programming privileges even without host bpffs;
place the agent only on trusted nodes. Its cluster-wide ClusterRole permits
Pod get/list/watch/patch, namespace get, gateway
get/list/watch, policy list, and `serviceaccounts/token` create in
any namespace for short-lived, Pod-bound registration tokens. This is a
powerful cluster-wide binding; restrict who may deploy/modify it. It has no
Secret read permission. To check rendering without a node:
`python3 charts/ratatoskr/tests/check_chart.py` (requires Helm and PyYAML).

**M9 package staging (no publish):** Chart metadata remains intentionally
`0.0.0-dev` / `dev`; do not install a release with those image tags. Run
`python3 charts/ratatoskr/tests/check_chart.py` to lint and check rendered
RBAC/security, compare two local archive hashes, and verify archive contents,
CRDs, and version-derived image tags. Before staging a particular release
`X.Y.Z`, ensure *all component images* (including
`ratatoskr-upstream-openvpn`) already exist at `X.Y.Z` and correspond to the
same source revision, then use `helm package charts/ratatoskr --version X.Y.Z
--app-version X.Y.Z --destination <private-staging-dir>` and inspect the
archive. Supply `--set image.tag=<explicit-tag>` only if image tags differ;
never silently ship `:dev` or an unmatched tag. Chart packages install CRDs
from `crds/` on initial install; Helm does not automatically upgrade or delete
CRDs. Review CRD schema upgrades separately before a chart upgrade. Do not
place Secret data, keys or live configuration in chart files or Helm values;
packaging and validation require no cluster credentials. Publishing, signing,
provenance and final traffic/e2e evidence are outside this chart-only check.

**Controller HA and observability:** Set `controller.replicas` and
`webhook.replicas` (both default to 1). More than one controller replica
requires `controller.leaderElection.enabled=true`; the chart passes
`--leader-elect` and grants the controller ServiceAccount create plus named
get/update for the `ratatoskr-controller.skaldhall.io` Lease **only in the Helm
release namespace**. RBAC cannot restrict Lease creation to a name. Webhooks
are horizontally scalable without controller leader election; every replica
reads the same TLS Secret and populates its private memory-backed serving
volume. Health endpoints remain on `:8081`, admission on HTTPS `:9443`.
The controller currently binds metrics to `0` (disabled), and the webhook
does not serve metrics; this chart therefore does **not** publish a misleading
metrics Service or open a metrics port in NetworkPolicy. Enable those only
after Go exposes a definite metrics listener and access-control contract.

**TLS:** No private key is rendered by Helm. The webhook Deployment init
container executes its own image with `--bootstrap-tls`, using a memory-backed
`/tls` emptyDir shared with the serving webhook (`--tls-dir=/tls/identity`). Bootstrap
creates or reads the namespaced `ratatoskr-webhook-tls` Secret, writes certificate
and key into `/tls/identity`, and patches CA bundles on `ratatoskr-pods` and
`ratatoskr-validation` webhook configurations. It must retry until the
configurations are visible. Serving replicas each bootstrap into their own
memory-backed volume. The webhook Service is `ratatoskr-webhook` in the Helm
release namespace. The chart only grants Secret creation in that namespace,
get/update/patch for that exact Secret name, and get/patch on the two named
webhook configurations. Kubernetes RBAC cannot constrain Secret `create` to a
resource name, nor permit metadata-only Secret `get`; the controller has
cluster-wide Secret `get` solely for PartialObjectMetadata reads and must never
fetch or log Secret data.

**Init-mode gateway address changes:** Clients connect to gateway **pod IPs**,
not the gateway Service VIP. An M2 gateway pod restart or replacement can
change its IP, and existing workload init containers do not rerun by
themselves. The controller must roll the affected client pods in a controlled
manner after endpoints change (or an operator must restart them) to reprogram
routes; a Service VIP is **not** a substitute for this rollout. NetworkPolicy
here only restricts webhook ingress to ports 9443 and 8081 (the latter is
needed for kubelet probes). It does not attempt to infer API-server or node
CIDRs or rely on a CNI extension.
