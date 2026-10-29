# Ratatoskr Helm chart (M6 eBPF / iproute modes)

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
