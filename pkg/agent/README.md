# Node agent (M5, Linux)

Run a single instance per node with `NODE_NAME` (Downward API `spec.nodeName`),
`CRI_SOCKET` (Unix socket available inside the agent), and
`OPERATOR_NAMESPACE` (default namespace for gateway references). The agent
needs host network namespace and privileges to enter another network namespace
(`SYS_ADMIN`) and program links, routes, nftables and WireGuard (`NET_ADMIN`).
**Workload containers must not receive these capabilities.** The socket and
`/var/run/netns` must be mounted from the node, not exposed to workload pods.
The health and readiness JSON endpoints listen on port 8081. The process
refuses kernels older than 5.10.

Suggested minimal Kubernetes permissions: `pods` get/list/patch (patch only for
agent annotations, constrain with admission), `namespaces` get,
`egressgateways` get, `egresspolicies` list; restrict access to node-scoped pods
via a validating webhook or a node-specific admission/RBAC solution where
available. Kubernetes standard RBAC does **not** provide field-selector-scoped
`list pods`, so a node agent's `list` permission can read pods on other nodes;
no claim of strict per-node RBAC isolation is made. For encrypted mode the
agent additionally needs `serviceaccounts/token` create in selected namespaces
with admission controls preventing issuance for arbitrary Pods.

Current limitations: existing webhook admission unconditionally injects a
NET_ADMIN init container, so agent mode does **not** yet admit PSA-restricted
workloads without a separately coordinated webhook update. The controller
readiness check also still depends on successful init. Encrypted mode obtains an audience-restricted Pod-bound TokenRequest in memory,
registers with pinned TLS against the gateway PodIP from the agent host netns,
and only then applies the WireGuard client; a missing CA, registration failure,
or token failure prevents readiness. Neither token nor WireGuard private key is
written to Pod metadata or node files by this agent. CRI PID fallback requires
cgroup ownership containing the exact Pod UID. Unknown CRI verbose formats
fail closed. The marker is a non-secret in-netns dummy link named `rtk-ready`;
its presence alongside the complete authorized config hash prevents redundant
route replacement after agent restart.

## Trusted host namespace anchor

`NODE_NAME`, `POD_NAMESPACE`, `POD_NAME`, and `POD_UID` must come from the
kubelet Downward API fieldRefs. On startup the agent makes an uncached API GET
of its own exact Pod UID and validates node, hostNetwork, hostPID, non-deleting
lifecycle, `ratatoskr-agent` ServiceAccount and the fieldRef declarations.
Only then does it pin its current thread's netns FD as the host baseline.
Every resync rechecks the Pod via the API and refuses programming/readiness on
API failure or identity changes. The candidate CRI netns must differ from that
pinned baseline and match the pinned sandbox PID via pidfd before programming.
This is a trusted **kubelet/API inference** that a hostNetwork agent's netns
is the node host netns; it is not independent PID1 attestation. A cluster
where the kubelet or API reports false Pod hostNetwork/identity breaks this
trust model. Kernel 5.10 must support pidfd_open and pidfd setns for sandbox
proof; otherwise the agent fails closed without adding privileges.
