# Node agent

The Linux node agent programs selected workload network namespaces and updates
readiness as gateway endpoints and policies change. The process entrypoint is
[cmd/agent](../../cmd/agent/); deployment and current permissions live in the
[Helm chart](../../charts/ratatoskr/).

## Runtime contract

Run one trusted instance per node. The chart gives the agent an ordinary Pod
network namespace (`hostNetwork: false`) and `hostPID: true`, `NET_ADMIN` and
`SYS_ADMIN`, plus `BPF`/`PERFMON` when eBPF is selected. It mounts the node-local
CRI socket and `/var/run/netns`; HostToContainer mount propagation allows newly
created CNI namespace bind mounts to be observed. **Workload containers must
not receive these privileges or mounts.**

Required Downward API fieldRefs are `NODE_NAME` (`spec.nodeName`),
`POD_NAMESPACE`, `POD_NAME`, and `POD_UID`. `CRI_SOCKET` identifies the mounted
Unix socket. `OPERATOR_NAMESPACE` selects the default gateway reference
namespace; `DATAPATH` chooses `iproute` or `ebpf`. Use the chart's
`agent.criSocket` to match the node runtime.

The webhook's agent driver injects a **capability-free wait-init**, not a
NET_ADMIN programming init. The agent installs the `rtk-ready` dummy marker only
after successful programming and authorization checks; the waiter cannot create
that marker. The marker and authorized configuration hash prevent redundant
replacement after restart, but are not accepted without fresh identity checks.

## Trust and fail-closed reconciliation

At startup, an uncached GET verifies the agent's own exact Pod UID, node,
ServiceAccount, non-deleting lifecycle, separate Pod network namespace,
`hostPID: true`, Downward API fieldRefs and the exact read-only `host-netns`
volume sourced from node `/proc/1/ns/net` and mounted at
`/var/run/ratatoskr/host-netns`. Kubelet resolves and bind-mounts the host
namespace path; the agent process does **not** open `/proc/1/ns/net` under
RuntimeDefault (ptrace permission can deny that). It pins its own thread netns
for restoration, then opens the fixed mounted nsfs host-PID-1 namespace as a
forbidden anchor using `O_NOFOLLOW`; both FDs must be valid, network-typed and
distinct. Each resync rechecks the Pod mount identity and its thread against
the pinned **own** namespace. This relies on the validated
hostPID/CRI/Kubernetes trust contract, not independent PID-to-netns
attestation. An unavailable or invalid kubelet mount fails startup closed; no
additional privilege or workload-path `/proc` fallback is introduced.

Before programming, the agent requires READY CRI namespace/name/UID/PodIP
metadata, a live pidfd whose cgroup contains the Pod UID, exactly one confined
nsfs network namespace path, and a unique eth0 IPv4 matching the PodIP. The
candidate netns must differ from both pinned own and host anchors. Sandbox identity,
path and namespace inode are rechecked around programming. The CRI-reported
path-to-PID association remains **trusted CRI authority**, not independent
pidfd namespace ownership proof.

Linux 5.10 or newer must provide `pidfd_open`, `openat2`, nsfs `NS_GET_NSTYPE`
and permitted direct `setns` of the confined CRI nsfs FD. Runtime/seccomp policies
that deny required calls fail closed; the agent does not automatically add
privileges or relax confinement. IPv6 workloads are refused or fenced rather
than allowed to escape an IPv4-only datapath.

The agent watches node Pods and gateway status with a 30-second full resync for
missed events. Healthy endpoints are chosen using Pod-UID affinity. No available
endpoint installs the unreachable fallback; projection lag and upstream failure
leave workload readiness pending instead of forwarding through ordinary egress.

### Applied-client acknowledgment

A Gateway ConfigMap write alone cannot activate a client. Before installing an
endpoint or registering an encrypted peer, the agent checks:

1. Controller-published gateway Pod UID and applied SHA-256 of the **exact raw**
   `gateway.json` bytes.
2. An uncached gateway Pod GET matching name/UID/PodIP and non-deleting lifecycle.
3. A Gateway-owned ConfigMap containing the exact client PodIP and gateway ID,
   with bytes matching the acknowledged hash.

Gateway status attests the Pod→ReplicaSet→Deployment→Gateway owner chain; the
agent does not independently GET each ReplicaSet/Deployment. A stale or absent
acknowledgment withdraws the marker and uses the closed fallback. No client list
is exposed by gateway `/info`. Kubernetes API/controller status and authorized
ConfigMap reads remain trusted control-plane inputs.

With WireGuard transport, the agent obtains a short-lived audience-restricted,
Pod-bound TokenRequest and registers against pinned gateway TLS before client
programming. Missing trust roots, failed token issuance or registration prevent
readiness. Tokens stay in memory; WireGuard private keys are not written to Pod
annotations or node files. eBPF does not support this transport mode.

## Permissions and observability

The chart grants pods get/list/watch/patch, namespaces get, ConfigMaps get,
gateways get/list/watch, policies list and serviceaccounts/token create. Standard
Kubernetes RBAC cannot scope pods/list to a node field selector or TokenRequests
to a Pod UID. Combined with CRI access and namespace privileges, this is a
**node-root-equivalent trust boundary**, not tenant-isolated RBAC. Protect the
agent ServiceAccount, operator namespace, admission configuration and runtime
socket; admission checks do not make a compromised agent safe.

`/healthz` and `/readyz` listen on the configured `HEALTH_PORT` (chart default 19903) in the agent Pod netns. Readiness reports process reconciliation,
not proof that every workload/VPN request succeeds. Programming metrics bind
only to `127.0.0.1:9903` in the agent Pod netns; no scraping Service is exposed.
They count completed client-netns operations (`usable`, `closed`, `cleanup`),
not CRI/API/token checks. Metrics contain no identity/error labels and reset on
process restart.

## Contributing

From the repository root:

```sh
go test ./pkg/agent/...
go vet ./pkg/agent/...
go build -o /tmp/ratatoskr-agent ./cmd/agent
```

Keep fake API/CRI tests separate from explicitly privileged namespace/kernel
checks. Cover stale Pod/sandbox identities, changed host anchors, revoked
selection, invalid gateway acknowledgments, backend failures and marker
withdrawal. Never use a user's runtime socket, profile, token or private key as
a fixture. Unit tests do not establish runtime/seccomp compatibility.
