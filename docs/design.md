# Ratatoskr design

This describes the implemented architecture, not a platform-compatibility
certification. API group and workload annotation/label prefix:
`ratatoskr.skaldhall.io`. Design choices and their trade-offs are indexed in
[the ADRs](adr/README.md). A passing component or synthetic fixture does not
establish behavior on every CNI, mesh, cloud or VPN provider.

## Scope and deployment modes

A namespaced `EgressGateway` owns gateway resources and a set of healthy Gateway
PodIP endpoints. A workload opts in by labeling its Pod
`ratatoskr.skaldhall.io/gateway: <name>` and optionally supplies
`ratatoskr.skaldhall.io/gateway-namespace` (label or annotation); otherwise the
operator namespace is used. A namespaced `EgressPolicy` selects workloads and
IPv4 destinations with `include` or `exclude` rules. Without a matching policy,
all non-excluded IPv4 destinations are steered. Exclusions take precedence over
rules, and ambiguous matching policies are rejected rather than arbitrarily
selected. The controller allocates a stable `status.gatewayID` (GENEVE VNI),
reports effective exclusions/MTU, and publishes each Gateway Pod's UID, IPv4,
health and applied-client-config hash. The API reserves additional upstream
types, including `custom`, but the current admission/controller implementation
**only deploys `openvpn`**; specifying a custom image is not an implemented
plugin-install path. `failMode` accepts only `closed`; `affinity` accepts only
`per-pod`.

The Helm chart defaults to `driver: agent`, `datapath: iproute`. `driver: init`
is also available; `datapath: ebpf` is opt-in for plaintext GENEVE on compatible
Linux nodes. eBPF + WireGuard is explicitly rejected, never silently changed
to plaintext. The gateway uses the shared backend interface, with the current
eBPF gateway implementation delegating to the iproute gateway backend. Both
modes require a Linux kernel at least 5.10 and the specific kernel facilities
used by their backend; a version check alone does not certify those facilities.
There is no Windows, IPv6 VPN egress, ingress-gateway or multi-cluster
implementation. Agent-mode FQDN rules derive IPv4 routing destinations from
observed DNS answers; see [domain policies](domain-policies.md). Dual-stack
workloads retain IPv4 routing, but every IPv6 packet is dropped in the selected
namespace by raw-priority INPUT/OUTPUT/FORWARD guards. IPv6 addresses alone do
not make the Pod unready or quarantine IPv4.

## Control plane and workload admission

The controller reconciles Gateway and Policy CRDs, reads the referenced
OpenVPN Secret without placing its contents in the ConfigMap, renders a
Deployment, ConfigMap, Service and ingress NetworkPolicy, and observes managed
Gateway Pod health and `/info`. The generated `gateway.json` contains the
Gateway ID and selected client PodIP membership. Only an owner- and
UID-verified Gateway Pod reporting the SHA-256 of the **exact applied ConfigMap
bytes** may advertise `appliedClientConfigHash`; a ConfigMap update by itself
is not evidence of gateway application. Failure Events and status messages use
bounded reason categories, not raw Secret/API error text.

The fail-closed admission webhooks validate Gateway/Policy and selected Pods.
For `driver: init`, a capability-bearing init container receives the pinned
config via Downward API, waits for the gateway's applied-client acknowledgement,
then programs its own network namespace before application startup. This mode
is incompatible with PSA `restricted` because programming requires NET_ADMIN;
its fixed Gateway PodIP cannot be changed inside an already-running selected
Pod. A Gateway PodIP replacement requires selected init-Pod recreation or
rollout, not a Service-VIP substitution ([ADR-0012](adr/0012-init-mvp-stable-endpoint.md)).

For `driver: agent`, the injected wait-init has no NET_ADMIN or workload API
token. The node DaemonSet authenticates its own Downward API Pod identity,
checks the assigned selected Pod and CRI sandbox, programs the Pod namespace,
then creates an UP dummy `rtk-ready` link **last**. Wait-init checks that marker
before allowing the application to run; the agent also patches the
`datapath-ready` annotation (`pending`, `true` or `error`) and keeps an
`agent-config`/`agent-hash` binding for safe restart adoption. The agent
rechecks owner-controlled Gateway status, exact applied ConfigMap bytes,
selected endpoint Pod UID/IP and client PodIP membership before opening an
active path. Lost endpoint or acknowledgement closes the managed path with an
unreachable fallback and withdraws readiness; a failed authorization read is
distinct and installs persistent namespace-wide quarantine requiring Pod
recreation. Agent restart can adopt a matching UP marker/config after backend
verification; an endpoint change reprograms the same selected Pod, but new
connections are the relevant acceptance proof, not established-flow continuity.

### Independent VPN profiles

The OpenVPN upstream may specify `upstream.profiles` instead of the legacy
`upstream.secretRef`. Each unique name identifies one independently credentialed
controller-owned Deployment with one replica and exactly one Secret mount.
`spec.replicas` remains the legacy single-profile replica count; profiled mode
requires it to be one. All profile Pods share the Gateway's client-routing
ConfigMap, gateway ID and selected Pod allowlist, but the upstream OpenVPN
connections and exit identities are independent. One shared Gateway Service
selects all current owned PodIPs; sticky client endpoint selection remains
Pod-UID based. Removing a profile retires only that controlled Deployment and
withdraws its endpoint. Existing connections may break on reassignment.

## Trust boundary for node namespace entry

The agent runs with an ordinary Pod network namespace, hostPID, NET_ADMIN and
SYS_ADMIN, and mounts a node CRI socket plus host `/var/run/netns`
(HostToContainer propagation). At bootstrap an uncached own-Pod GET verifies
`hostNetwork: false` and `hostPID: true`. It pins its **own** thread's nsfs
namespace for restoration. Direct `/proc/1/ns/net` access is ptrace-gated by
RuntimeDefault and kubelet/containerd could not bind-mount its proc magic
symlink on the validated runtime. The agent does **not** have an independent
host namespace FD or host-inode rejection. It
requires a unique READY CRI sandbox whose namespace, name, Pod UID and PodIP
match the Kubernetes workload. Its **CRI-authoritative** verbose sandbox info
must contain a PID and exactly one `runtimeSpec.linux.namespaces` network path.
A live pidfd pins that process, whose cgroup must contain the workload UID.
The path must be a direct child under `/var/run/netns`, opened with confined
`openat2` flags and validated as an nsfs network-namespace FD; the agent
rejects its own pinned namespace and requires exactly the selected PodIP on
`eth0`, without additional physical-looking numbered IPv4 interfaces. The
latter is not a host-identity proof: protection relies on the trusted API/CRI
READY sandbox UID, PID/cgroup, PodIP and path association. Repeated CRI and
pinned-FD checks precede mutation. Namespace entry/restoration to the **own
agent Pod namespace** occurs on one locked OS thread. There is **no `/proc/<pid>/ns/net` fallback** and no claim of independent
PID-to-path namespace attestation beyond the CRI trust contract
([ADR-0014](adr/0014-cri-netns-agent.md)). CRI-socket access grants broad
node authority and Kubernetes RBAC cannot scope `list pods` by node field
selector alone.

## Client and gateway datapaths

The common `pkg/datapath.Backend` implements `ApplyClient`, `RemoveClient`,
`ApplyGateway` and `Close` for an already-entered namespace. `ClientConfig`
contains PodIP, GatewayID, one selected endpoint, compiled IPv4 policy,
exclusions, MTU, encryption and identity; it does **not** carry a standby list.
Selection uses stable rendezvous affinity over healthy endpoint PodIPs; removal
moves affected clients only. Changed exit IPs can break existing connections.

In `iproute`, client `rtk0` is a fixed-remote GENEVE device over UDP 6081 with
per-Gateway policy table `0x52540000 | (gatewayID & 0xffff)`. Managed routes
include an `unreachable` default at the fallback metric; a usable endpoint
also gets a preferred-source unicast default through `rtk0`. On closure the
owned unicast default is withdrawn before the link is removed. A route/output
nftables chain marks selective TCP/UDP policy matches, and `ip rule`s route
only marked traffic through the client table; exclusions and direct cluster
traffic use main. Metadata `169.254.169.254/32` is prohibited by default, even
though other link-local destinations are excluded; explicit
`allowCloudMetadata: true` allows only the documented direct bypass. An
nftables IPv6 all-hook guard blocks IPv6 packets without quarantining IPv4.
Persistent IPv4/IPv6 quarantine remains for lost authorization. The eBPF option selects plaintext client
traffic with a clsact/tc egress program and external GENEVE, with a fail-closed
update guard; it cannot manage WireGuard.

Gateway `gnv0` is collect-md GENEVE. The gateway-owned table 100 forwards
selected packets to `upstream0`; table 101 returns to exact selected client
PodIPs. Its default-drop nftables forward chain is the kill switch; locally
originated, marked and `SO_BINDTODEVICE`-bound upstream recovery probes still
use table 100 while forwarding is closed. The gateway verifies outer/inner
packet identity at GENEVE ingress (tc) against authorized client PodIPs;
WireGuard additionally denies plaintext UDP 6081 on the underlay. The Pod's
main default route remains on `eth0`; client and gateway use fixed local
GENEVE MAC/neighbor addresses. See [ADR-0008](adr/0008-fail-closed.md).

## Upstream and optional encryption

The shipped OpenVPN upstream shares the Gateway Pod network namespace. It
reads an allowlist-sanitized Secret under `/etc/ratatoskr/upstream`, creates
`upstream0`, leaves default routing and resolver management to the gateway,
and serves private `/healthz` and `/info` on `127.0.0.1:9901`. The controller
mounts a Pod-local writable `/dev/net` emptyDir and grants NET_ADMIN/MKNOD to
the upstream (not `privileged`). The **gateway container itself is privileged**
to set `net.ipv4.ip_forward` in its own Pod network namespace when an ordinary
container's `/proc/sys` is read-only. This broad privilege is not bounded by
NET_ADMIN/BPF capabilities: use a trusted gateway namespace that admits
privileged Pods, while `hostNetwork`, `hostPID` and hostPath stay off. No kubelet
unsafe-sysctl allowlist is requested. The plugin creates `/dev/net/tun` (char 10:200)
there if absent and verifies device number plus read/write access before
starting OpenVPN. No chart `gateway.tunDevice` or hostPath fallback exists
([ADR-0007](adr/0007-tun-device-access.md)). The configured exit probe is
bound and marked through `upstream0`; DNS lookup of a hostname still uses
normal Pod DNS, while the exit-IP HTTP(S) connection never falls back to main.

`encryption: none` sends plaintext GENEVE between client and gateway PodIPs.
`encryption: wireguard` (with iproute) carries that leg over per-Pod WireGuard
routes. The gateway's ephemeral public WireGuard key and TLS registration CA
are bound to its owner-verified Pod UID and published through Gateway status;
private keys do not enter status or Pod annotations. The agent requests a
short-lived, Pod-bound, audience-specific token, registers through pinned TLS
at Gateway PodIP:9443, and the gateway TokenReviews it and rechecks current
Pod UID, namespace, ServiceAccount, PodIP and gateway authorization before
installing a `/32` peer. On gateway-process restart persisted kernel peers are
cleared before new registration; peer lifecycle has TTL and deletion/opt-out
reconciliation. Encrypted gateways are limited to the operator namespace under
the current RBAC design ([ADR-0013](adr/0013-wireguard-registration-identity.md)).

## DNS, exclusions, MTU and evidence

`dns.mode: cluster` keeps workload DNS unchanged and directs DNS over the
cluster path, which is not a DNS privacy guarantee. `dns.mode: gateway`
rewrites selected Pod DNS to a dedicated gateway DNS Service; cluster zones
and reverse lookups use a literal `dns.clusterIP` override or the controller
Pod's ClusterFirst `/etc/resolv.conf` nameserver. No fixed kube-dns Service
name/namespace is required; matching labeled DNS Services and EndpointSlices
are also direct exclusions. Other requests traverse the bound upstream path.
Admission requires a healthy gateway DNS endpoint. Effective
IPv4 exclusions combine configured Pod/Service/extra CIDRs, Node addresses,
ServiceCIDR discovery where available, Kubernetes API and DNS endpoints, and
link-local space; unknown required cluster ranges block the Gateway instead
of guessing. Effective inner MTU accounts for IPv4/UDP/GENEVE/Ethernet,
optional WireGuard and measured upstream MTU; below 576 fails, below 1280
warns. Status only reports measured healthy endpoint MTU.

Gateway and agent expose process-lifetime programming counters/errors/duration,
and gateways expose health, link traffic, WireGuard and tracked TCP/UDP connection
samples. Metrics are enabled by default on separately configurable Pod listeners
and exposed through selector-restricted ingress, Services and optional Prometheus
monitors. These are aggregate samples, not per-workload flow attribution.
See the [monitoring guide](monitoring.md) for deployment and dashboard import.
Health and
readiness have separate endpoints. Unit and disposable-netns packet tests,
bounded synthetic fixtures and platform-specific live tests exercise distinct
claims. They must not be conflated with a cross-CNI, cross-mesh, cross-runtime
or external-provider compatibility certification.
