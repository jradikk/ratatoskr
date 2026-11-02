# Gateway controller

This package reconciles `EgressGateway` resources and the Kubernetes objects
needed to run them. The executable is [cmd/controller](../../cmd/controller/);
use the [Helm chart](../../charts/ratatoskr/) for deployment and RBAC rather than
assembling permissions from this package alone.

## Responsibilities

- Allocate a persisted, collision-checked GENEVE gateway ID.
- Select opted-in IPv4 workload PodIPs from explicitly allowed namespaces,
  including Pods waiting for their datapath init barrier. An absent namespace
  selector authorizes no workloads.
- Render an owned Deployment, discovery Service, `gateway.json` ConfigMap and
  ingress NetworkPolicy. The selected client list is non-secret, but it is an
  authorization input and must remain controller-owned.
- Discover Pod/Service exclusion CIDRs and cluster DNS; publish measured MTUs,
  gateway endpoint identities and readiness conditions.
- Read gateway port 9900 `/info` and attest its applied-config hash against the
  exact expected ConfigMap bytes and current gateway Pod UID. A ConfigMap API
  write is not proof that its projection has been applied in the gateway netns.
- Reconcile init-driver completion and applied-client acknowledgments. In agent
  mode the node agent owns workload datapath readiness instead.

The UDP/6081 Service is for discovery, **not** a client GENEVE remote. Clients
use healthy gateway **PodIPs** from status. The gateway process, not the
controller, programs its network namespace and polls the upstream's private
127.0.0.1:9901 health API.

## Supported combinations

The renderer supports 1–32 gateway replicas, `init` or `agent` client drivers,
`iproute` or opt-in `ebpf` datapaths, and cluster or gateway DNS. The shipped
upstream is **OpenVPN only**. Both webhook admission and controller
reconciliation reject every other upstream type. The `custom` enum is reserved
for future implementations, not a deployable escape hatch; per-resource upstream
image overrides are also rejected. The plugin contract is contributor guidance,
not evidence that other upstream images are available.

`wireguard` encrypts the **client-to-gateway GENEVE transport**, not the provider
VPN. It requires `iproute`, a gateway in the operator namespace and authenticated
peer registration. The eBPF backend rejects WireGuard rather than falling back
to plaintext. Unsupported combinations are reported as `Unsupported`; an owned
Deployment is removed rather than forwarding under an invalid contract.

Init-driver Pods retain their original gateway remote/trust identity. Endpoint
loss or replacement can set `ClientRestartRequired`: roll out affected clients.
Agent-driver Pods can reconcile their endpoint in place. Endpoint changes can
still break established flows; they do not promise transparent session failover.

## Configuration and boundaries

Required controller environment: `OPERATOR_NAMESPACE`, `GATEWAY_IMAGE`,
`OPENVPN_IMAGE`. Optional values read by `OptionsFromEnv`:

| Environment | Purpose |
|---|---|
| `DRIVER`, `DATAPATH` | Client programming driver and backend; the chart defaults to agent/iproute. |
| `IMAGE_PULL_POLICY` | Pull policy for rendered containers. |
| `SERVICE_CIDRS`, `POD_CIDRS`, `EXTRA_CIDRS` | Comma-separated IPv4 discovery fallbacks/additional exclusions. |
| `CLUSTER_DOMAIN` | Cluster DNS suffix; defaults to `cluster.local`. |
| `GATEWAY_UPSTREAM_DNS_IP` | Optional unicast IPv4 resolver for gateway-mode external DNS. |
| `GATEWAY_UPSTREAM_PROBE_URL` | Operator-only literal unicast IPv4 HTTP(S) override; no credentials/query/fragment. Empty retains the OpenVPN plugin default. |

The manager exposes `/healthz` and `/readyz` on 8081 and supports
`-leader-elect`. These are controller-process checks, not VPN or workload
connectivity proofs.

Secrets are obtained through uncached GETs, never list/watch. The controller
checks that `client.ovpn` is nonempty; it does not parse or log provider material.
The Secret is mounted only into the upstream container. OpenVPN validates
referenced files and sanitizes provider options. Failures use fixed categories
in status/Events instead of private API/provider error text.

Readiness requires consistent **measured** Pod/GENEVE/upstream MTUs. Do not infer
link MTUs from defaults. Valid IPv4 MTUs below 1280 emit an IPv6-minimum warning;
IPv6 forwarding itself is not supported.

### Gateway forwarding prerequisite

Gateway Pods explicitly request **only** `net.ipv4.ip_forward=1` under their
Pod `securityContext.sysctls`. This enables forwarding in the Gateway Pod's
**own network namespace** before its gateway and upstream containers start;
workload Pods and the node's host network namespace are not configured by this
setting. A restricted/container-default read-only `/proc/sys` cannot reliably
set forwarding from the gateway binary even with NET_ADMIN. The backend still
checks the live value and fails closed if it is not `1`; neither readiness nor
selected-client acknowledgement should be published on failure.

Kubernetes treats this namespaced sysctl as **unsafe**, not default-allowed.
An operator must explicitly authorize the exact `net.ipv4.ip_forward` key in
the kubelet `allowedUnsafeSysctls` setting on **each node eligible for Gateway
Pods** (or provide a separately reviewed node-policy mechanism that sets the
same Pod-netns value before containers start). This is an operational prerequisite,
not a chart-side automatic kubelet change: nodes without the approval reject
Pod sandbox creation and the Gateway stays unavailable. Do not allowlist
`net.ipv4.*` broadly, mount a writable host `/proc`, add SYS_ADMIN/privileged,
or switch the Gateway to host networking. Existing Pods must be recreated to
receive a new Pod-level sysctl. On clusters that prohibit this unsafe sysctl,
Gateway forwarding is unsupported without a separately designed, validated
alternative; do not claim traffic-gate success from the rendered spec alone.

Gateway NetworkPolicies constrain ingress, not egress. Port 9900 remains open
for portable controller/kubelet access. Gateway DNS creates a separate Service
for TCP/UDP 53 to port 1053 and preserves cluster DNS availability while external
VPN DNS is unhealthy. WireGuard registration adds its authenticated ingress
contract. Review [render.go](render.go) and chart policies before tightening or
exposing these listeners; NetworkPolicy enforcement depends on the CNI.

## Contributing

From the repository root:

```sh
go test ./pkg/controller/...
go vet ./pkg/controller/...
go build -o /tmp/ratatoskr-controller ./cmd/controller
```

Tests use fake Kubernetes clients and controlled HTTP responses. Changes to
selection, rendering or endpoint status should cover absent namespace selectors,
foreign ownership, stale UID/hash acknowledgments and failure cleanup. Avoid
fixtures containing real profiles, credentials, tokens or private keys. Unit
checks do not establish a CNI/runtime's live datapath behavior.
