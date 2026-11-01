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
upstream is **OpenVPN only**; other upstream type names in API/design material
are not implemented images. Per-resource upstream image overrides are rejected.

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
