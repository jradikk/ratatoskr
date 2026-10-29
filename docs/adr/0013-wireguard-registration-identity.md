# ADR-0013: Per-pod WireGuard peer identity and gateway registration TLS

- Status: Accepted design for M4 (implementation/verification pending)
- Date: 2026-10-29

## Context

The optional in-cluster underlay is WireGuard. A gateway must bind each peer's
public key to a currently selected pod IP after verifying a pod-bound,
audience-specific ServiceAccount token through TokenReview. The registration
request includes that bearer token and MUST use HTTPS; the gateway PodIP and
WireGuard public key change on replacement. The client private key must never
leave its node or enter Kubernetes API objects. M2 `init` clients are recreated
after a gateway PodIP change; M5 agent clients are updated in place.

## Decision

- Create the client private key inside the client pod netns (init driver in M4,
  node agent in M5); configure a kernel WireGuard device using wgctrl. Only the
  public key is sent to the gateway. The private key exists in process memory
  only until configured and remains in the kernel device; never write it to a
  Secret, annotation, ConfigMap, report or log.
- Gateway creates its own WireGuard key in its netns. The GENEVE outer addresses
  remain **client PodIP ↔ gateway PodIP**, with `/32` overlay routes through WG.
  WireGuard UDP transport uses a dedicated fwmark and a higher-priority `main`
  rule to avoid recursively routing its own endpoint through the WG interface.
  WireGuard peers are restricted to the respective pod IP `/32` in AllowedIPs.
- Gateway serves registration over TLS on TCP 9443, separate from its public
  readiness/info port. It generates an ephemeral in-memory self-signed CA and
  serving cert with the gateway PodIP as IP SAN. It publishes **only the CA
  certificate** in an annotation on its *own* Pod using the Kubernetes API;
  controller copies that public certificate to the matching Gateway endpoint
  status. The client verifies the HTTPS peer against the authenticated status
  CA and IP SAN. TLS private keys stay in gateway pod process memory on its node.
  No Secret containing them is created.
- The workload init receives a projected Pod-bound ServiceAccount token with
  audience `ratatoskr.skaldhall.io/gateway` (M4). Only that init container
  mounts it. The gateway submits the token to Kubernetes TokenReview with the
  same audience, requires `authenticated`, a matching returned audience and
  Pod name/UID extras, then GETs that Pod, its Namespace and EgressGateway to
  verify current UID, assigned PodIP, gateway opt-in, namespace selector and
  matching ServiceAccount. A key is bound to the verified PodIP only after all
  checks pass; configuration update and response are atomic from the client's
  perspective. Wrong/missing audience, deleted pod, missing PodIP or wrong
  gateway fails closed. No token value is logged or stored.
- Gateway watches selected pods and removes peers on deletion/opt-out; an
  explicit peer TTL backstops missed events. In M4 the gateway ServiceAccount
  is scoped to the operator namespace; multi-namespace gateway identities
  need reviewed dynamic ClusterRoleBindings before enabling that mode. Workload
  pods may still live in any allowed namespace.

## Alternatives and consequences

- Plain HTTP for registration exposes Pod-bound bearer tokens on the pod
  network, so it is prohibited even if WireGuard later encrypts data traffic.
- Trusting a gateway self-signed certificate fetched directly from its PodIP
  without authenticated API publication lets a pod-network attacker substitute
  the TLS identity. The Kubernetes status publication is the trust anchor.
- Generating gateway TLS private keys in the controller/Secret broadens
  credentials and RBAC; gateway-local keys avoid this, at the cost of changing
  CA/peer keys when the gateway Pod is replaced.

The endpoint public keys/certificates remain informational until the Kubernetes
API has observed and validated the gateway Pod identity. A gateway that cannot
publish its public certificate or review Pod-bound tokens is NotReady for
WireGuard mode. Packet capture and lifecycle results remain deferred to the
final e2e gate; this ADR alone proves nothing about runtime encryption.
