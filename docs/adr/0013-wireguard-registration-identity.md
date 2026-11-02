# ADR-0013: Per-pod WireGuard peer identity and gateway registration TLS

- Status: Accepted
- Date: 2026-10-29

## Context

Optional WireGuard encryption must bind each peer public key to a currently
selected PodIP without publishing private keys or trusting a bearer token on a
plaintext, unauthenticated registration channel.

## Decision

- The iproute client and gateway configure kernel WireGuard devices in their
  own network namespaces; GENEVE addresses remain the client and gateway
  PodIPs. The private keys stay in node process memory and kernel state, never
  in API objects. WireGuard UDP uses a dedicated fwmark so `/32` peer routes
  cannot recursively steer its own transport.
- Gateway registration listens on TCP 9443 with an in-memory ephemeral TLS
  identity. The gateway publishes the **public CA certificate** on its own
  Pod; the controller binds it, its public WireGuard key and applied-client
  hash to the verified Gateway Pod UID/status. The client pins that CA and
  checks the PodIP SAN rather than accepting an arbitrary self-signed peer.
- Init clients use a projected Pod-bound, audience-specific ServiceAccount
  token; the node agent uses an in-memory Pod-bound TokenRequest for the
  selected workload. Gateway TokenReview checks authenticated identity and
  audience, then re-reads Pod, Namespace, Gateway and ServiceAccount bindings
  before configuring `/32` AllowedIPs. No token is persisted or logged.
- Gateway registration clears old kernel peers after its process restarts,
  before serving new registration. Pod deletion/opt-out and a TTL reconcile
  peer bindings. WireGuard gateways currently require the operator namespace
  because registration RBAC is scoped there; eBPF + WireGuard is rejected.

## Alternatives and consequences

- Plain HTTP exposes a Pod-bound bearer token to the Pod network.
- Fetching an unauthenticated CA directly from PodIP lets an attacker
  substitute the registration peer.
- Storing a private key in a controller Secret broadens credential exposure.

Replacing the gateway changes its PodUID and published TLS/WireGuard
identity; clients must authenticate the new endpoint rather than reusing the
old trust root. Component tests are not a claim of cross-provider encryption
compatibility.
