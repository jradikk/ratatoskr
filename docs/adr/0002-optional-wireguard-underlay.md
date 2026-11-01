# ADR-0002: Encryption as an optional WireGuard underlay

- Status: Accepted
- Date: 2026-10-29

## Context

Some clusters already encrypt pod traffic (Cilium WG/IPsec); others do not. GENEVE is unauthenticated.

## Decision

Per gateway `encryption: none | wireguard`. With `wireguard`, GENEVE packets between the client PodIP and gateway PodIP traverse per-Pod WireGuard `/32` routes. GENEVE outer addresses remain PodIPs, so selected-client identity checks still apply; encrypted mode also rejects plaintext GENEVE ingress and requires authenticated peer registration. The currently supported encrypted datapath is iproute, not eBPF.

## Alternatives considered

- IPsec/XFRM: heavier key management and harder to debug.
- Encrypting inside GENEVE: not possible without a custom protocol.
- Always encrypt: pays the cost twice on clusters with CNI encryption.

## Consequences

Registration requires Pod-bound audience tokens, pinned TLS, TokenReview and peer lifecycle ([ADR-0013](0013-wireguard-registration-identity.md)). WireGuard adds IPv4 transport overhead accounted for in MTU calculations. Its UDP transport is fwmarked to bypass the `/32` overlay routes.
