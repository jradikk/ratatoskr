# ADR-0002: Encryption as an optional WireGuard underlay

- Status: Accepted
- Date: 2026-10-29

## Context

Some clusters already encrypt pod traffic (Cilium WG/IPsec); others do not. GENEVE is unauthenticated.

## Decision

Per gateway `encryption: none | wireguard`. With `wireguard`, the GENEVE packets between client pod IP and gateway pod IP are routed through a per-pod WireGuard tunnel. Outer GENEVE addresses stay pod IPs (spec issue S2), so gateway logic is identical in both modes.

## Alternatives considered

- IPsec/XFRM: heavier key management and harder to debug.
- Encrypting inside GENEVE: not possible without a custom protocol.
- Always encrypt: pays the cost twice on clusters with CNI encryption.

## Consequences

Needs a registration API with TokenReview auth and peer lifecycle (M4). Adds 60 B of overhead (IPv4), which the MTU math accounts for. WireGuard UDP is fwmarked to bypass the /32 routes it serves.
