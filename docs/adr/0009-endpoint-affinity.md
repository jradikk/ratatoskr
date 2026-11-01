# ADR-0009: Sticky gateway selection with rendezvous hashing

- Status: Accepted
- Date: 2026-10-29

## Context

Replicas exit through different VPN IPs. Balancing flows across them would change a workload's apparent source IP per connection.

## Decision

Each selected client Pod uses one endpoint, chosen by HRW (rendezvous) hashing of `(PodUID, gateway PodIP)` over healthy endpoints before either datapath is programmed. Removing a failed endpoint keeps unaffected clients on their chosen endpoint; the agent reprograms affected existing Pod namespaces after a fresh applied-config acknowledgement. Init clients retain their fixed endpoint until recreated.

## Alternatives considered

- ECMP or per-flow hashing: exit IP churns per connection.
- Consistent-hash ring: more state, no benefit at gateway replica counts.

## Consequences

An affected client's existing connections can break when the new gateway has a different exit IP; neither selection nor reprogramming promises flow continuity. The selection function is shared by both client datapaths and unit-tested. See [ADR-0012](0012-init-mvp-stable-endpoint.md) for the init-mode fixed remote.
