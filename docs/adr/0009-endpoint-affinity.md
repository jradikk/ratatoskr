# ADR-0009: Sticky gateway selection with rendezvous hashing

- Status: Accepted
- Date: 2026-10-29

## Context

Replicas exit through different VPN IPs. Balancing flows across them would change a workload's apparent source IP per connection.

## Decision

Each client pod uses one endpoint, chosen by HRW (rendezvous) hashing of (podUID, endpoint IP) over healthy endpoints. Failover re-hashes only the pods of the failed endpoint.

## Alternatives considered

- ECMP or per-flow hashing: exit IP churns per connection.
- Consistent-hash ring: more state, no benefit at gateway replica counts.

## Consequences

Failover is connection-breaking (a new exit IP), and this is documented. The function is shared by both datapaths and unit-tested.
