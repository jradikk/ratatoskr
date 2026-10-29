# ADR-0008: Fail-closed semantics

- Status: Accepted
- Date: 2026-10-29

## Context

Steered traffic must never leak through the node's normal egress when the gateway, tunnel or VPN is down.

## Decision

Client: table N has an `unreachable` default at max metric, and is switched to `prohibit` when no endpoint is healthy (fast failure). eBPF drops with a counter. Startup: workloads cannot start before the datapath is programmed (init driver programs synchronously; agent driver has the wait-init). Gateway: forwarded traffic may only exit via `upstream0` (nft kill switch, policy-drop forward chain, `unreachable` fallback in table 100); the gateway goes NotReady when the upstream is unhealthy.

## Alternatives considered

- Fail-open option in v1: deliberately deferred. `failMode` exists in the API, but only `closed` is accepted.

## Consequences

Gateway outages cause visible connection failures for steered traffic. HA (M7) mitigates this.
