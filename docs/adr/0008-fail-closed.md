# ADR-0008: Fail-closed semantics

- Status: Accepted
- Date: 2026-10-29

## Context

Steered traffic must not silently fall through to direct egress when a Gateway,
peer, tunnel or upstream is unavailable.

## Decision

The iproute client table has an owned `unreachable` default; a healthy tunnel
has a preferred unicast route and a closed client withdraws that route before
removing its GENEVE link. The selective nft mark / policy rules continue to
lookup the unreachable fallback. eBPF uses a terminal drop guard across
fallible updates and drops selected traffic without a usable endpoint. Init
programming and agent wait-init block application startup until the selected
path is ready. Gateway forwarding has a default-drop nft kill switch and
unreachable fallback in table 100; locally marked upstream recovery probes
remain possible while forwarding is closed. Agent authorization loss or
unsupported workload IPv6 invokes persistent namespace quarantine rather than
trusting potentially forged Pod annotations. `failMode: open` is not supported.

## Alternatives considered

- Fail-open fallback: violates the selected workload's egress policy.
- Trusting the readiness annotation alone: metadata is not proof of a usable
  namespace route or an applied Gateway config.

## Consequences

Steered connections may fail visibly during outage or peer changes; direct
cluster traffic follows exclusions unless persistent quarantine applies. No
`prohibit default` switch is required or claimed as implemented.
