# ADR-0005: Network namespace programming drivers

- Status: Accepted
- Date: 2026-10-29

## Context

A selected workload's traffic must be steered before the application starts.
PSA `restricted` workloads cannot receive NET_ADMIN just to program their own
namespace.

## Decision

Two explicit Helm `driver` values share the `datapath.Backend` contract.
`init` injects a capability-bearing init container and cannot run in a
restricted namespace; it uses an applied-config acknowledgement before
programming a fixed Gateway PodIP. `agent` is the chart default: a host-network,
host-PID DaemonSet resolves the selected workload's READY sandbox using CRI,
enters its namespace under the checks in [ADR-0014](0014-cri-netns-agent.md),
and programs it. The injected wait-init needs no NET_ADMIN, no projected
Gateway token and no privileged workload sidecar. It waits for an UP
`rtk-ready` dummy link created only after programming succeeds.

## Alternatives considered

- CNI-specific chaining: requires ordering and support from each target CNI.
- Privileged workload sidecar: violates restricted admission and expands
  per-workload authority.

## Consequences

Init clients need rollout/recreation when a Gateway PodIP changes
([ADR-0012](0012-init-mvp-stable-endpoint.md)). The agent reconciles endpoint
changes and may adopt matching verified namespace state after its own restart;
its CRI socket and node privileges require explicit host-side trust.
