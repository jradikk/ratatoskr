# ADR-0005: netns programming drivers: init (MVP) and agent (default)

- Status: Accepted
- Date: 2026-10-29

## Context

Something must program each client pod's netns. Workloads in PSA `restricted` namespaces cannot have NET_ADMIN.

## Decision

Two drivers behind one interface. `init`: the webhook injects an init container with NET_ADMIN that programs the netns (MVP; not PSA-restricted compatible). `agent` (default): a node DaemonSet resolves the pod's netns via CRI `PodSandboxStatus` (verbose info → runtime spec netns path) and programs it. The webhook injects an unprivileged wait-init that blocks until the agent creates the `rtk-ready` marker link (spec issue S5), giving fail-closed startup.

## Alternatives considered

- CNI chaining plugin: depends on each CNI's chaining support and conflicts with Cilium exclusive mode and Istio CNI ordering.
- Sidecar with NET_ADMIN: violates `restricted` PSA.

## Consequences

The agent is privileged (documented). It has to handle restarts without dropping flows: the netns state is self-contained, and the agent reconciles idempotently. The CRI socket path is configurable (k3s: `/run/k3s/containerd/containerd.sock`).
