# ADR-0014: Entering workload network namespaces from the node agent

- Status: Accepted for M5 (validation pending)
- Date: 2026-10-29

## Context

The `agent` driver must program the same backend as the M2 init driver while
workload containers, including `restricted` Pod Security namespaces, need no
network capability. PodSandboxStatus in the CRI identifies the sandbox, but the
standard CRI does **not** guarantee a portable PID or netns path field. k3d's
containerd currently reports a sandbox PID and `runtimeSpec.linux.namespaces`
network path in the verbose status info (verified on k3d flannel).

## Decision

Run a node-scoped DaemonSet with hostPID and NET_ADMIN/SYS_ADMIN, not a privileged
workload. The agent obtains only Pods assigned to its node and queries the node's
CRI socket for the sandbox matching Pod namespace/name/UID. Prefer an explicitly
reported absolute network namespace path within mounted host `/var/run/netns`;
otherwise resolve the reported sandbox PID to `/proc/<pid>/ns/net` in the
hostPID namespace. Verify the Pod UID and process/netns identity again before
programming; never open an untrusted path outside the allowed host netns/PID
mounts. Lock the Go OS thread, enter the Pod netns, create the backend, apply
routes/nft/WG, then restore the original netns and unlock even on failure.

The webhook injects **only** a capability-free wait-init for `driver: agent`.
It polls a dummy `rtk-ready` link in its own netns and exits only once the
agent has installed a fail-closed datapath. The agent installs the marker last
and patches the Pod readiness annotation for observability; on missing or
failed programming, it leaves/sets unready and retries with bounded backoff.
On agent process restart, an unchanged config hash and marker allow adoption
without destroying the existing tunnel/rules (established-flow continuity).
Gateway endpoint changes cause in-place reprogramming; moved flows may break
as documented in ADR-0009, but no traffic may fall back to main routing.

## Alternatives and consequences

- An always-running privileged helper in workload Pods violates restricted PSA.
- The init container's Pod annotation projected with Downward API refreshes
  asynchronously and cannot provide a reliable fail-closed startup handshake.
- CNI-specific network APIs or host veth naming assumptions do not cover the
  requested heterogeneous CNIs. A CRI runtime that does not expose a safe PID
  or netns path must fail clearly and report the unsupported runtime, not guess
  a host path or program the host namespace.

The node agent is a powerful component and needs narrowly scoped Pod/Node/CRD
reads plus access to the CRI socket and hostPID. Gateway peer registration in
M5 uses a Pod-bound token requested through TokenRequest and authenticated by
the M4 TokenReview path; the agent must not copy private WireGuard keys to any
Kubernetes resource. Mounting a CRI socket grants node-root-equivalent power
and cannot be made safe solely with Kubernetes RBAC; document node isolation
and security review before a production release.
