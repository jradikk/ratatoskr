# ADR-0014: Entering workload network namespaces from the node agent

- Status: Accepted
- Date: 2026-10-29

## Context

The agent must program a selected workload namespace without giving the
workload NET_ADMIN. Standard CRI does not promise a portable network namespace
path or PID, but supported containerd verbose PodSandboxStatus reports both.
The CRI socket is a powerful node-level trust boundary.

## Decision

A `hostPID: true`, **`hostNetwork: false`** DaemonSet mounts the node's CRI
socket and host `/var/run/netns` with HostToContainer propagation. At startup
it GETs its own Pod uncached and verifies exact Downward API
namespace/name/UID/node identity, ServiceAccount, separate Pod netns, hostPID,
non-deleting status and the exact `host-netns` hostPath volume mounted read-only
at `/var/run/ratatoskr/host-netns`. Kubelet bind-mounts node `/proc/1/ns/net`;
the agent does **not** directly open that ptrace-gated proc path. It pins the
current agent thread's own netns FD for restoration and opens only the fixed
mounted host network namespace as a **forbidden anchor** (`O_NOFOLLOW`). Both
FDs must be nsfs network namespace objects and their inodes must differ; an
unavailable or invalid mount fails closed. No CRI workload namespace is derived
from this host anchor or a `/proc` PID path.

For each selected Pod, require exactly one READY CRI sandbox with matching
namespace, name, Pod UID and PodIP. Its verbose status must supply a PID and
**exactly one** `runtimeSpec.linux.namespaces` network path. Trust the CRI
sandbox-ID-to-netns-path mapping; do not independently claim the PID's netns
inode attests that path. A pidfd pins the live PID and its cgroup must contain
the selected Pod UID. Open only a direct child of `/var/run/netns` using
`openat2` confinement (`RESOLVE_BENEATH`, no symlinks or magic links); validate
nsfs and `CLONE_NEWNET`, reject both agent-own and host anchors and verify the
target has the expected PodIP as its sole `eth0` IPv4. Recheck sandbox ID,
state, PID, path, UID, PodIP and pinned FD inode before mutation. Enter and
restore to the **agent Pod's own** namespace on a locked OS thread; a failed
restoration is fatal, never hidden.

There is **no** fallback that constructs `/proc/<pid>/ns/net` from the PID or
accepts arbitrary paths. An unsupported/malformed CRI payload fails closed.
The former `setns(pidfd)` independent attestation approach was rejected for
the validated RuntimeDefault environment, which denies it.

## Alternatives and consequences

- A workload-privileged helper violates restricted Pod admission.
- Using annotations as sandbox ownership proof permits forged identity; the
  CRI/Pod/API and namespace checks are required instead.
- A CNI veth-name shortcut is not a portable Pod namespace identity.

The agent can adopt a matching UP `rtk-ready` marker and authorized config on
restart after backend verification; changed Gateway endpoints require in-place
reprogramming. A mounted CRI socket confers broad node authority, and ordinary
Kubernetes RBAC cannot restrict Pod LIST to one node by field selector.
