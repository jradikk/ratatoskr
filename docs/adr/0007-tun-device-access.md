# ADR-0007: /dev/net/tun access for upstream plugins

- Status: Accepted
- Date: 2026-10-29

## Context

OpenVPN, AmneziaWG and some IPsec setups need `/dev/net/tun` inside the upstream container, without making the container `privileged`.

## Decision

Default `mknod`: the plugin entrypoint creates `/dev/net/tun` (`c 10 200`) with CAP_MKNOD. containerd's default device cgroup allows `c 10:200 rwm`; CRI-O does too via its defaults. Fallback `gateway.tunDevice: hostPath` mounts the host char device (`type: CharDevice`) for runtimes with stricter device policy.

## Alternatives considered

- Device plugin (e.g. squat/generic-device-plugin): an extra DaemonSet and an extra moving part, for an allowlist that is usually already present.
- `privileged: true`: far too broad.

## Consequences

The M1 component check (`test/component/tun.yaml`) succeeded on k3d/containerd:
OpenVPN created `upstream0` using only NET_ADMIN and MKNOD, without privileged
mode, a VPN profile or external traffic. The temporary namespace was removed.
This verifies the device access path on that runtime, not the live VPN datapath.
Other runtime device policies and the hostPath fallback remain to be verified;
revisit this ADR if a target runtime denies 10:200 by default.
