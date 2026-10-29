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

Works on k3d (containerd) — verified in M1. The ADR is revisited if a target runtime denies 10:200 by default.
