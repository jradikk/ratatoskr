# ADR-0007: `/dev/net/tun` access for the OpenVPN upstream

- Status: Accepted
- Date: 2026-10-29

## Context

OpenVPN needs character device 10:200 without a privileged container or a
host-network mount. A read-only image may not have a writable `/dev/net`.

## Decision

The controller renders a **Pod-local writable `/dev/net` emptyDir** mounted
into the upstream container. Its security context grants NET_ADMIN and MKNOD,
drops all other capabilities and does not set `privileged: true`. The plugin's
`EnsureTUN` creates `/dev/net/tun` (10:200, mode 0600) if absent, verifies an
existing path is the right character device and attempts an O_RDWR open before
starting OpenVPN. If the runtime device cgroup denies access, it fails closed.
There is **no** chart `gateway.tunDevice` option or implemented hostPath
fallback; documentation must not invite use of one.

## Alternatives considered

- HostPath `/dev/net/tun`: broadens host device exposure and is not rendered
  by the current controller.
- Fully privileged upstream: unnecessarily broad authority.

## Consequences

The Pod-local path avoids reliance on an existing host device node but still
needs runtime permission for character device 10:200. The disposable component
fixture exercises one runtime; it does not certify all CRI device policies or
external VPN connectivity.
