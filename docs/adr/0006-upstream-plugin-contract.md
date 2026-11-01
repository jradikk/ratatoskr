# ADR-0006: Upstream VPN as a container contract

- Status: Accepted
- Date: 2026-10-29

## Context

A gateway should not bundle every provider VPN implementation. A separate
container can share its network namespace while keeping provider configuration
outside the gateway process.

## Decision

The upstream container creates the L3 interface `upstream0`, reports
`/healthz` and `/info` on pod loopback `127.0.0.1:9901`, and does not take
control of the Pod's main default route or resolver. The gateway owns policy
routing, forwarding and the kill switch. The **shipped and admitted** upstream
implementation is OpenVPN: its Secret-mounted profile is allowlist-sanitized
and provider-pushed route/DNS/script controls are rejected or stripped. Other
types, including `custom`, have reserved API fields but are rejected by current
admission/controller; a user-supplied image is not currently a deployment path.

## Alternatives considered

- Embed VPN executables in the gateway: couples privileges, licensing and
  releases to the datapath image.
- Node-wide VPN: cannot isolate a gateway's selected clients and namespace.

## Consequences

A new upstream type requires a reviewed implementation/admission/controller
path and the same tunnel, health, routing and Secret handling contract. Merely
adding an image or CRD enum value cannot enable a provider.
