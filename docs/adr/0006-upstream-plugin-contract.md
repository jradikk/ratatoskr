# ADR-0006: Upstream VPN as a pluggable container contract

- Status: Accepted
- Date: 2026-10-29

## Context

Providers use different VPN technologies. Hardcoding them would make the gateway image huge and the project hard to extend.

## Decision

An upstream is a container in the gateway pod that creates `upstream0`, serves `/healthz` and `/info` on `127.0.0.1:9901`, and never touches the default route or DNS. Shipped: openvpn, wireguard, amneziawg, strongswan. `type: custom` takes any image that honours the contract.

## Alternatives considered

- Gateway binary embedding VPN clients: licensing, size, and coupled release cycles.
- Host-level VPN: breaks per-gateway isolation.

## Consequences

The gateway only needs the interface name and the HTTP contract. Plugins must override provider-pushed routes/DNS; the OpenVPN sanitizer is unit-tested.
