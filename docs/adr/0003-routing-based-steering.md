# ADR-0003: Routing-based steering, never REDIRECT/DNAT on clients

- Status: Accepted
- Date: 2026-10-29

## Context

Istio sidecars redirect traffic to Envoy with iptables, and ambient's ztunnel opens sockets inside the pod netns. Rewriting destinations on the client would break original-destination semantics for both.

## Decision

Clients select traffic with routing: `ip rule` + a per-gateway table, nft only to set fwmarks for port rules (iproute), or a tc egress program that redirects after routing (ebpf). Destinations are never rewritten.

## Alternatives considered

- iptables REDIRECT to a local proxy: conflicts with Istio's capture and needs a userspace proxy.
- Transparent proxy (TPROXY): same conflicts, plus extra privileges.

## Consequences

Envoy and ztunnel upstream sockets follow the same routing decisions as the app, so all three mesh modes work. Port-based rules need nft marks (a small, mesh-compatible nft table). Replies to inbound connections need a connmark bypass (spec issue S8).
