# ADR-0003: Routing-based steering, never REDIRECT/DNAT on clients

- Status: Accepted
- Date: 2026-10-29

## Context

Mesh sidecars and ambient agents may open sockets in a workload network
namespace. Rewriting destinations for a local proxy would obscure the
original destination and conflict with other capture rules.

## Decision

The iproute client uses `ip rule`/a per-gateway routing table plus an IPv4
nftables route/output chain to mark selected CIDR and TCP/UDP-port rules. The
eBPF client uses a clsact/tc egress selector and external GENEVE. Neither
path REDIRECTs or DNATs the application's destination. Unselected cluster
traffic retains the main CNI route; selected traffic has an unreachable or
terminal-drop fallback.

## Alternatives considered

- REDIRECT/TPROXY to a local proxy: adds interception ordering and a process
  with its own permissions and failure modes.

## Consequences

Traffic from sidecar or ambient sockets inside the Pod namespace follows the
same selected routing rules, subject to the CNI/mesh's real packet path.
This architectural choice does **not** itself certify every Istio mode or CNI;
those require separate packet and live compatibility evidence.
