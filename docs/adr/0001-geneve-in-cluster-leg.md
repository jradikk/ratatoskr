# ADR-0001: GENEVE for the in-cluster leg

- Status: Accepted
- Date: 2026-10-29

## Context

Client pods must reach a gateway replica over any CNI, carrying the original packet unmodified plus optional workload identity.

## Decision

Client → gateway traffic is always GENEVE-encapsulated (UDP 6081). The gateway terminates it with a single `external` (collect_md) device. Both client datapaths produce GENEVE.

## Alternatives considered

- VXLAN: no extensible options, so identity could not travel with the packet.
- IP-in-IP/GRE: needs non-UDP protocols, which some CNIs and cloud firewalls drop. Also has no metadata.
- Plain WireGuard only: makes encryption mandatory and gives two datapaths to maintain.

## Consequences

One datapath, written once. Identity travels in TLVs (informational unless the packet arrived via WireGuard). UDP 6081 must be allowed pod-to-pod; the chart ships NetworkPolicies that restrict it to gateway pods. The Linux GENEVE device is L2, so fixed MACs and permanent neighbours are needed (design §4.1). It coexists with Cilium's own GENEVE tunnel because ours lives in pod netns.
