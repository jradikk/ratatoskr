# ADR-0001: GENEVE for the in-cluster leg

- Status: Accepted
- Date: 2026-10-29

## Context

A selected workload must reach a gateway replica through a Pod-network path
while preserving the inner packet's destination for gateway policy routing.

## Decision

The client-to-gateway leg uses L2 GENEVE over UDP 6081 with client and gateway
**PodIPs** as outer addresses. Clients use a fixed-remote GENEVE link in
iproute mode or an external/collect-md link selected by tc in eBPF mode;
the gateway terminates on a collect-md GENEVE device. Fixed local MACs and
permanent neighbors support the inner Ethernet frame. An optional WireGuard
underlay encrypts this leg without changing the outer GENEVE PodIP identity.

## Alternatives considered

- VXLAN: does not provide extensible GENEVE options if packet identity is
  later transported as metadata.
- IP-in-IP/GRE: depends on non-UDP transport through CNIs and firewalls.
- Mandatory WireGuard: duplicates cluster encryption cost when not needed.

## Consequences

Gateway ingress validates packet source/selected-client identity and must
fail closed on unauthenticated or unexpected packets. NetworkPolicy limits
allowed Pod-network ingress, but is not itself authentication. The existence
of GENEVE extension options does not imply they are an authenticated
workload-identity credential.
