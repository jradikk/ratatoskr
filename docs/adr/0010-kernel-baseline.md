# ADR-0010: Linux kernel baseline and feature checks

- Status: Accepted
- Date: 2026-10-29

## Context

GENEVE, nftables, optional WireGuard and tc/eBPF require kernel capabilities
that vary independently of the reported kernel version.

## Decision

Require Linux kernel at least 5.10. Agent/gateway startup checks that baseline;
selected backend operations then fail closed if the required network devices,
netlink, nftables, WireGuard or tc/BPF features cannot be used. The eBPF
backend explicitly rejects WireGuard rather than falling back. This does not
mean startup creates and deletes every potential device or proactively probes
all features in a throwaway namespace. The GENEVE datapath uses Ethernet/L2,
not Linux `innerprotoinherit` L3 GENEVE.

## Alternatives considered

- Version check alone as a compatibility guarantee: kernels can omit modules,
  permissions and BPF helpers despite an adequate version.

## Consequences

Operators need backend-specific component and runtime tests on the selected
node/kernel; the minimum version is necessary, not certification.
