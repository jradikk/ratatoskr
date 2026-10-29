# ADR-0011: Rootful Docker for the k3d validation environment

- Status: Accepted
- Date: 2026-10-29

## Context

The Lima-based dev VM shipped with the system Docker masked and rootless Docker configured but never set up. eBPF tc programs need CAP_BPF/CAP_NET_ADMIN in the initial user namespace, and Cilium-on-k3d needs a host bpffs with shared propagation.

## Decision

Use the system (rootful) Docker daemon. The developer user is in the `docker` group. `hack/bootstrap.sh` verifies access and explains how to fix it.

## Alternatives considered

- Rootless Docker: cannot load tc BPF or run Cilium.

## Consequences

Docker group membership is root-equivalent; acceptable on a dedicated VM. Documented in the quickstart.
