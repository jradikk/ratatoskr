# Delivery-focused validation plan

The user requested faster delivery and explicit deferral of noncritical edge
cases. The approximately 80% implementation estimate is subjective and is not
an acceptance percentage or production-release claim.

## Validation cadence

- Run targeted tests, vet/lint and builds for changed components.
- Run one integrated full validation checkpoint on the candidate source revision.
- Do not repeatedly run unchanged end-to-end fixtures for documentation or
  offline-parser-only changes.
- Preserve failures and scope limits. A deferred case is not a passed gate.

## Delivery-critical evidence

Existing scoped flannel/no-mesh evidence includes controller-managed synthetic
VPN traffic, selected fail-close/recovery with direct-path preservation,
WireGuard registration/revocation, wrong-audience rejection with peer identity
unchanged, gateway replacement, and same-workload agent restart. The supplied
OpenVPN init/iproute Germany subset also passed historically. Recheck the
chosen candidate's supported scope once against its exact source/image identities.

Do not defer credential leakage, routing escape, authorization bypass, invalid
artifact identity, or falsely labeled platform compatibility as edge cases.

## Deferred unless they affect the candidate's supported scope

- Further bespoke archive-format compatibility and parser hardening beyond
  demonstrable artifact integrity defects. Use standard tools for real artifacts.
- Broad telemetry refinements and optional flow logging.
- Established-flow continuity, which earlier HA checks did not assert.

Alternate CNI/mesh and Linux 5.10 are not proven. They can be excluded from a
limited experimental candidate only with explicit user-approved scope, and must
remain documented as untested rather than supported. The full acceptance ledger
continues to track these requirements independently.

## Next delivery decisions

1. Approve or decline serial replacement of the current flannel test cluster
   with Calico, followed by restoration. Do not remove it implicitly.
2. Choose full production acceptance or an explicitly limited experimental RC.
3. If a limited RC is approved, stage matching binaries, all six image components
   (including OpenVPN), Helm chart, release notes and checksums locally using
   standard tooling. Clearly label unsigned/unattested artifacts and untested
   configurations. Do not publish, push tags or claim production readiness.

The custom preparation guard and conservative archive validators are not a
shortcut to artifact provenance or full release acceptance. No acceptance gate
is changed by this plan.
