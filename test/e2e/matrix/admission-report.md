# Scoped M8 API/admission scaffold authoring report

## Approved UPDATE extension — October 30, 2026

UPDATE extension base: `2e604b6`; changes remain `test/e2e/matrix/**` only.
Parent approved one inert persisted Pod after verifying current k3d schedulingGate
support and absence of the never-schedule node label. This child **did not query
or execute the API**. The runner independently repeats label/barrier checks at
execution; it creates no Pod if CREATE dry-run rejects/prunes/changes the gate.

New separate `api-independent-update-validation` evidence requires exact retained
schedulingGate + never-match nodeSelector, no assignment/IP/container execution,
normal admitted security and UID checks. Four complete metadata-only server-dry-run
UPDATEs test benign annotation acceptance and exact validating-webhook rejection
of gateway-label, gateway-namespace and client-config tampering. The mutator must
be CREATE-only. Re-reading after each dry-run verifies no metadata/spec change;
resourceVersion and independent scheduler condition updates are not mistaken for
tamper persistence. No barrier is removed. Exact Pod deletion/absence is required
before Namespace cleanup; unsafe state or leftovers fail the overall report.

Cluster-free synthetic tests cover all four driver/datapath fixtures, missing/
changed gates/selectors, node label collisions, node/IP/container-start evidence,
metadata-only replacements and exact denial classification, unchanged-state checks,
cleanup ordering/leftovers and actual-evidence gating. Python source syntax is
compiled by static tests; existing matrix static regression checks and git diff
--check pass. No API runner, kubectl, Pod creation, image operation, provider
input, VM/cluster change or e2e traffic executed in this child. Parent owns actual
final-gate execution. Full compatibility matrix remains incomplete/non-green.

The original CREATE-only authoring report below is historical; its statements
that UPDATE remains unimplemented/no Pod is persisted are superseded **only for
this explicitly approved inert UPDATE fixture**. Healthy gateway selection and
other unimplemented traffic/CNI/mesh requirements remain uncovered.

Base: `7086139`. Scope: `test/e2e/matrix/**` only.

Added a separate bounded API-only final-gate tier for the existing flannel
release, including complete non-secret fixtures, server CRD/resource dry-runs,
authorized Pod mutation/security assertions, expected unauthorized CREATE
denials and conditional controller eBPF+WireGuard Unsupported rejection.
Actual workload Pods are never persisted; a missing-Secret Gateway is used to
assert fail-closed pending admission without a VPN or gateway Deployment.

Both EXPECTED_CONTROLLER_IMAGE_ID and EXPECTED_WEBHOOK_IMAGE_ID are required
immutable runtime IDs approved from current builds by the parent. Current M5
release image freshness is a parent-reported prerequisite blocker until rebuilt,
imported and rolled; it was **not queried or verified in this child**. Mutable
`:dev` tags alone cannot produce a pass. The harness never upgrades/reconfigures
the release, creates a cluster, reads Secret contents or attempts provider traffic.

The eBPF+WireGuard assertion is controller rejection (not schema/webhook rejection)
and is SKIPPED if the existing deployment uses iproute. Results are in the
separate `apiAdmission` inventory only after assertions, preflight and cleanup
execute; no unimplemented traffic/CNI/mesh cells become covered or green.
Independent validator tamper/UPDATE denial and healthy gateway selection remain
unimplemented and are not counted as the complete M2 admission scenario.

Validation performed in child: Python source syntax compilation through the
static checks; admission-static-check.py synthetic security/fixture/image-ID/
evidence-gating checks; existing matrix/static-check.py regression checks;
git diff --check. No API runner main, kubectl, cluster, live inputs, image
build/import, VM change or e2e traffic test executed. Parent owns actual final
API execution and must report blocked/stale-image results rather than a pass.
