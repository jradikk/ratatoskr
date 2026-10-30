# Scoped M8 API/admission scaffold authoring report

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
