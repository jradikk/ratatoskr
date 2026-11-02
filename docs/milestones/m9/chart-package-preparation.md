# M9 chart artifact preparation (no release)

**Status:** Local chart-only packaging and static-security validation. No
registry push, signed chart, Helm repository publication, or final traffic/e2e
validation is claimed by this preparation.

## Versioned package checklist

1. Confirm the source revision, CRD schemas, and five primary binary images
   (`controller`, `webhook`, `agent`, `gateway`, `init`) plus the OpenVPN upstream
   image were built and tested with matching, immutable release tags. The
   checked-in chart intentionally retains `version: 0.0.0-dev` and
   `appVersion: dev`; never publish that archive as a release.
2. Run `python3 charts/ratatoskr/tests/check_chart.py` (Helm and PyYAML needed).
   It strictly lints defaults/dev, parses driver/datapath/HA templates, tests
   security contexts and RBAC, packages twice in throwaway local directories
   and compares SHA-256 bytes, and checks the exact archive contents. Its
   release-override test packages with synthetic `1.2.3` metadata, renders
   version-derived component tags, and discards the archive. It neither signs
   nor publishes anything.
3. For a reviewed release `X.Y.Z`, stage a local chart using
   `helm package charts/ratatoskr --version X.Y.Z --app-version X.Y.Z
   --destination <private-staging-dir>`. Inspect its file list, Chart.yaml,
   CRDs and image references; record a SHA-256 digest for the *staged* archive
   in the release evidence. Do not commit an archive into the chart tree.
   This workflow does not by itself prove reproducibility across hosts, Helm
   versions, build toolchains or time zones.
4. Install or upgrade CRDs deliberately: Helm installs chart `crds/` only on
   initial install, and does not automatically upgrade or delete those CRDs.
   Apply a reviewed schema migration separately before an upgrade. Preserve
   webhook TLS Secret and ensure CA-bundle bootstrap can run in the release
   namespace. Never include Secret bytes or credentials in values, archives or
   log output.
5. Final project acceptance still needs the parent-owned runtime and full
   traffic/e2e gates. The static package check is not a substitute for
   gateway/agent packet tests, node security policy review, observability, or
   multi-replica failover validation.

## Security and artifact notes

The controller/webhook now explicitly run as UID 65532, without privilege
escalation or extra capabilities, with RuntimeDefault seccomp and read-only
root filesystems. Webhook TLS identities are created at runtime in a private
memory-backed volume, not included in the chart package. Agent mode remains
node-root-equivalent: hostPID, hostNetwork, node CRI socket, SYS_ADMIN and
NET_ADMIN, with BPF/PERFMON additionally on eBPF nodes. Review placement,
node policies and cluster-wide token-request RBAC before any real deployment.
The archive contains the CRDs, templates, default values/schema and README;
chart-local test sources and editor/temporary files are excluded by
`.helmignore`. The archive may be byte-identical in two local runs but is not
signed, attested or proven supply-chain reproducible without later gates.
