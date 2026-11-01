# Release preparation guard — intentionally blocked

`hack/prepare-release.py` is an **offline, no-artifact readiness guard**, not a
release or staging implementation. Default invocation and `--execute` currently
return `BLOCKED` / exit 4. It never creates an output directory, invokes Helm,
Docker, a registry, a Kubernetes API, or a signing command.

The guard first reads the checked-in M9 acceptance ledger and calls the
independent `test/e2e/matrix/release_acceptance.py:assess` with exactly the
25 scenario IDs from `coverage.json` plus four fixed release gates. Any OPEN,
PARTIAL, missing, duplicate, empty-evidence, remaining-gap or unknown gate
blocks **before an artifact path is inspected or anything is written**. At
present the ledger is incomplete, so nothing can be staged. If every gate is
later independently reviewed as PASSED, execution still requires explicit
`--execute`, an exact clean current 40-character source SHA, a canonical
reviewed version (`X.Y.Z` or `X.Y.Z-rc.N`), and an absolute `--output` path.
Even then it unconditionally blocks because artifact verification is not
implemented. The output path is never created or read.

A future separately reviewed implementation needs an exact artifact allowlist,
independent provenance/manifest verification, immutable digest bindings,
secret/symlink/path safety, collision-safe private staging, and a release
security review. Neither this guard nor manually editing gate statuses proves
a build/release is trustworthy. Do not supply credentials or live provider
input to this tool. No images, chart packages, version tags, SBOMs, signatures,
PRs or publication are produced by it.

## Offline reviewed-artifact manifest policy (not wired into guard)

`artifact_manifest.py` is a pure validator, **not** proof of signature, trusted
build provenance, OCI index platform completeness, SBOM contents or release
readiness. It does not stage or publish. The current `prepare-release.py` guard
still unconditionally blocks after the ledger check; no acceptance gates were
changed. Validation is a separately callable future review primitive.

The exact schemaVersion 1 JSON object is `{schemaVersion, reviewedVersion,
sourceSHA, artifacts}` with no additional keys. A caller must independently
supply its reviewed canonical version (`X.Y.Z` or `X.Y.Z-rc.N`), full 40-character
source SHA and, preferably, a separately reviewed SHA-256 of the manifest bytes.
Each of exactly **29** artifact records contains `{role, name, size, sha256}`:

- Ten binary roles: `binary:{controller|webhook|agent|gateway|init}:{amd64|arm64}`;
  exact flat filename `ratatoskr-{component}-linux-{arch}.bin`.
- One chart role: `chart`; filename `ratatoskr-{version}.tgz`.
- Six multiarch OCI archive roles: `image:{controller|webhook|agent|gateway|init|upstream-openvpn}`;
  filenames `ratatoskr-{component}-multiarch.oci.tar`. These names describe
  claimed artifacts; no OCI index/architecture checks are performed here.
- Twelve evidence-document roles (six each): `sbom:{component}` and
  `provenance:{component}`; filenames `ratatoskr-{component}.{kind}.json`.
  Documents must claim the same reviewed source/version and corresponding
  image archive SHA-256 as subject. **These claims are structural and can be
  self-authored; they are not signatures or independent attestations.**

Names are exact flat POSIX-compatible names, denying traversal, symlinks,
hardlinks, secret-like suffixes, empty files or directories. `verify_files`
accepts an absolute private input directory **outside the checkout**, opens
only the declared 29 regular files with `O_NOFOLLOW`, checks inode/size/times
before and after bounded streaming SHA-256 reads, and limits each file to 1 GiB,
total declared size to 4 GiB, and each evidence JSON document to 2 MiB. It
never extracts archives, copies inputs, creates directories, or logs file
contents/paths. A returned `BYTES_MATCH_MANIFEST_NOT_ATTESTED` remains
`releaseReady: false`; a future reviewed trust/signature, archive safety,
provenance and policy gate is required before actual staging or publication.

## Strict OCI archive content check (separate, not release-ready)

`archive_contents.py:verify` accepts only a seekable, regular, single-link
already-open **uncompressed ustar** archive FD supplied by a future reviewed
caller (the caller must use O_NOFOLLOW and independently bind it to a manifest
SHA-256). It does not open artifact paths, extract or execute archive members,
copy data, call a cluster/registry, or produce an artifact. An explicit
pre-parser refuses GNU/PAX/extended/sparse headers, non-regular members,
symlinks/hardlinks/devices, unsafe names, duplicate entries, nonzero tails,
malformed header checksums, extra root files or unreferenced blobs. It bounds
at most 4,096 entries, 1 GiB per blob, 4 GiB total member bytes, and 2 MiB
for parsed OCI JSON. The archive itself must be at most 4 GiB.

Only `oci-layout` version `1.0.0`, `index.json` schema 2 OCI index mediaType,
exactly **two OCI image manifest descriptors** (`linux/amd64`, `linux/arm64`),
OCI image manifest schema 2, config descriptor, recognized layer mediaTypes,
and content-addressed `blobs/sha256/<digest>` are accepted. Every descriptor's
size/digest must match bytes, config `os`/`architecture` must match the declared
platform, and every blob must be referenced. Extra attestation manifests with
`unknown/unknown` platforms are explicitly **refused**, not silently ignored;
those need a separate reviewed policy. If your builder emits Docker mediaTypes,
compressed outer archives, root directories, embedded attestations or other
extensions, the strict validator blocks pending review rather than declaring
them verified. It does not inspect config environment or layer contents and
must not log those bytes. Its result reports `contentVerified: true` for this
bounded layout only, `signatureVerified: false`, `releaseReady: false`.

Local, cluster-free tests: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest
discover -s test/e2e/release -p 'test_*.py'`.
