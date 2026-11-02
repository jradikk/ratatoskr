# Publishing a release

Release builds and publication run exclusively in
[release.yaml](workflows/release.yaml) on GitHub-hosted runners. Local build
commands are for development, not distribution.

## Repository setup

Configure these Actions secrets, never source-controlled credentials:

- `DOCKER_USERNAME`: Docker Hub account authorized to publish the six images.
- `DOCKER_PASSWORD`: Docker Hub access token with repository write permission.

For this repository, images use `docker.io/jradikk`. The token must be able to
publish every `ratatoskr-*` repository and its attestations. `GITHUB_TOKEN`
publishes the chart to GHCR and assets to GitHub Releases; repository policies
must allow the declared contents, packages, id-token, and attestations permissions.
Ensure published packages are publicly readable for the documented install path.

## Candidate review

1. Review the candidate source and CI results.
2. Check chart version/appVersion, image registry, and upgrade guidance.
3. Review security changes and the supported scope before publishing.

Publication is authorized by pushing a version tag. The workflow requires normal
CI validation, not a separate acceptance-ledger approval.

## Tag the reviewed source

```sh
git tag -a v0.1.0 -m 'Ratatoskr 0.1.0'
git push origin v0.1.0
```

Canonical `vX.Y.Z` tags create stable releases; `vX.Y.Z-rc.N` tags create
prereleases. There is no manual or
main-branch publication trigger. Never move a published tag to another commit.

## Published artifacts

The workflow validates the tag and runs reusable CI before publication:

1. Six component images for Linux amd64/arm64: controller, webhook, agent,
   gateway, init, and upstream-openvpn. Docker Hub receives versioned tags,
   Buildx SBOM/provenance, and GitHub provenance attestations.
2. Ten Linux binaries: five components for the two architectures, with source
   and version metadata and provenance attestations.
3. A Helm chart with version/appVersion matching the tag, published to
   `oci://ghcr.io/jradikk/charts/ratatoskr` after images and binaries succeed.
4. A GitHub release containing binaries, the chart, `IMAGE-DIGESTS.txt`, and
   `SHA256SUMS`, only after all preceding jobs succeed.

Attestation failures fail the workflow. Image matrix jobs publish independently;
a failed run can leave some images uploaded without a chart or GitHub release.
Inspect and rerun the same source/tag rather than treating partial publication
as a completed release. Tag protection and registry immutability are maintainer
responsibilities.

## Verify delivery

Check downloaded assets against `SHA256SUMS`. Verify GitHub provenance with
`gh attestation verify` for repository `jradikk/ratatoskr`, and verify images using
the immutable references in `IMAGE-DIGESTS.txt`, not only mutable tags.

After publication, install the OCI chart in a clean target cluster, verify that
all six image repositories are readable, and run the smoke/security scenarios
against the exact published digests. Artifact provenance establishes origin;
it does not by itself establish routing correctness or platform compatibility.
