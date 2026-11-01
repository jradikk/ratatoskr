# Contributing to Ratatoskr

Thank you for contributing. Keep changes focused, include tests for changed
behavior, and explain any impact on routing, permissions, or upgrades.

## Getting started

Read the [architecture guide](docs/design.md) and
[architecture decisions](docs/adr/README.md). Tool versions used by CI and local
bootstrap are pinned in [`hack/versions.env`](hack/versions.env).

```sh
make help
make test
make lint
make build
```

`make test` runs Go race-enabled unit tests without a cluster. `make lint` checks
Go, shell syntax, and Helm. For the chart's rendered security/RBAC and archive
checks, install Helm and PyYAML, then run:

```sh
python3 charts/ratatoskr/tests/check_chart.py
```

Offline Python fixture tests can be run without credentials or a cluster:

```sh
for suite in test/e2e/advanced test/e2e/matrix/synthetic test/e2e/m1 \
  test/e2e/matrix test/e2e/platform test/e2e/release; do
  PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$suite" -p 'test_*.py'
done
```

## Local cluster

The k3d helpers create and delete development clusters. Review them before use;
bootstrap installs host tooling and loads kernel modules. Resource checks are
mandatory, and cluster changes should be deliberate.

```sh
hack/bootstrap.sh
make dev-up
make dev-deploy
# Remove the development cluster when finished:
make dev-down
```

`VARIANT=flannel|calico|cilium|cilium-wg` selects cluster configuration;
`MESH=none|sidecar|ambient` selects mesh setup. A setup option is not a claim that
all test scenarios pass in that combination. Local images use the `dev` tag and
are imported into k3d; registry publication is reserved for GitHub Actions.

## Networking tests

```sh
make test-privileged
```

Privileged component tests require root, kernel features, and network-namespace
access. Run them on a disposable Linux test host. End-to-end runners additionally
require explicit execution authorization and report incomplete or inconclusive
scenarios separately from passes. Read their guides before running:

- [Compatibility matrix](test/e2e/matrix/README.md)
- [Synthetic VPN scenarios](test/e2e/matrix/synthetic/README.md)
- [Advanced lifecycle and security tests](test/e2e/advanced/README.md)
- [Live VPN profile handling](test/e2e/m1/README.md)
- [External kernel runner](test/e2e/platform/README.md)

Never commit VPN profiles, keys, tokens, kubeconfigs, or packet captures. Keep
unredacted provider and cluster logs out of issues and pull requests.

## Review expectations

- Preserve fail-closed ordering and namespace/Pod identity checks.
- Do not broaden egress exclusions or Linux privileges to conceal test failures.
- Add focused regression tests and run validation appropriate to touched code.
- Keep user docs and Helm values accurate; API acceptance does not imply an
  upstream implementation exists.
- Treat CRD changes as upgrades requiring review, not just regenerated YAML.
- Keep the Go module and Kubernetes API group stable unless migration is an
  explicit part of the change.

Report vulnerabilities through [SECURITY.md](SECURITY.md), not public issues.
Maintainers publish matching versioned images, binaries, and charts using the
[release workflow](.github/RELEASING.md).
