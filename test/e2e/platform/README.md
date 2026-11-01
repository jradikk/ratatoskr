# Linux 5.10 component gate

`runner.py` checks privileged components on an operator-approved Linux 5.10.x
`amd64`/`arm64` host. It does **not** provision a VM, create a cluster, build
images or establish CNI/mesh/VPN traffic compatibility. It requires a clean
checkout, exact current source SHA, native Go toolchain and preinstalled test
prerequisites before one bounded `make test-privileged` invocation.

Only after independent host/operator approval:

```sh
RATATOSKR_E2E_FINAL_GATE=1 RATATOSKR_E2E_PLATFORM_510=1 \
  python3 test/e2e/platform/runner.py --execute --source-sha <full-current-HEAD>
```

A newer kernel cannot substitute for 5.10. Even successful component checks
return **4 / INCOMPLETE**; actual traffic and release acceptance are separate.
No raw tool output or credentials belong in reports. Offline tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/platform -p 'test_*.py'
```
