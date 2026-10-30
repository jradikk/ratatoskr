# M8 incomplete coverage matrix

**All traffic execution is deferred to the final project gate.** The default
CI/live wrappers now build an inventory, not an e2e pass. They return **4** for
INCOMPLETE, including explicit or missing-profile skips. A listed unsupported or
unimplemented cell is SKIPPED/not covered. A selected subset passing does not
make the full matrix green. Error/failed run = 1; bad invocation or unauthorized
execution = 2. There is deliberately no green matrix exit while requirements
remain unimplemented.

`coverage.json` is the auditable source: 96 cells per fake/live mode and 25 named
scenario definitions. It is derived from docs/design.md and M2–M7 reports, not an
invented live steps 1–13 checklist. Only flannel/none/init/{iproute,ebpf}/none has
a direct-config runner. Cilium, Cilium-WireGuard, Calico, all meshes, agent and
WireGuard fixtures remain unimplemented. eBPF+WireGuard is unsupported and not
downgraded. Planned Cartesian combinations are not a compatibility guarantee.

## Static output and allowed validation

The wrappers' default mode reads local file/tool presence and builds JSON +
Markdown inventory outside the repo. It performs no subprocess/cluster request,
credential read, image operation or resource allocation. Tool presence is not a
resource/capability/image/runtime proof. Even default/skip CLI paths were **not
executed during authoring**; only the static checks below were run:

```sh
for script in test/e2e/ci/run.sh test/e2e/live/run.sh test/e2e/m1/run.sh test/e2e/m1/extended.sh; do
  bash -n "$script" || exit
done
sh -n test/e2e/m1/ipinfo.sh
python3 test/e2e/m1/static-check.py
python3 test/e2e/matrix/static-check.py
```

`static-check.py` loads pure inventory/config functions without calling runner
main. It prohibits subprocess calls while building inventory, checks 96 unique
cells per mode, checks missing evidence cannot be passed, and validates five
rendered non-secret selector JSON variants. M1's static validator parses all
nine complete YAML templates (25 documents), including eBPF capability scope.
No CLI inventory reports are claimed as e2e results.

## Future final-gate use — not authorization to execute now

At the final gate the wrappers accept `--execute` **and require**
`RATATOSKR_E2E_FINAL_GATE=1` in the environment. Options:

- `--mode=fake|live` (wrappers force their own mode), repeated `--cell=<id>` to
  select inventory cells; default executes the two implemented cells only.
- `--report-dir=/outside/repo/path`: JSON/Markdown inventory plus private
  per-cell checkpoint reports. Defaults to a private `/tmp/ratatoskr-m8-*` dir.
- `--no-build`: accepted; operator/parent already builds all local images.
- `--no-import`: images are already imported into the reused cluster.
- `--skip`: no execution, but still INCOMPLETE/nonzero, never a pass.

Cell IDs include `flannel/none/init/iproute/none` and
`flannel/none/init/ebpf/none`. Selecting an unimplemented cell yields no runner
execution and cannot inherit another cell's result. Exact checkpoint evidence
from the inner JSON is required before any individual scenario becomes PASSED.
Missing checkpoints are SKIPPED/not covered; external inconclusive remains so.

All selected runs are serial under a Linux process lock. Each calls the existing
bounded `hack/m1-proof.sh`, which uses mandatory `hack/k3d-up.sh` creation
resource/module preflight and flannel 1-server/2-agent topology. No alternate CNI
or mesh is installed here. Other existing Ratatoskr variants must be removed
using the existing lifecycle scripts before a flannel proof; no VM manipulation
or preflight bypass is added. The inner run removes its namespace/Secrets,
private input/payload files and newly-created cluster; reused cluster survives.
On a failed/timeout/cleanup run, orchestration stops rather than starting the
next cell on potentially dirty state. INT/TERM is forwarded to the active child
for bounded cleanup. SIGKILL/machine loss still requires operator orphan cleanup.

Extended fake checks are controlled direct-datapath tests: include/exclude CIDR
and TCP port selection, healthy endpoint withdrawal against the same reachable
remote with API/DNS preservation and steering restore, 4.5 MiB size/SHA256 payload,
measured MTU/MSS, and private health gauge 1/0/1 with PodIP:9902 denial. The remote
/32 is deliberately removed from pod exclusions only for selector tests; its
ordinary ClusterIP is not claimed to survive DNAT into that selected address
while the endpoint is withdrawn. It is restored for the normal M1 checks.
No real cloud-metadata request, raw capture, provider log or token dump occurs.

Live mode retains M1's exact inputs: outside-repo RATATOSKR_E2E_OVPN and optional
RATATOSKR_E2E_OVPN_AUTH paths, optional literal env IPINFO_TOKEN written privately
then projected as a Secret, optional RATATOSKR_E2E_EXPECT_COUNTRY. Missing profile
skips before cluster tooling, and private curl config keeps tokens out of exec
argv/logs. HTTP 429 gets at most one 10-second retry; external failure is
inconclusive. Live down/up metrics and provider disruption remain not covered.
Multiple VPN IP checks (including independent plugin health polling) can consume
provider/API rate limits; select only the required cell rather than repeating.

## Blocking gaps

See docs/milestones/m8/report.md and the inventory: CRD/admission, agent/restricted
workloads and restart adoption, authenticated WireGuard and capture denial,
gateway DNS/metadata/spoof/PMTU, HA, full telemetry, alternative CNI/mesh fixtures,
Linux 5.10 and late-IPv6/policy-failure runtime safety remain missing. Exact
original live 1–13 checklist must be supplied before final live acceptance.
This scaffold is **not complete M8 compatibility acceptance**.
