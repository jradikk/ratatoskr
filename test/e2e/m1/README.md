# M1 manual proof scaffold — executions deferred

> M8 update: `test/e2e/ci/run.sh` and `test/e2e/live/run.sh` now default to the
> incomplete **static matrix inventory**, not this original M1 execution wrapper.
> They return exit 4 for missing coverage. See `test/e2e/matrix/README.md` and
> `docs/milestones/m8/report.md`. `hack/m1-proof.sh` retains its M1 direct entrypoint;
> optional `--extended` / `--datapath=ebpf` requires explicit final-gate authorization.
> M1 interface/examples below are historical subset documentation, not a matrix pass.

**Do not run any fake or live e2e now. All e2e executions are deferred to the
final project gate.** This is initial M1 tooling, not the complete end-state
suite. No CI workflow is enabled by these files. Full M2–M9 scenario coverage
still needs extending; a future `passed` report only describes the listed M1
checks, never unimplemented scenarios.

## Scope and topology

The only supported initial environment is a **Linux validation VM**, k3d flannel
with **one server and two agents**, no mesh. The harness always calls
`hack/k3d-up.sh flannel --mesh=none`, preserving its mandatory resource/module
preflight **on cluster creation** and its one-Ratatoskr-cluster-at-a-time rule.
Existing clusters are reused without charging their occupied RAM again. The
server hosts a fake remote HTTP/IPIP endpoint; separate agents host the gateway
and selected client. The client init runs with **NET_ADMIN only in that existing
pod netns**. No SYS_ADMIN, privileged pods, host network, hostPath, netns switching,
registry pushes, kernel/module loading, or VM/host configuration changes are
performed by this harness. Component capability/TUN/flower checks and image
builds belong to the parent/operator, and remain prerequisites, not proven here.

The gateway container is UID 0, overrides its entrypoint with `/ratatoskr`, and
uses `-config /config/gateway.json`; POD_IP fills omitted gateway podIP and
POD_UID comes from Downward API metadata.uid for applied-config acknowledgment. It shares
its netns with an upstream plugin and a capability-free tools observer. Gateway
JSON selects only the client PodIP, gatewayID 7, MTU 1400, encryption `none`.
Client JSON uses that gateway PodIP endpoint, gatewayID 7, MTU 1400, `none`, and
exclusions for the entire pod CIDR, service CIDR and gateway PodIP /32.

Defaults are k3s pod CIDR `10.42.0.0/16` and service CIDR `10.43.0.0/16`.
`M1_POD_CIDR` / `M1_SERVICE_CIDR` may override them; all node pod subnets and the
API ClusterIP are checked against those declarations. This does not discover
all custom service ranges or support dual-stack. Base and gateway templates are
**complete YAML documents**, not patches. Dynamic client JSON is non-secret.

## Future execution interface (do not execute before final gate)

Local prerequisites: Bash, Python 3, jq, GNU timeout, kubectl, k3d, plus the
existing hack lifecycle dependencies. The tools image must contain `sh`, `sleep`,
`getent`, `cat`, curl, jq and iproute2 in addition to ratatoskr-init; host `cmp`
is also required.
The parent/operator builds the following images locally before using the harness:

- `ghcr.io/skaldhall/ratatoskr-gateway:dev`
- `ratatoskr-tools:m1-local`
- `ratatoskr-fakeupstream:m1-local`
- `ratatoskr-openvpn:m1-local` (live only)

No builds are implemented here because those component/image targets belong to
the parent. `--no-build` explicitly acknowledges that arrangement; it is accepted
but all runs already use prebuilt images. Images are imported with `k3d image
import` by default. Add `--no-import` when they are already loaded into the reused
cluster. Manifests use `imagePullPolicy: Never`; import/runtime failures are
reported without registry fallback. The four corresponding `*_IMAGE` environment
variables allow replacing local tags.

At the final gate, the entrypoints would be:

```sh
# Examples for the FINAL GATE ONLY, not authorization to execute now.
hack/m1-proof.sh --mode=fake --no-build --no-import
# Same initial fake M1 proof, intended eventual CI entrypoint:
test/e2e/ci/run.sh --no-build --no-import
# Initial live M1 proof; missing profile gives an explicit skip:
test/e2e/live/run.sh --no-build --no-import
```

Both fake and live wrappers accept `--skip` for an explicitly disabled matrix
entry: JSON status is `skipped`, with no cluster, Secret or traffic probe. Missing
required fake prerequisites is a failure, not a misleading skip. The live
missing-profile skip is automatic. None of these skip paths have been executed
during authoring.

Options also include `--report-dir=/absolute/outside/repo/path`. Defaults create a
private `/tmp/ratatoskr-m1-*-report.*` directory containing **report.json and
report.md**. Each checkpoint records a fixed diagnostic; no raw pod logs, Secret
YAML, provider configuration, credentials or tokenized URLs are retained in
reports. Stages fail on assertion, unavailable tooling, startup/runtime failure
or timeout. A failure report is not a successful proof. Exit 0 = all listed
checks passed **or explicit live skip** (distinguish JSON status); exit 1 = failure;
exit 2 = invalid invocation/local setup; exit 3 = live external check inconclusive.
GNU timeout may return 124 on the overall deadline even though the inner harness
writes its failure report. The default wall deadline is 1800 seconds, adjustable
with `M1_TOTAL_TIMEOUT_SECONDS`, plus up to 270 seconds cleanup grace. Exec/curl,
readiness, imports and lifecycle/cleanup operations have independent limits.

On ordinary exit, assertion failure, INT or TERM, cleanup deletes the ephemeral
namespace (including Secrets) and all private runtime files. It deletes a cluster
**only if this run created it**, via `hack/k3d-down.sh flannel`; a reused cluster
is retained. Cleanup failures make the report failed and require manual namespace
and/or lifecycle cleanup before another run. SIGKILL, machine loss and a failed
API cannot guarantee cleanup: remove orphaned `ratatoskr-m1-*` namespaces and
private `/tmp/ratatoskr-m1-private.*` directories securely before proceeding.
No debug/keep-Secret option exists.

## Fake proof assertions

1. Before steering, remote PodIP `/echo` sees the selected client PodIP on the
   ordinary cluster path. Record cluster DNS lookup/resolver, API reachability
   and the remote endpoint's ordinary ClusterIP path.
2. Gateway becomes Ready and cached `/info` supplies exitIP; its main default
   remains on eth0. Configure client steering in its existing netns.
3. DNS resolver is byte-identical; DNS lookup, API HTTP status, ordinary PodIP
   and ClusterIP paths remain usable. API `/version` uses unauthenticated TLS
   with certificate verification disabled only for this connectivity check;
   401/403 still proves TCP/TLS connectivity, **not API authorization**.
4. `http://198.19.0.1:8080/echo` sees `198.19.0.2`, matching gateway cached exitIP,
   via reciprocal IPIP and steered GENEVE, not the outer/client PodIP.
5. `/fakeupstream -role down` in the upstream container brings upstream0 down.
   Gateway becomes NotReady; tunnel request fails while ordinary PodIP and
   ClusterIP requests still work. `-role up` restores readiness and tunnel echo.

Fake `-role upstream -remote` receives **remote outer PodIP**, not the inner IP;
remote inner address is `198.19.0.1/30`, upstream inner `198.19.0.2/30`. Fake
upstream performs `/configure` itself and probes through marked/bound upstream0.
No SIGSTOP, sidecar process freezing, or host network fault injection is used.

## Live inputs and handling

Load inputs securely in your shell/session outside this repository, without
tracing or echoing values:

- `RATATOSKR_E2E_OVPN`: absolute path to a provider `client.ovpn` outside the repo.
  **Unset or empty -> clear live skip before cluster, Secret or external calls.**
- `RATATOSKR_E2E_OVPN_AUTH`: optional outside-repo auth file path (projected as
  `auth.txt`). Unset means no auth file; plugin never prompts.
- `RATATOSKR_E2E_OVPN_CA`, `RATATOSKR_E2E_OVPN_CERT`,
  `RATATOSKR_E2E_OVPN_KEY`: optional explicit absolute outside-repo file paths.
  The private staged copies become `ca.crt`, `client.crt`, `client.key`. Profiles
  with external `ca`, `cert`, `key` references require the corresponding input;
  original reference names need not match the staged names.
- `IPINFO_TOKEN`: optional literal environment token, read without output by
  Python into an out-of-repo 0600 file in a 0700 temporary directory. Secret
  creation uses **--from-file**, never --from-literal. Token contents are never
  placed in exec argv or logs; temporary token/YAML files are removed promptly
  and again by cleanup. Both wrapper and harness disable tracing immediately.
- `RATATOSKR_E2E_EXPECT_COUNTRY`: optional uppercase two-letter country code.

Do not paste provider configs/credentials/tokens/private keys into repository
files, shell examples, reports, issues or logs. Inline TLS blocks remain supported.
`bundle.py` runs **before cluster actions** and reads only explicitly selected env
input paths, never files inferred from the profile. It limits each input and the
normalized profile to 1 MiB, verifies regular files/outside-repo sources, then
normalizes relative external CA/cert/key/auth references to the fixed mount names.
Absolute/traversal references, unsafe quoting, includes, unknown options, hooks,
plugins, missing files and conflicting inline/external material are rejected
without raw data or path diagnostics. Safe route/DNS/interface/log controls are
stripped; unsupported external TLS-auth/crypt/CRL files require an explicit future
extension instead of implicit file discovery. The plugin sanitizer still runs.

Only copies enter a private 0700 temporary staging directory, in exclusive 0600
files. Inputs are never modified or chmodded (including permissive original
permissions). Keep supplied files immutable during staging; resolved source
symlinks must remain outside the repo. Staged files are removed immediately after
Secret creation and again by the existing EXIT/INT/TERM cleanup. Partial staging
failures roll back copies; cleanup failures return a fixed failure diagnostic.
Do not use this repository as the input or staging directory.

For a separate-file provider bundle, export absolute paths through a private,
non-traced shell session: `RATATOSKR_E2E_OVPN` selects the profile,
`RATATOSKR_E2E_OVPN_CA/_CERT/_KEY` select its three materials, and
`RATATOSKR_E2E_OVPN_AUTH` selects the login file. To require Germany set
`RATATOSKR_E2E_EXPECT_COUNTRY=DE`; leave `IPINFO_TOKEN` unset for anonymous mode.
These settings do not authorize or execute the final live gate.

OpenVPN uses its default safe sanitizer and default public exit probe. The plugin
runs with NET_ADMIN + MKNOD, a pod-local `/dev/net` emptyDir for `/dev/net/tun`, and
memory-backed `/run/ratatoskr`; no host mount or netns SYS_ADMIN. Runtime device
cgroup denial remains an explicit prerequisite failure; this harness never
escalates privileges. Upstream Secret is read-only; the supervisor owns private
sanitized runtime files and discards child output.

The client reads the optional token **only from a projected Secret**. The public
ipinfo URL, including `?token=...` if supplied, exists only in a pod-local private
curl config, consumed via `curl --config <file>` with stderr discarded. Raw
response files never leave the pod. The harness makes at most two ipinfo calls
(one 10-second backoff on 429), emitting only IP/country/status. Persistent 429,
service failure or malformed response -> **inconclusive**, not a pass. The
plugin's independent periodic exit-IP health probes use api.ipify.org by default,
reserving ipinfo for final live assertions; avoid repeated manual attempts. Expected client exit must equal gateway cached exitIP;
expected country is checked only when provided. Provider egress pools changing
between probes may fail equality; no claim of stable provider identity is made.
Live failure injection/recovery is explicitly skipped in this initial harness.

## Allowed static validation now

Only shell syntax, static rendering and offline synthetic bundle unit checks
are authorized at this stage:

```sh
for script in hack/m1-proof.sh test/e2e/m1/run.sh test/e2e/ci/run.sh test/e2e/live/run.sh; do
  bash -n "$script" || exit
done
sh -n test/e2e/m1/ipinfo.sh
PYTHONDONTWRITEBYTECODE=1 python3 test/e2e/m1/static-check.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/m1 -p 'test_bundle.py'
```

The static validator uses PyYAML (validation-only local dependency), renders all
complete manifests using dummy values, and checks key shape/config/capabilities.
It does **not** invoke kubectl, k3d, Docker, curl, Go binaries or any runner. These
checks cannot establish cluster admission, component flags, device access,
flower availability, routing, fail-close behavior, a real VPN or successful e2e.

## Explicitly unimplemented final coverage

M2–M9 need their full scenario tests: encryption/WireGuard, alternate CNIs,
meshes, additional isolation/spoof/failover scenarios, PMTU/fragmentation and
large-payload measurements, controller/webhook selection/reconciliation,
resilience and complete observability matrices. The available 4 MB fake payload
endpoint is not measured here. No packet capture/spoof proof or direct nft/flower
rule inspection is implemented. No live disruption, cross-provider/geo matrix,
IPv6, secret rotation, repeatability/soak or complete final CI job exists yet.
**All e2e executions, including these M1 scaffolds, remain deferred.**
