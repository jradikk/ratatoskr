# Advanced scoped network fixtures

These tools test **selected** agent, WireGuard and HA behaviors on an approved
existing release. They are not wired into matrix cell promotion, and a passing
fixture still leaves the compatibility matrix **INCOMPLETE / exit 4**. Do not
interpret synthetic/local evidence as provider, alternate CNI/mesh, or complete
release acceptance. Before execution the operator must approve context, images,
immutable runtime IDs, disposable resources and cleanup; no fixture configures
or provisions the cluster. Default/ungated paths never access the cluster.

- `wg_fixture.py --execute`: requires `RATATOSKR_E2E_FINAL_GATE=1` and
  `RATATOSKR_E2E_WG_SYNTHETIC=1`. Creates UID-owned synthetic OpenVPN/Gateway
  and restricted selected Pod, checks authenticated WG peer/marker and deletion
  revocation. Optional separate gates `RATATOSKR_E2E_TOKENREVIEW=1`,
  `RATATOSKR_E2E_WG_NEGATIVE=1`, and `RATATOSKR_E2E_WG_PLAINTEXT=1` add
  bounded independent checks; none silently awards all WireGuard scenarios.
  The plaintext probe sends only fixed synthetic L2 GENEVE frames from a
  root-pinned selected namespace and requires arrival on gateway eth0, exact
  owned nft INPUT drop-counter growth, no gnv0 delivery and a fresh encrypted
  marker. If CNI blocks before eth0 it is **inconclusive**, not an nft PASS;
  never loosen production NetworkPolicy for the test.
- `agent_lifecycle.py --execute --execute-agent-gateway-replacement`: requires
  `RATATOSKR_E2E_AGENT_GATEWAY_REPLACEMENT=1` plus final-gate authorization.
  Tests UID-owned singleton Gateway replacement with the **same selected Pod**.
  `--wait-external-agent-restart` additionally requires
  `RATATOSKR_E2E_AGENT_RESTART=1`; the operator, not the fixture, performs the
  approved agent Pod restart. It claims only freshly checked post-restart traffic.
- `ha_fixture.py --execute --execute-ha-fixture`: requires
  `RATATOSKR_E2E_HA_FIXTURE=1` plus final-gate authorization. Creates a
  disposable two-replica Gateway and one selected Pod, deletes only the chosen
  Gateway Pod with UID preconditions, and checks fresh-connection reselection
  and marker/direct API path. It does **not** promise established-flow continuity.
- `ha_live.py --execute` with explicit Gateway/client identifiers and
  `RATATOSKR_E2E_FINAL_GATE=1` is **read-only**. External operator-owned
  withdrawal is required; its result is status/config evidence only, never a
  traffic pass.
- `wireguard.py:validate` and `test_wireguard.py` are pure evidence contracts;
  synthetic dictionaries are not cluster evidence. `wg_transport.py` samples
  only strict fixed-role, fixed-direction public metrics from UID-bound Pods.

Root-side helpers use fixed commands, pinned namespaces, bounded output and
sanitized categories; they write no pcap or credential material. Kubernetes
TokenReview diagnostics do not observe the production Gateway's own call.
Unexpected PID/UID, image, route, policy, token or cleanup state blocks; failed
runs need operator orphan inspection. Offline tests (no cluster or image build):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/advanced -p 'test_*.py'
go test ./test/e2e/advanced
```
