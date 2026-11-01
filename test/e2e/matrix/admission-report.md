# API and admission fixture

`admission.py` exercises complete CRD/Gateway/Policy server dry-runs and
fail-closed admission against an approved existing release. It does not create
a cluster or VPN profile. The temporary Gateway refers to a deliberately absent
Secret; it cannot count as healthy traffic. Authorized Pod CREATE checks injected
security/configuration; rejected CREATE cases require Ratatoskr's exact denial
reason, not a generic API error. Unsupported eBPF+WireGuard is checked only when
the deployed controller already runs eBPF.

For independent UPDATE validation the runner may persist one scheduling-gated,
never-matching-selector Pod **only after** server dry-run proves its barriers
survive mutation. Four metadata-only server-dry-run UPDATEs check benign
annotation acceptance and reject gateway-label, namespace-reference and
client-config tampering. UID, gate, selector, no node assignment/IP/container
start and unchanged state are rechecked throughout. The exact Pod must be
removed and verified absent before namespace cleanup. A timeout, API error or
cleanup uncertainty fails closed; no Pod is allowed to run.

Execution needs `RATATOSKR_E2E_FINAL_GATE=1`, exact approved immutable
controller/webhook runtime image IDs and the existing Ready three-node
flannel/no-mesh context. Default matrix mode is static. Evidence belongs only
to the `apiAdmission` inventory and awards **no traffic/CNI/mesh coverage**;
full matrix remains exit **4 / INCOMPLETE** while cells are missing.

Offline fixture verification (never invokes the API):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test/e2e/matrix/admission-static-check.py
```
