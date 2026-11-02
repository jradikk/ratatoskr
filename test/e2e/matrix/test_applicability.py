"""Pure full-cartesian applicability checks; no cluster, subprocess or runner."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("matrix_applicability", HERE / "applicability.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
COVERAGE = json.loads((HERE / "coverage.json").read_text())
CELL = {"mode": "fake", "cni": "calico", "mesh": "none", "driver": "agent",
        "datapath": "iproute", "encryption": "none"}


class ApplicabilityTests(unittest.TestCase):
    def test_full_cartesian_72_candidates_and_24_refusals_each_mode_never_accepted(self):
        for mode in a.MODES:
            cells = a.cells(COVERAGE, mode)
            self.assertEqual(len(cells), 96)
            self.assertEqual(len({tuple(c.values()) for c in cells}), 96)
            self.assertEqual(sum(a.decide(COVERAGE, c)["decision"] == "refusal-required"
                                 for c in cells), 24)
            self.assertEqual(sum(a.decide(COVERAGE, c)["decision"] == "traffic-required"
                                 for c in cells), 72)
            for cell in cells:
                decision = a.decide(COVERAGE, cell)
                self.assertIs(decision["accepted"], False)
                self.assertEqual(decision["decision"] == "refusal-required",
                                 cell["datapath"] == "ebpf" and cell["encryption"] == "wireguard")
                for scenario in a.EXPECTED_SCENARIOS:
                    scoped = a.decide(COVERAGE, cell, scenario)
                    self.assertIn(scoped["decision"], ("traffic-required", "not-applicable"))
                    self.assertIs(scoped["accepted"], False)
                    if decision["decision"] == "refusal-required":
                        self.assertEqual(scoped["reason"], "cell-requires-unsupported-refusal")

    def test_driver_encryption_datapath_and_mode_specific_requirements(self):
        expected = (({"driver": "agent"}, "init-gateway-replacement", "scenario-init-driver-only"),
                    ({"driver": "init"}, "agent-restricted-workload", "scenario-agent-driver-only"),
                    ({"driver": "init"}, "agent-restart-endpoint-update", "scenario-agent-driver-only"),
                    ({"encryption": "none"}, "wireguard-registration", "scenario-wireguard-only"),
                    ({"encryption": "none"}, "wireguard-plaintext-denial", "scenario-wireguard-only"),
                    ({"datapath": "iproute"}, "ebpf-tunnel", "scenario-ebpf-only"),
                    ({"datapath": "iproute"}, "ebpf-revocation-failure", "scenario-ebpf-only"),
                    ({"mode": "fake"}, "public-exit-country", "scenario-mode-live-only"),
                    ({"mode": "fake"}, "live-provider-disruption", "scenario-mode-live-only"),
                    ({"mode": "live"}, "selective-cidr-port", "scenario-mode-fake-only"))
        for change, scenario, reason in expected:
            with self.subTest(scenario=scenario, change=change):
                result = a.decide(COVERAGE, {**CELL, **change}, scenario)
                self.assertEqual(result, {"decision": "not-applicable", "reason": reason,
                                          "accepted": False})
        for scenario in ("gateway-dns", "cni-mesh-compatibility", "agent-restricted-workload"):
            self.assertEqual(a.decide(COVERAGE, CELL, scenario)["decision"], "traffic-required")
        self.assertEqual(a.decide(COVERAGE, {**CELL, "driver": "init"},
                                  "init-gateway-replacement")["decision"], "traffic-required")
        self.assertEqual(a.decide(COVERAGE, {**CELL, "datapath": "ebpf"},
                                  "ebpf-tunnel")["decision"], "traffic-required")
        self.assertEqual(a.decide(COVERAGE, {**CELL, "encryption": "wireguard"},
                                  "wireguard-registration")["decision"], "traffic-required")

    def test_drift_unknown_values_and_malformed_schema_fail_before_shrinking_gate(self):
        alterations = (lambda d: d["axes"]["cni"].pop(),
                       lambda d: d["axes"]["mesh"].append("ambient"),
                       lambda d: d["axes"].update(driver=["agent", "init"]),
                       lambda d: d["scenarios"].pop(),
                       lambda d: d["scenarios"].append(copy.deepcopy(d["scenarios"][0])),
                       lambda d: d["scenarios"][0].update(mode="live"),
                       lambda d: d["scenarios"][0].update(id="invented"),
                       lambda d: d["scenarios"][0].update(implementation="unknown"),
                       lambda d: d["scenarios"][0].update(component="provider exit"),
                       lambda d: d["apiScenarios"][0].update(component="policy selection"),
                       lambda d: d["apiScenarios"].pop(),
                       lambda d: d.update(schemaVersion=True))
        for change in alterations:
            item = copy.deepcopy(COVERAGE)
            change(item)
            with self.subTest(change=change), self.assertRaises(a.InvalidInventory):
                a.cells(item, "fake")
        for key, invalid in (("cni", "weave"), ("mesh", ["none"]),
                             ("encryption", "wg"), ("mode", True), ("driver", "")):
            with self.subTest(key=key), self.assertRaises(a.InvalidInventory):
                a.decide(COVERAGE, {**CELL, key: invalid})
        for scenario in ("unknown", True, [], "api-crd-server-dry-run"):
            with self.assertRaises(a.InvalidInventory):
                a.decide(COVERAGE, CELL, scenario)
        with self.assertRaises(a.InvalidInventory):
            a.cells(COVERAGE, "production")
        with self.assertRaises(a.InvalidInventory):
            a.decide(COVERAGE, {**CELL, "accepted": True})


if __name__ == "__main__":
    unittest.main()
