"""Offline hostile-evidence regression tests; no Kubernetes or runner calls."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("coverage_evidence", HERE / "coverage_evidence.py")
evaluator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluator)

SOURCE = "a" * 40
IMAGES = {"controller": "sha256:" + "b" * 64, "gateway": "registry.example/gateway@sha256:" + "c" * 64}
CELL = {"mode": "fake", "cni": "flannel", "mesh": "none", "driver": "agent", "datapath": "iproute", "encryption": "none"}
COVERAGE = json.loads((HERE / "coverage.json").read_text())
REQUIREMENTS = {"controller-admission-selection": ["admission", "ownership"], "agent-restricted-workload": ["selected-traffic"]}


def fixture():
    return {"sourceSHA": SOURCE, "images": copy.deepcopy(IMAGES), "cell": copy.deepcopy(CELL),
            "scope": {"kind": "scenario-subset", "scenarios": list(REQUIREMENTS)},
            "checkpoints": [
                {"scenario": scenario, "name": name, "status": "PASSED"}
                for scenario, names in REQUIREMENTS.items() for name in names
            ], "cleanup": {"status": "PASSED", "ownedResourcesAbsent": True}}


def evaluate(value, **overrides):
    kwargs = {"source_sha": SOURCE, "image_ids": IMAGES, "expected_cell": CELL,
              "coverage": COVERAGE, "requirements": REQUIREMENTS}
    kwargs.update(overrides)
    return evaluator.evaluate_cell(value, **kwargs)


class TestEvidence(unittest.TestCase):
    def test_subset_never_full_pass(self):
        result = evaluate(fixture())
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["cell"], "flannel/none/agent/iproute/none")
        self.assertEqual(result["scenarios"], {name: "PASSED" for name in REQUIREMENTS})
        self.assertFalse(result["fullCellCovered"])

    def test_missing_or_partial_checkpoints_not_covered(self):
        value = fixture()
        value["checkpoints"].pop()
        result = evaluate(value)
        self.assertEqual(result["scenarios"]["agent-restricted-workload"], "INCOMPLETE")
        self.assertEqual(result["status"], "INCOMPLETE")
        for status, expected in (("FAILED", "FAILED"), ("INCONCLUSIVE", "INCONCLUSIVE"), ("SKIPPED", "INCOMPLETE")):
            value = fixture()
            value["checkpoints"][0]["status"] = status
            self.assertEqual(evaluate(value)["scenarios"]["controller-admission-selection"], expected)
        value = fixture()
        value["checkpoints"][0]["status"] = "FAILED"
        self.assertEqual(evaluate(value)["status"], "FAILED")

    def test_runtime_image_id_digest_formats(self):
        for image in ("containerd://sha256:" + "d" * 64,
                      "docker-pullable://registry.example/image@sha256:" + "d" * 64,
                      "cri-o://sha256:" + "d" * 64):
            value = fixture()
            value["images"]["gateway"] = image
            ids = {**IMAGES, "gateway": image}
            self.assertEqual(evaluate(value, image_ids=ids)["status"], "INCOMPLETE")

    def test_cleanup_must_succeed_even_when_checkpoints_pass(self):
        for cleanup, expected in (({"status": "FAILED", "ownedResourcesAbsent": True}, "FAILED"),
                                  ({"status": "INCONCLUSIVE", "ownedResourcesAbsent": True}, "INCOMPLETE"),
                                  ({"status": "PASSED", "ownedResourcesAbsent": False}, "FAILED")):
            value = fixture()
            value["cleanup"] = cleanup
            result = evaluate(value)
            self.assertEqual(result["status"], expected)
            self.assertTrue(all(s != "PASSED" for s in result["scenarios"].values()))

    def test_stale_or_mutable_identity_denied(self):
        for mutation in (
            lambda e: e.update(sourceSHA="d" * 40),
            lambda e: e.update(sourceSHA="a" * 7),
            lambda e: e["images"].update(gateway="gateway:dev"),
            lambda e: e["images"].pop("gateway"),
            lambda e: e["images"].update(upstream="sha256:" + "d" * 64),
        ):
            value = fixture()
            mutation(value)
            with self.assertRaises(evaluator.EvidenceError):
                evaluate(value)
        with self.assertRaises(evaluator.EvidenceError):
            evaluate(fixture(), source_sha="a" * 7)
        with self.assertRaises(evaluator.EvidenceError):
            evaluate(fixture(), image_ids={"gateway": "gateway:latest"})

    def test_wrong_cell_and_unsupported_denied(self):
        for axis, invalid in (("cni", "cilium"), ("driver", "init"), ("mode", "live"),
                              ("encryption", "wireguard"), ("mesh", "unknown")):
            value = fixture()
            value["cell"][axis] = invalid
            with self.assertRaises(evaluator.EvidenceError):
                evaluate(value)
        value = fixture()
        value["cell"].update(datapath="ebpf", encryption="wireguard")
        with self.assertRaises(evaluator.EvidenceError):
            evaluate(value, expected_cell=value["cell"])

    def test_scope_and_required_checks_independent(self):
        for mutation in (
            lambda e: e["scope"].update(kind="full-cell"),
            lambda e: e["scope"].update(scenarios=[]),
            lambda e: e["scope"].update(scenarios=["invented"]),
            lambda e: e["scope"].update(scenarios=["agent-restricted-workload"]),
            lambda e: e["scope"].update(scenarios=["agent-restricted-workload"] * 2),
            lambda e: e["checkpoints"].append(copy.deepcopy(e["checkpoints"][0])),
            lambda e: e["checkpoints"].append({"scenario": "agent-restricted-workload", "name": "invented", "status": "PASSED"}),
            lambda e: e["checkpoints"][0].update(scenario="invented"),
            lambda e: e["checkpoints"][0].update(status="passed"),
            lambda e: e["checkpoints"].append({"scenario": "controller-admission-selection"}),
            lambda e: e.update(unknown="PASSED"),
            lambda e: e["cleanup"].update(ownedResourcesAbsent="true"),
        ):
            value = fixture()
            mutation(value)
            with self.assertRaises(evaluator.EvidenceError):
                evaluate(value)
        with self.assertRaises(evaluator.EvidenceError):
            evaluate(fixture(), requirements={"controller-admission-selection": []})
        with self.assertRaises(evaluator.EvidenceError):
            evaluate(fixture(), requirements={"controller-admission-selection": ["admission"]})
        with self.assertRaises(evaluator.EvidenceError):
            evaluate(fixture(), requirements={"controller-admission-selection": ["admission", "ownership"],
                                              "agent-restricted-workload": ["ownership"]})

    def test_applicability_and_unknown_schema_denied(self):
        value = fixture()
        value["scope"]["scenarios"] = ["ebpf-tunnel"]
        value["checkpoints"] = [{"scenario": "ebpf-tunnel", "name": "tunnel", "status": "PASSED"}]
        with self.assertRaises(evaluator.EvidenceError):
            evaluate(value, requirements={"ebpf-tunnel": ["tunnel"]})
        schema = copy.deepcopy(COVERAGE)
        schema["schemaVersion"] = 2
        with self.assertRaises(evaluator.EvidenceError):
            evaluate(fixture(), coverage=schema)


if __name__ == "__main__":
    unittest.main()
