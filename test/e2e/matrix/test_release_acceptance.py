"""Release readiness cannot be inferred from scoped or missing evidence."""
import copy
import unittest

from release_acceptance import assess


def sample(status="PARTIAL"):
    return {"schemaVersion": 1, "scope": "release-acceptance", "gates": [{
        "id": "mandatory", "status": status, "requirement": "Full declared acceptance",
        "evidence": ["reviewed-evidence"], "remaining": "Unverified configurations"}]}


class ReleaseAcceptanceTests(unittest.TestCase):
    def test_partial_is_not_ready(self):
        result = assess(sample(), ["mandatory"])
        self.assertFalse(result["ready"])
        self.assertEqual(result["acceptedPercent"], 0)

    def test_pass_requires_evidence_and_no_gap(self):
        value = sample("PASSED")
        with self.assertRaises(ValueError):
            assess(value, ["mandatory"])
        value["gates"][0]["remaining"] = ""
        self.assertTrue(assess(value, ["mandatory"])["ready"])
        value["gates"][0]["evidence"] = []
        with self.assertRaises(ValueError):
            assess(value, ["mandatory"])

    def test_missing_duplicate_or_skipped_gate_rejected(self):
        for mutation in ("missing", "duplicate", "skipped", "unknown"):
            value = copy.deepcopy(sample())
            if mutation == "missing": value["gates"] = []
            elif mutation == "duplicate": value["gates"] *= 2
            elif mutation == "skipped": value["gates"][0]["status"] = "SKIPPED"
            else: value["gates"][0]["id"] = "other"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                assess(value, ["mandatory"])

    def test_boolean_schema_rejected(self):
        value = sample()
        value["schemaVersion"] = True
        with self.assertRaises(ValueError):
            assess(value, ["mandatory"])
