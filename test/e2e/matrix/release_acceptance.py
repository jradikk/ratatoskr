"""Offline release checklist guard; authored records do not self-certify runtime evidence."""
import argparse
import json
from pathlib import Path

STATUSES = {"OPEN", "PARTIAL", "PASSED"}


def assess(checklist, required_ids):
    if (type(checklist) is not dict or set(checklist) != {"schemaVersion", "scope", "gates"}
            or type(checklist["schemaVersion"]) is not int or checklist["schemaVersion"] != 1
            or checklist["scope"] != "release-acceptance" or type(checklist["gates"]) is not list):
        raise ValueError("Invalid release checklist schema")
    records = {}
    for gate in checklist["gates"]:
        if (type(gate) is not dict or set(gate) != {"id", "status", "requirement", "evidence", "remaining"}
                or not isinstance(gate["id"], str) or gate["id"] in records
                or gate["status"] not in STATUSES
                or not isinstance(gate["requirement"], str) or not gate["requirement"]
                or type(gate["evidence"]) is not list
                or any(not isinstance(item, str) or not item for item in gate["evidence"])
                or not isinstance(gate["remaining"], str)):
            raise ValueError("Invalid or duplicate release gate")
        if gate["status"] == "PASSED" and (not gate["evidence"] or gate["remaining"]):
            raise ValueError("Passed gate requires evidence and no remaining work")
        if gate["status"] != "PASSED" and not gate["remaining"]:
            raise ValueError("Incomplete gate requires an explicit remaining gap")
        records[gate["id"]] = gate
    if set(records) != set(required_ids) or not records:
        raise ValueError("Missing or unexpected mandatory release gates")
    passed = sum(gate["status"] == "PASSED" for gate in records.values())
    return {"passed": passed, "required": len(records), "acceptedPercent": 100 * passed / len(records),
            "ready": passed == len(records),
            "blocked": [key for key, gate in records.items() if gate["status"] != "PASSED"]}


def main():
    root = Path(__file__).resolve().parents[3]
    coverage = json.loads((root / "test/e2e/matrix/coverage.json").read_text())
    required = [item["id"] for item in coverage["scenarios"]] + [
        "linux-5-10-baseline", "final-source-validation", "release-artifact-provenance", "release-security-review"]
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    result = assess(json.loads((root / "test/e2e/release/acceptance.json").read_text()), required)
    print(json.dumps(result, sort_keys=True))
    return 1 if args.require_ready and not result["ready"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
