#!/usr/bin/env python3
"""Readiness guard only. This tool NEVER stages, builds, signs or publishes.

The release ledger is an independently reviewed prerequisite, not proof that
artifacts exist or are trustworthy. Even an all-PASSED ledger remains BLOCKED
until a later separately reviewed artifact-verification implementation exists.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}\Z")
PART = r"(?:0|[1-9][0-9]*)"
VERSION = re.compile(rf"{PART}\.{PART}\.{PART}(?:-rc\.[1-9][0-9]*)?\Z")
EXTRA_GATES = ("linux-5-10-baseline", "final-source-validation",
               "release-artifact-provenance", "release-security-review")


class Blocked(Exception):
    """Sanitized refusal; never surface raw evidence, paths, or credentials."""


def _acceptance(root):
    spec = importlib.util.spec_from_file_location(
        "release_acceptance", root / "test/e2e/matrix/release_acceptance.py")
    if spec is None or spec.loader is None:
        raise Blocked("acceptance assessor unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.assess


def _ledger(root):
    """Require exact 25 independent scenario IDs plus four fixed release gates."""
    try:
        coverage = json.loads((root / "test/e2e/matrix/coverage.json").read_text())
        specification = importlib.util.spec_from_file_location(
            "release_applicability", root / "test/e2e/matrix/applicability.py")
        if specification is None or specification.loader is None:
            raise ValueError()
        applicability = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(applicability)
        applicability.validate(coverage)
        # Required identities come from the reviewed contract, not a mutable
        # inventory count that could substitute easier acceptance requirements.
        scenario_ids = sorted(applicability.EXPECTED_SCENARIOS)
        required = scenario_ids + list(EXTRA_GATES)
        checklist = json.loads((root / "docs/milestones/m9/acceptance-checklist.json").read_text())
        result = _acceptance(root)(checklist, required)
        if result["required"] != 29 or result["passed"] != 29 or result["blocked"] or not result["ready"]:
            raise Blocked("mandatory acceptance gates remain incomplete")
    except Blocked:
        raise
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        raise Blocked("acceptance ledger unavailable or invalid") from None


def _git(root, *args):
    try:
        result = subprocess.run(["git", "-C", str(root), *args], text=True,
                                capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("source identity check unavailable") from None
    if result.returncode or len(result.stdout) > 8192:
        raise Blocked("source identity check failed")
    return result.stdout


def validate(*, execute, source_sha, version, output, root=ROOT, git=_git):
    """Fail closed without creating a file or inspecting any artifact path."""
    _ledger(root)  # Gate FIRST; no output/artifact path touched if any gate open.
    if not execute:
        raise Blocked("explicit execution required; default is read-only and blocked")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise Blocked("reviewed canonical release version required")
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        raise Blocked("full lowercase source SHA required")
    if not isinstance(output, str) or not output or not Path(output).is_absolute():
        raise Blocked("explicit absolute staging output path required")
    # Include tracked/untracked changes and ignored paths. Only repository
    # generated bin/ outputs may be ignored; ignored secrets/dist are blockers.
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise Blocked("source checkout is dirty")
    ignored = git(root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z")
    if any(path and not path.startswith("bin/") for path in ignored.split("\0")):
        raise Blocked("source checkout contains ignored non-binary files")
    if git(root, "rev-parse", "HEAD").strip() != source_sha:
        raise Blocked("source SHA differs from the clean current HEAD")
    # No reviewed artifact policy, manifest, provenance verifier or exact archive
    # allowlist exists. Never make a staging directory, even with passed gates.
    raise Blocked("artifact verification not implemented; staging prohibited")


def main(argv=None, *, root=ROOT, git=_git):
    parser = argparse.ArgumentParser(description="Blocked-only release preparation guard; no artifact staging")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source-sha")
    parser.add_argument("--version")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        validate(execute=args.execute, source_sha=args.source_sha, version=args.version,
                 output=args.output, root=root, git=git)
    except Blocked as err:
        print("BLOCKED: " + str(err))
        return 4
    print("BLOCKED: artifact verification not implemented; staging prohibited")
    return 4


if __name__ == "__main__":
    sys.exit(main())
