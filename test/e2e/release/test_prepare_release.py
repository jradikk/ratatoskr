"""Offline tests: no release file, credential, Helm, image or cluster access."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[3]
module = importlib.util.spec_from_file_location("prepare_release", SOURCE / "hack/prepare-release.py")
guard = importlib.util.module_from_spec(module)
module.loader.exec_module(guard)
SHA = "a" * 40
ARGS = dict(execute=True, source_sha=SHA, version="1.2.3", output="/unused/release-stage")


class Ledger:
    def __init__(self):
        self.dir = tempfile.TemporaryDirectory(prefix="release-guard-test-")
        self.root = Path(self.dir.name)
        (self.root / "test/e2e/matrix").mkdir(parents=True)
        (self.root / "docs/milestones/m9").mkdir(parents=True)
        shutil.copyfile(SOURCE / "test/e2e/matrix/release_acceptance.py",
                        self.root / "test/e2e/matrix/release_acceptance.py")
        source_coverage = json.loads((SOURCE / "test/e2e/matrix/coverage.json").read_text())
        shutil.copyfile(SOURCE / "test/e2e/matrix/applicability.py",
                        self.root / "test/e2e/matrix/applicability.py")
        self.coverage = source_coverage
        self.write_coverage()
        self.checklist = {"schemaVersion": 1, "scope": "release-acceptance", "gates": [
            {"id": item["id"], "status": "PASSED", "requirement": "Independently reviewed",
             "evidence": ["approved evidence reference"], "remaining": ""}
            for item in self.coverage["scenarios"]] + [
            {"id": name, "status": "PASSED", "requirement": "Independently reviewed",
             "evidence": ["approved evidence reference"], "remaining": ""}
            for name in guard.EXTRA_GATES]}
        self.write_checklist()

    def write_coverage(self):
        (self.root / "test/e2e/matrix/coverage.json").write_text(json.dumps(self.coverage))

    def write_checklist(self):
        (self.root / "docs/milestones/m9/acceptance-checklist.json").write_text(json.dumps(self.checklist))

    def close(self):
        self.dir.cleanup()


def fake_git(root, *args):
    if args[:2] == ("status", "--porcelain=v1"):
        return ""
    if args[:2] == ("ls-files", "--others"):
        return ""
    if args == ("rev-parse", "HEAD"):
        return SHA + "\n"
    raise AssertionError("unexpected git command")


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.ledger = Ledger()
        self.addCleanup(self.ledger.close)

    def fail_before_git(self, **args):
        with self.assertRaises(guard.Blocked):
            guard.validate(root=self.ledger.root, git=lambda *_a: self.fail("git should not be read while gates open"),
                           **(ARGS | args))

    def test_real_checked_in_ledger_is_blocked_without_git_or_writes(self):
        output = Path(self.ledger.root / "must-not-exist")
        with patch.object(guard, "_git", side_effect=AssertionError("git should not run")):
            with self.assertRaisesRegex(guard.Blocked, "mandatory acceptance gates remain incomplete"):
                guard.validate(root=SOURCE, git=lambda *_a: self.fail("git ran"),
                               **(ARGS | {"output": str(output)}))
        self.assertFalse(output.exists())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(guard.main([], root=SOURCE, git=lambda *_a: self.fail("git ran")), 4)
        self.assertFalse(output.exists())

    def test_open_partial_missing_duplicate_and_empty_evidence_block_first(self):
        for mutation in ("OPEN", "PARTIAL", "missing", "duplicate", "no-evidence", "remaining"):
            with self.subTest(mutation=mutation):
                original = copy.deepcopy(self.ledger.checklist)
                gates = self.ledger.checklist["gates"]
                if mutation in ("OPEN", "PARTIAL"):
                    gates[0].update(status=mutation, remaining="Unverified")
                elif mutation == "missing":
                    gates.pop()
                elif mutation == "duplicate":
                    gates[-1] = copy.deepcopy(gates[0])
                elif mutation == "no-evidence":
                    gates[0]["evidence"] = []
                else:
                    gates[0]["remaining"] = "Unverified"
                self.ledger.write_checklist()
                self.fail_before_git()
                self.ledger.checklist = original
                self.ledger.write_checklist()

    def test_schema_and_independent_25_plus_4_gate_ids(self):
        self.ledger.coverage["scenarios"].pop()
        self.ledger.write_coverage()
        self.fail_before_git()
        self.ledger.coverage = json.loads((SOURCE / "test/e2e/matrix/coverage.json").read_text())
        self.write_synthetic_coverage()
        self.ledger.checklist["gates"].append({"id": "invented", "status": "PASSED", "requirement": "x", "evidence": ["x"], "remaining": ""})
        self.ledger.write_checklist()
        self.fail_before_git()

    def write_synthetic_coverage(self):
        self.ledger.write_coverage()

    def test_renamed_inventory_and_matching_ledger_cannot_replace_required_gate(self):
        old = self.ledger.coverage["scenarios"][0]["id"]
        self.ledger.coverage["scenarios"][0]["id"] = "easier-substitute"
        for gate in self.ledger.checklist["gates"]:
            if gate["id"] == old:
                gate["id"] = "easier-substitute"
        self.ledger.write_coverage()
        self.ledger.write_checklist()
        self.fail_before_git()

    def test_execute_version_sha_and_output_cannot_stage(self):
        for change in ({"execute": False}, {"version": "dev"}, {"version": "1.2.3-dev"},
                       {"version": "v1.2.3"}, {"version": "1.2.3+build"},
                       {"version": "01.2.3"}, {"version": "1.2.3-rc.0"},
                       {"source_sha": "a" * 7}, {"output": "relative"}):
            with self.subTest(change=change), self.assertRaises(guard.Blocked):
                guard.validate(root=self.ledger.root, git=lambda *_a: self.fail("invalid args should not query git"),
                               **(ARGS | change))
        for version in ("1.2.3", "1.2.3-rc.1"):
            with self.subTest(version=version), self.assertRaisesRegex(guard.Blocked, "artifact verification not implemented"):
                guard.validate(root=self.ledger.root, git=fake_git, **(ARGS | {"version": version}))
        self.assertFalse(Path(ARGS["output"]).exists())

    def test_dirty_tracked_untracked_ignored_and_stale_sha(self):
        cases = (" M src.go\n", "?? new.go\n")
        for dirty in cases:
            def git(root, *args):
                if args[0] == "status": return dirty
                return fake_git(root, *args)
            with self.assertRaisesRegex(guard.Blocked, "dirty"):
                guard.validate(root=self.ledger.root, git=git, **ARGS)
        for ignored in ("secrets/profile.ovpn\0", "dist/chart.tgz\0"):
            def git(root, *args):
                if args[0] == "ls-files": return ignored
                return fake_git(root, *args)
            with self.assertRaisesRegex(guard.Blocked, "ignored"):
                guard.validate(root=self.ledger.root, git=git, **ARGS)
        def stale(root, *args):
            if args[0] == "rev-parse": return "b" * 40 + "\n"
            return fake_git(root, *args)
        with self.assertRaisesRegex(guard.Blocked, "SHA differs"):
            guard.validate(root=self.ledger.root, git=stale, **ARGS)
        def permitted_binary(root, *args):
            if args[0] == "ls-files": return "bin/ratatoskr-controller\0"
            return fake_git(root, *args)
        with self.assertRaisesRegex(guard.Blocked, "artifact verification not implemented"):
            guard.validate(root=self.ledger.root, git=permitted_binary, **ARGS)

    def test_main_never_creates_output_or_prints_inputs(self):
        secret_named = str(self.ledger.root / "private-token-output")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = guard.main(["--execute", "--source-sha", SHA, "--version", "1.2.3",
                               "--output", secret_named], root=self.ledger.root, git=fake_git)
        self.assertEqual(code, 4)
        self.assertIn("BLOCKED", buf.getvalue())
        self.assertNotIn(secret_named, buf.getvalue())
        self.assertFalse(Path(secret_named).exists())


if __name__ == "__main__":
    unittest.main()
