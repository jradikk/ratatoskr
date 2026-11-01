"""No real Go/Helm build: tiny synthetic outputs and command assertions."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("experimental_rc", HERE / "hack/build-experimental-rc.py")
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)
SHA = "a" * 40
VERSION = "0.1.0-rc.1"


class FakeBuild:
    def __init__(self, source, *, fail=None, dirty="", ignored=""):
        self.source = source
        self.fail = fail
        self.dirty = dirty
        self.ignored = ignored
        self.calls = []
    def __call__(self, argv, *, root, env=None, timeout=180):
        self.calls.append((argv, root, env, timeout))
        if argv[:2] == ["git", "status"]:
            return self.dirty
        if argv[:2] == ["git", "ls-files"]:
            return self.ignored
        if argv[:2] == ["git", "rev-parse"]:
            return SHA + "\n"
        if argv[0] == "go":
            if self.fail == "go": raise rc.Blocked("synthetic build failure")
            path = Path(argv[argv.index("-o") + 1])
            path.write_bytes((path.name + " compiled").encode())
            return ""
        if argv[0] == "helm":
            if self.fail == "helm": raise rc.Blocked("synthetic chart failure")
            self.assert_args(argv)
            (Path(argv[-1]) / ("ratatoskr-" + VERSION + ".tgz")).write_bytes(b"chart-fixture")
            return ""
        raise AssertionError("unknown command")
    def assert_args(self, argv):
        assert argv[1:3] == ["package", "charts/ratatoskr"]
        assert argv[argv.index("--version")+1] == VERSION
        assert argv[argv.index("--app-version")+1] == VERSION


class ExperimentalRCTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="experimental-rc-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.checkout = self.root / "source"
        self.checkout.mkdir()
        self.output = self.root / "stage"
        self.args = dict(execute=True, version=VERSION, source_sha=SHA,
                         output=str(self.output), root=self.checkout)

    def test_opt_in_version_source_and_destination_guard_before_build(self):
        for update in ({"execute": False}, {"version": "0.1.0"}, {"version": "0.1.0-dev"},
                       {"version": "v0.1.0-rc.1"}, {"version": "0.1.0-rc.0"},
                       {"version": "01.0.0-rc.1"}, {"source_sha": "a" * 7},
                       {"output": "relative"}, {"output": str(self.checkout / "stage")}):
            with self.subTest(update=update):
                fake = FakeBuild(self.checkout)
                with self.assertRaises(rc.Blocked):
                    rc.prepare(run=fake, **(self.args | update))
                self.assertFalse(self.output.exists())
                self.assertFalse(any(c[0][0] in ("go", "helm") for c in fake.calls))
        self.output.mkdir()
        with self.assertRaises(rc.Blocked):
            rc.prepare(run=FakeBuild(self.checkout), **self.args)

    def test_clean_source_and_ignored_secret_guard(self):
        for dirty, ignored in ((" M source.go\n", ""), ("?? temp.go\n", ""),
                               ("", "secrets/profile.ovpn\n"), ("", "dist/chart.tgz\n")):
            fake = FakeBuild(self.checkout, dirty=dirty, ignored=ignored)
            with self.assertRaises(rc.Blocked):
                rc.prepare(run=fake, **self.args)
            self.assertFalse(self.output.exists())
            self.assertFalse(any(c[0][0] in ("go", "helm") for c in fake.calls))

    def test_success_is_unsigned_local_binaries_chart_only(self):
        fake = FakeBuild(self.checkout)
        result = rc.prepare(run=fake, **self.args)
        self.assertFalse(result["publishable"])
        self.assertEqual(result["artifactCount"], 11)
        self.assertTrue(self.output.is_dir())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        contents = {p.name for p in self.output.iterdir()}
        self.assertEqual(len(contents), 14)
        self.assertFalse(any(n.endswith((".oci", ".oci.tar")) for n in contents))
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertEqual(manifest["images"], "NOT_INCLUDED")
        self.assertEqual(manifest["openvpnPluginImage"], "NOT_INCLUDED")
        self.assertEqual(manifest["sbom"], "NOT_VERIFIED")
        self.assertFalse(manifest["publishable"])
        self.assertEqual({a["role"] for a in manifest["artifacts"]},
                         {"binary:"+c+":"+arch for c in rc.COMPONENTS for arch in rc.ARCHES} | {"chart"})
        go = [call for call in fake.calls if call[0][0] == "go"]
        self.assertEqual(len(go), 10)
        self.assertEqual(len([call for call in fake.calls if call[0][0] == "helm"]), 1)
        self.assertTrue(all(call[2]["CGO_ENABLED"] == "0" and call[2]["GOOS"] == "linux" and
                            call[2]["GOARCH"] in rc.ARCHES for call in go))
        self.assertTrue(all(SHA in call[0][call[0].index("-ldflags")+1] for call in go))
        self.assertIn("NOT PRODUCTION-READY", (self.output / "RELEASE-NOTES.txt").read_text())
        self.assertEqual(len((self.output / "SHA256SUMS").read_text().splitlines()), 11)

    def test_failed_build_removes_partial_stage(self):
        for failed in ("go", "helm"):
            fake = FakeBuild(self.checkout, fail=failed)
            with self.assertRaises(rc.Blocked):
                rc.prepare(run=fake, **self.args)
            self.assertFalse(self.output.exists())

    def test_main_default_does_not_call_cluster_or_create(self):
        buffer = io.StringIO()
        with (patch.object(rc, "_source", side_effect=AssertionError("should not check git")),
              contextlib.redirect_stdout(buffer)):
            self.assertEqual(rc.main([]), 4)
        self.assertIn("BLOCKED", buffer.getvalue())
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
