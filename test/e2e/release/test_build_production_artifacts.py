"""Mock Buildx only; no Docker, network, image or Helm execution."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("production_artifacts", SOURCE / "hack/build-production-artifacts.py")
prod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prod)
SHA = "a" * 40


class FakeTools:
    def __init__(self, *, platforms="linux/amd64,linux/arm64", fail=None, dirty=""):
        self.calls = []
        self.platforms = platforms
        self.fail = fail
        self.dirty = dirty
    def git(self, argv, *, root):
        self.calls.append(("git", argv))
        if argv[0] == "status": return self.dirty
        if argv[0] == "ls-files": return ""
        if argv[0] == "rev-parse": return SHA + "\n"
        raise AssertionError("unexpected git operation")
    def command(self, argv, *, root, timeout=1800):
        self.calls.append(("command", argv))
        if argv[:3] == ["docker", "buildx", "inspect"]:
            return "Name: current\nPlatforms: " + self.platforms + "\n"
        if argv[:3] == ["docker", "buildx", "build"]:
            if self.fail == "docker": raise prod.Blocked("synthetic build failure")
            output = next(a for a in argv if a.startswith("type=oci,dest="))
            Path(output.removeprefix("type=oci,dest=")).write_bytes(b"fake-image:" + argv[argv.index("--tag")+1].encode())
            return ""
        if argv[:2] == ["helm", "package"]:
            if self.fail == "helm": raise prod.Blocked("synthetic chart failure")
            Path(argv[-1], "ratatoskr-0.1.0.tgz").write_bytes(b"fake-chart")
            return ""
        raise AssertionError("unexpected command")


class ArtifactBuildTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="prod-artifact-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.checkout = self.root / "source"
        self.checkout.mkdir()
        self.output = self.root / "stage"
        self.args = dict(execute=True, version="0.1.0", source_sha=SHA,
                         output=str(self.output), registry="ghcr.io/jradikk", root=self.checkout)

    def test_all_six_images_two_arch_and_plugin_dockerfile(self):
        fake = FakeTools()
        result = prod.build(**self.args, git_call=fake.git, command=fake.command)
        self.assertEqual(result["artifactCount"], 8)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        cmds = [cmd for kind, cmd in fake.calls if kind == "command"]
        self.assertEqual(cmds[0], ["docker", "buildx", "inspect"])
        builds = [cmd for cmd in cmds if cmd[:3] == ["docker", "buildx", "build"]]
        self.assertEqual(len(builds), 6)
        self.assertEqual(len([cmd for cmd in cmds if cmd[:2] == ["helm", "package"]]), 1)
        for component, argv in zip(prod.IMAGES, builds):
            self.assertEqual(argv[argv.index("--platform")+1], "linux/amd64,linux/arm64")
            self.assertEqual(argv[argv.index("--tag")+1], f"ghcr.io/jradikk/ratatoskr-{component}:0.1.0")
            self.assertIn("VERSION=0.1.0", argv)
            self.assertIn("COMMIT="+SHA, argv)
            self.assertIn("--provenance=mode=max", argv)
            self.assertIn("--sbom=true", argv)
            self.assertNotIn("--push", argv)
            self.assertEqual(argv[argv.index("--file")+1], "plugins/upstream/openvpn/Dockerfile" if component == "upstream-openvpn" else "Dockerfile")
            self.assertEqual(("COMPONENT="+component in argv), component != "upstream-openvpn")
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertEqual(manifest["sourceSHA"], SHA)
        self.assertEqual(manifest["version"], "0.1.0")
        self.assertEqual(manifest["platformsRequested"], ["linux/amd64", "linux/arm64"])
        self.assertEqual(manifest["registry"], "ghcr.io/jradikk")
        self.assertFalse(manifest["published"] or manifest["releaseReady"])
        self.assertEqual(len((self.output / "SHA256SUMS").read_text().splitlines()), 8)
        self.assertIn("registry: ghcr.io/jradikk", (self.output / "release-values.yaml").read_text())
        self.assertEqual({a["role"] for a in manifest["artifacts"]},
                         {"chart", "installation-values"} | {"image:"+c for c in prod.IMAGES})

    def test_reject_without_output_or_build(self):
        for change in ({"execute": False}, {"version": "0.1.0-rc.1"},
                       {"registry": "ghcr.io/skaldhall/ratatoskr"}, {"registry": "docker.io/jradikk"},
                       {"source_sha": "a"*7}, {"output": "relative"},
                       {"output": str(self.checkout / "bad")}):
            fake = FakeTools()
            with self.subTest(change=change), self.assertRaises(prod.Blocked):
                prod.build(**(self.args | change), git_call=fake.git, command=fake.command)
            self.assertFalse(self.output.exists())
            self.assertFalse([cmd for kind, cmd in fake.calls if kind == "command"])
        self.output.mkdir()
        with self.assertRaises(prod.Blocked):
            prod.build(**self.args, git_call=FakeTools().git, command=FakeTools().command)

    def test_missing_cross_platform_blocks_before_output(self):
        for platforms in ("linux/arm64", "linux/amd64", "linux/arm64,linux/amd64/v3"):
            fake = FakeTools(platforms=platforms)
            with self.assertRaisesRegex(prod.Blocked, "builder lacks"):
                prod.build(**self.args, git_call=fake.git, command=fake.command)
            self.assertFalse(self.output.exists())
            self.assertEqual([cmd for kind, cmd in fake.calls if kind == "command"], [["docker", "buildx", "inspect"]])

    def test_dirty_or_failed_build_cleans_partial_output(self):
        fake = FakeTools(dirty="?? stray.go\n")
        with self.assertRaises(prod.Blocked):
            prod.build(**self.args, git_call=fake.git, command=fake.command)
        self.assertFalse(self.output.exists())
        for failure in ("docker", "helm"):
            fake = FakeTools(fail=failure)
            with self.assertRaises(prod.Blocked):
                prod.build(**self.args, git_call=fake.git, command=fake.command)
            self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
