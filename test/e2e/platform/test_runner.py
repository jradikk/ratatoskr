"""Cluster-free fake host/process tests; never execute privileged commands."""
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from collections import namedtuple
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import runner

SHA = "a" * 40
HOST = namedtuple("Host", "sysname release machine")
GATES = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_PLATFORM_510": "1"}


class PlatformTest(unittest.TestCase):
    def fake(self, *, host=HOST("Linux", "5.10.231-generic", "x86_64"), sha=SHA,
             dirty=b"", compiler=b"go version go1.24.2 linux/amd64\n", fail=None):
        seen = []
        replies = {"git": [sha.encode() + b"\n", dirty], "go": [compiler], "make": [b""]}
        def invoke(argv, *, timeout, max_output):
            seen.append((argv, timeout, max_output))
            if argv[0] == fail:
                raise runner.Blocked("private-host-error")
            return replies[argv[0]].pop(0)
        return seen, lambda: runner.execute(SHA, host=lambda: host, invoke=invoke)

    def test_default_and_each_missing_gate_never_looks_at_host_or_checkout(self):
        for env, argv in (({}, []), ({}, ["--execute"]),
                          (GATES, []),
                          ({"RATATOSKR_E2E_FINAL_GATE": "1"}, ["--execute"]),
                          ({"RATATOSKR_E2E_PLATFORM_510": "1"}, ["--execute"])):
            with patch.dict(os.environ, env, clear=True), patch.object(
                    runner, "execute", side_effect=AssertionError("no IO")):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(runner.main(argv), 2)
                self.assertEqual(json.loads(out.getvalue()),
                                 {"status": "SKIPPED", "reason": "explicit-platform-optin-required"})

    def test_exact_510_release_arch_source_clean_checkout_and_compiler(self):
        with patch.dict(os.environ, GATES, clear=True):
            seen, check = self.fake()
            report = check()
        self.assertEqual(report, {"sourceSHA": SHA, "kernelRelease": "5.10.231-generic",
                                 "architecture": "amd64", "compiler": "go version go1.24.2 linux/amd64",
                                 "componentTests": "passed", "trafficAcceptance": "not-run",
                                 "releaseStatus": "INCOMPLETE"})
        self.assertEqual(seen[-1], (["make", "test-privileged"], 900, 0))
        self.assertEqual([step[0] for step in seen[:3]],
                         [["git", "rev-parse", "HEAD"],
                          ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                          ["go", "version"]])
        with patch.dict(os.environ, GATES, clear=True):
            other, check = self.fake(host=HOST("Linux", "5.10.205", "aarch64"),
                                     compiler=b"go version go1.25.0 linux/arm64\n")
            self.assertEqual(check()["architecture"], "arm64")
            self.assertEqual(other[-1][0], ["make", "test-privileged"])

    def test_wrong_kernel_arch_source_or_dirty_fails_before_privileged_test(self):
        cases = [(HOST("Linux", "6.1.0", "x86_64"), SHA, b"", b"", "kernel-not-5.10"),
                 (HOST("Linux", "5.11.0", "x86_64"), SHA, b"", b"", "kernel-not-5.10"),
                 (HOST("Linux", "5.10.0-rc7", "x86_64"), SHA, b"", b"", "kernel-not-5.10"),
                 (HOST("Linux", "5.10.5", "riscv64"), SHA, b"", b"", "architecture"),
                 (HOST("Darwin", "5.10.5", "x86_64"), SHA, b"", b"", "kernel-not-5.10"),
                 (HOST("Linux", "5.10.231", "x86_64"), "b" * 40, b"", b"", "source-mismatch"),
                 (HOST("Linux", "5.10.231", "x86_64"), SHA, b"?? secret\n", b"", "checkout-not-clean")]
        with patch.dict(os.environ, GATES, clear=True):
            for host, sha, dirty, _unused, reason in cases:
                with self.subTest(reason=reason):
                    seen, check = self.fake(host=host, sha=sha, dirty=dirty)
                    with self.assertRaisesRegex(runner.Blocked, "^" + reason + "$"):
                        check()
                    self.assertFalse(any(args[0] == "make" for args, _, _ in seen))
            seen, check = self.fake(fail="make")
            with self.assertRaisesRegex(runner.Blocked, "^privileged-component-tests$"):
                check()
            self.assertEqual(seen[-1][1:], (900, 0))
            seen, check = self.fake(compiler=b"go version go1.24 linux/arm64")
            with self.assertRaisesRegex(runner.Blocked, "^compiler-architecture$"):
                check()
            self.assertFalse(any(args[0] == "make" for args, _, _ in seen))
            with self.assertRaisesRegex(runner.Blocked, "^source-sha$"):
                runner.execute("short", host=lambda: HOST("Linux", "5.10.231", "x86_64"),
                               invoke=lambda *_a, **_k: self.fail("no IO"))

    def test_real_command_bounds_environment_and_exit_without_sudo(self):
        seen = []
        class Child:
            pid = 23108
            stdout = None
            def wait(self, timeout): return 0
        def spawn(argv, **kwargs):
            seen.append((argv, kwargs))
            return Child()
        with patch.object(runner.subprocess, "Popen", side_effect=spawn), \
                patch.object(runner.os, "killpg"):
            self.assertEqual(runner.command(["make", "test-privileged"],
                                            timeout=1, max_output=0), b"")
        self.assertEqual(seen[0][0], ["make", "test-privileged"])
        self.assertIs(seen[0][1]["stdin"], subprocess.DEVNULL)
        self.assertIs(seen[0][1]["stdout"], subprocess.DEVNULL)
        self.assertIs(seen[0][1]["stderr"], subprocess.DEVNULL)
        self.assertTrue(seen[0][1]["start_new_session"])
        self.assertNotIn("KUBECONFIG", seen[0][1]["env"])
        with patch.object(runner.subprocess, "Popen", side_effect=OSError("private")):
            with self.assertRaisesRegex(runner.Blocked, "platform-command-unavailable-or-timeout") as raised:
                runner.command(["make", "test-privileged"], timeout=1, max_output=0)
            self.assertNotIn("private", str(raised.exception))

    def test_cli_error_never_prints_private_host_error(self):
        with patch.dict(os.environ, GATES, clear=True), patch.object(
                runner, "execute", side_effect=runner.Blocked("privileged-component-tests")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(runner.main(["--execute", "--source-sha", SHA]), 1)
            self.assertEqual(json.loads(out.getvalue()),
                             {"status": "BLOCKED", "reason": "privileged-component-tests"})


if __name__ == "__main__":
    unittest.main()
