#!/usr/bin/env python3
"""Inert-by-default external Linux 5.10 privileged COMPONENT test tier.

No cluster, provider, installation, build/push or coverage-ledger integration.
Even an actual successful run remains INCOMPLETE until independently accepted
packet/CNI/image traffic evidence exists on the specified platform.
"""
import argparse
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}\Z")
KERNEL = re.compile(r"5\.10\.[0-9]+(?:[-+][a-zA-Z0-9._-]+)?\Z")
COMPILER = re.compile(r"go version go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[a-z0-9.]+)? linux/(?:amd64|arm64)\Z")


class Blocked(Exception):
    """Only fixed safe reasons; never forward host output or environment."""


def command(argv, *, timeout, max_output):
    """Bounded output/deadline, isolated group kill/reap, sanitized errors."""
    proc = None
    poll = selectors.DefaultSelector()
    output = bytearray()
    limit = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL if max_output == 0 else subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True,
                                env={key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ})
        if max_output:
            os.set_blocking(proc.stdout.fileno(), False)
            poll.register(proc.stdout, selectors.EVENT_READ)
        while poll.get_map():
            remaining = limit - time.monotonic()
            if remaining <= 0:
                raise Blocked("platform-command-timeout")
            for key, _ in poll.select(remaining):
                try:
                    chunk = os.read(key.fileobj.fileno(), min(4096, max_output + 1 - len(output)))
                except BlockingIOError:
                    continue
                if not chunk:
                    poll.unregister(key.fileobj)
                else:
                    output.extend(chunk)
                    if len(output) > max_output:
                        raise Blocked("platform-command-output-limit")
        if proc.wait(timeout=max(0.001, limit - time.monotonic())) != 0:
            raise Blocked("platform-command-failed")
        return bytes(output)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise Blocked("platform-command-unavailable-or-timeout") from None
    finally:
        poll.close()
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise Blocked("platform-command-reap-failed") from None
            if proc.stdout:
                proc.stdout.close()


def execute(source_sha, *, host=os.uname, invoke=command):
    """Run only existing privileged package tests on a clean exact Linux 5.10 host."""
    if (os.environ.get("RATATOSKR_E2E_FINAL_GATE") != "1" or
            os.environ.get("RATATOSKR_E2E_PLATFORM_510") != "1"):
        raise Blocked("authorization")
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        raise Blocked("source-sha")
    # Never allow a lookalike checkout elsewhere to be credited as this runner.
    repo = Path(__file__).resolve().parents[3]
    if Path.cwd().resolve() != repo:
        raise Blocked("checkout-location")
    u = host()
    if (u.sysname != "Linux" or type(u.release) is not str or
            len(u.release) > 128 or not KERNEL.fullmatch(u.release) or
            re.search(r"(?:^|[-+.])(?:rc|pre|test)[0-9]*", u.release, re.IGNORECASE)):
        raise Blocked("kernel-not-5.10")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(u.machine)
    if arch is None:
        raise Blocked("architecture")
    # GIT_OPTIONAL_LOCKS and GIT_CONFIG_* cannot be injected via sanitized env.
    try:
        actual = invoke(["git", "rev-parse", "HEAD"], timeout=10, max_output=64).decode("ascii").strip()
    except (Blocked, UnicodeError):
        raise Blocked("source-check") from None
    if actual != source_sha:
        raise Blocked("source-mismatch")
    try:
        # Commit parent history may be clean while ignored local build outputs
        # exist. The platform result only covers source files, not images.
        dirty = invoke(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                       timeout=10, max_output=1)
    except Blocked:
        raise Blocked("checkout-not-clean") from None
    if dirty:
        raise Blocked("checkout-not-clean")
    try:
        compiler = invoke(["go", "version"], timeout=10, max_output=128).decode("ascii").strip()
    except (Blocked, UnicodeError):
        raise Blocked("compiler-unavailable") from None
    if not COMPILER.fullmatch(compiler) or not compiler.endswith("linux/" + arch):
        raise Blocked("compiler-architecture")
    try:
        invoke(["make", "test-privileged"], timeout=900, max_output=0)
    except Blocked:
        raise Blocked("privileged-component-tests") from None
    return {"sourceSHA": actual, "kernelRelease": u.release, "architecture": arch,
            "compiler": compiler, "componentTests": "passed",
            "trafficAcceptance": "not-run", "releaseStatus": "INCOMPLETE"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="External Linux 5.10 component-only platform check")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source-sha")
    args = parser.parse_args(argv)
    if not (args.execute and os.environ.get("RATATOSKR_E2E_FINAL_GATE") == "1" and
            os.environ.get("RATATOSKR_E2E_PLATFORM_510") == "1"):
        print(json.dumps({"status": "SKIPPED", "reason": "explicit-platform-optin-required"}))
        return 2
    try:
        report = execute(args.source_sha)
    except Blocked as err:
        print(json.dumps({"status": "BLOCKED", "reason": str(err)}))
        return 1
    print(json.dumps({"status": "INCOMPLETE", **report}, sort_keys=True))
    return 4


if __name__ == "__main__":
    sys.exit(main())
