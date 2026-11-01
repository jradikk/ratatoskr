#!/usr/bin/env python3
"""Explicit, local UNSIGNED experimental RC: ten binaries + chart only.

Not a production release, not the 29-gate acceptance guard. Never builds OCI
images, SBOMs, attestations or a published/signed/tagged release. The operator
must independently review final flannel/no-mesh and Calico evidence beforehand.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ("controller", "webhook", "agent", "gateway", "init")
ARCHES = ("amd64", "arm64")
RC = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-rc\.[1-9][0-9]*\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
VERSION_PATH = "github.com/skaldhall/ratatoskr/pkg/version"


class Blocked(Exception):
    """Sanitized local refusal; do not print paths, CLI output or credentials."""


def command(argv, *, root=ROOT, env=None, timeout=180):
    clean_env = {key: os.environ[key] for key in ("PATH", "HOME", "GOCACHE", "GOMODCACHE", "GOTOOLCHAIN")
                 if key in os.environ}
    clean_env.update(GOPROXY="off", GOSUMDB="off", GOWORK="off", CGO_ENABLED="0")
    if env:
        clean_env.update(env)
    try:
        process = subprocess.run(argv, cwd=root, env=clean_env, capture_output=True,
                                 timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("local validation or build unavailable") from None
    if process.returncode or len(process.stdout) > 16384:
        raise Blocked("local validation or build failed; inspect offline toolchain privately")
    return process.stdout.decode("utf-8", errors="strict")


def _source(root, source_sha, run):
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        raise Blocked("exact full lowercase source SHA required")
    if run(["git", "status", "--porcelain=v1", "--untracked-files=all"], root=root).strip():
        raise Blocked("tracked or untracked source change detected")
    # Generated bin/ may exist; all other ignored files are refused to prevent
    # staging from a workspace with hidden secrets or stale outputs.
    ignored = run(["git", "ls-files", "--others", "--ignored", "--exclude-standard"], root=root)
    if any(path and not path.startswith("bin/") for path in ignored.splitlines()):
        raise Blocked("ignored non-binary files present in source checkout")
    if run(["git", "rev-parse", "HEAD"], root=root).strip() != source_sha:
        raise Blocked("current source HEAD differs from reviewed SHA")


def _destination(output, root):
    if not isinstance(output, str) or not output or not Path(output).is_absolute():
        raise Blocked("new absolute staging path required")
    target = Path(output)
    if target.name in (".", "..") or target.exists() or target.is_symlink():
        raise Blocked("staging path must be new and unused")
    if target == root or root in target.parents:
        raise Blocked("staging must be outside checkout")
    try:
        parent = target.parent
        if any(p.is_symlink() for p in (parent, *parent.parents)) or not parent.is_dir():
            raise Blocked("staging parent must be an existing real directory")
        if parent.resolve() == root.resolve() or root.resolve() in parent.resolve().parents:
            raise Blocked("staging must be outside checkout")
    except OSError:
        raise Blocked("staging path inaccessible") from None
    return target


def _hash(path):
    h = hashlib.sha256()
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= (1 << 30):
            raise Blocked("staged artifact is not a bounded regular file")
        with path.open("rb") as source:
            while data := source.read(1 << 20):
                h.update(data)
        after = path.stat(follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                         after.st_mtime_ns, after.st_ctime_ns):
            raise Blocked("staged artifact changed during digest")
    except OSError:
        raise Blocked("staged artifact unreadable") from None
    return h.hexdigest(), before.st_size


def prepare(*, execute, version, source_sha, output, root=ROOT, run=command):
    """Create only local binary/chart outputs after all read-only guards pass."""
    if not execute:
        raise Blocked("explicit --execute required; no output created")
    if not isinstance(version, str) or not RC.fullmatch(version):
        raise Blocked("only canonical experimental X.Y.Z-rc.N versions permitted")
    _source(root, source_sha, run)
    target = _destination(output, root)
    # Target is created exclusively with 0700; no existing file is touched.
    try:
        target.mkdir(mode=0o700)
        target.chmod(0o700)
    except OSError:
        raise Blocked("staging directory could not be created exclusively") from None
    try:
        artifacts = []
        ldflags = f"-s -w -X {VERSION_PATH}.Version={version} -X {VERSION_PATH}.Commit={source_sha}"
        for component in COMPONENTS:
            for arch in ARCHES:
                name = f"ratatoskr-{component}-linux-{arch}"
                path = target / name
                run(["go", "build", "-trimpath", "-ldflags", ldflags, "-o", str(path),
                     "./cmd/" + component], root=root,
                    env={"CGO_ENABLED": "0", "GOPROXY": "off", "GOSUMDB": "off",
                         "GOWORK": "off", "GOOS": "linux", "GOARCH": arch}, timeout=300)
                digest, size = _hash(path)
                artifacts.append({"role": "binary:" + component + ":" + arch,
                                  "name": name, "sha256": digest, "size": size})
        run(["helm", "package", "charts/ratatoskr", "--version", version,
             "--app-version", version, "--destination", str(target)], root=root, timeout=120)
        chart = target / ("ratatoskr-" + version + ".tgz")
        digest, size = _hash(chart)
        artifacts.append({"role": "chart", "name": chart.name, "sha256": digest, "size": size})
        _source(root, source_sha, run)  # detect source changes while building
        manifest = {"schemaVersion": 1, "scope": "LOCAL_UNSIGNED_EXPERIMENTAL_RC_ONLY",
                    "version": version, "sourceSHA": source_sha,
                    "artifacts": artifacts, "images": "NOT_INCLUDED",
                    "openvpnPluginImage": "NOT_INCLUDED", "sbom": "NOT_VERIFIED",
                    "provenance": "NOT_VERIFIED", "signatures": "NOT_INCLUDED",
                    "fullAcceptance": "NOT_CLAIMED", "publishable": False}
        (target / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        (target / "SHA256SUMS").write_text("".join(f'{a["sha256"]}  {a["name"]}\n' for a in artifacts))
        (target / "RELEASE-NOTES.txt").write_text(
            "LOCAL UNSIGNED EXPERIMENTAL RC ONLY — NOT PRODUCTION-READY\n"
            "Scope for parent review: flannel/no-mesh agent/iproute selected traffic, "
            "WireGuard, HA and outage/recovery evidence; serial Calico testing remains "
            "a separate parent-owned gate.\n"
            "Includes ten Linux binaries and a version-overridden Helm chart only. "
            "NO OCI images or OpenVPN plugin image, SBOM/provenance trust, signature, "
            "publication, full M8 matrix or full M9 acceptance is claimed.\n")
        return {"status": "LOCAL_EXPERIMENTAL_RC_STAGED", "sourceSHA": source_sha,
                "version": version, "artifactCount": len(artifacts), "publishable": False}
    except BaseException:
        # Partial binaries/chart must not resemble a completed RC after failure.
        shutil.rmtree(target)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--version")
    parser.add_argument("--source-sha")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        result = prepare(execute=args.execute, version=args.version,
                         source_sha=args.source_sha, output=args.output)
    except Blocked as error:
        print("BLOCKED: " + str(error))
        return 4
    print(result["status"] + ": unsigned binaries and chart only; NOT publishable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
