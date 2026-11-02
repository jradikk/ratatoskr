#!/usr/bin/env python3
"""Build local 0.1.0 image/chart candidates; never publish, sign or tag Git.

Explicit build opt-in is NOT a production acceptance decision. OCI archives may
contain requested BuildKit SBOM/provenance, but attestations are not trusted or
signature-verified here. No registry push/login or Kubernetes interaction.
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
IMAGES = COMPONENTS + ("upstream-openvpn",)
REGISTRY = re.compile(r"ghcr\.io/[a-z0-9][a-z0-9-]{0,38}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
VERSION = "0.1.0"
PLATFORMS = "linux/amd64,linux/arm64"


class Blocked(Exception):
    """Static, non-secret refusal reason."""


def run(argv, *, root=ROOT, timeout=1800):
    # Buildx may pull public base images/apt packages; never login/push/manifest
    # create or echo build output containing unknown private environment data.
    env = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_CONFIG", "BUILDX_BUILDER",
                                            "GOCACHE", "GOMODCACHE") if key in os.environ}
    inspect = argv[:3] == ["docker", "buildx", "inspect"]
    try:
        result = subprocess.run(argv, cwd=root, env=env, timeout=timeout,
                                stdout=subprocess.PIPE if inspect else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("local artifact tool unavailable or timed out") from None
    if result.returncode:
        raise Blocked("local artifact command failed; inspect tools privately")
    if inspect:
        return result.stdout.decode("utf-8", errors="replace")[:16384]
    return ""


def git(argv, *, root=ROOT):
    try:
        result = subprocess.run(["git", *argv], cwd=root, capture_output=True,
                                timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("source check unavailable") from None
    if result.returncode or len(result.stdout) > 65536:
        raise Blocked("source check failed")
    return result.stdout.decode("utf-8", errors="strict")


def source(root, expected_sha, git_call):
    if not isinstance(expected_sha, str) or not SHA.fullmatch(expected_sha):
        raise Blocked("exact full lowercase source SHA required")
    if git_call(["status", "--porcelain=v1", "--untracked-files=all"], root=root):
        raise Blocked("tracked or untracked source change detected")
    ignored = git_call(["ls-files", "--others", "--ignored", "--exclude-standard"], root=root)
    if any(line and not line.startswith("bin/") for line in ignored.splitlines()):
        raise Blocked("ignored non-binary file in source checkout")
    if git_call(["rev-parse", "HEAD"], root=root).strip() != expected_sha:
        raise Blocked("current HEAD differs from reviewed source")


def destination(path, root):
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise Blocked("new absolute output path required")
    target = Path(path)
    if target.exists() or target.is_symlink() or target.name in ("", ".", ".."):
        raise Blocked("output must not exist")
    base = target.parent
    try:
        if not base.is_dir() or any(p.is_symlink() for p in (base, *base.parents)):
            raise Blocked("output parent must be an existing real directory")
        if root.resolve() == base.resolve() or root.resolve() in base.resolve().parents:
            raise Blocked("output must be outside source checkout")
    except OSError:
        raise Blocked("output parent unavailable") from None
    return target


def digest(path):
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= (4 << 30):
            raise Blocked("artifact absent or not regular bounded file")
        h = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1 << 20):
                h.update(block)
        after = path.stat(follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Blocked("artifact changed during checksum")
        return {"sha256": h.hexdigest(), "size": before.st_size}
    except OSError:
        raise Blocked("artifact checksum unavailable") from None


def check_platforms(*, root, command):
    """Require both reviewed platforms before output; never install emulators."""
    try:
        result = command(["docker", "buildx", "inspect"], root=root, timeout=30)
    except Blocked:
        raise Blocked("Buildx needs both linux/amd64 and linux/arm64 before staging; configure builder separately") from None
    if not isinstance(result, str):
        raise Blocked("Buildx platform preflight unavailable")
    platforms = set()
    for line in result.splitlines():
        if line.lstrip().startswith("Platforms:"):
            platforms.update(part.strip() for part in line.split(":", 1)[1].split(","))
    if not {"linux/amd64", "linux/arm64"} <= platforms:
        raise Blocked("Buildx builder lacks amd64 or arm64; configure emulation/remote builder separately")


def build(*, execute, version, source_sha, output, registry, root=ROOT, git_call=git, command=run):
    if not execute:
        raise Blocked("explicit --execute required")
    if version != VERSION:
        raise Blocked("only reviewed production candidate 0.1.0 is accepted")
    if not isinstance(registry, str) or not REGISTRY.fullmatch(registry):
        raise Blocked("explicit reviewed ghcr.io/<namespace> required")
    source(root, source_sha, git_call)
    target = destination(output, root)
    check_platforms(root=root, command=command)
    try:
        target.mkdir(mode=0o700)
        target.chmod(0o700)
    except OSError:
        raise Blocked("new private output directory unavailable") from None
    try:
        artifacts = []
        for component in IMAGES:
            name = f"ratatoskr-{component}-multiarch.oci.tar"
            image = f"{registry}/ratatoskr-{component}:{version}"
            args = ["docker", "buildx", "build", "--platform", PLATFORMS,
                    "--build-arg", f"VERSION={version}", "--build-arg", f"COMMIT={source_sha}",
                    "--provenance=mode=max", "--sbom=true", "--tag", image,
                    "--output", f"type=oci,dest={target / name}"]
            if component == "upstream-openvpn":
                args.extend(["--file", "plugins/upstream/openvpn/Dockerfile"])
            else:
                args.extend(["--build-arg", f"COMPONENT={component}", "--file", "Dockerfile"])
            args.append(".")
            command(args, root=root, timeout=2400)
            artifacts.append({"role": "image:" + component, "name": name,
                              "image": image, **digest(target / name)})
        command(["helm", "package", "charts/ratatoskr", "--version", version,
                 "--app-version", version, "--destination", str(target)], root=root, timeout=180)
        chart = target / f"ratatoskr-{version}.tgz"
        artifacts.append({"role": "chart", "name": chart.name, **digest(chart)})
        # Chart defaults retain ghcr.io/skaldhall; exact installation override is
        # staged as non-secret values and MUST be passed with -f when installing.
        values = target / "release-values.yaml"
        values.write_text("image:\n  registry: " + registry + "\n  tag: " + version + "\n")
        artifacts.append({"role": "installation-values", "name": values.name, **digest(values)})
        source(root, source_sha, git_call)
        manifest = {"schemaVersion": 1, "scope": "LOCAL_PRODUCTION_ARTIFACT_CANDIDATE_NOT_RELEASED",
                    "sourceSHA": source_sha, "version": version, "registry": registry,
                    "platformsRequested": PLATFORMS.split(","), "artifacts": artifacts,
                    "sbom": "REQUESTED_IN_BUILDX_NOT_INDEPENDENTLY_VERIFIED",
                    "provenance": "REQUESTED_IN_BUILDX_NOT_INDEPENDENTLY_VERIFIED",
                    "signatures": "NOT_VERIFIED", "runtimeAcceptance": "NOT_ASSESSED_BY_BUILDER",
                    "published": False, "releaseReady": False}
        (target / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        (target / "SHA256SUMS").write_text("".join(f'{entry["sha256"]}  {entry["name"]}\n' for entry in artifacts))
        return {"artifactCount": len(artifacts), "sourceSHA": source_sha,
                "status": "LOCAL_ARTIFACTS_PREPARED_NOT_RELEASED"}
    except BaseException:
        shutil.rmtree(target)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--version")
    parser.add_argument("--source-sha")
    parser.add_argument("--output")
    parser.add_argument("--registry")
    args = parser.parse_args(argv)
    try:
        result = build(execute=args.execute, version=args.version, source_sha=args.source_sha,
                       output=args.output, registry=args.registry)
    except Blocked as err:
        print("BLOCKED: " + str(err))
        return 4
    print(result["status"] + ": local unsigned artifacts only; no release claim")
    return 0


if __name__ == "__main__":
    sys.exit(main())
