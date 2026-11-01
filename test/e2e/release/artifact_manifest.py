"""Offline, read-only manifest/digest validator; NOT an artifact attestor.

No production release is staged by this module. Checksums and self-authored
SBOM/provenance claims cannot verify image contents, signatures or build origin.
Callers must independently review acceptance gates *before* opening inputs.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

COMPONENTS = ("controller", "webhook", "agent", "gateway", "init", "upstream-openvpn")
BINARIES = COMPONENTS[:5]
ARCHES = ("amd64", "arm64")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PART = r"(?:0|[1-9][0-9]*)"
_VERSION = re.compile(rf"{_PART}\.{_PART}\.{_PART}(?:-rc\.[1-9][0-9]*)?\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_FORBIDDEN = re.compile(r"(?:^|[._-])(?:secret|token|password|credential|private|auth)(?:[._-]|$)|\.(?:ovpn|key|pem|crt|p12|pfx|env|secret|token)\Z", re.I)
_MAX_FILE = 1 << 30  # 1 GiB per reviewed input
_MAX_TOTAL = 4 << 30  # 4 GiB total bound; a larger policy needs fresh review
_MAX_MANIFEST = 64 << 10
_MAX_DOC = 2 << 20


class Rejected(ValueError):
    """Sanitized refusal; never reveal artifact contents or private paths."""


def _roles(version):
    result = {}
    for component in BINARIES:
        for arch in ARCHES:
            result[f"binary:{component}:{arch}"] = (f"ratatoskr-{component}-linux-{arch}.bin", None)
    result["chart"] = (f"ratatoskr-{version}.tgz", None)
    for component in COMPONENTS:
        image = "image:" + component
        result[image] = (f"ratatoskr-{component}-multiarch.oci.tar", None)
        for kind in ("sbom", "provenance"):
            result[f"{kind}:{component}"] = (f"ratatoskr-{component}.{kind}.json", image)
    assert len(result) == 29
    return result


def validate_manifest(raw, *, reviewed_version, source_sha, expected_manifest_sha256=None):
    """Validate exact 29-role metadata and independently supplied identities.

    `raw` is externally obtained JSON bytes, not a path. If given, an expected
    manifest hash MUST come from independent review, not from this manifest.
    Nothing is opened or copied here. A successful return is NOT release-ready.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_MANIFEST:
        raise Rejected("manifest bytes absent or oversized")
    if not isinstance(reviewed_version, str) or not _VERSION.fullmatch(reviewed_version):
        raise Rejected("reviewed canonical version required")
    if not isinstance(source_sha, str) or not _SHA.fullmatch(source_sha):
        raise Rejected("exact reviewed source SHA required")
    digest = hashlib.sha256(raw).hexdigest()
    if expected_manifest_sha256 is not None and (not isinstance(expected_manifest_sha256, str) or
       not _HASH.fullmatch(expected_manifest_sha256) or expected_manifest_sha256 != digest):
        raise Rejected("manifest differs from independently reviewed digest")
    try:
        obj = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        raise Rejected("manifest JSON malformed") from None
    if (type(obj) is not dict or set(obj) != {"schemaVersion", "reviewedVersion", "sourceSHA", "artifacts"} or
            type(obj["schemaVersion"]) is not int or obj["schemaVersion"] != 1 or
            obj["reviewedVersion"] != reviewed_version or obj["sourceSHA"] != source_sha or
            type(obj["artifacts"]) is not list or len(obj["artifacts"]) != 29):
        raise Rejected("manifest scope, version, source or inventory invalid")
    roles = _roles(reviewed_version)
    seen, paths = set(), set()
    for item in obj["artifacts"]:
        if type(item) is not dict or set(item) != {"role", "name", "size", "sha256"}:
            raise Rejected("artifact metadata schema invalid")
        role, name = item["role"], item["name"]
        if (type(role) is not str or role not in roles or role in seen or type(name) is not str or
            not _NAME.fullmatch(name) or name in (".", "..") or _FORBIDDEN.search(name) or
            name != roles[role][0] or name in paths or type(item["size"]) is not int or
            not 0 < item["size"] <= _MAX_FILE or type(item["sha256"]) is not str or
            not _HASH.fullmatch(item["sha256"])):
            raise Rejected("artifact role, flat name, size or digest invalid")
        seen.add(role)
        paths.add(name)
    if seen != set(roles) or sum(item["size"] for item in obj["artifacts"]) > _MAX_TOTAL:
        raise Rejected("required artifacts missing or total size exceeds policy")
    return {"manifestSHA256": digest, "sourceSHA": source_sha,
            "reviewedVersion": reviewed_version, "status": "METADATA_ONLY_NOT_ATTESTED",
            "artifactRoles": tuple(sorted(seen)), "releaseReady": False}


def _directory(root, checkout):
    if not isinstance(root, Path) or not root.is_absolute() or not isinstance(checkout, Path):
        raise Rejected("absolute external input directory required")
    try:
        root_abs = root.resolve(strict=True)
        code_abs = checkout.resolve(strict=True)
        if root_abs == code_abs or code_abs in root_abs.parents or root_abs.is_symlink():
            raise Rejected("artifact input directory must be outside checkout")
        for parent in (root, *root.parents):
            if parent.is_symlink():
                raise Rejected("artifact input directory contains symlink")
        mode = root.stat().st_mode
        if not stat.S_ISDIR(mode):
            raise Rejected("artifact input directory is not a directory")
    except (OSError, RuntimeError):
        raise Rejected("artifact input directory unavailable") from None
    return root_abs


def _read_bounded(root_fd, name, size_limit):
    """Open a single flat file without symlinks and detect in-place mutations."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(name, flags, dir_fd=root_fd)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    not 0 < before.st_size <= size_limit):
                raise Rejected("artifact must be nonempty regular single-link file within limits")
            sha = hashlib.sha256()
            data = bytearray() if name.endswith((".sbom.json", ".provenance.json")) else None
            count = 0
            while chunk := stream.read(min(1 << 20, size_limit - count + 1)):
                count += len(chunk)
                if count > size_limit:
                    raise Rejected("artifact exceeds bounded size")
                sha.update(chunk)
                if data is not None:
                    data.extend(chunk)
            after = os.fstat(stream.fileno())
            stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                      before.st_ctime_ns, before.st_nlink) == (
                      after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                      after.st_ctime_ns, after.st_nlink)
            if not stable or count != before.st_size:
                raise Rejected("artifact changed during validation")
            return count, sha.hexdigest(), bytes(data) if data is not None else None
    except Rejected:
        raise
    except (OSError, UnicodeError):
        raise Rejected("artifact unreadable or unsafe") from None


def verify_files(raw, *, input_dir, checkout, reviewed_version, source_sha,
                 expected_manifest_sha256=None):
    """Read-only digests + structural document subjects; no archive extraction."""
    result = validate_manifest(raw, reviewed_version=reviewed_version, source_sha=source_sha,
                               expected_manifest_sha256=expected_manifest_sha256)
    root = _directory(input_dir, checkout)
    obj = json.loads(raw)
    items = {item["role"]: item for item in obj["artifacts"]}
    roles = _roles(reviewed_version)
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise Rejected("artifact input directory unavailable") from None
    try:
        for role in sorted(items):
            item = items[role]
            limit = _MAX_DOC if role.startswith(("sbom:", "provenance:")) else _MAX_FILE
            size, digest, body = _read_bounded(root_fd, item["name"], limit)
            if size != item["size"] or digest != item["sha256"]:
                raise Rejected("artifact bytes do not match manifest digest or size")
            image_role = roles[role][1]
            if image_role:
                try:
                    doc = json.loads(body)
                except (UnicodeDecodeError, ValueError):
                    raise Rejected("evidence document JSON malformed") from None
                if (type(doc) is not dict or set(doc) != {"schemaVersion", "kind", "subject", "sourceSHA", "reviewedVersion"} or
                        type(doc["schemaVersion"]) is not int or doc["schemaVersion"] != 1 or
                        doc["kind"] != role.split(":")[0] or doc["sourceSHA"] != source_sha or
                        doc["reviewedVersion"] != reviewed_version or type(doc["subject"]) is not dict or
                        doc["subject"] != {"role": image_role, "sha256": items[image_role]["sha256"]}):
                    raise Rejected("evidence document subject or source claim mismatch")
    finally:
        os.close(root_fd)
    return {**result, "status": "BYTES_MATCH_MANIFEST_NOT_ATTESTED", "releaseReady": False}
