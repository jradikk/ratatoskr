#!/usr/bin/env python3
"""Ownership-safe namespace lifecycle. Tests inject an offline Kubernetes API."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

CONTEXT = "k3d-ratatoskr-flannel"
LABEL = "ratatoskr.skaldhall.io/m1-owner"
NAME = re.compile(r"ratatoskr-m1-(?:fake|live)-[0-9a-f]{32}\Z")
TOKEN = re.compile(r"[0-9a-f]{32}\Z")
UID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


class NamespaceError(Exception):
    """Fixed diagnostics only; never emit Kubernetes responses or manifests."""


def identity(mode):
    if mode not in ("fake", "live"):
        raise NamespaceError("Invalid namespace mode.")
    token = uuid.uuid4().hex
    return "ratatoskr-m1-" + mode + "-" + uuid.uuid4().hex, token


def validate_identity(name, token):
    if not NAME.fullmatch(name) or not TOKEN.fullmatch(token):
        raise NamespaceError("Invalid namespace identity.")


def namespace_object(name, token):
    validate_identity(name, token)
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": {
        "name": name, "labels": {LABEL: token, "app.kubernetes.io/part-of": "ratatoskr-m1-proof"}}}


def owned(item, name, token, uid=None):
    try:
        metadata = item["metadata"]
        return (item.get("kind") == "Namespace" and metadata.get("name") == name
                and metadata.get("labels", {}).get(LABEL) == token
                and isinstance(metadata.get("uid"), str) and UID.fullmatch(metadata["uid"])
                and (uid is None or metadata["uid"] == uid))
    except (KeyError, TypeError, AttributeError):
        return False


class KubectlAPI:
    def __init__(self, run=subprocess.run):
        self.run = run

    def call(self, action, *args, obj=None, timeout=12):
        if action not in ("get", "create", "delete") or not 0 < timeout <= 12:
            raise NamespaceError("Invalid bounded namespace operation.")
        env = {key: os.environ[key] for key in ("PATH", "HOME", "KUBECONFIG") if key in os.environ}
        env["KUBECTL_KUBERC"] = "false"
        try:
            result = self.run(["kubectl", "--context", CONTEXT, "--request-timeout=10s", action, *args],
                              input=None if obj is None else json.dumps(obj), text=True,
                              capture_output=True, timeout=timeout, check=False, env=env)
            if result.returncode:
                raise NamespaceError("Namespace API operation failed (response suppressed).")
            return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            raise NamespaceError("Namespace API unavailable or timed out.") from None

    def get(self, name, timeout=12):
        if not NAME.fullmatch(name):
            raise NamespaceError("Invalid namespace name.")
        raw = self.call("get", "namespace", name, "--ignore-not-found", "-o", "json", timeout=timeout)
        if not raw.strip():
            return None
        try:
            item = json.loads(raw)
            if item.get("kind") != "Namespace" or item.get("metadata", {}).get("name") != name:
                raise ValueError()
            return item
        except (ValueError, TypeError, AttributeError):
            raise NamespaceError("Malformed namespace observation.") from None

    def create(self, name, token):
        raw = self.call("create", "-f", "-", "-o", "json", obj=namespace_object(name, token))
        try:
            item = json.loads(raw)
            if not owned(item, name, token):
                raise ValueError()
            return item["metadata"]["uid"]
        except (ValueError, TypeError, AttributeError, KeyError):
            raise NamespaceError("CREATE identity unconfirmed; no deletion authorized.") from None

    def delete(self, name, uid, timeout=12):
        if not NAME.fullmatch(name) or not UID.fullmatch(uid):
            raise NamespaceError("Invalid namespace deletion identity.")
        options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid},
                   "propagationPolicy": "Foreground"}
        self.call("delete", "--raw=/api/v1/namespaces/" + name, "-f", "-", obj=options, timeout=timeout)


def record_path(private):
    supplied = Path(private)
    if supplied.is_symlink():
        raise NamespaceError("Unsafe private lifecycle directory.")
    path = supplied.resolve(strict=True)
    root = Path(__file__).resolve().parents[3]
    if (path == root or root in path.parents or not path.is_dir()
            or stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise NamespaceError("Unsafe private lifecycle directory.")
    return path / "namespace-owner.json"


def write_record(path, value):
    # Exclusive initial record is persisted BEFORE CREATE, so a signal or timeout
    # cannot turn an ambiguous create into authority to adopt/delete by name.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())


def create_namespace(api, private, name, token):
    validate_identity(name, token)
    path = record_path(private)
    # A preexisting ownership record (including an ambiguous attempt) must not
    # be reused for another CREATE, and will be inspected fail-closed at cleanup.
    write_record(path, {"name": name, "token": token, "uid": None})
    if api.get(name) is not None:
        path.unlink()
        raise NamespaceError("Namespace already exists; no adoption or deletion authorized.")
    # Exactly one CREATE; do not retry/adopt after conflict or timeout.
    uid = api.create(name, token)
    if not isinstance(uid, str) or not UID.fullmatch(uid):
        raise NamespaceError("CREATE UID unconfirmed; no deletion authorized.")
    next_path = path.with_suffix(".next")
    write_record(next_path, {"name": name, "token": token, "uid": uid})
    os.replace(next_path, path)


def cleanup_namespace(api, private, clock=time.monotonic, sleep=time.sleep, budget=120):
    if not 0 < budget <= 120:
        raise NamespaceError("Invalid namespace cleanup budget.")
    path = record_path(private)
    if not path.exists():
        return
    try:
        if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ValueError()
        data = path.read_bytes()
        if len(data) > 1024:
            raise ValueError()
        record = json.loads(data)
        name, token, uid = record["name"], record["token"], record["uid"]
        validate_identity(name, token)
    except (ValueError, KeyError, TypeError):
        raise NamespaceError("Namespace ownership record invalid; deletion refused.") from None
    if not isinstance(uid, str) or not UID.fullmatch(uid):
        # Even if GET would show our owner label, an unconfirmed CREATE response
        # has no UID proof. Never infer authority from names or labels alone.
        raise NamespaceError("Namespace CREATE was ambiguous; cleanup unverified, no delete authorized.")
    deadline = clock() + budget
    def remaining():
        seconds = min(12, deadline - clock())
        if seconds <= 0:
            raise NamespaceError("Namespace cleanup timed out.")
        return seconds
    item = api.get(name, timeout=remaining())
    if item is None:
        path.unlink()
        return
    if not owned(item, name, token, uid):
        raise NamespaceError("Namespace identity replaced; deletion refused.")
    # A replacement BETWEEN GET and DELETE is protected by API UID precondition.
    api.delete(name, uid, timeout=remaining())
    while True:
        item = api.get(name, timeout=remaining())
        if item is None:
            path.unlink()
            return
        if not owned(item, name, token, uid):
            raise NamespaceError("Namespace replaced during cleanup; no further deletion authorized.")
        sleep(min(1, remaining()))


def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "identity":
            print(*identity(sys.argv[2]))
        elif len(sys.argv) == 5 and sys.argv[1] == "create":
            create_namespace(KubectlAPI(), *sys.argv[2:])
        elif len(sys.argv) == 3 and sys.argv[1] == "cleanup":
            cleanup_namespace(KubectlAPI(), sys.argv[2])
        else:
            raise NamespaceError("Invalid namespace lifecycle command.")
    except (NamespaceError, OSError, ValueError):
        print("Namespace lifecycle failed; ownership/cleanup unverified (details suppressed).", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
