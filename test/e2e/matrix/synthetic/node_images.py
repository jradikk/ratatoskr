#!/usr/bin/env python3
"""Read-only, bounded k3d node CRI config-digest preflight; no image import.

The operator provides exact nine expected immutable runtime IDs. The mapping
below is deliberately fixed for six local fixture/build tags; no arbitrary
node/tag/command is accepted. This is NOT provenance for a source build and
never authorizes resource creation by itself.
"""
import json
import os
import re
import selectors
import signal
import subprocess
import time

NODES = ("k3d-ratatoskr-flannel-server-0",
         "k3d-ratatoskr-flannel-agent-0",
         "k3d-ratatoskr-flannel-agent-1")
TAGS = {"gateway": "ghcr.io/skaldhall/ratatoskr-gateway:dev",
        "plugin": "docker.io/library/ratatoskr-openvpn:m1-local",
        "server": "docker.io/library/ratatoskr-synthetic-openvpn:local",
        "tools": "docker.io/library/ratatoskr-tools:m1-local",
        "witness": "docker.io/library/ratatoskr-synthetic-witness:local",
        "selected": "docker.io/library/ratatoskr-synthetic-client:local"}
ID = re.compile(r"sha256:[a-fA-F0-9]{64}\Z")
EXPECTED = re.compile(r"(?:containerd://)?sha256:[a-fA-F0-9]{64}\Z")
MAX_JSON = 2_000_000
RUNTIME = "unix:///run/k3s/containerd/containerd.sock"


class Blocked(Exception):
    """Never includes raw CRI JSON, host paths or runtime stderr."""


def approved(expected):
    if (not isinstance(expected, dict) or set(expected) != set(TAGS) or
            not all(isinstance(expected[k], str) and EXPECTED.fullmatch(expected[k]) for k in TAGS)):
        raise Blocked("Six approved exact CRI config IDs for local images required.")
    return {k: v.removeprefix("containerd://") for k, v in expected.items()}


def inspect(data, expected):
    """Verify exactly one image name→config-ID mapping for each fixed tag."""
    ids = approved(expected)
    try:
        if not isinstance(data, dict) or set(data) != {"images"}:
            raise ValueError()
        images = data["images"]
        if not isinstance(images, list) or not 0 < len(images) <= 2048:
            raise ValueError()
        found = {tag: [] for tag in TAGS.values()}
        for entry in images:
            if not isinstance(entry, dict):
                raise ValueError()
            tags = entry.get("repoTags", [])
            if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
                raise ValueError()
            matches = set(tags) & set(found)
            if matches:
                value = entry.get("id")
                if not isinstance(value, str) or not ID.fullmatch(value):
                    raise ValueError()
                for tag in matches:
                    if tags.count(tag) != 1:
                        raise ValueError()
                    found[tag].append(value)
        if any(len(found[tag]) != 1 or found[tag][0] != ids[component]
               for component, tag in TAGS.items()):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Blocked("Node CRI image tag/config ID missing, duplicate or mismatched.") from None
    return True


def _bounded(argv, *, timeout, max_output):
    """Kill isolated CLI process group on timeout/cap; suppress stderr."""
    env = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT")
           if key in os.environ}
    process = None
    selector = selectors.DefaultSelector()
    result = bytearray()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=env, start_new_session=True)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Blocked("Node CRI query timed out.")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), min(8192, max_output + 1 - len(result)))
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    result.extend(chunk)
                    if len(result) > max_output:
                        raise Blocked("Node CRI output exceeded cap.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Blocked("Node CRI query timed out.")
        if process.wait(timeout=remaining) != 0:
            raise Blocked("Node CRI query failed.")
        return bytes(result)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise Blocked("Node CRI query unavailable or timed out.") from None
    finally:
        selector.close()
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise Blocked("Node CRI process could not be reaped.") from None
            if process.stdout:
                process.stdout.close()


def verify(expected, *, transport=_bounded, clock=time.monotonic, budget=60):
    """Fixed docker exec argv; no shell, mounts, nodes outside allowlist or logs."""
    ids = approved(expected)
    if not 0 < budget <= 90:
        raise Blocked("Node CRI verification budget invalid.")
    deadline = clock() + budget
    for node in NODES:
        timeout = min(12, deadline - clock())
        if timeout <= 0:
            raise Blocked("Node CRI verification total deadline exceeded.")
        argv = ["docker", "exec", node, "/bin/crictl", "--runtime-endpoint", RUNTIME,
                "images", "-o", "json"]
        try:
            response = transport(argv, timeout=timeout, max_output=MAX_JSON)
            if not isinstance(response, bytes) or len(response) > MAX_JSON:
                raise Blocked("Node CRI output type or size invalid.")
            inspect(json.loads(response), ids)
        except (ValueError, TypeError, UnicodeError):
            raise Blocked("Node CRI verification response malformed.") from None
        if clock() >= deadline:
            raise Blocked("Node CRI verification total deadline exceeded.")
    return True
