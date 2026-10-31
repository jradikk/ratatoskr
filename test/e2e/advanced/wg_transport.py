"""Fixed read-only k3d CRI/netns WireGuard metrics transport for one owned gateway.

No Pod exec, shell, wg dumps, raw CRI/metrics output or credentials are printed.
Every command is fixed except owner-verified UID/container ID/PID and allowed node.
"""
import json
import re

try:
    from . import wg_fixture as fixture
except ImportError:
    import wg_fixture as fixture

CONTAINER = re.compile(r"containerd://([a-f0-9]{64})\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
SAMPLE = re.compile(r"ratatoskr_gateway_wireguard_(sample_ok|installed_peers|handshaken_peers|receive_bytes|transmit_bytes) ([0-9]+)\Z")
OTHER = re.compile(r"ratatoskr_gateway_(?:upstream_healthy|effective_mtu_bytes) [0-9]+\Z|ratatoskr_gateway_wireguard_latest_handshake_age_seconds -?[0-9]+(?:\.[0-9]+)?\Z")
NODES = fixture.node_images.NODES
RUNTIME = fixture.node_images.RUNTIME


def _container(pod, expected_image):
    fixture.need(pod.get("spec", {}).get("nodeName") in NODES and
                 fixture.lifecycle.UID.fullmatch(pod.get("metadata", {}).get("uid", "")),
                 "Owned gateway node/UID unavailable for metrics.")
    entries = [s for s in pod.get("status", {}).get("containerStatuses", [])
               if s.get("name") == "gateway"]
    fixture.need(len(entries) == 1 and entries[0].get("ready") is True and
                 entries[0].get("imageID") == expected_image,
                 "Gateway runtime image or readiness not verified.")
    ident = entries[0].get("containerID", "")
    match = CONTAINER.fullmatch(ident)
    fixture.need(match is not None, "Gateway CRI container ID invalid.")
    return pod["spec"]["nodeName"], match.group(1)


def _pid(raw, container_id, pod_uid):
    """CRI inspection binds running gateway container to exact Pod UID."""
    try:
        obj = json.loads(raw)
        status, info = obj["status"], obj["info"]
        labels = status["labels"]
        pid = info.get("pid")
        if not isinstance(pid, int) and isinstance(info.get("info"), dict):
            pid = info["info"].get("pid")
        fixture.need(status["id"] == container_id and
                     status["state"] == "CONTAINER_RUNNING" and
                     status["metadata"]["name"] == "gateway" and
                     labels["io.kubernetes.pod.uid"] == pod_uid and
                     type(pid) is int and 1 < pid <= 2**31 - 1,
                     "CRI gateway container PID/Pod UID mismatch.")
        return pid
    except (ValueError, KeyError, TypeError, AttributeError):
        raise fixture.Blocked("CRI gateway container inspection malformed.") from None


def parse_metrics(raw):
    """Only fixed zero-label numeric fields; known zero != unavailable."""
    try:
        text = raw.decode("ascii")
        fixture.need(len(raw) <= 8192, "WG metrics size cap exceeded.")
        values = {}
        for line in text.splitlines():
            if line.startswith("#") or not line:
                continue
            match = SAMPLE.fullmatch(line)
            if match is None:
                fixture.need(OTHER.fullmatch(line) is not None,
                             "WG metrics field or label invalid.")
                continue
            fixture.need(match.group(1) not in values,
                         "WG metrics duplicate field invalid.")
            values[match.group(1)] = int(match.group(2))
        fixture.need(values.get("sample_ok") == 1 and
                     set(values) == {"sample_ok", "installed_peers", "handshaken_peers",
                                     "receive_bytes", "transmit_bytes"} and
                     values["handshaken_peers"] <= values["installed_peers"],
                     "Kernel WG peer sample unavailable or incomplete.")
        return values
    except (UnicodeError, ValueError, TypeError):
        raise fixture.Blocked("WG metrics malformed or unavailable.") from None


def read_metrics(operator, pod, expected_image, *, transport=None):
    """Two CRI identity/PID checks bracket one bounded read in the same netns."""
    if transport is None:
        transport = fixture.node_images._bounded
    node, container_id = _container(pod, expected_image)
    def inspect():
        argv = ["docker", "exec", node, "/bin/crictl", "--runtime-endpoint", RUNTIME,
                "inspect", "-o", "json", container_id]
        try:
            return _pid(transport(argv, timeout=5, max_output=65536), container_id,
                        pod["metadata"]["uid"])
        except fixture.node_images.Blocked:
            raise fixture.Blocked("CRI gateway inspection unavailable.") from None
    pid = inspect()
    # nsenter affects only this fixed node-side wget process, never a workload.
    argv = ["docker", "exec", node, "nsenter", "-t", str(pid), "-n", "--",
            "busybox", "wget", "-q", "-O", "-", "http://127.0.0.1:9902/metrics"]
    try:
        raw = transport(argv, timeout=5, max_output=8192)
    except fixture.node_images.Blocked:
        raise fixture.Blocked("Gateway loopback metrics unavailable.") from None
    fixture.need(inspect() == pid, "Gateway PID changed during kernel metrics read.")
    current = operator.get_object("pod", pod["metadata"]["name"], fixture.SYSTEM)
    fixture.need(current["metadata"]["uid"] == pod["metadata"]["uid"] and
                 _container(current, expected_image) == (node, container_id),
                 "Gateway Pod/container changed during kernel metrics read.")
    return parse_metrics(raw)
