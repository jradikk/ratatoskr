"""Fixed read-only k3d CRI/netns WireGuard metrics transport for one owned gateway.

No Pod exec, shell, wg dumps, raw CRI/metrics output or credentials are printed.
Every command is fixed except owner-verified UID/container ID/PID and allowed node.
"""
import json
import math
import re

try:
    from . import wg_fixture as fixture
except ImportError:
    import wg_fixture as fixture

CONTAINER = re.compile(r"containerd://([a-f0-9]{64})\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
SAMPLE = re.compile(r"ratatoskr_gateway_wireguard_(sample_ok|installed_peers|handshaken_peers|receive_bytes|transmit_bytes) ([0-9]+)\Z")
OTHER = re.compile(r"ratatoskr_gateway_(?:upstream_healthy|effective_mtu_bytes) [0-9]+\Z|ratatoskr_gateway_wireguard_latest_handshake_age_seconds -?[0-9]+(?:\.[0-9]+)?\Z")
# GatewayProgramming is a separate zero-label metric family. Histograms use
# exactly the explicit Go buckets plus +Inf; no identity or dynamic labels.
PROGRAMMING_BUCKETS = frozenset(("0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1", "5", "10", "+Inf"))
PROGRAMMING_COUNTER = re.compile(r"ratatoskr_gateway_programming_(attempts|errors)_total ([0-9]+)\Z")
PROGRAMMING_COUNT = re.compile(r"ratatoskr_gateway_programming_duration_seconds_count ([0-9]+)\Z")
PROGRAMMING_SUM = re.compile(r"ratatoskr_gateway_programming_duration_seconds_sum ([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)\Z")
PROGRAMMING_BUCKET = re.compile(r'ratatoskr_gateway_programming_duration_seconds_bucket\{le="([+A-Za-z0-9.]+)"\} ([0-9]+)\Z')
LINK_ROLES = frozenset(("geneve", "upstream", "wireguard"))
LINK_FIELDS = frozenset(("sample_ok", "receive_bytes", "transmit_bytes", "receive_packets", "transmit_packets"))
LINK_SAMPLE = re.compile(r'ratatoskr_gateway_link_(sample_ok|receive_bytes|transmit_bytes|receive_packets|transmit_packets)\{role="(geneve|upstream|wireguard)"\} ([0-9]+)\Z')
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
    """Keep WG sample schema; accept only bounded zero-label programming rows."""
    try:
        text = raw.decode("ascii")
        fixture.need(len(raw) <= 8192, "WG metrics size cap exceeded.")
        values = {}
        programming = {}
        buckets = {}
        links = {}
        for line in text.splitlines():
            if line.startswith("#") or not line:
                continue
            match = SAMPLE.fullmatch(line)
            if match is not None:
                fixture.need(match.group(1) not in values,
                             "WG metrics duplicate field invalid.")
                values[match.group(1)] = int(match.group(2))
                continue
            if OTHER.fullmatch(line):
                continue
            if line.startswith("ratatoskr_gateway_link_"):
                link = LINK_SAMPLE.fullmatch(line)
                fixture.need(link is not None, "Gateway link metric field or label invalid.")
                field, role, count = link.groups()
                role_values = links.setdefault(role, {})
                fixture.need(field not in role_values, "Gateway link metric duplicated.")
                role_values[field] = int(count)
                continue
            if line.startswith("ratatoskr_gateway_programming_"):
                counter = PROGRAMMING_COUNTER.fullmatch(line)
                count = PROGRAMMING_COUNT.fullmatch(line)
                total = PROGRAMMING_SUM.fullmatch(line)
                bucket = PROGRAMMING_BUCKET.fullmatch(line)
                if counter:
                    key, number = counter.groups()
                    fixture.need(key not in programming, "Programming counter duplicated.")
                    programming[key] = int(number)
                elif count:
                    fixture.need("count" not in programming, "Programming count duplicated.")
                    programming["count"] = int(count.group(1))
                elif total:
                    fixture.need("sum" not in programming, "Programming sum duplicated.")
                    duration = float(total.group(1))
                    fixture.need(math.isfinite(duration) and duration >= 0,
                                 "Programming duration invalid.")
                    programming["sum"] = duration
                elif bucket:
                    bound, number = bucket.groups()
                    fixture.need(bound in PROGRAMMING_BUCKETS and bound not in buckets,
                                 "Programming bucket label unexpected or duplicated.")
                    buckets[bound] = int(number)
                else:
                    raise fixture.Blocked("WG/programming metric field or label invalid.")
                continue
            raise fixture.Blocked("WG/programming metric field or label invalid.")
        fixture.need(values.get("sample_ok") == 1 and
                     set(values) == {"sample_ok", "installed_peers", "handshaken_peers",
                                     "receive_bytes", "transmit_bytes"} and
                     values["handshaken_peers"] <= values["installed_peers"],
                     "Kernel WG peer sample unavailable or incomplete.")
        if programming or buckets:
            fixture.need(set(programming) == {"attempts", "errors", "count", "sum"} and
                         set(buckets) == PROGRAMMING_BUCKETS and
                         programming["errors"] <= programming["attempts"] and
                         buckets["+Inf"] == programming["count"] and
                         all(buckets[bound] <= buckets["+Inf"] for bound in buckets),
                         "Programming metric family incomplete or inconsistent.")
            ordered = ("0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1", "5", "10", "+Inf")
            fixture.need(all(buckets[left] <= buckets[right] for left, right in zip(ordered, ordered[1:])),
                         "Programming cumulative histogram invalid.")
        if links:
            fixture.need(set(links) == LINK_ROLES, "Gateway fixed-role link sample incomplete.")
            for role_values in links.values():
                sample = role_values.get("sample_ok")
                fixture.need(sample in (0, 1) and (type(sample) is int) and
                             (set(role_values) == {"sample_ok"} if sample == 0 else set(role_values) == LINK_FIELDS),
                             "Gateway fixed-role link sample missing, stale, or invalid.")
        return values
    except (UnicodeError, ValueError, TypeError, OverflowError):
        raise fixture.Blocked("WG/programming metrics malformed or unavailable.") from None


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
