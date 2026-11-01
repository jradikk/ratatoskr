#!/usr/bin/env python3
"""Opt-in, owned-fixture gateway wrong-audience rejection (partial evidence).

No cluster access on import. Never emit token, peer public keys, TLS data, API
responses, or HTTP bodies. An HTTP 401 proves a gateway rejection; it does not
by itself audit the server's internal TokenReview call.
"""
import base64
import hashlib
import json
import os
import re
import socket
import ssl
from pathlib import Path

try:
    from . import tokenreview as auth, wg_fixture as wg
except ImportError:
    import tokenreview as auth
    import wg_fixture as wg

TEST_KEY = base64.b64encode(b"\x07" * 32).decode("ascii")
PEM = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]{1,4096}-----END CERTIFICATE-----\s*\Z")


class Blocked(Exception):
    """Only fixed, secret-free stage names."""


class ConnectBlocked(Blocked):
    """Direct PodIP cannot be reached from the verified node network namespace."""


class TLSBlocked(Blocked):
    """Pinned gateway CA, PodIP SAN or TLS 1.3 handshake failed."""


STAGES = frozenset({"authorization", "identity-pre", "token-request", "peer-before",
                    "gateway-request", "gateway-request-connect", "gateway-request-tls",
                    "gateway-request-http", "gateway-request-netns", "gateway-request-input",
                    "identity-post", "peer-after", "marker-after"})


def stage(name, action):
    if name not in STAGES:
        raise Blocked("Gateway negative checkpoint invalid.")
    try:
        return action()
    except (KeyboardInterrupt, SystemExit, wg.lifecycle.Interrupted):
        raise
    except Blocked as err:
        if str(err) in ("Gateway negative blocked at " + reason + "." for reason in STAGES):
            raise err from None
        raise Blocked("Gateway negative blocked at " + name + ".") from None
    except BaseException:
        raise Blocked("Gateway negative blocked at " + name + ".") from None


def send(ip, ca, bearer, public_key=TEST_KEY):
    """Direct numeric-IP TLS 1.3, CA+hostname validated; no proxy/redirect."""
    wg.ipv4(ip)
    if (not isinstance(ca, str) or len(ca) > 4096 or not PEM.fullmatch(ca) or
            not isinstance(bearer, str) or not bearer or len(bearer) > 16384 or
            any(c in bearer for c in " \t\r\n") or public_key != TEST_KEY):
        raise Blocked("Gateway negative request invalid.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=ca)
    body = json.dumps({"publicKey": public_key}, separators=(",", ":")).encode()
    request = ("POST /v1/peers HTTP/1.1\r\nHost: " + ip + ":9443\r\nAuthorization: Bearer " + bearer +
               "\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n" +
               "Content-Length: " + str(len(body)) + "\r\n\r\n").encode() + body
    try:
        raw = socket.create_connection((ip, 9443), timeout=5)
    except OSError:
        raise ConnectBlocked("Gateway negative connection unavailable.") from None
    with raw:
        raw.settimeout(8)
        try:
            sock = context.wrap_socket(raw, server_hostname=ip)
        except (ssl.SSLError, OSError):
            raise TLSBlocked("Gateway negative pinned TLS unavailable.") from None
        with sock:
            sock.settimeout(8)
            try:
                sock.sendall(request)
                # Read ONLY the status line; no response body/headers are retained.
                line = bytearray()
                while len(line) < 128:
                    c = sock.recv(1)
                    if not c or c == b"\n":
                        break
                    line.extend(c)
            except OSError:
                raise Blocked("Gateway negative HTTP response unavailable.") from None
            if not c or c != b"\n":
                raise Blocked("Gateway negative response invalid.")
            status = bytes(line).rstrip(b"\r")
            if not re.fullmatch(rb"HTTP/1\.[01] (401|403) [\x20-\x7e]{0,90}", status):
                # Never print received status text (or read headers/body).
                raise Blocked("Gateway negative authorization rejection absent.")
            return int(status.split(b" ", 2)[1])


def send_from_node(source_api, selected_uid, gateway_name, expected_image, ip, ca, bearer,
                   *, transport=None, root_transport=None):
    """Bound node-host network request with selected UID/CRI ownership checks."""
    try:
        from . import plaintext_denial
    except ImportError:
        import plaintext_denial
    if transport is None:
        transport = wg.node_images._bounded
    if root_transport is None:
        root_transport = auth.adapter._bounded
    namespace = source_api.owner.names[1]
    def pinned():
        selected = source_api.get("pod", wg.CLIENT, namespace)
        auth.validate_pod(selected, namespace, selected_uid, "default",
                          source_api.owner.token, gateway_name)
        node = selected.get("spec", {}).get("nodeName")
        wg.need(node in wg.node_images.NODES, "Selected Pod node unavailable.")
        statuses = [item for item in selected.get("status", {}).get("containerStatuses", [])
                    if item.get("name") == "client" and item.get("ready") is True and
                    item.get("imageID") == expected_image]
        wg.need(len(statuses) == 1, "Selected Pod runtime image unverified.")
        pod_ip = wg.ipv4(selected.get("status", {}).get("podIP"))
        sid = plaintext_denial.sandbox_id(plaintext_denial._node_cmd(node, ["pods", "-o", "json"], transport),
                                          selected_uid, namespace, wg.CLIENT)
        pid = plaintext_denial.sandbox_pid(
            plaintext_denial._node_cmd(node, ["inspectp", "-o", "json", sid], transport),
            sid, selected_uid, namespace, wg.CLIENT, pod_ip)
        host = plaintext_denial._host_pid(node, transport)
        return node, sid, pid, host
    before = pinned()
    # Node-host netns matches the host-network agent; the selected Pod sandbox
    # is verified for ownership only, never used as the request source.
    payload = json.dumps({"gatewayPodIP": ip, "registrationCACert": ca,
                          "token": bearer}, separators=(",", ":")).encode()
    wg.need(len(payload) <= 20500, "Gateway negative stdin payload too large.")
    path = Path(__file__).with_name("gateway_request_root.py")
    output = root_transport(["sudo", "-n", "/usr/bin/python3", str(path),
                             str(before[3])], payload=payload,
                            timeout=20, max_output=128)
    result = json.loads(output)
    wg.need(type(result) is dict and set(result) in ({"status"}, {"blocked"}),
            "Gateway negative root response malformed.")
    if "blocked" in result:
        reason = result["blocked"]
        if type(reason) is not str or reason not in {"input", "netns", "connect", "tls", "http"}:
            raise Blocked("Gateway negative root response malformed.")
        raise Blocked("Gateway negative blocked at gateway-request-" + reason + ".")
    wg.need(type(result["status"]) is int and result["status"] in (401, 403),
            "Gateway negative root rejection invalid.")
    wg.need(pinned() == before, "Selected sandbox or host node changed after gateway request.")
    return result["status"]


def peer_digest(operator, gateway_pod, image_id, *, transport=None, root=None):
    """UID/container-pinned public peer-key digest; never return raw key."""
    try:
        from . import wg_transport, plaintext_denial
    except ImportError:
        import wg_transport
        import plaintext_denial
    if transport is None:
        transport = wg.node_images._bounded
    node, cid = wg_transport._container(gateway_pod, image_id)
    def inspect():
        raw = transport(["docker", "exec", node, "/bin/crictl", "--runtime-endpoint",
                         wg_transport.RUNTIME, "inspect", "-o", "json", cid],
                        timeout=5, max_output=65536)
        return wg_transport._pid(raw, cid, gateway_pod["metadata"]["uid"])
    pid = inspect()
    if root is None:
        path = Path(__file__).with_name("gateway_peer_root.py")
        host_pid = plaintext_denial._host_pid(node, transport)
        output = plaintext_denial._bounded_root(["sudo", "-n", "/usr/bin/python3", str(path),
                                                   str(host_pid), str(pid)])
        obj = json.loads(output)
    else:
        obj = root(node, pid)
    if (type(obj) is not dict or set(obj) != {"peerDigest"} or
            type(obj["peerDigest"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", obj["peerDigest"]) or
            obj["peerDigest"] == hashlib.sha256(TEST_KEY.encode()).hexdigest()):
        raise Blocked("Gateway negative peer identity invalid.")
    if inspect() != pid or (root is None and plaintext_denial._host_pid(node, transport) != host_pid):
        raise Blocked("Gateway negative peer namespace changed.")
    current = operator.get_object("pod", gateway_pod["metadata"]["name"], wg.SYSTEM)
    if current["metadata"].get("uid") != gateway_pod["metadata"]["uid"] or \
            wg_transport._container(current, image_id) != (node, cid):
        raise Blocked("Gateway negative peer Pod changed.")
    return obj["peerDigest"]


def run(owner, source_api, operator, gateway_uid, selected_uid, gateway_pod,
        ids, marker, *, send_request=None, read_metrics=None, read_peer_digest=peer_digest):
    """Require exact owned UID, 401/403, unchanged public peer-key digest and marker."""
    if send_request is None:
        send_request = lambda ip, ca, bearer: send_from_node(
            source_api, selected_uid, operator.name, ids["selected"], ip, ca, bearer)
    if read_metrics is None:
        try:
            from . import wg_transport
        except ImportError:
            import wg_transport
        read_metrics = wg_transport.read_metrics
    stage("authorization", lambda: wg.need(
        os.environ.get("RATATOSKR_E2E_FINAL_GATE") == "1" and
        os.environ.get("RATATOSKR_E2E_WG_SYNTHETIC") == "1" and
        os.environ.get("RATATOSKR_E2E_WG_NEGATIVE") == "1" and
        operator.created.get("Pod") == selected_uid and
        operator.created.get("EgressGateway") == gateway_uid and
        owner.names[1] in owner.created and owner.owned.get(owner.names[1]) == owner.created[owner.names[1]] and
        not owner.closed and
        owner.deadline - owner.clock() > 170,
        "Owned negative fixture authorization absent."))
    namespace = owner.names[1]
    def identity():
        auth.identity(namespace, selected_uid, "default", owner.token, operator.name)
        ns = source_api._namespace(namespace)
        wg.need(ns == namespace, "Owned namespace changed.")
        pod = source_api.get("pod", wg.CLIENT, namespace)
        auth.validate_pod(pod, namespace, selected_uid, "default", owner.token, operator.name)
        gw_obj = operator.get_object("egressgateway", operator.name, wg.SYSTEM)
        wg.need(gw_obj["metadata"].get("uid") == gateway_uid and
                gw_obj["spec"].get("encryption") == "wireguard", "Owned Gateway changed.")
        ip = wg.verify_encrypted_ready(gw_obj, pod, gateway_uid, selected_uid, operator.name)
        endpoints = [e for e in gw_obj["status"]["endpoints"] if e["podIP"] == ip]
        wg.need(len(endpoints) == 1 and
                endpoints[0]["podUID"] == gateway_pod["metadata"]["uid"] and
                endpoints[0]["podName"] == gateway_pod["metadata"]["name"] and
                gateway_pod["status"].get("podIP") == ip and
                gateway_pod["metadata"].get("labels", {}).get(wg.PREFIX + "gateway-uid") == gateway_uid,
                "Pinned gateway Pod changed.")
        current = operator.get_object("pod", gateway_pod["metadata"]["name"], wg.SYSTEM)
        wg.need(current["metadata"]["uid"] == gateway_pod["metadata"]["uid"] and
                current["status"].get("podIP") == ip and
                current["metadata"].get("labels", {}).get(wg.PREFIX + "gateway-uid") == gateway_uid,
                "Pinned gateway Pod changed.")
        ca = endpoints[0]["registrationCACert"]
        wg.need(type(ca) is str and len(ca) <= 4096 and PEM.fullmatch(ca),
                "Pinned gateway CA unavailable.")
        return ip, ca
    ip, ca = stage("identity-pre", identity)
    def token():
        body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
                "spec": {"audiences": [auth.WRONG_AUDIENCE], "expirationSeconds": 600,
                         "boundObjectRef": {"kind": "Pod", "apiVersion": "v1",
                                            "name": wg.CLIENT, "uid": selected_uid}}}
        path = "/api/v1/namespaces/" + namespace + "/serviceaccounts/default/token"
        obj = auth._call(["create", "--raw", path, "-f", "-"],
                         payload=json.dumps(body, separators=(",", ":")).encode(), max_output=16384)
        wg.need(obj.get("kind") == "TokenRequest" and type(obj.get("status", {}).get("token")) is str and
                0 < len(obj["status"]["token"]) <= 16384 and
                not any(c in obj["status"]["token"] for c in " \t\r\n") and
                type(obj["status"].get("expirationTimestamp")) is str,
                "Wrong-audience Pod-bound token unavailable.")
        spec = obj.get("spec")
        if spec is not None:
            wg.need(spec.get("audiences") == [auth.WRONG_AUDIENCE] and
                    spec.get("boundObjectRef") == body["spec"]["boundObjectRef"],
                    "Wrong-audience token echo changed.")
        return obj["status"]["token"]
    bearer = stage("token-request", token)
    def baseline():
        sample = read_metrics(operator, gateway_pod, ids["gateway"])
        wg.need(sample["sample_ok"] == 1 and sample["installed_peers"] == 1 and
                sample["handshaken_peers"] == 1,
                "Gateway kernel peer baseline unavailable.")
        return read_peer_digest(operator, gateway_pod, ids["gateway"])
    original_digest = stage("peer-before", baseline)
    def request():
        status = send_request(ip, ca, bearer)
        wg.need(type(status) is int and status in (401, 403),
                "Gateway did not reject wrong audience.")
    stage("gateway-request", request)
    stage("identity-post", lambda: wg.need(identity() == (ip, ca),
                                           "Gateway negative identity changed."))
    def after():
        sample = read_metrics(operator, gateway_pod, ids["gateway"])
        wg.need(sample["sample_ok"] == 1 and sample["installed_peers"] == 1 and
                sample["handshaken_peers"] == 1 and
                read_peer_digest(operator, gateway_pod, ids["gateway"]) == original_digest,
                "Gateway kernel peer set changed.")
    stage("peer-after", after)
    stage("marker-after", lambda: wg.need(
        source_api.probe_running(wg.CLIENT, selected_uid, ids["selected"], "healthy", marker) is True,
        "Authenticated selected marker not delivered after gateway rejection."))
    return {"wrongAudienceGatewayRejected": True, "gatewayTokenReviewCallObserved": False}
