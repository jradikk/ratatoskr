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


STAGES = frozenset({"authorization", "identity-pre", "token-request", "peer-before",
                    "gateway-request", "identity-post", "peer-after", "marker-after"})


def stage(name, action):
    if name not in STAGES:
        raise Blocked("Gateway negative checkpoint invalid.")
    try:
        return action()
    except (KeyboardInterrupt, SystemExit, wg.lifecycle.Interrupted):
        raise
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
    with socket.create_connection((ip, 9443), timeout=5) as raw:
        raw.settimeout(8)
        with context.wrap_socket(raw, server_hostname=ip) as sock:
            sock.settimeout(8)
            sock.sendall(request)
            # Read ONLY the status line; no response body/headers are retained.
            line = bytearray()
            while len(line) < 128:
                c = sock.recv(1)
                if not c or c == b"\n":
                    break
                line.extend(c)
            if not c or c != b"\n":
                raise Blocked("Gateway negative response invalid.")
            status = bytes(line).rstrip(b"\r")
            if not re.fullmatch(rb"HTTP/1\.[01] (401|403) [\x20-\x7e]{0,90}", status):
                # Never print received status text (or read headers/body).
                raise Blocked("Gateway negative authorization rejection absent.")
            return int(status.split(b" ", 2)[1])


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
        ids, marker, *, send_request=send, read_metrics=None, read_peer_digest=peer_digest):
    """Require exact owned UID, 401/403, unchanged public peer-key digest and marker."""
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
    stage("gateway-request", lambda: wg.need(send_request(ip, ca, bearer) in (401, 403),
                                            "Gateway did not reject wrong audience."))
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
