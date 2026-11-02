"""Offline malicious-identity/status/TLS/peer checks; never touches a cluster."""
import hashlib
import json
import os
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import gateway_negative as neg
import wg_fixture as wg

OWNER = "a" * 32
UID = "b" * 32
GW_UID = "c" * 32
GW_POD_UID = "d" * 32
NAME = "rtk-wg-" + OWNER[:16]
NS = "rtk-syn-" + OWNER[:16] + "-apps"
CA = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
SECRET = "secret-bearer-token"
GATES = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_WG_SYNTHETIC": "1",
         "RATATOSKR_E2E_WG_NEGATIVE": "1"}


def selected(uid=UID):
    return {"kind": "Pod", "metadata": {"namespace": NS, "name": wg.CLIENT, "uid": uid,
            "labels": {wg.OWN: OWNER, wg.PREFIX + "gateway": NAME,
                       wg.PREFIX + "gateway-namespace": wg.SYSTEM}},
            "spec": {"serviceAccountName": "default"}, "status": {"podIP": "10.42.1.8"}}


def gateway(uid=GW_UID, pod_uid=GW_POD_UID):
    return {"metadata": {"name": NAME, "namespace": wg.SYSTEM, "uid": uid},
            "spec": {"encryption": "wireguard"},
            "status": {"endpoints": [{"podIP": "10.42.0.7", "podUID": pod_uid,
                                      "podName": "rtk-wg-gateway", "registrationCACert": CA}]}}


def gateway_pod(uid=GW_POD_UID):
    return {"metadata": {"name": "rtk-wg-gateway", "uid": uid,
                         "labels": {wg.PREFIX + "gateway-uid": GW_UID}},
            "status": {"podIP": "10.42.0.7"}}


class Owner:
    token = OWNER
    names = (NS.removesuffix("-apps"), NS)
    owned = {NS: "e" * 32}
    created = {NS: "e" * 32}
    deadline = 500
    closed = False
    def clock(self): return 0


class Source:
    def __init__(self):
        self.pod = selected()
        self.probed = False
    def _namespace(self, ns):
        assert ns == NS
        return ns
    def get(self, kind, name, ns):
        assert (kind, name, ns) == ("pod", wg.CLIENT, NS)
        return self.pod
    def probe_running(self, name, uid, image, phase, marker):
        self.probed = True
        return uid == UID and marker == "healthy-marker"


class Operator:
    name = NAME
    created = {"Pod": UID, "EgressGateway": GW_UID}
    def __init__(self): self.gw = gateway(); self.pod = gateway_pod()
    def get_object(self, kind, name, namespace):
        assert namespace == wg.SYSTEM
        return self.gw if kind == "egressgateway" else self.pod


class NegativeTest(unittest.TestCase):
    def invoke(self, source=None, operator=None, **changes):
        source = source or Source(); operator = operator or Operator()
        calls = []
        def fake_call(argv, *, payload, max_output):
            calls.append((argv, payload, max_output))
            return {"kind": "TokenRequest", "status": {"token": SECRET,
                    "expirationTimestamp": "2030-01-01T00:00:00Z"}}
        status = changes.pop("status", 401)
        send = changes.pop("send", lambda ip, ca, token: status)
        metrics = changes.pop("metrics", lambda *_: {"sample_ok": 1, "installed_peers": 1,
                                                      "handshaken_peers": 1})
        digest = changes.pop("digest", lambda *_: hashlib.sha256(b"peer").hexdigest())
        with patch.dict(os.environ, GATES, clear=True), \
                patch.object(neg.wg, "verify_encrypted_ready", return_value="10.42.0.7"), \
                patch.object(neg.auth, "_call", side_effect=fake_call):
            result = neg.run(Owner(), source, operator, GW_UID, UID, gateway_pod(),
                             {"gateway": "image", "selected": "image"}, "healthy-marker",
                             send_request=send, read_metrics=metrics, read_peer_digest=digest, **changes)
        return result, calls, source

    def test_actual_gateway_rejection_uses_wrong_audience_bound_token(self):
        seen = []
        result, calls, source = self.invoke(send=lambda ip, ca, token:
                                           seen.append((ip, ca, token)) or 401)
        self.assertEqual(result, {"wrongAudienceGatewayRejected": True,
                                  "gatewayTokenReviewCallObserved": False})
        self.assertTrue(source.probed)
        self.assertEqual(seen, [("10.42.0.7", CA, SECRET)])
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(SECRET not in str(argv) for argv, _, _ in calls))
        self.assertEqual(calls[0][2], 16384)
        body = json.loads(calls[0][1])
        self.assertEqual(body["spec"]["audiences"], [neg.auth.WRONG_AUDIENCE])
        self.assertEqual(body["spec"]["boundObjectRef"]["uid"], UID)
        self.assertEqual(body["spec"]["expirationSeconds"], 600)

    def test_gate_owner_and_replacement_block_before_or_after_request(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(neg.Blocked) as caught:
                neg.run(Owner(), Source(), Operator(), GW_UID, UID, gateway_pod(),
                        {"gateway": "image", "selected": "image"}, "healthy-marker",
                        send_request=lambda *_: self.fail("no network"))
        self.assertIn("authorization", str(caught.exception))
        replacement = Source(); replacement.pod = selected("f" * 32)
        with self.assertRaisesRegex(neg.Blocked, "identity-pre"):
            self.invoke(source=replacement, send=lambda *_: self.fail("no network"))
        for which in ("gateway", "pod"):
            op = Operator()
            if which == "gateway": op.gw = gateway(uid="f" * 32)
            else: op.pod = gateway_pod("f" * 32)
            with self.assertRaisesRegex(neg.Blocked, "identity-pre"):
                self.invoke(operator=op, send=lambda *_: self.fail("no network"))
        current = Source()
        def replace(_ip, _ca, _bearer):
            current.pod = selected("f" * 32)
            return 401
        with self.assertRaisesRegex(neg.Blocked, "identity-post"):
            self.invoke(source=current, send=replace)

    def test_bad_status_tls_peer_change_and_secret_error_have_fixed_stages(self):
        for code in (201, 204, 302, 400, 409, 500):
            with self.subTest(code=code), self.assertRaisesRegex(neg.Blocked, "gateway-request"):
                self.invoke(status=code)
        with self.assertRaisesRegex(neg.Blocked, "gateway-request") as caught:
            self.invoke(send=lambda *_: (_ for _ in ()).throw(RuntimeError(SECRET)))
        self.assertNotIn(SECRET, str(caught.exception))
        seen = []
        def changed(*_):
            seen.append(1)
            return {"sample_ok": 1, "installed_peers": 1 if len(seen) == 1 else 2,
                    "handshaken_peers": 1}
        with self.assertRaisesRegex(neg.Blocked, "peer-after"):
            self.invoke(metrics=changed)
        fingerprints = iter(["f" * 64, "e" * 64])
        with self.assertRaisesRegex(neg.Blocked, "peer-after"):
            self.invoke(digest=lambda *_: next(fingerprints))
        # No fallback if TLS CA verification fails or a redirect is returned.
        with self.assertRaisesRegex(neg.Blocked, "gateway-request") as caught:
            self.invoke(send=lambda *_: (_ for _ in ()).throw(ssl.SSLError(SECRET)))
        self.assertNotIn(SECRET, str(caught.exception))



if __name__ == "__main__":
    unittest.main()
