"""Hermetic checks for the independent Kubernetes TokenReview diagnostic."""
import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import tokenreview as t

OWNER = "a" * 32
NS = "rtk-syn-" + OWNER[:16] + "-apps"
UID = "b" * 32
GATEWAY = "rtk-wg-" + OWNER[:16]
SA = "default"
BEARER = "secret-only-in-stdin"
GATES = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_WG_SYNTHETIC": "1",
         "RATATOSKR_E2E_TOKENREVIEW": "1"}


def namespace(uid="c" * 32):
    return {"kind": "Namespace", "metadata": {"name": NS, "uid": uid,
            "labels": {t.LABEL: OWNER}}}


def pod(uid=UID):
    return {"kind": "Pod", "metadata": {"namespace": NS, "name": t.POD, "uid": uid,
            "labels": {t.LABEL: OWNER, "ratatoskr.skaldhall.io/gateway": GATEWAY,
                       "ratatoskr.skaldhall.io/gateway-namespace": "ratatoskr-system"}},
            "spec": {"serviceAccountName": SA}}


def request():
    return {"kind": "TokenRequest", "status": {"token": BEARER,
            "expirationTimestamp": "2030-01-01T00:00:00Z"}}


def positive():
    return {"kind": "TokenReview", "status": {"authenticated": True,
            "audiences": [t.AUDIENCE], "user": {
                "username": "system:serviceaccount:" + NS + ":" + SA,
                "extra": {"authentication.kubernetes.io/pod-name": [t.POD],
                          "authentication.kubernetes.io/pod-uid": [UID]}}}}


def negative():
    return {"kind": "TokenReview", "status": {"authenticated": False}}


class TokenReviewTest(unittest.TestCase):
    def test_default_does_not_touch_cluster(self):
        with patch.object(t, "execute", side_effect=AssertionError("cluster call")):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), patch.dict(os.environ, GATES, clear=True):
                self.assertEqual(t.main([]), 2)
            self.assertIn("SKIPPED", stdout.getvalue())
        for key in GATES:
            with patch.dict(os.environ, {k: v for k, v in GATES.items() if k != key}, clear=True):
                with patch.object(t, "execute", side_effect=AssertionError("cluster call")):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(t.main(["--execute"]), 2)

    def test_identity_and_pure_validators_reject_replacement_and_invalid_review(self):
        t.identity(NS, UID, SA, OWNER, GATEWAY)
        t.validate_pod(pod(), NS, UID, SA, OWNER, GATEWAY)
        t.validate_namespace(namespace(), NS, OWNER)
        self.assertEqual(t.validate_request(request(), NS, UID, SA), BEARER)
        t.validate_review(positive(), NS, UID, SA, positive=True)
        t.validate_review(negative(), NS, UID, SA, positive=False)
        for inputs in [(NS.removesuffix("-apps"), UID, SA, OWNER, GATEWAY),
                       (NS, UID, SA, "f" * 32, GATEWAY),
                       (NS, UID, SA, OWNER, "arbitrary-gateway"),
                       (NS, UID, "release-controller", OWNER, GATEWAY + "/bad")]:
            with self.assertRaises(t.Blocked):
                t.identity(*inputs)
        for obj in (pod("d" * 32), {**pod(), "spec": {"serviceAccountName": "other"}}):
            with self.assertRaises(t.Blocked):
                t.validate_pod(obj, NS, UID, SA, OWNER, GATEWAY)
        bad = positive()
        bad["status"]["user"]["extra"]["authentication.kubernetes.io/pod-uid"] = ["other"]
        with self.assertRaises(t.Blocked):
            t.validate_review(bad, NS, UID, SA, positive=True)
        for bad in (positive(), {"kind": "TokenReview", "status": {"authenticated": True,
                                                                       "audiences": []}}):
            with self.assertRaises(t.Blocked):
                t.validate_review(bad, NS, UID, SA, positive=False)

    def test_request_optional_spec_but_wrong_echo_rejected(self):
        response = request()
        response["spec"] = {"audiences": [t.AUDIENCE], "boundObjectRef": {
            "kind": "Pod", "apiVersion": "v1", "name": t.POD, "uid": UID}}
        self.assertEqual(t.validate_request(response, NS, UID, SA), BEARER)
        response["spec"]["boundObjectRef"]["uid"] = "wrong"
        with self.assertRaises(t.Blocked):
            t.validate_request(response, NS, UID, SA)

    def test_transport_stdin_only_and_rechecks_namespace_and_pod(self):
        responses = [namespace(), pod(), request(), positive(), negative(), namespace(), pod()]
        calls = []
        def fake_transport(argv, *, payload, timeout, max_output):
            calls.append((argv, payload, timeout, max_output))
            return json.dumps(responses.pop(0)).encode()
        with patch.dict(os.environ, GATES, clear=True):
            result = t.execute(NS, UID, SA, OWNER, GATEWAY, transport=fake_transport)
        self.assertFalse(result["gatewayTokenReviewObserved"])
        self.assertEqual(len(calls), 7)
        self.assertFalse(responses)
        self.assertTrue(all("secret-only-in-stdin" not in " ".join(argv) for argv, *_ in calls))
        self.assertEqual(calls[2][0][-4:], ["--raw", "/api/v1/namespaces/" + NS +
                                                    "/serviceaccounts/default/token", "-f", "-"])
        body = json.loads(calls[2][1])
        self.assertEqual(body["spec"]["expirationSeconds"], 600)
        self.assertEqual(body["spec"]["boundObjectRef"]["uid"], UID)
        self.assertEqual([json.loads(c[1])["spec"]["audiences"] for c in calls[3:5]],
                         [[t.AUDIENCE], [t.WRONG_AUDIENCE]])
        self.assertEqual([json.loads(c[1])["spec"]["token"] for c in calls[3:5]],
                         [BEARER, BEARER])

    def test_changed_pod_or_negative_authenticated_blocks_without_secret_output(self):
        for altered_index, altered in ((6, pod("d" * 32)), (4, positive())):
            responses = [namespace(), pod(), request(), positive(), negative(), namespace(), pod()]
            responses[altered_index] = altered
            def fake_transport(_argv, *, payload, timeout, max_output):
                return json.dumps(responses.pop(0)).encode()
            with patch.dict(os.environ, GATES, clear=True):
                with self.assertRaises(t.Blocked) as raised:
                    t.execute(NS, UID, SA, OWNER, GATEWAY, transport=fake_transport)
                self.assertNotIn(BEARER, str(raised.exception))
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(t.Blocked):
                t.execute(NS, UID, SA, OWNER, GATEWAY,
                          transport=lambda *_a, **_kw: self.fail("cluster called"))


if __name__ == "__main__":
    unittest.main()
