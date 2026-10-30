#!/usr/bin/env python3
"""Cluster/PKI-free partial Gateway smoke tests; never call a real API."""
from contextlib import redirect_stdout
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_partial_gateway", HERE / "partial_gateway.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
UID = "b" * 32
IMAGE = "containerd://sha256:" + "c" * 64
IDS = {k: IMAGE for k in smoke.run.COMPONENTS}


class FakeOwner:
    def __init__(self):
        self.names = ("rtk-syn-" + "a" * 16, "rtk-syn-" + "a" * 16 + "-apps")
        self.token = "a" * 32
        self.private_dir = None
        self.deadline = 10_000_000
        self.closed = False
        self.fail_cleanup = False
        self.created_namespaces = False
        self.generated_pki = False
        self.cleanup_attempted = False
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        self.cleanup_attempted = True
        self.closed = True
        if self.fail_cleanup:
            raise smoke.lifecycle.LifecycleError("test-only cleanup failure")
        return False
    def create_namespaces(self):
        self.created_namespaces = True
    def generate_pki(self):
        self.generated_pki = True


class FakeAdapter:
    def __init__(self, owner):
        self.owner = owner
        self.created = []
        self.fail_at = None
    def create(self, obj):
        kind, meta = obj["kind"], obj["metadata"]
        if len(self.created) == self.fail_at:
            raise smoke.adapter.AdapterError("ambiguous test-only CREATE")
        identity = {"kind": kind, "namespace": meta["namespace"],
                    "name": meta["name"], "uid": UID}
        self.created.append(identity)
        return identity


def fixture(owner):
    objects = smoke.prepare.manifests(owner.names[0], "ratatoskr-synthetic-openvpn:local",
               ("CA", "SERVER", "SERVER_KEY", "CLIENT", "CLIENT_KEY", "WITNESS", "WITNESS_KEY"), owner.token)
    return objects


class SmokeTests(unittest.TestCase):
    def setUp(self):
        self.owner = FakeOwner()
        self.adapter = FakeAdapter(self.owner)

    def execute(self, observer=None, selected_observer=None):
        baseline = {"gatewayUID": UID, "serverUID": UID, "gatewayPodUID": UID,
                    "gatewayID": 7, "endpoint": "10.42.1.7",
                    "session": {"cn": "synthetic-client", "received": 100, "sent": 200}}
        result = {"podUID": UID, "healthyExit": True, "directAPITLSAndDNS": True,
                  "serverSessionBytesAdvanced": True}
        with patch.object(smoke, "private_contents", return_value=("x",) * 7):
            return smoke.execute(IDS, lifecycle_factory=lambda: self.owner,
                                 adapter_factory=lambda _owner: self.adapter,
                                 observer=(lambda *_a: baseline) if observer is None else observer,
                                 selected_observer=(lambda *_a: result) if selected_observer is None else selected_observer,
                                 api_ip="10.43.0.1")

    def test_base_eight_only_no_selected_or_witness_pod_and_cleanup(self):
        self.assertIs(self.execute(), False)
        self.assertTrue(self.owner.created_namespaces and self.owner.generated_pki)
        self.assertTrue(self.owner.cleanup_attempted and self.owner.closed)
        self.assertEqual([(x["kind"], x["name"]) for x in self.adapter.created], list(smoke.BASE))
        self.assertNotIn(("Pod", "synthetic-witness"), list(smoke.BASE))
        self.assertNotIn(("Pod", "synthetic-probe-outage"), list(smoke.BASE))

    def test_ambiguous_create_and_observation_timeout_still_cleanup(self):
        self.adapter.fail_at = 2  # Secret create ambiguity
        with self.assertRaises(smoke.adapter.AdapterError):
            self.execute()
        self.assertTrue(self.owner.cleanup_attempted)
        self.assertEqual(len(self.adapter.created), 2)
        self.owner = FakeOwner()
        self.adapter = FakeAdapter(self.owner)
        with self.assertRaises(smoke.Blocked):
            self.execute(observer=lambda *_a: False)
        self.assertTrue(self.owner.cleanup_attempted)

    def test_cleanup_failure_overrides_success(self):
        self.owner.fail_cleanup = True
        with self.assertRaises(smoke.lifecycle.LifecycleError):
            self.execute()
        self.assertTrue(self.owner.cleanup_attempted)

    def test_wrong_expected_ids_block_before_namespace_or_pki(self):
        for mismatch in ({**IDS, "server": "latest"}, {"server": IMAGE}):
            with self.subTest(mismatch=mismatch), self.assertRaises(smoke.Blocked):
                smoke.execute(mismatch, lifecycle_factory=lambda: self.owner,
                              observer=lambda *_a: self.fail("observer must not run"))
            self.assertFalse(self.owner.created_namespaces)

    def test_realistic_owner_chain_measured_mtu_and_sanitized_session(self):
        import copy
        import test_evidence
        fields = test_evidence.fixture()
        gateway, deployment, rs, gateway_pod, children = copy.deepcopy(fields)
        ns = self.owner.names[0]
        gateway["metadata"]["namespace"] = ns
        gateway["metadata"]["uid"] = UID
        for child in [deployment, *children]:
            child["metadata"]["namespace"] = ns
            child["metadata"]["ownerReferences"][0]["uid"] = UID
        rs["metadata"]["namespace"] = ns
        gateway_pod["metadata"]["namespace"] = ns
        gateway_pod["metadata"]["uid"] = "d" * 32
        gateway_pod["metadata"]["labels"] = {
            "ratatoskr.skaldhall.io/gateway-name": "synthetic",
            "ratatoskr.skaldhall.io/gateway-uid": UID}
        for status in gateway_pod["status"]["containerStatuses"]:
            status["imageID"] = IMAGE
        for entry in gateway_pod["spec"]["containers"]:
            entry["imagePullPolicy"] = "Never"
        server = {"kind": "Pod", "metadata": {"name": "synthetic-vpn", "namespace": ns,
                            "uid": "e" * 32, "labels": {"app": "synthetic-vpn"}},
                  "spec": {"containers": [{"name": "server", "imagePullPolicy": "Never"}]},
                  "status": {"podIP": "10.42.2.9", "conditions": [test_evidence.cond()],
                             "containerStatuses": [{"name": "server", "imageID": IMAGE, "ready": True}]}}
        source = {"kind": "Service", "metadata": {"name": "synthetic-vpn", "namespace": ns},
                  "spec": {"selector": {"app": "synthetic-vpn"}, "clusterIP": "10.43.0.44",
                           "ports": [{"protocol": "UDP", "port": 1194, "targetPort": 1194}]}}
        slice_obj = {"kind": "EndpointSlice", "addressType": "IPv4", "metadata": {
            "namespace": ns, "labels": {"kubernetes.io/service-name": "synthetic-vpn"}},
            "ports": [{"protocol": "UDP", "port": 1194}],
            "endpoints": [{"conditions": {"ready": True}, "targetRef": {
                "kind": "Pod", "name": "synthetic-vpn", "uid": "e" * 32},
                "addresses": ["10.42.2.9"]}]}
        objects = {
            ("egressgateway", "synthetic"): gateway,
            ("deployment", "synthetic"): deployment,
            ("replicaset", "rs"): rs,
            ("pod", "synthetic-vpn"): server,
            ("service", "synthetic-vpn"): source,
            **{(kind.lower(), "synthetic"): child
               for kind, child in zip(("Service", "ConfigMap", "NetworkPolicy"), children)},
        }
        rs["metadata"]["uid"] = gateway_pod["metadata"]["ownerReferences"][0]["uid"]
        gateway_pod["metadata"]["ownerReferences"][0]["name"] = "rs"
        gateway["status"]["endpoints"][0]["podIP"] = gateway_pod["status"]["podIP"]
        class Snapshot:
            def get(self, kind, name, _namespace):
                return objects[(kind, name)]
            def list_owned_gateway_pods(self, _namespace, _uid):
                return gateway_pod
            def source_endpoint(self, _namespace, _service, _server):
                return slice_obj
            def server_session(self, _namespace, _uid, *, expected_image_id):
                return {"sessions": [{"cn": "synthetic-client", "cipher": "AES-256-GCM",
                                      "received": 321, "sent": 123}]}
        api = Snapshot()
        created = {("Pod", ns, "synthetic-vpn"): server["metadata"]["uid"],
                   ("EgressGateway", ns, "synthetic"): UID}
        now = [0]
        def clock():
            now[0] += 56
            return now[0]
        self.owner.deadline = 1000
        self.owner.clock = lambda: 0
        smoke.source_ready(server, source, IMAGE)
        smoke.gateway_ready(api, UID, ns, IDS)
        smoke.evidence.assert_source_endpoint(api.source_endpoint(ns, source, server), source, server)
        assert api.server_session(ns, server["metadata"]["uid"], expected_image_id=IMAGE)["sessions"][0]["received"] > 0
        self.assertEqual(smoke.observe(api, self.owner, IDS, created,
                                      clock=clock, sleep=lambda _seconds: None)["gatewayUID"], UID)
        gateway_pod["status"]["containerStatuses"][1]["imageID"] = "sha256:" + "f" * 64
        now = [0]
        def clock():
            now[0] += 56
            return now[0]
        self.owner.deadline = 1000
        with self.assertRaises(smoke.Blocked):
            smoke.observe(api, self.owner, IDS, created, clock=clock, sleep=lambda _seconds: None)

    def test_bounded_poll_timeout_without_sleeping_and_no_success(self):
        class Missing:
            def get(self, *_args):
                raise smoke.adapter.AdapterError("unavailable")
        now = [0]
        def clock():
            now[0] += 23
            return now[0]
        self.owner.clock = lambda: 0
        self.owner.deadline = 1_000
        created = {("Pod", self.owner.names[0], "synthetic-vpn"): "e" * 32,
                   ("EgressGateway", self.owner.names[0], "synthetic"): UID}
        with self.assertRaisesRegex(smoke.Blocked, "timed out at non-secret checkpoint source-pod"):
            smoke.observe(Missing(), self.owner, IDS, created, clock=clock, sleep=lambda _sec: None)
        self.assertLess(now[0], 140)

    def test_fake_source_service_and_endpoint_uid_mismatch_rejected(self):
        import test_evidence
        service = {"kind": "Service", "metadata": {"name": "synthetic-vpn", "namespace": self.owner.names[0]},
                   "spec": {"selector": {"app": "synthetic-vpn"}, "clusterIP": "10.43.0.44",
                            "ports": [{"protocol": "UDP", "port": 1194, "targetPort": 1194}]}}
        pod = {"kind": "Pod", "metadata": {"name": "synthetic-vpn", "namespace": self.owner.names[0],
                       "uid": "e" * 32, "labels": {"app": "synthetic-vpn"}},
               "spec": {"containers": [{"name": "server", "imagePullPolicy": "Never"}]},
               "status": {"conditions": [test_evidence.cond()],
                          "containerStatuses": [{"name": "server", "ready": True, "imageID": IMAGE}]}}
        self.assertIs(smoke.source_ready(pod, service, IMAGE), pod)
        with self.assertRaises(smoke.evidence.EvidenceError):
            smoke.source_ready(pod, service, "sha256:" + "a" * 64)

    def test_status_poll_fails_closed_on_runtime_or_gateway_owner_mismatch(self):
        class FakeAPI:
            def __init__(self, ns):
                self.ns = ns
            def get(self, kind, name, ns):
                if kind == "egressgateway":
                    return {"metadata": {"name": name, "namespace": ns, "uid": "wrong", "generation": 1},
                            "status": {"conditions": [{"type": "Ready", "status": "True", "observedGeneration": 1}]}}
                return {}
        with self.assertRaises(smoke.Blocked):
            smoke.gateway_ready(FakeAPI(self.owner.names[0]), UID, self.owner.names[0], IDS)


if __name__ == "__main__":
    unittest.main()
