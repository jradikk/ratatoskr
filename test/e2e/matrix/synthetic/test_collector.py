#!/usr/bin/env python3
"""Fake-only collector tests. No Kubernetes, OpenSSL, Docker or credentials."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_collector", HERE / "collector.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
UID = "c" * 32
EXPECTED = "containerd://sha256:" + "d" * 64
IDS = {name: EXPECTED for name in ("controller", "webhook", "agent", "gateway", "plugin", "server", "tools")}
LINK = {"ifname": "rtk0", "ifindex": 5, "operstate": "UP", "linkinfo": {
    "info_kind": "geneve", "info_data": {"id": 7, "remote": "10.42.1.7"}}}
MARKER = {"ifname": "rtk-ready", "flags": ["UP"], "linkinfo": {"info_kind": "dummy"}}


def payload(obj):
    return json.dumps([obj])


class FakeClient(mod.adapter.FixtureAPI):
    def __init__(self, owner):
        self.owner = owner
        self.commands = []
        self.outputs = {}

    def exec(self, namespace, pod, uid, container, command, *, expected_image_id):
        assert namespace == self.owner.names[1]
        assert (pod, uid, container, expected_image_id) == ("synthetic-client", UID, "client", EXPECTED)
        self.commands.append(command)
        value = self.outputs[command]
        if isinstance(value, list):
            return value.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def fixture():
    owner = mod.lifecycle.Lifecycle(api=object(), token_factory=lambda: "a" * 32)
    owner.deadline = owner.clock() + 180
    owner.owned = {name: "b" * 32 for name in owner.names}
    api = FakeClient(owner)
    return mod.Collector(owner, api, IDS), api


class CollectorTests(unittest.TestCase):
    def test_rejects_missing_lifecycle_owner_or_image_expectation(self):
        collector, api = fixture()
        with self.assertRaises(mod.Incomplete):
            mod.Collector(collector.owner, mod.adapter.FixtureAPI.__new__(mod.adapter.FixtureAPI), IDS)
        owner = collector.owner
        invalid = dict(IDS, tools="latest")
        with self.assertRaises(mod.Incomplete):
            mod.Collector(owner, api, invalid)
        owner.closed = True
        with self.assertRaises(mod.Incomplete):
            mod.Collector(owner, api, IDS)

    def test_strict_iproute2_json_shape_and_selected_marker_bytes(self):
        collector, api = fixture()
        api.outputs = {
            "geneve-link": payload(LINK),
            "geneve-bytes": [payload({"ifname": "rtk0", "stats64": {"tx": {"bytes": n}}})
                             for n in (100, 100, 220)],
            "vpn-marker": mod.evidence.MARKER,
            "vpn-exit": mod.evidence.EXIT,
        }
        self.assertEqual(collector.selected_traffic(UID, 7, "10.42.1.7"), 120)
        self.assertEqual(api.commands.count("geneve-bytes"), 3)
        self.assertEqual(api.commands.count("vpn-marker"), 1)
        self.assertEqual(collector.final_result.__name__, "final_result")
        with self.assertRaisesRegex(mod.Incomplete, "cannot certify PASS"):
            collector.final_result()

    def test_gateway_ready_status_poll_and_wrong_namespace_denied(self):
        collector, api = fixture()
        class GatewayAPI(FakeClient):
            def __init__(self, owner):
                super().__init__(owner)
                self.responses = []
            def get(self, kind, name, namespace):
                assert (kind, name, namespace) == ("egressgateway", "synthetic", self.owner.names[0])
                return self.responses.pop(0)
        read = GatewayAPI(collector.owner)
        collector.api = read
        gw = {"metadata": {"name": "synthetic", "namespace": collector.owner.names[0],
                           "uid": UID, "generation": 2},
              "status": {"observedGeneration": 2, "conditions": [{"type": "Ready", "status": "True",
                                                                "observedGeneration": 2}]}}
        stale = json.loads(json.dumps(gw))
        stale["status"]["observedGeneration"] = 1
        read.responses = [stale, gw]
        self.assertEqual(collector.gateway_status(budget=2), gw)
        with self.assertRaises(mod.Incomplete):
            collector.assert_gateway_graph(dict(gw, metadata=dict(gw["metadata"], namespace="other")),
                                           {}, {}, {}, [])

    def test_counter_background_traffic_wrong_link_or_false_marker_denied(self):
        for before, baseline, after in ((100, 101, 120), (100, 100, 100), (100, 100, 90)):
            collector, api = fixture()
            api.outputs = {"geneve-link": payload(LINK),
                           "geneve-bytes": [payload({"ifname": "rtk0", "stats64": {"tx": {"bytes": n}}})
                                            for n in (before, baseline, after)],
                           "vpn-marker": mod.evidence.MARKER,
                           "vpn-exit": mod.evidence.EXIT}
            with self.assertRaises((mod.Incomplete, mod.evidence.EvidenceError)):
                collector.selected_traffic(UID, 7, "10.42.1.7")
        collector, api = fixture()
        api.outputs = {"geneve-link": payload(dict(LINK, ifname="eth0"))}
        with self.assertRaises(mod.evidence.EvidenceError):
            collector.selected_traffic(UID, 7, "10.42.1.7")
        collector, api = fixture()
        api.outputs = {"geneve-link": payload(LINK),
                       "geneve-bytes": [payload({"ifname": "rtk0", "stats64": {"tx": {"bytes": n}}})
                                        for n in (100, 100, 200)], "vpn-marker": "spoof"}
        with self.assertRaises(mod.evidence.EvidenceError):
            collector.selected_traffic(UID, 7, "10.42.1.7")

    def test_dns_exact_api_cluster_ip_and_verified_exclusion_only(self):
        collector, api = fixture()
        api.outputs = {"direct-dns": "10.43.0.1 STREAM kubernetes.default.svc.cluster.local\n" * 3}
        self.assertEqual(collector.direct_dns(UID, "10.43.0.1", [{"source": "serviceCIDR", "cidr": "10.43.0.0/16"}]),
                         "kubernetes.default.svc.cluster.local")
        for text in ("10.43.0.2 STREAM kubernetes.default.svc.cluster.local\n",
                     "SECRET invalid", "10.43.0.1 STREAM test\n10.43.0.2 STREAM test\n"):
            api.outputs = {"direct-dns": text}
            with self.assertRaises((mod.Incomplete, mod.evidence.EvidenceError)) as ctx:
                collector.direct_dns(UID, "10.43.0.1", [{"source": "serviceCIDR", "cidr": "10.43.0.0/16"}])
            self.assertNotIn("SECRET", str(ctx.exception))
        api.outputs = {"direct-dns": "10.43.0.1 STREAM kubernetes.default.svc.cluster.local\n"}
        with self.assertRaises(mod.evidence.EvidenceError):
            collector.direct_dns(UID, "10.43.0.1", [])

    def test_poll_convergence_strict_budget_and_timeout(self):
        collector, api = fixture()
        now = [0.0]
        collector.clock = lambda: now[0]
        collector.owner.deadline = 10
        collector.sleep = lambda value: now.__setitem__(0, now[0] + value)
        tries = [None, None, "ready"]
        self.assertEqual(collector.poll(lambda: tries.pop(0), budget=3), "ready")
        with self.assertRaisesRegex(mod.Incomplete, "did not converge"):
            collector.poll(lambda: None, budget=2)
        with self.assertRaises(mod.Incomplete):
            collector.poll(lambda: True, budget=100)

    def test_strict_link_counter_parse_rejects_unknown_or_oversized(self):
        for raw in ("[]", "{}", "not-json", "x" * 4097, payload({"ifname": "rtk0"}),
                    payload({"ifname": "eth0", "stats64": {"tx": {"bytes": 7}}}),
                    payload({"ifname": "rtk0", "stats64": {"tx": {"bytes": "7"}}})):
            with self.assertRaises(mod.Incomplete):
                mod._tx_bytes(raw)


if __name__ == "__main__":
    unittest.main()
