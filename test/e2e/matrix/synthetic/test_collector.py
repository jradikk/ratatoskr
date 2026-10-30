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

    def test_server_authenticated_session_bytes_independent_of_geneve(self):
        collector, api = fixture()
        original = {"cn": "synthetic-client", "virtualIPv4": "10.88.0.2", "received": 100,
                    "sent": 200, "connected": 42, "peer": 7, "cipher": "AES-256-GCM"}
        class ServerAPI(FakeClient):
            def server_session(self, namespace, uid, *, expected_image_id):
                assert namespace == self.owner.names[0] and uid == "e" * 32
                assert expected_image_id == EXPECTED
                value = self.sessions.pop(0)
                return {"sessions": value if isinstance(value, list) else [value]}
        server_api = ServerAPI(collector.owner)
        collector.api = server_api
        def configure(sessions):
            server_api.sessions = list(sessions)
            server_api.outputs = {
                "geneve-link": payload(LINK),
                "geneve-bytes": [payload({"ifname": "rtk0", "stats64": {"tx": {"bytes": n}}}) for n in (100, 100, 220)],
                "vpn-marker": mod.evidence.MARKER,
            }
        later = dict(original, received=320, sent=410)
        configure([original, dict(original), later])
        self.assertEqual(collector.session_traffic("e" * 32, UID, 7, "10.42.1.7"),
                         {"geneveBytesIncreased": True, "authenticatedSessionBytesIncreased": True})
        for invalid in (dict(original, received=100, sent=410),
                        dict(original, received=320, sent=200),
                        dict(original, received=320, sent=410, cn="intruder"),
                        dict(original, received=320, sent=410, peer=8),
                        dict(original, received=320, sent=410, privateKey="PRIVATE-CREDENTIAL")):
            configure([original, dict(original), invalid])
            with self.assertRaises((mod.Incomplete, mod.evidence.EvidenceError)) as ctx:
                collector.session_traffic("e" * 32, UID, 7, "10.42.1.7")
            self.assertNotIn("PRIVATE-CREDENTIAL", str(ctx.exception))
        configure([original, dict(original, received=101), later])
        with self.assertRaises(mod.evidence.EvidenceError):
            collector.session_traffic("e" * 32, UID, 7, "10.42.1.7")

    def test_independent_witness_uid_image_and_distinct_status_contract(self):
        from datetime import datetime, timedelta, timezone
        collector, api = fixture()
        start = datetime.now(timezone.utc) - timedelta(seconds=20)
        started = (start + timedelta(seconds=2)).isoformat().replace("+00:00", "Z")
        finished = (start + timedelta(seconds=16)).isoformat().replace("+00:00", "Z")
        image = EXPECTED
        witness = {"metadata": {"name": "synthetic-witness", "namespace": collector.owner.names[0], "uid": "f" * 32},
                   "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False},
                   "status": {"phase": "Succeeded", "containerStatuses": [{"name": "witness", "imageID": image,
                     "state": {"terminated": {"exitCode": 0, "startedAt": started, "finishedAt": finished}}}]}}
        class WitnessAPI(FakeClient):
            def get(self, kind, name, namespace):
                assert kind == "pod" and name == "synthetic-witness" and namespace == self.owner.names[0]
                return self.pod
            def server_session(self, namespace, uid, *, expected_image_id):
                return {"sessions": self.sessions}
        wapi = WitnessAPI(collector.owner)
        collector.api = wapi
        running = json.loads(json.dumps(witness))
        running["status"]["phase"] = "Running"
        running["status"]["containerStatuses"][0]["state"] = {"running": {"startedAt": started}}
        wapi.pod = running
        primary = {"cn": "synthetic-client", "virtualIPv4": "10.88.0.2", "received": 10,
                   "sent": 20, "connected": 100, "peer": 7, "cipher": "AES-256-GCM"}
        second = dict(primary, cn="synthetic-witness", virtualIPv4="10.88.0.3", peer=8,
                      connected=int((start + timedelta(seconds=3)).timestamp()))
        wapi.sessions = [primary, second]
        observed = collector.witness_session("e" * 32, "f" * 32, image, start)
        wapi.pod = witness
        self.assertEqual(observed["cn"], "synthetic-witness")
        self.assertEqual(collector.witness_status("f" * 32, image, start,
                                                  start + timedelta(seconds=25), observed),
                         {"witnessSucceededDuringOutage": True, "distinctSession": True})
        with self.assertRaises(mod.Incomplete):
            collector.witness_status("f" * 32, image, start,
                                     start + timedelta(seconds=5), observed)
        for bad in ([primary], [primary, dict(second, cn="synthetic-client")],
                    [primary, dict(second, virtualIPv4="10.88.0.2")]):
            wapi.sessions = bad
            with self.assertRaises(mod.Incomplete):
                wapi.pod = running
                collector.witness_session("e" * 32, "f" * 32, image, start)
        wapi.sessions = [primary, second]
        wapi.pod = witness
        for tamper in (lambda: witness["status"].update(phase="Failed"),
                       lambda: witness["status"]["containerStatuses"][0]["state"]["terminated"].update(exitCode=1),
                       lambda: witness["status"]["containerStatuses"][0].update(imageID="wrong")):
            import copy
            wapi.pod = copy.deepcopy(witness)
            witness = wapi.pod
            tamper()
            with self.assertRaises(mod.Incomplete):
                collector.witness_status("f" * 32, image, start,
                                         start + timedelta(seconds=25), observed)
            witness = {"metadata": {"name": "synthetic-witness", "namespace": collector.owner.names[0], "uid": "f" * 32},
                       "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False},
                       "status": {"phase": "Succeeded", "containerStatuses": [{"name": "witness", "imageID": image,
                           "state": {"terminated": {"exitCode": 0, "startedAt": started, "finishedAt": finished}}}]}}
        wapi.pod = witness
        with self.assertRaises(mod.Incomplete):
            collector.witness_status("f" * 32, image, start + timedelta(minutes=1),
                                     start + timedelta(minutes=2), observed)

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

    def test_public_ca_tls_anonymous_denial_and_direct_cni_route(self):
        collector, api = fixture()
        route = {"dst": "10.43.0.1", "dev": "eth0", "prefsrc": "10.42.2.5"}
        api.outputs = {"direct-dns": "10.43.0.1 STREAM kubernetes.default.svc.cluster.local\n",
                       "direct-api-route": payload(route), "direct-api-tls": "10.43.0.1 403"}
        exclusions = [{"source": "serviceCIDR", "cidr": "10.43.0.0/16"}]
        self.assertEqual(collector.direct_api_tls(UID, "10.42.2.5", "10.43.0.1", "10.43.0.10", exclusions),
                         {"verifiedCA": True, "anonymousDenied": True, "directClusterRoute": True})
        for result in ("10.43.0.1 200", "10.43.0.1 000", "10.43.0.2 403", "SECRET", "10.43.0.1 403 EXTRA"):
            api.outputs["direct-api-tls"] = result
            with self.assertRaises(mod.Incomplete) as ctx:
                collector.direct_api_tls(UID, "10.42.2.5", "10.43.0.1", "10.43.0.10", exclusions)
            self.assertNotIn("SECRET", str(ctx.exception))
        api.outputs["direct-api-tls"] = "10.43.0.1 403"
        for wrong in (dict(route, dev="rtk0"), dict(route, prefsrc="10.88.0.2"),
                      dict(route, dst="10.43.0.2")):
            api.outputs["direct-api-route"] = payload(wrong)
            with self.assertRaises(mod.evidence.EvidenceError):
                collector.direct_api_tls(UID, "10.42.2.5", "10.43.0.1", "10.43.0.10", exclusions)
        api.outputs["direct-api-route"] = payload(route)
        with self.assertRaises(mod.evidence.EvidenceError):
            collector.direct_api_tls(UID, "10.42.2.5", "10.43.0.1", "10.43.0.10", [])

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
