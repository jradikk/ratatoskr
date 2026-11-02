#!/usr/bin/env python3
"""Pure negative evidence fixtures, without API/PKI/container execution."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_evidence", Path(__file__).with_name("evidence.py"))
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
ID = "containerd://sha256:" + "a" * 64
IDS = {"gateway": ID, "plugin": ID}


def ref(kind, uid):
    return {"ownerReferences": [{"kind": kind, "uid": uid, "controller": True}]}


def cond(name="Ready", state="True", generation=1):
    return {"type": name, "status": state, "observedGeneration": generation}


def fixture():
    gw = {"metadata": {"name": "synthetic", "namespace": "rtk-syn-fixture", "uid": "gw-uid", "generation": 1},
          "status": {"observedGeneration": 1, "gatewayID": 7, "readyReplicas": 1,
                     "conditions": [cond(), cond("MTUUnknown", "False")],
                     "mtu": {"geneveMTU": 1400, "effectiveMTU": 1350},
                     "endpoints": [{"podName": "gw-pod", "podIP": "10.42.1.7", "upstreamHealthy": True,
                                    "upstreamExitIP": "10.88.0.1"}]}}
    dep = {"metadata": dict(ref("EgressGateway", "gw-uid"), name="synthetic", namespace="rtk-syn-fixture",
                             uid="deployment-uid", generation=1), "spec": {"replicas": 1},
           "status": {"readyReplicas": 1, "updatedReplicas": 1, "observedGeneration": 1}}
    rs = {"metadata": dict(ref("Deployment", "deployment-uid"), uid="replicaset-uid", namespace="rtk-syn-fixture")}
    pod = {"metadata": dict(ref("ReplicaSet", "replicaset-uid"), name="gw-pod", namespace="rtk-syn-fixture"),
           "spec": {"containers": [{"name": "gateway", "imagePullPolicy": "Never"},
                                   {"name": "upstream", "imagePullPolicy": "Never", "args": ["--probe-url", e.PROBE]}]},
           "status": {"podIP": "10.42.1.7", "conditions": [cond()], "containerStatuses": [
               {"name": "gateway", "ready": True, "imageID": ID}, {"name": "upstream", "ready": True, "imageID": ID}]}}
    children = [{"kind": kind, "metadata": dict(ref("EgressGateway", "gw-uid"), name="synthetic",
                                              namespace="rtk-syn-fixture")} for kind in ("Service", "ConfigMap", "NetworkPolicy")]
    return [gw, dep, rs, pod, children]


def client():
    return {"metadata": {"name": "synthetic-client", "namespace": "rtk-syn-fixture-apps",
                         "annotations": {e.PREFIX + "datapath-ready": "true"}},
            "spec": {"automountServiceAccountToken": False, "containers": [{"name": "client", "imagePullPolicy": "Never",
                     "securityContext": {"capabilities": {"drop": ["ALL"]}, "allowPrivilegeEscalation": False,
                                         "runAsNonRoot": True}, "volumeMounts": [{"name": "api-public-ca",
                                         "mountPath": "/var/run/ratatoskr/api-ca", "readOnly": True}]}],
                     "initContainers": [{"name": "ratatoskr-init", "args": ["-wait-agent"], "securityContext": {
                         "capabilities": {"drop": ["ALL"]}, "allowPrivilegeEscalation": False,
                         "runAsNonRoot": True}}], "volumes": [{"name": "ratatoskr-agent-api-shadow", "emptyDir": {}},
                                 {"name": "api-public-ca", "configMap": {"name": "kube-root-ca.crt",
                                  "items": [{"key": "ca.crt", "path": "ca.crt"}], "defaultMode": 292}}]},
            "status": {"podIP": "10.42.2.5", "conditions": [cond()],
                       "containerStatuses": [{"name": "client", "ready": True, "imageID": ID}],
                       "initContainerStatuses": [{"name": "ratatoskr-init", "state": {"terminated": {"exitCode": 0}}}]}}


class EvidenceTests(unittest.TestCase):
    def test_gateway_owner_status_runtime_and_plugin_provenance(self):
        fields = fixture()
        self.assertEqual(e.assert_gateway_chain(*fields, IDS), (7, "10.42.1.7"))
        cases = [
            lambda a: a[1]["metadata"]["ownerReferences"][0].update(uid="wrong"),
            lambda a: a[2]["metadata"]["ownerReferences"][0].update(uid="wrong"),
            lambda a: a[3]["metadata"]["ownerReferences"][0].update(uid="wrong"),
            lambda a: a[4][0]["metadata"]["ownerReferences"][0].update(uid="wrong"),
            lambda a: a[0]["status"].update(observedGeneration=0),
            lambda a: a[0]["status"]["conditions"][0].update(status="False"),
            lambda a: a[0]["status"]["endpoints"][0].update(upstreamHealthy=False),
            lambda a: a[0]["status"]["mtu"].update(effectiveMTU=0),
            lambda a: a[3]["spec"]["containers"][1].update(args=[]),
            lambda a: a[3]["status"]["containerStatuses"][1].update(imageID="wrong"),
        ]
        for modify in cases:
            with self.subTest(case=modify):
                items = copy.deepcopy(fields)
                modify(items)
                with self.assertRaises(e.EvidenceError):
                    e.assert_gateway_chain(*items, IDS)

    def test_source_service_and_restricted_client(self):
        service = {"metadata": {"namespace": "rtk-syn-fixture", "name": "synthetic-vpn"},
                   "spec": {"clusterIP": "10.43.0.55", "selector": {"app": "synthetic-vpn"},
                            "ports": [{"port": 1194, "protocol": "UDP", "targetPort": 1194}]}}
        server = {"metadata": {"namespace": "rtk-syn-fixture", "name": "synthetic-vpn", "labels": {"app": "synthetic-vpn"}},
                  "spec": {"containers": [{"name": "server", "imagePullPolicy": "Never"}]},
                  "status": {"conditions": [cond()], "containerStatuses": [{"name": "server", "imageID": ID, "ready": True}]}}
        self.assertEqual(str(e.assert_source_service(service, server, ID)), "10.43.0.55")
        fixture_client = client()
        self.assertEqual(e.assert_restricted_client(fixture_client, "rtk-syn-fixture-apps", 7, "10.42.1.7", ID), "10.42.2.5")
        for update in (
            lambda c: c["spec"]["volumes"].append({"name": "creds", "secret": {"secretName": "x"}}),
            lambda c: c["spec"]["initContainers"][0]["securityContext"]["capabilities"].update(add=["NET_ADMIN"]),
            lambda c: c["status"]["initContainerStatuses"][0]["state"]["terminated"].update(exitCode=1),
            lambda c: c["metadata"]["annotations"].update({e.PREFIX + "datapath-ready": "pending"}),
            lambda c: c["spec"]["volumes"][1]["configMap"].update(name="malicious-ca"),
            lambda c: c["spec"]["containers"][0]["volumeMounts"].append({"name": "secret", "mountPath": "/bad"}),
            lambda c: c["status"]["containerStatuses"][0].update(imageID="wrong"),
        ):
            invalid = copy.deepcopy(fixture_client)
            update(invalid)
            with self.assertRaises(e.EvidenceError):
                e.assert_restricted_client(invalid, "rtk-syn-fixture-apps", 7, "10.42.1.7", ID)
        service["spec"]["ports"].append({"port": 8080})
        with self.assertRaises(e.EvidenceError):
            e.assert_source_service(service, server, ID)

    def test_source_slice_identity_and_agent_link_marker(self):
        service = {"metadata": {"name": "synthetic-vpn", "namespace": "rtk-syn-fixture"}}
        server = {"metadata": {"uid": "server-uid"}, "status": {"podIP": "10.42.1.9"}}
        slice_obj = {"addressType": "IPv4", "metadata": {"namespace": "rtk-syn-fixture",
                     "labels": {"kubernetes.io/service-name": "synthetic-vpn"}},
                     "ports": [{"protocol": "UDP", "port": 1194}],
                     "endpoints": [{"targetRef": {"kind": "Pod", "name": "synthetic-vpn", "uid": "server-uid"},
                                    "conditions": {"ready": True}, "addresses": ["10.42.1.9"]}]}
        e.assert_source_endpoint(slice_obj, service, server)
        invalid = copy.deepcopy(slice_obj)
        invalid["endpoints"][0]["targetRef"]["uid"] = "other"
        with self.assertRaises(e.EvidenceError):
            e.assert_source_endpoint(invalid, service, server)
        marker = {"ifname": "rtk-ready", "linkinfo": {"info_kind": "dummy"}, "flags": ["UP"]}
        e.assert_agent_marker(marker)
        marker["flags"] = []
        with self.assertRaises(e.EvidenceError):
            e.assert_agent_marker(marker)

    def test_marker_requires_independent_geneve_egress_bytes_and_endpoint(self):
        link = {"ifname": "rtk0", "operstate": "UP", "linkinfo": {"info_kind": "geneve",
                 "info_data": {"id": 7, "remote": "10.42.1.7"}}}
        e.assert_selected_tunnel(20, 102, e.MARKER, link, 7, "10.42.1.7")
        for marker, before, after in ((e.MARKER, 20, 20), (e.MARKER, 20, 10), ("spoof", 20, 102)):
            with self.assertRaises(e.EvidenceError):
                e.assert_selected_tunnel(before, after, marker, link, 7, "10.42.1.7")
        link["linkinfo"]["info_data"]["remote"] = "10.42.1.8"
        with self.assertRaises(e.EvidenceError):
            e.assert_selected_tunnel(20, 102, e.MARKER, link, 7, "10.42.1.7")

    def test_direct_paths_fail_close_and_recovery(self):
        exclusions = [{"source": "serviceCIDR", "cidr": "10.43.0.0/16"}]
        route = {"dst": "10.43.0.1", "dev": "eth0", "prefsrc": "10.42.2.5"}
        e.assert_direct_paths(exclusions, "10.43.0.10", "10.43.0.1", "kubernetes.default.svc.cluster.local",
                              403, route, "10.42.2.5")
        for bad in (([], "10.43.0.10", "10.43.0.1", "kubernetes.default.svc.cluster.local", 403, route, "10.42.2.5"),
                    (exclusions, "10.43.0.10", "10.43.0.1", "invalid", 403, route, "10.42.2.5"),
                    (exclusions, "10.43.0.10", "10.43.0.1", "kubernetes.default.svc.cluster.local", 200, route, "10.42.2.5"),
                    (exclusions, "10.43.0.10", "10.43.0.1", "kubernetes.default.svc.cluster.local", 403,
                     dict(route, dev="rtk0"), "10.42.2.5")):
            with self.assertRaises(e.EvidenceError):
                e.assert_direct_paths(*bad)
        gw = fixture()[0]
        uid = gw["metadata"]["uid"]
        down = copy.deepcopy(gw)
        down["status"]["readyReplicas"] = 0
        down["status"]["conditions"][0]["status"] = "False"
        down["status"]["endpoints"][0]["upstreamHealthy"] = False
        e.assert_fail_close(down, True, True)
        e.assert_recovery(gw, uid, e.MARKER, 100, 200)
        for good_marker, direct in ((False, True), (True, False)):
            with self.assertRaises(e.EvidenceError):
                e.assert_fail_close(down, good_marker, direct)
        with self.assertRaises(e.EvidenceError):
            e.assert_recovery(gw, "other", e.MARKER, 100, 200)


if __name__ == "__main__":
    unittest.main()
