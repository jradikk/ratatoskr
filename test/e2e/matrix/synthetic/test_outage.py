#!/usr/bin/env python3
"""Adversarial fake-only outage orchestration; never invokes kubectl/PKI."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_outage", HERE / "outage.py")
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
UID = "a" * 32
IMAGE = "sha256:" + "b" * 64


class Owner:
    def __init__(self, **_kw):
        self.names = ("rtk-syn-" + "c" * 16, "rtk-syn-" + "c" * 16 + "-apps")
        self.token = "c" * 32
        self.deadline = 1000
        self.closed = False
        self.private_dir = Path("/unused-test-private")
        self.events = []
    def __enter__(self):
        self.events.append("enter")
        return self
    def __exit__(self, *_):
        self.events.append("cleanup")
    def clock(self):
        return 0
    def create_namespaces(self):
        self.events.append("namespaces")
    def generate_pki(self):
        self.events.append("pki")


class ExitSwitch:
    def __init__(self, api):
        self.api = api
    def __enter__(self):
        self.api.owner.events.append("disable")
    def __exit__(self, *_):
        self.api.owner.events.append("restore")


class API:
    def __init__(self, owner):
        self.owner = owner
        self.ids = {}
    def create(self, item):
        name, namespace, kind = item["metadata"]["name"], item["metadata"]["namespace"], item["kind"]
        identity = {"kind": kind, "namespace": namespace, "name": name, "uid": UID}
        self.ids[(kind, namespace, name)] = UID
        self.owner.events.append("create:" + name)
        return identity
    def get(self, kind, name, namespace):
        if kind == "pod" and name == "synthetic-client":
            return {"metadata": {"uid": UID}}
        raise AssertionError("Unexpected fake API GET")
    def probe_running(self, name, uid, _image, phase, _api_ip):
        assert uid == UID
        self.owner.events.append("probe:" + name + ":" + phase)
        return True
    def exit_health_snapshot(self):
        return UID, "11", "true"
    def exit_health_outage(self):
        return ExitSwitch(self)


class OutageTests(unittest.TestCase):
    def run_fake(self, *, fail_stage=None):
        owner = Owner()
        api = API(owner)
        objects = [{"kind": kind, "metadata": {"name": name,
                    "namespace": owner.names[1] if kind == "EgressPolicy" else owner.names[0]}}
                   for kind, name in o.partial_gateway.BASE]
        objects.append({"kind": "Pod", "metadata": {"name": "synthetic-witness", "namespace": owner.names[0]}})
        baseline = {"gatewayUID": UID, "serverUID": UID, "gatewayPodUID": UID,
                    "gatewayID": 9, "endpoint": "10.42.0.5", "session": {}}
        def observer(*_args):
            owner.events.append("baseline")
            return baseline
        def healthy(*_args):
            owner.events.append("healthy-one-shot")
            return {"podUID": UID, "healthyExit": True, "directAPITLSAndDNS": True,
                    "serverSessionBytesAdvanced": True}
        def polling(_owner, stage, predicate, **_kw):
            owner.events.append(stage)
            if fail_stage == stage:
                raise o.Blocked("Outage/recovery did not converge at " + stage + ".")
            return {}  # predicate checked separately in focused fake tests
        with patch.object(o.partial_gateway, "private_contents", return_value=()), \
             patch.object(o.prepare, "manifests", return_value=objects), \
             patch.object(o.prepare, "running_probe_pod", return_value={"kind": "Pod", "metadata": {
                 "name": "synthetic-client", "namespace": owner.names[1]}}), \
             patch.object(o, "poll", side_effect=polling):
            if fail_stage:
                with self.assertRaises(o.Blocked):
                    o.execute({name: IMAGE for name in o.run.COMPONENTS}, api_ip="10.43.0.1",
                              lifecycle_factory=lambda **kw: owner, adapter_factory=lambda _owner: api,
                              observer=observer, healthy=healthy)
            else:
                self.assertFalse(o.execute({name: IMAGE for name in o.run.COMPONENTS}, api_ip="10.43.0.1",
                                           lifecycle_factory=lambda **kw: owner,
                                           adapter_factory=lambda _owner: api,
                                           observer=observer, healthy=healthy))
        return owner.events

    def test_ordered_healthy_outage_witness_restore_recovery_and_cleanup(self):
        events = self.run_fake()
        self.assertLess(events.index("healthy-one-shot"), events.index("disable"))
        self.assertLess(events.index("disable"), events.index("gateway-withdrawal"))
        self.assertLess(events.index("gateway-withdrawal"), events.index("probe:synthetic-witness:outage"))
        self.assertLess(events.index("probe:synthetic-client:outage"), events.index("restore"))
        self.assertLess(events.index("restore"), events.index("gateway-recovery"))
        self.assertEqual(events[-1], "cleanup")

    def test_every_outage_and_recovery_failure_restores_and_cleans(self):
        for stage in ("gateway-withdrawal", "outage-still-withdrawn", "gateway-recovery", "agent-recovery"):
            with self.subTest(stage=stage):
                events = self.run_fake(fail_stage=stage)
                self.assertEqual(events[-1], "cleanup")
                if stage != "gateway-withdrawal":
                    self.assertIn("restore", events)

    def test_uid_gateway_status_never_accepts_stale_or_healthy_outage(self):
        class StatusAPI:
            def get(self, *_):
                return {"metadata": {"uid": UID, "generation": 4},
                        "status": {"observedGeneration": 4, "readyReplicas": 1,
                                   "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 4}],
                                   "endpoints": [{"podIP": "10.42.0.5", "upstreamHealthy": True}]}}
            def list_owned_gateway_pods(self, *_):
                return {"metadata": {"uid": UID}}
        self.assertIsNone(o.gateway_state(StatusAPI(), "ns", UID, UID,
                                         healthy=False, endpoint="10.42.0.5"))
        self.assertIsNotNone(o.gateway_state(StatusAPI(), "ns", UID, UID,
                                             healthy=True, endpoint="10.42.0.5"))
        with self.assertRaises(o.Blocked):
            o.gateway_state(StatusAPI(), "ns", UID, "f" * 32,
                            healthy=True, endpoint="10.42.0.5")


if __name__ == "__main__":
    unittest.main()
