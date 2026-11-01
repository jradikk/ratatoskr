"""Pure Calico outage/capture environment plumbing; no API, Docker or root."""
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
import environment
import failclose_capture as capture
import lifecycle
import outage
import test_failclose_capture as fixtures

UID = fixtures.UID


class Owner:
    def __init__(self, env):
        self.environment = env
        self.api = type("API", (), {"environment": env})()
        self.names = (fixtures.NS.removesuffix("-apps"), fixtures.NS)
        self.token = "e" * 32
        self.deadline = 1000
        self.private_dir = Path("/fake-calico-test-private")
        self.closed = False
        self.events = []
    def clock(self): return 0
    def __enter__(self): self.events.append("enter"); return self
    def __exit__(self, *_args): self.events.append("cleanup"); return False
    def create_namespaces(self): self.events.append("namespaces")
    def generate_pki(self): self.events.append("private-pki")


def calico_pod():
    item = fixtures.pod()
    item["spec"]["nodeName"] = environment.CALICO.nodes[1]
    return item


class OutageEnvironmentTest(unittest.TestCase):
    def test_identity_exact_calico_node_without_flannel_fallback(self):
        self.assertEqual(capture.identity(calico_pod(), fixtures.NS, UID, fixtures.IMAGE,
                                         environment=environment.CALICO)[0], environment.CALICO.nodes[1])
        with self.assertRaises(capture.Blocked):
            capture.identity(calico_pod(), fixtures.NS, UID, fixtures.IMAGE)
        with self.assertRaises(capture.Blocked):
            capture.identity(fixtures.pod(), fixtures.NS, UID, fixtures.IMAGE,
                             environment=environment.CALICO)
        with self.assertRaises(capture.Blocked):
            capture.identity(calico_pod(), fixtures.NS, UID, fixtures.IMAGE,
                             environment="calico")

    def test_mixed_owner_or_environment_rejected_before_api_or_root(self):
        owner = lifecycle.Lifecycle(api=type("Mock", (), {"environment": environment.CALICO})(),
                                    environment=environment.CALICO, token_factory=lambda: "e" * 32)
        owner.deadline = 1000
        class API:
            def __init__(self, actual): self.owner = actual
            def get(self, *_args): raise AssertionError("no Kubernetes")
        api = API(owner)
        for env in (environment.FLANNEL, "calico"):
            with self.subTest(env=env), self.assertRaises(capture.Blocked):
                capture.prove(api, fixtures.NS, UID, fixtures.IMAGE, 7, fixtures.API,
                              trigger=lambda: self.fail("no trigger"),
                              transport=lambda *_a, **_k: self.fail("no Docker"),
                              local=lambda *_a, **_k: self.fail("no root"),
                              environment=env)
        api.owner = None
        with self.assertRaises(capture.Blocked):
            capture.prove(api, fixtures.NS, UID, fixtures.IMAGE, 7, fixtures.API,
                          trigger=lambda: None, environment=environment.CALICO)

    def test_calico_prove_uses_only_verified_calico_node_and_rechecks_uid(self):
        owner = lifecycle.Lifecycle(api=type("Mock", (), {"environment": environment.CALICO})(),
                                    environment=environment.CALICO, token_factory=lambda: "e" * 32)
        owner.deadline = 1000
        class API:
            def __init__(self): self.owner = owner; self.replaced = False; self.calls = 0
            def get(self, kind, name, namespace):
                self.calls += 1
                assert (kind, name, namespace) == ("pod", "synthetic-client", fixtures.NS)
                pod = calico_pod()
                if self.replaced and self.calls >= 4: pod["metadata"]["uid"] = "f" * 32
                return pod
        api = API()
        seen = []
        def transport(argv, **_kwargs):
            seen.append(argv)
            assert argv[:3] == ["docker", "exec", environment.CALICO.nodes[1]]
            return fixtures.sandbox() if "inspectp" in argv else fixtures.sandboxes()
        def local(argv, **_kwargs):
            seen.append(argv)
            assert argv[:5] == ["docker", "inspect", "-f", "{{json .State.Pid}}", environment.CALICO.nodes[1]]
            return b"321\n"
        route = json.dumps([{"dst": "default", "type": "unreachable", "protocol": 186,
                             "metric": 4294967295, "table": fixtures.TABLE}])
        rule = json.dumps([{"priority": 10998, "protocol": "186", "table": str(fixtures.TABLE),
                            "fwmark": "0x200000", "fwmask": "0xf00000"}])
        result = {"routeBefore": route, "routeAfter": route,
                  "ruleBefore": rule, "ruleAfter": rule,
                  "capture": "1.000 IP 10.42.2.5.12345 > 10.43.0.1.443: Flags [S], seq 1\n"}
        self.assertTrue(capture.prove(api, fixtures.NS, UID, fixtures.IMAGE, 7, fixtures.API,
                                      transport=transport, local=local,
                                      collect_fn=lambda *_args: result,
                                      trigger=lambda: None, environment=environment.CALICO))
        self.assertTrue(seen)
        self.assertFalse(any(environment.FLANNEL.nodes[1] in row for row in seen))
        api.calls = 0; api.replaced = True
        with self.assertRaises(capture.Blocked):
            capture.prove(api, fixtures.NS, UID, fixtures.IMAGE, 7, fixtures.API,
                          transport=transport, local=local, collect_fn=lambda *_args: result,
                          trigger=lambda: None, environment=environment.CALICO)

    def test_outage_fixture_passes_calico_environment_to_capture_when_triggered(self):
        import test_outage as old
        owner = Owner(environment.CALICO)
        class API(old.API):
            def get(self, kind, name, namespace):
                if kind == "pod" and name == "synthetic-client":
                    result = super().get(kind, name, namespace)
                    result["metadata"]["annotations"][old.o.evidence.PREFIX + "datapath-ready"] = "pending"
                    return result
                return super().get(kind, name, namespace)
            def probe_running(self, name, uid, image, phase, api_ip):
                owner.events.append("probe:" + phase)
                return True
        api = API(owner)
        baseline = {"gatewayUID": old.UID, "serverUID": old.UID,
                    "gatewayPodUID": old.UID, "gatewayID": 9,
                    "endpoint": "10.42.0.5", "session": {}}
        objects = [{"kind": kind, "metadata": {"name": name,
                    "namespace": owner.names[1] if kind == "EgressPolicy" else owner.names[0]}}
                   for kind, name in outage.partial_gateway.BASE]
        objects.append({"kind": "Pod", "metadata": {"name": "synthetic-witness",
                                                 "namespace": owner.names[0]}})
        seen = []
        def fail_closed(*_args):
            raise outage.adapter.AdapterError("timeout requiring capture")
        def fake_capture(*args, **kwargs):
            seen.append(kwargs)
            return True
        def polling(_owner, checkpoint, predicate, **_kwargs):
            owner.events.append(checkpoint)
            if checkpoint == "withdrawn-selected-fail-close":
                return predicate()
            return {}
        from unittest.mock import patch
        with patch.object(outage.partial_gateway, "private_contents", return_value=("fake",) * 7), \
             patch.object(outage.prepare, "manifests", return_value=objects), \
             patch.object(outage.prepare, "running_probe_pod", return_value={"kind": "Pod",
                 "metadata": {"name": "synthetic-client", "namespace": owner.names[1]}}), \
             patch.object(outage, "poll", side_effect=polling), \
             patch.object(outage, "selected_fail_closed", side_effect=fail_closed), \
             patch.object(outage.failclose_capture, "prove", side_effect=fake_capture):
            self.assertFalse(outage.execute({name: old.IMAGE for name in outage.run.COMPONENTS},
                                            api_ip="10.43.0.1", environment=environment.CALICO,
                                            lifecycle_factory=lambda **kwargs: owner,
                                            adapter_factory=lambda _owner: api,
                                            observer=lambda *_args: baseline,
                                            healthy=lambda *_args: {"podUID": old.UID,
                                                "healthyExit": True, "directAPITLSAndDNS": True,
                                                "serverSessionBytesAdvanced": True}))
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["environment"], environment.CALICO)
        self.assertEqual(owner.events[0], "enter")
        self.assertEqual(owner.events[-1], "cleanup")

    def test_outage_environment_mismatch_blocks_before_namespace_create_cleanup_runs(self):
        selected = Owner(environment.FLANNEL)
        with self.assertRaises(outage.Blocked):
            outage.execute({key: "sha256:" + "b" * 64 for key in outage.run.COMPONENTS},
                           api_ip="10.43.0.1", environment=environment.CALICO,
                           lifecycle_factory=lambda **kwargs: selected,
                           adapter_factory=lambda *_args: self.fail("no fixture"))
        self.assertEqual(selected.events, ["enter", "cleanup"])
        with self.assertRaises(outage.Blocked):
            outage.execute({}, api_ip="10.43.0.1", environment="calico",
                           lifecycle_factory=lambda **kwargs: self.fail("no owner"))


if __name__ == "__main__":
    unittest.main()
