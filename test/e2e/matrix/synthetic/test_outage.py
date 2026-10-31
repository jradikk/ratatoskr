#!/usr/bin/env python3
"""Adversarial fake-only outage orchestration; never invokes kubectl/PKI."""
import importlib.util
import json
from pathlib import Path
from contextlib import contextmanager
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
        self.api.selected_pending = True
    def __exit__(self, *_):
        self.api.owner.events.append("restore")
        self.api.selected_pending = False


class API:
    def __init__(self, owner):
        self.owner = owner
        self.ids = {}
        self.selected_pending = False
    def create(self, item):
        name, namespace, kind = item["metadata"]["name"], item["metadata"]["namespace"], item["kind"]
        identity = {"kind": kind, "namespace": namespace, "name": name, "uid": UID}
        self.ids[(kind, namespace, name)] = UID
        self.owner.events.append("create:" + name)
        return identity
    def get(self, kind, name, namespace):
        if kind == "pod" and name == "synthetic-client":
            return {"metadata": {"uid": UID, "annotations": {
                o.evidence.PREFIX + "datapath-ready": "pending" if self.selected_pending else "true"}},
                "status": {"phase": "Running"}}
        raise AssertionError("Unexpected fake API GET")
    def exec(self, namespace, name, uid, container, command, *, expected_image_id):
        assert (namespace, name, uid, container, command) == (self.owner.names[1], "synthetic-client", UID,
                                                              "client", "agent-marker")
        return json.dumps([{"ifname": "rtk-ready", "flags": ["UP"],
                            "linkinfo": {"info_kind": "dummy"}}])
    def probe_running(self, name, uid, _image, phase, _api_ip):
        assert uid == UID
        self.owner.events.append("probe:" + name + ":" + phase)
        return True
    def exit_health_snapshot(self):
        return UID, "11", "true"
    def exit_health_outage(self):
        return ExitSwitch(self)


class OutageTests(unittest.TestCase):
    @contextmanager
    def _fake_execute(self, owner, api):
        objects = [{"kind": kind, "metadata": {"name": name,
                    "namespace": owner.names[1] if kind == "EgressPolicy" else owner.names[0]}}
                   for kind, name in o.partial_gateway.BASE]
        objects.append({"kind": "Pod", "metadata": {"name": "synthetic-witness", "namespace": owner.names[0]}})
        baseline = {"gatewayUID": UID, "serverUID": UID, "gatewayPodUID": UID,
                    "gatewayID": 9, "endpoint": "10.42.0.5", "session": {}}
        def healthy(*_args):
            return {"podUID": UID, "healthyExit": True, "directAPITLSAndDNS": True,
                    "serverSessionBytesAdvanced": True}
        def polling(_owner, stage, predicate, **_kw):
            if stage == "withdrawn-selected-fail-close":
                try:
                    return predicate()
                except o.adapter.AdapterError:
                    raise o.Blocked("Outage/recovery did not converge at " + stage + ".") from None
            return {}  # other stages retain their established fake behavior
        with patch.object(o.partial_gateway, "private_contents", return_value=()), \
             patch.object(o.prepare, "manifests", return_value=objects), \
             patch.object(o.prepare, "running_probe_pod", return_value={"kind": "Pod", "metadata": {
                 "name": "synthetic-client", "namespace": owner.names[1]}}), \
             patch.object(o, "poll", side_effect=polling):
            yield lambda: o.execute({name: IMAGE for name in o.run.COMPONENTS}, api_ip="10.43.0.1",
                                    lifecycle_factory=lambda **kw: owner, adapter_factory=lambda _owner: api,
                                    observer=lambda *_args: baseline, healthy=healthy)

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
            if stage == "withdrawn-selected-fail-close":
                return predicate()
            return {}  # other stages checked separately in focused fake tests
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

    def test_selected_timeout_categories_never_include_untrusted_status_or_logs(self):
        base = {"gatewayUID": UID, "gatewayPodUID": UID, "gatewayID": 9, "endpoint": "10.42.0.5"}
        def pod(phase="Pending", init=None, annotations=None, image_id=None):
            status = {"phase": phase, "podIP": "10.42.2.5", "initContainerStatuses": init or [],
                      "containerStatuses": [{"name": "client", "ready": True,
                                             "imageID": image_id or IMAGE}],
                      "conditions": [{"type": "Ready", "status": "True"}],
                      "message": "PRIVATE_ERROR_SHOULD_NOT_LEAK"}
            return {"metadata": {"uid": UID, "annotations": annotations or {},
                                  "message": "PRIVATE_ERROR_SHOULD_NOT_LEAK"},
                    "spec": {"nodeName": "agent-0"}, "status": status}
        pending = pod()
        self.assertEqual(o.selected_wait_category(pending, UID, IMAGE, base), "wait-init-pending")
        wrong_uid = pod()
        wrong_uid["metadata"]["uid"] = "f" * 32
        self.assertEqual(o.selected_wait_category(wrong_uid, UID, IMAGE, base), "uid-changed")
        failed = pod("Failed")
        self.assertEqual(o.selected_wait_category(failed, UID, IMAGE, base), "pod-failed")
        terminated = [{"name": "ratatoskr-init", "state": {"terminated": {"exitCode": 1,
                       "message": "PRIVATE_ERROR_SHOULD_NOT_LEAK"}}}]
        self.assertEqual(o.selected_wait_category(pod(init=terminated), UID, IMAGE, base), "wait-init-failed")
        unscheduled = pod()
        unscheduled["spec"].pop("nodeName")
        self.assertEqual(o.selected_wait_category(unscheduled, UID, IMAGE, base), "unscheduled")
        gateway = {"metadata": {"uid": UID}, "status": {"endpoints": [{
            "podIP": "10.42.0.5", "podUID": UID,
            "appliedClientConfigHash": "0" * 64}]}}
        self.assertEqual(o.selected_wait_category(pending, UID, IMAGE, base, gateway), "wait-init-pending")
        gateway["status"]["endpoints"][0]["appliedClientConfigHash"] = ""
        self.assertEqual(o.selected_wait_category(pending, UID, IMAGE, base, gateway), "gateway-ack-pending")
        gateway["status"]["endpoints"][0]["appliedClientConfigHash"] = "0" * 64
        gateway["metadata"]["uid"] = "e" * 32
        self.assertEqual(o.selected_wait_category(pending, UID, IMAGE, base, gateway), "gateway-identity-changed")
        running = pod("Running", [{"name": "ratatoskr-init", "state": {"terminated": {"exitCode": 0}}}])
        self.assertEqual(o.selected_wait_category(running, UID, IMAGE, base), "agent-readiness-pending")
        running["status"]["containerStatuses"][0]["imageID"] = "unknown"
        self.assertEqual(o.selected_wait_category(running, UID, IMAGE, base), "app-image-pending")
        self.assertTrue(all("PRIVATE_ERROR" not in label for label in (
            o.selected_wait_category(p, UID, IMAGE, base) for p in (pending, failed, running))))

    def test_running_selected_diagnosis_does_not_replace_strict_acceptance(self):
        owner = Owner()
        api = API(owner)
        def pending_pod(kind, name, namespace):
            if kind != "pod" or name != "synthetic-client" or namespace != owner.names[1]:
                raise o.adapter.AdapterError("PRIVATE_API_ERROR")
            return {"metadata": {"uid": UID}, "spec": {"nodeName": "agent-0"},
                    "status": {"phase": "Pending", "podIP": "10.42.2.5"}}
        api.get = pending_pod
        diagnosis = {}
        base = {"gatewayUID": UID, "gatewayPodUID": UID, "gatewayID": 9, "endpoint": "10.42.0.5"}
        self.assertIsNone(o.observe_running_selected(api, owner.names[1], UID, IMAGE, base,
                                                     "10.43.0.1", diagnosis))
        self.assertEqual(diagnosis, {"category": "wait-init-pending"})
        def malformed_pod(kind, name, namespace):
            raise o.adapter.AdapterError("PRIVATE_API_ERROR")
        api.get = malformed_pod
        with self.assertRaises(o.adapter.AdapterError):
            o.observe_running_selected(api, owner.names[1], UID, IMAGE, base, "10.43.0.1", diagnosis)
        self.assertEqual(diagnosis, {"category": "api-unavailable"})

    def test_selected_fail_closed_waits_for_agent_and_actual_unreachable(self):
        class Selected:
            def __init__(self):
                self.ready = "true"
                self.probes = 0
            def get(self, kind, name, namespace):
                assert (kind, name) == ("pod", "synthetic-client")
                return {"metadata": {"uid": UID, "annotations": {o.evidence.PREFIX + "datapath-ready": self.ready}},
                        "status": {"phase": "Running"}}
            def probe_running(self, _name, _uid, _image, phase, _ip):
                assert phase == "outage"
                self.probes += 1
                if self.probes == 1:
                    raise o.adapter.AdapterError("unreachable not yet observed")
                return True
        selected = Selected()
        self.assertIsNone(o.selected_fail_closed(selected, "apps", UID, IMAGE, "10.43.0.1"))
        self.assertEqual(selected.probes, 0, "readiness pending must precede probe")
        selected.ready = "pending"
        owner = Owner()
        now = [0]
        owner.clock = lambda: now[0]
        owner.deadline = 20
        def sleep(seconds):
            now[0] += seconds
        outcome = o.poll(owner, "withdrawn-selected-fail-close", lambda: o.selected_fail_closed(
            selected, "apps", UID, IMAGE, "10.43.0.1"), seconds=8,
            clock=owner.clock, sleep=sleep)
        self.assertEqual(outcome["metadata"]["uid"], UID)
        self.assertEqual(selected.probes, 2)
        self.assertLessEqual(now[0], 8)
        selected.ready = "true"
        selected.probes = 0
        now[0] = 0
        with self.assertRaisesRegex(o.Blocked, "did not converge at withdrawn-selected-fail-close"):
            o.poll(owner, "withdrawn-selected-fail-close", lambda: o.selected_fail_closed(
                selected, "apps", UID, IMAGE, "10.43.0.1"), seconds=4,
                clock=owner.clock, sleep=sleep)
        self.assertEqual(selected.probes, 0, "ready marker must not qualify for withdrawn state")
        self.assertEqual(now[0], 4)
        selected.ready = "pending"
        selected.get = lambda *_args: {"metadata": {"uid": "replacement", "annotations": {
            o.evidence.PREFIX + "datapath-ready": "pending"}}, "status": {"phase": "Running"}}
        with self.assertRaisesRegex(o.Blocked, "identity changed"):
            o.selected_fail_closed(selected, "apps", UID, IMAGE, "10.43.0.1")

    def test_probe_body_failure_preserves_fixed_stage_after_verified_cleanup(self):
        owner = Owner()
        api = API(owner)
        original = api.probe_running
        def fail(name, uid, image, phase, api_ip):
            if name == "synthetic-client" and phase == "outage":
                raise o.adapter.AdapterError("PRIVATE_TOKEN_FROM_UNTRUSTED_TRANSPORT")
            return original(name, uid, image, phase, api_ip)
        api.probe_running = fail
        with self._fake_execute(owner, api) as run:
            with self.assertRaisesRegex(o.Blocked, "withdrawn-selected-fail-close") as caught:
                run()
        self.assertNotIn("PRIVATE_TOKEN", str(caught.exception))
        self.assertEqual(owner.events[-1], "cleanup")
        self.assertIn("restore", owner.events)

    def test_restoration_failure_distinct_from_probe_body_failure(self):
        owner = Owner()
        api = API(owner)
        class FailedRestore(ExitSwitch):
            def __exit__(self, *_):
                self.api.owner.events.append("restore-failed")
                raise o.adapter.RestorationError("PRIVATE_TOKEN")
        api.exit_health_outage = lambda: FailedRestore(api)
        with self._fake_execute(owner, api) as run:
            with self.assertRaisesRegex(o.RestoreBlocked, "probe-switch restoration unverified") as caught:
                run()
        self.assertNotIn("PRIVATE_TOKEN", str(caught.exception))
        self.assertEqual(owner.events[-1], "cleanup")

    def test_cleanup_failure_overrides_body_checkpoint(self):
        class CleanupFailure(Owner):
            def __exit__(self, *_):
                self.events.append("cleanup-failed")
                raise o.lifecycle.LifecycleError("Final-gate cleanup unverified (namespace).")
        owner = CleanupFailure()
        api = API(owner)
        original = api.probe_running
        def fail(name, uid, image, phase, api_ip):
            if name == "synthetic-client" and phase == "outage":
                raise o.adapter.AdapterError("PRIVATE_TOKEN")
            return original(name, uid, image, phase, api_ip)
        api.probe_running = fail
        with self._fake_execute(owner, api) as run:
            with self.assertRaisesRegex(o.lifecycle.LifecycleError, "cleanup unverified") as caught:
                run()
        self.assertNotIn("withdrawn-selected-fail-close", str(caught.exception))
        self.assertEqual(owner.events[-1], "cleanup-failed")

    def test_ordered_healthy_outage_witness_restore_recovery_and_cleanup(self):
        events = self.run_fake()
        self.assertLess(events.index("healthy-one-shot"), events.index("disable"))
        self.assertLess(events.index("disable"), events.index("exit-projection"))
        self.assertLess(events.index("exit-projection"), events.index("gateway-withdrawal"))
        self.assertLess(events.index("gateway-withdrawal"), events.index("probe:synthetic-witness:outage"))
        self.assertLess(events.index("probe:synthetic-client:outage"), events.index("restore"))
        self.assertLess(events.index("restore"), events.index("gateway-recovery"))
        self.assertEqual(events[-1], "cleanup")

    def test_every_outage_and_recovery_failure_restores_and_cleans(self):
        for stage in ("exit-projection", "gateway-withdrawal", "outage-still-withdrawn",
                      "gateway-recovery", "agent-recovery"):
            with self.subTest(stage=stage):
                events = self.run_fake(fail_stage=stage)
                self.assertEqual(events[-1], "cleanup")
                if stage != "exit-projection":
                    self.assertIn("restore", events)

    def test_withdrawal_accepts_omitted_zero_but_not_malformed_or_healthy_status(self):
        class StatusAPI:
            def __init__(self):
                self.status = {"observedGeneration": 4,
                               "conditions": [{"type": "Ready", "status": "False", "observedGeneration": 4}],
                               "endpoints": [{"podIP": "10.42.0.5", "upstreamHealthy": False}]}
            def get(self, *_):
                return {"metadata": {"uid": UID, "generation": 4}, "status": self.status}
            def list_owned_gateway_pods(self, *_):
                return {"metadata": {"uid": UID}}
        api = StatusAPI()
        self.assertIsNotNone(o.gateway_state(api, "ns", UID, UID, healthy=False, endpoint="10.42.0.5"))
        api.status["readyReplicas"] = 0
        self.assertIsNotNone(o.gateway_state(api, "ns", UID, UID, healthy=False, endpoint="10.42.0.5"))
        for value in (True, "0", None, -1, 1):
            with self.subTest(value=value):
                api.status["readyReplicas"] = value
                self.assertIsNone(o.gateway_state(api, "ns", UID, UID, healthy=False, endpoint="10.42.0.5"))
        api.status.pop("readyReplicas")
        api.status["endpoints"][0]["upstreamHealthy"] = True
        self.assertIsNone(o.gateway_state(api, "ns", UID, UID, healthy=False, endpoint="10.42.0.5"))
        api.status["endpoints"][0]["upstreamHealthy"] = False
        api.status["conditions"][0]["status"] = "True"
        self.assertIsNone(o.gateway_state(api, "ns", UID, UID, healthy=False, endpoint="10.42.0.5"))
        api.status["conditions"][0]["status"] = "False"
        api.status["observedGeneration"] = 3
        self.assertIsNone(o.gateway_state(api, "ns", UID, UID, healthy=False, endpoint="10.42.0.5"))

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
