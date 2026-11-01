"""Offline gateway replacement fixture tests; no kubectl or cluster access."""
import copy
import hashlib
import io
import json
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import agent_lifecycle as f
from test_ha_fixture import FakeFixtureAPI
from test_ha_live import A, B, CLIENT_NS, CLIENT_UID, GATEWAY, GW_UID, records


class Owner:
    names = (GATEWAY, CLIENT_NS)
    token = "a" * 32
    closed = False

    def __init__(self):
        self.deadline = time.monotonic() + 700
        self.clock = time.monotonic


class API(FakeFixtureAPI):
    def __init__(self):
        super().__init__()
        self.frame = records((A,), A)
        client = self.frame.pop(("pod", CLIENT_NS, "probe"))
        client["metadata"]["name"] = "synthetic-client"
        client["status"].update(phase="Running", conditions=[{"type": "Ready", "status": "True"}],
                                initContainerStatuses=[{"name": "ratatoskr-init", "state": {
                                    "terminated": {"exitCode": 0}}}])
        client["spec"]["containers"] = [{"imagePullPolicy": "Never"}]
        config = json.loads(client["metadata"]["annotations"][f.ha.ha_live.PREFIX + "agent-config"])
        config["identity"]["pod"] = "synthetic-client"
        self._set_config(client, config)
        self.frame[("pod", CLIENT_NS, "synthetic-client")] = client
        self.frame[("egressgateway", GATEWAY, "synthetic")]["spec"] = {"replicas": 1}
        source = {"metadata": {"uid": "abc12345-1111-2222-3333-123456789012"}}
        self.frame[("pod", GATEWAY, "synthetic-vpn")] = source
        self.frame[("service", GATEWAY, "synthetic-vpn")] = {"metadata": {"name": "synthetic-vpn"}}
        self.frame[("configmap", GATEWAY, "synthetic")] = {
            "metadata": {"ownerReferences": [{"kind": "EgressGateway", "uid": GW_UID,
                                               "controller": True}]},
            "data": {"gateway.json": json.dumps({"gatewayID": 13, "encryption": "none",
                                                    "clients": ["10.42.1.8"]})}}
        self._ack()
        self.probes = []
        self.on_delete = self.replace_pod

    @staticmethod
    def _set_config(pod, config):
        annotations = pod["metadata"]["annotations"]
        raw = json.dumps(config)
        annotations[f.ha.ha_live.PREFIX + "agent-config"] = raw
        annotations[f.ha.ha_live.PREFIX + "agent-hash"] = hashlib.sha256(raw.encode()).hexdigest()

    def _ack(self):
        raw = self.frame[("configmap", GATEWAY, "synthetic")]["data"]["gateway.json"]
        self.frame[("egressgateway", GATEWAY, "synthetic")]["status"]["endpoints"][0][
            "appliedClientConfigHash"] = hashlib.sha256(raw.encode()).hexdigest()

    def create(self, obj):
        self.created_manifest = obj
        return {"kind": "Pod", "namespace": CLIENT_NS, "name": "synthetic-client", "uid": CLIENT_UID}

    def pod_image_id(self, namespace, name, container, uid):
        if (namespace, name, container, uid) != (CLIENT_NS, "synthetic-client", "client", CLIENT_UID):
            raise AssertionError("unapproved selected identity")
        return "image-selected"

    def probe_running(self, name, uid, image_id, phase, api_ip):
        self.probes.append((name, uid, image_id, phase, api_ip))
        return True

    def delete_chosen_gateway_pod(self, namespace, name, uid):
        super().delete_chosen_gateway_pod(namespace, name, uid)
        self.on_delete()

    def replace_pod(self):
        gw = self.frame[("egressgateway", GATEWAY, "synthetic")]
        old = gw["status"]["endpoints"][0]
        new = copy.deepcopy(old)
        new.update(podName="synthetic-1", podUID="abc12345-2222-3333-4444-123456789012",
                   podIP=B)
        gw["status"]["endpoints"] = [new]
        old_pod = self.frame[("pod", GATEWAY, "synthetic-0")]
        new_pod = copy.deepcopy(old_pod)
        new_pod["metadata"].update(name="synthetic-1", uid=new["podUID"])
        new_pod["status"]["podIP"] = B
        self.frame[("pod", GATEWAY, "synthetic-1")] = new_pod
        selected = self.frame[("pod", CLIENT_NS, "synthetic-client")]
        config = json.loads(selected["metadata"]["annotations"][f.ha.ha_live.PREFIX + "agent-config"])
        config["endpoint"] = B
        self._set_config(selected, config)


class GatewayReplacementTest(unittest.TestCase):
    ids = {"selected": "image-selected", "server": "image-server"}
    created = {("EgressGateway", GATEWAY, "synthetic"): GW_UID,
               ("Pod", GATEWAY, "synthetic-vpn"): "abc12345-1111-2222-3333-123456789012"}

    def state(self, api):
        def ready(_api, _uid, ns, _ids):
            gateway = api.get("egressgateway", "synthetic", ns)
            endpoint = gateway["status"]["endpoints"][0]
            pod = api.get("pod", endpoint["podName"], ns)
            return gateway, pod
        with patch.object(f.partial_gateway, "gateway_ready", side_effect=ready):
            return f.gateway_state(api, Owner(), self.ids, GW_UID)

    def test_hash_matches_exact_owned_gateway_json_and_client_membership(self):
        api = API()
        self.assertEqual(self.state(api)["endpoint"], A)
        api.frame[("egressgateway", GATEWAY, "synthetic")]["status"]["endpoints"][0][
            "appliedClientConfigHash"] = "a" * 64
        with self.assertRaises(f.Blocked):
            self.state(api)
        api._ack()
        api.frame[("configmap", GATEWAY, "synthetic")]["data"]["gateway.json"] = json.dumps(
            {"gatewayID": 13, "clients": []})
        api._ack()
        with patch.object(f.evidence, "assert_restricted_client", return_value="10.42.1.8"):
            with self.assertRaises(f.Blocked):
                f.selected_state(api, Owner(), self.ids, self.state(api), CLIENT_UID)

    def test_same_pod_reprogram_after_exactly_one_gateway_delete(self):
        api = API()
        owner = Owner()
        def ready(_api, _uid, ns, _ids):
            gw = api.get("egressgateway", "synthetic", ns)
            endpoint = gw["status"]["endpoints"][0]
            return gw, api.get("pod", endpoint["podName"], ns)
        with (patch.object(f.partial_gateway, "gateway_ready", side_effect=ready),
              patch.object(f.partial_gateway, "source_ready", side_effect=lambda server, *_: server),
              patch.object(f.evidence, "assert_restricted_client", return_value="10.42.1.8"),
              patch.object(f.prepare, "running_probe_pod", return_value={"kind": "Pod", "metadata": {"name": "synthetic-client"}})):
            result = f.replace(api, owner, self.ids, self.created, "10.96.0.1", sleep=lambda _: None)
        self.assertEqual(result["sameSelectedPodUID"], True)
        self.assertEqual(result["establishedFlowContinuity"], "not-asserted")
        self.assertEqual(api.actions, [(GATEWAY, "synthetic-0",
                                        "abcd1234-abcd-1234-abcd-abcd1234abc0")])
        self.assertEqual(len(api.probes), 2)
        self.assertEqual({call[:4] for call in api.probes},
                         {("synthetic-client", CLIENT_UID, "image-selected", "healthy")})
        self.assertEqual(api.created_manifest, {"kind": "Pod", "metadata": {"name": "synthetic-client"}})

    def test_changed_client_uid_is_terminal_after_delete(self):
        api = API()
        def replacement():
            api.replace_pod()
            api.frame[("pod", CLIENT_NS, "synthetic-client")]["metadata"]["uid"] = "changed-client-uid"
        api.on_delete = replacement
        with (patch.object(f.partial_gateway, "gateway_ready", side_effect=lambda _api, _uid, ns, _ids:
               (api.get("egressgateway", "synthetic", ns), api.get("pod",
                api.get("egressgateway", "synthetic", ns)["status"]["endpoints"][0]["podName"], ns))),
              patch.object(f.partial_gateway, "source_ready", side_effect=lambda server, *_: server),
              patch.object(f.evidence, "assert_restricted_client", return_value="10.42.1.8"),
              patch.object(f.prepare, "running_probe_pod", return_value={"kind": "Pod", "metadata": {"name": "synthetic-client"}})):
            with self.assertRaises(f.SelectedUIDChanged):
                f.replace(api, Owner(), self.ids, self.created, "10.96.0.1")
        self.assertEqual(len(api.actions), 1)
        self.assertEqual(len(api.probes), 1)

    def test_stale_applied_hash_never_qualifies_and_times_out(self):
        api = API()
        api.replace_pod()
        api.frame[("egressgateway", GATEWAY, "synthetic")]["status"]["endpoints"][0][
            "appliedClientConfigHash"] = "0" * 64
        now = [0.0]
        def clock():
            return now[0]
        def sleep(seconds):
            now[0] += seconds
        with patch.object(f.partial_gateway, "gateway_ready", side_effect=lambda _api, _uid, ns, _ids:
                          (api.get("egressgateway", "synthetic", ns), api.get("pod", "synthetic-1", ns))):
            with self.assertRaisesRegex(f.Blocked, "replacement-ready"):
                f.await_stage(Owner(), "replacement-ready",
                              lambda: f.gateway_state(api, Owner(), self.ids, GW_UID),
                              seconds=3, clock=clock, sleep=sleep)
        self.assertEqual(now[0], 3.0)

    def test_real_singleton_adapter_baseline_with_owner_and_applied_bytes(self):
        """Exercise production adapter GET/list + evidence, not mocked gateway_ready."""
        import test_evidence
        ns = "rtk-syn-" + "a" * 16
        uid = "a" * 32
        dep_uid, rs_uid, pod_uid = "b" * 32, "c" * 32, "d" * 32
        gw, dep, rs, pod, children = copy.deepcopy(test_evidence.fixture())
        gw["metadata"].update(namespace=ns, uid=uid)
        gw["spec"] = {"replicas": 1}
        gw["status"]["endpoints"][0].update(podName="synthetic-abc123-xyz",
            podUID=pod_uid)
        dep["metadata"].update(namespace=ns, uid=dep_uid)
        dep["metadata"]["ownerReferences"][0]["uid"] = uid
        rs["metadata"].update(namespace=ns, name="synthetic-abc123", uid=rs_uid)
        rs["metadata"]["ownerReferences"][0]["uid"] = dep_uid
        pod["kind"] = "Pod"
        pod["metadata"].update(namespace=ns, name="synthetic-abc123-xyz", uid=pod_uid,
            labels={"ratatoskr.skaldhall.io/gateway-uid": uid,
                    "ratatoskr.skaldhall.io/gateway-name": "synthetic"})
        pod["metadata"]["ownerReferences"][0].update(name="synthetic-abc123", uid=rs_uid)
        for child in children:
            child["metadata"].update(namespace=ns)
            child["metadata"]["ownerReferences"][0]["uid"] = uid
        cm = children[1]
        raw = json.dumps({"gatewayID": 7, "clients": ["10.42.1.8"], "encryption": "none"})
        cm["data"] = {"gateway.json": raw}
        gw["status"]["endpoints"][0]["appliedClientConfigHash"] = hashlib.sha256(raw.encode()).hexdigest()
        objects = {("egressgateway", "synthetic"): gw,
                   ("deployment", "synthetic"): dep,
                   ("replicaset", "synthetic-abc123"): rs,
                   ("pod", "synthetic-abc123-xyz"): pod,
                   **{(kind.lower(), "synthetic"): child for kind, child in zip(
                       ("Service", "ConfigMap", "NetworkPolicy"), children)}}
        gateway_pods = {"kind": "List", "items": [pod]}
        api = f.LifecycleAPI.__new__(f.LifecycleAPI)
        api.owner = type("Owned", (), {"names": (ns, ns + "-apps")})()
        api._namespace = lambda name: name if name == ns else self.fail("foreign namespace")
        def get(argv, *, max_output=262144, payload=None):
            self.assertIsNone(payload)
            self.assertEqual(argv[0], "get")
            if argv[1] == "pods":
                return json.dumps(gateway_pods).encode()
            self.assertIn((argv[1], argv[2]), objects)
            return json.dumps(objects[(argv[1], argv[2])]).encode()
        api._call = Mock(side_effect=get)
        ids = {"gateway": test_evidence.ID, "plugin": test_evidence.ID}
        self.assertEqual(f.gateway_state(api, api.owner, ids, uid)["podUID"], pod_uid)
        gw["status"]["endpoints"][0]["appliedClientConfigHash"] = "0" * 64
        with self.assertRaises(f.StageError) as caught:
            f.gateway_state(api, api.owner, ids, uid)
        self.assertEqual(caught.exception.reason, "gateway-applied-hash")
        gw["status"]["endpoints"][0]["appliedClientConfigHash"] = hashlib.sha256(raw.encode()).hexdigest()
        cm["data"]["gateway.json"] = raw + " "
        with self.assertRaises(f.StageError) as caught:
            f.gateway_state(api, api.owner, ids, uid)
        self.assertEqual(caught.exception.reason, "gateway-applied-hash")

    def test_checkpoint_diagnostics_only_print_fixed_stage_and_reason(self):
        env = {"RATATOSKR_E2E_FINAL_GATE": "1",
               "RATATOSKR_E2E_AGENT_GATEWAY_REPLACEMENT": "1"}
        ids = {component: "sha256:" + "a" * 64 for component in f.run.COMPONENTS}
        for exception, expected in (
                (f.StageError("gateway-baseline", "gateway-applied-hash"),
                 "gateway-baseline/gateway-applied-hash"),
                (f.StageError("replacement-ready", "selected-readiness"),
                 "replacement-ready/selected-readiness"),
                (f.SelectedUIDChanged(), "selected-uid/blocked"),
                (f.adapter.AdapterError("PRIVATE-ADAPTER-RESPONSE"), None)):
            with (self.subTest(exception=type(exception).__name__),
                  patch.object(f.run, "expected_ids", return_value=ids),
                  patch.object(f.run, "preflight", return_value=None),
                  patch.object(f.node_images, "verify", return_value=True),
                  patch.object(f.partial_gateway, "api_service_ip", return_value="10.96.0.1")):
                with redirect_stdout(io.StringIO()) as output:
                    code = f.main(["--execute", "--execute-agent-gateway-replacement"], env,
                                  readonly_factory=lambda: object(),
                                  executor=Mock(side_effect=exception))
                self.assertEqual(code, 1)
                self.assertNotIn("PRIVATE-ADAPTER-RESPONSE", output.getvalue())
                if expected is not None:
                    self.assertIn(expected, output.getvalue())
                else:
                    self.assertIn("gateway replacement blocked", output.getvalue())
        with self.assertRaises(ValueError):
            f.StageError("private-from-API")
        with self.assertRaises(ValueError):
            f.StageError("selected-ready", "private-from-API")

    def test_checkpoint_wraps_private_errors_and_never_retries_delete(self):
        for stage in ("selected-create", "baseline-probe", "gateway-delete",
                      "replacement-probe"):
            with self.subTest(stage=stage):
                calls = Mock(side_effect=f.adapter.AdapterError("PRIVATE-RESPONSE"))
                with self.assertRaises(f.StageError) as caught:
                    f.checkpoint(stage, calls)
                calls.assert_called_once_with()
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(caught.exception.reason, "blocked")
                self.assertNotIn("PRIVATE-RESPONSE", str(caught.exception))

    def test_poll_reasons_are_bounded_and_uid_change_is_terminal(self):
        for error, reason in ((f.StageError("gateway-baseline", "gateway-applied-hash"),
                               "gateway-applied-hash"),
                              (f.adapter.AdapterError("PRIVATE-RESPONSE"), "adapter-read")):
            now = [0.0]
            def clock(): return now[0]
            def sleep(seconds): now[0] += seconds
            def fail(): raise error
            with self.assertRaises(f.StageError) as caught:
                f.await_stage(Owner(), "selected-ready", fail, seconds=3,
                              clock=clock, sleep=sleep)
            self.assertEqual((caught.exception.stage, caught.exception.reason),
                             ("selected-ready", reason))
            self.assertNotIn("PRIVATE-RESPONSE", str(caught.exception))
        called = Mock(side_effect=f.SelectedUIDChanged())
        with self.assertRaises(f.SelectedUIDChanged):
            f.await_stage(Owner(), "replacement-ready", called, seconds=3)
        called.assert_called_once_with()

    def test_final_gate_is_noop_without_both_explicit_flags(self):
        readonly, executor = Mock(), Mock()
        with redirect_stdout(io.StringIO()) as output:
            rc = f.main(["--execute"], {"RATATOSKR_E2E_FINAL_GATE": "1"},
                        readonly_factory=readonly, executor=executor)
        self.assertEqual(rc, 2)
        self.assertIn("SKIPPED", output.getvalue())
        readonly.assert_not_called()
        executor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
