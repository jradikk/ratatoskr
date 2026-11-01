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
