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


class AgentReader:
    """Strict fake read-only release API; never runs Kubernetes commands."""
    namespace = "ratatoskr-system"
    daemon_uid = "12345678-1234-1234-1234-123456789abc"
    old_uid = "aaaaaaaa-1234-1234-1234-123456789abc"
    new_uid = "bbbbbbbb-1234-1234-1234-123456789abc"
    image = "containerd://sha256:" + "a" * 64
    node = f.node_images.NODES[1]

    def __init__(self):
        self.new = False
        self.pods = None
        self.changed_daemon = False
        self.wrong_image = False
        self.wrong_node = False
        self.wrong_owner = False
        self.calls = []

    def get(self, kind, name=None, namespace=None, selector=None):
        self.calls.append((kind, name, namespace, selector))
        assert namespace == self.namespace
        labels = {"app.kubernetes.io/name": "ratatoskr",
                  "app.kubernetes.io/instance": "ratatoskr",
                  "app.kubernetes.io/component": "agent"}
        if kind == "daemonset":
            assert name == "ratatoskr-agent" and selector is None
            return {"metadata": {"name": name, "namespace": namespace,
                                 "uid": self.new_uid if self.changed_daemon else self.daemon_uid},
                    "spec": {"selector": {"matchLabels": labels},
                             "template": {"metadata": {"labels": labels}, "spec": {
                                 "containers": [{"name": "agent", "image": "ratatoskr-agent:local",
                                                 "imagePullPolicy": "Never"}]}}}}
        assert kind == "pods" and name is None
        assert selector == ",".join(k + "=" + v for k, v in sorted(labels.items()))
        if self.pods is not None:
            return {"kind": "List", "items": self.pods}
        return {"kind": "List", "items": [self.pod(labels)]}

    def pod(self, labels=None):
        labels = labels or {"app.kubernetes.io/name": "ratatoskr",
                            "app.kubernetes.io/instance": "ratatoskr",
                            "app.kubernetes.io/component": "agent"}
        return {"kind": "Pod", "metadata": {"uid": self.new_uid if self.new else self.old_uid,
                "namespace": self.namespace, "labels": labels,
                "ownerReferences": [{"kind": "DaemonSet", "uid":
                                    self.old_uid if self.wrong_owner else self.daemon_uid,
                                    "controller": True}]},
                "spec": {"nodeName": f.node_images.NODES[2] if self.wrong_node else self.node,
                         "containers": [{"name": "agent", "image": "ratatoskr-agent:local",
                                         "imagePullPolicy": "Never"}]},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                           "containerStatuses": [{"name": "agent", "ready": True,
                            "imageID": "other-image" if self.wrong_image else self.image}]}}


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

    def test_release_agent_owner_node_image_and_single_live_pod(self):
        reader = AgentReader()
        self.assertEqual(f.agent_snapshot(reader, reader.namespace, reader.node, reader.image),
                         {"daemonUID": reader.daemon_uid, "agentUID": reader.old_uid,
                          "node": reader.node})
        for wrong, reason in (("wrong_node", "agent-node"), ("wrong_image", "agent-runtime"),
                              ("wrong_owner", "agent-runtime"), ("changed_daemon", "agent-owner")):
            with self.subTest(wrong=wrong):
                setattr(reader, wrong, True)
                with self.assertRaises(f.StageError) as caught:
                    f.agent_snapshot(reader, reader.namespace, reader.node, reader.image,
                                     expected_ds_uid=reader.daemon_uid)
                self.assertEqual(caught.exception.reason, reason)
                setattr(reader, wrong, False)
        reader.pods = [reader.pod(), reader.pod()]
        with self.assertRaises(f.StageError) as caught:
            f.agent_snapshot(reader, reader.namespace, reader.node, reader.image)
        self.assertEqual(caught.exception.reason, "agent-node")
        reader.pods[0]["metadata"]["deletionTimestamp"] = "2026-10-01T00:00:00Z"
        reader.new = True
        reader.pods[1]["metadata"]["uid"] = reader.new_uid
        self.assertEqual(f.agent_snapshot(reader, reader.namespace, reader.node, reader.image)["agentUID"],
                         reader.new_uid)
        with self.assertRaises(f.StageError):
            f.agent_snapshot(reader, "foreign_namespace", reader.node, reader.image)
        self.assertEqual({call[0] for call in reader.calls}, {"daemonset", "pods"})

    def test_passive_restart_wait_requires_new_uid_and_fresh_probe(self):
        api, reader, owner = API(), AgentReader(), Owner()
        api.frame[("pod", CLIENT_NS, "synthetic-client")]["spec"]["nodeName"] = reader.node
        ids = {**self.ids, "agent": reader.image}
        gateway = self.state(api)
        calls = []
        def ready(node, agent_uid, ds_uid):
            calls.append((node, agent_uid, ds_uid))
            reader.new = True  # external parent action, NOT fixture mutation
        with (patch.object(f, "selected_state", side_effect=lambda *_: api.get(
                "pod", "synthetic-client", CLIENT_NS)),
              patch.object(f, "gateway_state", return_value=gateway)):
            self.assertTrue(f.external_agent_restart(api, owner, ids, gateway, CLIENT_UID,
                                                      "10.96.0.1", readonly=reader,
                                                      release_namespace=reader.namespace,
                                                      ready_callback=ready))
        self.assertEqual(calls, [(reader.node, reader.old_uid, reader.daemon_uid)])
        self.assertEqual(len(api.probes), 1)
        self.assertEqual(api.probes[0][1], CLIENT_UID)
        self.assertEqual(api.actions, [])  # observer never deletes DaemonSet Pods

    def test_unchanged_agent_uid_times_out_without_probe(self):
        api, reader, owner = API(), AgentReader(), Owner()
        api.frame[("pod", CLIENT_NS, "synthetic-client")]["spec"]["nodeName"] = reader.node
        ids = {**self.ids, "agent": reader.image}
        gateway = self.state(api)
        now = [0.0]
        owner.deadline = 200
        owner.clock = lambda: now[0]
        def clock(): return now[0]
        def sleep(seconds): now[0] += seconds
        with (patch.object(f, "selected_state", side_effect=lambda *_: api.get(
                "pod", "synthetic-client", CLIENT_NS)),
              patch.object(f, "gateway_state", return_value=gateway)):
            with self.assertRaises(f.StageError) as caught:
                f.external_agent_restart(api, owner, ids, gateway, CLIENT_UID,
                                         "10.96.0.1", readonly=reader,
                                         release_namespace=reader.namespace,
                                         ready_callback=lambda *_: None, clock=clock, sleep=sleep)
        self.assertEqual(caught.exception.stage, "agent-restart-ready")
        self.assertEqual(now[0], 150)
        self.assertEqual(api.probes, [])

    def test_restart_selected_uid_change_is_terminal_and_probe_failure_blocks(self):
        api, reader, owner = API(), AgentReader(), Owner()
        api.frame[("pod", CLIENT_NS, "synthetic-client")]["spec"]["nodeName"] = reader.node
        ids = {**self.ids, "agent": reader.image}
        gateway = self.state(api)
        with (patch.object(f, "selected_state", side_effect=lambda *_: api.get(
                "pod", "synthetic-client", CLIENT_NS)),
              patch.object(f, "gateway_state", return_value=gateway)):
            def replaced_uid(*_):
                reader.new = True
                api.frame[("pod", CLIENT_NS, "synthetic-client")]["metadata"]["uid"] = "foreign-client-uid"
            with self.assertRaises(f.SelectedUIDChanged):
                f.external_agent_restart(api, owner, ids, gateway, CLIENT_UID,
                                         "10.96.0.1", readonly=reader,
                                         release_namespace=reader.namespace, ready_callback=replaced_uid)
            self.assertEqual(api.probes, [])
            api.frame[("pod", CLIENT_NS, "synthetic-client")]["metadata"]["uid"] = CLIENT_UID
            reader.new = False
            api.probe_running = Mock(return_value=False)
            def restart_again(*_): reader.new = True
            with self.assertRaises(f.StageError) as caught:
                f.external_agent_restart(api, owner, ids, gateway, CLIENT_UID,
                                         "10.96.0.1", readonly=reader,
                                         release_namespace=reader.namespace,
                                         ready_callback=restart_again)
            self.assertEqual(caught.exception.stage, "agent-restart-probe")
            api.probe_running.assert_called_once()

    def test_restart_opt_in_gate_and_default_are_separate(self):
        env = {"RATATOSKR_E2E_FINAL_GATE": "1",
               "RATATOSKR_E2E_AGENT_GATEWAY_REPLACEMENT": "1"}
        readonly, executor = Mock(), Mock()
        with redirect_stdout(io.StringIO()) as output:
            rc = f.main(["--execute", "--execute-agent-gateway-replacement",
                         "--wait-external-agent-restart"], env,
                        readonly_factory=readonly, executor=executor)
        self.assertEqual(rc, 2)
        self.assertIn("SKIPPED", output.getvalue())
        readonly.assert_not_called()
        executor.assert_not_called()

    def test_opt_in_main_pins_release_daemon_uid_and_emits_only_fixed_ready(self):
        env = {"RATATOSKR_E2E_FINAL_GATE": "1",
               "RATATOSKR_E2E_AGENT_GATEWAY_REPLACEMENT": "1",
               "RATATOSKR_E2E_AGENT_RESTART": "1"}
        ids = {component: AgentReader.image for component in f.run.COMPONENTS}
        release = AgentReader()
        readonly = Mock()
        readonly.get.side_effect = lambda kind, name, namespace: {
            "metadata": {"uid": release.daemon_uid}} if (kind, name, namespace) == (
                "daemonset", "ratatoskr-agent", release.namespace) else self.fail("unexpected preflight GET")
        result = {"sameSelectedPodUID": True, "newGatewayPodUIDAndIP": True,
                  "newConnectionMarker": True, "establishedFlowContinuity": "not-asserted",
                  "agentRestart": "observed", "agentRestartObserved": True}
        def execute(*_args, **kw):
            self.assertEqual(kw["release_namespace"], release.namespace)
            self.assertEqual(kw["expected_daemon_uid"], release.daemon_uid)
            self.assertIs(kw["restart_reader"], release)
            kw["ready_callback"](release.node, release.old_uid, release.daemon_uid)
            return result
        with (patch.object(f.run, "expected_ids", return_value=ids),
              patch.object(f.run, "preflight", return_value=release.namespace),
              patch.object(f.node_images, "verify", return_value=True),
              patch.object(f.partial_gateway, "api_service_ip", return_value="10.96.0.1")):
            with redirect_stdout(io.StringIO()) as output:
                rc = f.main(["--execute", "--execute-agent-gateway-replacement",
                             "--wait-external-agent-restart"], env,
                            readonly_factory=lambda: readonly,
                            restart_reader_factory=lambda **kw: release,
                            executor=execute)
        self.assertEqual(rc, 4)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("READY:"))
        self.assertTrue(lines[1].startswith("PARTIAL:"))
        self.assertNotIn(release.old_uid, output.getvalue())
        readonly.get.assert_called_once_with("daemonset", "ratatoskr-agent", release.namespace)

    def test_opt_in_rejects_changed_preflight_daemon_uid_before_fixture(self):
        env = {"RATATOSKR_E2E_FINAL_GATE": "1",
               "RATATOSKR_E2E_AGENT_GATEWAY_REPLACEMENT": "1",
               "RATATOSKR_E2E_AGENT_RESTART": "1"}
        ids = {component: AgentReader.image for component in f.run.COMPONENTS}
        reader, executor = AgentReader(), Mock()
        readonly = Mock()
        readonly.get.return_value = {"metadata": {"uid": "not-a-uid"}}
        with (patch.object(f.run, "expected_ids", return_value=ids),
              patch.object(f.run, "preflight", return_value=reader.namespace)):
            with redirect_stdout(io.StringIO()) as output:
                code = f.main(["--execute", "--execute-agent-gateway-replacement",
                               "--wait-external-agent-restart"], env,
                              readonly_factory=lambda: readonly, executor=executor)
        self.assertEqual(code, 1)
        self.assertIn("agent-baseline/agent-owner", output.getvalue())
        executor.assert_not_called()

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
