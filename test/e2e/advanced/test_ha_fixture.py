"""HA fixture authoring tests: fake APIs only; no cluster or PKI execution."""
import base64
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import ha_fixture as f
import ha_live as h
from test_ha_live import A, B, CLIENT_NS, GATEWAY, GW_UID, records


class FakeOwner:
    names = (GATEWAY, CLIENT_NS)
    token = "a" * 32
    deadline = 200
    closed = False


class FakeFixtureAPI:
    def __init__(self):
        self.frame = records((A, B), A)
        self.frame[("pod", CLIENT_NS, "synthetic-client")] = self.frame.pop(("pod", CLIENT_NS, "probe"))
        self.frame[("pod", CLIENT_NS, "synthetic-client")]["metadata"]["name"] = "synthetic-client"
        client_annotations = self.frame[("pod", CLIENT_NS, "synthetic-client")]["metadata"]["annotations"]
        import json
        import hashlib
        client_config = json.loads(client_annotations[h.PREFIX + "agent-config"])
        client_config["identity"]["pod"] = "synthetic-client"
        raw = json.dumps(client_config)
        client_annotations[h.PREFIX + "agent-config"] = raw
        client_annotations[h.PREFIX + "agent-hash"] = hashlib.sha256(raw.encode()).hexdigest()
        self.frame[("egressgateway", GATEWAY, "synthetic")]["spec"] = {"replicas": 2, "encryption": "none"}
        self.frame[("deployment", GATEWAY, "synthetic")]["spec"] = {"replicas": 2}
        self.frame[("deployment", GATEWAY, "synthetic")]["status"] = {"readyReplicas": 2}
        for index in range(2):
            pod = self.frame[("pod", GATEWAY, f"synthetic-{index}")]
            pod["status"]["containerStatuses"] = [
                {"name": "gateway", "ready": True, "imageID": "image-gateway"},
                {"name": "upstream", "ready": True, "imageID": "image-plugin"}]
        self.actions = []

    def get(self, kind, name, namespace):
        return self.frame[(kind, namespace, name)]

    def _namespace(self, namespace):
        if namespace != GATEWAY:
            raise ValueError()

    def delete_chosen_gateway_pod(self, namespace, name, uid):
        self.actions.append((namespace, name, uid))


class HAFixtureTest(unittest.TestCase):
    def test_local_duplicate_cn_only_and_two_replicas(self):
        contents = ("ca", "cert", "key", "clientcert", "clientkey", "witnesscert", "witnesskey")
        objects = f.fixture_manifests("rtk-syn-" + "a" * 16, "a" * 32, contents)
        config = base64.b64decode(objects[0]["data"]["server.conf"]).decode()
        self.assertEqual(config, f.prepare.server_config() + "duplicate-cn\n")
        self.assertEqual(objects[6]["spec"]["replicas"], 2)
        self.assertEqual(f.prepare.server_config().count("duplicate-cn"), 0)
        self.assertEqual(objects[1]["data"].keys(), {"client.ovpn"})

    def test_uid_preconditioned_exact_chosen_replica_delete(self):
        api = FakeFixtureAPI()
        before = h.snapshot(lambda _ctx, kind, ns, name: api.get(kind, name, ns),
                            "fixture", GATEWAY, "synthetic", CLIENT_NS, "synthetic-client")
        f.remove_chosen_gateway_pod(api, FakeOwner(), GW_UID, before)
        self.assertEqual(len(api.actions), 1)
        namespace, name, uid = api.actions[0]
        self.assertEqual((namespace, name, uid),
                         (GATEWAY, "synthetic-0", api.get("pod", "synthetic-0", GATEWAY)["metadata"]["uid"]))
        api.frame[("pod", GATEWAY, "synthetic-0")]["metadata"]["uid"] = "changed"
        with self.assertRaises((f.Blocked, h.Blocked)):
            f.remove_chosen_gateway_pod(api, FakeOwner(), GW_UID, before)
        self.assertEqual(len(api.actions), 1)

    def test_real_bounded_delete_discards_large_pod_without_content_or_retry(self):
        import json
        token, namespace_uid = "a" * 32, "b" * 32
        pod_uid = "c" * 32
        class NamespaceAPI:
            def get(self, name, timeout):
                return {"metadata": {"name": name, "uid": namespace_uid,
                        "labels": {f.lifecycle.LABEL: token}}}
        owner = f.lifecycle.Lifecycle(NamespaceAPI(), token_factory=lambda: token)
        owner.deadline = owner.clock() + 60
        owner.seen_absent = set(owner.names)
        owner.attempted = set(owner.names)
        owner.created = {name: namespace_uid for name in owner.names}
        owner.owned = dict(owner.created)
        calls = []
        # Only a fixture-local Python process is run. No kubectl, cluster, or
        # Secret GET occurs; its large output simulates a Kubernetes Pod body.
        def transport(argv, **kwargs):
            calls.append((argv, kwargs))
            self.assertEqual(argv[4:6], ["delete", "--raw=/api/v1/namespaces/" +
                             owner.names[0] + "/pods/synthetic-0"])
            self.assertEqual(kwargs["max_output"], 0)
            self.assertIs(kwargs["discard_output"], True)
            self.assertEqual(kwargs["max_discard"], 1 << 20)
            return f.adapter._bounded(["python3", "-c", "import sys; "
                "sys.stdin.buffer.read(); sys.stdout.buffer.write(b'private-body' * 2000)"], **kwargs)
        api = f.HAFixtureAPI(owner, transport=transport)
        api.get = lambda kind, name, namespace: {"metadata": {"uid": pod_uid}}
        self.assertIsNone(api.delete_chosen_gateway_pod(owner.names[0], "synthetic-0", pod_uid))
        self.assertEqual(len(calls), 1)
        self.assertEqual(json.loads(calls[0][1]["payload"]), {
            "apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": pod_uid},
            "gracePeriodSeconds": 5, "propagationPolicy": "Foreground"})
        self.assertLessEqual(calls[0][1]["timeout"], 12)
        self.assertTrue(api.owner.owned[owner.names[0]] == namespace_uid)

    def test_delete_rejects_oversize_response_foreign_uid_and_name(self):
        token, namespace_uid = "a" * 32, "b" * 32
        class NamespaceAPI:
            def get(self, name, timeout):
                return {"metadata": {"name": name, "uid": namespace_uid,
                        "labels": {f.lifecycle.LABEL: token}}}
        owner = f.lifecycle.Lifecycle(NamespaceAPI(), token_factory=lambda: token)
        owner.deadline = owner.clock() + 60
        owner.seen_absent = set(owner.names)
        owner.attempted = set(owner.names)
        owner.created = {name: namespace_uid for name in owner.names}
        owner.owned = dict(owner.created)
        calls = []
        def oversize(_argv, **kwargs):
            calls.append(kwargs)
            return f.adapter._bounded(["python3", "-c", "import sys; "
                "sys.stdin.buffer.read(); sys.stdout.buffer.write(b'x' * 1048577)"], **kwargs)
        api = f.HAFixtureAPI(owner, transport=oversize)
        api.get = lambda kind, name, namespace: {"metadata": {"uid": "c" * 32}}
        for namespace, name, uid in ((owner.names[1], "synthetic-0", "c" * 32),
                                     (owner.names[0], "foreign-pod", "c" * 32),
                                     (owner.names[0], "synthetic-0", "bad")):
            with self.assertRaises(f.adapter.AdapterError):
                api.delete_chosen_gateway_pod(namespace, name, uid)
        self.assertEqual(len(calls), 0)
        with self.assertRaises(f.adapter.AdapterError) as error:
            api.delete_chosen_gateway_pod(owner.names[0], "synthetic-0", "c" * 32)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("xxxxx", str(error.exception))

    def test_delete_blocks_changed_uid_before_transport(self):
        token, namespace_uid = "a" * 32, "b" * 32
        class NamespaceAPI:
            def get(self, name, timeout):
                return {"metadata": {"name": name, "uid": namespace_uid,
                        "labels": {f.lifecycle.LABEL: token}}}
        owner = f.lifecycle.Lifecycle(NamespaceAPI(), token_factory=lambda: token)
        owner.deadline = owner.clock() + 60
        owner.seen_absent = set(owner.names)
        owner.attempted = set(owner.names)
        owner.created = {name: namespace_uid for name in owner.names}
        owner.owned = dict(owner.created)
        from unittest.mock import Mock
        transport = Mock(return_value=b"")
        api = f.HAFixtureAPI(owner, transport=transport)
        api.get = lambda kind, name, namespace: {"metadata": {"uid": "d" * 32}}
        with self.assertRaises(f.adapter.AdapterError):
            api.delete_chosen_gateway_pod(owner.names[0], "synthetic-0", "c" * 32)
        transport.assert_not_called()

    def test_removed_client_reselect_is_not_new_traffic_proof(self):
        api = FakeFixtureAPI()
        before = h.snapshot(lambda _ctx, kind, ns, name: api.get(kind, name, ns),
                            "fixture", GATEWAY, "synthetic", CLIENT_NS, "synthetic-client")
        api.frame[("egressgateway", GATEWAY, "synthetic")]["status"]["endpoints"] = [
            api.frame[("egressgateway", GATEWAY, "synthetic")]["status"]["endpoints"][1]]
        api.frame[("egressgateway", GATEWAY, "synthetic")]["status"]["readyReplicas"] = 1
        import json
        import hashlib
        annotations = api.frame[("pod", CLIENT_NS, "synthetic-client")]["metadata"]["annotations"]
        config = json.loads(annotations[h.PREFIX + "agent-config"])
        config["endpoint"] = B
        raw = json.dumps(config)
        annotations[h.PREFIX + "agent-config"] = raw
        annotations[h.PREFIX + "agent-hash"] = hashlib.sha256(raw.encode()).hexdigest()
        self.assertEqual(f.reselected(api, FakeOwner(), before)["chosen"], B)

    def test_default_adapter_dynamic_pod_get_requires_status_and_owner(self):
        import json
        from unittest.mock import Mock
        api = FakeFixtureAPI()
        dynamic = f.HAFixtureAPI.__new__(f.HAFixtureAPI)
        dynamic.owner = FakeOwner()
        dynamic._namespace = lambda ns: None if ns == GATEWAY else self.fail("foreign namespace")
        def transport(args, *, max_output=262144, payload=None):
            if args[0] != "get" or args[1] not in {"pod", "egressgateway", "deployment", "replicaset"}:
                self.fail("unexpected fixture GET")
            return json.dumps(api.get(args[1], args[2], GATEWAY)).encode()
        dynamic._call = Mock(side_effect=transport)
        self.assertEqual(dynamic.get("pod", "synthetic-0", GATEWAY)["metadata"]["uid"],
                         api.get("pod", "synthetic-0", GATEWAY)["metadata"]["uid"])
        self.assertEqual(dynamic.get("pod", "synthetic-1", GATEWAY)["metadata"]["uid"],
                         api.get("pod", "synthetic-1", GATEWAY)["metadata"]["uid"])
        self.assertIs(f.execute.__kwdefaults__["adapter_factory"], f.HAFixtureAPI)
        with self.assertRaises(f.adapter.AdapterError):
            dynamic.get("pod", "arbitrary", GATEWAY)
        endpoints = api.get("egressgateway", "synthetic", GATEWAY)["status"]["endpoints"]
        endpoints[0]["appliedClientConfigHash"] = ""
        with self.assertRaises(f.adapter.AdapterError):
            dynamic.get("pod", "synthetic-0", GATEWAY)
        endpoints[0]["appliedClientConfigHash"] = "a" * 64
        api.get("replicaset", "synthetic-rs", GATEWAY)["metadata"]["ownerReferences"] = []
        with self.assertRaises(f.adapter.AdapterError):
            dynamic.get("pod", "synthetic-0", GATEWAY)

    def test_default_adapter_two_gateway_pod_list_requires_owner_labels(self):
        import json
        from unittest.mock import Mock
        api = FakeFixtureAPI()
        dynamic = f.HAFixtureAPI.__new__(f.HAFixtureAPI)
        dynamic.owner = FakeOwner()
        dynamic._namespace = lambda ns: None if ns == GATEWAY else self.fail("foreign namespace")
        gateway_pods = [api.get("pod", f"synthetic-{i}", GATEWAY) for i in range(2)]
        for pod in gateway_pods:
            pod["kind"] = "Pod"
            pod["metadata"]["labels"] = {"ratatoskr.skaldhall.io/gateway-name": "synthetic",
                                         "ratatoskr.skaldhall.io/gateway-uid": GW_UID}
        dynamic._call = Mock(side_effect=lambda _args, *, max_output=32768: json.dumps(
            {"kind": "List", "items": gateway_pods}).encode())
        self.assertEqual(len(dynamic.list_owned_gateway_pods(GATEWAY, GW_UID)), 2)
        gateway_pods[0]["metadata"]["labels"]["ratatoskr.skaldhall.io/gateway-uid"] = "other"
        with self.assertRaises(f.adapter.AdapterError):
            dynamic.list_owned_gateway_pods(GATEWAY, GW_UID)

    def test_stage_is_preserved_after_verified_cleanup(self):
        from unittest.mock import Mock
        ids = {component: "containerd://sha256:" + "f" * 64 for component in f.run.COMPONENTS}

        class Owner:
            names = ("rtk-syn-" + "a" * 16, "rtk-syn-" + "a" * 16 + "-apps")
            token = "a" * 32
            deadline = 500
            closed = False
            private_dir = None
            cleanup_verified = False
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                self.cleanup_verified = True
                # Mirror Lifecycle: unknown exceptions are sanitized after cleanup.
                if exc_type and not issubclass(exc_type, (f.lifecycle.LifecycleError,
                                                          KeyboardInterrupt, SystemExit)):
                    raise f.lifecycle.LifecycleError("Final-gate body failed (details suppressed).")
            def create_namespaces(self):
                return self.names
            def generate_pki(self):
                self.private_dir = "private-test-placeholder"

        owner = Owner()
        adapter = Mock()
        adapter.create.side_effect = f.adapter.AdapterError("raw untrusted API error")
        with patch.object(f.partial_gateway, "private_contents", return_value=("ca", "cert", "key",
                    "clientcert", "clientkey", "witnesscert", "witnesskey")):
            with self.assertRaises(f.StageError) as observed:
                f.execute(ids, "10.43.0.1", lifecycle_factory=lambda **_kw: owner,
                          adapter_factory=lambda _owner: adapter)
        self.assertTrue(owner.cleanup_verified)
        self.assertEqual(str(observed.exception), "HA fixture blocked at fixture-object-create.")
        self.assertNotIn("raw untrusted", str(observed.exception))

    def test_failed_cleanup_overrides_any_stage(self):
        from unittest.mock import Mock
        ids = {component: "containerd://sha256:" + "f" * 64 for component in f.run.COMPONENTS}
        class Owner:
            names = ("rtk-syn-" + "a" * 16, "rtk-syn-" + "a" * 16 + "-apps")
            token = "a" * 32
            deadline = 500
            closed = False
            private_dir = "private-test-placeholder"
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                raise f.lifecycle.LifecycleError("Final-gate cleanup unverified; no PASS permitted.")
            def create_namespaces(self):
                pass
            def generate_pki(self):
                pass
        adapter = Mock()
        adapter.create.side_effect = f.adapter.AdapterError("untrusted")
        with patch.object(f.partial_gateway, "private_contents", return_value=("ca", "cert", "key",
                    "clientcert", "clientkey", "witnesscert", "witnesskey")):
            with self.assertRaisesRegex(f.lifecycle.LifecycleError, "cleanup unverified"):
                f.execute(ids, "10.43.0.1", lifecycle_factory=lambda **_kw: Owner(),
                          adapter_factory=lambda _owner: adapter)

    def test_unexpected_body_error_retains_only_stage(self):
        ids = {component: "containerd://sha256:" + "f" * 64 for component in f.run.COMPONENTS}
        class Owner:
            names = ("rtk-syn-" + "a" * 16, "rtk-syn-" + "a" * 16 + "-apps")
            token = "a" * 32
            deadline = 500
            closed = False
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                pass
            def create_namespaces(self):
                raise RuntimeError("unexpected sensitive Kubernetes response")
        with self.assertRaises(f.StageError) as observed:
            f.execute(ids, "10.43.0.1", lifecycle_factory=lambda **_kw: Owner())
        self.assertEqual(str(observed.exception), "HA fixture blocked at owned-namespaces-create.")
        self.assertNotIn("sensitive", str(observed.exception))

    def test_checkpoint_does_not_leak_untrusted_details_to_cli(self):
        from unittest.mock import Mock
        ids = {component: "containerd://sha256:" + "f" * 64 for component in f.run.COMPONENTS}
        env = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_HA_FIXTURE": "1", **{
            "EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in ids.items()}}
        printed = io.StringIO()
        with (patch.object(f.run, "preflight", return_value="operator"),
              patch.object(f.node_images, "verify", return_value=True),
              patch.object(f.partial_gateway, "api_service_ip", return_value="10.43.0.1"),
              redirect_stdout(printed)):
            result = f.main(["--execute", "--execute-ha-fixture"], environ=env,
                            readonly_factory=Mock(),
                            executor=lambda *_: (_ for _ in ()).throw(f.StageError("fixture-object-create")))
        self.assertEqual(result, 1)
        self.assertIn("fixture-object-create", printed.getvalue())
        self.assertNotIn("10.43.0.1", printed.getvalue())
        self.assertNotIn("containerd://", printed.getvalue())

    def test_cleanup_failure_reports_distinct_message(self):
        from unittest.mock import Mock
        ids = {component: "containerd://sha256:" + "f" * 64 for component in f.run.COMPONENTS}
        env = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_HA_FIXTURE": "1", **{
            "EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in ids.items()}}
        printed = io.StringIO()
        with (patch.object(f.run, "preflight", return_value="operator"),
              patch.object(f.node_images, "verify", return_value=True),
              patch.object(f.partial_gateway, "api_service_ip", return_value="10.43.0.1"),
              redirect_stdout(printed)):
            result = f.main(["--execute", "--execute-ha-fixture"], environ=env,
                            readonly_factory=Mock(), executor=lambda *_: (_ for _ in ()).throw(
                                f.lifecycle.LifecycleError("untrusted cleanup internals")))
        self.assertEqual(result, 1)
        self.assertIn("cleanup unverified", printed.getvalue())
        self.assertNotIn("untrusted", printed.getvalue())

    def test_real_adapter_accepts_exact_running_pod_create_input(self):
        import json
        from unittest.mock import Mock
        token = "a" * 32
        uid = "b" * 32
        class NamespaceAPI:
            def get(self, name, timeout):
                return {"metadata": {"name": name, "uid": uid,
                        "labels": {f.lifecycle.LABEL: token}}}
        owner = f.lifecycle.Lifecycle(NamespaceAPI(), token_factory=lambda: token)
        owner.deadline = owner.clock() + 120
        owner.seen_absent = set(owner.names)
        owner.attempted = set(owner.names)
        owner.created = {name: uid for name in owner.names}
        owner.owned = dict(owner.created)
        def transport(argv, *, payload=None, timeout, max_output):
            self.assertIn("create", argv)
            self.assertLessEqual(timeout, 12)
            obj = json.loads(payload)
            self.assertEqual(obj, f.prepare.running_probe_pod(owner.names[1], owner.names[0], "10.43.0.1"))
            self.assertEqual(obj["spec"]["containers"][0]["env"][1],
                             {"name": "API_IP", "value": "10.43.0.1"})
            return ("v1\tPod\t" + owner.names[1] + "\tsynthetic-client\t" + uid).encode()
        wire = Mock(side_effect=transport)
        actual = f.HAFixtureAPI(owner, transport=wire)
        created = actual.create(f.prepare.running_probe_pod(owner.names[1], owner.names[0], "10.43.0.1"))
        self.assertEqual(created, {"kind": "Pod", "namespace": owner.names[1],
                                   "name": "synthetic-client", "uid": uid})
        self.assertEqual(wire.call_count, 1)
        # The first POST is quarantined; no ambiguous second attempt.
        with self.assertRaises(f.StageError) as failure:
            actual.create(f.prepare.running_probe_pod(owner.names[1], owner.names[0], "10.43.0.1"))
        self.assertIn("submitted-or-uncertain", str(failure.exception))
        self.assertEqual(wire.call_count, 1)

    def test_selected_create_classifies_before_vs_after_first_post(self):
        from unittest.mock import Mock
        token, uid = "a" * 32, "b" * 32
        class NamespaceAPI:
            def get(self, name, timeout):
                return {"metadata": {"name": name, "uid": uid,
                        "labels": {f.lifecycle.LABEL: token}}}
        def fixture(transport):
            owner = f.lifecycle.Lifecycle(NamespaceAPI(), token_factory=lambda: token)
            owner.deadline = owner.clock() + 120
            owner.seen_absent = set(owner.names)
            owner.attempted = set(owner.names)
            owner.created = {name: uid for name in owner.names}
            owner.owned = dict(owner.created)
            return f.HAFixtureAPI(owner, transport=transport), owner
        wire = Mock(side_effect=AssertionError("must not send malformed manifest"))
        api, owner = fixture(wire)
        malformed = f.prepare.running_probe_pod(owner.names[1], owner.names[0], "10.43.0.1")
        malformed["spec"]["containers"][0]["command"] = ["sh", "-c", "unsafe"]
        with self.assertRaises(f.StageError) as failure:
            api.create(malformed)
        self.assertIn("local-validation", str(failure.exception))
        self.assertFalse(api.create_attempts)
        wire.assert_not_called()
        def failed_transport(*_args, **_kwargs):
            raise f.adapter.AdapterError("untrusted credential or admission output")
        wire = Mock(side_effect=failed_transport)
        api, owner = fixture(wire)
        manifest = f.prepare.running_probe_pod(owner.names[1], owner.names[0], "10.43.0.1")
        with self.assertRaises(f.StageError) as failure:
            api.create(manifest)
        self.assertIn("submitted-or-uncertain", str(failure.exception))
        self.assertNotIn("credential", str(failure.exception))
        self.assertEqual(api.create_attempts, {("Pod", owner.names[1], "synthetic-client")})
        self.assertEqual(wire.call_count, 1)

    def test_missing_gate_never_constructs_kube_api(self):
        with patch.object(f.run, "ReadOnlyAPI") as api, redirect_stdout(io.StringIO()):
            result = f.main([], environ={})
        self.assertEqual(result, 2)
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
