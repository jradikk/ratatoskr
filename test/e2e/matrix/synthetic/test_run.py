#!/usr/bin/env python3
"""Cluster-free synthetic preflight contracts. No Docker, OpenSSL or kubectl."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_run", HERE / "run.py")
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
DIGEST = "containerd://sha256:" + "a" * 64
IDS = {component: DIGEST for component in run.COMPONENTS}


def node(control=False, name=""):
    return {"metadata": {"name": name, "labels": {"node-role.kubernetes.io/control-plane": ""} if control else {}},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}}


def pod(component, owner_kind, owner_uid):
    return {"metadata": {"ownerReferences": [{"kind": owner_kind, "name": owner_uid, "uid": owner_uid,
                                               "controller": True}]},
            "spec": {"containers": [{"name": component, "image": component + ":local", "imagePullPolicy": "Never"}]},
            "status": {"conditions": [{"type": "Ready", "status": "True"}],
                       "containerStatuses": [{"name": component, "ready": True, "imageID": DIGEST}]}}


def deployment(component):
    return {"metadata": {"uid": component + "-uid", "generation": 1},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": component}},
                     "template": {"spec": {"containers": [{"name": component, "image": component + ":local",
                         "imagePullPolicy": "Never", "env": [
                         {"name": "DRIVER", "value": "agent"}, {"name": "DATAPATH", "value": "iproute"},
                         {"name": "GATEWAY_UPSTREAM_PROBE_URL", "value": run.PROBE},
                         {"name": "IMAGE_PULL_POLICY", "value": "Never"},
                         {"name": "GATEWAY_IMAGE", "value": "ghcr.io/skaldhall/ratatoskr-gateway:dev"},
                         {"name": "OPENVPN_IMAGE", "value": "ghcr.io/skaldhall/ratatoskr-upstream-openvpn:dev"},
                         {"name": "INIT_IMAGE", "value": "ratatoskr-tools:m1-local"}]}]}}},
            "status": {"observedGeneration": 1, "availableReplicas": 1, "updatedReplicas": 1,
                       "readyReplicas": 1}}


class FakeAPI:
    def __init__(self):
        self.objects = {
            ("nodes", None, None, None): {"items": [node(True, run.node_images.NODES[0]),
                                                  node(False, run.node_images.NODES[1]),
                                                  node(False, run.node_images.NODES[2])]},
            ("configmap", "ratatoskr-testenv", "kube-system", None):
                {"data": {"variant": "flannel", "mesh": "none"}},
        }
        paths = [("pods.ratatoskr.skaldhall.io", "/mutate-v1alpha1-pod"),
                 ("pods.ratatoskr.skaldhall.io", "/validate-v1alpha1"),
                 ("egressgateways.ratatoskr.skaldhall.io", "/validate-v1alpha1"),
                 ("egresspolicies.ratatoskr.skaldhall.io", "/validate-v1alpha1")]
        hooks = [{"name": name, "failurePolicy": "Fail", "sideEffects": "None",
                  "objectSelector": {"matchExpressions": [{"key": "ratatoskr.skaldhall.io/gateway",
                                                            "operator": "Exists"}]} if name.startswith("pods.") else None,
                  "rules": [{"resources": [name.split(".")[0]],
                             "operations": ["CREATE"] if path == "/mutate-v1alpha1-pod" else ["CREATE", "UPDATE"]}],
                  "clientConfig": {"caBundle": "public", "service": {"namespace": "operator", "path": path}}}
                 for name, path in paths]
        self.objects[("mutatingwebhookconfiguration", "ratatoskr-pods", None, None)] = {"webhooks": hooks[:1]}
        self.objects[("validatingwebhookconfiguration", "ratatoskr-validation", None, None)] = {"webhooks": hooks[1:]}
        for component in ("controller", "webhook"):
            name = "ratatoskr-" + component
            self.objects[("deployment", name, "operator", None)] = deployment(component)
            self.objects[("pods", None, "operator", "app=" + component)] = (
                {"items": [pod(component, "ReplicaSet", component + "-rs")]})
            self.objects[("replicaset", component + "-rs", "operator", None)] = (
                {"metadata": {"uid": component + "-rs", "ownerReferences": [
                    {"kind": "Deployment", "uid": component + "-uid", "controller": True}]}})
        self.objects[("daemonset", "ratatoskr-agent", "operator", None)] = {
            "metadata": {"uid": "agent-uid", "generation": 1},
            "spec": {"selector": {"matchLabels": {"app": "agent"}},
                     "template": {"spec": {"containers": [{"name": "agent", "image": "agent:local",
                                                           "imagePullPolicy": "Never",
                                                           "env": [{"name": "DATAPATH", "value": "iproute"}]}]}}},
            "status": {"observedGeneration": 1, "desiredNumberScheduled": 3,
                       "updatedNumberScheduled": 3, "numberReady": 3}}
        self.objects[("pods", None, "operator", "app=agent")] = {
            "items": [pod("agent", "DaemonSet", "agent-uid") for _ in range(3)]}
        self.calls = []

    def get(self, resource, name=None, namespace=None, selector=None):
        self.calls.append((resource, name, namespace, selector))
        return self.objects[(resource, name, namespace, selector)]


class GateTests(unittest.TestCase):
    def test_disabled_does_not_access_api(self):
        def forbidden():
            raise AssertionError("unauthorized cluster access")
        for argv, env in (([], {}), (["--execute"], {}), ([], {"RATATOSKR_E2E_FINAL_GATE": "1"})):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.main(argv, env, forbidden), 2)

    def test_partial_smoke_triple_opt_in_without_cluster_mutation(self):
        called = []
        def api():
            called.append(True)
            return FakeAPI()
        ids = {"EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in IDS.items()}
        for argv, env in ((["--execute", "--allow-partial-vpn-smoke"],
                           dict(ids, RATATOSKR_E2E_FINAL_GATE="1")),
                          (["--allow-partial-vpn-smoke"],
                           dict(ids, RATATOSKR_E2E_FINAL_GATE="1", RATATOSKR_E2E_PARTIAL_VPN_SMOKE="1")),
                          (["--execute", "--allow-partial-vpn-smoke"],
                           dict(ids, RATATOSKR_E2E_PARTIAL_VPN_SMOKE="1"))):
            with self.subTest(argv=argv), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.main(argv, env, api), 2)
        self.assertFalse(called)
        env = dict(ids, RATATOSKR_E2E_FINAL_GATE="1", RATATOSKR_E2E_PARTIAL_VPN_SMOKE="1")
        out = io.StringIO()
        checked = []
        def fake_nodes(images, *, init):
            self.assertFalse(init)
            checked.append(images)
            return True
        with contextlib.redirect_stdout(out):
            self.assertEqual(run.main(["--execute", "--allow-partial-vpn-smoke"], env, api,
                                      fake_nodes), 4)
        self.assertEqual(len(called), 1)
        self.assertEqual(checked, [{k: IDS[k] for k in run.node_images.TAGS}])
        self.assertIn("three-node CRI config image IDs matched", out.getvalue())
        self.assertIn("No resources, PKI or Pods created", out.getvalue())
        self.assertNotIn("PASSED", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run.main(["--execute", "--allow-partial-vpn-smoke"], env,
                                      lambda: FakeAPI(),
                                      lambda _ids, **_kw: (_ for _ in ()).throw(run.node_images.Blocked("SECRET"))), 1)

    def test_read_only_api_service_cluster_ip_contract(self):
        import partial_gateway
        class Service:
            def get(self, kind, name, namespace):
                self.calls = (kind, name, namespace)
                return {"metadata": {"name": "kubernetes", "namespace": "default"},
                        "spec": {"type": "ClusterIP", "clusterIP": "10.43.0.1"}}
        api = Service()
        self.assertEqual(partial_gateway.api_service_ip(api), "10.43.0.1")
        self.assertEqual(api.calls, ("service", "kubernetes", "default"))

    def test_fourth_gateway_mutation_flag_requires_all_other_gates(self):
        seen = []
        def smoke(_ids, *, api_ip):
            seen.append(("smoke", api_ip))
            return False
        env = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_PARTIAL_VPN_SMOKE": "1"}
        env.update({"EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in IDS.items()})
        for args, vars in (
                (["--execute", "--execute-partial-gateway"], env),
                (["--execute", "--allow-partial-vpn-smoke", "--execute-partial-gateway"],
                 dict(env, RATATOSKR_E2E_PARTIAL_VPN_SMOKE="0")),
                (["--allow-partial-vpn-smoke", "--execute-partial-gateway"], env)):
            with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.main(args, vars, lambda: (_ for _ in ()).throw(AssertionError("API called")),
                                          lambda _ids: (_ for _ in ()).throw(AssertionError("CRI called")), smoke), 2)
        self.assertEqual(seen, [])
        output = io.StringIO()
        class SmokeAPI(FakeAPI):
            def get(self, resource, name=None, namespace=None, selector=None):
                if (resource, name, namespace) == ("service", "kubernetes", "default"):
                    return {"metadata": {"name": name, "namespace": namespace},
                            "spec": {"type": "ClusterIP", "clusterIP": "10.43.0.1"}}
                return super().get(resource, name, namespace, selector)
        with contextlib.redirect_stdout(output):
            self.assertEqual(run.main(["--execute", "--allow-partial-vpn-smoke", "--execute-partial-gateway"],
                                      env, SmokeAPI, lambda _ids, **_kw: True, smoke), 4)
        self.assertEqual(seen, [("smoke", "10.43.0.1")])
        self.assertIn("INCOMPLETE", output.getvalue())
        self.assertIn("selected tunnel attribution, fail-close, witness and recovery NOT TESTED", output.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run.main(["--execute", "--allow-partial-vpn-smoke", "--execute-partial-gateway"],
                                      env, SmokeAPI, lambda _ids, **_kw: True,
                                      lambda _ids, **_kw: (_ for _ in ()).throw(RuntimeError("SECRET"))), 1)
        self.assertEqual(seen, [("smoke", "10.43.0.1")])
    def test_outage_cli_reports_fixed_body_stage_vs_true_cleanup_failure(self):
        env = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_PARTIAL_VPN_SMOKE": "1",
               "RATATOSKR_E2E_AGENT_OUTAGE": "1"}
        env.update({"EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in IDS.items()})
        class SmokeAPI(FakeAPI):
            def get(self, resource, name=None, namespace=None, selector=None):
                if (resource, name, namespace) == ("service", "kubernetes", "default"):
                    return {"metadata": {"name": name, "namespace": namespace},
                            "spec": {"type": "ClusterIP", "clusterIP": "10.43.0.1"}}
                return super().get(resource, name, namespace, selector)
        args = ["--execute", "--allow-partial-vpn-smoke", "--execute-agent-outage"]
        # Standalone test imports the same synthetic module via run.py path.
        import outage
        for failure, expected, forbidden in (
                (outage.Blocked("Synthetic outage body blocked at withdrawn-selected-fail-close."),
                 "withdrawn-selected-fail-close", "lifecycle unverified"),
                (outage.RestoreBlocked("Synthetic outage probe-switch restoration unverified."),
                 "probe-switch restoration unverified", "withdrawn-selected-fail-close"),
                (outage.lifecycle.LifecycleError("Final-gate cleanup unverified (namespace)."),
                 "lifecycle unverified", "withdrawn-selected-fail-close")):
            with self.subTest(expected=expected):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    result = run.main(args, env, SmokeAPI, lambda _ids, **_kw: None,
                                      lambda _ids, **_kw: (_ for _ in ()).throw(failure))
                self.assertEqual(result, 1)
                self.assertIn(expected, output.getvalue())
                self.assertNotIn(forbidden, output.getvalue())

    def test_gateway_smoke_blocks_stale_controller_image_refs_before_mutation(self):
        env = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_PARTIAL_VPN_SMOKE": "1"}
        env.update({"EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in IDS.items()})
        api = FakeAPI()
        config = api.objects[("deployment", "ratatoskr-controller", "operator", None)]
        values = config["spec"]["template"]["spec"]["containers"][0]["env"]
        next(item for item in values if item["name"] == "OPENVPN_IMAGE")["value"] = "stale:local"
        called = []
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run.main(["--execute", "--allow-partial-vpn-smoke", "--execute-partial-gateway"],
                                      env, lambda: api, lambda _ids, **_kw: True,
                                      lambda _ids: called.append(True)), 1)
        self.assertEqual(called, [])

    def test_partial_smoke_missing_image_id_fails_before_api(self):
        env = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_PARTIAL_VPN_SMOKE": "1"}
        def forbidden():
            raise AssertionError("image preflight should not contact cluster")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run.main(["--execute", "--allow-partial-vpn-smoke"], env, forbidden), 1)

    def test_expected_ids_all_mandatory_immutable(self):
        env = {"EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in IDS.items()}
        self.assertEqual(run.expected_ids(env), IDS)
        for key in env:
            for invalid in ("", "example:latest", "sha256:" + "g" * 64):
                altered = dict(env, **{key: invalid})
                with self.assertRaises(run.Blocked):
                    run.expected_ids(altered)

    def test_outage_cli_requires_separate_flag_and_never_awards_full_pass(self):
        env = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_PARTIAL_VPN_SMOKE": "1"}
        env.update({"EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in IDS.items()})
        args = ["--execute", "--allow-partial-vpn-smoke", "--execute-agent-outage"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(run.main(args, env, lambda: (_ for _ in ()).throw(AssertionError("API called"))), 2)
        self.assertIn("SKIPPED", output.getvalue())
        env["RATATOSKR_E2E_AGENT_OUTAGE"] = "1"
        called = []
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(run.main(args, env, lambda: FakeAPI(),
                                      lambda _ids, **_kw: None,
                                      lambda _ids, **kw: called.append(kw)), 1)
        # FakeAPI does not expose a complete Kubernetes Service; fail closed
        # before resource creation even when explicit outage opt-in is present.
        self.assertEqual(called, [])
        api = FakeAPI()
        api.objects[("service", "kubernetes", "default", None)] = {"metadata": {
            "name": "kubernetes", "namespace": "default"},
            "spec": {"clusterIP": "10.43.0.1", "type": "ClusterIP"}}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(run.main(args, env, lambda: api,
                                      lambda _ids, **_kw: None,
                                      lambda _ids, **kw: called.append(kw)), 4)
        self.assertEqual(called, [{"api_ip": "10.43.0.1"}])
        self.assertIn("INCOMPLETE", output.getvalue())
        self.assertNotIn("full M8 PASS.", output.getvalue().replace("No full M8 PASS.", ""))

    def test_positive_preflight_never_awards_e2e(self):
        api = FakeAPI()
        self.assertEqual(run.preflight(api, IDS), "operator")
        env = {"RATATOSKR_E2E_FINAL_GATE": "1"}
        env.update({"EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in IDS.items()})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(run.main(["--execute"], env, lambda: api), 4)
        self.assertIn("INCOMPLETE", output.getvalue())
        self.assertNotIn("PASSED", output.getvalue())
        self.assertTrue(all(call[0] not in ("secret", "logs") for call in api.calls))

    def test_safety_breaks_fail_closed(self):
        mutations = [
            lambda a: a.objects[("nodes", None, None, None)]["items"][0]["metadata"].update(name="foreign-control-plane"),
            lambda a: a.objects[("nodes", None, None, None)]["items"].pop(),
            lambda a: a.objects[("configmap", "ratatoskr-testenv", "kube-system", None)]["data"].update(variant="cilium"),
            lambda a: a.objects[("deployment", "ratatoskr-controller", "operator", None)]["spec"]["template"]["spec"]["containers"][0]["env"][2].update(value=""),
            lambda a: a.objects[("pods", None, "operator", "app=agent")]["items"][0]["status"]["containerStatuses"][0].update(imageID="sha256:bad"),
            lambda a: a.objects[("validatingwebhookconfiguration", "ratatoskr-validation", None, None)]["webhooks"][0].update(failurePolicy="Ignore"),
            lambda a: a.objects[("mutatingwebhookconfiguration", "ratatoskr-pods", None, None)]["webhooks"][0].update(rules=[]),
            lambda a: a.objects[("daemonset", "ratatoskr-agent", "operator", None)]["status"].update(updatedNumberScheduled=2),
            lambda a: a.objects[("deployment", "ratatoskr-webhook", "operator", None)]["status"].update(updatedReplicas=0),
            lambda a: a.objects[("pods", None, "operator", "app=agent")]["items"][0]["spec"]["containers"][0].update(imagePullPolicy="Always"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                api = FakeAPI()
                mutate(api)
                with self.assertRaises(run.Blocked):
                    run.preflight(api, IDS)

    def test_api_no_raw_errors_or_mutations(self):
        original = subprocess.run
        try:
            def fake(args, **_kwargs):
                self.assertEqual(args[4:6], ["get", "nodes"])
                raise subprocess.TimeoutExpired(args, 1, stderr="private")
            subprocess.run = fake
            with self.assertRaisesRegex(run.Blocked, "unavailable") as ctx:
                run.ReadOnlyAPI().get("nodes")
            self.assertNotIn("private", str(ctx.exception))
            with self.assertRaises(run.Blocked):
                run.ReadOnlyAPI(budget=-1).get("nodes")
        finally:
            subprocess.run = original


if __name__ == "__main__":
    unittest.main()
