#!/usr/bin/env python3
"""No cluster or PKI: init-driver preflight and admission security fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
import test_run
import test_selected
from test_run import run, IDS
spec = importlib.util.spec_from_file_location("synthetic_init_evidence", HERE / "init_evidence.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InitAPI(test_run.FakeAPI):
    def __init__(self):
        super().__init__()
        for component in ("controller", "webhook"):
            deployment = self.objects[("deployment", "ratatoskr-" + component, "operator", None)]
            values = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            for item in values:
                if item["name"] == "DRIVER":
                    item["value"] = "init"
            if component == "webhook":
                values.append({"name": "INIT_IMAGE_PULL_POLICY", "value": "Never"})
        del self.objects[("daemonset", "ratatoskr-agent", "operator", None)]
        del self.objects[("pods", None, "operator", "app=agent")]

    def get(self, resource, name=None, namespace=None, selector=None, ignore_not_found=False):
        if ignore_not_found:
            if (resource, name, namespace) != ("daemonset", "ratatoskr-agent", "operator"):
                raise AssertionError("broad ignore-not-found")
            return self.objects.get((resource, name, namespace, None))
        return super().get(resource, name, namespace, selector)


class InitTests(unittest.TestCase):
    def test_readonly_init_mode_and_absent_agent_required(self):
        api = InitAPI()
        self.assertEqual(run.init_release_preflight(api, IDS), "operator")
        invalid = InitAPI()
        invalid.objects[("daemonset", "ratatoskr-agent", "operator", None)] = {}
        with self.assertRaises(run.Blocked):
            run.init_release_preflight(invalid, IDS)
        for component in ("controller", "webhook"):
            invalid = InitAPI()
            values = invalid.objects[("deployment", "ratatoskr-" + component, "operator", None)]["spec"]["template"]["spec"]["containers"][0]["env"]
            next(v for v in values if v["name"] == "DRIVER")["value"] = "agent"
            with self.assertRaises(run.Blocked):
                run.init_release_preflight(invalid, IDS)
        invalid = InitAPI()
        pod = invalid.objects[("pods", None, "operator", "app=controller")]["items"][0]
        pod["status"]["containerStatuses"][0]["imageID"] = "sha256:" + "f" * 64
        with self.assertRaises(run.Blocked):
            run.init_release_preflight(invalid, IDS)

    def test_init_pod_never_claims_restricted_and_detects_privilege_tamper(self):
        pod, _, _ = test_selected.pod("healthy")
        uid = pod["metadata"]["uid"]
        cfg = {"gatewayID": 7, "endpoint": "10.42.1.7", "podIP": "10.42.2.5",
               "identity": {"namespace": test_selected.APP, "pod": "synthetic-probe-healthy",
                            "uid": uid, "policy": "synthetic"},
               "policy": {"mode": "include", "rules": [{"cidrs": ["10.88.0.1/32"],
                          "ports": [{"protocol": "TCP", "port": 8080}]}]}}
        pod["metadata"]["annotations"].pop(module.evidence.PREFIX + "agent-config", None)
        pod["metadata"]["annotations"][module.evidence.PREFIX + "client-config"] = json.dumps(cfg)
        init = pod["spec"]["initContainers"][0]
        init.update(image="ratatoskr-init:local", args=["-config=/var/run/ratatoskr/client.json"],
                    env=[{"name": k, "valueFrom": {"fieldRef": {"fieldPath": field}}}
                         for k, field in (("POD_IP", "status.podIP"), ("POD_UID", "metadata.uid"),
                                          ("POD_NAME", "metadata.name"))] +
                        [{"name": "DATAPATH", "value": "iproute"}],
                    volumeMounts=[{"name": "ratatoskr-client-config", "mountPath": "/var/run/ratatoskr",
                                   "readOnly": True}],
                    securityContext={"privileged": False, "capabilities": {"add": ["NET_ADMIN"]}})
        pod["spec"]["volumes"] = [v for v in pod["spec"]["volumes"] if v["name"] != "ratatoskr-agent-api-shadow"]
        pod["spec"]["volumes"].append({"name": "ratatoskr-client-config", "downwardAPI": {
            "items": [{"path": "client.json", "fieldRef": {
                "fieldPath": "metadata.annotations['ratatoskr.skaldhall.io/client-config']"}}]}})
        expected = dict(namespace=test_selected.APP, name="synthetic-probe-healthy", uid=uid,
                        init_image="ratatoskr-init:local", app_image=test_selected.IMAGE,
                        gateway_id=7, endpoint="10.42.1.7", api_ip="10.43.0.1")
        self.assertEqual(module.assert_init_pod(pod, **expected),
                         {"uid": uid, "initDriverNonrestricted": True, "healthyExit": True})
        for change in (
            lambda p: p["spec"]["containers"][0]["securityContext"]["capabilities"].update(add=["NET_ADMIN"]),
            lambda p: p["spec"]["initContainers"][0]["securityContext"]["capabilities"].update(add=["SYS_ADMIN"]),
            lambda p: p["spec"]["initContainers"][0].update(image="wrong"),
            lambda p: p["metadata"].update(uid="wrong"),
            lambda p: p["metadata"]["annotations"].update({module.evidence.PREFIX + "client-config": "{}"}),
            lambda p: p["status"]["initContainerStatuses"][0]["state"]["terminated"].update(exitCode=1),
            lambda p: p["status"]["containerStatuses"][0]["state"]["terminated"].update(exitCode=1)):
            damaged = copy.deepcopy(pod)
            change(damaged)
            with self.assertRaises(module.Blocked):
                module.assert_init_pod(damaged, **expected)

    def test_fifth_opt_in_is_readonly_and_never_invokes_gateway_smoke(self):
        import contextlib
        import io
        env = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_PARTIAL_VPN_SMOKE": "1",
               "RATATOSKR_E2E_INIT_SMOKE": "1"}
        env.update({"EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in IDS.items()})
        args = ["--execute", "--allow-partial-vpn-smoke", "--execute-init-smoke"]
        called = []
        def node_check(_ids):
            called.append("node-preflight")
            return True
        def forbidden_smoke(*_args, **_kw):
            raise AssertionError("init mode must not mutate cluster")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(run.main(args, env, InitAPI, node_check, forbidden_smoke), 4)
        self.assertEqual(called, ["node-preflight"])
        self.assertIn("init-driver/nonrestricted", output.getvalue())
        for bad_args, bad_env in (
                (["--execute-init-smoke"], dict(env, RATATOSKR_E2E_INIT_SMOKE="0")),
                (args, dict(env, RATATOSKR_E2E_INIT_SMOKE="0")),
                (args[1:], env),
                (args + ["--execute-partial-gateway"], env)):
            with self.subTest(args=bad_args), contextlib.redirect_stdout(io.StringIO()):
                result = run.main(bad_args, bad_env, lambda: (_ for _ in ()).throw(AssertionError("API called")),
                                  lambda _ids: (_ for _ in ()).throw(AssertionError("CRI called")), forbidden_smoke)
                self.assertEqual(result, 2)

    def test_init_mode_rejects_insecure_release_probe_and_malformed_preflight(self):
        for component, env_name, value in (("controller", "DATAPATH", "ebpf"),
                                            ("controller", "GATEWAY_UPSTREAM_PROBE_URL", "http://public/exit"),
                                            ("controller", "OPENVPN_IMAGE", "foreign:latest"),
                                            ("webhook", "INIT_IMAGE_PULL_POLICY", "Always")):
            api = InitAPI()
            data = api.objects[("deployment", "ratatoskr-" + component, "operator", None)]
            values = data["spec"]["template"]["spec"]["containers"][0]["env"]
            next(v for v in values if v["name"] == env_name)["value"] = value
            with self.subTest(component=component, env_name=env_name), self.assertRaises(run.Blocked):
                run.init_release_preflight(api, IDS)

    def test_init_namespace_privileged_only_when_explicit(self):
        import lifecycle
        ns = "rtk-syn-" + "a" * 16
        labels = lifecycle._namespace(ns + "-apps", "a" * 32, True, "privileged")["metadata"]["labels"]
        self.assertEqual(labels["pod-security.kubernetes.io/enforce"], "privileged")
        self.assertEqual(labels["ratatoskr-synthetic"], ns)
        self.assertEqual(lifecycle._namespace(ns + "-apps", "a" * 32, True)["metadata"]["labels"][
            "pod-security.kubernetes.io/enforce"], "restricted")
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.Lifecycle(apps_psa="baseline")


if __name__ == "__main__":
    unittest.main()
