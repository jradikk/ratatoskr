"""No cluster: exact immutable environment and read-only Calico preflight."""
import contextlib
import dataclasses
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
import environment
import run


class IdentityTests(unittest.TestCase):
    def test_only_fixed_contexts_and_nodes_immutable_default_flannel(self):
        self.assertEqual(environment.FLANNEL.context, run.CONTEXT)
        self.assertEqual(environment.FLANNEL.nodes, run.node_images.NODES)
        self.assertEqual(environment.CALICO.context, "k3d-ratatoskr-calico")
        self.assertEqual(environment.CALICO.nodes,
                         ("k3d-ratatoskr-calico-server-0", "k3d-ratatoskr-calico-agent-0",
                          "k3d-ratatoskr-calico-agent-1"))
        for variant in ("cilium", "calico-evil", "", "Calico", None, ["calico"]):
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                environment.Environment(variant)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            environment.CALICO.variant = "flannel"
        for bad in ("calico", "k3d-ratatoskr-calico", object()):
            with self.assertRaises(run.Blocked):
                run.ReadOnlyAPI(environment=bad)

    def test_calico_get_is_read_only_with_exact_context_and_no_other_actions(self):
        api = run.ReadOnlyAPI(environment=environment.CALICO, clock=lambda: 0)
        calls = []
        def subprocess_run(argv, **kwargs):
            calls.append((argv, kwargs))
            class Result:
                returncode = 0
                stdout = '{"items":[]}'
            return Result()
        with patch.object(run.subprocess, "run", side_effect=subprocess_run):
            self.assertEqual(api.get("nodes"), {"items": []})
        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]
        self.assertEqual(argv[:6], ["kubectl", "--context", environment.CALICO.context,
                                    "--request-timeout=10s", "get", "nodes"])
        self.assertNotIn("create", argv)
        self.assertNotIn("delete", argv)
        self.assertEqual(set(kwargs["env"]) & {"PATH", "HOME", "KUBECONFIG"}, set(kwargs["env"]))
        self.assertTrue(kwargs["capture_output"] and kwargs["check"] is False)

    def test_preflight_exact_calico_ready_nodes_variant_none_then_release(self):
        class API(run.ReadOnlyAPI):
            def __init__(self, env):
                super().__init__(environment=env, clock=lambda: 0)
                self.calls = []
                self.variant = env.variant
                self.names = env.nodes
                self.mesh = "none"
            def get(self, resource, name=None, namespace=None, selector=None, ignore_not_found=False):
                self.calls.append((resource, name, namespace))
                if resource == "nodes":
                    return {"items": [{"metadata": {"name": node, "labels":
                            {"node-role.kubernetes.io/control-plane": ""} if i == 0 else {}},
                            "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
                            for i, node in enumerate(self.names)]}
                if resource == "configmap":
                    return {"data": {"variant": self.variant, "mesh": self.mesh}}
                raise run.Blocked("release-not-injected")
        api = API(environment.CALICO)
        with self.assertRaisesRegex(run.Blocked, "release-not-injected"):
            run.preflight_basics(api, environment=environment.CALICO)
        self.assertEqual([call[0] for call in api.calls],
                         ["nodes", "configmap", "mutatingwebhookconfiguration"])
        for change, value in (("variant", "flannel"), ("mesh", "ambient"),
                              ("names", environment.FLANNEL.nodes)):
            api = API(environment.CALICO)
            setattr(api, change, value)
            with self.subTest(change=change), self.assertRaises(run.Blocked):
                run.preflight_basics(api, environment=environment.CALICO)
            self.assertTrue(all(call[0] in ("nodes", "configmap") for call in api.calls))
        api = API(environment.CALICO)
        api.names = (environment.CALICO.nodes[0],) * 3
        with self.assertRaises(run.Blocked):
            run.preflight(api, {}, environment=environment.CALICO)
        self.assertEqual(api.calls, [("nodes", None, None)])
        api = API(environment.CALICO)
        with self.assertRaisesRegex(run.Blocked, "release-not-injected"):
            run.preflight(api, {}, environment=environment.CALICO)
        self.assertEqual([call[0] for call in api.calls],
                         ["nodes", "configmap", "mutatingwebhookconfiguration"])
        api = API(environment.CALICO)
        with self.assertRaisesRegex(run.Blocked, "identity mismatch"):
            run.preflight(api, {}, environment=environment.FLANNEL)
        self.assertEqual(api.calls, [])

    def test_no_calico_traffic_dispatch_or_mutation_api_from_read_only(self):
        with patch.object(run, "ReadOnlyAPI", wraps=run.ReadOnlyAPI):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.main([], environ={}), 2)
        self.assertFalse(hasattr(run.ReadOnlyAPI, "create"))
        self.assertFalse(hasattr(run.ReadOnlyAPI, "delete"))


if __name__ == "__main__":
    unittest.main()
