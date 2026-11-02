"""Offline-only Calico healthy gate/preflight/owner context; no cluster commands."""
import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
import calico_healthy as c
import environment
import test_run

IDS = {key: test_run.DIGEST for key in c.run.COMPONENTS}
GATES = {"RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_CALICO_HEALTHY": "1"}
INPUT = {**GATES, **{"EXPECTED_" + key.upper() + "_IMAGE_ID": value for key, value in IDS.items()}}


class CalicoAPI(c.run.ReadOnlyAPI):
    def __init__(self, *, environment=environment.CALICO):
        super().__init__(environment=environment, clock=lambda: 0)
        self.fake = test_run.FakeAPI()
        self.calls = []
        self.fake.objects[("nodes", None, None, None)] = {"items": [
            test_run.node(i == 0, name) for i, name in enumerate(environment.nodes)]}
        self.fake.objects[("configmap", "ratatoskr-testenv", "kube-system", None)] = {
            "data": {"variant": environment.variant, "mesh": "none"}}
        self.fake.objects[("service", "kubernetes", "default", None)] = {
            "metadata": {"name": "kubernetes", "namespace": "default"},
            "spec": {"clusterIP": "10.43.0.1", "type": "ClusterIP"}}
    def get(self, resource, name=None, namespace=None, selector=None, ignore_not_found=False):
        self.calls.append((self.environment.context, resource, name, namespace))
        if ignore_not_found:
            raise AssertionError("agent preflight never ignores absence")
        return self.fake.get(resource, name, namespace, selector)


class HealthyTest(unittest.TestCase):
    def test_default_and_missing_optins_never_read_cluster(self):
        for argv, env in (([], {}), (["--execute-calico-healthy"], {}),
                          ([], GATES),
                          (["--execute-calico-healthy"], {"RATATOSKR_E2E_FINAL_GATE": "1"}),
                          (["--execute-calico-healthy"], {"RATATOSKR_E2E_CALICO_HEALTHY": "1"})):
            with self.subTest(argv=argv, env=env), \
                    patch.object(c, "execute", side_effect=AssertionError("no IO")):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(c.main(argv, environ=env), 2)
                self.assertIn("SKIPPED", output.getvalue())

    def test_preflight_images_controller_and_api_ip_before_one_scoped_smoke(self):
        api = CalicoAPI()
        order = []
        def verify(images, *, environment, observed_nodes):
            order.append("images")
            self.assertEqual(environment, c.environment.CALICO)
            self.assertEqual(observed_nodes, c.environment.CALICO.nodes)
            self.assertEqual(images, {k: IDS[k] for k in c.node_images.TAGS})
            return True
        def smoke(ids, *, api_ip, environment):
            order.append("smoke")
            self.assertEqual(ids, IDS)
            self.assertEqual(api_ip, "10.43.0.1")
            self.assertEqual(environment, c.environment.CALICO)
            return False
        self.assertEqual(c.execute(INPUT, api_factory=lambda *, environment: api,
                                   verifier=verify, smoke=smoke),
                         {"environment": "calico/none", "subset": "agent/iproute/healthy",
                          "result": "INCOMPLETE", "fullMatrix": False})
        self.assertEqual(order, ["images", "smoke"])
        self.assertTrue(all(context == environment.CALICO.context for context, *_ in api.calls))
        self.assertEqual(api.calls[0][1], "nodes")
        self.assertIn("configmap", [row[1] for row in api.calls])
        self.assertIn("service", [row[1] for row in api.calls])

    def test_wrong_variant_nodes_mesh_stale_or_missing_images_stop_before_smoke(self):
        for field in ("nodes", "variant", "mesh", "release", "images", "ids"):
            api = CalicoAPI()
            provided = dict(INPUT)
            if field == "nodes":
                api.fake.objects[("nodes", None, None, None)] = {"items": [
                    test_run.node(i == 0, name) for i, name in enumerate(environment.FLANNEL.nodes)]}
            if field == "variant":
                api.fake.objects[("configmap", "ratatoskr-testenv", "kube-system", None)]["data"]["variant"] = "flannel"
            if field == "mesh":
                api.fake.objects[("configmap", "ratatoskr-testenv", "kube-system", None)]["data"]["mesh"] = "sidecar"
            if field == "release":
                api.fake.objects[("deployment", "ratatoskr-controller", "operator", None)]["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] = "init"
            if field == "ids":
                provided["EXPECTED_CONTROLLER_IMAGE_ID"] = "mutable:latest"
            def verify(*_a, **_kw):
                if field == "images":
                    raise c.node_images.Blocked("no approved images")
                return True
            with self.subTest(field=field), self.assertRaises(c.Blocked):
                c.execute(provided, api_factory=lambda *, environment: api,
                          verifier=verify, smoke=lambda *_a, **_kw: self.fail("no write"))
            if field in ("nodes", "variant", "mesh", "ids"):
                self.assertTrue(all(row[1] in ("nodes", "configmap") for row in api.calls))

    def test_wrong_context_or_incomplete_cleanup_not_credited(self):
        with self.assertRaises(c.Blocked):
            c.execute(INPUT, api_factory=lambda *, environment: CalicoAPI(environment.FLANNEL),
                      verifier=lambda *_a, **_k: self.fail("no Docker"),
                      smoke=lambda *_a, **_k: self.fail("no writes"))
        api = CalicoAPI()
        with self.assertRaisesRegex(c.Blocked, "fixture-or-cleanup"):
            c.execute(INPUT, api_factory=lambda *, environment: api,
                      verifier=lambda *_a, **_k: True,
                      smoke=lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("secret")))
        with self.assertRaisesRegex(c.Blocked, "fixture-or-cleanup"):
            c.execute(INPUT, api_factory=lambda *, environment: CalicoAPI(),
                      verifier=lambda *_a, **_k: True,
                      smoke=lambda *_a, **_k: True)

    def test_partial_fixture_rejects_wrong_owner_context_before_any_creation(self):
        class Owner:
            environment = environment.FLANNEL
            api = None
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def create_namespaces(self): self.fail("must not create")
        owner = Owner()
        owner.fail = self.fail
        with self.assertRaises(c.partial_gateway.Blocked):
            c.partial_gateway.execute(IDS, api_ip="10.43.0.1",
                                      environment=environment.CALICO,
                                      lifecycle_factory=lambda **kwargs: owner,
                                      adapter_factory=lambda *_: self.fail("no adapter"))


if __name__ == "__main__":
    unittest.main()
