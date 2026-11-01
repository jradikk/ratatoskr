"""Offline Calico namespace lifecycle/fixture argv pinning; never invoke kubectl."""
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
import adapter
import environment
import lifecycle

TOKEN = "a" * 32
UID = "b" * 32
IMAGE = "containerd://sha256:" + "c" * 64


class ScriptedKubectl:
    def __init__(self, context):
        self.context = context
        self.calls = []
        self.namespaces = {}
    def __call__(self, argv, *, input, text, capture_output, timeout, check, env):
        self.calls.append((argv, input))
        assert argv[:4] == ["kubectl", "--context", self.context, "--request-timeout=10s"]
        assert text and capture_output and not check and 0 < timeout <= 15
        assert all(key in {"PATH", "HOME", "KUBECONFIG", "KUBECTL_KUBERC"} for key in env)
        action = argv[4]
        if action == "get":
            found = self.namespaces.get(argv[6])
            output = json.dumps(found) if found else ""
        elif action == "create":
            manifest = json.loads(input)
            meta = manifest["metadata"]
            assert meta["name"] not in self.namespaces
            created = {**manifest, "metadata": {**meta, "uid": UID}}
            self.namespaces[meta["name"]] = created
            output = json.dumps(created)
        elif action == "delete":
            name = argv[5].split("/")[-1]
            assert argv[5].startswith("--raw=/api/v1/namespaces/")
            assert json.loads(input)["preconditions"]["uid"] == self.namespaces[name]["metadata"]["uid"]
            self.namespaces.pop(name)
            output = "{}"
        else:
            raise AssertionError("unexpected action")
        class Response:
            returncode = 0
            stdout = output
        return Response()


class CalicoLifecycleTest(unittest.TestCase):
    def test_context_owned_get_create_uid_delete_all_stay_calico(self):
        fake = ScriptedKubectl(environment.CALICO.context)
        api = lifecycle.KubectlAPI(environment=environment.CALICO, run=fake)
        life = lifecycle.Lifecycle(api=api, environment=environment.CALICO,
                                   token_factory=lambda: TOKEN)
        with life:
            self.assertEqual(life.environment, environment.CALICO)
            self.assertEqual(life.create_namespaces(), life.names)
            self.assertEqual(life.owned, {name: UID for name in life.names})
        self.assertEqual(fake.namespaces, {})
        actions = [argv[4] for argv, _ in fake.calls]
        self.assertEqual(actions.count("create"), 2)
        self.assertEqual(actions.count("delete"), 2)
        self.assertTrue(all(argv[2] == environment.CALICO.context for argv, _ in fake.calls))
        self.assertEqual([argv[5].split("/")[-1] for argv, _ in fake.calls if argv[4] == "delete"],
                         list(reversed(life.names)))

    def test_mixed_api_context_or_fake_missing_env_rejected_before_mutation(self):
        fake = ScriptedKubectl(environment.FLANNEL.context)
        api = lifecycle.KubectlAPI(run=fake)
        for env, wrong in ((environment.CALICO, api), (environment.FLANNEL,
                         lifecycle.KubectlAPI(environment=environment.CALICO, run=fake))):
            with self.subTest(env=env), self.assertRaises(lifecycle.LifecycleError):
                lifecycle.Lifecycle(api=wrong, environment=env)
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.KubectlAPI(context=environment.FLANNEL.context,
                                 environment=environment.CALICO, run=fake)
        class Mock:
            def get(self, *args, **kwargs):
                raise AssertionError("no cluster")
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.Lifecycle(api=Mock(), environment=environment.CALICO)
        self.assertEqual(fake.calls, [])
        self.assertEqual(lifecycle.Lifecycle(api=Mock()).environment, environment.FLANNEL)

    def test_fixture_get_create_and_direct_probe_exec_context_pinned(self):
        class MockAPI:
            environment = environment.CALICO
            def get(self, name, timeout):
                return {"metadata": {"name": name, "uid": UID,
                                     "labels": {lifecycle.LABEL: TOKEN}}}
        owner = lifecycle.Lifecycle(api=MockAPI(), environment=environment.CALICO,
                                    token_factory=lambda: TOKEN)
        owner.deadline = owner.clock() + 120
        owner.seen_absent = set(owner.names)
        owner.attempted = set(owner.names)
        owner.created = {name: UID for name in owner.names}
        owner.owned = dict(owner.created)
        calls = []
        def transport(argv, *, payload=None, timeout, max_output):
            calls.append((argv, payload))
            assert argv[:4] == ["kubectl", "--context", environment.CALICO.context,
                                "--request-timeout=10s"]
            if argv[4] == "get":
                name = argv[6]
                namespace = argv[8]
                if name == "synthetic-client":
                    from prepare import running_probe_pod
                    pod = running_probe_pod(owner.names[1], owner.names[0], "10.43.0.1")
                    pod["metadata"]["uid"] = UID
                    pod["spec"]["nodeName"] = "node"
                    pod["status"] = {"phase": "Running", "podIP": "10.42.0.8",
                                     "containerStatuses": [{"name": "client", "imageID": IMAGE,
                                                            "ready": True}]}
                    return json.dumps(pod).encode()
                return json.dumps({"kind": "Pod", "metadata": {"name": name,
                    "namespace": namespace, "uid": UID}}).encode()
            if argv[4] == "create":
                obj = json.loads(payload)
                return ("\t".join((obj["apiVersion"], obj["kind"],
                    obj["metadata"]["namespace"], obj["metadata"]["name"], UID))).encode()
            if "exec" in argv:
                return b""
            raise AssertionError("unexpected fixture action")
        fixture = adapter.FixtureAPI(owner, transport=transport)
        self.assertEqual(fixture.get("pod", "synthetic-vpn", owner.names[0])["metadata"]["uid"], UID)
        from prepare import running_probe_pod
        pod = running_probe_pod(owner.names[1], owner.names[0], "10.43.0.1")
        created = fixture.create(pod)
        self.assertEqual(created["uid"], UID)
        self.assertEqual(fixture.created[("Pod", owner.names[1], "synthetic-client")], UID)
        fixture.probe_running("synthetic-client", UID, IMAGE, "healthy", "10.43.0.1")
        self.assertTrue(any(call[0][4] == "create" for call in calls))
        self.assertTrue(any("exec" in call[0] for call in calls))
        self.assertTrue(all(argv[2] == environment.CALICO.context for argv, _ in calls))
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.Lifecycle(api=MockAPI(), environment=environment.FLANNEL)


if __name__ == "__main__":
    unittest.main()
