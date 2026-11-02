"""Cluster-free tests for variant lifecycle, read-only API and agent guard."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("variant_gate", HERE / "variant_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
DIGEST = "containerd://sha256:" + "a" * 64


def fixtures(variant="flannel", mesh="none", mode="iproute"):
    prefix = "k3d-ratatoskr-" + variant
    names = [prefix + suffix for suffix in ("-server-0", "-agent-0", "-agent-1")]
    nodes = [{"metadata": {"name": name, "labels": {"node-role.kubernetes.io/control-plane": ""} if i == 0 else {}},
              "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
             for i, name in enumerate(names)]
    caps = sorted(gate.AGENT_CAPS | ({"BPF", "PERFMON"} if mode == "ebpf" else set()))
    sock = "/run/k3s/containerd/containerd.sock"
    ds = {"metadata": {"uid": "daemon-uid", "generation": 3},
          "spec": {"template": {"spec": {"hostPID": True, "hostNetwork": True,
                   "serviceAccountName": "ratatoskr-agent", "automountServiceAccountToken": True,
                   "containers": [{"name": "agent", "securityContext": {"runAsUser": 0,
                       "privileged": False, "allowPrivilegeEscalation": False,
                       "seccompProfile": {"type": "RuntimeDefault"},
                       "capabilities": {"drop": ["ALL"], "add": caps}},
                       "env": [{"name": "CRI_SOCKET", "value": sock}, {"name": "DATAPATH", "value": mode}],
                       "volumeMounts": [{"name": "cri-socket", "mountPath": sock, "readOnly": True},
                                        {"name": "netns", "mountPath": "/var/run/netns", "readOnly": True}]}],
                   "volumes": [{"name": "cri-socket", "hostPath": {"path": sock, "type": "Socket"}},
                               {"name": "netns", "hostPath": {"path": "/var/run/netns", "type": "DirectoryOrCreate"}}]}}},
          "status": {"observedGeneration": 3, "desiredNumberScheduled": 3,
                     "updatedNumberScheduled": 3, "numberReady": 3}}
    pods = [{"metadata": {"ownerReferences": [{"kind": "DaemonSet", "uid": "daemon-uid", "controller": True}]},
             "spec": {"nodeName": name}, "status": {"conditions": [{"type": "Ready", "status": "True"}],
             "containerStatuses": [{"name": "agent", "ready": True, "imageID": DIGEST}]}} for name in names]
    return {"clusters": [{"name": "ratatoskr-" + variant}], "nodes": {"items": nodes},
            "env": {"metadata": {"name": "ratatoskr-testenv"}, "data": {"variant": variant, "mesh": mesh}},
            "ds": ds, "pods": {"items": pods}}


class FakeCall:
    def __init__(self, state):
        self.state = state
        self.calls = []
    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[0] == "bash":
            return ""
        if argv[:3] == ["k3d", "cluster", "list"]:
            return json.dumps(self.state["clusters"])
        assert argv[0] == "kubectl" and argv[1] == "--context" and "--request-timeout=10s" in argv
        resource = argv[argv.index("get") + 1]
        key = {"nodes": "nodes", "configmap": "env", "daemonset": "ds", "pods": "pods"}[resource]
        return json.dumps(self.state[key])


class GateTests(unittest.TestCase):
    def test_no_opt_in_or_unknown_runner_never_calls_cluster(self):
        def forbid(*_args, **_kwargs):
            raise AssertionError("no commands authorized")
        for opts in ({}, {"execute": True}, {"authorization": "1"},
                     {"execute": True, "authorization": "1", "runner": "invented"},
                     {"execute": True, "authorization": "1", "variant": "cilium"}):
            args = {"variant": "flannel", "mesh": "none", "runner": "synthetic-agent-iproute",
                    "expected_agent_image_id": DIGEST, "approved_runner": forbid, "call": forbid,
                    "environ": {"RATATOSKR_E2E_FINAL_GATE": "1"}}
            args.update(opts)
            with self.assertRaises(gate.Blocked):
                gate.dispatch(**args)

    def test_missing_environment_or_image_id_no_lifecycle_call(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("no cluster command permitted")
        for env, image in (({}, DIGEST), ({"RATATOSKR_E2E_FINAL_GATE": "1"}, "agent:dev"),
                           ({"RATATOSKR_E2E_FINAL_GATE": "0"}, DIGEST)):
            with self.assertRaises(gate.Blocked):
                gate.dispatch("flannel", "none", "synthetic-agent-iproute", execute=True,
                              authorization="1", expected_agent_image_id=image,
                              call=forbidden, approved_runner=forbidden, environ=env)

    def test_lifecycle_order_and_partial_result_not_promoted(self):
        state = fixtures()
        fake = FakeCall(state)
        def runner(verified):
            self.assertEqual(verified["status"], "PREFLIGHT_ONLY")
            self.assertIs(verified["trafficCovered"], False)
            self.assertEqual(len(fake.calls), 6)
            return {"status": "INCOMPLETE", "trafficCovered": False}
        result = gate.dispatch("flannel", "none", "synthetic-agent-iproute", execute=True,
                               authorization="1", expected_agent_image_id=DIGEST, call=fake, approved_runner=runner,
                               environ={"RATATOSKR_E2E_FINAL_GATE": "1"})
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(fake.calls[0][0][0], "bash")
        self.assertEqual(fake.calls[0][0][-2:], ["flannel", "--mesh=none"])
        self.assertTrue(all(c[0][0] == "kubectl" for c in fake.calls[2:]))
        self.assertEqual(fake.calls[1][0][:3], ["k3d", "cluster", "list"])
        self.assertEqual(fake.calls[0][1], {"timeout": 1200})
        self.assertEqual(state, fixtures())

    def test_preflight_works_for_declared_variants_but_not_dispatch(self):
        for variant in gate.VARIANTS:
            for mesh in gate.MESHES:
                state = fixtures(variant, mesh)
                result = gate.preflight(variant, mesh, expected_agent_image_id=DIGEST, call=FakeCall(state))
                self.assertEqual(result["status"], "PREFLIGHT_ONLY")
                self.assertEqual(result["variant"], variant)
                self.assertEqual(result["mesh"], mesh)
                self.assertFalse(result["trafficCovered"])
                if (variant, mesh) != ("flannel", "none"):
                    with self.assertRaises(gate.Blocked):
                        gate.dispatch(variant, mesh, "synthetic-agent-iproute", execute=True,
                                      authorization="1", expected_agent_image_id=DIGEST,
                                      call=FakeCall(state), approved_runner=lambda _: None,
                                      environ={"RATATOSKR_E2E_FINAL_GATE": "1"})
        self.assertEqual(gate.preflight("flannel", "none", expected_agent_image_id=DIGEST, call=FakeCall(fixtures(mode="ebpf")))["agentDatapath"], "ebpf")
        with self.assertRaises(gate.Blocked):
            gate.dispatch("flannel", "none", "synthetic-agent-iproute", execute=True, authorization="1",
                          expected_agent_image_id=DIGEST,
                          call=FakeCall(fixtures(mode="ebpf")), approved_runner=lambda _: None,
                          environ={"RATATOSKR_E2E_FINAL_GATE": "1"})

    def test_preflight_rejects_mismatched_cluster_variant_mesh_topology(self):
        alterations = (
            lambda s: s["clusters"].append({"name": "ratatoskr-calico"}),
            lambda s: s["env"]["data"].update(mesh="ambient"),
            lambda s: s["env"]["data"].update(variant="cilium"),
            lambda s: s["nodes"]["items"].pop(),
            lambda s: s["nodes"]["items"][0]["status"].update(conditions=[]),
            lambda s: s["nodes"]["items"][0]["metadata"].update(name="wrong"),
        )
        for mutation in alterations:
            state = fixtures()
            mutation(state)
            with self.assertRaises(gate.Blocked):
                gate.preflight("flannel", "none", expected_agent_image_id=DIGEST, call=FakeCall(state))

    def test_preflight_rejects_unsafe_agent(self):
        alterations = (
            lambda s: s["ds"]["spec"]["template"]["spec"].update(hostPID=False),
            lambda s: s["ds"]["spec"]["template"]["spec"].update(hostNetwork=False),
            lambda s: s["ds"]["spec"]["template"]["spec"]["containers"][0]["securityContext"].update(privileged=True),
            lambda s: s["ds"]["spec"]["template"]["spec"]["containers"][0]["securityContext"].update(allowPrivilegeEscalation=True),
            lambda s: s["ds"]["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"]["add"].append("SYS_PTRACE"),
            lambda s: s["ds"]["spec"]["template"]["spec"]["volumes"].append({"name": "host-root", "hostPath": {"path": "/"}}),
            lambda s: s["ds"]["status"].update(numberReady=2),
            lambda s: s["pods"]["items"][0]["status"]["containerStatuses"][0].update(imageID="agent:dev"),
            lambda s: s["pods"]["items"][0]["metadata"]["ownerReferences"][0].update(uid="wrong"),
        )
        for mutation in alterations:
            state = fixtures()
            mutation(state)
            with self.assertRaises(gate.Blocked):
                gate.preflight("flannel", "none", expected_agent_image_id=DIGEST, call=FakeCall(state))

    def test_dispatch_blocks_when_preflight_fails(self):
        fake = FakeCall(fixtures())
        fake.state["env"]["data"]["mesh"] = "ambient"
        invoked = []
        with self.assertRaises(gate.Blocked):
            gate.dispatch("flannel", "none", "synthetic-agent-iproute", execute=True,
                          authorization="1", call=fake, approved_runner=lambda v: invoked.append(v),
                                  environ={"RATATOSKR_E2E_FINAL_GATE": "1"})
        self.assertFalse(invoked)

    def test_read_only_kubectl_and_bounded_commands(self):
        state = fixtures()
        fake = FakeCall(state)
        gate.preflight("flannel", "none", expected_agent_image_id=DIGEST, call=fake)
        self.assertEqual(len(fake.calls), 5)
        self.assertEqual(fake.calls[0][0][:3], ["k3d", "cluster", "list"])
        for argv, kwargs in fake.calls[1:]:
            self.assertEqual(argv[0], "kubectl")
            self.assertIn("get", argv)
            self.assertNotIn("Secret", argv)
            self.assertEqual(argv[-2:], ["-o", "json"])
        with patch.object(gate.subprocess, "run", side_effect=AssertionError("offline test")):
            with self.assertRaises(AssertionError):
                gate._command(["kubectl", "get", "pods"])
        self.assertEqual(state, fixtures())


if __name__ == "__main__":
    unittest.main()
