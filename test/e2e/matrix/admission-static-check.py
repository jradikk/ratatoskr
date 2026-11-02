#!/usr/bin/env python3
"""Static admission fixture/assertion tests; no API runner, kubectl or credentials."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def must_block(function):
    try:
        function()
    except admission.Blocked:
        return
    raise AssertionError("invalid assertion unexpectedly accepted")


admission = load("admission_static", "admission.py")
runner = load("admission_inventory_static", "run.py")


def synthetic_mutation(original, driver, datapath):
    pod = copy.deepcopy(original)
    pod["metadata"]["annotations"] = {
        admission.PREFIX + "datapath-ready": "pending",
        admission.PREFIX + "client-config": json.dumps({"gatewayID": 7, "mtu": 0, "encryption": "none", "endpoint": "invalid IP", "identity": {"namespace": original["metadata"]["namespace"], "pod": original["metadata"]["name"]}})}
    if driver == "init":
        pod["spec"]["initContainers"] = [{"name": "ratatoskr-init", "image": "init:test",
            "args": ["-config=/var/run/ratatoskr/client.json"],
            "securityContext": {"privileged": False, "capabilities": {"add": ["NET_ADMIN"] if datapath == "iproute" else ["NET_ADMIN", "BPF", "PERFMON"]}},
            "env": [{"name": name, "valueFrom": {"fieldRef": {"fieldPath": path}}} for name, path in
                    (("POD_IP", "status.podIP"), ("POD_UID", "metadata.uid"), ("POD_NAME", "metadata.name"))] + [{"name": "DATAPATH", "value": datapath}],
            "volumeMounts": [{"name": "ratatoskr-client-config", "mountPath": "/var/run/ratatoskr", "readOnly": True}]}]
        pod["spec"]["volumes"] = [{"name": "ratatoskr-client-config", "downwardAPI": {"items": [{"path": "client.json", "fieldRef": {"fieldPath": "metadata.annotations['ratatoskr.skaldhall.io/client-config']"}}]}}]
    else:
        pod["spec"]["initContainers"] = [{"name": "ratatoskr-init", "image": "init:test", "args": ["-wait-agent"],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}},
            "volumeMounts": [{"name": "ratatoskr-agent-api-shadow", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": True}]}]
        pod["spec"]["volumes"] = [{"name": "ratatoskr-agent-api-shadow", "emptyDir": {}}]
    return pod


def check_inert_update_helpers():
    from types import SimpleNamespace

    original = admission.inert_pod("fixture", "update-inert", "gateway", "abc123")
    admission.assert_no_matching_node([{"metadata": {"labels": {}}} for _ in range(3)])
    must_block(lambda: admission.assert_no_matching_node([{"metadata": {"labels": {admission.NEVER_SCHEDULE_LABEL: "anything"}}}] * 3))
    must_block(lambda: admission.assert_no_matching_node([]))
    for driver in ("init", "agent"):
        for datapath in ("iproute", "ebpf"):
            mutated = synthetic_mutation(original, driver, datapath)
            mutated["metadata"].update(uid="fixture-uid", resourceVersion="1")
            admission.assert_inert(original, mutated)
            admission.assert_security(original, mutated, driver, datapath, "init:test", 7)
            for field, value in (("schedulingGates", []), ("nodeSelector", {}), ("nodeName", "assigned")):
                unsafe = copy.deepcopy(mutated)
                unsafe["spec"][field] = value
                must_block(lambda: admission.assert_inert(original, unsafe))
            for status in ({"podIP": "10.42.0.1"}, {"startTime": "2026-10-30T00:00:00Z"},
                           {"phase": "Running"}, {"containerStatuses": [{"name": "app"}]},
                           {"initContainerStatuses": [{"name": "ratatoskr-init"}]},
                           {"conditions": [{"type": "PodScheduled", "status": "True"}]}):
                unsafe = copy.deepcopy(mutated)
                unsafe["status"] = status
                must_block(lambda: admission.assert_inert(original, unsafe))
            for case in ("benign", "gateway-label", "gateway-namespace", "client-config"):
                replacement = admission.update_document(mutated, case, "abc123")
                assert replacement["spec"] == mutated["spec"]
                assert replacement["metadata"]["resourceVersion"] == "1"
                admission.assert_inert(original, replacement)
                if case == "benign":
                    admission.assert_update_response(SimpleNamespace(returncode=0, stderr=""), case)
                    must_block(lambda: admission.assert_update_response(SimpleNamespace(returncode=1, stderr="timeout"), case))
                else:
                    phrase = ("pod client config is immutable; recreate the pod to change its gateway configuration" if case == "client-config" else
                              "pod gateway opt-in and gateway namespace are immutable; change the Deployment template and recreate the pod")
                    denial = SimpleNamespace(returncode=1, stderr='Error: admission webhook "pods.ratatoskr.skaldhall.io" denied the request: ' + phrase)
                    admission.assert_update_response(denial, case)
                    for invalid in (SimpleNamespace(returncode=0, stderr=denial.stderr), SimpleNamespace(returncode=1, stderr="Conflict"),
                                    SimpleNamespace(returncode=1, stderr='admission webhook "wrong.example" denied the request: ' + phrase)):
                        must_block(lambda: admission.assert_update_response(invalid, case))
                unchanged = copy.deepcopy(mutated)
                unchanged["metadata"]["resourceVersion"] = "2"
                admission.assert_unchanged_fixture(mutated, unchanged)
                must_block(lambda: admission.assert_unchanged_fixture(mutated, replacement))
                json.loads(json.dumps(replacement))
            print(f"PASS static inert {driver}/{datapath} barriers, exact UPDATE responses and unchanged-state assertions")

    class CleanupAPI:
        def __init__(self, leftover=False, unsafe=False):
            self.calls = []
            self.leftover = leftover
            self.unsafe = unsafe
        def call(self, *args, **kwargs):
            self.calls.append(args)
            if args[0] == "delete":
                return SimpleNamespace(stdout="")
            if args[-1] == "json":
                obj = copy.deepcopy(original)
                if self.unsafe:
                    obj["spec"]["nodeName"] = "bad-node"
                return SimpleNamespace(stdout=json.dumps(obj))
            return SimpleNamespace(stdout="pod/update-inert" if self.leftover else "")

    for leftover, unsafe in ((False, False), (True, False), (False, True)):
        fake = CleanupAPI(leftover, unsafe)
        assert admission.delete_inert_fixture(fake, "pod.json", "fixture", "update-inert", original) == (not leftover and not unsafe)
        assert [call[0] for call in fake.calls] == ["get", "delete", "get"]
        assert all(call[0] != "replace" for call in fake.calls)
    print("PASS static exact Pod cleanup attempts despite unsafe state and fails on leftovers")


def main():
    with patch.object(admission.subprocess, "run", side_effect=AssertionError("cluster command forbidden")), patch.object(runner.subprocess, "Popen", side_effect=AssertionError("runner forbidden")):
        check_inert_update_helpers()
        for driver in ("init", "agent"):
            for datapath in ("iproute", "ebpf"):
                original = admission.pod("fixture", "authorized", "gateway", "fixture")
                mutated = synthetic_mutation(original, driver, datapath)
                admission.assert_security(original, mutated, driver, datapath, "init:test", 7)
                forged = copy.deepcopy(mutated)
                forged["spec"]["initContainers"][0]["securityContext"]["privileged"] = True
                must_block(lambda: admission.assert_security(original, forged, driver, datapath, "init:test", 7))
                forged = copy.deepcopy(mutated)
                forged["spec"]["volumes"].append({"name": "leak", "secret": {"secretName": "forbidden"}})
                must_block(lambda: admission.assert_security(original, forged, driver, datapath, "init:test", 7))
                must_block(lambda: admission.assert_security(original, mutated, driver, datapath, "stale:init", 7))
                json.loads(json.dumps(original))
                print(f"PASS static {driver}/{datapath} mutation assertion and hostile-field rejection")
        # Required expected image IDs are checked before making any API call.
        api = admission.API()
        with patch.object(api, "get", side_effect=AssertionError("API access forbidden")):
            must_block(lambda: admission.release_preflight(api, {}))
            must_block(lambda: admission.release_preflight(api, {"controller": "controller:dev", "webhook": "webhook:dev"}))
        entry = {"scenarios": [{"id": key, "status": "DEFERRED", "covered": False} for key in (*admission.CHECKS[1:6], admission.UPDATE_CHECK)]}
        runner.apply_api_result(entry, {"status": "PASSED", "checks": []})
        assert all(not s["covered"] for s in entry["scenarios"])
        evidence = [{"name": key, "status": "PASSED"} for key in (*admission.CHECKS, admission.UPDATE_CHECK)]
        runner.apply_api_result(entry, {"status": "PASSED", "checks": evidence})
        assert all(s["covered"] for s in entry["scenarios"])
        next(e for e in evidence if e["name"] == "api-cleanup")["status"] = "FAILED"
        runner.apply_api_result(entry, {"status": "FAILED", "checks": evidence})
        assert all(not s["covered"] for s in entry["scenarios"])
        for mode in ("fake", "live"):
            _, cells = runner.inventory(mode)
            assert len(cells) == 96 and all(not s["covered"] for cell in cells for s in cell["scenarios"])
        for mode in ("none", "wireguard"):
            obj = admission.gateway("fixture", "gateway", "allowed", mode)
            assert obj["apiVersion"] and obj["kind"] and obj["spec"]["upstream"]["secretRef"]["name"].endswith("-deliberately-absent")
            assert "status" not in obj and "data" not in obj
            json.loads(json.dumps(obj))
    for path in (HERE / "admission.py", HERE / "admission-static-check.py", HERE / "run.py"):
        compile(path.read_text(), str(path), "exec")
    print("PASS static image-ID guard, complete non-secret fixtures and API-only evidence gating; no API or runner executed")


if __name__ == "__main__":
    main()
