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


def main():
    with patch.object(admission.subprocess, "run", side_effect=AssertionError("cluster command forbidden")), patch.object(runner.subprocess, "Popen", side_effect=AssertionError("runner forbidden")):
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
        entry = {"scenarios": [{"id": key, "status": "DEFERRED", "covered": False} for key in admission.CHECKS[1:6]]}
        runner.apply_api_result(entry, {"status": "PASSED", "checks": []})
        assert all(not s["covered"] for s in entry["scenarios"])
        evidence = [{"name": key, "status": "PASSED"} for key in admission.CHECKS]
        runner.apply_api_result(entry, {"status": "PASSED", "checks": evidence})
        assert all(s["covered"] for s in entry["scenarios"])
        evidence[-1]["status"] = "FAILED"
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
