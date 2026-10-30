#!/usr/bin/env python3
"""Selected restricted one-shot fixture and immutable Pod-status evidence."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
prepare = load("synthetic_prepare_selected", "prepare.py")
evidence = load("synthetic_evidence_selected", "evidence.py")
NS = "rtk-syn-" + "a" * 16
APP = NS + "-apps"
UID = "b" * 32
IMAGE = "containerd://sha256:" + "c" * 64


def pod(phase):
    item = prepare.selected_probe_pod(APP, NS, phase, "10.43.0.1")
    item["metadata"].update(uid=UID, annotations={evidence.PREFIX + "datapath-ready": "true"})
    init = {"name": "ratatoskr-init", "args": ["-wait-agent"],
            "volumeMounts": [{"name": "ratatoskr-agent-api-shadow", "mountPath":
                              "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": True}],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}
    item["spec"]["initContainers"] = [init]
    item["spec"]["volumes"].append({"name": "ratatoskr-agent-api-shadow", "emptyDir": {}})
    now = datetime.now(timezone.utc)
    start, end = now - timedelta(seconds=12), now - timedelta(seconds=6)
    item["status"] = {"podIP": "10.42.2.5", "phase": "Failed" if phase == "outage" else "Succeeded",
                      "initContainerStatuses": [{"name": "ratatoskr-init", "state": {"terminated": {"exitCode": 0}}}],
                      "containerStatuses": [{"name": "client", "imageID": IMAGE, "state": {"terminated": {
                          "exitCode": 42 if phase == "outage" else 0,
                          "startedAt": start.isoformat(), "finishedAt": end.isoformat()}}}]}
    return item, start, end


class SelectedTests(unittest.TestCase):
    def test_three_unique_names_security_and_arguments(self):
        names = []
        for phase in ("healthy", "outage", "recovery"):
            item = prepare.selected_probe_pod(APP, NS, phase, "10.43.0.1")
            names.append(item["metadata"]["name"])
            spec = item["spec"]
            self.assertIs(spec["automountServiceAccountToken"], False)
            self.assertEqual(spec["restartPolicy"], "Never")
            self.assertEqual(spec["activeDeadlineSeconds"], 120)
            self.assertEqual(spec["containers"][0]["securityContext"]["capabilities"], {"drop": ["ALL"]})
            self.assertEqual(spec["containers"][0]["imagePullPolicy"], "Never")
            self.assertEqual(spec["containers"][0]["args"],
                             ["outage" if phase == "outage" else "healthy", "10.43.0.1"])
            self.assertNotIn("secret", str(spec["volumes"]))
            self.assertNotIn("hostPath", str(spec["volumes"]))
        self.assertEqual(len(set(names)), 3)
        for bad in ("not-owned", "rtk-syn-../other", "rtk-syn-bad"):
            with self.assertRaises(ValueError):
                prepare.selected_probe_pod(bad + "-apps", bad, "healthy", "10.43.0.1")
        for ip in ("not-ip", "127.0.0.1", "::1", "0.0.0.0"):
            with self.assertRaises(ValueError):
                prepare.selected_probe_pod(APP, NS, "healthy", ip)

    def test_adapter_create_captures_each_selected_pod_uid_without_retry(self):
        import test_adapter as fake_adapter
        client, transport = fake_adapter.make()
        for phase in ("healthy", "outage", "recovery"):
            obj = prepare.selected_probe_pod(APP, NS, phase, "10.43.0.1")
            created = client.create(obj)
            self.assertEqual(created, {"kind": "Pod", "namespace": APP,
                                       "name": "synthetic-probe-" + phase, "uid": fake_adapter.POD_UID})
        self.assertEqual(len([call for call in transport.calls if call[0][4] == "create"]), 3)
        with self.assertRaises(fake_adapter.a.AdapterError):
            client.create(prepare.selected_probe_pod(APP, NS, "outage", "10.43.0.1"))

    def test_positive_pod_status_and_negative_fail_close_exit(self):
        ids = set()
        for phase in ("healthy", "outage", "recovery"):
            item, start, end = pod(phase)
            ids.add(item["metadata"]["name"])
            result = evidence.assert_selected_probe(item, namespace=APP, phase=phase,
                expected_uid=UID, expected_image_id=IMAGE, expected_api_ip="10.43.0.1",
                outage_started=start - timedelta(seconds=1), outage_ended=end + timedelta(seconds=1))
            self.assertEqual(result, {"phase": phase, "verifiedExit": 42 if phase == "outage" else 0, "uid": UID})
        self.assertEqual(len(ids), 3)

    def test_tamper_denials_and_interval(self):
        item, start, end = pod("outage")
        for tamper in (
            lambda v: v["metadata"].update(uid="another"),
            lambda v: v["metadata"]["labels"].update({evidence.PREFIX + "gateway": "other"}),
            lambda v: v["spec"].update(automountServiceAccountToken=True),
            lambda v: v["spec"]["containers"][0]["securityContext"]["capabilities"].update(add=["NET_ADMIN"]),
            lambda v: v["spec"]["volumes"].append({"name": "credentials", "secret": {"secretName": "x"}}),
            lambda v: v["spec"]["containers"][0].update(args=["healthy", "10.43.0.1"]),
            lambda v: v["status"]["initContainerStatuses"][0]["state"]["terminated"].update(exitCode=1),
            lambda v: v["status"]["containerStatuses"][0]["state"]["terminated"].update(exitCode=1),
            lambda v: v["status"]["containerStatuses"][0].update(imageID="wrong"),
        ):
            invalid = copy.deepcopy(item)
            tamper(invalid)
            with self.assertRaises(evidence.EvidenceError):
                evidence.assert_selected_probe(invalid, namespace=APP, phase="outage",
                    expected_uid=UID, expected_image_id=IMAGE, expected_api_ip="10.43.0.1",
                    outage_started=start - timedelta(seconds=1), outage_ended=end + timedelta(seconds=1))
        with self.assertRaises(evidence.EvidenceError):
            evidence.assert_selected_probe(item, namespace=APP, phase="outage",
                expected_uid=UID, expected_image_id=IMAGE, expected_api_ip="10.43.0.1",
                outage_started=end, outage_ended=end + timedelta(seconds=1))
        with self.assertRaises(evidence.EvidenceError):
            evidence.assert_selected_probe(item, namespace=APP, phase="outage",
                expected_uid=UID, expected_image_id=IMAGE, expected_api_ip="10.43.0.1",
                outage_started=start - timedelta(seconds=1), outage_ended=start)


if __name__ == "__main__": unittest.main()
