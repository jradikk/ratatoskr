"""Pure fake CRI/route/netns/packet contracts; no docker, sudo or capture."""
import json
import os
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import failclose_capture as f
import root_capture as root

UID = "a" * 32
CID = "b" * 64
SID = "c" * 64
IMAGE = "sha256:" + "d" * 64
NS = "rtk-syn-" + "e" * 16 + "-apps"
SOURCE = "10.42.2.5"
API = "10.43.0.1"
TABLE = f.TABLE_BASE | 7


def pod(uid=UID, image=IMAGE, cid=CID):
    return {"metadata": {"namespace": NS, "name": "synthetic-client", "uid": uid},
            "spec": {"nodeName": f.node_images.NODES[1]},
            "status": {"phase": "Running", "podIP": SOURCE,
                       "containerStatuses": [{"name": "client", "ready": True,
                                              "imageID": image, "containerID": "containerd://" + cid}]}}


def sandboxes(uid=UID):
    return json.dumps({"items": [{"id": SID, "state": "SANDBOX_READY",
                                   "metadata": {"name": "synthetic-client", "namespace": NS, "uid": uid},
                                   "labels": {"io.kubernetes.pod.uid": uid}}]}).encode()


def sandbox(pid=123, uid=UID, ip=SOURCE):
    return json.dumps({"status": {"id": SID, "state": "SANDBOX_READY", "metadata": {
        "name": "synthetic-client", "namespace": NS, "uid": uid},
        "labels": {"io.kubernetes.pod.uid": uid}, "network": {"ip": ip}},
        "info": {"pid": pid, "runtimeSpec": {"linux": {"namespaces": [{"type": "network",
             "path": "/var/run/netns/synthetic"}]}}}}).encode()


class CollectorTests(unittest.TestCase):
    def test_pinned_uid_cri_pid_and_replacement_are_fail_closed(self):
        self.assertEqual(f.identity(pod(), NS, UID, IMAGE)[1], SOURCE)
        self.assertEqual(f.sandbox_list(sandboxes(), UID, NS), SID)
        self.assertEqual(f.sandbox_status(sandbox(), SID, UID, NS, SOURCE), 123)
        for broken in (pod(uid="f" * 32), pod(image="latest"), pod(cid="bad")):
            with self.assertRaises(f.Blocked):
                f.identity(broken, NS, UID, IMAGE)
        with self.assertRaises(f.Blocked):
            f.sandbox_list(sandboxes(uid="f" * 32), UID, NS)
        for broken in (sandbox(pid=0), sandbox(uid="f" * 32), sandbox(ip="10.42.2.6")):
            with self.assertRaises(f.Blocked):
                f.sandbox_status(broken, SID, UID, NS, SOURCE)

    def test_exact_owned_fallback_and_mark_not_guessed_table(self):
        closed = [{"dst": "default", "type": "unreachable", "protocol": 186,
                   "metric": 4294967295, "table": TABLE}]
        rule = [{"priority": 10998, "protocol": "186", "table": str(TABLE),
                 "fwmark": "0x200000", "fwmask": "0xf00000"}]
        self.assertTrue(f.route_proof(json.dumps(closed).encode(), TABLE))
        for route_type in (7, "7"):
            self.assertTrue(f.route_proof(json.dumps([dict(closed[0], type=route_type)]).encode(), TABLE))
        for route_type in (1, "1", 8, "8", None, True):
            with self.assertRaises(f.Blocked):
                f.route_proof(json.dumps([dict(closed[0], type=route_type)]).encode(), TABLE)
        self.assertTrue(f.rule_proof(json.dumps(rule).encode(), TABLE))
        # Legacy combined form is unambiguous only without fwmask.
        combined = dict(rule[0], fwmark="0x200000/0xf00000")
        combined.pop("fwmask")
        self.assertTrue(f.rule_proof(json.dumps([combined]).encode(), TABLE))
        for bad in ([dict(closed[0], type="unicast")], closed + [dict(closed[0], type="unicast")],
                    [dict(closed[0], metric=0)], [dict(closed[0], protocol="bgp")],
                    [dict(closed[0], protocol="boot")]):
            with self.assertRaises(f.Blocked):
                f.route_proof(json.dumps(bad).encode(), TABLE)
        for bad in ([dict(rule[0], priority=10999)], [dict(rule[0], fwmark="0x0")],
                    [dict(rule[0], fwmask="0x0")], [dict(rule[0], fwmask=None)],
                    [dict(rule[0], fwmark="0x200000/0xf00000")],
                    [dict(rule[0], table=10007)], [dict(rule[0], protocol="bgp")],
                    [dict(rule[0], protocol="boot")]):
            with self.assertRaises(f.Blocked):
                f.rule_proof(json.dumps(bad).encode(), TABLE)

    def test_packet_positive_control_and_no_selected_egress(self):
        positive = b"1.000 IP 10.42.2.5.12345 > 10.43.0.1.443: Flags [S], seq 1\n"
        self.assertTrue(f.capture_proof(positive, SOURCE, API))
        for bad in (b"", positive.replace(b"10.43.0.1.443", b"10.88.0.1.8080"),
                    positive + b"2.000 IP 10.42.2.5.12345 > 10.88.0.1.8080: Flags [S], seq 1\n",
                    positive.replace(b"10.42.2.5", b"10.42.2.6"), positive + b"SECRET\n"):
            with self.assertRaises(f.Blocked):
                f.capture_proof(bad, SOURCE, API)

    def test_root_helper_validates_args_and_pins_netns_type_inode(self):
        self.assertEqual(root.validated(["321", "123", str(TABLE), SOURCE, API])[:3], (321, 123, TABLE))
        for bad in (["321", "0", str(TABLE), SOURCE, API], ["321", "123", "10007", SOURCE, API],
                    ["321", "123", str(TABLE), "10.42.2.5;sh", API]):
            with self.assertRaises(ValueError):
                root.validated(bad)
        class Stat:
            st_ino = 713
        with patch.object(root.os, "open", return_value=70), patch.object(root.os, "close") as closed, \
             patch.object(root.os, "readlink", return_value="net:[713]"), \
             patch.object(root.os, "fstat", return_value=Stat()), \
             patch.object(root.fcntl, "ioctl", return_value=root.CLONE_NEWNET):
            self.assertEqual(root.pin_netns(20, 30), 70)
            closed.assert_not_called()
            with patch.object(root.fcntl, "ioctl", return_value=0):
                with self.assertRaises(ValueError):
                    root.pin_netns(20, 30)
            closed.assert_called_once_with(70)

    def test_proof_exact_fixed_commands_and_pid_uid_rechecks(self):
        class APIReader:
            def __init__(self):
                self.calls = 0
                self.replace = False
            def get(self, kind, name, namespace):
                self.calls += 1
                value = pod()
                if self.replace and self.calls >= 4:
                    value["metadata"]["uid"] = "f" * 32
                return value
        reader = APIReader()
        seen = []
        route = json.dumps([{"dst": "default", "type": "unreachable", "protocol": 186,
                             "metric": 4294967295, "table": TABLE}]).encode()
        rule = json.dumps([{"priority": 10998, "protocol": 186,
                            "table": TABLE, "fwmark": "0x200000/0xf00000"}]).encode()
        def transport(argv, **_kw):
            seen.append(argv)
            if "inspectp" in argv: return sandbox()
            if "pods" in argv: return sandboxes()
            raise AssertionError("Unexpected CRI command")
        def local(argv, **_kw):
            seen.append(argv)
            if argv[:2] == ["docker", "inspect"]: return b"321\n"
            if "route" in argv: return route
            if "rule" in argv: return rule
            raise AssertionError("Unexpected host command")
        def collect(host, sandbox, table, source, api_ip, trigger):
            self.assertEqual((host, sandbox, table, source, api_ip), (321, 123, TABLE, SOURCE, API))
            trigger()
            return {"routeBefore": route.decode(), "ruleBefore": rule.decode(),
                    "capture": "1.000 IP 10.42.2.5.12345 > 10.43.0.1.443: Flags [S], seq 1\n",
                    "routeAfter": route.decode(), "ruleAfter": rule.decode()}
        invoked = []
        self.assertTrue(f.prove(reader, NS, UID, IMAGE, 7, API, transport=transport,
                                local=local, collect_fn=collect,
                                trigger=lambda: invoked.append(True)))
        self.assertEqual(invoked, [True])
        self.assertGreaterEqual(reader.calls, 4)
        self.assertTrue(any("inspectp" in argv for argv in seen))
        self.assertFalse(any("route" in argv or "rule" in argv for argv in seen))
        self.assertTrue(all("sh" not in argv and "-c" not in argv for argv in seen))
        reader = APIReader()
        reader.replace = True
        with self.assertRaises(f.Blocked):
            f.prove(reader, NS, UID, IMAGE, 7, API, transport=transport, local=local,
                    collect_fn=collect, trigger=lambda: None)

    def test_proof_missing_api_positive_or_closed_default_never_passes(self):
        class Reader:
            def get(self, *_): return pod()
        def transport(argv, **_kw):
            return sandbox() if "inspectp" in argv else sandboxes()
        def local(argv, **_kw):
            if argv[:2] == ["docker", "inspect"]: return b"321\n"
            if "route" in argv:
                return json.dumps([{"dst": "default", "type": "unreachable", "protocol": 186,
                                    "metric": 4294967295, "table": TABLE}]).encode()
            return json.dumps([{"priority": 10998, "protocol": "186", "table": str(TABLE),
                                "fwmark": "0x200000", "fwmask": "0xf00000"}]).encode()
        with self.assertRaises(f.Blocked):
            f.prove(Reader(), NS, UID, IMAGE, 7, API, transport=transport, local=local,
                    trigger=lambda: None,
                    collect_fn=lambda host, sandbox, table, source, api_ip, trigger: {
                        "routeBefore": local(["route"]).decode(), "ruleBefore": local(["rule"]).decode(),
                        "capture": "", "routeAfter": local(["route"]).decode(),
                        "ruleAfter": local(["rule"]).decode()})

    def test_root_capture_client_requires_ready_and_bounded_result(self):
        class FakeStream:
            def fileno(self): return 7
            def close(self): pass
        class FakeProc:
            pid = 12345
            stdout = FakeStream()
            stderr = FakeStream()
            stdin = FakeStream()
            def poll(self): return 0
            def wait(self, timeout): return 0
        with patch.object(f.subprocess, "Popen", return_value=FakeProc()), \
             patch.object(f.os, "set_blocking"), patch.object(f.os, "killpg"), \
             patch.object(f.selectors, "DefaultSelector") as selector:
            selector.return_value.get_map.return_value = {1: 1}
            callback = []
            with self.assertRaises(f.Blocked):
                f.root_collect(321, 123, TABLE, SOURCE, API, lambda: callback.append(True))
            self.assertEqual(callback, [])


if __name__ == "__main__":
    unittest.main()
