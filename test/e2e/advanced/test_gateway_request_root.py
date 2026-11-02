"""Offline node-netns TLS helper tests; no root, network or cluster needed."""
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import gateway_negative as neg
import gateway_request_root as root
import test_gateway_negative as fixture


class RequestRootTest(unittest.TestCase):
    def test_root_input_shape_and_fixed_failure_taxonomy(self):
        value = {"gatewayPodIP": "10.42.0.7", "registrationCACert": fixture.CA,
                 "token": fixture.SECRET}
        payload = json.dumps(value).encode()
        self.assertEqual(root.read_input(io.BytesIO(payload)), value)
        for raw in (b"", b"x" * 20501, b"{}", b'{"gatewayPodIP":"x","token":"x"}',
                    json.dumps({**value, "privateKey": "forbidden"}).encode()):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                root.read_input(io.BytesIO(raw))
        for failure, label in ((neg.ConnectBlocked("secret"), "connect"),
                               (neg.TLSBlocked("secret"), "tls"),
                               (neg.Blocked("secret"), "http"),
                               (OSError("secret"), "http")):
            with patch.object(root, "enter_node"), patch.object(root.gateway_negative, "send", side_effect=failure):
                output = io.StringIO()
                with patch("sys.stdout", output):
                    self.assertEqual(root.main(["234"], io.BytesIO(payload)), 0)
                self.assertEqual(output.getvalue(), '{"blocked":"' + label + '"}\n')
                self.assertNotIn(fixture.SECRET, output.getvalue())
        with patch.object(root, "enter_node", side_effect=ValueError("secret")):
            output = io.StringIO()
            with patch("sys.stdout", output):
                self.assertEqual(root.main(["234"], io.BytesIO(payload)), 0)
            self.assertEqual(output.getvalue(), '{"blocked":"netns"}\n')

    def test_valid_status_scalar_only_after_entered_netns(self):
        value = {"gatewayPodIP": "10.42.0.7", "registrationCACert": fixture.CA,
                 "token": fixture.SECRET}
        with patch.object(root, "enter_node") as entered, patch.object(
                root.gateway_negative, "send", return_value=401) as tls:
            output = io.StringIO()
            with patch("sys.stdout", output):
                self.assertEqual(root.main(["234"], io.BytesIO(json.dumps(value).encode())), 0)
        entered.assert_called_once_with("234")
        tls.assert_called_once_with("10.42.0.7", fixture.CA, fixture.SECRET)
        self.assertEqual(output.getvalue(), '{"status":401}\n')

    def test_invalid_pid_never_opens_proc_or_drops_privileges(self):
        with patch.object(root.os, "open", side_effect=AssertionError("no fs")):
            for host in ("0", "../1", "1"):
                with self.assertRaises(ValueError):
                    root.enter_node(host)
        with patch.object(root.os, "open", return_value=13) as opened, \
                patch.object(root.os, "readlink", return_value="net:[123]"), \
                patch.object(root.fcntl, "ioctl", return_value=root.CLONE_NEWNET), \
                patch.object(root.os, "fstat") as stats, \
                patch.object(root.os, "setns"), patch.object(root.os, "setgroups"), \
                patch.object(root.os, "setgid"), patch.object(root.os, "setuid"), \
                patch.object(root.os, "close"):
            stats.return_value.st_ino = 123
            root.enter_node("234")
            opened.assert_called_once_with("/proc/234/ns/net", root.os.O_RDONLY | root.os.O_CLOEXEC)


class NodePinnedTest(unittest.TestCase):
    def test_secret_only_stdin_exact_verified_node_sandbox_and_second_pin(self):
        source = fixture.Source(); source.owner = fixture.Owner()
        source.pod["spec"]["nodeName"] = neg.wg.node_images.NODES[0]
        source.pod["status"]["containerStatuses"] = [{"name": "client", "ready": True, "imageID": "image"}]
        commands = []
        sid = "f" * 64
        ip = source.pod["status"]["podIP"]
        def transport(argv, *, timeout, max_output):
            commands.append(argv)
            if argv[1] == "inspect": return b"234\n"
            if "inspectp" in argv:
                return json.dumps({"status": {"id": sid, "state": "SANDBOX_READY",
                          "metadata": {"uid": fixture.UID, "namespace": fixture.NS,
                                       "name": neg.wg.CLIENT},
                          "labels": {"io.kubernetes.pod.uid": fixture.UID},
                          "network": {"ip": ip}}, "info": {"pid": 567,
                          "runtimeSpec": {"linux": {"namespaces": [{"type": "network",
                                                        "path": "/var/run/netns/owned"}]}}}}).encode()
            return json.dumps({"items": [{"id": sid, "state": "SANDBOX_READY",
                            "metadata": {"uid": fixture.UID, "namespace": fixture.NS,
                                         "name": neg.wg.CLIENT},
                            "labels": {"io.kubernetes.pod.uid": fixture.UID}}]}).encode()
        sent = []
        def stdin(argv, *, payload, timeout, max_output):
            sent.append((argv, payload, timeout, max_output))
            return b'{"status":401}\n'
        self.assertEqual(neg.send_from_node(source, fixture.UID, fixture.NAME, "image",
                                             "10.42.0.7", fixture.CA, fixture.SECRET,
                                             transport=transport, root_transport=stdin), 401)
        self.assertEqual(len(sent), 1)
        argv, payload, timeout, max_output = sent[0]
        self.assertEqual(argv[-1:], ["234"])
        self.assertTrue(argv[0:3] == ["sudo", "-n", "/usr/bin/python3"])
        self.assertNotIn(fixture.SECRET, " ".join(argv))
        self.assertEqual(json.loads(payload)["token"], fixture.SECRET)
        self.assertEqual((timeout, max_output), (20, 128))
        self.assertEqual(len(commands), 6)
        def replaced(argv, *, payload, timeout, max_output):
            source.pod = fixture.selected(uid="0" * 32)
            return b'{"status":401}\n'
        with self.assertRaises((neg.Blocked, neg.wg.Blocked, neg.auth.Blocked)):
            neg.send_from_node(source, fixture.UID, fixture.NAME, "image", "10.42.0.7",
                               fixture.CA, fixture.SECRET, transport=transport,
                               root_transport=replaced)


if __name__ == "__main__":
    unittest.main()
