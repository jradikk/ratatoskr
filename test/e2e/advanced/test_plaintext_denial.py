"""Pure fake denial evidence; no host/cluster commands or private data."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import plaintext_denial as d
import plaintext_root as r

UID = "a" * 32
SID = "b" * 64
CID = "c" * 64
SOURCE = "10.42.1.8"
GATEWAY = "10.42.0.7"
IDS = {"selected": "containerd://sha256:" + "d" * 64,
       "gateway": "containerd://sha256:" + "e" * 64}


def sandbox(uid=UID, name="synthetic-client", namespace="apps", ip=SOURCE, pid=123):
    return {"status": {"id": SID, "state": "SANDBOX_READY",
            "metadata": {"uid": uid, "namespace": namespace, "name": name},
            "labels": {"io.kubernetes.pod.uid": uid}, "network": {"ip": ip}},
            "info": {"pid": pid, "runtimeSpec": {"linux": {"namespaces": [
                {"type": "network", "path": "/var/run/netns/owned"}]}}}}


class DenialTests(unittest.TestCase):
    def test_nft_exact_input_guard_and_counter(self):
        chain = {"chain": {"family": "inet", "table": "ratatoskr_wg", "name": "input",
                           "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}
        expr = [{"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "rtkwg0"}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}},
                           "right": 6081}}, {"counter": {"packets": 9, "bytes": 900}}, {"drop": None}]
        rule = {"rule": {"family": "inet", "table": "ratatoskr_wg", "chain": "input", "expr": expr}}
        self.assertEqual(r.guard(json.dumps({"nftables": [{"metainfo": {}}, chain, rule]}).encode()), 9)
        import copy
        for field, replacement in (("interface", "eth0"), ("port", 51820),
                                   ("counter", -1), ("verdict", "accept")):
            with self.subTest(field=field):
                bad = copy.deepcopy({"nftables": [chain, rule]})
                altered = bad["nftables"][1]["rule"]["expr"]
                if field == "interface": altered[0]["match"]["right"] = replacement
                elif field == "port": altered[1]["match"]["right"] = replacement
                elif field == "counter": altered[2]["counter"]["packets"] = replacement
                else: altered[3] = {replacement: None}
                with self.assertRaises(ValueError): r.guard(json.dumps(bad).encode())

    def test_root_helper_only_fixed_failure_category_crosses_stdout(self):
        import contextlib
        import io
        for label in ("guard-before", "capture-start", "send", "header-parse"):
            with self.subTest(label=label), patch.object(r, "collect", side_effect=ValueError("PRIVATE_ERROR")), \
                 patch.object(r, "checkpoint", wraps=r.checkpoint):
                r._stage = label
                output = io.StringIO()
                with patch.object(r, "validated", return_value=tuple()), contextlib.redirect_stdout(output):
                    # main resets stage first; patched collect selects a fixed stage.
                    def fail(_args):
                        r.checkpoint(label)
                        raise ValueError("PRIVATE_ERROR")
                    with patch.object(r, "collect", side_effect=fail):
                        self.assertEqual(r.main(), 1)
                self.assertEqual(json.loads(output.getvalue()), {"blocked": label})
                self.assertNotIn("PRIVATE_ERROR", output.getvalue())

    def test_raw_l2_packet_route_neighbor_and_fixed_content(self):
        route = json.dumps([{"dst": GATEWAY, "dev": "eth0", "prefsrc": SOURCE,
                             "gateway": "10.42.1.1"}]).encode()
        self.assertEqual(r.route_next_hop(route, SOURCE, GATEWAY), "10.42.1.1")
        for bad in ([{"dst": GATEWAY, "dev": "rtkwg0", "prefsrc": SOURCE}],
                    [{"dst": GATEWAY, "dev": "eth0", "prefsrc": "10.42.2.8"}]):
            with self.assertRaises(ValueError):
                r.route_next_hop(json.dumps(bad).encode(), SOURCE, GATEWAY)
        link = json.dumps([{"ifname": "eth0", "address": "02:00:00:00:00:02"}]).encode()
        neigh = json.dumps([{"dst": "10.42.1.1", "dev": "eth0", "lladdr": "02:00:00:00:00:03",
                             "state": ["REACHABLE"]}]).encode()
        source_mac = r.link_mac(link)
        dest_mac = r.neighbor_mac(neigh, "10.42.1.1")
        raw = r.packet(SOURCE, GATEWAY, 7, source_mac, dest_mac)
        self.assertEqual(raw[:14], dest_mac + source_mac + b"\x08\x00")
        self.assertEqual(r.ip_checksum(raw[14:34]), 0)
        self.assertEqual(raw[36:38], (6081).to_bytes(2, "big"))
        self.assertEqual(raw[42:46], b"\0\0\x65\x58")
        self.assertEqual(len(raw), 92)
        for malformed in (neigh.replace(b"REACHABLE", b"FAILED"),
                          neigh.replace(b'["REACHABLE"]', b'"REACHABLE"'),
                          neigh.replace(b'["REACHABLE"]', b'["REACHABLE","STALE"]')):
            with self.assertRaises(ValueError):
                r.neighbor_mac(malformed, "10.42.1.1")
        with self.assertRaises(ValueError):
            r.mac("ff:ff:ff:ff:ff:ff")

    def test_interface_bound_neighbor_query_may_omit_dev(self):
        entry = {"dst": "10.42.1.1", "lladdr": "02:00:00:00:00:03", "state": ["REACHABLE"]}
        self.assertEqual(r.neighbor_mac(json.dumps([entry]).encode(), "10.42.1.1"),
                         bytes.fromhex("020000000003"))
        for device in ("eth1", None):
            with self.subTest(device=device), self.assertRaises(ValueError):
                r.neighbor_mac(json.dumps([dict(entry, dev=device)]).encode(), "10.42.1.1")

    def test_inner_and_outer_ipv4_lengths_and_checksums_are_valid(self):
        import socket
        import struct
        inner = r.frame(7, SOURCE, GATEWAY)
        self.assertEqual(len(inner), 50)
        self.assertEqual(inner[:4], b"\x00\x00\x65\x58")
        self.assertEqual(int.from_bytes(inner[4:7], "big"), 7)
        ip = inner[22:42]
        self.assertEqual(struct.unpack("!H", ip[2:4])[0], 28)
        self.assertEqual(r.ip_checksum(ip), 0)
        self.assertEqual(ip[12:16], socket.inet_aton(SOURCE))
        self.assertEqual(ip[16:20], socket.inet_aton(GATEWAY))
        self.assertEqual(struct.unpack("!HHHH", inner[42:]), (40000, 8080, 8, 0))
        packet = r.packet(SOURCE, GATEWAY, 7, bytes.fromhex("020000000001"),
                          bytes.fromhex("020000000002"))
        self.assertEqual(len(packet), 92)
        self.assertEqual(r.ip_checksum(packet[14:34]), 0)
        self.assertEqual(struct.unpack("!H", packet[16:18])[0], len(packet) - 14)
        self.assertEqual(struct.unpack("!HHHH", packet[34:42]), (40000, 6081, 58, 0))
        self.assertEqual(packet[42:], inner)

    def test_raw_l2_sender_only_three_approved_datagrams(self):
        import socket
        observed = []
        class Sock:
            def setsockopt(self, *_): raise AssertionError("unexpected setsockopt")
            def bind(self, value): observed.append(("bind", value))
            def send(self, data): observed.append(("send", data)); return len(data)
            def close(self): observed.append(("close",))
        def fake_run(argv, fd, **_kw):
            observed.append(("argv", argv))
            if "route" in argv: return json.dumps([{"dst": GATEWAY, "dev": "eth0",
                "prefsrc": SOURCE, "gateway": "10.42.1.1"}]).encode()
            if "neigh" in argv: return json.dumps([{"dst": "10.42.1.1", "dev": "eth0",
                "lladdr": "02:00:00:00:00:03", "state": ["REACHABLE"]}]).encode()
            return json.dumps([{"ifname": "eth0", "address": "02:00:00:00:00:02"}]).encode()
        with patch.object(r, "run", side_effect=fake_run), patch.object(r.socket, "socket", return_value=Sock()) as sock:
            r.send([SOURCE, GATEWAY, "7"])
        self.assertEqual(sock.call_args.args[:2], (socket.AF_PACKET, socket.SOCK_RAW))
        self.assertEqual(len([x for x in observed if x[0] == "send"]), 3)
        sent = [x[1] for x in observed if x[0] == "send"]
        self.assertTrue(all(packet == sent[0] for packet in sent))
        self.assertFalse(any(x[0] == "argv" and any(token in ("sh", "bash", "-c") for token in x[1])
                             for x in observed))

    def test_exact_plaintext_arrival_drop_and_no_gnv_delivery(self):
        good = {"source": SOURCE, "gateway": GATEWAY, "vni": 7, "sent": 3,
                "ethIn": 2, "gnvIn": 0, "dropBefore": 10, "dropAfter": 12}
        self.assertTrue(d.proof(json.dumps(good).encode(), source=SOURCE, gateway=GATEWAY, vni=7))
        for change in ({"ethIn": 0}, {"gnvIn": 1}, {"dropAfter": 11}, {"sent": 0},
                       {"gateway": "10.42.0.8"}, {"vni": 8}, {"dropBefore": 15},
                       {"dropAfter": True}):
            with self.subTest(change=change), self.assertRaises(d.Blocked):
                d.proof(json.dumps(dict(good, **change)).encode(), source=SOURCE, gateway=GATEWAY, vni=7)

    def test_ownership_cri_wrong_uid_pid_ip_and_missing_capture_fail(self):
        listing = {"items": [{"id": SID, "state": "SANDBOX_READY",
                              "metadata": {"uid": UID, "namespace": "apps", "name": "synthetic-client"},
                              "labels": {"io.kubernetes.pod.uid": UID}}]}
        self.assertEqual(d.sandbox_id(json.dumps(listing).encode(), UID, "apps", "synthetic-client"), SID)
        self.assertEqual(d.sandbox_pid(json.dumps(sandbox()).encode(), SID, UID, "apps", "synthetic-client", SOURCE), 123)
        for value in (sandbox(uid="f" * 32), sandbox(pid=0), sandbox(ip="10.42.2.8")):
            with self.assertRaises(d.Blocked):
                d.sandbox_pid(json.dumps(value).encode(), SID, UID, "apps", "synthetic-client", SOURCE)
        with self.assertRaises(d.Blocked):
            d.sandbox_id(json.dumps(listing).encode(), "f" * 32, "apps", "synthetic-client")

    def test_already_entered_sender_does_not_pass_invalid_fd(self):
        import subprocess
        result = r.run([sys.executable, "-c", "pass"], -1, limit=0, timeout=2)
        self.assertEqual(result, b"")
        with patch.object(r.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"")) as mocked:
            r.run(["fixed-command"], 9, limit=0, timeout=2)
            self.assertEqual(mocked.call_args.kwargs["pass_fds"], (9,))

    def test_root_fixed_args_frame_and_no_dynamic_command(self):
        self.assertEqual(r.validated(["321", "123", "322", "124", SOURCE, GATEWAY, "7"]),
                         (321, 123, 322, 124, SOURCE, GATEWAY, 7))
        self.assertEqual(len(r.frame(7, SOURCE, GATEWAY)), 50)
        for bad in (["321", "0", "322", "124", SOURCE, GATEWAY, "7"],
                    ["321", "123", "322", "124", SOURCE, GATEWAY, "7;sh"],
                    ["321", "123", "322", "124", SOURCE, GATEWAY, "16777216"]):
            with self.assertRaises(ValueError): r.validated(bad)
        raw = json.dumps([{"ifname": "gnv0", "stats64": {"rx": {"packets": 11}}}]).encode()
        self.assertEqual(r.rx_packets(raw), 11)
        with self.assertRaises(ValueError): r.rx_packets(raw.replace(b"gnv0", b"eth0"))


if __name__ == "__main__": unittest.main()
