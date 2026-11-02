#!/usr/bin/env python3
"""Synthetic OpenVPN status-v3 data only; no OpenSSL, cluster or private keys."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_session", Path(__file__).parent / "server" / "session.py")
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)


def status(*, common_name="synthetic-client", received="1024", sent="2048", username="UNDEF",
           client_id="", connected=None, updated=None, more=""):
    now = int(time.time())
    connected = now - 20 if connected is None else connected
    updated = now if updated is None else updated
    header = "HEADER\tCLIENT_LIST\t" + "\t".join(session.HEADER)
    row = ["CLIENT_LIST", common_name, "10.42.1.2:1194", "10.88.0.2", "", received, sent,
           "today", str(connected), username, client_id, "7", "AES-256-GCM"]
    return ("TITLE\tOpenVPN 2.6\nTIME\ttoday\t" + str(updated) + "\n" + header + "\n" +
            "\t".join(row) + "\n" + more + "END\n").encode()


class SessionTests(unittest.TestCase):
    def test_only_exact_session_identity_and_counters_returned(self):
        value = session.parse(status())
        self.assertEqual(value, {"sessions": [{"cn": "synthetic-client", "virtualIPv4": "10.88.0.2",
                                 "received": 1024, "sent": 2048, "connected": value["sessions"][0]["connected"],
                                 "peer": 7, "cipher": "AES-256-GCM"}]})
        self.assertNotIn("10.42.1.2", json.dumps(value))
        row = status(common_name="synthetic-witness").decode().split("\nCLIENT_LIST\t", 1)[1].split("\n", 1)[0]
        witness = "CLIENT_LIST\t" + row.replace("10.88.0.2", "10.88.0.3").replace("\t7\t", "\t8\t")
        combined = status(more=witness + "\n")
        result = session.parse(combined)
        self.assertEqual([v["cn"] for v in result["sessions"]], ["synthetic-client", "synthetic-witness"])
        self.assertNotIn("10.42.1.2", json.dumps(result))
        for invalid in (witness.replace("synthetic-witness", "intruder"),
                        witness.replace("synthetic-witness", "synthetic-client"),
                        witness.replace("10.88.0.3", "10.88.0.2")):
            with self.assertRaises(session.Invalid):
                session.parse(status(more=invalid + "\n"))
        self.assertEqual(session.parse(status(client_id="42")), value)

    def test_zero_wrong_cn_duplicate_stale_or_tampered_denied(self):
        stale = int(time.time()) - 30
        variants = (
            b"TITLE\tOpenVPN\nTIME\ttoday\t1\nEND\n", status(common_name="intruder"),
            status()[:-4] + status().split(b"CLIENT_LIST\t", 1)[1],
            status(received="nan"), status(sent="-1"), status(username="user"),
            status(username=""), status(client_id="SECRET"),
            status(updated=stale, connected=stale - 10),
            status(more="CLIENT_LIST\tsynthetic-client\tduplicate\n"),
            status().replace(b"AES-256-GCM", b"NONE"),
            status().replace(b"10.88.0.2", b"192.0.2.99"),
            status().replace(b"END", b"PRIVATE-CREDENTIAL"),
            b"PRIVATE-CREDENTIAL" * 2000,
        )
        for raw in variants:
            with self.subTest(raw_size=len(raw)):
                with self.assertRaises(session.Invalid):
                    session.parse(raw)

    def test_read_status_file_private_mode_and_no_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "status"
            path.write_bytes(status())
            path.chmod(0o600)
            self.assertEqual(session.read_status(path)["sessions"][0]["cn"], session.CNS[0])
            path.chmod(0o644)
            with self.assertRaises(session.Invalid):
                session.read_status(path)
            path.chmod(0o600)
            link = Path(temp) / "linked"
            link.symlink_to(path)
            with self.assertRaises(session.Invalid):
                session.read_status(link)

    def test_cli_never_prints_raw_status_key_or_error(self):
        with patch.object(session, "read_status", side_effect=session.Invalid("PRIVATE-CREDENTIAL")):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(session.main(), 1)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), "")
        with patch.object(session, "read_status", return_value=session.parse(status())):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(session.main(), 0)
            data = json.loads(out.getvalue())
            self.assertEqual(set(data), {"sessions"})
            self.assertEqual([s["cn"] for s in data["sessions"]], ["synthetic-client"])


if __name__ == "__main__":
    unittest.main()
