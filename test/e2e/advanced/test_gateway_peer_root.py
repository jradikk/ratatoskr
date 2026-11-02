"""Only canonical, public, single-peer key is accepted by root digest helper."""
import base64
import contextlib
import hashlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import gateway_peer_root as root

PUBLIC = base64.b64encode(bytes([8]) * 32)


class RootPublicPeerTest(unittest.TestCase):
    def test_only_exact_one_canonical_public_peer_digest(self):
        expect = hashlib.sha256(PUBLIC).hexdigest()
        self.assertEqual(root.digest(PUBLIC + b"\n"), expect)
        self.assertEqual(root.digest(PUBLIC), expect)
        for invalid in (b"", b"secret-key", PUBLIC + b"\n" + PUBLIC,
                        PUBLIC + b"\nprivate_key=fake", b"x" * 257,
                        PUBLIC[:-1] + b" ", PUBLIC + b"\x00"):
            with self.subTest(invalid=invalid[:12]), self.assertRaises(ValueError):
                root.digest(invalid)

    def test_bad_pid_never_opens_namespace_or_launches_command(self):
        with patch.object(root.os, "open", side_effect=AssertionError("not read")):
            for args in (("0", "123"), ("12", "../1"), ("12", "1")):
                with self.assertRaises(ValueError):
                    root.run(*args)
        with patch.object(root, "run", side_effect=OSError("private material")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(root.main(["12", "13"]), 1)
            self.assertEqual(out.getvalue(), '{"blocked":"peer-key"}\n')


if __name__ == "__main__":
    unittest.main()
