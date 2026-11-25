"""Run with:  python -m unittest discover -s tests -v"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils import rsa_utils as r

# 1024-bit keys keep the test suite fast; the scripts default to 2048.
_TMP = tempfile.TemporaryDirectory()
E, D, N = r.generate_keys(_TMP.name, bits=1024)


def tearDownModule():
    _TMP.cleanup()


class PrimeTests(unittest.TestCase):
    def test_known_primes(self):
        for p in (2, 3, 5, 97, 7919, 2**61 - 1):
            self.assertTrue(r.is_prime(p), p)

    def test_known_composites(self):
        for c in (0, 1, 4, 100, 7917, 2**61 + 1):
            self.assertFalse(r.is_prime(c), c)

    def test_carmichael_numbers_rejected(self):
        # These fool the old Fermat test; Miller-Rabin must reject them.
        for c in (561, 1105, 1729, 2465, 2821, 6601, 8911):
            self.assertFalse(r.is_prime(c), c)

    def test_generate_prime_bit_length(self):
        p = r.generate_prime(256)
        self.assertEqual(p.bit_length(), 256)
        self.assertTrue(r.is_prime(p))


class KeyTests(unittest.TestCase):
    def test_key_properties(self):
        self.assertEqual(E, 65537)
        self.assertEqual(N.bit_length(), 1024)
        self.assertEqual(pow(pow(12345, E, N), D, N), 12345)

    def test_key_files_round_trip(self):
        self.assertEqual(r.read_key(Path(_TMP.name) / "public_key.txt"), (E, N))
        self.assertEqual(r.read_key(Path(_TMP.name) / "private_key.txt"), (D, N))


class SignatureTests(unittest.TestCase):
    def test_valid_signature(self):
        sig = r.sign_message("hello", D, N)
        self.assertTrue(r.verify_signature("hello", sig, E, N))

    def test_tampered_message_rejected(self):
        sig = r.sign_message("hello", D, N)
        self.assertFalse(r.verify_signature("hellp", sig, E, N))

    def test_tampered_signature_rejected(self):
        sig = r.sign_message("hello", D, N)
        self.assertFalse(r.verify_signature("hello", sig + 1, E, N))
        self.assertFalse(r.verify_signature("hello", 0, E, N))
        self.assertFalse(r.verify_signature("hello", N + 5, E, N))

    def test_wrong_key_rejected(self):
        with tempfile.TemporaryDirectory() as other:
            e2, _, n2 = r.generate_keys(other, bits=1024)
        sig = r.sign_message("hello", D, N)
        self.assertFalse(r.verify_signature("hello", sig, e2, n2))

    def test_signing_is_deterministic(self):
        self.assertEqual(r.sign_message("x", D, N), r.sign_message("x", D, N))


class ParsingTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(r.parse_signed_text("hi there\n12345"), ("hi there", 12345))

    def test_parse_crlf_and_multiline(self):
        self.assertEqual(r.parse_signed_text("a\r\nb\r\n99\r\n"), ("a\nb", 99))

    def test_parse_rejects_bad_input(self):
        for bad in ("only one line", "msg\nnot-a-number", ""):
            with self.assertRaises(ValueError):
                r.parse_signed_text(bad)


class ServerTests(unittest.TestCase):
    def setUp(self):
        import importlib
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
        self.app_module = importlib.import_module("app")
        self.tmp = tempfile.TemporaryDirectory()
        self.app_module.CHECKED_MESSAGE_PATH = Path(self.tmp.name) / "checked_message.txt"
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_download_before_upload_is_404(self):
        self.assertEqual(self.client.get("/api/download").status_code, 404)

    def test_empty_post_is_400(self):
        self.assertEqual(self.client.post("/api/receive", data={}).status_code, 400)

    def test_malformed_post_is_400(self):
        resp = self.client.post("/api/receive", data={"signed_message": "no signature here"})
        self.assertEqual(resp.status_code, 400)

    def test_round_trip_and_verify(self):
        sig = r.sign_message("hello", D, N)
        resp = self.client.post("/api/receive", data={"signed_message": f"hello\r\n{sig}"})  # CRLF like a browser
        self.assertEqual(resp.status_code, 200)
        with self.client.get("/api/download") as download:
            text = download.get_data(as_text=True)
        message, signature = r.parse_signed_text(text)
        self.assertTrue(r.verify_signature(message, signature, E, N))


if __name__ == "__main__":
    unittest.main()
