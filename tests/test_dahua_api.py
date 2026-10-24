"""Unit tests for Dahua digest auth + device info fetch (stdlib only)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "custom_components" / "lixil_companion"),
)

import dahua_api as api  # noqa: E402


class TestDigest(unittest.TestCase):
    def test_rfc7616_example_vector(self):
        # The canonical RFC 2617/7616 example - expected response is known.
        header = api.build_digest_header(
            method="GET",
            uri="/dir/index.html",
            username="Mufasa",
            password="Circle Of Life",
            challenge={
                "realm": "testrealm@host.com",
                "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                "qop": "auth",
                "algorithm": "MD5",
            },
            nc="00000001",
            cnonce="0a4f113b",
        )
        self.assertIn('response="6629fae49393a05397450978507c4ef1"', header)
        self.assertIn('username="Mufasa"', header)

    def test_parse_www_authenticate(self):
        parsed = api.parse_www_authenticate(
            'Digest realm="Login to IPC", nonce="abc123", qop="auth", algorithm=MD5'
        )
        self.assertEqual(parsed["realm"], "Login to IPC")
        self.assertEqual(parsed["nonce"], "abc123")
        self.assertEqual(parsed["qop"], "auth")
        self.assertEqual(parsed["algorithm"], "MD5")


class FakeCamera:
    """Transport stub emulating a Dahua digest handshake."""

    def __init__(self, password="Ab12Cd34", serial="FAKE1234567890"):
        self.password = password
        self.serial = serial
        self.requests = []

    def __call__(self, method, path, headers):
        self.requests.append((path, dict(headers)))
        if "Authorization" not in headers:
            return (
                401,
                {"www-authenticate": 'Digest realm="Login to IPC", nonce="n0nce", qop="auth"'},
                "",
            )
        expected = api.build_digest_header(
            method="GET",
            uri=path,
            username="admin",
            password=self.password,
            challenge={"realm": "Login to IPC", "nonce": "n0nce", "qop": "auth"},
        )
        if headers["Authorization"] != expected:
            return 401, {}, ""
        if "getSerialNo" in path:
            return 200, {}, f"sn={self.serial}\n"
        if "getDeviceType" in path:
            return 200, {}, "type=FAKE-CAM-9000\n"
        return 404, {}, ""


class TestFetchDeviceInfo(unittest.TestCase):
    def test_happy_path(self):
        cam = FakeCamera()
        info = api.fetch_device_info("192.0.2.10", "admin", "Ab12Cd34", transport=cam)
        self.assertEqual(info["serial"], "FAKE1234567890")
        self.assertEqual(info["device_type"], "FAKE-CAM-9000")

    def test_wrong_password_raises_auth(self):
        cam = FakeCamera()
        with self.assertRaises(api.DahuaAuthError):
            api.fetch_device_info("192.0.2.10", "admin", "WrongPass1", transport=cam)

    def test_unreachable_raises(self):
        def boom(method, path, headers):
            raise ConnectionRefusedError("nope")

        with self.assertRaises(api.DahuaUnreachableError):
            api.fetch_device_info("192.0.2.10", "admin", "Ab12Cd34", transport=boom)


if __name__ == "__main__":
    unittest.main()
