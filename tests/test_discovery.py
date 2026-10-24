"""Unit tests for discovery fingerprinting/parsing (stdlib only).

Fixtures are synthetic except the LS279 MAC OUI, which was observed on
the author's real unit (prefix only, no full address).
"""

import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "custom_components" / "lixil_companion"),
)

import discovery as d  # noqa: E402


class TestClassify(unittest.TestCase):
    def test_full_dahua_profile_is_likely(self):
        fp = d.classify(
            "192.0.2.10",
            mac="1c:4d:89:aa:bb:cc",
            open_ports=(80, 554, 37777),
            http_server="Dahua Web Server",
            http_body="<html><title>WEB SERVICE</title></html>",
        )
        self.assertTrue(fp.is_likely_dahua)
        self.assertGreaterEqual(fp.score, 90)
        self.assertIn("dahua_private_port", fp.reasons)

    def test_rtsp_only_is_not_enough(self):
        fp = d.classify("192.0.2.11", open_ports=(554,))
        self.assertFalse(fp.is_likely_dahua)

    def test_private_port_plus_rtsp_is_likely(self):
        fp = d.classify("192.0.2.12", open_ports=(554, 37777))
        self.assertTrue(fp.is_likely_dahua)

    def test_generic_http_host_scores_low(self):
        fp = d.classify(
            "192.0.2.13",
            open_ports=(80,),
            http_server="nginx",
            http_body="<title>Welcome</title>",
        )
        self.assertFalse(fp.is_likely_dahua)
        self.assertEqual(fp.http_title, "Welcome")

    def test_unknown_mac_oui_no_bonus(self):
        fp = d.classify("192.0.2.14", mac="00:11:22:33:44:55", open_ports=(37777,))
        self.assertNotIn("dahua_mac_oui", fp.reasons)


class TestParsers(unittest.TestCase):
    def test_magicbox_serial(self):
        self.assertEqual(d.parse_magicbox("sn=FAKE1234567890\n"), {"sn": "FAKE1234567890"})

    def test_magicbox_device_type_and_junk(self):
        out = d.parse_magicbox("error\ntype=LS279-LIKE\nfoo=bar baz\n")
        self.assertEqual(out["type"], "LS279-LIKE")
        self.assertEqual(out["foo"], "bar baz")

    def test_onvif_probe_matches(self):
        xml = (
            "<ProbeMatches><ProbeMatch>"
            "<XAddrs>http://192.0.2.20/onvif/device_service</XAddrs>"
            "<Scopes>onvif://www.onvif.org/type/video_encoder "
            "onvif://www.onvif.org/serial/FAKE1234567890</Scopes>"
            "</ProbeMatch></ProbeMatches>"
        )
        out = d.parse_onvif_probe_matches(xml)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "192.0.2.20")
        self.assertEqual(out[0]["serial"], "FAKE1234567890")

    def test_onvif_empty(self):
        self.assertEqual(d.parse_onvif_probe_matches(""), [])

    def test_arp_bsd_format(self):
        arp = "? (192.0.2.10) at 1c:4d:89:aa:bb:cc on en0 ifscope [ethernet]\n"
        self.assertEqual(d.mac_from_arp_table(arp, "192.0.2.10"), "1c:4d:89:aa:bb:cc")
        self.assertIsNone(d.mac_from_arp_table(arp, "192.0.2.99"))

    def test_subnet_hosts(self):
        hosts = d.subnet_hosts("192.0.2.55")
        self.assertEqual(len(hosts), 254)
        self.assertEqual(hosts[0], "192.0.2.1")
        self.assertEqual(hosts[-1], "192.0.2.254")
        with self.assertRaises(ValueError):
            d.subnet_hosts("not-an-ip")


class TestScanOrchestration(unittest.TestCase):
    """Scan logic with network probers faked - no real sockets touched."""

    def _run_scan(self):
        from unittest.mock import AsyncMock, patch

        async def fake_port(ip, port, timeout=0.8):
            return ip.endswith(".10") and port in (554, 37777, 80)

        async def fake_http(ip, port=80, timeout=1.5):
            if ip.endswith(".10"):
                return "Dahua Web Server", "<title>WEB SERVICE</title>"
            return None, ""

        with patch.object(d, "probe_port", AsyncMock(side_effect=fake_port)), patch.object(
            d, "fetch_http", AsyncMock(side_effect=fake_http)
        ):
            return asyncio.run(d.scan_subnet("192.0.2.55"))

    def test_scan_finds_only_the_dahua_like_host(self):
        found = self._run_scan()
        self.assertEqual([fp.ip for fp in found], ["192.0.2.10"])
        self.assertTrue(found[0].is_likely_dahua)
        self.assertIn("dahua_http_marker", found[0].reasons)


if __name__ == "__main__":
    unittest.main()


class CandidateOptionsTests(unittest.TestCase):
    def test_label_includes_ip_mac_score(self):
        fp = d.classify("192.168.11.115", mac="1c:4d:89:5d:25:a0",
                      open_ports=(37777, 554))
        label = d.candidate_label(fp)
        self.assertIn("192.168.11.115", label)
        self.assertIn("1c:4d:89:5d:25:a0", label)

    def test_options_filters_and_sorts(self):
        strong = d.classify("192.168.11.115", open_ports=(37777, 554))
        weak = d.classify("192.168.11.50", open_ports=(554,))
        opts = d.candidate_options([weak, strong])
        self.assertEqual(list(opts), ["192.168.11.115"])


