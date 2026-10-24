"""Unit tests for the QR payload parser (stdlib unittest, no HA needed).

All serials/codes below are fictional test fixtures.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "custom_components" / "lixil_companion"),
)

from qr import QrParseError, parse_qr_text, sn_matches  # noqa: E402


class TestParseQrText(unittest.TestCase):
    def test_canonical_payload(self):
        data = parse_qr_text("{SN:FAKE1234567890, SC:Ab12Cd34, PID:98765}")
        self.assertEqual(data.sn, "FAKE1234567890")
        self.assertEqual(data.sc, "Ab12Cd34")
        self.assertEqual(data.pid, "98765")
        self.assertFalse(data.partial)
        self.assertEqual(data.warnings, ())

    def test_json_style_payload(self):
        data = parse_qr_text('{"SN": "FAKE1234567890", "SC": "Ab12Cd34", "PID": "98765"}')
        self.assertEqual(data.sc, "Ab12Cd34")
        self.assertEqual(data.sn, "FAKE1234567890")

    def test_messy_whitespace_and_newlines(self):
        text = "  \n {  SN : FAKE1234567890 ,\n SC : Ab12Cd34 , PID : 98765 } \n "
        data = parse_qr_text(text)
        self.assertEqual(data.sc, "Ab12Cd34")
        self.assertEqual(data.pid, "98765")

    def test_payload_embedded_in_noise(self):
        text = "scanned result => {SN:FAKE1234567890, SC:Ab12Cd34, PID:98765} (copied)"
        data = parse_qr_text(text)
        self.assertEqual(data.sc, "Ab12Cd34")

    def test_bare_security_code(self):
        data = parse_qr_text("Ab12Cd34")
        self.assertEqual(data.sc, "Ab12Cd34")
        self.assertIsNone(data.sn)
        self.assertTrue(data.partial)
        self.assertIn("qr_bare_sc", data.warnings)

    def test_missing_sc_in_block_raises(self):
        with self.assertRaises(QrParseError) as ctx:
            parse_qr_text("{SN:FAKE1234567890, PID:98765}")
        self.assertEqual(ctx.exception.key, "qr_missing_sc")

    def test_missing_sn_warns_but_extracts(self):
        data = parse_qr_text("{SC:Ab12Cd34, PID:98765}")
        self.assertEqual(data.sc, "Ab12Cd34")
        self.assertIsNone(data.sn)
        self.assertIn("qr_missing_sn", data.warnings)

    def test_empty_raises(self):
        for bad in ("", "   ", "\n\n"):
            with self.assertRaises(QrParseError) as ctx:
                parse_qr_text(bad)
            self.assertEqual(ctx.exception.key, "qr_empty")

    def test_unrecognized_raises(self):
        with self.assertRaises(QrParseError) as ctx:
            parse_qr_text("hello world this is not a code")
        self.assertEqual(ctx.exception.key, "qr_unrecognized")


class TestSnMatches(unittest.TestCase):
    def test_match_case_insensitive(self):
        data = parse_qr_text("{SN:fake1234567890, SC:Ab12Cd34, PID:98765}")
        self.assertTrue(sn_matches(data, "FAKE1234567890"))

    def test_mismatch(self):
        data = parse_qr_text("{SN:FAKE1234567890, SC:Ab12Cd34, PID:98765}")
        self.assertFalse(sn_matches(data, "OTHER987654321"))

    def test_cannot_check_returns_none(self):
        data = parse_qr_text("Ab12Cd34")  # bare code, no SN
        self.assertIsNone(sn_matches(data, "FAKE1234567890"))
        data2 = parse_qr_text("{SN:FAKE1234567890, SC:Ab12Cd34, PID:98765}")
        self.assertIsNone(sn_matches(data2, None))


if __name__ == "__main__":
    unittest.main()
