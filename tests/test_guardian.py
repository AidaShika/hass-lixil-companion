"""Unit tests for the guardian decision core + ARP reverse lookups."""

import sys
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "custom_components" / "lixil_companion"),
)

import discovery as d  # noqa: E402
from guardian import GuardianTracker  # noqa: E402


class TestArpReverse(unittest.TestCase):
    BSD = "? (192.0.2.10) at 1c:4d:89:aa:bb:cc on en0 ifscope [ethernet]\n"
    PROC = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.0.2.10       0x1         0x2         1c:4d:89:aa:bb:cc     *        eth0\n"
        "192.0.2.1        0x1         0x2         00:11:22:33:44:55     *        eth0\n"
    )

    def test_ip_from_bsd_arp(self):
        self.assertEqual(d.ip_from_arp_table(self.BSD, "1c:4d:89:aa:bb:cc"), "192.0.2.10")

    def test_ip_from_proc_arp(self):
        self.assertEqual(d.ip_from_arp_table(self.PROC, "1C:4D:89:AA:BB:CC"), "192.0.2.10")
        self.assertEqual(d.mac_from_arp_table(self.PROC, "192.0.2.1"), "00:11:22:33:44:55")

    def test_ip_not_found(self):
        self.assertIsNone(d.ip_from_arp_table(self.PROC, "de:ad:be:ef:00:01"))


class TestGuardianTracker(unittest.TestCase):
    def test_same_ip_no_action(self):
        t = GuardianTracker()
        self.assertEqual(t.found("192.0.2.10", "192.0.2.10").action, "none")

    def test_new_ip_triggers_update(self):
        t = GuardianTracker()
        dec = t.found("192.0.2.10", "192.0.2.11")
        self.assertEqual(dec.action, "update")
        self.assertEqual(dec.new_ip, "192.0.2.11")

    def test_notify_only_after_threshold_and_once(self):
        t = GuardianTracker(notify_after=3)
        self.assertEqual(t.not_found().action, "none")
        self.assertEqual(t.not_found().action, "none")
        self.assertEqual(t.not_found().action, "notify")
        self.assertEqual(t.not_found().action, "none")  # latched, no spam

    def test_recovery_resets_latch(self):
        t = GuardianTracker(notify_after=2)
        t.not_found()
        self.assertEqual(t.not_found().action, "notify")
        t.found("192.0.2.10", "192.0.2.10")  # recovered
        t.not_found()
        self.assertEqual(t.not_found().action, "notify")  # can notify again


if __name__ == "__main__":
    unittest.main()
