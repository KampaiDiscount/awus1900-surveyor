#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("awus_surveyor", ROOT / "awus_surveyor.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


SAMPLE = r"""BSS 00:11:22:33:44:55(on wlan0)
	last seen: 10 ms ago
	freq: 2412
	beacon interval: 100 TUs
	capability: ESS ShortSlotTime (0x0401)
	signal: -41.00 dBm
	SSID: Coffee Shop
	DS Parameter set: channel 1
	HT capabilities:
		Capabilities: 0x11ef
BSS 10:20:30:40:50:60(on wlan0)
	last seen: 20 ms ago
	freq: 2437
	beacon interval: 100 TUs
	capability: ESS Privacy ShortSlotTime (0x0411)
	signal: -52.50 dBm
	SSID: OfficeNet
	DS Parameter set: channel 6
	RSN:
		 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK
		 * Capabilities: 1-PTKSA-RC 1-GTKSA-RC MFP-capable (0x0080)
	WPS:
		 * Version: 1.0
		 * AP setup locked: 0x01
	BSS Load:
		 * station count: 14
		 * channel utilisation: 128/255
BSS aa:bb:cc:dd:ee:ff(on wlan0)
	last seen: 30 ms ago
	freq: 5180
	capability: ESS Privacy (0x0011)
	signal: -63.00 dBm
	SSID: CorpWiFi
	RSN:
		 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK SAE
		 * Capabilities: 16-PTKSA-RC 1-GTKSA-RC MFP-capable (0x008c)
	VHT capabilities:
	HE capabilities:
BSS de:ad:be:ef:00:01(on wlan0)
	last seen: 40 ms ago
	freq: 5200
	capability: ESS Privacy (0x0011)
	signal: -70.00 dBm
	SSID: Enterprise
	RSN:
		 * Version: 1
		 * Group cipher: GCMP-256
		 * Pairwise ciphers: GCMP-256
		 * Authentication suites: Suite B 192
		 * Capabilities: 16-PTKSA-RC 1-GTKSA-RC MFP-required MFP-capable (0x00cc)
BSS 02:00:00:00:00:01(on wlan0)
	last seen: 50 ms ago
	freq: 2462
	capability: ESS Privacy (0x0011)
	signal: -80.00 dBm
	SSID: 
BSS 02:00:00:00:00:02(on wlan0)
	last seen: 60 ms ago
	freq: 5240
	capability: ESS Privacy (0x0011)
	signal: -77.00 dBm
	SSID: SecureOpen
	RSN:
		 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: OWE
		 * Capabilities: 16-PTKSA-RC 1-GTKSA-RC MFP-required MFP-capable (0x00cc)
"""


class ParserTests(unittest.TestCase):
    def test_parse_multiple_security_modes(self):
        results = MODULE.parse_iw_scan(SAMPLE)
        self.assertEqual(len(results), 6)
        by_bssid = {item.bssid: item for item in results}

        self.assertEqual(by_bssid["00:11:22:33:44:55"].security, "Open")
        self.assertEqual(by_bssid["00:11:22:33:44:55"].channel, 1)
        self.assertEqual(by_bssid["00:11:22:33:44:55"].wifi_standard, "802.11n (Wi-Fi 4)")

        office = by_bssid["10:20:30:40:50:60"]
        self.assertEqual(office.security, "WPA2-Personal")
        self.assertEqual(office.pmf, "Capable")
        self.assertTrue(office.wps)
        self.assertTrue(office.wps_locked)
        self.assertEqual(office.station_count, 14)
        self.assertAlmostEqual(office.channel_utilization_pct, 50.2)

        transition = by_bssid["aa:bb:cc:dd:ee:ff"]
        self.assertEqual(transition.security, "WPA2/WPA3-Personal (Transition)")
        self.assertEqual(transition.band, "5 GHz")
        self.assertEqual(transition.channel, 36)
        self.assertEqual(transition.wifi_standard, "802.11ax (Wi-Fi 6/6E)")

        enterprise = by_bssid["de:ad:be:ef:00:01"]
        self.assertEqual(enterprise.security, "WPA3-Enterprise 192-bit")
        self.assertEqual(enterprise.pmf, "Required")

        hidden = by_bssid["02:00:00:00:00:01"]
        self.assertTrue(hidden.hidden)
        self.assertEqual(hidden.security, "WEP / Legacy Privacy")

        owe = by_bssid["02:00:00:00:00:02"]
        self.assertEqual(owe.security, "Enhanced Open (OWE)")

    def test_ssid_escape_decode(self):
        ssid, hidden = MODULE.decode_iw_ssid(r"Test\x20Network")
        self.assertEqual(ssid, "Test Network")
        self.assertFalse(hidden)
        ssid, hidden = MODULE.decode_iw_ssid(r"\x00\x00")
        self.assertEqual(ssid, "")
        self.assertTrue(hidden)

    def test_inventory_keeps_history(self):
        logger = MODULE.logging.getLogger("test")
        oui = MODULE.OUILookup.__new__(MODULE.OUILookup)
        oui.logger = logger
        oui.prefixes = {}
        oui.source = ""
        inventory = MODULE.Inventory(oui)
        first = MODULE.ScanResult(bssid="00:11:22:33:44:55", ssid="Old", hidden=False, frequency_mhz=2412, signal_dbm=-70).finalize()
        second = MODULE.ScanResult(bssid="00:11:22:33:44:55", ssid="New", hidden=False, frequency_mhz=5180, signal_dbm=-40).finalize()
        inventory.update(first, 1000.0)
        inventory.update(second, 1010.0)
        record = inventory.records[first.bssid]
        self.assertEqual(record.ssid, "New")
        self.assertEqual(record.ssid_history, ["Old", "New"])
        self.assertEqual(record.channel_history, ["2.4 GHz:1", "5 GHz:36"])
        self.assertEqual(record.signal_best_dbm, -40)
        self.assertEqual(record.signal_worst_dbm, -70)
        self.assertEqual(record.signal_avg_dbm, -55)
        payload = record.to_dict(1010.0)
        self.assertEqual(payload["signal_quality"], "Strong")
        self.assertEqual(payload["signal_spread_db"], 30)

    def test_signal_quality_bands(self):
        self.assertEqual(MODULE.signal_quality(-38), "Excellent")
        self.assertEqual(MODULE.signal_quality(-60), "Strong")
        self.assertEqual(MODULE.signal_quality(-63), "Good")
        self.assertEqual(MODULE.signal_quality(-72), "Fair")
        self.assertEqual(MODULE.signal_quality(-80), "Weak")
        self.assertEqual(MODULE.signal_quality(-90), "Very weak")
        self.assertEqual(MODULE.signal_quality(None), "Unknown")

    def test_output_writer(self):
        logger = MODULE.logging.getLogger("test-output")
        oui = MODULE.OUILookup.__new__(MODULE.OUILookup)
        oui.logger = logger
        oui.prefixes = {}
        oui.source = ""
        inventory = MODULE.Inventory(oui)
        result = MODULE.parse_iw_scan(SAMPLE)[0]
        inventory.update(result, 1000.0)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            writer = MODULE.OutputWriter(directory, logger)
            session = {
                "status": "running",
                "started_at": "test",
                "updated_at": "test",
                "interface": "wlan0",
                "driver": "rtw88_8814au",
                "output_directory": str(directory),
                "sweeps": 1,
                "scan_successes": 1,
                "scan_failures": 0,
            }
            writer.checkpoint(session, inventory)
            for name in ("wireless_zones.csv", "wireless_zones.json", "wireless_zones.html", "wireless_zones.md", "session.json"):
                path = directory / name
                self.assertTrue(path.exists())
                self.assertGreater(path.stat().st_size, 20)
            payload = __import__("json").loads((directory / "wireless_zones.json").read_text())
            self.assertEqual(payload["networks"][0]["signal_quality"], "Excellent")
            self.assertIn("RSSI avg dBm", (directory / "wireless_zones.html").read_text())


class OrchestrationTests(unittest.TestCase):
    def test_one_shot_main_generates_complete_session(self):
        from unittest import mock

        selected = MODULE.WirelessInterface(
            name="wlan0",
            phy="phy0",
            wiphy=0,
            interface_type="managed",
            mac="00:aa:bb:cc:dd:ee",
            driver="rtw88_8814au",
            usb_id="0bda:8813",
            usb_product="ALFA AWUS1900",
            is_up=False,
            nm_managed=True,
        )

        class FakeManager:
            def __init__(self, *_args, **_kwargs):
                self.interface = "wlan0"
                self.phy = "phy0"
                self.driver = "rtw88_8814au"
                self.usb_id = "0bda:8813"

            def prepare(self):
                return None

            def cleanup(self):
                return None

            def recover(self):
                return True

        class FakeLock:
            def __init__(self, _key):
                pass

            def acquire(self):
                return None

            def release(self):
                return None

        class FakeScanRunner:
            def __init__(self, *_args, **_kwargs):
                pass

            def scan(self, _frequencies):
                return SAMPLE

        channels = [
            MODULE.Channel(2412, 1, "2.4 GHz"),
            MODULE.Channel(2437, 6, "2.4 GHz"),
            MODULE.Channel(2462, 11, "2.4 GHz"),
            MODULE.Channel(5180, 36, "5 GHz"),
            MODULE.Channel(5200, 40, "5 GHz"),
            MODULE.Channel(5240, 48, "5 GHz"),
        ]

        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(MODULE, "require_commands", return_value=None), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0), \
             mock.patch.object(MODULE, "select_interface", return_value=selected), \
             mock.patch.object(MODULE, "InterfaceManager", FakeManager), \
             mock.patch.object(MODULE, "ProcessLock", FakeLock), \
             mock.patch.object(MODULE, "ScanRunner", FakeScanRunner), \
             mock.patch.object(MODULE, "discover_channels", return_value=channels), \
             mock.patch.object(MODULE, "get_regulatory_country", return_value="ZA"), \
             mock.patch.object(MODULE, "chown_output_to_invoking_user", return_value=None), \
             mock.patch.object(MODULE, "state_file_for", return_value=Path(temp) / "no-state.json"):
            code = MODULE.main([
                "--once",
                "--no-ui",
                "--country", "ZA",
                "--output-root", temp,
                "--session-name", "integration",
            ])
            self.assertEqual(code, 0)
            directory = Path(temp) / "integration"
            payload = __import__("json").loads((directory / "wireless_zones.json").read_text())
            self.assertEqual(payload["session"]["status"], "completed")
            self.assertEqual(payload["session"]["completion_reason"], "once")
            self.assertEqual(payload["summary"]["total"], 6)
            self.assertEqual(payload["summary"]["2.4_ghz"], 3)
            self.assertEqual(payload["summary"]["5_ghz"], 3)


if __name__ == "__main__":
    unittest.main()
