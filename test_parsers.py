#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit-Tests für die Parser-/Normalisierungslogik des IoT Netzwerkscanners.

Ausführen:
    python3 -m unittest test_parsers -v
    # oder einfach:
    python3 test_parsers.py
"""

import os
import logging
import tempfile
import unittest
import configparser

# Logging während der Tests stummschalten
logging.disable(logging.CRITICAL)

from modules.scanner_metasploit import normalize_findings
from modules.database import Database
from modules.analyzer import Analyzer


class TestNormalizeFindings(unittest.TestCase):
    """normalize_findings(): rohe Schwachstellentexte -> (cve_id, cvss, beschreibung)."""

    def test_cve_with_score(self):
        out = normalize_findings("CVE-2021-3618\t7.4\thttps://vulners.com/cve/CVE-2021-3618")
        self.assertEqual(len(out), 1)
        cve, cvss, desc = out[0]
        self.assertEqual(cve, "CVE-2021-3618")
        self.assertEqual(cvss, 7.4)
        self.assertIsInstance(cvss, float)
        self.assertIn("CVE-2021-3618", desc)

    def test_cve_without_score(self):
        out = normalize_findings("CVE-2007-6750")
        self.assertEqual(len(out), 1)
        cve, cvss, _ = out[0]
        self.assertEqual(cve, "CVE-2007-6750")
        self.assertIsNone(cvss)

    def test_multiple_cves_deduped(self):
        text = (
            "CVE-2023-38408\t9.8\tx\n"
            "CVE-2016-1908\t9.8\tx\n"
            "CVE-2023-38408\t9.8\tx"  # Duplikat
        )
        out = normalize_findings(text)
        cves = [c for c, _, _ in out]
        self.assertEqual(cves, ["CVE-2023-38408", "CVE-2016-1908"])

    def test_sweet32_weakness(self):
        out = normalize_findings("64-bit block cipher 3DES vulnerable to SWEET32 attack")
        self.assertEqual(len(out), 1)
        cve, cvss, desc = out[0]
        self.assertIsNone(cve)
        self.assertEqual(cvss, 5.9)
        self.assertIn("SWEET32", desc)

    def test_grade_f_weakness(self):
        out = normalize_findings("Schwache SSL/TLS-Cipher-Suiten (Gesamtbewertung: F)")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][1], 7.0)

    def test_sha1_weakness(self):
        out = normalize_findings("Unsicheres Zertifikat: SHA1-Signatur")
        self.assertTrue(any("SHA1" in d for _, _, d in out))

    def test_slowloris_weakness(self):
        out = normalize_findings("Slowloris DOS attack")
        self.assertTrue(any("Slowloris" in d for _, _, d in out))

    def test_weak_public_key(self):
        self.assertTrue(normalize_findings("Public Key bits: 1024"))
        # 2048 ist KEINE Schwäche -> nicht als Schwachstelle melden
        self.assertEqual(normalize_findings("Public Key bits: 2048"), [])

    def test_cve_and_weakness_together(self):
        text = "CVE-2016-2183\t7.5\tx\n64-bit block cipher 3DES vulnerable to SWEET32 attack"
        out = normalize_findings(text)
        cves = [c for c, _, _ in out]
        descs = [d for _, _, d in out]
        self.assertIn("CVE-2016-2183", cves)
        self.assertTrue(any("SWEET32" in d for d in descs))

    def test_noise_fragments_dropped(self):
        for noise in ("State: LIKELY VULNERABLE", "VULNERABLE:", "LIKELY VULNERABLE",
                      "|   some nmap continuation line"):
            self.assertEqual(normalize_findings(noise), [], f"sollte gefiltert werden: {noise!r}")

    def test_empty_input(self):
        self.assertEqual(normalize_findings(""), [])
        self.assertEqual(normalize_findings(None), [])

    def test_plain_text_kept(self):
        out = normalize_findings("Irgendeine andere Schwachstellenbeschreibung")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][0], None)
        self.assertIn("Irgendeine", out[0][2])

    def test_big_blob_explodes(self):
        # Simuliert eine große vulners-Liste mit vielen CVEs
        lines = [f"CVE-2020-{1000+i}\t{5.0+i*0.1:.1f}\tx" for i in range(20)]
        out = normalize_findings("\n".join(lines))
        self.assertEqual(len(out), 20)
        self.assertTrue(all(c is not None for c, _, _ in out))


class TestSeverityToRisk(unittest.TestCase):
    """Database._severity_to_risk(): Schweregrad -> Risikostufe."""

    def test_numeric_thresholds(self):
        cases = {
            9.8: "Critical", 9.0: "Critical",
            8.9: "High", 7.4: "High", 7.0: "High",
            6.9: "Medium", 5.0: "Medium", 4.0: "Medium",
            3.9: "Low", 0.1: "Low",
            0.0: "Info",
        }
        for value, expected in cases.items():
            self.assertEqual(Database._severity_to_risk(value), expected, f"bei {value}")
            # auch als String akzeptiert
            self.assertEqual(Database._severity_to_risk(str(value)), expected, f"bei '{value}'")

    def test_textual_levels(self):
        cases = {
            "critical": "Critical", "kritisch": "Critical",
            "high": "High", "hoch": "High",
            "medium": "Medium", "mittel": "Medium",
            "low": "Low", "niedrig": "Low",
            "info": "Info", "informational": "Info", "none": "Info",
        }
        for value, expected in cases.items():
            self.assertEqual(Database._severity_to_risk(value), expected, f"bei {value!r}")

    def test_unknown_and_empty(self):
        for value in (None, "", "  ", "voellig_unbekannt"):
            self.assertEqual(Database._severity_to_risk(value), "Info", f"bei {value!r}")


class TestParseServicePorts(unittest.TestCase):
    """Analyzer._parse_service_ports(): Dienstliste -> {Protokoll: Port}."""

    def setUp(self):
        self.analyzer = Analyzer("dummy.db")  # __init__ greift nicht auf die DB zu

    def test_basic_mapping(self):
        services = (
            "21/tcp: ftp (vsftpd 3.0.2)\n"
            "22/tcp: ssh (Dropbear sshd 2014.66)\n"
            "23/tcp: telnet\n"
            "80/tcp: http (TwistedWeb httpd 16.2.0)"
        )
        result = self.analyzer._parse_service_ports(services)
        self.assertEqual(result.get("ftp"), 21)
        self.assertEqual(result.get("ssh"), 22)
        self.assertEqual(result.get("telnet"), 23)
        self.assertEqual(result.get("http"), 80)

    def test_https_counts_as_http(self):
        result = self.analyzer._parse_service_ports("443/tcp: https")
        self.assertEqual(result.get("http"), 443)

    def test_first_port_wins(self):
        # Zwei http-Ports -> der erste gewinnt
        result = self.analyzer._parse_service_ports("80/tcp: http\n8080/tcp: http")
        self.assertEqual(result.get("http"), 80)

    def test_empty(self):
        self.assertEqual(self.analyzer._parse_service_ports(""), {})
        self.assertEqual(self.analyzer._parse_service_ports(None), {})


class TestLoadCredentialList(unittest.TestCase):
    """Analyzer._load_credential_list(): Einzelwert / Kommaliste / Datei."""

    def setUp(self):
        self.analyzer = Analyzer("dummy.db")

    def test_single_value(self):
        self.assertEqual(self.analyzer._load_credential_list("admin"), ["admin"])

    def test_comma_list(self):
        self.assertEqual(
            self.analyzer._load_credential_list("admin,root,user"),
            ["admin", "root", "user"],
        )

    def test_comma_list_trims_spaces(self):
        self.assertEqual(
            self.analyzer._load_credential_list("admin, root , user"),
            ["admin", "root", "user"],
        )

    def test_empty_and_none(self):
        self.assertEqual(self.analyzer._load_credential_list(""), [""])
        self.assertEqual(self.analyzer._load_credential_list(None), [""])

    def test_wordlist_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("admin\nroot\n\npassword123\n")
            path = f.name
        try:
            self.assertEqual(
                self.analyzer._load_credential_list(path),
                ["admin", "root", "password123"],
            )
        finally:
            os.unlink(path)


class TestGetDevicesInRange(unittest.TestCase):
    """Database.get_devices_in_range(): IP / CIDR / Kommaliste-Filter."""

    def setUp(self):
        # Temporäre DB anlegen und ein paar Geräte einfügen
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.db_path)  # Database soll die Struktur frisch erstellen

        cfg = configparser.ConfigParser()
        cfg.add_section("DATABASE")
        cfg.set("DATABASE", "db_name", self.db_path)
        self.db = Database(cfg)

        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            for ip in ("192.168.0.1", "192.168.0.20", "192.168.1.5", "10.0.0.7"):
                c.execute("INSERT INTO devices (ip) VALUES (?)", (ip,))
            conn.commit()

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def _ips(self, devices):
        return sorted(d["ip"] for d in devices)

    def test_single_ip(self):
        self.assertEqual(self._ips(self.db.get_devices_in_range("192.168.0.20")),
                         ["192.168.0.20"])

    def test_cidr_24(self):
        self.assertEqual(self._ips(self.db.get_devices_in_range("192.168.0.0/24")),
                         ["192.168.0.1", "192.168.0.20"])

    def test_comma_list(self):
        self.assertEqual(
            self._ips(self.db.get_devices_in_range("192.168.0.1, 10.0.0.7")),
            ["10.0.0.7", "192.168.0.1"],
        )

    def test_empty_returns_all(self):
        self.assertEqual(
            self._ips(self.db.get_devices_in_range("")),
            ["10.0.0.7", "192.168.0.1", "192.168.0.20", "192.168.1.5"],
        )

    def test_no_match(self):
        self.assertEqual(self.db.get_devices_in_range("172.16.0.0/16"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
