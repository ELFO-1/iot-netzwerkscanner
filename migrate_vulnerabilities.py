#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Einmal-Migration für vulnerability_details.

Normalisiert bestehende Schwachstellen-Einträge:
- zerlegt rohe nmap/vulners-Blobs in einzelne Funde,
- füllt die Spalten cve_id und severity (CVSS) anhand des Beschreibungstextes,
- entfernt Duplikate (pro Host/Port/CVE) und Rausch-Fragmente.

Vor der Migration wird automatisch ein Backup der Datenbank angelegt.
Neue Scans speichern bereits normalisiert (siehe Scanner._update_vulnerability_info),
dieses Skript ist nur für Altbestände nötig.

Aufruf:  python3 migrate_vulnerabilities.py [pfad/zur/iot_devices.db]
"""

import sys
import shutil
import sqlite3
from datetime import datetime

from modules.scanner_metasploit import normalize_findings


def migrate(db_path: str = "iot_devices.db") -> None:
    # 1) Backup anlegen (Endung .db -> via .gitignore ausgeschlossen)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = f"{db_path.rsplit('.', 1)[0]}.bak_{ts}.db"
    shutil.copy(db_path, backup)
    print(f"Backup angelegt: {backup}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute(
        "SELECT device_ip, port, description, cve_id, severity, discovered_date "
        "FROM vulnerability_details"
    )
    rows = c.fetchall()
    print(f"Zeilen vorher: {len(rows)}")

    new_rows = []
    seen = set()
    for r in rows:
        for cve_id, cvss, desc in normalize_findings(r["description"] or ""):
            cid = cve_id or r["cve_id"]
            sev = (str(cvss) if cvss is not None else None) or r["severity"]
            key = (r["device_ip"], str(r["port"]), cid or desc)
            if key in seen:
                continue
            seen.add(key)
            new_rows.append(
                (r["device_ip"], str(r["port"]), desc, cid, sev, r["discovered_date"])
            )

    c.execute("DELETE FROM vulnerability_details")
    c.executemany(
        "INSERT INTO vulnerability_details "
        "(device_ip, port, description, cve_id, severity, discovered_date) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        new_rows,
    )
    conn.commit()

    c.execute("SELECT COUNT(*) FROM vulnerability_details WHERE cve_id IS NOT NULL")
    with_cve = c.fetchone()[0]
    conn.close()

    print(f"Zeilen nachher: {len(new_rows)} (davon {with_cve} mit CVE-ID)")
    print("Migration abgeschlossen.")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "iot_devices.db"
    migrate(path)
