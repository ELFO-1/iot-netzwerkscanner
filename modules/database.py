#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database module for the IoT Netzwerkscanner
Handles all database operations and provides a clean interface
"""

import os
import re
import sqlite3
import logging
import json
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Union, Any, Tuple


class Database:
    """Database class for handling all database operations"""
    
    def __init__(self, config):
        """Initialize the database connection
        
        Args:
            config: Configuration object or dict with database settings
        """
        self.config = config
        
        # Get database name from config
        if hasattr(config, 'get'):
            # It's a Config object
            self.db_name = config.get('DATABASE', 'db_name', fallback='iot_devices.db')
        elif isinstance(config, dict) and 'DATABASE' in config and 'db_name' in config['DATABASE']:
            # It's a dict
            self.db_name = config['DATABASE']['db_name']
        else:
            # Default
            self.db_name = 'iot_devices.db'
            
        # Ensure the database exists and has the correct structure
        self._ensure_db_exists()
        
    def _ensure_db_exists(self) -> None:
        """Ensure the database exists and has the correct structure"""
        if not os.path.exists(self.db_name):
            self._create_database_structure()
        else:
            # Update the database structure if needed
            self._update_database_structure()
    
    def _create_database_structure(self) -> None:
        """Create the initial database structure"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                
                # Create devices table
                c.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    os TEXT,
                    open_ports TEXT,
                    services TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    metasploit_exploits TEXT
                )
                """)
                
                # Create scan_history table
                c.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TEXT,
                    scan_type TEXT,
                    network_range TEXT,
                    devices_found INTEGER,
                    duration REAL,
                    status TEXT,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    metasploit_exploits_found INTEGER DEFAULT 0,
                    results TEXT
                )
                """)
                
                # Create vulnerability_details table
                c.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_details (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_ip TEXT,
                    port TEXT,
                    description TEXT,
                    cve_id TEXT,
                    severity TEXT,
                    discovered_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_ip) REFERENCES devices (ip)
                )
                """)
                
                # Create settings table
                c.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """)
                
                conn.commit()
                logging.info("Database structure created successfully")
        except Exception as e:
            logging.error(f"Error creating database structure: {str(e)}")
            raise
    
    def _update_database_structure(self) -> None:
        """Update the database structure if needed"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                
                # Check if metasploit_exploits column exists in devices table
                c.execute("PRAGMA table_info(devices)")
                columns = [column[1] for column in c.fetchall()]
                
                if 'metasploit_exploits' not in columns:
                    c.execute("ALTER TABLE devices ADD COLUMN metasploit_exploits TEXT")
                
                conn.commit()
                logging.info("Database structure updated successfully")
        except Exception as e:
            logging.error(f"Error updating database structure: {str(e)}")
    
    def get_devices(self) -> pd.DataFrame:
        """Get all devices from the database"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                query = "SELECT * FROM devices"
                return pd.read_sql_query(query, conn)
        except Exception as e:
            logging.error(f"Error getting devices: {str(e)}")
            return pd.DataFrame()
    
    def get_scan_history(self, limit: int = 10) -> pd.DataFrame:
        """Get scan history from the database"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                query = """
                    SELECT scan_date, scan_type, network_range, devices_found, duration, status,
                           vulnerabilities_found, metasploit_exploits_found
                    FROM scan_history
                    ORDER BY scan_date DESC
                    LIMIT ?
                """
                return pd.read_sql_query(query, conn, params=(limit,))
        except Exception as e:
            logging.error(f"Error getting scan history: {str(e)}")
            return pd.DataFrame()
    
    def save_scan_result(self, scan_type: str, network_range: str, 
                         devices_found: int, duration: float, status: str = 'completed',
                         vulnerabilities_found: int = 0, metasploit_exploits_found: int = 0) -> None:
        """Save scan result to the database"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                
                c.execute("""
                    INSERT INTO scan_history (scan_date, scan_type, network_range, devices_found, duration, status, vulnerabilities_found, metasploit_exploits_found)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    scan_type,
                    network_range,
                    devices_found,
                    duration,
                    status,
                    vulnerabilities_found,
                    metasploit_exploits_found
                ))
                conn.commit()
        except Exception as e:
            logging.error(f"Error saving scan result: {str(e)}")
            raise
    
    def update_device_info(self, devices_df: pd.DataFrame) -> None:
        """Update or insert device information in the database"""
        if devices_df.empty:
            return
            
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                for _, device in devices_df.iterrows():
                    if 'ip' not in device or pd.isna(device['ip']):
                        continue
                        
                    # Check if device already exists
                    c.execute("SELECT * FROM devices WHERE ip=?", (device['ip'],))
                    existing_device = c.fetchone()
                    
                    if existing_device:
                        # Update existing device
                        self._update_existing_device(c, device, now)
                    else:
                        # Insert new device
                        self._insert_new_device(c, device, now)
                
                conn.commit()
        except Exception as e:
            logging.error(f"Error updating device information: {str(e)}")
            raise
    
    def _update_existing_device(self, cursor, device: pd.Series, timestamp: str) -> None:
        """Update an existing device in the database"""
        update_fields = []
        update_values = []
        
        for col in device.index:
            if col != 'ip' and not pd.isna(device[col]):
                update_fields.append(f"{col}=?")
                update_values.append(device[col])
        
        update_fields.append("last_seen=?")
        update_values.append(timestamp)
        
        if update_fields:
            update_sql = f"UPDATE devices SET {', '.join(update_fields)} WHERE ip=?"
            update_values.append(device['ip'])
            cursor.execute(update_sql, update_values)
    
    def _insert_new_device(self, cursor, device: pd.Series, timestamp: str) -> None:
        """Insert a new device into the database"""
        insert_cols = ['ip']
        insert_vals = [device['ip']]
        insert_placeholders = ['?']
        
        for col in device.index:
            if col != 'ip' and not pd.isna(device[col]):
                insert_cols.append(col)
                insert_vals.append(device[col])
                insert_placeholders.append('?')
        
        # Add timestamps
        insert_cols.extend(['first_seen', 'last_seen'])
        insert_vals.extend([timestamp, timestamp])
        insert_placeholders.extend(['?', '?'])
        
        insert_sql = f"INSERT INTO devices ({', '.join(insert_cols)}) VALUES ({', '.join(insert_placeholders)})"
        cursor.execute(insert_sql, insert_vals)
    
    def get_vulnerabilities(self, device_ip: str = None, port: str = None) -> pd.DataFrame:
        """Get vulnerabilities from the database"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                if device_ip:
                    query = "SELECT * FROM vulnerability_details WHERE device_ip = ?"
                    return pd.read_sql_query(query, conn, params=(device_ip,))
                else:
                    query = "SELECT * FROM vulnerability_details"
                    return pd.read_sql_query(query, conn)
        except Exception as e:
            logging.error(f"Error getting vulnerabilities: {str(e)}")
            return pd.DataFrame()
    
    def save_vulnerability(self, device_ip: str, port: str, description: str, 
                          cve_id: str = None, severity: str = "medium") -> None:
        """Save vulnerability details to the database
        
        Args:
            device_ip: IP address of the device
            port: Port number where vulnerability was found
            description: Description of the vulnerability
            cve_id: CVE ID if available
            severity: Severity level (low, medium, high, critical)
        """
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                
                c.execute("""
                    INSERT INTO vulnerability_details 
                    (device_ip, port, description, cve_id, severity, discovered_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    device_ip,
                    port,
                    description,
                    cve_id,
                    severity,
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
                conn.commit()
                logging.info(f"Vulnerability saved for device {device_ip} on port {port}")
        except Exception as e:
            logging.error(f"Error saving vulnerability: {str(e)}")
            raise
    
    # ------------------------------------------------------------------
    # Adapter-Methoden für den Exporter (modules/exporter.py)
    #
    # Der Exporter wurde ursprünglich für ein anderes Schema geschrieben
    # (numerische device_id, getrennte open_ports-/vulnerabilities-Tabellen).
    # Diese Methoden bilden das tatsächliche Schema (devices.ip als PK,
    # vulnerability_details, open_ports als TEXT-Spalte) auf das ab, was der
    # Exporter erwartet. Dadurch entfallen die "Using fallback"-Warnungen und
    # der Export (Menüpunkt 17) funktioniert.
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_to_risk(severity) -> str:
        """Wandelt einen DB-Severity-Wert in eine Risikostufe um."""
        if severity is None:
            return 'Info'
        s = str(severity).strip().lower()
        # Numerische CVSS-artige Werte
        try:
            val = float(s)
            if val >= 9.0:
                return 'Critical'
            if val >= 7.0:
                return 'High'
            if val >= 4.0:
                return 'Medium'
            if val > 0.0:
                return 'Low'
            return 'Info'
        except (ValueError, TypeError):
            pass
        # Textuelle Werte
        mapping = {
            'critical': 'Critical', 'kritisch': 'Critical',
            'high': 'High', 'hoch': 'High',
            'medium': 'Medium', 'mittel': 'Medium',
            'low': 'Low', 'niedrig': 'Low',
            'info': 'Info', 'informational': 'Info', 'none': 'Info',
        }
        return mapping.get(s, 'Info')

    def _row_to_device(self, row: dict) -> dict:
        """Ergänzt eine devices-Zeile um die vom Exporter erwarteten Schlüssel."""
        device = dict(row)
        # Der Exporter nutzt 'id' als Geräte-Schlüssel und gibt diesen an
        # get_vulnerabilities_by_device_id / get_open_ports_by_device_id weiter.
        # Diese sind über die IP verknüpft (vulnerability_details.device_ip,
        # devices.ip), daher MUSS 'id' hier die IP sein – nicht die numerische
        # Spalte 'id' der devices-Tabelle.
        device['id'] = device.get('ip')
        device['ip_address'] = device.get('ip')
        device['mac_address'] = device.get('mac')
        if not device.get('device_type'):
            device['device_type'] = 'Unknown'
        return device

    def get_all_devices(self) -> list:
        """Alle Geräte als Liste von Dictionaries (für den Exporter)."""
        try:
            with sqlite3.connect(self.db_name) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM devices")
                return [self._row_to_device(dict(r)) for r in c.fetchall()]
        except Exception as e:
            logging.error(f"Error getting all devices: {str(e)}")
            return []

    def get_device_by_id(self, device_id) -> Optional[dict]:
        """Ein einzelnes Gerät anhand der IP (= id) bzw. der numerischen id."""
        try:
            with sqlite3.connect(self.db_name) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute(
                    "SELECT * FROM devices WHERE ip = ? OR id = ?",
                    (str(device_id), device_id)
                )
                row = c.fetchone()
                return self._row_to_device(dict(row)) if row else None
        except Exception as e:
            logging.error(f"Error getting device by id {device_id}: {str(e)}")
            return None

    def get_vulnerabilities_by_device_id(self, device_id) -> list:
        """Schwachstellen eines Geräts als Liste von Dictionaries (für den Exporter)."""
        try:
            with sqlite3.connect(self.db_name) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute(
                    "SELECT * FROM vulnerability_details WHERE device_ip = ?",
                    (str(device_id),)
                )
                vulns = []
                for r in c.fetchall():
                    row = dict(r)
                    cve = row.get('cve_id')
                    description = row.get('description') or ''
                    severity = row.get('severity')

                    # Falls cve_id/severity leer sind, aus dem rohen Beschreibungs-
                    # Blob ableiten (das vulners-Skript legt die komplette CVE-Liste
                    # mit CVSS-Score dort ab).
                    if not cve:
                        m = re.search(r'(CVE-\d{4}-\d{4,7})', description)
                        if m:
                            cve = m.group(1)
                    if severity is None or str(severity).strip() == '':
                        scores = [float(x) for x in re.findall(r'\b(\d{1,2}\.\d)\b', description)]
                        if scores:
                            severity = max(scores)
                    exploit_available = '*EXPLOIT*' in description or bool(
                        re.search(r'\bVULNERABLE\b', description)
                    )

                    vulns.append({
                        'id': row.get('id'),
                        'device_id': row.get('device_ip'),
                        'name': cve or (description.strip().split('\n')[0][:80] if description else 'Schwachstelle'),
                        'cve_id': cve or '',
                        'description': description,
                        'risk_level': self._severity_to_risk(severity),
                        'severity': severity,
                        'port': row.get('port'),
                        'solution': '',
                        'exploit_available': exploit_available,
                        'discovered_date': row.get('discovered_date'),
                    })
                return vulns
        except Exception as e:
            logging.error(f"Error getting vulnerabilities for device {device_id}: {str(e)}")
            return []

    def get_open_ports_by_device_id(self, device_id) -> list:
        """Offene Ports eines Geräts als Liste von Dictionaries (für den Exporter).

        Die Ports werden aus der TEXT-Spalte ``open_ports`` (und falls vorhanden
        ``services``) der devices-Tabelle geparst. Unterstützt JSON-Listen sowie
        kommaseparierte Strings.
        """
        try:
            with sqlite3.connect(self.db_name) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute(
                    "SELECT open_ports, services FROM devices WHERE ip = ?",
                    (str(device_id),)
                )
                row = c.fetchone()
                if not row:
                    return []

                raw_ports = row['open_ports']
                raw_services = row['services'] if 'services' in row.keys() else None

                if not raw_ports:
                    return []

                # Services (optional) parsen für die Zuordnung Port -> Dienst
                services_map = {}
                if raw_services:
                    try:
                        svc = json.loads(raw_services)
                        if isinstance(svc, dict):
                            services_map = {str(k): v for k, v in svc.items()}
                    except (ValueError, TypeError):
                        pass

                # Ports parsen: zuerst JSON, sonst kommasepariert
                ports = []
                parsed = None
                try:
                    parsed = json.loads(raw_ports)
                except (ValueError, TypeError):
                    parsed = None

                if isinstance(parsed, list):
                    iterable = parsed
                elif isinstance(parsed, dict):
                    iterable = list(parsed.keys())
                else:
                    iterable = [p.strip() for p in str(raw_ports).split(',') if p.strip()]

                for item in iterable:
                    if isinstance(item, dict):
                        port_number = item.get('port') or item.get('port_number') or ''
                        entry = dict(item)
                        entry.setdefault('port_number', port_number)
                    else:
                        port_number = str(item).strip()
                        entry = {'port_number': port_number}
                    pn = str(entry.get('port_number', ''))
                    if pn in services_map and 'service' not in entry:
                        entry['service'] = services_map[pn]
                    ports.append(entry)
                return ports
        except Exception as e:
            logging.error(f"Error getting open ports for device {device_id}: {str(e)}")
            return []

    def get_last_scan(self) -> Optional[dict]:
        """Gibt den neuesten Eintrag aus scan_history zurück (oder None)."""
        try:
            with sqlite3.connect(self.db_name) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute(
                    "SELECT * FROM scan_history "
                    "ORDER BY datetime(scan_date) DESC, id DESC LIMIT 1"
                )
                row = c.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logging.error(f"Error getting last scan: {str(e)}")
            return None

    def get_devices_in_range(self, network_range) -> list:
        """Liefert die Geräte, deren IP im angegebenen Bereich liegt.

        Unterstützt einzelne IPs, CIDR-Notation (z. B. 192.168.0.0/24) und
        kommaseparierte Listen. Fällt im Zweifel auf alle Geräte zurück.
        """
        import ipaddress
        devices = self.get_all_devices()
        nr = (network_range or '').strip()
        if not nr:
            return devices

        # Kommaseparierte Liste einzelner Ziele
        targets = [t.strip() for t in re.split(r'[,\s]+', nr) if t.strip()]
        if len(targets) > 1:
            return [d for d in devices if d.get('ip') in targets]

        # Einzelnes Ziel: als (CIDR-)Netz interpretieren (eine IP wird zu /32)
        try:
            net = ipaddress.ip_network(nr, strict=False)
            out = []
            for d in devices:
                try:
                    if ipaddress.ip_address(d.get('ip')) in net:
                        out.append(d)
                except (ValueError, TypeError):
                    continue
            return out
        except ValueError:
            # Kein gültiges Netz/keine IP -> exakter String-Vergleich
            return [d for d in devices if d.get('ip') == nr]

    def get_devices_for_last_scan(self) -> list:
        """Geräte, die zum zuletzt durchgeführten Scan gehören."""
        scan = self.get_last_scan()
        if not scan:
            return []
        return self.get_devices_in_range(scan.get('network_range'))

    def cleanup(self) -> None:
        """Clean up the database and perform maintenance"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                
                # Optimize the database
                c.execute("VACUUM")
                
                # Update statistics
                c.execute("ANALYZE")
            
            logging.info("Database cleanup completed")
        except Exception as e:
            logging.error(f"Error during database cleanup: {str(e)}")
            raise