#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IoT Netzwerkscanner v4.0
Ein umfassendes Tool zur Identifikation und Analyse von Schwachstellen in Netzwerken
Special mit sortierter Anzeige von Sicherheitslücken und Metasploit-Integration
Author: ELFO
Version: 4.0
"""

import os
import sys
import time
import logging
import argparse
import sqlite3
import re
import subprocess
import uuid
import tempfile
import json
from typing import Dict, List, Optional, Union, Any, Tuple
from datetime import datetime
import configparser
from modules.database import Database
import pandas as pd

# Import exporter after database to avoid circular imports
try:
    from exporter import Exporter
except ImportError:
    # If exporter is in modules directory
    try:
        from modules.exporter import Exporter
    except ImportError:
        print("Warning: Exporter module not found. Export functionality will be limited.")

# Importiere Module
try:
    from modules.utils import Color, BANNER_TEXT, clear, create_database_structure, decode_unicode_escape
    from modules.scanner_metasploit import Scanner
    from modules.config import Config
    from modules.metasploit_integration import MetasploitIntegration
    from modules.nmap_special_scans import NmapSpecialScans
    from modules.analyzer import Analyzer
except ImportError as e:
    print(f"Fehler beim Importieren der Module: {e}")
    print("Bitte stellen Sie sicher, dass alle erforderlichen Module installiert sind.")
    sys.exit(1)


class ProgressBar:
    """Fortschrittsanzeige-Klasse für langwierige Operationen"""
    
    def __init__(self, total: int = 100, prefix: str = 'Fortschritt:', suffix: str = 'Abgeschlossen', 
                 decimals: int = 1, length: int = 50, fill: str = '█', print_end: str = "\r"):
        """
        Initialisiert eine Fortschrittsanzeige
        
        Args:
            total: Gesamtanzahl der Schritte
            prefix: Präfix-String
            suffix: Suffix-String
            decimals: Anzahl der Dezimalstellen für den Prozentsatz
            length: Länge der Fortschrittsanzeige in Zeichen
            fill: Füllzeichen für die Fortschrittsanzeige
            print_end: Zeichen am Ende der Ausgabe
        """
        self.total = max(1, total)  # Verhindere Division durch Null
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.print_end = print_end
        self.iteration = 0
        self.start_time = time.time()
        self._last_update_time = 0
        self._update_interval = 0.1  # Aktualisiere höchstens alle 100ms
        self._print_progress()
    
    def update(self, iteration: Optional[int] = None) -> None:
        """
        Aktualisiert die Fortschrittsanzeige
        
        Args:
            iteration: Aktueller Schritt (wenn None, wird der interne Zähler inkrementiert)
        """
        current_time = time.time()
        
        # Aktualisiere nur, wenn genug Zeit vergangen ist (verhindert zu häufige Aktualisierungen)
        if current_time - self._last_update_time < self._update_interval and iteration != self.total:
            if iteration is not None:
                self.iteration = iteration
            else:
                self.iteration += 1
            return
            
        self._last_update_time = current_time
        
        if iteration is not None:
            self.iteration = iteration
        else:
            self.iteration += 1
        
        self._print_progress()
    
    def finish(self) -> None:
        """Schließt die Fortschrittsanzeige ab und zeigt die Gesamtzeit an"""
        self.update(self.total)
        elapsed_time = time.time() - self.start_time
        print(f"\n{self.prefix} Abgeschlossen in {elapsed_time:.2f} Sekunden.")
    
    def _print_progress(self) -> None:
        """Gibt die Fortschrittsanzeige aus"""
        percent = ("{0:." + str(self.decimals) + "f}").format(100 * (self.iteration / float(self.total)))
        filled_length = int(self.length * self.iteration // self.total)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        
        elapsed_time = time.time() - self.start_time
        # Verhindere Division durch Null
        if self.iteration > 0:
            eta = (elapsed_time / self.iteration) * (self.total - self.iteration)
        else:
            eta = 0
            
        print(f'\r{self.prefix} |{bar}| {percent}% {self.suffix} (ETA: {eta:.1f}s)', end=self.print_end)
        
        # Leere den Ausgabepuffer, um die Anzeige sofort zu aktualisieren
        sys.stdout.flush()
        
        if self.iteration >= self.total:
            print()


class DatabaseManager:
    """Klasse zur Verwaltung der Datenbankoperationen"""
    
    def __init__(self, db_name: str):
        self.db_name = db_name
        self._ensure_db_exists()
    
    def _ensure_db_exists(self) -> None:
        """Stellt sicher, dass die Datenbank existiert und die richtige Struktur hat"""
        if not os.path.exists(self.db_name):
            create_database_structure(self.db_name)
        
        # Aktualisiere die Datenbankstruktur in jedem Fall
        self._update_database_structure()
    
    def _update_database_structure(self) -> None:
        """Aktualisiert die Datenbankstruktur, falls nötig"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                
                # Erstelle die scan_history Tabelle
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
                
                # Erstelle die vulnerability_details Tabelle
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
                
                # Erstelle die settings Tabelle
                c.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """)
                
                # Erstelle die devices Tabelle
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
                
                # Prüfe, ob alle benötigten Spalten in der devices Tabelle existieren
                c.execute("PRAGMA table_info(devices)")
                columns = [column[1] for column in c.fetchall()]

                # Spalten, die von Scanner/Analyzer beschrieben werden, aber im
                # minimalen Schema fehlen könnten – defensiv nachrüsten
                for missing_col in ('metasploit_exploits', 'vulnerabilities',
                                    'device_type', 'raw_vulnerabilities', 'notes'):
                    if missing_col not in columns:
                        c.execute(f"ALTER TABLE devices ADD COLUMN {missing_col} TEXT")

                conn.commit()
                logging.info("Datenbankstruktur erfolgreich aktualisiert")
        except Exception as e:
            logging.error(f"Fehler beim Aktualisieren der Datenbankstruktur: {str(e)}")
    
    def cleanup(self) -> None:
        """Bereinigt die Datenbank und führt Wartungsarbeiten durch"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                
                # Optimiere die Datenbank
                c.execute("VACUUM")
                
                # Aktualisiere Statistiken
                c.execute("ANALYZE")
            
            logging.info("Datenbank-Cleanup durchgeführt")
        except Exception as e:
            logging.error(f"Fehler beim Datenbank-Cleanup: {str(e)}")
            raise
    
    def get_scan_history(self, limit: int = 10) -> pd.DataFrame:
        """Holt die Scan-Historie aus der Datenbank"""
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
            logging.error(f"Fehler beim Laden der Scan-Historie: {str(e)}")
            return pd.DataFrame()
    
    def save_scan_result(self, scan_type: str, network_range: str, 
                         devices_found: int, duration: float, status: str = 'completed',
                         vulnerabilities_found: int = 0, metasploit_exploits_found: int = 0) -> None:
        """Speichert ein Scan-Ergebnis in der Datenbank"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                
                # Überprüfe, ob die Tabelle existiert
                c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
                if not c.fetchone():
                    logging.warning("Tabelle scan_history existiert nicht, wird erstellt")
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
                    conn.commit()
                
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
            logging.error(f"Fehler beim Speichern des Scan-Ergebnisses: {str(e)}")
            # Versuche, die Datenbankstruktur zu aktualisieren und erneut zu speichern
            try:
                self._update_database_structure()
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
                    logging.info("Scan-Ergebnis nach Datenbankaktualisierung erfolgreich gespeichert")
            except Exception as e2:
                logging.error(f"Fehler beim erneuten Speichern des Scan-Ergebnisses: {str(e2)}")
                raise
    
    def update_device_info(self, devices_df: pd.DataFrame) -> None:
        """Aktualisiert oder fügt Geräteinformationen in die Datenbank ein"""
        if devices_df.empty:
            return
            
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                for _, device in devices_df.iterrows():
                    if 'ip' not in device or pd.isna(device['ip']):
                        continue
                        
                    # Prüfe, ob das Gerät bereits existiert
                    c.execute("SELECT * FROM devices WHERE ip=?", (device['ip'],))
                    existing_device = c.fetchone()
                    
                    if existing_device:
                        # Aktualisiere vorhandenes Gerät
                        self._update_existing_device(c, device, now)
                    else:
                        # Füge neues Gerät hinzu
                        self._insert_new_device(c, device, now)
                
                conn.commit()
        except Exception as e:
            logging.error(f"Fehler beim Aktualisieren der Geräteinformationen: {str(e)}")
            raise
    
    def _update_existing_device(self, cursor, device: pd.Series, timestamp: str) -> None:
        """Aktualisiert ein vorhandenes Gerät in der Datenbank"""
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
        """Fügt ein neues Gerät in die Datenbank ein"""
        insert_cols = ['ip']
        insert_vals = [device['ip']]
        insert_placeholders = ['?']
        
        for col in device.index:
            if col != 'ip' and not pd.isna(device[col]):
                insert_cols.append(col)
                insert_vals.append(device[col])
                insert_placeholders.append('?')
        
        # Füge Zeitstempel hinzu
        insert_cols.extend(['first_seen', 'last_seen'])
        insert_vals.extend([timestamp, timestamp])
        insert_placeholders.extend(['?', '?'])
        
        insert_sql = f"INSERT INTO devices ({', '.join(insert_cols)}) VALUES ({', '.join(insert_placeholders)})"
        cursor.execute(insert_sql, insert_vals)


class IOTScanner:
    """Hauptklasse für den Pentesting-Netzwerkscanner"""
    
    def __init__(self):
        # Initialisiere Logging
        self._setup_logging()
        
        # Initialisiere Konfiguration
        self.config = Config()
        
        # Setze Grundeinstellungen
        self.db_name = self.config.get('DATABASE', 'db_name', fallback='iot_devices.db')
        self.default_network = self.config.get('SCAN', 'default_network', fallback='192.168.0.0/24')
        self.export_dir = self.config.get('EXPORT', 'export_path', fallback='exports')
        self.mac_api_key = self.config.get('API', 'mac_api_key', fallback='')
        self.metasploit_path = self.config.get('METASPLOIT', 'path', fallback='/opt/metasploit/')
        
        # Initialisiere Scan-Profile
        self.scan_profiles = self.config.scan_profiles
        
        # Initialisiere Datenbankmanager und stelle sicher, dass die Struktur korrekt ist
        self.db_manager = DatabaseManager(self.db_name)
        self.db_manager._update_database_structure()  # Explizit die Datenbankstruktur aktualisieren
        
        # Initialisiere Module
        self.scanner = Scanner(self.db_name, self.default_network)
        # Create a Database instance for the exporter
        db_instance = Database(self.config)
        try:
            # First try to import from modules
            from modules.exporter import Exporter
            self.exporter = Exporter(db_instance, self.config)
            logging.info("Using Exporter from modules directory")
        except Exception as e:
            logging.error(f"Error initializing Exporter from modules: {e}")
            try:
                # Then try to import from root
                from exporter import Exporter as RootExporter
                self.exporter = RootExporter(db_instance, self.config)
                logging.info("Using Exporter from root directory")
            except Exception as e2:
                logging.error(f"Error initializing Exporter from root: {e2}")
                # Create a minimal exporter as fallback
                class MinimalExporter:
                    def __init__(self, db, config):
                        self.db = db
                        self.config = config
                        self.logger = logging.getLogger('minimal_exporter')
                    
                    def export_results(self, export_format='csv'):
                        logging.warning("Using minimal exporter with limited functionality")
                        return False
                
                self.exporter = MinimalExporter(db_instance, self.config)
                logging.warning("Using minimal fallback exporter with limited functionality")
        self.analyzer = Analyzer(self.db_name)
        
        # Initialisiere Metasploit-Integration mit dem konfigurierten Pfad
        self.metasploit = MetasploitIntegration(self.metasploit_path)
        
        # Initialisiere spezielle Nmap-Scans mit der konfigurierten Datenbank
        self.nmap_special = NmapSpecialScans(self.db_name)
        
        # Initialisiere Status-Variablen
        self.scanning = False
        self.current_network = None
        self._banner_shown = False

        # Sichere die ursprünglichen Terminal-Einstellungen, um sie nach
        # Subprozessen (z.B. msfconsole), die das TTY verändern, wiederherzustellen
        self._term_attrs = None
        if os.name == 'posix':
            try:
                import termios
                self._term_attrs = termios.tcgetattr(sys.stdin.fileno())
            except Exception:
                self._term_attrs = None
    
    def _setup_logging(self) -> None:
        """Konfiguriert das Logging-System"""
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        log_file = os.path.join(log_dir, f'iot_scanner_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(logging.WARNING)  # Only warnings+ to console to reduce noise

        root_logger.addHandler(file_handler)
        root_logger.addHandler(stream_handler)
        root_logger.setLevel(logging.INFO)

        logging.info("IoT Netzwerkscanner gestartet")
    
    def _safe_json_parse(self, json_str: str) -> Dict[str, Any]:
        """Parst einen JSON-String sicher und gibt ein leeres Dict zurück, wenn ein Fehler auftritt"""
        try:
            # Entferne mögliche BOM-Marker oder andere ungültige Zeichen am Anfang
            if json_str.startswith('\ufeff'):
                json_str = json_str[1:]
                
            # Entferne mögliche Whitespaces am Anfang und Ende
            json_str = json_str.strip()
            
            # Wenn der String leer ist, gib ein leeres Dict zurück
            if not json_str:
                return {}
            
            # Versuche, den String als JSON zu parsen
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as je:
                # Wenn es ein JSON-Parsing-Fehler ist, versuche zu reparieren
                logging.warning(f"JSON-Parsing-Fehler: {str(je)}. Versuche zu reparieren...")
                
                # Entferne mögliche ungültige Zeichen
                cleaned_str = re.sub(r'[^\x20-\x7E]', '', json_str)
                
                # Wenn es wie ein JSON-Array aussieht, aber Probleme hat
                if cleaned_str.startswith('[') and cleaned_str.endswith(']'):
                    # Versuche, es als Liste von Strings zu behandeln
                    try:
                        items = [item.strip() for item in cleaned_str[1:-1].split(',')]
                        return {"items": items}
                    except Exception:
                        pass
                
                # Wenn es wie ein JSON-Objekt aussieht, aber Probleme hat
                if cleaned_str.startswith('{') and cleaned_str.endswith('}'):
                    # Versuche, es als einfaches Key-Value-Paar zu behandeln
                    try:
                        pairs = [pair.strip() for pair in cleaned_str[1:-1].split(',')]
                        result = {}
                        for pair in pairs:
                            if ':' in pair:
                                key, value = pair.split(':', 1)
                                key = key.strip().strip('"\'')
                                value = value.strip().strip('"\'')
                                result[key] = value
                        return result
                    except Exception:
                        pass
                
                # Wenn alle Reparaturversuche fehlschlagen, gib ein Dict mit dem Originalstring zurück
                return {"raw_data": json_str}
                
        except Exception as e:
            logging.error(f"Fehler beim Parsen von JSON: {str(e)}. String: {json_str[:100]}...")
            return {}
    
    # Hilfsfunktion zum Dekodieren von Strings in der Benutzeroberfläche
    def _d(self, text: str) -> str:
        """Dekodiert Unicode-Escape-Sequenzen für die Benutzeroberfläche"""
        return decode_unicode_escape(text)
    
    def _check_metasploit_installation(self) -> bool:
        """Überprüft, ob Metasploit installiert ist und setzt den Pfad"""
        try:
            # Prüfe den konfigurierten Pfad
            if os.path.exists(self.metasploit_path):
                logging.info(f"Metasploit gefunden unter: {self.metasploit_path}")
                return True
                
            # Prüfe, ob msfconsole im PATH ist
            result = subprocess.run(['which', 'msfconsole'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if result.returncode == 0:
                self.metasploit_path = os.path.dirname(result.stdout.decode('utf-8').strip())
                logging.info(f"Metasploit gefunden im PATH: {self.metasploit_path}")
                return True
                
            # Prüfe alternative Pfade
            common_paths = [
                '/usr/bin/msfconsole',
                '/usr/share/metasploit-framework/msfconsole',
                '/opt/metasploit-framework/bin/msfconsole',
                '/opt/metasploit/msfconsole'
            ]

            for path in common_paths:
                if os.path.exists(path):
                    self.metasploit_path = os.path.dirname(path)
                    logging.info(f"Metasploit gefunden unter: {self.metasploit_path}")
                    return True

            logging.warning("Metasploit ist nicht installiert oder nicht im PATH")
            print(f"{Color.YELLOW}HINWEIS: Metasploit ist nicht installiert oder nicht im PATH.{Color.RESET}")
            print(f"{Color.YELLOW}Einige erweiterte Funktionen zur Schwachstellenanalyse sind nicht verfügbar.{Color.RESET}")
            return False
        except Exception as e:
            logging.error(f"Fehler bei der Überprüfung der Metasploit-Installation: {str(e)}")
            return False
    
    def run_metasploit_command(self, command: str) -> Dict[str, Any]:
        """Führt einen Metasploit-Befehl aus und gibt das Ergebnis zurück"""
        temp_file_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.rc', delete=False) as temp_file:
                temp_file.write(command + "\n")
                temp_file.write("exit\n")
                temp_file_path = temp_file.name

            msfconsole_path = os.path.join(self.metasploit_path, 'msfconsole')
            if not os.path.exists(msfconsole_path):
                msfconsole_path = 'msfconsole'

            result = subprocess.run(
                [msfconsole_path, '-q', '-r', temp_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
            }
        except Exception as e:
            logging.error(f"Fehler bei der Ausführung des Metasploit-Befehls: {str(e)}")
            return {
                "success": False,
                "output": "",
                "error": str(e),
            }
        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    def search_metasploit_exploits(self, search_term: str) -> Dict[str, Any]:
        """Sucht nach Exploits in Metasploit"""
        command = f"search {search_term}"
        return self.run_metasploit_command(command)
    
    def cleanup_database(self) -> None:
        """Bereinigt die Datenbank und führt Wartungsarbeiten durch"""
        try:
            # Stelle sicher, dass die Datenbankstruktur korrekt ist
            self.db_manager._update_database_structure()
            self.db_manager.cleanup()
            logging.info("Datenbank-Cleanup erfolgreich durchgeführt")
        except Exception as e:
            print(f"{Color.RED}Fehler beim Datenbank-Cleanup: {str(e)}{Color.RESET}")
    
    def scan_network(self, network_range: Optional[str] = None) -> Optional[pd.DataFrame]:
        """Führt einen Netzwerk-Discovery-Scan durch"""
        try:
            start_time = time.time()
            result = self.scanner.scan_network(network_range)
            duration = time.time() - start_time
            
            if result is not None:
                # Speichere Scan-Ergebnis in der Datenbank
                self.db_manager.save_scan_result(
                    scan_type="Netzwerk-Discovery",
                    network_range=network_range or self.default_network,
                    devices_found=len(result),
                    duration=duration
                )
                
                # Aktualisiere Geräteinformationen
                self.db_manager.update_device_info(result)
            
            return result
        except Exception as e:
            logging.error(f"Fehler beim Netzwerk-Scan: {str(e)}")
            print(f"{Color.RED}Fehler beim Scan: {str(e)}{Color.RESET}")
            return None
    
    def identify_devices(self, devices_df: pd.DataFrame) -> Optional[pd.DataFrame]:
        """Führt eine detaillierte Geräteidentifikation durch"""
        try:
            start_time = time.time()
            result = self.scanner.identify_devices(devices_df)
            duration = time.time() - start_time
            
            if result is not None:
                # Speichere Scan-Ergebnis in der Datenbank
                self.db_manager.save_scan_result(
                    scan_type="Geräteidentifikation",
                    network_range="",  # Kein spezifischer Netzwerkbereich
                    devices_found=len(result),
                    duration=duration
                )
                
                # Aktualisiere Geräteinformationen
                self.db_manager.update_device_info(result)
            
            return result
        except Exception as e:
            logging.error(f"Fehler bei der Geräteidentifikation: {str(e)}")
            print(f"{Color.RED}Fehler bei der Identifikation: {str(e)}{Color.RESET}")
            return None
    
    def scan_vulnerabilities(self, network_range: Optional[str] = None) -> Optional[pd.DataFrame]:
        """Führt eine Schwachstellenanalyse durch"""
        try:
            start_time = time.time()
            # Übergebe die Konfiguration an die Scanner-Klasse
            result = self.scanner.scan_vulnerabilities(network_range, self.config)
            duration = time.time() - start_time
            
            if result is not None:
                # Speichere Scan-Ergebnis in der Datenbank
                try:
                    self.db_manager.save_scan_result(
                        scan_type="Schwachstellenanalyse",
                        network_range=network_range or self.default_network,
                        devices_found=len(result),
                        duration=duration,
                        vulnerabilities_found=result.get('vulnerabilities_count', 0) if isinstance(result, dict) else 0
                    )
                except Exception as db_error:
                    logging.error(f"Fehler beim Speichern der Schwachstellenanalyse: {str(db_error)}")
            
            return result
        except Exception as e:
            logging.error(f"Fehler bei der Schwachstellenanalyse: {str(e)}")
            print(f"{Color.RED}Fehler bei der Analyse: {str(e)}{Color.RESET}")
            return None
    
    def export_results(self) -> bool:
        """Exportiert die Scan-Ergebnisse"""
        try:
            export_format = self.config.get('EXPORT', 'default_format', fallback='all')
            return self.exporter.export_results(export_format)
        except Exception as e:
            logging.error(f"Fehler beim Exportieren der Ergebnisse: {str(e)}")
            print(f"{Color.RED}Fehler beim Export: {str(e)}{Color.RESET}")
            return False

    def export_last_scan(self) -> bool:
        """Exportiert nur die Ergebnisse des zuletzt durchgeführten Scans"""
        try:
            export_format = self.config.get('EXPORT', 'default_format', fallback='all')
            if hasattr(self.exporter, 'export_last_scan'):
                return self.exporter.export_last_scan(export_format)
            print(f"{Color.YELLOW}Der aktive Exporter unterstützt diese Funktion nicht.{Color.RESET}")
            return False
        except Exception as e:
            logging.error(f"Fehler beim Exportieren des letzten Scans: {str(e)}")
            print(f"{Color.RED}Fehler beim Export: {str(e)}{Color.RESET}")
            return False
    
    def check_ssl_configuration(self, ip: str, port: int = 443) -> Dict[str, Any]:
        """Überprüft die SSL/TLS-Konfiguration eines Geräts"""
        try:
            return self.analyzer.check_ssl_configuration(ip, port)
        except Exception as e:
            logging.error(f"Fehler bei der SSL-Konfigurationsprüfung: {str(e)}")
            print(f"{Color.RED}Fehler bei der SSL-Prüfung: {str(e)}{Color.RESET}")
            return {"error": str(e)}
    
    def check_default_credentials(self, ip: str, device_type: Optional[str] = None) -> Dict[str, Any]:
        """Überprüft, ob ein Gerät Standardanmeldedaten verwendet"""
        try:
            return self.analyzer.check_default_credentials(ip, device_type)
        except Exception as e:
            logging.error(f"Fehler bei der Prüfung auf Standardanmeldedaten: {str(e)}")
            print(f"{Color.RED}Fehler bei der Anmeldedatenprüfung: {str(e)}{Color.RESET}")
            return {"error": str(e)}
    
    def test_port_knocking(self, ip: str, ports: List[int]) -> Dict[str, Any]:
        """Führt einen Port-Knocking-Test durch"""
        try:
            return self.analyzer.test_port_knocking(ip, ports)
        except Exception as e:
            logging.error(f"Fehler beim Port-Knocking-Test: {str(e)}")
            print(f"{Color.RED}Fehler beim Port-Knocking: {str(e)}{Color.RESET}")
            return {"error": str(e)}
    
    def brute_force(self, ip: str, service: str, username: str, password: str,
                    port: Optional[int] = None, workers: int = 8) -> Any:
        """Führt einen Brute-Force-Angriff gegen einen Dienst durch"""
        try:
            return self.analyzer.brute_force(ip, service, username, password,
                                             port=port, workers=workers)
        except Exception as e:
            logging.error(f"Fehler beim Brute-Force-Angriff: {str(e)}")
            print(f"{Color.RED}Fehler beim Brute-Force: {str(e)}{Color.RESET}")
            return None

    def classify_device(self, device_info: Dict[str, Any]) -> str:
        """Klassifiziert ein Gerät basierend auf seinen Eigenschaften"""
        try:
            return self.analyzer.classify_device(device_info)
        except Exception as e:
            logging.error(f"Fehler bei der Geräteklassifikation: {str(e)}")
            print(f"{Color.RED}Fehler bei der Klassifikation: {str(e)}{Color.RESET}")
            return "Unbekannt"
    
    def create_behavior_profile(self, ip: str, days: int = 7) -> Optional[Dict[str, Any]]:
        """Erstellt ein Verhaltensprofil für ein Gerät"""
        try:
            return self.analyzer.create_behavior_profile(ip, days)
        except Exception as e:
            logging.error(f"Fehler bei der Erstellung des Verhaltensprofils: {str(e)}")
            print(f"{Color.RED}Fehler beim Verhaltensprofil: {str(e)}{Color.RESET}")
            return None
    
    def show_scan_history(self) -> None:
        """Zeigt die Scan-Historie an"""
        try:
            history_df = self.db_manager.get_scan_history(limit=10)
            
            if history_df.empty:
                print(f"\n{Color.YELLOW}Keine Scan-Historie verfügbar.{Color.RESET}")
                return
            
            print(f"\n{Color.GREEN}Letzte 10 Scans:{Color.RESET}")
            print("\n" + "=" * 80)
            
            # Formatierte Tabellenausgabe
            headers = [
                f"{Color.YELLOW}{'Datum':<20} | {'Scan-Typ':<15} | {'Netzwerkbereich':<15} | "
                f"{'Geräte':<6} | {'Dauer (s)':<8} | {'Schwachst.':<9} | {'Exploits':<8} | {'Status':<8}{Color.RESET}"
            ]
            print(headers[0])
            print("-" * 100)
            
            # Zeilen formatieren und ausgeben
            for _, row in history_df.iterrows():
                print(
                    f"{row['scan_date']:<20} | {row['scan_type']:<15} | {row['network_range']:<15} | "
                    f"{row['devices_found']:<6} | {row['duration']:<8.2f} | {row.get('vulnerabilities_found', 0):<9} | "
                    f"{row.get('metasploit_exploits_found', 0):<8} | {row['status']:<8}"
                )
                
            print("=" * 100)
        except Exception as e:
            logging.error(f"Fehler beim Anzeigen der Scan-Historie: {str(e)}")
            print(f"{Color.RED}Fehler beim Laden der Scan-Historie: {str(e)}{Color.RESET}")
    
    def show_device_overview(self) -> None:
        """Zeigt alle bekannten Geräte aus der Datenbank mit Schwachstellen-Anzahl an.

        Geräte, die innerhalb der letzten 7 Tage zum ersten Mal gesehen wurden,
        werden als NEU markiert – so fallen unbekannte Geräte im Netz sofort auf.
        """
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                # Einzigartige Schwachstellen zählen: dieselbe CVE auf mehreren
                # Ports (z.B. Samba auf 139 UND 445) ist EIN Fund, nicht mehrere.
                # COALESCE(cve_id, description) fasst CVE-lose Funde sinnvoll zusammen.
                c.execute("""
                    SELECT d.ip, d.hostname, d.vendor, d.device_type, d.open_ports,
                           d.first_seen, d.last_seen,
                           (SELECT COUNT(DISTINCT COALESCE(v.cve_id, v.description))
                            FROM vulnerability_details v
                            WHERE v.device_ip = d.ip) AS vuln_count
                    FROM devices d
                    ORDER BY d.last_seen DESC
                """)
                rows = c.fetchall()

            if not rows:
                print(f"\n{Color.YELLOW}Noch keine Geräte in der Datenbank. "
                      f"Führe zuerst einen Scan durch.{Color.RESET}")
                return

            now = datetime.now()
            new_count = 0
            total_vulns = 0

            print(f"\n{Color.GREEN}Bekannte Geräte: {len(rows)}{Color.RESET}\n")
            print(f"{Color.YELLOW}{'IP-Adresse':<16} {'Hostname':<22} {'Hersteller':<16} "
                  f"{'Typ':<18} {'Ports':>5} {'Vulns':>5}  {'Zuletzt gesehen':<19}{Color.RESET}")
            print("-" * 110)

            for ip, hostname, vendor, dev_type, open_ports, first_seen, last_seen, vuln_count in rows:
                ports_count = len([p for p in str(open_ports or '').replace(' ', '').split(',') if p])
                total_vulns += vuln_count or 0

                # NEU-Markierung: first_seen innerhalb der letzten 7 Tage
                is_new = False
                if first_seen:
                    try:
                        fs = datetime.strptime(str(first_seen)[:19], '%Y-%m-%d %H:%M:%S')
                        is_new = (now - fs).days < 7
                    except ValueError:
                        pass
                if is_new:
                    new_count += 1

                def _fmt(val, width):
                    s = str(val) if val else '-'
                    return s[:width - 1] + '…' if len(s) >= width else s

                vuln_color = Color.RED if (vuln_count or 0) > 0 else Color.GREEN
                line = (f"{_fmt(ip, 16):<16} {_fmt(hostname, 22):<22} {_fmt(vendor, 16):<16} "
                        f"{_fmt(dev_type, 18):<18} {ports_count:>5} "
                        f"{vuln_color}{vuln_count or 0:>5}{Color.RESET}  "
                        f"{_fmt(last_seen, 19):<19}")
                if is_new:
                    line += f" {Color.YELLOW}NEU{Color.RESET}"
                print(line)

            print("-" * 110)
            print(f"\nGesamt: {len(rows)} Geräte, {total_vulns} einzigartige Schwachstellen-Funde")
            print(f"{Color.BLUE}Hinweis: Vulns werden über den Versions-Banner (vulners) erkannt. "
                  f"Distros backporten\nFixes oft ohne Versionssprung – ein Teil der Funde sind "
                  f"daher Fehlalarme auf gepatchten Systemen.{Color.RESET}")
            if new_count:
                print(f"{Color.YELLOW}{new_count} Gerät(e) in den letzten 7 Tagen "
                      f"neu im Netzwerk aufgetaucht.{Color.RESET}")
        except Exception as e:
            logging.error(f"Fehler bei der Geräteübersicht: {str(e)}")
            print(f"{Color.RED}Fehler bei der Geräteübersicht: {str(e)}{Color.RESET}")

    def manage_scan_profiles(self) -> None:
        """Verwaltet die Scan-Profile"""
        try:
            self.config.manage_scan_profiles()
            # Aktualisiere die lokale Kopie der Profile
            self.scan_profiles = self.config.scan_profiles
            logging.info("Scan-Profile aktualisiert")
        except Exception as e:
            logging.error(f"Fehler bei der Verwaltung der Scan-Profile: {str(e)}")
            print(f"{Color.RED}Fehler bei den Scan-Profilen: {str(e)}{Color.RESET}")
    
    def show_settings(self) -> None:
        """Zeigt die Einstellungen an und ermöglicht Änderungen"""
        try:
            self.config.show_settings()
            # Aktualisiere lokale Einstellungen nach Änderungen
            self._update_settings_from_config()
            logging.info("Einstellungen aktualisiert")
        except Exception as e:
            logging.error(f"Fehler beim Anzeigen/Ändern der Einstellungen: {str(e)}")
            print(f"{Color.RED}Fehler bei den Einstellungen: {str(e)}{Color.RESET}")
        
    def _update_settings_from_config(self) -> None:
        """Aktualisiert die lokalen Einstellungen aus der Konfiguration"""
        self.db_name = self.config.get('DATABASE', 'db_name', fallback='iot_devices.db')
        self.default_network = self.config.get('SCAN', 'default_network', fallback='192.168.0.0/24')
        self.export_dir = self.config.get('EXPORT', 'export_path', fallback='exports')
        self.mac_api_key = self.config.get('API', 'mac_api_key', fallback='')
    
    def custom_scan(self) -> Optional[pd.DataFrame]:
        """Führt einen benutzerdefinierten Scan durch"""
        try:
            print(f"\n{Color.GREEN}=== Benutzerdefinierter Scan ==={Color.RESET}")
            
            # Zeige verfügbare Profile
            print(self._d(f"\n{Color.YELLOW}Verfügbare Scan-Profile:{Color.RESET}"))
            for key, profile in self.scan_profiles.items():
                print(f"  {key}: {profile['description']}")
            
            # Benutzer wählt ein Profil
            profile_name = input(self._d(f"\n{Color.YELLOW}Wähle ein Profil (oder 'neu' für eigene Argumente): {Color.RESET}"))
            
            if profile_name.lower() == 'neu':
                # Benutzerdefinierte Argumente
                args = input(f"\n{Color.YELLOW}Gib die Nmap-Argumente ein: {Color.RESET}")
                profile_type = "eigene Argumente"
            elif profile_name in self.scan_profiles:
                # Verwende vorhandenes Profil
                args = self.scan_profiles[profile_name]['args']
                profile_type = profile_name
                print(f"\n{Color.GREEN}Verwende Profil: {profile_name} mit Argumenten: {args}{Color.RESET}")
            else:
                print(self._d(f"\n{Color.RED}Ungültiges Profil!{Color.RESET}"))
                return None
            
            # Netzwerkbereich
            network_range = input(
                self._d(f"\n{Color.YELLOW}Gib den Netzwerkbereich ein (Enter für Standard {self.default_network}): {Color.RESET}")) or self.default_network
            
            # Führe den Scan durch
            print(f"\n{Color.GREEN}Starte benutzerdefinierten Scan auf {network_range} mit Argumenten: {args}{Color.RESET}")
            
            try:
                import nmap
            except ImportError:
                print(f"\n{Color.RED}Fehler: Das nmap-Modul ist nicht installiert. Bitte installieren Sie es mit 'pip install python-nmap'.{Color.RESET}")
                return None
            
            nm = nmap.PortScanner()
            
            start_time = time.time()
            nm.scan(hosts=network_range, arguments=args)
            duration = time.time() - start_time
            
            # Verarbeite die Ergebnisse
            hosts_list = self._process_nmap_results(nm)
            
            # Erstelle DataFrame
            results_df = pd.DataFrame(hosts_list)
            
            # Zeige Ergebnisse an
            print(f"\n{Color.GREEN}Scan abgeschlossen in {duration:.2f} Sekunden.{Color.RESET}")
            print(f"\n{Color.YELLOW}Gefundene Geräte: {len(results_df)}{Color.RESET}")
            
            if not results_df.empty:
                self._display_scan_results(results_df)
                
                # Speichere die Ergebnisse in der Datenbank
                self.db_manager.save_scan_result(
                    scan_type=f"Benutzerdefiniert ({profile_type})",
                    network_range=network_range,
                    devices_found=len(results_df),
                    duration=duration
                )
                
                # Aktualisiere Geräteinformationen
                self.db_manager.update_device_info(results_df)
            
            return results_df
        
        except Exception as e:
            logging.error(f"Fehler beim benutzerdefinierten Scan: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Scan: {str(e)}{Color.RESET}")
            return None
    
    def _process_nmap_results(self, nm) -> List[Dict[str, Any]]:
        """Verarbeitet die Nmap-Scan-Ergebnisse"""
        hosts_list = []
        
        for host in nm.all_hosts():
            try:
                host_info = {'ip': host}
                
                # Extrahiere Informationen
                if 'addresses' in nm[host]:
                    if 'mac' in nm[host]['addresses']:
                        mac_address = nm[host]['addresses']['mac']
                        host_info['mac'] = mac_address
                        
                        # Correctly access vendor information
                        if 'vendor' in nm[host]:
                            if isinstance(nm[host]['vendor'], dict) and mac_address in nm[host]['vendor']:
                                host_info['vendor'] = nm[host]['vendor'][mac_address]
                            elif isinstance(nm[host]['vendor'], str):
                                host_info['vendor'] = nm[host]['vendor']
                
                # Extrahiere Hostname
                if 'hostnames' in nm[host] and len(nm[host]['hostnames']) > 0:
                    for hostname in nm[host]['hostnames']:
                        if isinstance(hostname, dict) and 'name' in hostname and hostname['name'] and hostname['name'] != '':
                            host_info['hostname'] = hostname['name']
                            break
                
                # Extrahiere OS-Informationen
                if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
                    host_info['os'] = nm[host]['osmatch'][0]['name']
                
                # Extrahiere Dienste
                services = []
                open_ports = []
                if 'tcp' in nm[host]:
                    for port, port_info in nm[host]['tcp'].items():
                        if port_info['state'] == 'open':
                            open_ports.append(str(port))
                            service_info = f"Port {port}: {port_info['name']}"
                            if 'product' in port_info and port_info['product']:
                                service_info += f" - {port_info['product']}"
                            if 'version' in port_info and port_info['version']:
                                service_info += f" {port_info['version']}"
                            services.append(service_info)
                
                host_info['open_ports'] = ','.join(open_ports) if open_ports else ''
                host_info['services'] = '\n'.join(services) if services else 'Keine offenen Ports gefunden'
                
                hosts_list.append(host_info)
            except Exception as e:
                print(f"\n{Color.RED}Fehler bei der Verarbeitung von {host}: {str(e)}{Color.RESET}")
                logging.error(f"Fehler bei der Verarbeitung von {host}: {str(e)}")
        
        return hosts_list
    
    def _display_scan_results(self, results_df: pd.DataFrame) -> None:
        """Zeigt die Scan-Ergebnisse an"""
        # Zeige eine Zusammenfassung
        print("\nIP-Adresse\tMAC-Adresse\t\tHersteller\tHostname")
        print("-" * 80)
        
        for _, device in results_df.iterrows():
            ip = device.get('ip', 'N/A')
            mac = device.get('mac', 'N/A')
            vendor = device.get('vendor', 'N/A')
            hostname = device.get('hostname', 'N/A')
            
            # Check if vendor is a string before trying to slice it
            vendor_display = vendor
            if isinstance(vendor, str) and len(vendor) > 15:
                vendor_display = vendor[:15]
            print(f"{ip}\t{mac}\t{vendor_display}\t{hostname}")
        
        # Frage, ob detaillierte Ergebnisse angezeigt werden sollen
        show_details = input(f"\n{Color.YELLOW}Detaillierte Ergebnisse anzeigen? (j/n): {Color.RESET}").lower() == 'j'
        
        if show_details:
            for _, device in results_df.iterrows():
                ip = device.get('ip', 'N/A')
                os = device.get('os', 'Unbekannt')
                services = device.get('services', 'Keine Dienste gefunden')
                
                print(f"\n{Color.GREEN}=== Details für {ip} ==={Color.RESET}")
                print(f"OS: {os}")
                print(f"Dienste:\n{services}")
    
    def _run_special_nmap_scan(self, scan_name: str, nmap_args: str) -> Optional[pd.DataFrame]:
        """Führt einen speziellen Nmap-Scan durch"""
        try:
            print(f"\n{Color.GREEN}=== {scan_name} ==={Color.RESET}")
            
            # Netzwerkbereich
            network_range = input(
                self._d(f"\n{Color.YELLOW}Gib den Netzwerkbereich ein (Enter für Standard {self.default_network}): {Color.RESET}")) or self.default_network
            
            # Führe den Scan durch
            print(f"\n{Color.GREEN}Starte {scan_name} auf {network_range} mit Argumenten: {nmap_args}{Color.RESET}")
            
            try:
                import nmap
            except ImportError:
                print(f"\n{Color.RED}Fehler: Das nmap-Modul ist nicht installiert. Bitte installieren Sie es mit 'pip install python-nmap'.{Color.RESET}")
                return None
            
            nm = nmap.PortScanner()
            
            start_time = time.time()
            nm.scan(hosts=network_range, arguments=nmap_args)
            duration = time.time() - start_time
            
            # Verarbeite die Ergebnisse
            hosts_list = self._process_nmap_results(nm)
            
            # Erstelle DataFrame
            results_df = pd.DataFrame(hosts_list)
            
            # Zeige Ergebnisse an
            print(f"\n{Color.GREEN}Scan abgeschlossen in {duration:.2f} Sekunden.{Color.RESET}")
            print(f"\n{Color.YELLOW}Gefundene Geräte: {len(results_df)}{Color.RESET}")
            
            if not results_df.empty:
                self._display_scan_results(results_df)
                
                # Speichere die Ergebnisse in der Datenbank
                self.db_manager.save_scan_result(
                    scan_type=f"Spezieller Scan ({scan_name})",
                    network_range=network_range,
                    devices_found=len(results_df),
                    duration=duration
                )
                
                # Aktualisiere Geräteinformationen
                self.db_manager.update_device_info(results_df)
            
            return results_df
        
        except Exception as e:
            logging.error(f"Fehler beim speziellen Nmap-Scan: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Scan: {str(e)}{Color.RESET}")
            return None
    
    def _run_complete_scan(self) -> None:
        """Führt einen kompletten Scan durch"""
        try:
            print(f"{Color.GREEN}Starte kompletten Scan...{Color.RESET}")
            self.current_network = input(
                self._d(f"{Color.YELLOW}Gib den Netzwerkbereich ein (z.B. 192.168.0.1-20 oder einzelne IP (Enter für Standard {self.default_network})): {Color.RESET}")) or self.default_network
            
            # Validiere Netzwerkbereich
            if not self._validate_network_range(self.current_network):
                print(f"{Color.RED}Ungültiger Netzwerkbereich. Bitte verwenden Sie ein gültiges Format.{Color.RESET}")
                return
            
            # Scan durchführen
            start_time = time.time()
            self.scanning = True
            
            devices = self.scan_network(self.current_network)
            if devices is not None and not devices.empty:
                identified_devices = self.identify_devices(devices)
                self.scan_vulnerabilities(self.current_network)
                
                # Zeige detaillierte Geräteidentifikation mit Ports und Diensten
                if identified_devices is not None and not identified_devices.empty:
                    print(f"\n{Color.GREEN}Gefundene Geräte: {len(identified_devices)}{Color.RESET}")
                    print("\nIP-Adresse\tMAC-Adresse\t\tHersteller\tHostname")
                    print("-" * 80)
                    
                    for _, device in identified_devices.iterrows():
                        ip = device.get('ip', 'N/A')
                        mac = device.get('mac', 'N/A')
                        vendor = device.get('vendor', 'N/A')
                        hostname = device.get('hostname', 'N/A')
                        
                        # Check if vendor is a string before trying to slice it
                        vendor_display = vendor
                        if isinstance(vendor, str) and len(vendor) > 15:
                            vendor_display = vendor[:15]
                        print(f"{ip}\t{mac}\t{vendor_display}\t{hostname}")
                    
                    print("\nStarte detaillierte Geräteidentifikation...")
                    
                    for idx, device in identified_devices.iterrows():
                        ip = device.get('ip', 'N/A')
                        os = device.get('os', 'Unbekannt')
                        
                        # Sichere Verarbeitung der offenen Ports
                        try:
                            open_ports = device.get('open_ports', '')
                            if isinstance(open_ports, str) and open_ports.strip():
                                # Versuche, die Ports als Komma-getrennte Liste zu behandeln
                                try:
                                    # Entferne mögliche Whitespaces und prüfe auf JSON-Format
                                    open_ports_clean = open_ports.strip()
                                    
                                    # Wenn es wie ein JSON-Array aussieht, versuche es zu parsen
                                    if open_ports_clean.startswith('[') and open_ports_clean.endswith(']'):
                                        try:
                                            ports_list = json.loads(open_ports_clean)
                                            ports_display = ', '.join(map(str, ports_list))
                                        except json.JSONDecodeError:
                                            # Wenn JSON-Parsing fehlschlägt, verwende den Originaltext
                                            ports_display = open_ports
                                    else:
                                        # Verwende den Originaltext
                                        ports_display = open_ports
                                        
                                    print(f"\nIdentifiziere Gerät: {ip}")
                                    print(f"Offene Ports: {ports_display}")
                                except Exception as port_parse_error:
                                    logging.error(f"Fehler beim Parsen der offenen Ports für {ip}: {str(port_parse_error)}")
                                    print(f"\nIdentifiziere Gerät: {ip}")
                                    print(f"Offene Ports: {open_ports}")
                            else:
                                print(f"\nIdentifiziere Gerät: {ip}")
                                print("Keine offenen Ports gefunden")
                                
                            services = device.get('services', 'Keine Dienste gefunden')
                            print(f"Dienste:\n{services}")
                        except Exception as port_error:
                            logging.error(f"Fehler beim Verarbeiten der offenen Ports für {ip}: {str(port_error)}")
                            print(f"\nIdentifiziere Gerät: {ip}")
                            print("Fehler beim Verarbeiten der Port-Informationen")
            
            duration = time.time() - start_time
            
            # Speichere Gesamtscan in der Historie
            try:
                self.db_manager.save_scan_result(
                    scan_type="Komplett-Scan",
                    network_range=self.current_network,
                    devices_found=len(devices) if devices is not None else 0,
                    duration=duration
                )
            except Exception as db_error:
                logging.error(f"Fehler beim Speichern des Komplett-Scans: {str(db_error)}")
            
            print(f"\n{Color.GREEN}Kompletter Scan abgeschlossen in {duration:.2f} Sekunden.{Color.RESET}")
            
            # Stelle sicher, dass der Scanner-Status zurückgesetzt wird
            self.scanning = False
            
            # Warte kurz, damit alle Ausgaben abgeschlossen sind
            time.sleep(0.5)
            
            # Input-Stream leeren (plattformabhängig)
            self._clear_input_buffer()
        
        except Exception as e:
            self.scanning = False  # Status auch bei Fehler zurücksetzen
            logging.error(f"Fehler beim kompletten Scan: {str(e)}")
            print(f"{Color.RED}Fehler beim Scan: {str(e)}{Color.RESET}")
    
    def _run_full_pentest(self, network_range: str) -> None:
        """Führt einen vollständigen Pentest durch"""
        try:
            print(f"\n{Color.GREEN}=== Vollständiger Pentest ==={Color.RESET}")
            print(f"\n{Color.YELLOW}Starte vollständigen Pentest auf {network_range}...{Color.RESET}")
            
            # Führe einen vollständigen Portscan durch
            print(f"\n{Color.GREEN}1. Vollständiger Portscan...{Color.RESET}")
            self.nmap_special.full_port_scan(network_range)
            
            # Führe eine Service- und OS-Erkennung durch
            print(f"\n{Color.GREEN}2. Service- und OS-Erkennung...{Color.RESET}")
            self.nmap_special.service_detection_scan(network_range)
            
            # Führe eine Schwachstellenanalyse durch
            print(f"\n{Color.GREEN}3. Schwachstellenanalyse...{Color.RESET}")
            self.scan_vulnerabilities(network_range)
            
            # Suche nach Metasploit-Exploits
            print(f"\n{Color.GREEN}4. Suche nach Metasploit-Exploits...{Color.RESET}")
            if self._check_metasploit_installation():
                print(f"\n{Color.YELLOW}Metasploit-Integration ist verfügbar. "
                      f"Durchsuche gefundene Dienste/CVEs...{Color.RESET}")
                self._metasploit_search_after_scan(network_range)
            else:
                print(f"\n{Color.YELLOW}Metasploit ist nicht verfügbar. Überspringe Exploit-Suche.{Color.RESET}")

            print(f"\n{Color.GREEN}Vollständiger Pentest abgeschlossen.{Color.RESET}")
        except Exception as e:
            logging.error(f"Fehler beim vollständigen Pentest: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Pentest: {str(e)}{Color.RESET}")

    def _resolve_scan_hosts(self, network_range: str) -> List[str]:
        """Ermittelt die gescannten Hosts (aus der DB) im angegebenen Bereich."""
        import ipaddress
        nr = (network_range or '').strip()
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                c.execute("SELECT ip FROM devices")
                all_ips = [r[0] for r in c.fetchall() if r[0]]
        except Exception as e:
            logging.error(f"Fehler beim Laden der Hosts: {str(e)}")
            return []

        if not nr:
            return all_ips
        try:
            net = ipaddress.ip_network(nr, strict=False)
        except ValueError:
            return [ip for ip in all_ips if ip == nr]
        hosts = []
        for ip in all_ips:
            try:
                if ipaddress.ip_address(ip) in net:
                    hosts.append(ip)
            except ValueError:
                continue
        return hosts

    def _metasploit_search_after_scan(self, network_range: str) -> None:
        """Durchsucht Metasploit nach den im Scan gefundenen Diensten und CVEs.

        Für jeden Host im Bereich werden Dienst-Produktnamen (z. B. vsftpd, samba)
        und gefundene CVEs gesammelt, in Metasploit gesucht und die gefundenen
        Module angezeigt sowie in der Datenbank gespeichert.
        """
        import re
        try:
            hosts = self._resolve_scan_hosts(network_range)
            if not hosts:
                print(f"{Color.YELLOW}Keine gescannten Hosts im Bereich '{network_range}' gefunden.{Color.RESET}")
                return

            for host in hosts:
                # Dienste + CVEs aus der DB laden
                services = ''
                vuln_blob = ''
                try:
                    with sqlite3.connect(self.db_name) as conn:
                        c = conn.cursor()
                        c.execute("SELECT services FROM devices WHERE ip=?", (host,))
                        row = c.fetchone()
                        services = row[0] if row and row[0] else ''
                        c.execute("SELECT cve_id, description FROM vulnerability_details WHERE device_ip=?", (host,))
                        vuln_blob = ' '.join(
                            ((r[0] or '') + ' ' + (r[1] or '')) for r in c.fetchall()
                        )
                except Exception as e:
                    logging.error(f"Fehler beim Laden der Scan-Daten für {host}: {str(e)}")

                # Dienst-Produktnamen aus den Klammern extrahieren (z. B. "(vsftpd 3.0.2)")
                products = []
                for m in re.finditer(r'\(([A-Za-z][\w\-]+)', services):
                    p = m.group(1).lower()
                    if p not in products and p not in ('nmap',):
                        products.append(p)

                # CVEs sammeln (dedupliziert)
                cves = []
                for cve in re.findall(r'CVE-\d{4}-\d{4,7}', vuln_blob):
                    if cve not in cves:
                        cves.append(cve)

                if not products and not cves:
                    print(f"\n{Color.YELLOW}{host}: keine Dienste/CVEs für eine Metasploit-Suche vorhanden.{Color.RESET}")
                    continue

                # Suchbegriffe: erst Dienste, dann CVEs; auf ein vernünftiges Limit kürzen
                search_terms = [(f"Dienst '{p}'", p) for p in products]
                search_terms += [(f"CVE {cve}", f"cve:{cve}") for cve in cves]
                MAX_TERMS = 15
                if len(search_terms) > MAX_TERMS:
                    print(f"{Color.YELLOW}{len(search_terms)} Suchbegriffe gefunden – "
                          f"begrenze auf {MAX_TERMS}.{Color.RESET}")
                    search_terms = search_terms[:MAX_TERMS]

                print(f"\n{Color.BLUE}=== Host {host}: durchsuche Metasploit "
                      f"({len(search_terms)} Begriffe, kann etwas dauern) ==={Color.RESET}")

                found_modules = set()
                try:
                    for label, term in search_terms:
                        print(f"\n{Color.GREEN}>>> Suche: {label}{Color.RESET}")
                        result = self.metasploit.search_exploits(term)
                        if result.get('success') and result.get('output'):
                            for mod in re.findall(r'((?:exploit|auxiliary|post)/[\w/]+)',
                                                  result['output']):
                                found_modules.add(mod)
                except KeyboardInterrupt:
                    print(f"\n{Color.YELLOW}Metasploit-Suche abgebrochen.{Color.RESET}")

                if found_modules:
                    print(f"\n{Color.RED}{host}: {len(found_modules)} potenzielle "
                          f"Metasploit-Module gefunden:{Color.RESET}")
                    for mod in sorted(found_modules):
                        print(f"  {Color.RED}{mod}{Color.RESET}")
                    try:
                        self.scanner.update_metasploit_exploits(host, sorted(found_modules))
                        print(f"  {Color.GREEN}-> in der Datenbank gespeichert.{Color.RESET}")
                    except Exception as e:
                        logging.error(f"Fehler beim Speichern der Exploits für {host}: {str(e)}")
                else:
                    print(f"\n{Color.YELLOW}{host}: keine passenden Metasploit-Module gefunden.{Color.RESET}")

        except Exception as e:
            logging.error(f"Fehler bei der Metasploit-Suche: {str(e)}")
            print(f"\n{Color.RED}Fehler bei der Metasploit-Suche: {str(e)}{Color.RESET}")
    
    def _clear_input_buffer(self) -> None:
        """Leert den Input-Buffer (plattformabhängig)"""
        if os.name == 'posix':  # Für Unix-basierte Systeme
            try:
                import termios
                termios.tcflush(sys.stdin, termios.TCIOFLUSH)
            except Exception:
                pass
        elif os.name == 'nt':  # Für Windows
            try:
                import msvcrt
                while msvcrt.kbhit():
                    msvcrt.getch()
            except Exception:
                pass

    def _restore_terminal(self) -> None:
        """Stellt die Terminal-Einstellungen wieder her (Echo/Canonical-Modus).

        Subprozesse wie msfconsole können das TTY in einen Zustand ohne Echo
        versetzen. Dann sind eingetippte Zeichen unsichtbar. Diese Methode
        stellt die ursprünglichen Einstellungen vor jeder Menüeingabe wieder her.
        """
        if os.name != 'posix':
            return
        try:
            import termios
            fd = sys.stdin.fileno()
            if self._term_attrs is not None:
                # Ursprüngliche, vom Benutzer erwartete Einstellungen wiederherstellen
                termios.tcsetattr(fd, termios.TCSANOW, self._term_attrs)
            else:
                # Fallback: Echo und kanonischen Modus explizit aktivieren
                attrs = termios.tcgetattr(fd)
                attrs[3] = attrs[3] | termios.ECHO | termios.ICANON | termios.ECHOE | termios.ECHOK | termios.ISIG
                termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except Exception:
            # Nicht-Terminal-Umgebungen (z.B. Pipes) ignorieren
            pass
    
    def _wait_for_user(self) -> None:
        """Wartet auf Benutzereingabe"""
        input(self._d(f"\n{Color.YELLOW}Drücke ENTER um zum Hauptmenü zurückzukehren...{Color.RESET}"))
    
    def _validate_network_range(self, network_range: str) -> bool:
        """Validiert einen Netzwerkbereich"""
        # Einfache Validierung für IP-Adressen und Netzwerkbereiche
        ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2}|-\d{1,3})?$'
        return re.match(ip_pattern, network_range) is not None
    
    def show_menu(self) -> None:
        """Zeigt das Hauptmenü an"""
        while True:
            # Terminal-Echo wiederherstellen, falls ein Subprozess (z.B. msfconsole)
            # das TTY verändert hat – sonst sind Eingaben unsichtbar
            self._restore_terminal()

            # -Pn-Sitzungsstatus zwischen Standard- und Spezial-Scans abgleichen:
            # wurde -Pn in einem der beiden Subsysteme aktiviert, gilt es überall.
            try:
                pn_active = self.scanner.use_pn or self.nmap_special.use_pn
                self.scanner.use_pn = pn_active
                self.nmap_special.use_pn = pn_active
            except AttributeError:
                pass

            clear()  # Terminal vor jeder Menüanzeige leeren

            # Banner nur einmal beim Start anzeigen
            if not self._banner_shown:
                print(BANNER_TEXT)
                self._banner_shown = True
                time.sleep(3)  # Banner für 3 Sekunden anzeigen
                clear()
            
            print(f"\n{Color.GREEN}=== IoT Netzwerkscanner v4.0 ==={Color.RESET}")
            print(f"\n{Color.GREEN}=============== BY =============={Color.RESET}")
            print(f"\n{Color.GREEN}============== ELFO ============={Color.RESET}")
            print()
            print(f"{Color.YELLOW}Hauptmenü:{Color.RESET}")
            print()
            print(self._d("1. Netzwerk-Discovery Scan"))
            print("2. Detaillierte Geräteidentifikation")
            print(self._d("3. Schwachstellenanalyse"))
            print(self._d("4. Komplett-Scan"))
            print(self._d("5. Benutzerdefinierter Scan"))
            print(f"{Color.BLUE}Spezielle Nmap-Scans:{Color.RESET}")
            print("6. Schneller Portscan (Top 100 Ports)")
            print("7. Vollständiger Portscan (Alle Ports)")
            print("8. Service-Erkennung (Version Detection)")
            print("9. OS-Erkennung (OS Detection)")
            print("10. Aggressive Scan (Service, OS, Scripts)")
            print("11. Vollständiger Pentest (Alle Ports, Schwachstellen, Brute-Force)")
            print(f"{Color.BLUE}Erweiterte Pentesting-Funktionen:{Color.RESET}")
            print("12. SSL/TLS-Konfiguration prüfen")
            print("13. Standardpasswörter testen")
            print("14. Port-Knocking-Tests")
            print("15. Metasploit-Exploits suchen")
            print("16. Brute-Force-Angriff starten")
            print(f"{Color.BLUE}Export:{Color.RESET}")
            print("17. Ergebnisse exportieren (alle Scans)")
            print("18. Nur letzten Scan exportieren")
            print("19. Scan-Verlauf anzeigen")
            print(self._d("20. Geräteübersicht (Datenbank, neue Geräte)"))
            print(f"{Color.BLUE}Konfiguration:{Color.RESET}")
            print("21. Scan-Profile verwalten")
            print("22. Einstellungen (iot_config2.ini)")
            print("23. Beenden")
            
            try:
                choice = input(f"\n{Color.YELLOW}Wähle eine Option: {Color.RESET}")
                
                if choice == "1":
                    network_range = input(
                        f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self.scan_network(network_range)
                    self._wait_for_user()
                
                elif choice == "2":
                    network_range = input(
                        f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    devices = self.scan_network(network_range)
                    if devices is not None and not devices.empty:
                        self.identify_devices(devices)
                    self._wait_for_user()
                
                elif choice == "3":
                    network_range = input(
                        f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self.scan_vulnerabilities(network_range)
                    self._wait_for_user()
                
                elif choice == "4":
                    self._run_complete_scan()
                    self._wait_for_user()
                
                elif choice == "5":
                    self.custom_scan()
                    self._wait_for_user()
                
                elif choice == "6":
                    # Schneller Portscan
                    network_range = input(f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self.nmap_special.quick_port_scan(network_range)
                    self._wait_for_user()
                
                elif choice == "7":
                    # Vollständiger Portscan
                    network_range = input(f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self.nmap_special.full_port_scan(network_range)
                    self._wait_for_user()
                
                elif choice == "8":
                    # Service-Erkennung
                    network_range = input(f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self.nmap_special.service_detection_scan(network_range)
                    self._wait_for_user()
                
                elif choice == "9":
                    # OS-Erkennung
                    network_range = input(f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self.nmap_special.os_detection_scan(network_range)
                    self._wait_for_user()
                
                elif choice == "10":
                    # Aggressiver Scan
                    network_range = input(f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self.nmap_special.aggressive_scan(network_range)
                    self._wait_for_user()
                
                elif choice == "11":
                    # Vollständiger Pentest
                    network_range = input(f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self._run_full_pentest(network_range)
                    self._wait_for_user()
                
                elif choice == "12":
                    # SSL/TLS-Konfiguration prüfen
                    ip = input(f"{Color.YELLOW}IP-Adresse für SSL/TLS-Prüfung: {Color.RESET}")
                    port = input(f"{Color.YELLOW}Port (Standard: 443): {Color.RESET}") or "443"
                    self.check_ssl_configuration(ip, int(port))
                    self._wait_for_user()
                
                elif choice == "13":
                    # Standardpasswörter testen
                    ip = input(f"{Color.YELLOW}IP-Adresse für Passwort-Test: {Color.RESET}")
                    device_type = input(f"{Color.YELLOW}Gerätetyp (optional): {Color.RESET}")
                    self.check_default_credentials(ip, device_type if device_type else None)
                    self._wait_for_user()
                
                elif choice == "14":
                    # Port-Knocking-Tests
                    ip = input(f"{Color.YELLOW}IP-Adresse für Port-Knocking-Test: {Color.RESET}")
                    seq = input(f"{Color.YELLOW}Port-Sequenz (z.B. 1000,2000,3000): {Color.RESET}") or "1000,2000,3000"
                    ports = [int(p) for p in seq.split(',')]
                    self.test_port_knocking(ip, ports)
                    self._wait_for_user()
                
                elif choice == "15":
                    # Metasploit-Exploits suchen
                    search_term = input(f"{Color.YELLOW}Suchbegriff für Metasploit-Exploits: {Color.RESET}")
                    if search_term:
                        result = self.metasploit.search_exploits(search_term)
                        if not result["success"]:
                            print(f"{Color.RED}Fehler bei der Suche: {result.get('error', 'Unbekannter Fehler')}{Color.RESET}")
                    else:
                        print(f"{Color.RED}Bitte geben Sie einen Suchbegriff ein.{Color.RESET}")
                    self._wait_for_user()
                
                elif choice == "16":
                    # Brute-Force-Angriff
                    ip = input(f"{Color.YELLOW}IP-Adresse für Brute-Force-Angriff: {Color.RESET}")
                    service = input(f"{Color.YELLOW}Dienst (ssh, ftp, telnet, http, http-form): {Color.RESET}").lower()
                    port_in = input(f"{Color.YELLOW}Port (Enter für Standard des Dienstes): {Color.RESET}").strip()
                    username = input(f"{Color.YELLOW}Benutzername (oder Pfad zur Benutzerliste): {Color.RESET}")
                    password = input(f"{Color.YELLOW}Passwort (oder Pfad zur Passwortliste): {Color.RESET}")
                    threads_in = input(f"{Color.YELLOW}Parallele Threads (Enter für 8): {Color.RESET}").strip()
                    port = int(port_in) if port_in.isdigit() else None
                    workers = int(threads_in) if threads_in.isdigit() and int(threads_in) > 0 else 8
                    if ip and service:
                        self.brute_force(ip, service, username, password, port, workers)
                    else:
                        print(f"{Color.RED}IP-Adresse und Dienst sind erforderlich.{Color.RESET}")
                    self._wait_for_user()
                
                elif choice == "17":
                    # Ergebnisse exportieren (alle Scans)
                    self.export_results()
                    self._wait_for_user()

                elif choice == "18":
                    # Nur letzten Scan exportieren
                    self.export_last_scan()
                    self._wait_for_user()

                elif choice == "19":
                    # Scan-Verlauf anzeigen
                    self.show_scan_history()
                    self._wait_for_user()

                elif choice == "20":
                    # Geräteübersicht aus der Datenbank
                    self.show_device_overview()
                    self._wait_for_user()

                elif choice == "21":
                    # Scan-Profile verwalten
                    self.manage_scan_profiles()
                    # Kein wait_for_user nötig, da manage_scan_profiles eigene Eingabeaufforderung hat

                elif choice == "22":
                    # Einstellungen
                    self.show_settings()
                    # Kein wait_for_user nötig, da show_settings eigene Eingabeaufforderung hat

                elif choice == "23":
                    # Beenden
                    print(f"{Color.GREEN}Programm wird beendet...{Color.RESET}")
                    break
                

                
                else:
                    print(f"{Color.RED}Ungültige Auswahl!{Color.RESET}")
                    self._wait_for_user()
            
            except Exception as e:
                logging.error(f"Fehler im Hauptmenü: {str(e)}")
                print(f"{Color.RED}Ein Fehler ist aufgetreten: {str(e)}{Color.RESET}")
                self._wait_for_user()


def check_root() -> bool:
    """Überprüft, ob das Skript mit Root-Rechten ausgeführt wird, und startet es ggf. neu"""
    # Prüfen, ob das Skript bereits mit Root-Rechten läuft
    if os.name == 'posix':  # Nur für Unix-basierte Systeme
        if os.geteuid() != 0:
            print(f"{Color.RED}Dieses Programm benötigt Root-Rechte (sudo) für Netzwerk-Scans.{Color.RESET}")
            print(f"{Color.YELLOW}Das Programm wird jetzt mit sudo neu gestartet...{Color.RESET}")
            
            try:
                # Starte das Skript mit sudo neu
                args = ['sudo', sys.executable] + sys.argv
                subprocess.call(args)
                sys.exit(0)  # Beende das ursprüngliche Skript
            except Exception as e:
                print(f"{Color.RED}Fehler beim Neustart mit sudo: {str(e)}{Color.RESET}")
                sys.exit(1)
    elif os.name == 'nt':  # Windows
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print(f"{Color.RED}Dieses Programm benötigt Administratorrechte für Netzwerk-Scans.{Color.RESET}")
            print(f"{Color.YELLOW}Bitte starte das Programm als Administrator.{Color.RESET}")
            input("Drücke ENTER zum Beenden...")
            sys.exit(1)
    return True

def generate_reports():
    """Generate reports using the Exporter module"""
    # Load configuration
    config = configparser.ConfigParser()
    config.read('iot_config2.ini')

    # Initialize database
    db = Database(config)

    # Initialize exporter
    exporter = Exporter(db, config)

    # Example: Generate HTML report for all devices
    html_report = exporter.generate_html_report()
    with open('security_report.html', 'w') as f:
        f.write(html_report)
    print("HTML report generated: security_report.html")

    # Example: Export to CSV
    exporter.export_to_csv('security_report.csv')
    print("CSV report generated: security_report.csv")

    # Example: Start web server to view reports
    # Uncomment the line below to start the web server
    # exporter.serve_reports(host='127.0.0.1', port=8080)

# Hauptprogramm
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='IoT Netzwerkscanner')
    parser.add_argument('--headless', action='store_true', help='Ausführung ohne GUI')
    parser.add_argument('--debug', action='store_true', help='Aktiviere detailliertes Debugging')
    parser.add_argument('--scan-type', 
        choices=['quick', 'standard', 'deep', 'vulnerability'],
        default='standard', 
        help='Scan-Typ'
    )
    parser.add_argument('--target', 
        default=None, 
        help='Ziel IP oder Netzwerk'
    )
    parser.add_argument('--generate-reports', 
        action='store_true',
        help='Generiere Berichte'
    )
    
    args = parser.parse_args()
    
    try:
        # Überprüfe Root-Rechte
        check_root()
        
        # Wenn Reports generiert werden sollen
        if args.generate_reports:
            generate_reports()
            sys.exit(0)
        
        scanner = IOTScanner()
        scanner.cleanup_database()
        
        # Setze Logging-Level basierend auf Debug-Flag
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("Debug-Modus aktiviert")
        
        if args.headless:
            target = args.target or scanner.default_network
            logging.info(f"Starte Scan im Headless-Modus: {target}")
            
            if args.scan_type == 'vulnerability':
                scanner.scan_vulnerabilities(target)
            else:
                # Wähle das entsprechende Scan-Profil
                devices = scanner.scan_network(target)
                if devices is not None and not devices.empty and args.scan_type != 'quick':
                    scanner.identify_devices(devices)
        else:
            clear()
            print(BANNER_TEXT)
            scanner.show_menu()
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Programm wurde vom Benutzer beendet.{Color.RESET}")
    except Exception as e:
        logging.critical(f"Kritischer Fehler: {str(e)}")
        print(f"{Color.RED}Kritischer Fehler: {str(e)}{Color.RESET}")