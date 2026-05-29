#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IoT Netzwerkscanner v4.0
Ein umfassendes Tool zur Identifikation und Analyse von IoT-Geräten im Netzwerk

Author: ELFO
Version: 4.0
"""

import os
import re
import time
import socket
import logging
import subprocess
import tempfile  # Für temporäre Dateien
import pandas as pd
import sqlite3
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from threading import Timer  # Für die Fortschrittsanzeige
import nmap
from .utils import Color, decode_unicode_escape

class Scanner:
    def __init__(self, db_name='iot_devices.db', default_network='192.168.0.0/24'):
        self.db_name = db_name
        self.default_network = default_network
        self.scanning = False
        self.current_network = None
        self.nm = nmap.PortScanner()
        self.vulners_api_key = None
        self.metasploit_available = self._check_metasploit_installation()
        self._load_vulners_api_key()
    
    # Hilfsfunktion zum Dekodieren von Strings
    def _d(self, text):
        """Dekodiert Unicode-Escape-Sequenzen"""
        return decode_unicode_escape(text)

    def _mask_secrets(self, text):
        """Maskiert sensible Werte (z.B. den Vulners-API-Key) in Ausgaben/Logs"""
        if not text:
            return text
        key = getattr(self, 'vulners_api_key', None)
        if key:
            text = text.replace(key, '***MASKED***')
        return text

    def _get_cfg(self, config, section, option, fallback):
        """Liest einen Konfigurationswert sicher aus dem übergebenen Config-Objekt"""
        try:
            if config is not None and hasattr(config, 'get'):
                val = config.get(section, option, fallback=fallback)
                return val if val is not None else fallback
        except Exception:
            pass
        return fallback

    def _build_vuln_script_expr(self, config):
        """Baut den --script-Ausdruck für die Schwachstellenanalyse.

        Steuerbar über [SCAN] in der iot_config2.ini:
          - vuln_script_categories: Komma-Liste der NSE-Kategorien
            (Standard: vuln,exploit,auth,default – findet möglichst viel)
          - enable_brute: brute-Kategorie zusätzlich (langsam) – Standard aus
          - exclude_ssl_scripts: ssl-*-Skripte ausschließen – Standard aus

        Brute-Force-Skripte sind der häufigste Absturz-/Hänger-Verursacher und
        daher standardmäßig deaktiviert.
        """
        categories_raw = str(self._get_cfg(
            config, 'SCAN', 'vuln_script_categories', 'vuln,exploit,auth,default'))
        categories = [c.strip() for c in categories_raw.split(',') if c.strip()]
        if not categories:
            categories = ['vuln']

        # Zusätzliche, namentlich genannte Skripte, die in keiner der obigen
        # Kategorien liegen (z.B. ssl-enum-ciphers = discovery/intrusive), aber
        # wertvolle Funde liefern (schwache Ciphers, SWEET32, POODLE, ...).
        extras_raw = str(self._get_cfg(
            config, 'SCAN', 'extra_scripts',
            'ssl-enum-ciphers,ssl-poodle,ssl-dh-params'))
        extras = [e.strip() for e in extras_raw.split(',') if e.strip()]

        enable_brute = str(self._get_cfg(config, 'SCAN', 'enable_brute', 'false')).strip().lower() == 'true'
        exclude_ssl = str(self._get_cfg(config, 'SCAN', 'exclude_ssl_scripts', 'false')).strip().lower() == 'true'

        if enable_brute and 'brute' not in categories:
            categories.append('brute')

        # Bei exclude_ssl die ssl-Extras weglassen
        if exclude_ssl:
            extras = [e for e in extras if not e.lower().startswith('ssl')]

        terms = categories + extras
        cat_expr = ' or '.join(terms)
        if len(terms) > 1:
            cat_expr = f'({cat_expr})'
        if exclude_ssl:
            return f'{cat_expr} and not ssl-*'
        return cat_expr

    def _run_with_spinner(self, cmd, label='Scanning'):
        """Führt einen Subprozess aus und zeigt dabei einen Fortschritts-Spinner an"""
        import threading
        progress_chars = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
        idx = 0
        stop = threading.Event()

        def _spin():
            nonlocal idx
            while not stop.wait(0.2):
                print(f"\r  {Color.BLUE}{label} {progress_chars[idx]}{Color.RESET} ", end='', flush=True)
                idx = (idx + 1) % len(progress_chars)

        t = threading.Thread(target=_spin, daemon=True)
        t.start()
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                check=False
            )
        finally:
            stop.set()
            t.join()
            print("\r" + " " * 50 + "\r", end='', flush=True)  # Spinner-Zeile löschen
        return result

    def _vulners_retry(self, host, ports, config):
        """Wiederholt gezielt den vulners-CVE-Lookup.

        vulners fragt einen externen Dienst (vulners.com) ab und liefert je nach
        Last/Rate-Limit mal alle, mal keine Treffer. Dieser gezielte Zweitlauf nur
        mit dem vulners-Skript auf den bereits bekannten offenen Ports gleicht das
        aus. Steuerbar über [SCAN] vulners_retries (0 = aus).

        Rückgabe: {port(str): [CVE-Zeilen]}
        """
        if not ports or not getattr(self, 'vulners_api_key', None):
            return {}
        try:
            retries = int(str(self._get_cfg(config, 'SCAN', 'vulners_retries', '2')).strip() or '0')
        except ValueError:
            retries = 2
        if retries <= 0:
            return {}

        port_arg = ','.join(str(p) for p in ports)
        cve_by_port = {}
        for attempt in range(1, retries + 1):
            cmd = ['nmap', '-sV', '-T4', '-p', port_arg, '--script', 'vulners',
                   '--script-args', f'vulners.apikey={self.vulners_api_key}', host]
            result = self._run_with_spinner(cmd, f'vulners-Lookup {attempt}/{retries} für {host}')
            if result.returncode != 0:
                logging.warning(f"vulners-Retry {attempt} für {host} fehlgeschlagen (Code {result.returncode})")
                continue
            for port in ports:
                ps = re.search(rf'{port}/tcp\s+open.*?(?=^\d+/tcp\s|\Z)',
                               result.stdout, re.DOTALL | re.MULTILINE)
                if ps:
                    cves = [c.strip() for c in re.findall(r'(CVE-\d{4}-\d{4,7}[^\n]*)', ps.group(0))]
                    if cves:
                        cve_by_port.setdefault(str(port), set()).update(cves)
            # Sobald irgendein Port CVEs liefert, ist der Dienst erreichbar – Schluss
            if cve_by_port:
                break
        return {p: sorted(v) for p, v in cve_by_port.items()}

    def _load_vulners_api_key(self) -> None:
        """Lädt den Vulners API-Key aus der Datenbank oder Konfigurationsdatei"""
        try:
            # Versuche zuerst, den API-Key aus der Datenbank zu laden
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                c.execute("SELECT value FROM settings WHERE key='vulners_api_key'")
                result = c.fetchone()

                if result and result[0]:
                    self.vulners_api_key = result[0].strip()  # Entferne Leerzeichen und Zeilenumbrüche
                    logging.info("Vulners API-Key aus Datenbank geladen")
                else:
                    # Wenn kein API-Key in der Datenbank gefunden wurde, versuche ihn aus der Konfigurationsdatei zu laden
                    try:
                        import configparser
                        config = configparser.ConfigParser()
                        config.read('iot_config2.ini')
                        
                        if 'VULNERS' in config and 'vulners_api_key' in config['VULNERS']:
                            self.vulners_api_key = config['VULNERS']['vulners_api_key'].strip()
                            logging.info("Vulners API-Key aus Konfigurationsdatei geladen")
                            
                            # Optional: Speichere den API-Key in der Datenbank für zukünftige Verwendung
                            try:
                                c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", 
                                         ('vulners_api_key', self.vulners_api_key))
                                conn.commit()
                                logging.info("Vulners API-Key in Datenbank gespeichert")
                            except Exception as db_err:
                                logging.warning(f"Konnte API-Key nicht in Datenbank speichern: {str(db_err)}")
                        else:
                            self.vulners_api_key = None
                            logging.warning("Kein Vulners API-Key in der Konfigurationsdatei gefunden")
                    except Exception as config_err:
                        self.vulners_api_key = None
                        logging.warning(f"Fehler beim Laden des Vulners API-Keys aus der Konfigurationsdatei: {str(config_err)}")
        except Exception as e:
            self.vulners_api_key = None
            logging.error(f"Fehler beim Laden des Vulners API-Keys: {str(e)}")

    def _check_metasploit_installation(self) -> bool:
        """Überprüft, ob Metasploit installiert ist"""
        try:
            # Prüfe, ob msfconsole im PATH ist
            subprocess.run(['which', 'msfconsole'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            logging.info("Metasploit ist installiert")
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            # Prüfe alternative Pfade
            common_paths = [
                '/usr/bin/msfconsole',
                '/usr/share/metasploit-framework/msfconsole',
                '/opt/metasploit-framework/bin/msfconsole',
                '/opt/metasploit',
            ]

            for path in common_paths:
                if os.path.exists(path):
                    logging.info(f"Metasploit gefunden unter: {path}")
                    return True

            logging.warning("Metasploit ist nicht installiert oder nicht im PATH")
            print(f"{Color.YELLOW}HINWEIS: Metasploit ist nicht installiert oder nicht im PATH.{Color.RESET}")
            print(
                f"{Color.YELLOW}Einige erweiterte Funktionen zur Schwachstellenanalyse sind nicht verfügbar.{Color.RESET}")
            return False

    def scan_network(self, network_range: Optional[str] = None) -> Optional[pd.DataFrame]:
        try:
            if not network_range and self.current_network:
                network_range = self.current_network
            elif not network_range:
                network_range = self.default_network

            self.current_network = network_range

            print(f"\n{Color.GREEN}Starte Netzwerk-Discovery auf {network_range}...{Color.RESET}")

            # Fortschrittsanzeige initialisieren
            import threading
            progress_chars = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
            progress_idx = 0
            stop_progress = threading.Event()

            def _spinner():
                nonlocal progress_idx
                while not stop_progress.wait(0.1):
                    print(f"\rScanning {progress_chars[progress_idx]}", end='', flush=True)
                    progress_idx = (progress_idx + 1) % len(progress_chars)

            spinner_thread = threading.Thread(target=_spinner, daemon=True)
            spinner_thread.start()

            # Führe nmap-Scan durch
            start_time = time.time()

            # Use the nmap PortScanner object instead of subprocess
            self.nm.scan(hosts=network_range, arguments='-sn')

            # Stoppe Fortschrittsanzeige
            stop_progress.set()
            spinner_thread.join()
            print("\r", end='', flush=True)  # Lösche Fortschrittsanzeige
            
            # Verarbeite die Ergebnisse
            hosts_list = []
            for host in self.nm.all_hosts():
                if 'status' in self.nm[host] and self.nm[host]['status']['state'] == 'up':
                    host_info = {'ip': host}
                    
                    # MAC-Adresse und Hersteller extrahieren, wenn verfügbar
                    if 'addresses' in self.nm[host]:
                        if 'mac' in self.nm[host]['addresses']:
                            host_info['mac'] = self.nm[host]['addresses']['mac']
                            if 'vendor' in self.nm[host] and self.nm[host]['addresses']['mac'] in self.nm[host]['vendor']:
                                host_info['vendor'] = self.nm[host]['vendor'][self.nm[host]['addresses']['mac']]
                    
                    # Hostname extrahieren, wenn verfügbar
                    if 'hostnames' in self.nm[host] and len(self.nm[host]['hostnames']) > 0:
                        for hostname in self.nm[host]['hostnames']:
                            if hostname['name'] and hostname['name'] != '':
                                host_info['hostname'] = hostname['name']
                                break
                    
                    hosts_list.append(host_info)
            
            # Erstelle DataFrame
            devices_df = pd.DataFrame(hosts_list)
            
            # Speichere Ergebnisse in der Datenbank
            self._save_scan_results(devices_df, network_range, start_time)
            
            # Zeige Ergebnisse an
            duration = time.time() - start_time
            print(f"\n{Color.GREEN}Scan abgeschlossen in {duration:.2f} Sekunden.{Color.RESET}")
            print(f"\n{Color.YELLOW}Gefundene Geräte: {len(devices_df)}{Color.RESET}")
            
            if not devices_df.empty:
                print("\nIP-Adresse\tMAC-Adresse\t\tHersteller\tHostname")
                print("-" * 80)
                
                for _, device in devices_df.iterrows():
                    ip = device.get('ip', 'N/A')
                    mac = device.get('mac', 'N/A')
                    vendor = device.get('vendor', 'N/A')
                    hostname = device.get('hostname', 'N/A')
                    
                    # Check if vendor is a string before trying to slice it
                    vendor_display = vendor
                    if isinstance(vendor, str) and len(vendor) > 15:
                        vendor_display = vendor[:15]
                    print(f"{ip}\t{mac}\t{vendor_display}\t{hostname}")
            
            self.scanning = False
            return devices_df
        
        except Exception as e:
            # Stoppe Fortschrittsanzeige im Fehlerfall
            try:
                stop_progress.set()
            except NameError:
                pass
            print("\r", end='', flush=True)  # Lösche Fortschrittsanzeige

            self.scanning = False
            logging.error(f"Fehler beim Netzwerk-Scan: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Scan: {str(e)}{Color.RESET}")
            return pd.DataFrame()
    
    def identify_devices(self, devices_df):
        """Führt eine detaillierte Geräteidentifikation durch"""
        try:
            if devices_df.empty:
                print(f"\n{Color.YELLOW}Keine Geräte für die Identifikation gefunden.{Color.RESET}")
                return
            
            print(f"\n{Color.GREEN}Starte detaillierte Geräteidentifikation...{Color.RESET}")
            start_time = time.time()
            
            # Erstelle eine Kopie des DataFrames für die Ergebnisse
            results_df = devices_df.copy()
            results_df['services'] = None
            results_df['os'] = None
            results_df['device_type'] = None
            results_df['open_ports'] = None  # Neue Spalte für offene Ports
            
            # Für jedes Gerät einen detaillierten Scan durchführen
            for idx, device in devices_df.iterrows():
                ip = device['ip']
                print(f"\n{Color.YELLOW}Identifiziere Gerät: {ip}{Color.RESET}")
                
                try:
                    # Führe einen Service-Scan durch
                    self.nm.scan(ip, arguments='-sV -O --script=banner')
                    
                    # Überprüfe, ob die IP in den Scan-Ergebnissen vorhanden ist
                    if ip not in self.nm.all_hosts():
                        raise Exception(f"Gerät {ip} konnte nicht gescannt werden. Möglicherweise ist es nicht erreichbar.")
                    
                    # Extrahiere Dienste
                    services = []
                    open_ports = []
                    if 'tcp' in self.nm[ip]:
                        for port, port_info in self.nm[ip]['tcp'].items():
                            if port_info['state'] == 'open':
                                open_ports.append(str(port))
                                service_info = f"{port}/tcp: {port_info['name']}"
                                if 'product' in port_info and port_info['product']:
                                    service_info += f" ({port_info['product']}"
                                    if 'version' in port_info and port_info['version']:
                                        service_info += f" {port_info['version']}"
                                    service_info += ")"
                                services.append(service_info)
                    
                    # Extrahiere OS-Informationen
                    os_info = 'Unbekannt'
                    if 'osmatch' in self.nm[ip] and len(self.nm[ip]['osmatch']) > 0:
                        os_match = self.nm[ip]['osmatch'][0]
                        os_info = f"{os_match['name']} ({os_match['accuracy']}%)"
                    
                    # Aktualisiere DataFrame
                    results_df.at[idx, 'services'] = '\n'.join(services) if services else 'Keine offenen Ports gefunden'
                    results_df.at[idx, 'open_ports'] = ', '.join(open_ports) if open_ports else ''
                    results_df.at[idx, 'os'] = os_info
                    
                    # Bestimme Gerätetyp basierend auf Diensten und OS
                    device_type = self._determine_device_type(services, os_info)
                    results_df.at[idx, 'device_type'] = device_type
                    
                    print(f"  {Color.GREEN}Identifikation abgeschlossen: {device_type}{Color.RESET}")
                    print(f"  {Color.BLUE}OS: {os_info}{Color.RESET}")
                    print(f"  {Color.BLUE}Dienste: {len(services)} gefunden{Color.RESET}")
                    
                    # Zeige offene Ports und Dienste an
                    if open_ports:
                        print(f"  {Color.BLUE}Offene Ports: {', '.join(open_ports)}{Color.RESET}")
                        print(f"  {Color.BLUE}Dienste:{Color.RESET}")
                        for service in services:
                            print(f"  {service}")
                
                except Exception as e:
                    logging.error(f"Fehler bei der Identifikation von {ip}: {str(e)}")
                    print(f"  {Color.RED}Fehler bei der Identifikation: {str(e)}{Color.RESET}")
                    # Setze Standardwerte für nicht identifizierte Geräte
                    results_df.at[idx, 'services'] = 'Keine Dienste identifiziert'
                    results_df.at[idx, 'open_ports'] = ''
                    results_df.at[idx, 'os'] = 'Unbekannt'
                    results_df.at[idx, 'device_type'] = 'Nicht identifiziert'
            
            # Speichere die Ergebnisse in der Datenbank
            self._update_device_info(results_df)
            
            duration = time.time() - start_time
            print(f"\n{Color.GREEN}Geräteidentifikation abgeschlossen in {duration:.2f} Sekunden.{Color.RESET}")
            
            return results_df
        
        except Exception as e:
            logging.error(f"Fehler bei der Geräteidentifikation: {str(e)}")
            print(f"\n{Color.RED}Fehler bei der Geräteidentifikation: {str(e)}{Color.RESET}")
            return devices_df
    
    def _check_metasploit_exploit(self, vulnerability_text):
        """Prüft, ob für eine Schwachstelle ein Metasploit-Exploit verfügbar ist"""
        # Liste von Schlüsselwörtern, die auf Metasploit-Exploits hinweisen
        metasploit_indicators = [
            'metasploit', 'msf', 'exploit/windows', 'exploit/unix', 'exploit/linux',
            'exploit/multi', 'auxiliary/', 'post/', 'payload/', 'encoder/', 'nop/',
            'evasion/', 'rapid7', 'framework'
        ]
        
        # Prüfe, ob einer der Indikatoren im Schwachstellentext vorkommt
        vulnerability_text_lower = vulnerability_text.lower()
        for indicator in metasploit_indicators:
            if indicator in vulnerability_text_lower:
                return True
        
        # Prüfe auf CVE-IDs und führe eine Abfrage durch, ob diese in Metasploit verfügbar sind
        # Dies ist eine vereinfachte Implementierung - in der Praxis würde man hier eine
        # Datenbank oder API abfragen, um zu prüfen, ob ein Exploit verfügbar ist
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_matches = re.findall(cve_pattern, vulnerability_text)
        
        if cve_matches:
            try:
                # Hier könnte man eine lokale Metasploit-Installation abfragen oder eine API nutzen
                # In dieser vereinfachten Version prüfen wir nur, ob die CVE-ID in einer Liste bekannter
                # Metasploit-Exploits vorkommt (diese Liste müsste regelmäßig aktualisiert werden)
                
                # Beispiel für eine vereinfachte Prüfung (in der Praxis würde man eine vollständige Liste verwenden)
                known_metasploit_cves = [
                    'CVE-2017-0144',  # EternalBlue
                    'CVE-2019-0708',  # BlueKeep
                    'CVE-2021-44228',  # Log4Shell
                    'CVE-2021-1675',  # PrintNightmare
                    'CVE-2021-34527',  # PrintNightmare (alternative ID)
                    'CVE-2021-40444',  # MSHTML
                    'CVE-2021-26084',  # Confluence
                    'CVE-2019-19781',  # Citrix
                    'CVE-2020-1472',   # Zerologon
                    'CVE-2021-21972',  # vCenter
                    'CVE-2021-26855',  # Exchange ProxyLogon
                    'CVE-2021-34473',  # Exchange ProxyShell
                    'CVE-2021-31207',  # Exchange ProxyShell
                    'CVE-2021-34523',  # Exchange ProxyShell
                    'CVE-2021-41773',  # Apache httpd
                    'CVE-2021-42013',  # Apache httpd
                    'CVE-2022-22963',  # Spring4Shell
                    'CVE-2022-22965',  # Spring4Shell
                    'CVE-2022-30190',  # Follina
                    'CVE-2022-26134',  # Confluence
                    'CVE-2022-26923',  # Active Directory
                    'CVE-2022-24521',  # Windows
                    'CVE-2022-21882',  # Windows
                    'CVE-2022-26925',  # Windows LSA
                    'CVE-2022-30075',  # TP-Link
                    'CVE-2022-1388',   # F5 BIG-IP
                ]
                
                for cve in cve_matches:
                    if cve in known_metasploit_cves:
                        return True
                        
            except Exception as e:
                logging.error(f"Fehler bei der Prüfung auf Metasploit-Exploits: {str(e)}")
        
        return False

    def scan_vulnerabilities(self, network_range: Optional[str] = None, config=None) -> Optional[pd.DataFrame]:
        """Führt eine Schwachstellenanalyse durch"""
        try:
            if not network_range and self.current_network:
                network_range = self.current_network
            elif not network_range:
                network_range = self.default_network

            print(f"\n{Color.GREEN}Starte Schwachstellenanalyse auf {network_range}...{Color.RESET}")

            # Führe zuerst einen Basis-Scan durch, um aktive Hosts zu identifizieren
            active_hosts = []
            vulnerabilities = {}
            metasploit_exploits = []
            try:
                result = subprocess.run(
                    ['nmap', '-sn', network_range],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    check=True
                )

                # Extrahiere IP-Adressen
                ip_pattern = r'Nmap scan report for ([\w.-]+)(?: \(([\d.]+)\))?'
                matches = re.findall(ip_pattern, result.stdout)

                for match in matches:
                    hostname, ip = match
                    if not ip:  # Wenn keine IP in Klammern, dann ist hostname die IP
                        ip = hostname
                    active_hosts.append(ip)

            except Exception as e:
                logging.error(f"Fehler beim Basis-Scan: {str(e)}")
                print(f"\n{Color.RED}Fehler beim Basis-Scan: {str(e)}{Color.RESET}")
                return None

            if not active_hosts:
                print(f"\n{Color.YELLOW}Keine aktiven Hosts gefunden.{Color.RESET}")
                return pd.DataFrame()

            # Führe Schwachstellenanalyse für jeden aktiven Host durch
            start_time = time.time()
            vuln_results = []
            total_vulns = 0
            total_metasploit_vulns = 0

            for host in active_hosts:
                print(f"\n{Color.YELLOW}Prüfe Schwachstellen für: {host}{Color.RESET}")

                try:
                    # Standard nmap Schwachstellenscan – Script-Set konfigurierbar,
                    # ssl-* standardmäßig ausgeschlossen (SIGABRT-Schutz)
                    host_timeout = str(self._get_cfg(config, 'SCAN', 'host_timeout', '')).strip()
                    script_expr = self._build_vuln_script_expr(config)
                    nmap_cmd = ['nmap', '-sV', '-T4', '--script', script_expr]
                    # Host-Timeout nur setzen, wenn konfiguriert. Ein zu kurzes Timeout
                    # bricht externe vulners-Lookups ab → es werden keine CVEs gefunden.
                    if host_timeout:
                        nmap_cmd.extend(['--host-timeout', host_timeout])

                    # Füge Vulners API-Key hinzu, wenn verfügbar
                    if hasattr(self, 'vulners_api_key') and self.vulners_api_key:
                        vulners_arg = f"vulners.apikey={self.vulners_api_key}"
                        logging.info(f"Verwende Vulners API-Key für Scan von {host}")
                        nmap_cmd.extend(['--script-args', vulners_arg])

                    # Füge Host hinzu
                    nmap_cmd.append(host)

                    # Mit Spinner ausführen; check=False, damit nmaps stderr bei einem
                    # Absturz (z.B. SIGABRT durch ein fehlerhaftes NSE-Skript) auswertbar ist
                    result = self._run_with_spinner(nmap_cmd, f'Scanne {host}')

                    # Negativer returncode = von Signal beendet (z.B. -6 = SIGABRT)
                    if result.returncode != 0:
                        stderr_text = self._mask_secrets((result.stderr or '').strip())
                        if result.returncode < 0:
                            import signal as _signal
                            try:
                                sig_name = _signal.Signals(-result.returncode).name
                            except (ValueError, AttributeError):
                                sig_name = str(-result.returncode)
                            reason = f"nmap wurde durch Signal {sig_name} beendet (Absturz)"
                        else:
                            reason = f"nmap endete mit Code {result.returncode}"
                        logging.error(f"{reason} für {host}. stderr: {stderr_text[:1000]}")
                        print(f"  {Color.RED}{reason} für {host}.{Color.RESET}")
                        if stderr_text:
                            print(f"  {Color.YELLOW}nmap-Meldung:{Color.RESET}\n  " +
                                  stderr_text[:1000].replace('\n', '\n  '))
                        print(f"  {Color.YELLOW}Tipp: Wahrscheinlich stürzt ein NSE-Skript ab. "
                              f"Teste manuell mit reduzierten Skripten, z.B.:{Color.RESET}")
                        print(f"  nmap -sV --script vuln {host}")
                        # Diesen Host überspringen, mit den nächsten weitermachen
                        continue

                    # Rohe nmap-Ausgabe zur Diagnose speichern (API-Key maskiert)
                    try:
                        os.makedirs('logs', exist_ok=True)
                        raw_path = os.path.join('logs', f'vuln_raw_{host}.txt')
                        with open(raw_path, 'w', encoding='utf-8') as rf:
                            rf.write(self._mask_secrets(result.stdout or ''))
                        logging.info(f"Rohe nmap-Ausgabe gespeichert: {raw_path}")
                    except Exception as raw_err:
                        logging.warning(f"Konnte rohe nmap-Ausgabe nicht speichern: {raw_err}")

                    # Führe zusätzlich Metasploit-Scan durch, wenn verfügbar
                    metasploit_results = None
                    if hasattr(self, 'metasploit_available') and self.metasploit_available:
                        # Metasploit-Scan wurde deaktiviert, aber wir rufen die Funktion trotzdem auf,
                        # um die Darstellung der Sicherheitslücken beizubehalten
                        metasploit_results = self.scan_vulnerabilities_with_metasploit(host)

                    # Verarbeite die Ergebnisse
                    host_info = {
                        'ip': host,
                        'vulnerabilities': [],
                        'metasploit_exploits': [],
                        'other_vulnerabilities': [],
                        'port_vulnerabilities': {}
                    }

                    # Initialisiere Vulnerabilities-Dictionary für diesen Host
                    vulnerabilities[host] = {}

                    # Verarbeite nmap-Ergebnisse
                    port_pattern = r'(\d+)/tcp\s+open\s+(\w+)\s*(.*)'
                    ports_found = re.findall(port_pattern, result.stdout)

                    # Verarbeite jeden Port
                    for port, service, _ in ports_found:
                        port_vulns = []
                        port_metasploit_vulns = []

                        # Den Ausgabeblock dieses Ports isolieren (bis zur nächsten
                        # Portzeile am Zeilenanfang bzw. Ende der Ausgabe)
                        port_section = re.search(
                            rf'{port}/tcp\s+open.*?(?=^\d+/tcp\s|\Z)',
                            result.stdout, re.DOTALL | re.MULTILINE)

                        if port_section:
                            port_text = port_section.group(0)

                            # 1) Jede CVE-Zeile einzeln (vulners-Format: CVE-ID  Score  URL)
                            cve_lines = re.findall(r'(CVE-\d{4}-\d{4,7}[^\n]*)', port_text)
                            # 2) Zeilen mit 'vulnerable' (case-insensitive) – erfasst auch
                            #    Treffer wie 'vulnerable to SWEET32 attack'
                            vulnerable_lines = re.findall(r'([^\n|]*vulnerable[^\n]*)', port_text, re.IGNORECASE)

                            # 3) Gezielte Schwäche-Muster aus ssl-enum-ciphers / ssl-cert
                            weakness_lines = []
                            grade = re.search(r'least strength:\s*([C-F])', port_text)
                            if grade:
                                weakness_lines.append(
                                    f"Schwache SSL/TLS-Cipher-Suiten (Gesamtbewertung: {grade.group(1)})")
                            for kb in re.findall(r'Public Key bits:\s*(\d+)', port_text):
                                if int(kb) < 2048:
                                    weakness_lines.append(f"Schwacher öffentlicher Schlüssel: {kb} Bit (< 2048)")
                            if re.search(r'Signature Algorithm:\s*\S*sha1', port_text, re.IGNORECASE) or \
                               re.search(r'Insecure certificate signature \(SHA1\)', port_text, re.IGNORECASE):
                                weakness_lines.append("Unsicheres Zertifikat: SHA1-Signatur")

                            # Nichtssagende Marker herausfiltern
                            noise = re.compile(
                                r'^(VULNERABLE:?|State:\s*(LIKELY\s+)?VULNERABLE\.?)$',
                                re.IGNORECASE)

                            seen = set()
                            for vuln in vulnerable_lines + weakness_lines + cve_lines:
                                vuln_info = vuln.strip(' |_').strip()
                                if not vuln_info or vuln_info in seen or noise.match(vuln_info):
                                    continue
                                seen.add(vuln_info)
                                host_info['vulnerabilities'].append(vuln_info)
                                port_vulns.append(vuln_info)

                                if self._check_metasploit_exploit(vuln_info):
                                    host_info['metasploit_exploits'].append(vuln_info)
                                    port_metasploit_vulns.append(vuln_info)
                                else:
                                    host_info['other_vulnerabilities'].append(vuln_info)

                        # Füge Metasploit-Ergebnisse hinzu, wenn vorhanden
                        if metasploit_results and metasploit_results.get("success"):
                            for vuln in metasploit_results.get("vulnerabilities", []):
                                if port in vuln:  # Wenn die Schwachstelle zu diesem Port gehört
                                    port_vulns.append(vuln)
                                    port_metasploit_vulns.append(vuln)
                                    host_info['vulnerabilities'].append(vuln)
                                    host_info['metasploit_exploits'].append(vuln)

                        if port_vulns:
                            host_info['port_vulnerabilities'][port] = {
                                'service': service,
                                'all_vulns': port_vulns,
                                'metasploit_vulns': port_metasploit_vulns
                            }

                            vulnerabilities[host][port] = {
                                'service': service,
                                'vulnerabilities': port_vulns,
                                'metasploit_exploits': port_metasploit_vulns
                            }

                    # Gezielter vulners-Retry: gleicht aus, dass der externe
                    # vulners-Dienst beim Hauptscan mal nicht alle Ports beantwortet
                    open_ports = [p for p, _, _ in ports_found]
                    port_services = {p: s for p, s, _ in ports_found}
                    retry_cves = self._vulners_retry(host, open_ports, config)
                    for port, cves in retry_cves.items():
                        existing = set(vulnerabilities[host].get(port, {}).get('vulnerabilities', []))
                        new_cves = [c for c in cves if c not in existing]
                        if not new_cves:
                            continue
                        if port not in vulnerabilities[host]:
                            svc = port_services.get(port, 'unbekannt')
                            vulnerabilities[host][port] = {
                                'service': svc, 'vulnerabilities': [], 'metasploit_exploits': []}
                            host_info['port_vulnerabilities'][port] = {
                                'service': svc, 'all_vulns': [], 'metasploit_vulns': []}
                        for c in new_cves:
                            vulnerabilities[host][port]['vulnerabilities'].append(c)
                            host_info['port_vulnerabilities'][port]['all_vulns'].append(c)
                            host_info['vulnerabilities'].append(c)
                            host_info['other_vulnerabilities'].append(c)
                        logging.info(f"vulners-Retry ergänzte {len(new_cves)} CVE(s) auf Port {port} ({host})")

                    if host_info['vulnerabilities']:
                        vuln_results.append(host_info)
                        metasploit_count = len(host_info['metasploit_exploits'])
                        other_count = len(host_info['other_vulnerabilities'])
                        print(f"  {Color.RED}Schwachstellen gefunden: {len(host_info['vulnerabilities'])}{Color.RESET}")
                        if metasploit_count > 0:
                            print(f"  {Color.RED}Davon mit speziellen Exploits: {metasploit_count}{Color.RESET}")

                        total_vulns += len(host_info['vulnerabilities'])
                        total_metasploit_vulns += metasploit_count
                    else:
                        print(f"  {Color.GREEN}Keine Schwachstellen gefunden.{Color.RESET}")

                    # Aktualisiere Schwachstelleninformationen für diesen Host
                    if host in vulnerabilities:
                        self._update_vulnerability_info(host, vulnerabilities[host], host_info.get('metasploit_exploits', []))

                except Exception as e:
                    logging.error(f"Fehler bei der Schwachstellenanalyse für {host}: {str(e)}")
                    print(f"  {Color.RED}Fehler bei der Schwachstellenanalyse für {host}: {str(e)}{Color.RESET}")
            
            # Erstelle DataFrame und zeige Ergebnisse
            vuln_df = pd.DataFrame(vuln_results)
            duration = time.time() - start_time

            print(f"\n{Color.GREEN}Schwachstellenanalyse abgeschlossen in {duration:.2f} Sekunden.{Color.RESET}")
            print(f"\n{Color.YELLOW}Geräte mit Schwachstellen: {len(vuln_df)}{Color.RESET}")

            if not vuln_df.empty:
                self._display_vulnerability_summary(vulnerabilities, total_vulns, total_metasploit_vulns)

            return vuln_df

        except Exception as e:
            logging.error(f"Fehler bei der Schwachstellenanalyse: {str(e)}")
            print(f"\n{Color.RED}Fehler bei der Schwachstellenanalyse: {str(e)}{Color.RESET}")
            return pd.DataFrame()
    
    def _extract_metasploit_info(self, vuln_info):
        """Extrahiert relevante Metasploit-Informationen aus einer Schwachstellenbeschreibung"""
        try:
            # Prüfe, ob vuln_info ein String ist
            if not isinstance(vuln_info, str):
                logging.warning(f"Ungültiges Format für Metasploit-Info: {type(vuln_info)}")
                return "Metasploit-Exploit verfügbar (Ungültiges Format)"
                
            # Suche nach Metasploit-Modulpfaden
            metasploit_patterns = [
                r'(exploit/[\w/]+)',
                r'(auxiliary/[\w/]+)',
                r'(post/[\w/]+)',
                r'(payload/[\w/]+)',
                r'(encoder/[\w/]+)',
                r'(nop/[\w/]+)',
                r'(evasion/[\w/]+)'
            ]
            
            metasploit_info = []
            
            # Extrahiere Port und Service
            port_match = re.search(r'Port (\d+) \(([^)]+)\)', vuln_info)
            if port_match:
                try:
                    port, service = port_match.groups()
                    metasploit_info.append(f"Port {port} ({service})")
                except Exception as e:
                    logging.warning(f"Fehler beim Extrahieren von Port und Service: {str(e)}")
                    # Füge einen Standardeintrag hinzu, wenn die Extraktion fehlschlägt
                    metasploit_info.append("Port: Unbekannt")
            else:
                # Versuche, den Port direkt zu extrahieren, falls er im Text vorkommt
                port_direct = re.search(r'\b(\d+)\b', vuln_info)
                if port_direct:
                    try:
                        port = port_direct.group(1)
                        metasploit_info.append(f"Port {port}")
                    except Exception:
                        metasploit_info.append("Port: Unbekannt")
                else:
                    metasploit_info.append("Port: Unbekannt")
            
            # Extrahiere CVE-IDs
            cve_matches = re.findall(r'(CVE-\d{4}-\d{4,7})', vuln_info)
            if cve_matches:
                metasploit_info.append(f"CVE: {', '.join(cve_matches)}")
            
            # Suche nach Metasploit-Modulpfaden
            metasploit_modules_found = False
            for pattern in metasploit_patterns:
                matches = re.findall(pattern, vuln_info)
                for match in matches:
                    metasploit_info.append(f"Metasploit: {match}")
                    metasploit_modules_found = True
            
            # Wenn keine spezifischen Metasploit-Informationen gefunden wurden
            if not metasploit_modules_found:
                metasploit_info.append("Metasploit-Exploit verfügbar (Details nicht extrahiert)")
            
            return "\n".join(metasploit_info)
        except Exception as e:
            logging.error(f"Fehler beim Extrahieren der Metasploit-Informationen: {str(e)}")
            return "Metasploit-Exploit verfügbar (Fehler bei der Extraktion)"

    def scan_vulnerabilities_with_metasploit(self, ip: str) -> Dict[str, Any]:
        """Führt einen Schwachstellenscan mit Metasploit durch"""
        try:
            # Prüfe, ob Metasploit verfügbar ist
            if not self.metasploit_available:
                return {
                    "success": False,
                    "error": "Metasploit ist nicht installiert oder nicht im PATH",
                    "vulnerabilities": []
                }
            
            # Erstelle temporäre Datei für das Metasploit-Skript
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.rc', delete=False) as temp_file:
                # Schreibe Befehle in die Datei
                temp_file.write(f"db_nmap -sV {ip}\n")
                temp_file.write("vulns\n")  # Zeige gefundene Schwachstellen an
                temp_file.write("exit\n")
                temp_file_path = temp_file.name
            
            # Führe Metasploit mit dem Skript aus
            try:
                # Versuche zuerst, msfconsole im PATH zu finden
                result = subprocess.run(
                    ['msfconsole', '-q', '-r', temp_file_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    check=False
                )
            except FileNotFoundError:
                # Versuche alternative Pfade
                common_paths = [
                    '/usr/bin/msfconsole',
                    '/usr/share/metasploit-framework/msfconsole',
                    '/opt/metasploit-framework/bin/msfconsole',
                    '/opt/metasploit/msfconsole'
                ]
                
                for path in common_paths:
                    if os.path.exists(path):
                        result = subprocess.run(
                            [path, '-q', '-r', temp_file_path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL,
                            text=True,
                            check=False
                        )
                        break
                else:
                    # Wenn kein Pfad gefunden wurde
                    return {
                        "success": False,
                        "error": "Metasploit konnte nicht ausgeführt werden",
                        "vulnerabilities": []
                    }
            
            # Lösche die temporäre Datei
            os.unlink(temp_file_path)
            
            # Verarbeite die Ausgabe
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr,
                    "vulnerabilities": []
                }
            
            # Extrahiere Schwachstellen aus der Ausgabe
            vulnerabilities = []
            vuln_pattern = r'(CVE-\d{4}-\d{4,7}).*?\s+(\d+\.\d+)\s+([^\n]+)'
            vuln_matches = re.findall(vuln_pattern, result.stdout, re.DOTALL)
            
            for cve, score, description in vuln_matches:
                vuln_info = f"{cve} (Score: {score}): {description}"
                vulnerabilities.append(vuln_info)
            
            return {
                "success": True,
                "raw_output": result.stdout,
                "vulnerabilities": vulnerabilities
            }
        
        except Exception as e:
            logging.error(f"Fehler beim Metasploit-Scan: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "vulnerabilities": []
            }

    def _display_vulnerability_summary(self, vulnerabilities: Dict, total_vulns: int,
                                       total_metasploit_vulns: int) -> None:
        """Zeigt eine Zusammenfassung der gefundenen Schwachstellen an"""
        print(f"\nSchwachstellen gefunden: {total_vulns}")
        print(f"Davon mit speziellen Exploits: {total_metasploit_vulns}")

        all_metasploit_exploits = []

        for ip, ports in vulnerabilities.items():
            print(f"\n{Color.RED}Schwachstellen für {ip}:{Color.RESET}")

            for port, port_info in ports.items():
                service = port_info.get('service', 'unbekannt')
                all_vulns = port_info.get('vulnerabilities', [])
                metasploit_vulns = port_info.get('metasploit_exploits', [])

                if all_vulns:
                    print(f"\n{Color.YELLOW}=== Port {port} ({service}) ==={Color.RESET}")

                    for vuln in all_vulns:
                        print(f"\n{vuln}")

                    if metasploit_vulns:
                        for vuln in metasploit_vulns:
                            try:
                                metasploit_info = self._extract_metasploit_info(vuln)
                                all_metasploit_exploits.append(f"{ip}:{port} ({service}) - {metasploit_info}")
                            except Exception as e:
                                logging.error(f"Fehler beim Extrahieren der Metasploit-Informationen: {str(e)}")
                                all_metasploit_exploits.append(
                                    f"{ip}:{port} ({service}) - Metasploit-Exploit verfügbar (Fehler bei der Extraktion der Details)")

        # Zeige separate Metasploit-Übersicht
        if all_metasploit_exploits:
            print(f"\n\n{Color.RED}{'=' * 30}{Color.RESET}")
            print(f"{Color.RED}SICHERHEITSLÜCKEN ÜBERSICHT{Color.RESET}")
            print(f"{Color.RED}{'=' * 30}{Color.RESET}\n")

            for exploit in all_metasploit_exploits:
                print(f"{Color.YELLOW}{exploit}{Color.RESET}\n")

    def _save_scan_results(self, devices_df, network_range, start_time):
        """Speichert die Scan-Ergebnisse in der Datenbank"""
        try:
            conn = sqlite3.connect(self.db_name)

            # Speichere Geräte-Informationen
            if not devices_df.empty:
                # Füge Zeitstempel hinzu
                devices_df['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Speichere in der Datenbank
                for _, device in devices_df.iterrows():
                    # Prüfe, ob das Gerät bereits existiert
                    c = conn.cursor()
                    c.execute("SELECT * FROM devices WHERE ip=?", (device['ip'],))
                    existing_device = c.fetchone()

                    if existing_device:
                        # Aktualisiere vorhandenes Gerät
                        update_fields = []
                        update_values = []

                        for col in devices_df.columns:
                            if col != 'ip' and col in device and not pd.isna(device[col]):
                                update_fields.append(f"{col}=?")
                                update_values.append(device[col])

                        if update_fields:
                            update_sql = f"UPDATE devices SET {', '.join(update_fields)} WHERE ip=?"
                            update_values.append(device['ip'])
                            c.execute(update_sql, update_values)
                    else:
                        # Füge neues Gerät hinzu
                        insert_cols = ['ip']
                        insert_vals = [device['ip']]

                        for col in devices_df.columns:
                            if col != 'ip' and col in device and not pd.isna(device[col]):
                                insert_cols.append(col)
                                insert_vals.append(device[col])

                        placeholders = ['?'] * len(insert_cols)
                        insert_sql = f"INSERT INTO devices ({', '.join(insert_cols)}) VALUES ({', '.join(placeholders)})"
                        c.execute(insert_sql, insert_vals)

                # Speichere Scan-Historie
                duration = time.time() - start_time
                c = conn.cursor()
                c.execute("""
                INSERT INTO scan_history (
                    scan_date, scan_type, network_range, devices_found,
                    duration, status, vulnerabilities_found, metasploit_exploits_found
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'discovery',
                    network_range,
                    len(devices_df),
                    duration,
                    'completed',
                    0,  # vulnerabilities_found wird später aktualisiert
                    0  # metasploit_exploits_found wird später aktualisiert
                ))

                conn.commit()
                conn.close()

                logging.info(f"Scan-Ergebnisse gespeichert: {len(devices_df)} Geräte")

        except Exception as e:
            logging.error(f"Fehler beim Speichern der Scan-Ergebnisse: {str(e)}")
    
    def _update_device_info(self, devices_df):
        """Aktualisiert die Geräteinformationen in der Datenbank"""
        try:
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            
            for _, device in devices_df.iterrows():
                if 'ip' in device:
                    # Prüfe, ob das Gerät bereits existiert
                    c.execute("SELECT * FROM devices WHERE ip=?", (device['ip'],))
                    existing_device = c.fetchone()
                    
                    if existing_device:
                        # Aktualisiere vorhandenes Gerät
                        update_fields = []
                        update_values = []
                        
                        for col in ['services', 'os', 'device_type', 'open_ports']:
                            if col in device and not pd.isna(device[col]):
                                update_fields.append(f"{col}=?")
                                update_values.append(device[col])
                        
                        if update_fields:
                            update_sql = f"UPDATE devices SET {', '.join(update_fields)} WHERE ip=?"
                            update_values.append(device['ip'])
                            c.execute(update_sql, update_values)
            
            conn.commit()
            conn.close()
            
            logging.info(f"Geräteinformationen aktualisiert: {len(devices_df)} Geräte")
        
        except Exception as e:
            logging.error(f"Fehler beim Aktualisieren der Geräteinformationen: {str(e)}")

    def update_metasploit_exploits(self, ip, exploits):
        """Speichert gefundene Metasploit-Exploits für ein Gerät in der Datenbank"""
        import json
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            c.execute("UPDATE devices SET metasploit_exploits = ? WHERE ip = ?",
                      (json.dumps(exploits), ip))
            conn.commit()

    def _update_vulnerability_info(self, ip, vulnerabilities, metasploit_exploits=None):
        try:
            import json
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            
            # Konvertiere zu JSON-Strings mit besserer Fehlerbehandlung
            try:
                if vulnerabilities:
                    # Stelle sicher, dass die Daten JSON-serialisierbar sind
                    clean_vulnerabilities = {}
                    for port, port_info in vulnerabilities.items():
                        clean_port_info = {}
                        for key, value in port_info.items():
                            if isinstance(value, (str, int, float, bool, list, dict, type(None))):
                                clean_port_info[key] = value
                            else:
                                clean_port_info[key] = str(value)
                        clean_vulnerabilities[port] = clean_port_info
                    vuln_json = json.dumps(clean_vulnerabilities)
                else:
                    vuln_json = None
            except Exception as e:
                logging.error(f"Fehler beim Konvertieren der Schwachstelleninformationen zu JSON: {str(e)}")
                # Fallback: Speichere als String
                if isinstance(vulnerabilities, dict):
                    vuln_json = str(vulnerabilities)
                else:
                    vuln_json = None
            
            try:
                if metasploit_exploits:
                    # Stelle sicher, dass die Daten JSON-serialisierbar sind
                    clean_exploits = []
                    for exploit in metasploit_exploits:
                        if isinstance(exploit, (str, int, float, bool)):
                            clean_exploits.append(exploit)
                        else:
                            clean_exploits.append(str(exploit))
                    metasploit_json = json.dumps(clean_exploits)
                else:
                    metasploit_json = None
            except Exception as e:
                logging.error(f"Fehler beim Konvertieren der Metasploit-Exploits zu JSON: {str(e)}")
                # Fallback: Speichere als String
                if isinstance(metasploit_exploits, list):
                    metasploit_json = str(metasploit_exploits)
                else:
                    metasploit_json = None
            
            # Aktualisiere die Haupttabelle
            c.execute("""
                UPDATE devices
                SET vulnerabilities = ?,
                    metasploit_exploits = ?,
                    last_seen = CURRENT_TIMESTAMP
                WHERE ip = ?
            """, (vuln_json, metasploit_json, ip))
            
            # Füge detaillierte Einträge hinzu
            if isinstance(vulnerabilities, dict):
                for port, port_info in vulnerabilities.items():
                    if isinstance(port_info, dict) and 'vulnerabilities' in port_info:
                        for vuln in port_info['vulnerabilities']:
                            if isinstance(vuln, str):
                                # Einfache Speicherung als String
                                c.execute("""
                                    INSERT INTO vulnerability_details (device_ip, port, description)  
                                    VALUES (?, ?, ?)
                                """, (ip, port, vuln))
            
            conn.commit()
            logging.info(f"Schwachstelleninformationen aktualisiert für {ip}")
            conn.close()
        except Exception as e:
            logging.error(f"Fehler beim Aktualisieren der Schwachstelleninformationen: {str(e)}")
    
    def _determine_device_type(self, services, os_info):
        """Bestimmt den Gerätetyp basierend auf Diensten und OS"""
        # Einfache Heuristik für die Gerätetyp-Bestimmung
        device_type = 'Unbekannt'
        
        # Prüfe auf typische IoT-Dienste und Betriebssysteme
        services_text = '\n'.join(services).lower() if services else ''
        os_lower = os_info.lower()
        
        # Router/Gateway
        if any(s in services_text for s in ['FRITZ''AVM','avm','router', 'gateway', 'dhcp', 'dns']) or \
           any(s in os_lower for s in ['router', 'gateway', 'mikrotik', 'cisco', 'juniper', 'avm', 'tp-link']):
            device_type = 'Router/Gateway'
        
        # Kamera
        elif any(s in services_text for s in ['rtsp', 'onvif', 'camera', 'webcam', 'ipcam']) or \
             any(s in os_lower for s in ['camera', 'webcam', 'hikvision', 'dahua']):
            device_type = 'IP-Kamera'
        
        # Smart TV
        elif any(s in services_text for s in ['dlna', 'upnp', 'ssdp', 'hbbtv', 'smart tv']) or \
             any(s in os_lower for s in ['samsung''smart tv', 'webos', 'tizen', 'android tv']):
            device_type = 'Smart TV'
        
        # Thermostat/Klimaanlage
        elif any(s in services_text for s in ['thermostat', 'hvac', 'climate']) or \
             any(s in os_lower for s in ['thermostat', 'nest', 'ecobee']):
            device_type = 'Thermostat/Klimaanlage'
        
        # Drucker
        elif any(s in services_text for s in ['printer', 'ipp', 'cups', 'jetdirect']) or \
             any(s in os_lower for s in ['printer', 'hp', 'epson', 'canon']):
            device_type = 'Drucker'
        
        # NAS
        elif any(s in services_text for s in ['nas', 'smb', 'cifs', 'nfs', 'afp']) or \
             any(s in os_lower for s in ['nas', 'synology', 'qnap', 'freenas']):
            device_type = 'NAS'
        
        # Smart Speaker
        elif any(s in services_text for s in ['speaker', 'sonos', 'alexa', 'google home']) or \
             any(s in os_lower for s in ['speaker', 'sonos', 'alexa', 'google home']):
            device_type = 'Smart Speaker'
        
        # Allgemeine Kategorien
        elif 'linux' in os_lower:
            device_type = 'Linux-Gerät'
        elif 'windows' in os_lower:
            device_type = 'Windows-Gerät'
        elif 'mac' in os_lower or 'apple' in os_lower:
            device_type = 'Apple-Gerät'
        elif 'android' in os_lower:
            device_type = 'Android-Gerät'
        
        return device_type