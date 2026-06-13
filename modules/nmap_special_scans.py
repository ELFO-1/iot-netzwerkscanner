#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Spezielle Nmap-Scans für den IoT Netzwerkscanner
Author: ELFO
Version: 4.0
"""

import os
import subprocess
import logging
import uuid
import re
import pandas as pd
from datetime import datetime
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from .utils import Color

class NmapSpecialScans:
    """Klasse für spezielle Nmap-Scans mit erweiterter Funktionalität für Pentesting"""
    
    def __init__(self, db_name: str = "scanner.db"):
        """Initialisiert die Nmap-Scans-Klasse"""
        self.db_name = db_name
        self.nmap_available = self._check_nmap_available()
        self.scan_profiles = self._load_scan_profiles()
        # -Pn ("Host-Discovery überspringen") für Spezial-Scans erzwingen, wenn
        # Ziele Ping blocken. Standard aus [SCAN] use_pn, zur Laufzeit per
        # Abfrage für die restliche Sitzung aktivierbar.
        self.use_pn = self._load_use_pn_setting()

    def _load_use_pn_setting(self) -> bool:
        """Liest den Standardwert für -Pn aus [SCAN] use_pn der iot_config2.ini"""
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read('iot_config2.ini')
            if 'SCAN' in config and 'use_pn' in config['SCAN']:
                return str(config['SCAN']['use_pn']).strip().lower() in ('true', '1', 'yes', 'ja')
        except Exception as e:
            logging.warning(f"Konnte [SCAN] use_pn nicht lesen: {str(e)}")
        return False

    def _inject_pn(self, options: str) -> str:
        """Ergänzt -Pn in einem nmap-Options-String, wenn self.use_pn aktiv ist"""
        if self.use_pn and '-Pn' not in options.split():
            return f"-Pn {options}".strip()
        return options

    def _ask_enable_pn(self, context: str = '') -> bool:
        """Fragt interaktiv, ob mit -Pn erneut gescannt werden soll.

        Bei Bestätigung wird self.use_pn für die restliche Sitzung aktiviert.
        Gibt True zurück, wenn -Pn (neu) aktiviert wurde.
        """
        if self.use_pn:
            return False
        msg = context or "Keine Hosts erreichbar – evtl. blockt das Netz ICMP-/ARP-Ping."
        print(f"\n{Color.YELLOW}{msg}{Color.RESET}")
        try:
            answer = input(
                f"{Color.YELLOW}Erneut mit -Pn versuchen (Host-Discovery "
                f"überspringen)? [j/N]: {Color.RESET}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if answer in ('j', 'ja', 'y', 'yes'):
            self.use_pn = True
            print(f"{Color.GREEN}-Pn ist jetzt für die restliche Sitzung aktiv.{Color.RESET}")
            return True
        return False

    def _check_nmap_available(self) -> bool:
        """Überprüft, ob Nmap verfügbar ist"""
        try:
            result = subprocess.run(
                ['which', 'nmap'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                logging.info("Nmap wurde gefunden und ist verfügbar")
                return True
            else:
                logging.warning("Nmap wurde nicht gefunden. Bitte installieren Sie Nmap.")
                print(f"{Color.RED}WARNUNG: Nmap wurde nicht gefunden. Bitte installieren Sie Nmap.{Color.RESET}")
                return False
        except Exception as e:
            logging.error(f"Fehler beim Überprüfen von Nmap: {str(e)}")
            return False
    
    def _load_scan_profiles(self) -> Dict[str, Dict[str, str]]:
        """Lädt vordefinierte Scan-Profile"""
        return {
            "quick": {
                "name": "Schneller Portscan",
                "description": "Scannt die Top 100 Ports (schnell)",
                "args": "-F -T4"
            },
            "full": {
                "name": "Vollständiger Portscan",
                "description": "Scannt alle 65535 Ports (langsam)",
                "args": "-p- -T4"
            },
            "service": {
                "name": "Service-Erkennung",
                "description": "Identifiziert Dienste auf offenen Ports",
                "args": "-sV -T4"
            },
            "os": {
                "name": "OS-Erkennung",
                "description": "Versucht, das Betriebssystem zu erkennen",
                "args": "-O -T4"
            },
            "aggressive": {
                "name": "Aggressive Scan",
                "description": "Kombiniert Service-, OS- und Script-Scans",
                "args": "-A -T4"
            },
            "vuln": {
                "name": "Schwachstellenscan",
                "description": "Sucht nach bekannten Schwachstellen",
                "args": "-sV --script vuln -T4"
            },
            "stealth": {
                "name": "Stealth Scan",
                "description": "SYN-Scan für verdeckte Erkennung",
                "args": "-sS -T2"
            },
            "udp": {
                "name": "UDP Scan",
                "description": "Scannt UDP-Ports (langsam)",
                "args": "-sU --top-ports 100"
            },
            "webserver": {
                "name": "Webserver Scan",
                "description": "Detaillierte Analyse von Webservern",
                "args": "-p 80,443,8080,8443 --script http-enum,http-headers,http-methods,http-auth"
            },
            "smb": {
                "name": "SMB/Windows Scan",
                "description": "Prüft Windows/SMB auf Schwachstellen",
                "args": "-p 139,445 --script smb-vuln*,smb-enum*"
            },
            "ssh": {
                "name": "SSH Scan",
                "description": "Prüft SSH-Server auf Schwachstellen",
                "args": "-p 22 --script ssh-auth-methods,ssh-hostkey,ssh-brute"
            },
            "ssl": {
                "name": "SSL/TLS Scan",
                "description": "Prüft SSL/TLS-Konfiguration",
                "args": "-p 443,8443 --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle"
            },
            "firewall": {
                "name": "Firewall Evasion",
                "description": "Versucht, Firewalls zu umgehen",
                "args": "-f -D RND:5 --data-length 24 -T2"
            }
        }
    
    def run_special_scan(self, scan_name: str, target: str, nmap_options: str) -> Dict[str, Any]:
        """Führt einen speziellen Nmap-Scan mit den angegebenen Optionen durch"""
        try:
            if not self.nmap_available:
                return {
                    "success": False,
                    "error": "Nmap ist nicht installiert oder nicht im PATH"
                }
                
            def _run(options: str):
                """Führt nmap mit den gegebenen Optionen aus → (returncode, stdout, stderr)"""
                options = self._inject_pn(options)
                cmd = f"nmap {options} {target}"
                print(f"\n{Color.GREEN}Starte {scan_name} auf {target}...{Color.RESET}")
                print(f"{Color.BLUE}Verwendete Nmap-Optionen: {options}{Color.RESET}\n")
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True
                )
                stdout, stderr = process.communicate()
                return process.returncode, stdout, stderr

            returncode, stdout, stderr = _run(nmap_options)

            if returncode != 0:
                print(f"{Color.RED}Fehler beim Ausführen des Scans: {stderr}{Color.RESET}")
                return {
                    "success": False,
                    "error": stderr
                }

            # nmap endet mit Code 0, auch wenn der Host Ping blockt ("Host seems
            # down ... try -Pn"). In dem Fall -Pn anbieten und einmal wiederholen.
            blocked = ('seems down' in stdout or '0 hosts up' in stdout)
            if blocked and self._ask_enable_pn(
                    f"{target} antwortet nicht auf Ping – möglicherweise wird Ping geblockt."):
                print(f"\n{Color.GREEN}Wiederhole {scan_name} mit -Pn...{Color.RESET}")
                returncode, stdout, stderr = _run(nmap_options)
                if returncode != 0:
                    print(f"{Color.RED}Fehler beim Ausführen des Scans: {stderr}{Color.RESET}")
                    return {
                        "success": False,
                        "error": stderr
                    }

            # Speichere die Ergebnisse in der Datenbank
            scan_id = str(uuid.uuid4())
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            try:
                with sqlite3.connect(self.db_name) as conn:
                    c = conn.cursor()
                    c.execute(
                        "INSERT INTO scan_history (scan_date, scan_type, network_range, devices_found, duration, status, results) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (timestamp, scan_name, target, 1, 0.0, "completed", stdout)
                    )
            except Exception as db_err:
                logging.error(f"Fehler beim Speichern der Scan-Ergebnisse: {str(db_err)}")
            
            # Formatierte Ausgabe der Ergebnisse
            self._display_formatted_results(stdout, scan_name)
            
            return {
                "success": True,
                "output": stdout,
                "scan_id": scan_id
            }
            
        except Exception as e:
            logging.error(f"Fehler beim speziellen Nmap-Scan: {str(e)}")
            print(f"{Color.RED}Fehler beim Scan: {str(e)}{Color.RESET}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _display_formatted_results(self, output: str, scan_name: str) -> None:
        """Zeigt formatierte Scan-Ergebnisse an"""
        # Extrahiere wichtige Informationen aus der Nmap-Ausgabe
        host_sections = re.split(r'Nmap scan report for ', output)[1:]
        
        if not host_sections:
            print(f"{Color.YELLOW}Keine Ergebnisse gefunden.{Color.RESET}")
            return
        
        print(f"\n{Color.GREEN}=== {scan_name} Ergebnisse ==={Color.RESET}")
        
        for section in host_sections:
            try:
                # Extrahiere Host-Informationen
                host_line = section.split('\n')[0].strip()
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_line)
                ip = ip_match.group(1) if ip_match else host_line
                
                print(f"\n{Color.YELLOW}Host: {ip}{Color.RESET}")
                
                # Extrahiere offene Ports
                port_lines = re.findall(r'(\d+/\w+)\s+(open|filtered|closed)\s+([^\n]+)', section)
                
                if port_lines:
                    print(f"{Color.BLUE}Offene Ports:{Color.RESET}")
                    for port_info in port_lines:
                        port, state, service = port_info
                        if state == 'open':
                            print(f"  {Color.GREEN}{port:10} {service.strip()}{Color.RESET}")
                        elif state == 'filtered':
                            print(f"  {Color.YELLOW}{port:10} {service.strip()} (gefiltert){Color.RESET}")
                        else:
                            print(f"  {port:10} {service.strip()}")
                
                # Extrahiere OS-Informationen, wenn vorhanden
                os_match = re.search(r'OS details: ([^\n]+)', section)
                if os_match:
                    print(f"{Color.BLUE}Betriebssystem: {Color.GREEN}{os_match.group(1)}{Color.RESET}")
                
                # Extrahiere Schwachstellen, wenn vorhanden
                vuln_matches = re.findall(r'(VULNERABLE|CVE-\d+-\d+)[^\n]+', section, re.IGNORECASE)
                if vuln_matches:
                    print(f"{Color.RED}Gefundene Schwachstellen:{Color.RESET}")
                    for vuln in vuln_matches:
                        print(f"  {Color.RED}{vuln}{Color.RESET}")
            
            except Exception as e:
                logging.error(f"Fehler bei der Anzeige der Ergebnisse: {str(e)}")
                continue
    
    def parse_scan_results(self, output: str) -> pd.DataFrame:
        """Parst die Scan-Ergebnisse in ein DataFrame"""
        try:
            hosts_list = []
            host_sections = re.split(r'Nmap scan report for ', output)[1:]
            
            for section in host_sections:
                try:
                    # Extrahiere Host-Informationen
                    host_line = section.split('\n')[0].strip()
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_line)
                    ip = ip_match.group(1) if ip_match else host_line
                    
                    # Extrahiere Port-Informationen
                    port_info = {}
                    port_lines = re.findall(r'(\d+/\w+)\s+(open|filtered|closed)\s+([^\n]+)', section)
                    
                    for port_data in port_lines:
                        port, state, service = port_data
                        port_num = port.split('/')[0]
                        port_info[port_num] = {
                            'state': state,
                            'service': service.strip()
                        }
                    
                    # Füge Host zu Liste hinzu
                    hosts_list.append({
                        'ip': ip,
                        'ports': port_info,
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
                except Exception as e:
                    logging.error(f"Fehler beim Parsen der Host-Informationen: {str(e)}")
                    continue
            
            # Erstelle DataFrame aus der Host-Liste
            if hosts_list:
                return pd.DataFrame(hosts_list)
            else:
                return pd.DataFrame(columns=['ip', 'ports', 'timestamp'])
        
        except Exception as e:
            logging.error(f"Fehler beim Parsen der Scan-Ergebnisse: {str(e)}")
            return pd.DataFrame(columns=['ip', 'ports', 'timestamp'])
            
    def quick_port_scan(self, target: str) -> Dict[str, Any]:
        """Führt einen schnellen Portscan durch"""
        return self.run_special_scan(
            "Schneller Portscan", 
            target, 
            self.scan_profiles["quick"]["args"]
        )
    
    def full_port_scan(self, target: str) -> Dict[str, Any]:
        """Führt einen vollständigen Portscan durch"""
        return self.run_special_scan(
            "Vollständiger Portscan", 
            target, 
            self.scan_profiles["full"]["args"]
        )
    
    def service_detection_scan(self, target: str) -> Dict[str, Any]:
        """Führt einen Service-Erkennungsscan durch"""
        return self.run_special_scan(
            "Service-Erkennung", 
            target, 
            self.scan_profiles["service"]["args"]
        )
    
    def os_detection_scan(self, target: str) -> Dict[str, Any]:
        """Führt einen Betriebssystem-Erkennungsscan durch"""
        return self.run_special_scan(
            "OS-Erkennung", 
            target, 
            self.scan_profiles["os"]["args"]
        )
    
    def aggressive_scan(self, target: str) -> Dict[str, Any]:
        """Führt einen aggressiven Scan durch"""
        return self.run_special_scan(
            "Aggressiver Scan", 
            target, 
            self.scan_profiles["aggressive"]["args"]
        )
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Führt einen Schwachstellenscan durch"""
        return self.run_special_scan(
            "Schwachstellenscan", 
            target, 
            self.scan_profiles["vuln"]["args"]
        )