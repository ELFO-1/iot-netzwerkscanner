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
                
            print(f"\n{Color.GREEN}Starte {scan_name} auf {target}...{Color.RESET}")
            print(f"{Color.BLUE}Verwendete Nmap-Optionen: {nmap_options}{Color.RESET}\n")
            
            # Erstelle den Nmap-Befehl
            cmd = f"nmap {nmap_options} {target}"
            
            # Führe den Nmap-Befehl aus
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True
            )
            
            # Lese die Ausgabe
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
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