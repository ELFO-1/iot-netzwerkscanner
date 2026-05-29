#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit-Integration für den IoT Netzwerkscanner
Author: ELFO
Version: 4.0
"""

import os
import tempfile
import subprocess
import logging
import re
import json
from typing import Dict, Any, List, Optional, Tuple
from .utils import Color

class MetasploitIntegration:
    """Klasse für die Integration von Metasploit in den Scanner"""
    
    def __init__(self, metasploit_path: str = None):
        """Initialisiert die Metasploit-Integration
        
        Args:
            metasploit_path: Optionaler Pfad zur Metasploit-Installation
        """
        self.metasploit_path = metasploit_path
        self.metasploit_available, self.msfconsole_path = self._check_metasploit_available()
        self.msf_db_status = self._check_msf_db_status() if self.metasploit_available else False
    
    def _check_metasploit_available(self) -> Tuple[bool, Optional[str]]:
        """Überprüft, ob Metasploit verfügbar ist und gibt den Pfad zurück"""
        try:
            # Wenn ein Pfad angegeben wurde, prüfe diesen zuerst
            if self.metasploit_path:
                msfconsole_path = os.path.join(self.metasploit_path, 'msfconsole')
                if os.path.exists(msfconsole_path) and os.access(msfconsole_path, os.X_OK):
                    logging.info(f"Metasploit gefunden unter: {self.metasploit_path}")
                    return True, msfconsole_path
            
            # Versuche, msfconsole im PATH zu finden
            result = subprocess.run(
                ['which', 'msfconsole'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                msfconsole_path = result.stdout.strip()
                logging.info(f"Metasploit gefunden im PATH: {msfconsole_path}")
                return True, msfconsole_path
            
            # Überprüfe alternative Pfade
            common_paths = [
                '/usr/bin/msfconsole',
                '/usr/share/metasploit-framework/msfconsole',
                '/opt/metasploit-framework/bin/msfconsole',
                '/opt/metasploit/msfconsole',
                '/opt/metasploit-framework/msfconsole'
            ]
            
            for path in common_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    logging.info(f"Metasploit gefunden unter: {path}")
                    return True, path
            
            logging.warning("Metasploit ist nicht installiert oder nicht im PATH")
            print(f"{Color.YELLOW}HINWEIS: Metasploit ist nicht installiert oder nicht im PATH.{Color.RESET}")
            print(f"{Color.YELLOW}Einige erweiterte Funktionen zur Schwachstellenanalyse sind nicht verfügbar.{Color.RESET}")
            return False, None
        
        except Exception as e:
            logging.error(f"Fehler beim Überprüfen von Metasploit: {str(e)}")
            return False, None
    
    def _check_msf_db_status(self) -> bool:
        """Überprüft, ob die Metasploit-Datenbank verbunden ist"""
        try:
            if not self.metasploit_available or not self.msfconsole_path:
                return False
                
            # Erstelle temporäre Datei für das Metasploit-Skript
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.rc', delete=False) as temp_file:
                temp_file.write("db_status\n")
                temp_file.write("exit\n")
                temp_file_path = temp_file.name
            
            # Führe Metasploit mit dem Skript aus
            result = subprocess.run(
                [self.msfconsole_path, '-q', '-r', temp_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                check=False
            )
            
            # Lösche die temporäre Datei
            os.unlink(temp_file_path)
            
            # Überprüfe, ob die Datenbank verbunden ist
            if "database: connected" in result.stdout.lower():
                logging.info("Metasploit-Datenbank ist verbunden")
                return True
            else:
                logging.warning("Metasploit-Datenbank ist nicht verbunden")
                print(f"{Color.YELLOW}HINWEIS: Die Metasploit-Datenbank ist nicht verbunden.{Color.RESET}")
                print(f"{Color.YELLOW}Führen Sie 'msfdb init' aus, um die Datenbank zu initialisieren.{Color.RESET}")
                return False
                
        except Exception as e:
            logging.error(f"Fehler beim Überprüfen des Metasploit-Datenbankstatus: {str(e)}")
            return False
    
    def search_exploits(self, search_term: str) -> Dict[str, Any]:
        """Sucht nach Metasploit-Exploits basierend auf einem Suchbegriff"""
        try:
            if not self.metasploit_available:
                return {
                    "success": False,
                    "error": "Metasploit ist nicht installiert oder nicht im PATH"
                }
            
            print(f"\n{Color.GREEN}Suche nach Exploits für: {search_term}{Color.RESET}")
            
            # Erstelle temporäre Datei für das Metasploit-Skript
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.rc', delete=False) as temp_file:
                # Schreibe Befehle in die Datei
                temp_file.write(f"search {search_term}\n")
                temp_file.write("exit\n")
                temp_file_path = temp_file.name
            
            # Führe Metasploit mit dem Skript aus
            result = subprocess.run(
                [self.msfconsole_path, '-q', '-r', temp_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                check=False
            )
            
            # Lösche die temporäre Datei
            os.unlink(temp_file_path)
            
            # Verarbeite die Ausgabe
            if result.returncode != 0:
                print(f"{Color.RED}Fehler bei der Exploit-Suche: {result.stderr}{Color.RESET}")
                return {
                    "success": False,
                    "error": result.stderr
                }
            
            # Extrahiere die Ergebnisse aus der Ausgabe
            output_lines = result.stdout.split('\n')
            
            # Finde den Beginn der Ergebnistabelle
            start_index = -1
            for i, line in enumerate(output_lines):
                if "Matching Modules" in line or "=====" in line:
                    start_index = i
                    break
            
            if start_index == -1:
                print(f"{Color.YELLOW}Keine Exploits gefunden für: {search_term}{Color.RESET}")
                return {
                    "success": True,
                    "output": "Keine Ergebnisse gefunden."
                }
            
            # Extrahiere die Ergebnisse
            results = '\n'.join(output_lines[start_index:])
            
            # Formatierte Ausgabe
            self._display_formatted_exploits(results)
            
            return {
                "success": True,
                "output": results
            }
        
        except Exception as e:
            logging.error(f"Fehler bei der Metasploit-Suche: {str(e)}")
            print(f"{Color.RED}Fehler bei der Exploit-Suche: {str(e)}{Color.RESET}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _display_formatted_exploits(self, results: str) -> None:
        """Zeigt formatierte Exploit-Ergebnisse an"""
        try:
            # Extrahiere die Tabelle mit den Exploits
            table_pattern = r'(\s*#\s*Name\s+Disclosure\s+.*?\n(?:.*?\n)+)'
            table_match = re.search(table_pattern, results, re.DOTALL)
            
            if not table_match:
                print(f"{Color.YELLOW}Keine strukturierten Exploit-Informationen gefunden.{Color.RESET}")
                print(results)
                return
            
            table_text = table_match.group(1)
            
            # Extrahiere die einzelnen Zeilen der Tabelle
            lines = table_text.strip().split('\n')
            if len(lines) <= 1:
                print(f"{Color.YELLOW}Keine Exploits gefunden.{Color.RESET}")
                return
            
            # Überschrift
            print(f"\n{Color.GREEN}=== Gefundene Exploits ==={Color.RESET}")
            print(f"{Color.BLUE}{lines[0]}{Color.RESET}")
            
            # Exploits
            for line in lines[1:]:
                # Hebe CVEs und Exploit-Pfade hervor
                line = re.sub(r'(CVE-\d+-\d+)', f"{Color.RED}\\1{Color.RESET}", line)
                line = re.sub(r'(exploit/[\w/]+)', f"{Color.GREEN}\\1{Color.RESET}", line)
                print(line)
        
        except Exception as e:
            logging.error(f"Fehler bei der formatierten Anzeige der Exploits: {str(e)}")
            print(results)  # Fallback zur unformatierten Ausgabe
    
    def search_cve(self, cve_id: str) -> Dict[str, Any]:
        """Sucht nach einem bestimmten CVE in Metasploit"""
        return self.search_exploits(f"cve:{cve_id}")
    
    def check_vulnerability(self, ip: str, port: int, service: str) -> Dict[str, Any]:
        """Prüft, ob für einen bestimmten Dienst Schwachstellen bekannt sind"""
        try:
            if not self.metasploit_available:
                return {
                    "success": False,
                    "error": "Metasploit ist nicht installiert oder nicht im PATH"
                }
            
            print(f"\n{Color.GREEN}Prüfe Schwachstellen für {service} auf {ip}:{port}{Color.RESET}")
            
            # Erstelle temporäre Datei für das Metasploit-Skript
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.rc', delete=False) as temp_file:
                # Schreibe Befehle in die Datei
                temp_file.write(f"search type:exploit name:{service}\n")
                temp_file.write("exit\n")
                temp_file_path = temp_file.name
            
            # Führe Metasploit mit dem Skript aus
            result = subprocess.run(
                [self.msfconsole_path, '-q', '-r', temp_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                check=False
            )
            
            # Lösche die temporäre Datei
            os.unlink(temp_file_path)
            
            # Verarbeite die Ausgabe
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr
                }
            
            # Extrahiere die Ergebnisse
            output = result.stdout
            
            # Formatierte Ausgabe
            self._display_formatted_exploits(output)
            
            return {
                "success": True,
                "output": output,
                "ip": ip,
                "port": port,
                "service": service
            }
        
        except Exception as e:
            logging.error(f"Fehler bei der Schwachstellenprüfung: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def run_exploit(self, exploit_path: str, target: str, options: Dict[str, str] = None) -> Dict[str, Any]:
        """Führt einen Metasploit-Exploit aus"""
        try:
            if not self.metasploit_available:
                return {
                    "success": False,
                    "error": "Metasploit ist nicht installiert oder nicht im PATH"
                }
            
            print(f"\n{Color.GREEN}Führe Exploit aus: {exploit_path} gegen {target}{Color.RESET}")
            if options:
                print(f"{Color.BLUE}Optionen: {json.dumps(options, indent=2)}{Color.RESET}")
            
            # Erstelle temporäre Datei für das Metasploit-Skript
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.rc', delete=False) as temp_file:
                # Schreibe Befehle in die Datei
                temp_file.write(f"use {exploit_path}\n")
                temp_file.write(f"set RHOSTS {target}\n")
                
                # Setze zusätzliche Optionen
                if options:
                    for key, value in options.items():
                        temp_file.write(f"set {key} {value}\n")
                
                temp_file.write("exploit\n")
                temp_file.write("exit\n")
                temp_file_path = temp_file.name
            
            # Führe Metasploit mit dem Skript aus
            result = subprocess.run(
                [self.msfconsole_path, '-q', '-r', temp_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                check=False
            )
            
            # Lösche die temporäre Datei
            os.unlink(temp_file_path)
            
            # Verarbeite die Ausgabe
            if result.returncode != 0:
                print(f"{Color.RED}Fehler beim Ausführen des Exploits: {result.stderr}{Color.RESET}")
                return {
                    "success": False,
                    "error": result.stderr
                }
            
            # Zeige Ergebnis an
            print(f"\n{Color.GREEN}Exploit-Ausführung abgeschlossen:{Color.RESET}")
            print(result.stdout)
            
            return {
                "success": True,
                "output": result.stdout
            }
        
        except Exception as e:
            logging.error(f"Fehler beim Ausführen des Exploits: {str(e)}")
            print(f"{Color.RED}Fehler beim Ausführen des Exploits: {str(e)}{Color.RESET}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """Holt Details zu einer CVE aus der Metasploit-Datenbank"""
        try:
            if not self.metasploit_available:
                return {
                    "success": False,
                    "error": "Metasploit ist nicht installiert oder nicht im PATH"
                }
            
            print(f"\n{Color.GREEN}Hole Details für CVE: {cve_id}{Color.RESET}")
            
            # Erstelle temporäre Datei für das Metasploit-Skript
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.rc', delete=False) as temp_file:
                # Schreibe Befehle in die Datei
                temp_file.write(f"search cve:{cve_id}\n")
                temp_file.write("exit\n")
                temp_file_path = temp_file.name
            
            # Führe Metasploit mit dem Skript aus
            result = subprocess.run(
                [self.msfconsole_path, '-q', '-r', temp_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                check=False
            )
            
            # Lösche die temporäre Datei
            os.unlink(temp_file_path)
            
            # Verarbeite die Ausgabe
            if result.returncode != 0:
                print(f"{Color.RED}Fehler beim Abrufen der CVE-Details: {result.stderr}{Color.RESET}")
                return {
                    "success": False,
                    "error": result.stderr
                }
            
            # Extrahiere die Ergebnisse
            output = result.stdout
            
            # Formatierte Ausgabe
            self._display_formatted_exploits(output)
            
            # Extrahiere zusätzliche Informationen über die CVE
            cve_info = self._extract_cve_info(output, cve_id)
            
            return {
                "success": True,
                "output": output,
                "cve_info": cve_info
            }
        
        except Exception as e:
            logging.error(f"Fehler beim Abrufen der CVE-Details: {str(e)}")
            print(f"{Color.RED}Fehler beim Abrufen der CVE-Details: {str(e)}{Color.RESET}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _extract_cve_info(self, output: str, cve_id: str) -> Dict[str, Any]:
        """Extrahiert Informationen über eine CVE aus der Metasploit-Ausgabe"""
        cve_info = {
            "cve_id": cve_id,
            "description": "",
            "exploits": [],
            "references": []
        }
        
        try:
            # Extrahiere Exploit-Pfade
            exploit_paths = re.findall(r'\s+(exploit/[\w/]+)\s+', output)
            if exploit_paths:
                cve_info["exploits"] = exploit_paths
            
            # Extrahiere Beschreibung (falls vorhanden)
            desc_match = re.search(r'Description:\s+([^\n]+)', output)
            if desc_match:
                cve_info["description"] = desc_match.group(1).strip()
            
            # Extrahiere Referenzen (falls vorhanden)
            ref_matches = re.findall(r'Reference:\s+([^\n]+)', output)
            if ref_matches:
                cve_info["references"] = [ref.strip() for ref in ref_matches]
            
            return cve_info
        
        except Exception as e:
            logging.error(f"Fehler beim Extrahieren der CVE-Informationen: {str(e)}")
            return cve_info