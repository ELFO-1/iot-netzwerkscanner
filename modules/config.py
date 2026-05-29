#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IoT Netzwerkscanner v4.0
Ein umfassendes Tool zur Identifikation und Analyse von IoT-Geräten im Netzwerk

Author: ELFO
Version: 4.0
"""

import os
import json
import configparser
import logging
from .utils import Color, decode_unicode_escape

class Config:
    def __init__(self, config_file='iot_config2.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.scan_profiles = {}
        self.mac_api_key = ''
        
        # Lade Konfiguration
        self._load_config()
        self._load_scan_profiles()
    
    # Hilfsfunktion zum Dekodieren von Strings
    def _d(self, text):
        """Dekodiert Unicode-Escape-Sequenzen"""
        return decode_unicode_escape(text)
    
    def _load_config(self):
        """Lädt die Konfiguration aus der INI-Datei"""
        try:
            if os.path.exists(self.config_file):
                self.config.read(self.config_file, encoding='utf-8')
                logging.info(f"Konfiguration geladen aus {self.config_file}")
                
                # Lade API-Schlüssel
                if 'API' in self.config and 'mac_api_key' in self.config['API']:
                    self.mac_api_key = self.config['API']['mac_api_key']
            else:
                # Erstelle Standardkonfiguration
                self._create_default_config()
                logging.info("Standardkonfiguration erstellt")
        except Exception as e:
            logging.error(f"Fehler beim Laden der Konfiguration: {str(e)}")
            # Erstelle Standardkonfiguration im Fehlerfall
            self._create_default_config()
    
    def _create_default_config(self):
        """Erstellt eine Standardkonfiguration"""
        self.config['SCAN'] = {
            'default_network': '192.168.0.0/24',
            'scan_timeout': '300',
            'max_parallel_scans': '5',
            # Schwachstellenanalyse
            # NSE-Kategorien für die Schwachstellenanalyse (findet möglichst viel)
            'vuln_script_categories': 'vuln,exploit,auth,default',
            # Zusätzliche Einzelskripte außerhalb der Kategorien (ssl-Cipher-Funde)
            'extra_scripts': 'ssl-enum-ciphers,ssl-poodle,ssl-dh-params',
            'enable_brute': 'false',          # Brute-Force-NSE-Skripte (langsam, Absturzgefahr)
            'exclude_ssl_scripts': 'false',   # ssl-*-Skripte ausschließen (nur bei Absturz aktivieren)
            'host_timeout': '',               # leer = kein Limit; z.B. '30m' setzen, wenn gewünscht
            'vulners_retries': '2'            # Zweitläufe für den externen vulners-Lookup (0 = aus)
        }
        
        self.config['DATABASE'] = {
            'db_name': 'iot_devices.db',
            'backup_enabled': 'true',
            'backup_interval': '86400'
        }
        
        self.config['API'] = {
            'mac_api_key': ''
        }
        
        self.config['LOGGING'] = {
            'log_file': 'iot_scanner.log',
            'log_level': 'INFO'
        }
        
        self.config['EXPORT'] = {
            'export_path': 'exports',
            'default_format': 'all',
            'detailed_vulnerabilities': 'true',
            'separate_metasploit': 'true',
        }
        
        self.config['ML'] = {
            'enabled': 'true',
            'model_path': 'models'
        }
        
        self.config['WEB'] = {
            'enabled': 'false',
            'host': '127.0.0.1',
            'port': '8080'
        }
        
        # Speichere die Standardkonfiguration
        self._save_config()
    
    def _save_config(self):
        """Speichert die Konfiguration in der INI-Datei"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as configfile:
                self.config.write(configfile)
            logging.info(f"Konfiguration gespeichert in {self.config_file}")
            return True
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Konfiguration: {str(e)}")
            return False
    
    def _load_scan_profiles(self):
        """Lädt die Scan-Profile aus der JSON-Datei"""
        try:
            if os.path.exists('scan_profiles.json'):
                with open('scan_profiles.json', 'r', encoding='utf-8') as f:
                    self.scan_profiles = json.load(f)
                logging.info("Scan-Profile geladen")
            else:
                # Erstelle Standardprofile
                self._create_default_profiles()
                logging.info("Standard-Scan-Profile erstellt")
        except Exception as e:
            logging.error(f"Fehler beim Laden der Scan-Profile: {str(e)}")
            # Erstelle Standardprofile im Fehlerfall
            self._create_default_profiles()
    
    def _create_default_profiles(self):
        """Erstellt Standardprofile für Scans"""
        self.scan_profiles = {
            'quick': {
                'name': 'quick',
                'description': 'Schneller Scan (nur Ping)',
                'args': '-sn'
            },
            'standard': {
                'name': 'standard',
                'description': 'Standardscan (Ports und Dienste)',
                'args': '-sV -O'
            },
            'deep': {
                'name': 'deep',
                'description': 'Tiefgehender Scan (alle Ports, Banner)',
                'args': '-sV -O -p- --script=banner'
            },
            'vulnerability': {
                'name': 'vulnerability',
                'description': 'Schwachstellenscan',
                'args': '-sV --script=vuln'
            }
        }
        
        # Speichere die Standardprofile
        self.save_scan_profiles()
    
    def save_scan_profiles(self):
        """Speichert die Scan-Profile in der JSON-Datei"""
        try:
            profiles_json = json.dumps(self.scan_profiles, indent=4, ensure_ascii=False)
            with open('scan_profiles.json', 'w', encoding='utf-8') as f:
                f.write(profiles_json)
            logging.info("Scan-Profile wurden gespeichert")
            return True
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Scan-Profile: {str(e)}")
            return False
    
    def get(self, section, option, fallback=None):
        """Gibt einen Konfigurationswert zurück"""
        return self.config.get(section, option, fallback=fallback)
    
    def set(self, section, option, value):
        """Setzt einen Konfigurationswert"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][option] = value
        return self._save_config()
    
    def show_settings(self):
        """Zeigt die aktuellen Einstellungen an und ermöglicht Änderungen"""
        while True:
            print(f"\n{Color.GREEN}=== Einstellungen ==={Color.RESET}")
            print(f"\n{Color.YELLOW}Scan-Einstellungen:{Color.RESET}")
            print(f"1. Standard-Netzwerk: {self.get('SCAN', 'default_network', fallback='192.168.0.0/24')}")
            print(f"2. Scan-Timeout: {self.get('SCAN', 'scan_timeout', fallback='300')} Sekunden")
            print(f"3. Max. parallele Scans: {self.get('SCAN', 'max_parallel_scans', fallback='5')}")
            
            print(f"\n{Color.YELLOW}Datenbank-Einstellungen:{Color.RESET}")
            print(f"4. Datenbankname: {self.get('DATABASE', 'db_name', fallback='iot_devices.db')}")
            print(f"5. Backup aktiviert: {self.get('DATABASE', 'backup_enabled', fallback='true')}")
            print(f"6. Backup-Intervall: {self.get('DATABASE', 'backup_interval', fallback='86400')} Sekunden")
            
            print(f"\n{Color.YELLOW}API-Einstellungen:{Color.RESET}")
            print(f"7. MAC API Key: {'*' * len(self.mac_api_key)}")
            
            print(f"\n{Color.YELLOW}Logging-Einstellungen:{Color.RESET}")
            print(f"8. Log-Datei: {self.get('LOGGING', 'log_file', fallback='iot_scanner.log')}")
            print(f"9. Log-Level: {self.get('LOGGING', 'log_level', fallback='INFO')}")
            
            print(f"\n{Color.YELLOW}Export-Einstellungen:{Color.RESET}")
            print(f"10. Export-Pfad: {self.get('EXPORT', 'export_path', fallback='exports')}")
            print(f"11. Standard-Format: {self.get('EXPORT', 'default_format', fallback='all')}")
            print(f"11a. Detaillierte Schwachstellenausgabe: {self.get('EXPORT', 'detailed_vulnerabilities', fallback='true')}")
            print(f"11b. Separate Metasploit-Übersicht: {self.get('EXPORT', 'separate_metasploit', fallback='true')}")
            
            print(f"\n{Color.YELLOW}ML-Einstellungen:{Color.RESET}")
            print(f"12. ML aktiviert: {self.get('ML', 'enabled', fallback='true')}")
            print(f"13. Modell-Pfad: {self.get('ML', 'model_path', fallback='models')}")
            
            print(f"\n{Color.YELLOW}Web-Interface-Einstellungen:{Color.RESET}")
            print(f"14. Web aktiviert: {self.get('WEB', 'enabled', fallback='false')}")
            print(f"15. Web-Host: {self.get('WEB', 'host', fallback='127.0.0.1')}")
            print(f"16. Web-Port: {self.get('WEB', 'port', fallback='8080')}")
            
            print("\n20. Zurück zum Hauptmenü")
            
            choice = input(f"\n{Color.YELLOW}Wähle eine Option (1-20): {Color.RESET}")
            
            try:
                if choice == "1":
                    new_value = input("Neues Standard-Netzwerk (z.B. 192.168.0.0/24): ")
                    if new_value:
                        self.set('SCAN', 'default_network', new_value)
                elif choice == "2":
                    new_value = input("Neuer Scan-Timeout (in Sekunden): ")
                    if new_value.isdigit():
                        self.set('SCAN', 'scan_timeout', new_value)
                elif choice == "3":
                    new_value = input("Neue maximale Anzahl paralleler Scans: ")
                    if new_value.isdigit():
                        self.set('SCAN', 'max_parallel_scans', new_value)
                elif choice == "4":
                    print(f"{Color.YELLOW}Hinweis: Änderung der Datenbank erfordert Neustart{Color.RESET}")
                    new_value = input("Neuer Datenbankname: ")
                    if new_value:
                        self.set('DATABASE', 'db_name', new_value)
                elif choice == "5":
                    new_value = input("Backup aktivieren? (true/false): ")
                    if new_value.lower() in ['true', 'false']:
                        self.set('DATABASE', 'backup_enabled', new_value)
                elif choice == "6":
                    new_value = input("Neues Backup-Intervall (in Sekunden): ")
                    if new_value.isdigit():
                        self.set('DATABASE', 'backup_interval', new_value)
                elif choice == "7":
                    new_value = input("Neuer MAC API Key: ")
                    if new_value:
                        self.set('API', 'mac_api_key', new_value)
                        self.mac_api_key = new_value
                elif choice == "8":
                    new_value = input("Neue Log-Datei: ")
                    if new_value:
                        self.set('LOGGING', 'log_file', new_value)
                elif choice == "9":
                    new_value = input("Neues Log-Level (DEBUG/INFO/WARNING/ERROR/CRITICAL): ")
                    if new_value in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                        self.set('LOGGING', 'log_level', new_value)
                elif choice == "10":
                    new_value = input("Neuer Export-Pfad: ")
                    if new_value:
                        self.set('EXPORT', 'export_path', new_value)
                elif choice == "11":
                    new_value = input("Neues Standard-Format (csv/json/html/all): ")
                    if new_value in ['csv', 'json', 'html', 'all']:
                        self.set('EXPORT', 'default_format', new_value)
                elif choice == "11a":
                    new_value = input("Detaillierte Schwachstellenausgabe aktivieren? (true/false): ")
                    if new_value.lower() in ['true', 'false']:
                        self.set('EXPORT', 'detailed_vulnerabilities', new_value)
                elif choice == "11b":
                    new_value = input("Separate Metasploit-Übersicht aktivieren? (true/false): ")
                    if new_value.lower() in ['true', 'false']:
                        self.set('EXPORT', 'separate_metasploit', new_value)
                elif choice == "12":
                    new_value = input("ML aktivieren? (true/false): ")
                    if new_value.lower() in ['true', 'false']:
                        self.set('ML', 'enabled', new_value)
                elif choice == "13":
                    new_value = input("Neuer Modell-Pfad: ")
                    if new_value:
                        self.set('ML', 'model_path', new_value)
                elif choice == "14":
                    new_value = input("Web-Interface aktivieren? (true/false): ")
                    if new_value.lower() in ['true', 'false']:
                        self.set('WEB', 'enabled', new_value)
                elif choice == "15":
                    new_value = input("Neuer Web-Host (z.B. 127.0.0.1 oder 0.0.0.0): ")
                    if new_value:
                        self.set('WEB', 'host', new_value)
                elif choice == "16":
                    new_value = input("Neuer Web-Port: ")
                    if new_value.isdigit():
                        self.set('WEB', 'port', new_value)
                elif choice == "20":
                    break
                else:
                    print(f"{Color.RED}Ungültige Auswahl!{Color.RESET}")
            
            except Exception as e:
                logging.error(f"Fehler beim Ändern der Einstellungen: {str(e)}")
                print(f"{Color.RED}Fehler beim Ändern der Einstellungen: {str(e)}{Color.RESET}")
    
    def manage_scan_profiles(self):
        """Verwaltet die Scan-Profile"""
        while True:
            print(f"\n{Color.GREEN}=== Scan-Profile Verwaltung ==={Color.RESET}")
            print(self._d(f"\n{Color.YELLOW}Verfügbare Profile:{Color.RESET}"))
            
            for key, profile in self.scan_profiles.items():
                print(f"\n{key}:")
                print(f"  Name: {profile['name']}")
                print(f"  Beschreibung: {profile['description']}")
                print(f"  Argumente: {profile['args']}")
            
            print("\nOptionen:")
            print("1. Neues Profil erstellen")
            print("2. Profil bearbeiten")
            print("3. Profil löschen")
            print(self._d("4. Zurück zum Hauptmenü"))
            
            choice = input(f"\n{Color.YELLOW}Wähle eine Option (1-4): {Color.RESET}")
            
            if choice == "1":
                name = input("Profilname (keine Leerzeichen): ").strip()
                if ' ' in name:
                    print(f"{Color.RED}Profilname darf keine Leerzeichen enthalten!{Color.RESET}")
                    continue
                description = input("Beschreibung: ")
                args = input("Nmap-Argumente: ")
                
                self.scan_profiles[name] = {
                    'name': name,
                    'description': description,
                    'args': args
                }
                self.save_scan_profiles()
                print(f"{Color.GREEN}Profil wurde erstellt und gespeichert.{Color.RESET}")
            
            elif choice == "2":
                profile_name = input("Name des zu bearbeitenden Profils: ")
                if profile_name in self.scan_profiles:
                    description = input("Neue Beschreibung (Enter für unverändert): ")
                    args = input("Neue Nmap-Argumente (Enter für unverändert): ")
                    
                    if description:
                        self.scan_profiles[profile_name]['description'] = description
                    if args:
                        self.scan_profiles[profile_name]['args'] = args
                    self.save_scan_profiles()
                    print(f"{Color.GREEN}Profil wurde aktualisiert und gespeichert.{Color.RESET}")
                else:
                    print(f"{Color.RED}Profil nicht gefunden!{Color.RESET}")
            
            elif choice == "3":
                profile_name = input("Name des zu löschenden Profils: ")
                if profile_name in self.scan_profiles:
                    confirm = input(f"Profil '{profile_name}' wirklich löschen? (j/n): ")
                    if confirm.lower() == 'j':
                        del self.scan_profiles[profile_name]
                        self.save_scan_profiles()
                        print(f"{Color.GREEN}Profil wurde gelöscht.{Color.RESET}")
                else:
                    print(f"{Color.RED}Profil nicht gefunden!{Color.RESET}")
            
            elif choice == "4":
                break
            else:
                print(f"{Color.RED}Ungültige Auswahl!{Color.RESET}")