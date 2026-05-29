#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IoT Netzwerkscanner v4.0
Ein umfassendes Tool zur Identifikation und Analyse von IoT-Geräten im Netzwerk

Author: ELFO
Version: 4.0
"""

import os
import platform
import codecs

# Farbklasse für Terminal-Ausgaben
class Color:
    # ANSI-Farbcodes
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    
    # Deaktiviere Farben für Windows, wenn nicht in einem ANSI-fähigen Terminal
    if platform.system() == 'Windows' and not os.environ.get('TERM'):
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''

# Banner-Text für das Programm
BANNER_TEXT = (
    Color.GREEN +
    r"""
 <-. (`-')_  (`-')  _(`-')       (`-')       .->    (`-')  _   (`-') <-.(`-')  (`-').->           (`-')  _ <-. (`-')_ <-. (`-')_  (`-')  _   (`-')
   \( OO) ) ( OO).-/( OO).->    ( OO).->(`(`-')/`) ( OO).-/<-.(OO )  __( OO)  ( OO)_   _         (OO ).-/    \( OO) )   \( OO) ) ( OO).-/<-.(OO )
,--./ ,--/ (,------./    '._  ,(_/----.,-`( OO).',(,------.,------,)'-'. ,--.(_)--\_)  \-,-----. / ,---.  ,--./ ,--/ ,--./ ,--/ (,------.,------,)
|   \ |  |  |  .---'|'--...__)|__,    ||  |\  |  | |  .---'|   /`. '|  .'   //    _ /   |  .--./ | \ /`.\ |   \ |  | |   \ |  |  |  .---'|   /`. '
|  . '|  |)(|  '--. `--.  .--' (_/   / |  | '.|  |(|  '--. |  |_.' ||      /)\_..`--.  /_) (`-') '-'|_.' ||  . '|  |)|  . '|  |)(|  '--. |  |_.' |
|  |\    |  |  .--'    |  |    .'  .'_ |  |.'.|  | |  .--' |  .   .'|  .   ' .-._)   \ ||  |OO )(|  .-.  ||  |\    | |  |\    |  |  .--' |  .   .'
|  | \   |  |  `---.   |  |   |       ||   ,'.   | |  `---.|  |\  \ |  |\   \\       /(_'  '--'\ |  | |  ||  | \   | |  | \   |  |  `---.|  |\  \
`--'  `--'  `------'   `--'   `-------'`--'   '--' `------'`--' '--'`--' '--' `-----'    `-----' `--' `--'`--'  `--' `--'  `--'  `------'`--' '--'

 """ +
    Color.RESET + "\n" +
    Color.YELLOW + "                                  Version 4.0 - by ELFO" + Color.RESET + "\n"
)

# Funktion zum Leeren des Terminals
def clear():
    """Leert das Terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def decode_unicode_escape(text):
    return text if text else ""

# Decorator zum automatischen Dekodieren von Unicode-Escape-Sequenzen
def auto_decode_unicode(func):
    """Decorator, der automatisch Unicode-Escape-Sequenzen in Strings dekodiert"""
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if isinstance(result, str):
            return decode_unicode_escape(result)
        return result
    return wrapper

# Funktion zum Erstellen der Datenbankstruktur
def create_database_structure(db_name):
    """Erstellt die Datenbankstruktur, falls sie nicht existiert"""
    import sqlite3
    
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    
    # Tabelle für Geräte
    c.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        mac TEXT,
        hostname TEXT,
        vendor TEXT,
        device_type TEXT,
        os TEXT,
        services TEXT,
        open_ports TEXT,
        vulnerabilities TEXT,
        first_seen TEXT,
        last_seen TEXT,
        notes TEXT,
        raw_vulnerabilities TEXT,
        metasploit_exploits TEXT
    )
    """)
    
    # Tabelle für Scan-Historie
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
    
    # Tabelle für Verhaltensprofile
    c.execute("""
    CREATE TABLE IF NOT EXISTS behavior_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT,
        profile_data TEXT,
        created_date TEXT,
        FOREIGN KEY (device_ip) REFERENCES devices (ip)
    )
    """)
    
    # Tabelle für Schwachstellendetails
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
    
    # Tabelle für Einstellungen
    c.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Prüfe, ob die Spalten vulnerabilities_found und metasploit_exploits_found in der scan_history Tabelle existieren
    # und füge sie hinzu, falls sie fehlen
    try:
        c.execute("PRAGMA table_info(scan_history)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'vulnerabilities_found' not in columns:
            c.execute("ALTER TABLE scan_history ADD COLUMN vulnerabilities_found INTEGER DEFAULT 0")
            
        if 'metasploit_exploits_found' not in columns:
            c.execute("ALTER TABLE scan_history ADD COLUMN metasploit_exploits_found INTEGER DEFAULT 0")
            
        if 'results' not in columns:
            c.execute("ALTER TABLE scan_history ADD COLUMN results TEXT")
    except Exception as e:
        print(f"Fehler beim Aktualisieren der Datenbankstruktur: {str(e)}")
    
    conn.commit()
    conn.close()