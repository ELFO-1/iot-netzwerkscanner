# IoT Netzwerkscanner v4.0

Ein umfassendes, interaktives CLI-Tool zur Erkennung, Identifikation und Sicherheitsanalyse von Geräten im Netzwerk – mit Metasploit-Integration, ML-basierter Geräteklassifikation und HTML/CSV/JSON/PDF-Reportgenerierung.

> **Hinweis:** Dieses Tool ist ausschließlich für den Einsatz in eigenen Netzwerken oder in Umgebungen, für die eine ausdrückliche schriftliche Genehmigung vorliegt, bestimmt.

---

## Features

| Kategorie | Funktionen |
|---|---|
| **Scanning** | Netzwerk-Discovery, Portscan (schnell / vollständig), Service- & OS-Erkennung, Aggressiv-Scan |
| **Schwachstellen** | Vulnerability-Scan via Vulners-API (mit Retry), SSL/TLS-Prüfung, Standardpasswort-Test (echte Logins), Port-Knocking |
| **Brute-Force** | Echte Login-Versuche gegen SSH, FTP, Telnet, HTTP (Basic) & HTTP-Formulare – mit Wortlisten-Unterstützung |
| **Metasploit** | Exploit-Suche, MSFRPC-Integration, automatisierte Exploit-Übersichten |
| **ML-Klassifikation** | Random-Forest-Klassifikator zur Geräteerkennung (Router, Kamera, IoT, etc.) |
| **Export** | HTML-Berichte (Detail, Vuln-Report, Executive Summary), CSV, JSON, PDF (optional), XML |
| **Web-Interface** | Lokaler Flask-Webserver zur Berichtsansicht (optional) |
| **Konfiguration** | INI-Konfigurationsdatei, verwaltbare Scan-Profile (JSON), SQLite-Datenbank |

---

## Voraussetzungen

### System

- Linux (empfohlen) oder Windows
- Python 3.10+
- **`nmap`** muss systemweit installiert sein
- Root- / Administratorrechte für Raw-Socket-Scans

```bash
# Arch / Garuda / CachyOS
sudo pacman -S nmap

# Debian / Ubuntu
sudo apt install nmap

# Fedora / RHEL
sudo dnf install nmap
```

### Optional

- **Metasploit Framework** – für Exploit-Suche und MSFRPC-Integration
- **WeasyPrint** – für PDF-Export (benötigt weitere Systembibliotheken, siehe [WeasyPrint Docs](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html))

---

## Installation

```bash
# 1. Repository klonen
git clone https://github.com/ELFO-1/iot-netzwerkscanner
cd iot-netzwerkscanner

# 2. Virtuelle Umgebung erstellen (empfohlen)
python3 -m venv .venv
source .venv/bin/activate

# 3. Abhängigkeiten installieren
pip install -r requirements.txt

# 4. Konfiguration aus der Vorlage anlegen und eigene API-Keys eintragen
cp iot_config2.ini.example iot_config2.ini
# danach iot_config2.ini öffnen und mac_api_key / vulners_api_key setzen
```

> **Hinweis:** `iot_config2.ini` ist absichtlich per `.gitignore` ausgeschlossen
> (enthält API-Keys) – nach dem Klonen ist nur die Vorlage `iot_config2.ini.example`
> vorhanden. Schritt 4 ist daher erforderlich.

---

## Verwendung

### Interaktives Menü (Standard)

```bash
sudo python3 netzwerkscanner_v4.py
```

Das Tool startet automatisch mit Root-Rechten (fragt via `sudo` nach, falls nötig).

### Headless-Modus (ohne Menü)

```bash
# Netzwerk-Discovery + Geräteidentifikation
sudo python3 netzwerkscanner_v4.py --headless --target 192.168.0.0/24

# Vulnerability-Scan
sudo python3 netzwerkscanner_v4.py --headless --target 192.168.0.0/24 --scan-type vulnerability

# Mit Debug-Output
sudo python3 netzwerkscanner_v4.py --headless --target 192.168.0.1 --debug
```

### Berichte generieren

```bash
sudo python3 netzwerkscanner_v4.py --generate-reports
```

### ML-Klassifikator trainieren / verbessern

```bash
python3 train_classifier.py
```

---

## CLI-Argumente

| Argument | Werte | Beschreibung |
|---|---|---|
| `--headless` | – | Startet ohne interaktives Menü |
| `--target` | IP / CIDR | Ziel-IP oder Netzwerkbereich (z. B. `192.168.0.0/24`) |
| `--scan-type` | `quick` `standard` `deep` `vulnerability` | Scan-Profil (Standard: `standard`) |
| `--generate-reports` | – | Exportiert Berichte aus der aktuellen Datenbank |
| `--debug` | – | Aktiviert detailliertes Logging |

---

## Menü-Übersicht

```
 1  Netzwerk-Discovery Scan
 2  Detaillierte Geräteidentifikation
 3  Schwachstellenanalyse
 4  Komplett-Scan
 5  Benutzerdefinierter Scan

── Spezielle Nmap-Scans ──────────────────
 6  Schneller Portscan (Top 100 Ports)
 7  Vollständiger Portscan (Alle Ports)
 8  Service-Erkennung (Version Detection)
 9  OS-Erkennung (OS Detection)
10  Aggressive Scan (Service, OS, Scripts)
11  Vollständiger Pentest

── Erweiterte Pentesting-Funktionen ──────
12  SSL/TLS-Konfiguration prüfen
13  Standardpasswörter testen (echte Logins)
14  Port-Knocking-Tests
15  Metasploit-Exploits suchen
16  Brute-Force-Angriff (SSH / FTP / Telnet / HTTP / HTTP-Form)

── Export & Konfiguration ────────────────
17  Ergebnisse exportieren (alle Scans)
18  Nur letzten Scan exportieren
19  Scan-Verlauf anzeigen
20  Scan-Profile verwalten
21  Einstellungen (iot_config2.ini)
22  Beenden
```

---

## Brute-Force (Option 16)

Führt **echte** Anmeldeversuche gegen einen Dienst durch (keine Simulation). Unterstützt:

| Dienst | Methode |
|---|---|
| `ssh` | echter SSH-Login (benötigt `paramiko`) |
| `ftp` | FTP-Login (`ftplib`) |
| `telnet` | roher Socket-Login (Treffer nur bei klarem Shell-Prompt) |
| `http` | HTTP-Basic-Auth |
| `http-form` | Formular-Login mit automatischer Felderkennung |

Benutzername und Passwort akzeptieren jeweils: einen einzelnen Wert, eine
Komma­liste (`admin,root,user`) **oder einen Pfad zu einer Wortliste** (z. B.
`rockyou.txt`). Der Scan stoppt pro Benutzer beim ersten Treffer, pausiert kurz
zwischen den Versuchen und bricht früh ab, wenn der Dienst nicht erreichbar ist.
Lässt sich jederzeit mit `Strg+C` abbrechen.

> Nur im eigenen Netz bzw. mit ausdrücklicher Genehmigung verwenden.

---

## Konfiguration

### `iot_config2.ini`

```ini
[SCAN]
default_network = 192.168.0.0/24
scan_timeout = 300
max_parallel_scans = 5
# Schwachstellen-Scan (Menüpunkt 3): NSE-Skriptkategorien + Zusatzskripte
vuln_script_categories = vuln,exploit,auth,default
extra_scripts = ssl-enum-ciphers,ssl-poodle,ssl-dh-params
enable_brute = false          # NSE-brute-Skripte (langsam, kann nmap crashen)
exclude_ssl_scripts = false
host_timeout =                # leer = kein Timeout (für langsame Geräte)
vulners_retries = 2           # gleicht Schwankungen der Vulners-API aus

[DATABASE]
db_name = iot_devices.db

[EXPORT]
export_path = exports
default_format = all          # csv | json | html | all

[VULNERS]
vulners_api_key = DEIN_API_KEY

[METASPLOIT]
enabled = true
path = /opt/metasploit/

[ML]
enabled = true
model_path = models
```

Alle Einstellungen können auch direkt im Menü unter **Option 20** geändert werden.

### Vulners API-Key

Für die CVE-Schwachstellenanalyse wird ein kostenloser API-Key von [vulners.com](https://vulners.com) benötigt:

1. Account anlegen auf [vulners.com](https://vulners.com)
2. API-Key generieren
3. In `iot_config2.ini` unter `[VULNERS]` → `vulners_api_key` eintragen

### Scan-Profile

Eigene nmap-Argumentprofile können in `scan_profiles.json` oder direkt im Menü (Option 19) verwaltet werden:

```json
{
    "mein_profil": {
        "name": "mein_profil",
        "description": "Stealth-Scan",
        "args": "-sS -T2 -p 22,80,443"
    }
}
```

---

## Projektstruktur

```
.
├── netzwerkscanner_v4.py       # Hauptprogramm & interaktives Menü
├── exporter.py                 # Fallback-Exporter (root-level)
├── train_classifier.py         # ML-Modell trainieren/verbessern
├── iot_config2.ini.example     # Konfigurations-Vorlage (versioniert)
├── iot_config2.ini             # Eigene Konfiguration (gitignored, lokal anlegen)
├── scan_profiles.json          # Nmap-Scan-Profile
├── iot_devices.db              # SQLite-Datenbank (auto-erstellt, gitignored)
├── requirements.txt
├── .gitignore
│
├── modules/
│   ├── scanner_metasploit.py   # Nmap-Scanner + Vulners-CVE-Lookup
│   ├── analyzer.py             # SSL/TLS, Standardpasswörter, Brute-Force, Verhaltensprofile
│   ├── database.py             # SQLite-CRUD (Geräte, Schwachstellen, Historie)
│   ├── config.py               # INI-Konfiguration + Scan-Profile
│   ├── exporter.py             # Jinja2-Export (HTML, CSV, JSON, PDF, XML)
│   ├── metasploit_integration.py  # msfconsole subprocess + MSFRPC
│   ├── nmap_special_scans.py   # Erweiterte Nmap-Profile
│   ├── ml_classifier.py        # RandomForest-Geräteklassifikator
│   ├── msfrpc.py               # MSFRPC-Protokoll-Client
│   └── utils.py                # Farben, Banner, Hilfsfunktionen
│
├── templates/                  # Jinja2-HTML-Vorlagen
│   ├── detailed_report.html
│   ├── executive_summary.html
│   ├── vulnerability_report.html
│   ├── vulnerability_detail.html
│   └── remediation_plan.html
│
├── exports/                    # Generierte Berichte (auto-erstellt)
└── logs/                       # Log-Dateien (auto-erstellt)
```

---

## Export-Formate

Ergebnisse können exportiert werden über:

- **Option 17** – alle Scans / die komplette Datenbank
- **Option 18** – nur den zuletzt durchgeführten Scan (Dateien erhalten das Präfix `last_scan_`)
- `--generate-reports` – Export aus der aktuellen Datenbank (Headless)

Erzeugte Dateien (Formate konfigurierbar über `default_format`):

| Datei | Inhalt |
|---|---|
| `vulnerability_report_*.html` | Vollständiger Schwachstellenbericht (HTML) |
| `security_report_*.csv` | Geräte + Schwachstellen als CSV |
| `security_report_*.json` | Geräte + Schwachstellen als JSON |
| `security_report_*.xml` | Geräte + Schwachstellen als XML |
| `security_report_*.pdf` | PDF-Export (WeasyPrint erforderlich) |
| `export_summary_*.txt` | Übersicht der erzeugten Dateien |

> Beim Export „nur letzter Scan" (Option 18) tragen alle Dateien zusätzlich das Präfix `last_scan_`.

---

## ML-Geräteklassifikation

Der eingebaute Random-Forest-Klassifikator erkennt Gerätetypen anhand von Vendor, MAC-OUI, OS, Hostname, Diensten und offenen Ports.

```bash
# Modell erstellen / neu trainieren
python3 train_classifier.py

# Optionen im Trainings-Script:
# 1. Initiales Modell erstellen (Standarddaten)
# 2. Mit eigenen Gerätedaten trainieren
# 3. Klassifikator testen & Feedback geben
# 4. Feature-Importance anzeigen
```

Modell wird gespeichert unter: `modules/models/device_classifier.pkl`  
Trainingsdaten: `modules/models/training_data.json`

---

## Datenbank

SQLite-Datenbank (`iot_devices.db`) mit folgenden Tabellen:

| Tabelle | Inhalt |
|---|---|
| `devices` | IP, MAC, Hostname, Vendor, OS, Ports, Dienste |
| `vulnerability_details` | CVE-ID, Schweregrad, Port, Beschreibung |
| `scan_history` | Datum, Typ, Netzwerk, Dauer, Anzahl Geräte/Schwachstellen |
| `settings` | Konfigurationswerte (u. a. API-Keys) |

---

## Sicherheitshinweis

Dieses Tool verwendet aktive Scanning-Techniken (nmap, Credential-Testing, Exploit-Suche), die in fremden Netzwerken **ohne ausdrückliche Genehmigung illegal** sind. Die Nutzung erfolgt ausschließlich auf eigene Verantwortung:

- Nur in eigenen Netzwerken oder mit schriftlicher Genehmigung verwenden
- Nicht für Angriffe auf fremde Systeme einsetzen
- Lokale Gesetze und Vorschriften beachten

---

## Lizenz

Dieses Projekt steht unter der [MIT License](LICENSE).

---

*Erstellt von **ELFO** · IoT Netzwerkscanner v4.0*
