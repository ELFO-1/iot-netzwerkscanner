# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

IoT Netzwerkscanner v4.0 — an interactive CLI tool for discovering, fingerprinting, and assessing IoT/network devices. It combines nmap scanning, Vulners CVE lookup, optional Metasploit integration, and an ML-based device classifier. The UI is German-language (menu-driven terminal). Intended for authorized pentesting/home lab use.

## Running the Scanner

```bash
# Start the interactive CLI (requires root/sudo for raw socket scans)
sudo python3 netzwerkscanner_v4.py

# Train or retrain the ML device classifier
python3 train_classifier.py

# Verify circular imports are resolved
python3 test_circular_import.py

# Test config loading
python3 test_config.py

# Unit tests for the parser/normalization logic (no extra deps)
python3 -m unittest test_parsers -v
```

## System Dependencies

nmap must be installed and in PATH. Metasploit is optional; if present it is detected automatically or via the `path` key in `[METASPLOIT]` config. The Vulners API key and MAC vendor lookup key live in `iot_config2.ini`.

## Architecture

All orchestration lives in `netzwerkscanner_v4.py` inside the `IOTScanner` class, which owns an interactive menu loop. The `modules/` package contains the functional components:

| Module | Class | Responsibility |
|---|---|---|
| `modules/scanner_metasploit.py` | `Scanner` | nmap scans, Vulners API CVE lookup, device data collection |
| `modules/analyzer.py` | `Analyzer` | SSL/TLS checks, vulnerability trend analysis, post-scan reporting |
| `modules/database.py` | `Database` | SQLite CRUD (devices, vulnerabilities, scan_history, settings tables) |
| `modules/config.py` | `Config` | INI config wrapper (`iot_config2.ini`) + scan profile JSON management |
| `modules/metasploit_integration.py` | `MetasploitIntegration` | msfconsole subprocess + MSFRPC exploit lookup |
| `modules/nmap_special_scans.py` | `NmapSpecialScans` | Extended nmap profiles (OS, firewall, IDS evasion) |
| `modules/ml_classifier.py` | `DeviceClassifier` | RandomForest + TF-IDF device type classification |
| `modules/msfrpc.py` | — | Low-level MSFRPC wire protocol |
| `modules/utils.py` | `Color`, helpers | ANSI colors, banner, `decode_unicode_escape` |
| `exporter.py` (root) | `Exporter` | CSV/JSON/HTML export with Jinja2 templates |
| `modules/exporter.py` | `Exporter` | Thin wrapper that re-exports the root `Exporter` |

`netzwerkscanner_v4.py` also contains `DatabaseManager` (a second DB wrapper used directly by the main class) and `ProgressBar`.

## Circular Import Pattern

There is a known and intentional import layering to avoid circular imports:

1. `modules/database.py` imports nothing from other local modules.
2. Root `exporter.py` imports `Database` but not `Scanner`.
3. `modules/exporter.py` imports root `exporter.Exporter` as a base class.
4. `netzwerkscanner_v4.py` imports `modules.database.Database` first, then tries `modules.exporter.Exporter`, falling back to root `exporter.Exporter`, then a minimal inline fallback.

Do not introduce imports that break this order (e.g., having `database.py` import from `scanner_metasploit.py`).

## Configuration

`iot_config2.ini` is the primary config file. Key sections:

- `[SCAN]` — default network CIDR, timeout, parallelism
- `[DATABASE]` — SQLite file name (`iot_devices.db`)
- `[EXPORT]` — output path (`exports/`), format (`csv`/`json`/`html`/`all`)
- `[METASPLOIT]` — enable flag, path, MSGRPC service address
- `[ML]` — enable flag, model path (`modules/models/`)
- `[VULNERS]` — API key
- `[API]` — MAC vendor lookup API key

`scan_profiles.json` stores named nmap argument sets (quick / standard / deep / vulnerability). The `Config` class manages both files and exposes a `get(section, option, fallback)` interface.

## Scan Profiles

Profiles are loaded from `scan_profiles.json` and map a name to an `args` string passed directly to `python-nmap`. Predefined: `quick` (`-sn`), `standard` (`-sV -O`), `deep` (`-sV -O -p- --script=banner`), `vulnerability` (`-sV --script=vuln`).

## ML Classifier

`DeviceClassifier` in `modules/ml_classifier.py` uses scikit-learn (RandomForest + TF-IDF). Model persisted at `modules/models/device_classifier.pkl`, training data at `modules/models/training_data.json`. When confidence is below threshold the scanner falls back to rule-based classification and optionally prompts the user to correct and retrain.

## Export Output

Exports go to the `exports/` directory (configurable). A full export produces: `devices_*.{csv,json,html}`, `vulnerability_report_*.html`, `executive_summary_*.html`, per-device `detailed_report_*_N.html`, and `export_summary_*.txt`. Jinja2 templates are in `templates/`.

## Logging

Logs are written to `logs/iot_scanner_<timestamp>.log` and `logs/console_output.log`. Log level defaults to INFO; change via `[LOGGING] log_level` in the INI.
