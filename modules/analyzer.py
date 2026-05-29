#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IoT Netzwerkscanner v4.0
Ein umfassendes Tool zur Identifikation und Analyse von IoT-Geräten im Netzwerk

Author: ELFO
Version: 4.0
"""

import os
import time
import logging
import sqlite3
import pandas as pd
import numpy as np
import json
from datetime import datetime, timedelta
from .utils import Color, decode_unicode_escape

class Analyzer:
    def __init__(self, db_name='iot_devices.db'):
        self.db_name = db_name
    
    # Hilfsfunktion zum Dekodieren von Strings
    def _d(self, text):
        """Dekodiert Unicode-Escape-Sequenzen"""
        return decode_unicode_escape(text)
    
    def check_ssl_configuration(self, ip, port=443):
        """Überprüft die SSL/TLS-Konfiguration eines Geräts"""
        try:
            print(f"\n{Color.GREEN}Starte SSL/TLS-Konfigurationsprung für {ip}:{port}...{Color.RESET}")
            
            # Verwende nmap mit ssl-enum-ciphers Skript
            import nmap
            nm = nmap.PortScanner()
            nm.scan(ip, str(port), arguments='--script ssl-enum-ciphers -sV')
            
            if ip in nm.all_hosts() and str(port) in nm[ip].get('tcp', {}):
                port_info = nm[ip]['tcp'][port]
                
                print(f"\n{Color.YELLOW}SSL/TLS-Konfiguration für {ip}:{port}{Color.RESET}")
                
                # Zeige allgemeine Informationen
                print(f"\nDienst: {port_info.get('name', 'Unbekannt')} {port_info.get('product', '')} {port_info.get('version', '')}")
                
                # Zeige SSL/TLS-Details, wenn verfügbar
                if 'script' in port_info and 'ssl-enum-ciphers' in port_info['script']:
                    ssl_info = port_info['script']['ssl-enum-ciphers']
                    print(f"\n{Color.BLUE}SSL/TLS-Details:{Color.RESET}")
                    print(ssl_info)
                    
                    # Bewerte die Sicherheit basierend auf den Ergebnissen
                    security_rating = self._rate_ssl_security(ssl_info)
                    print(f"\n{Color.YELLOW}Sicherheitsbewertung: {security_rating}{Color.RESET}")
                else:
                    print(f"\n{Color.RED}Keine SSL/TLS-Informationen gefunden.{Color.RESET}")
            else:
                print(f"\n{Color.RED}Port {port} ist nicht offen oder unterstützt kein SSL/TLS.{Color.RESET}")
        
        except Exception as e:
            logging.error(f"Fehler bei der SSL/TLS-Konfigurationsprüfung: {str(e)}")
            print(f"\n{Color.RED}Fehler bei der SSL/TLS-Prüfung: {str(e)}{Color.RESET}")
    
    def _rate_ssl_security(self, ssl_info):
        """Bewertet die SSL/TLS-Sicherheit basierend auf den Ergebnissen"""
        # Einfache heuristische Bewertung
        rating = "Mittel"
        
        # Prüfe auf bekannte Schwachstellen
        if any(vuln in ssl_info.lower() for vuln in ['heartbleed', 'poodle', 'freak', 'logjam', 'drown']):
            rating = "Kritisch"
        elif 'sslv2' in ssl_info.lower() or 'sslv3' in ssl_info.lower():
            rating = "Schlecht"
        elif 'tlsv1.0' in ssl_info.lower() and 'tlsv1.2' not in ssl_info.lower() and 'tlsv1.3' not in ssl_info.lower():
            rating = "Schlecht"
        elif 'tlsv1.2' in ssl_info.lower() or 'tlsv1.3' in ssl_info.lower():
            if 'strong' in ssl_info.lower() and not any(weak in ssl_info.lower() for weak in ['weak', 'medium']):
                rating = "Gut"
        
        return rating
    
    def check_default_credentials(self, ip, device_type=None):
        """Prüft, ob ein Gerät Standardanmeldedaten verwendet"""
        try:
            print(f"\n{Color.GREEN}Starte Prüfung auf Standardanmeldedaten für {ip}...{Color.RESET}")
            
            # Lade Dienste des Geräts aus der Datenbank
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            c.execute("SELECT services, device_type FROM devices WHERE ip=?", (ip,))
            result = c.fetchone()
            conn.close()
            
            if not result or not result[0]:
                print(f"\n{Color.YELLOW}Keine Dienstinformationen für {ip} gefunden. Führe zuerst einen detaillierten Scan durch.{Color.RESET}")
                return
            
            services = result[0]
            device_type = device_type or result[1] or "Unbekannt"
            
            # Definiere Standardanmeldedaten für verschiedene Gerätetypen und Dienste
            default_credentials = self._get_default_credentials(device_type, services)
            
            if not default_credentials:
                print(f"\n{Color.YELLOW}Keine bekannten Standardanmeldedaten für {device_type} gefunden.{Color.RESET}")
                return
            
            # Ports aus der Dienstliste ermitteln (z. B. "22/tcp: ssh")
            port_map = self._parse_service_ports(services)

            # Teste die Anmeldedaten
            print(f"\n{Color.YELLOW}Teste Standardanmeldedaten für {ip} ({device_type}):{Color.RESET}")
            print(f"{Color.BLUE}Hinweis: Es werden echte Anmeldeversuche durchgeführt. "
                  f"Nur mit Genehmigung im eigenen Netz verwenden.{Color.RESET}")

            any_success = False
            for service, creds_list in default_credentials.items():
                protocol, default_port = self._SERVICE_META.get(service, ('http', None))
                port = port_map.get(protocol) or default_port
                print(f"\n{Color.BLUE}Dienst: {service}"
                      f"{f' (Port {port})' if port else ''}{Color.RESET}")

                for cred in creds_list:
                    username = cred['username']
                    password = cred['password']
                    print(f"  Teste: {username} / {password if password else '<leer>'}")

                    result, detail = self._test_credential(
                        protocol, ip, port, username, password
                    )

                    if result is True:
                        any_success = True
                        print(f"  {Color.RED}>>> ERFOLG! Standardanmeldedaten funktionieren! "
                              f"({detail}){Color.RESET}")
                    elif result is False:
                        print(f"  {Color.GREEN}Fehlgeschlagen – Zugangsdaten greifen nicht. "
                              f"({detail}){Color.RESET}")
                    else:  # None = nicht eindeutig testbar
                        print(f"  {Color.YELLOW}Nicht testbar: {detail}{Color.RESET}")

            if any_success:
                print(f"\n{Color.RED}Achtung: Mindestens ein Standardlogin war erfolgreich – "
                      f"bitte Passwörter ändern!{Color.RESET}")
            else:
                print(f"\n{Color.GREEN}Keine funktionierenden Standardanmeldedaten gefunden.{Color.RESET}")

        except Exception as e:
            logging.error(f"Fehler bei der Prüfung auf Standardanmeldedaten: {str(e)}")
            print(f"\n{Color.RED}Fehler bei der Prüfung: {str(e)}{Color.RESET}")

    # Zuordnung Dienst-Kategorie -> (Protokoll, Standard-Port)
    _SERVICE_META = {
        'SSH': ('ssh', 22),
        'Telnet': ('telnet', 23),
        'FTP': ('ftp', 21),
        'Web': ('http', 80),
        'Router': ('http', 80),
        'Kamera': ('http', 80),
    }

    def _parse_service_ports(self, services):
        """Extrahiert {Protokoll: Port} aus der Dienst-Zeichenkette der DB.

        Erwartetes Format pro Zeile z. B. ``22/tcp: ssh`` oder ``80/tcp: http``.
        """
        import re
        port_map = {}
        if not services:
            return port_map
        for m in re.finditer(r'(\d{1,5})/tcp:\s*([a-zA-Z0-9_\-]+)', services):
            port = int(m.group(1))
            name = m.group(2).lower()
            if 'ssh' in name and 'ssh' not in port_map:
                port_map['ssh'] = port
            elif 'telnet' in name and 'telnet' not in port_map:
                port_map['telnet'] = port
            elif 'ftp' in name and 'ftp' not in port_map:
                port_map['ftp'] = port
            elif ('http' in name or 'www' in name) and 'http' not in port_map:
                port_map['http'] = port
        return port_map

    def _test_credential(self, protocol, ip, port, username, password):
        """Führt einen echten Anmeldeversuch durch.

        Rückgabe: (True|False|None, detail)
          True  = Login erfolgreich
          False = Login eindeutig abgelehnt
          None  = konnte nicht zuverlässig getestet werden
        """
        try:
            if protocol == 'ssh':
                return self._test_ssh(ip, port or 22, username, password)
            if protocol == 'ftp':
                return self._test_ftp(ip, port or 21, username, password)
            if protocol == 'telnet':
                return self._test_telnet(ip, port or 23, username, password)
            if protocol == 'http':
                return self._test_http(ip, port or 80, username, password)
            return None, f"unbekanntes Protokoll {protocol}"
        except Exception as e:
            return None, f"Fehler: {e}"

    def _test_ssh(self, ip, port, username, password):
        """SSH-Login via paramiko (falls installiert)."""
        try:
            import paramiko
        except ImportError:
            return None, "paramiko nicht installiert (pip install paramiko)"
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                ip, port=port, username=username, password=password,
                timeout=6, banner_timeout=6, auth_timeout=6,
                allow_agent=False, look_for_keys=False
            )
            return True, "SSH-Authentifizierung akzeptiert"
        except paramiko.AuthenticationException:
            return False, "SSH-Auth abgelehnt"
        except Exception as e:
            return None, f"SSH nicht erreichbar ({type(e).__name__})"
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _test_ftp(self, ip, port, username, password):
        """FTP-Login via ftplib (Standardbibliothek)."""
        import ftplib
        ftp = ftplib.FTP()
        try:
            ftp.connect(ip, port, timeout=6)
            ftp.login(username, password)
            return True, "FTP-Login akzeptiert"
        except ftplib.error_perm:
            return False, "FTP-Login abgelehnt"
        except Exception as e:
            return None, f"FTP nicht erreichbar ({type(e).__name__})"
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _test_telnet(self, ip, port, username, password):
        """Telnet-Login über rohen Socket (telnetlib ist ab Python 3.13 entfernt).

        Erfolg wird nur bei einem starken Positiv-Signal gemeldet (Shell-Prompt),
        um Falschmeldungen zu vermeiden.
        """
        import socket
        try:
            sock = socket.create_connection((ip, port), timeout=6)
        except Exception as e:
            return None, f"Telnet nicht erreichbar ({type(e).__name__})"
        try:
            sock.settimeout(5)

            def recv_until_idle():
                data = b''
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 65536:
                            break
                except socket.timeout:
                    pass
                return data

            banner = recv_until_idle().lower()
            # Auf Login-Aufforderung reagieren
            if b'login' in banner or b'user' in banner or b'username' in banner:
                sock.sendall(username.encode() + b'\r\n')
            else:
                # Kein klarer Login-Prompt -> nicht zuverlässig testbar
                sock.sendall(username.encode() + b'\r\n')
            prompt = recv_until_idle().lower()
            if b'password' in prompt or b'passwort' in prompt:
                sock.sendall(password.encode() + b'\r\n')
            after = recv_until_idle()
            after_l = after.lower()

            fail_markers = [b'incorrect', b'failed', b'denied', b'invalid',
                            b'falsch', b'fehlgeschlagen', b'login:', b'authentication']
            success_markers = [b'$', b'#', b'>', b'welcome', b'last login']

            if any(fm in after_l for fm in fail_markers):
                return False, "Telnet-Login abgelehnt"
            stripped = after.strip()
            if stripped and any(stripped.endswith(sm) or sm in after_l[-40:]
                                for sm in success_markers):
                return True, "Telnet-Shell-Prompt erkannt"
            return None, "Telnet-Antwort nicht eindeutig (manuell prüfen)"
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _test_http(self, ip, port, username, password):
        """HTTP-Login-Versuch via HTTP-Basic-Auth.

        Viele Geräte nutzen formularbasierte Logins, die sich nicht generisch
        testen lassen – in dem Fall wird ``None`` (nicht testbar) zurückgegeben,
        statt einen Erfolg zu erfinden.
        """
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            return None, "requests nicht installiert"

        schemes = ['https', 'http'] if port in (443, 8443) else ['http', 'https']
        last_detail = "kein HTTP-Endpunkt erreichbar"
        for scheme in schemes:
            url = f"{scheme}://{ip}:{port}/"
            try:
                # Erst ohne Auth: verlangt der Server überhaupt Basic-Auth?
                r0 = requests.get(url, timeout=6, verify=False, allow_redirects=False)
            except Exception as e:
                last_detail = f"HTTP nicht erreichbar ({type(e).__name__})"
                continue

            www_auth = r0.headers.get('WWW-Authenticate', '').lower()
            if r0.status_code == 401 and 'basic' in www_auth:
                # Echter Basic-Auth-Test möglich
                try:
                    r = requests.get(url, auth=HTTPBasicAuth(username, password),
                                     timeout=6, verify=False, allow_redirects=False)
                    if r.status_code in (200, 301, 302):
                        return True, "HTTP-Basic-Auth akzeptiert"
                    if r.status_code == 401:
                        return False, "HTTP-Basic-Auth abgelehnt"
                    return None, f"HTTP-Antwort {r.status_code} (unklar)"
                except Exception as e:
                    return None, f"HTTP-Fehler ({type(e).__name__})"
            else:
                # Formular-Login o. Ä. – nicht generisch testbar
                return None, ("kein Basic-Auth (Formular-Login) – "
                              "nutze Dienst 'http-form' für Formular-Logins")
        return None, last_detail

    def _test_http_form(self, ip, port, username, password):
        """Heuristischer Formular-Login (POST) für Web-Oberflächen.

        Sucht ein Login-Formular, sendet die Zugangsdaten und bewertet die
        Antwort. Ergebnis: True nur bei deutlichem Erfolgssignal, sonst False/None.
        """
        try:
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            return None, "requests nicht installiert"
        import re
        from urllib.parse import urljoin

        schemes = ['https', 'http'] if port in (443, 8443) else ['http', 'https']
        fail_markers = ['invalid', 'incorrect', 'failed', 'wrong', 'denied',
                        'ungültig', 'falsch', 'fehlgeschlagen', 'try again',
                        'erneut', 'fehler bei der anmeldung', 'login failed']

        for scheme in schemes:
            base = f"{scheme}://{ip}:{port}/"
            session = requests.Session()
            try:
                r = session.get(base, timeout=8, verify=False)
            except Exception as e:
                last = f"HTTP nicht erreichbar ({type(e).__name__})"
                continue

            html = r.text or ''
            # Erstes Formular mit Passwortfeld suchen
            form_match = None
            for fm in re.finditer(r'<form\b[^>]*>(.*?)</form>', html,
                                  re.IGNORECASE | re.DOTALL):
                if re.search(r'type\s*=\s*["\']?password', fm.group(1), re.IGNORECASE):
                    form_match = fm
                    break
            if not form_match:
                return None, "kein Login-Formular mit Passwortfeld gefunden"

            form_html = form_match.group(0)
            inner = form_match.group(1)

            # action und method ermitteln
            am = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = urljoin(base, am.group(1)) if am and am.group(1) else base
            mm = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = (mm.group(1).lower() if mm else 'post')

            # Eingabefelder einsammeln
            data = {}
            user_field = None
            pass_field = None
            for inp in re.finditer(r'<input\b[^>]*>', inner, re.IGNORECASE):
                tag = inp.group(0)
                nm = re.search(r'name\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if not nm:
                    continue
                name = nm.group(1)
                tm = re.search(r'type\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
                itype = (tm.group(1).lower() if tm else 'text')
                vm = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
                value = vm.group(1) if vm else ''
                if itype == 'password' and pass_field is None:
                    pass_field = name
                elif itype in ('text', 'email') and user_field is None:
                    user_field = name
                else:
                    data[name] = value  # hidden/CSRF-Token etc. beibehalten
            # Fallback-Feldnamen
            if not user_field:
                user_field = 'username'
            if not pass_field:
                pass_field = 'password'
            data[user_field] = username
            data[pass_field] = password

            try:
                if method == 'get':
                    resp = session.get(action, params=data, timeout=8,
                                       verify=False, allow_redirects=False)
                else:
                    resp = session.post(action, data=data, timeout=8,
                                        verify=False, allow_redirects=False)
            except Exception as e:
                return None, f"HTTP-POST-Fehler ({type(e).__name__})"

            body = (resp.text or '').lower()
            got_cookie = bool(resp.cookies) or 'set-cookie' in {k.lower() for k in resp.headers}
            location = resp.headers.get('Location', '')

            # Bewertung
            if any(fm in body for fm in fail_markers):
                return False, "Formular meldet Anmeldefehler"
            if resp.status_code in (301, 302, 303, 307, 308):
                if 'login' not in location.lower():
                    return True, f"Redirect nach Login ({resp.status_code} -> {location or '/'})"
                return False, "Redirect zurück zur Login-Seite"
            if resp.status_code == 200:
                still_login = bool(re.search(r'type\s*=\s*["\']?password', body, re.IGNORECASE))
                if not still_login and got_cookie:
                    return True, "Session-Cookie gesetzt, kein Login-Formular mehr"
                if still_login:
                    return False, "Login-Formular wird erneut angezeigt"
                return None, "Antwort nicht eindeutig (manuell prüfen)"
            return None, f"HTTP-Status {resp.status_code} (unklar)"
        return None, "kein Web-Endpunkt erreichbar"

    def _load_credential_list(self, spec):
        """Macht aus einer Eingabe eine Liste von Werten.

        - existierende Datei -> jede nichtleere Zeile
        - mit Komma -> aufgesplittet
        - sonst -> einzelner Wert (auch leerer String erlaubt)
        """
        if spec is None:
            return ['']
        spec = spec.strip()
        if spec and os.path.isfile(spec):
            try:
                with open(spec, 'r', encoding='utf-8', errors='ignore') as f:
                    items = [line.rstrip('\n\r') for line in f]
                items = [i for i in items if i.strip() != '' or i == '']
                # Leere Trailing-Zeilen entfernen, aber bewusst leere Passwörter zulassen
                items = [i for i in items if i != '' or True]
                cleaned = [i for i in items if i.strip() != '']
                return cleaned if cleaned else ['']
            except Exception as e:
                print(f"{Color.RED}Konnte Datei '{spec}' nicht lesen: {e}{Color.RESET}")
                return [spec]
        if ',' in spec:
            return [s.strip() for s in spec.split(',') if s.strip() != '']
        return [spec]

    def brute_force(self, ip, service, user_spec, pass_spec, port=None,
                    delay=0.0, max_attempts=5000, stop_on_first=True, workers=8):
        """Echter, parallelisierter Brute-Force-Angriff gegen einen Dienst.

        service: ssh | ftp | telnet | http (Basic-Auth) | http-form (Formular)
        user_spec / pass_spec: einzelner Wert, Kommaliste oder Pfad zu einer Wortliste.
        workers: Anzahl paralleler Threads (1 = sequentiell).
        delay: optionale Pause (s) vor jedem Versuch (gegen Rate-Limits/Lockouts).
        """
        import threading
        from concurrent.futures import ThreadPoolExecutor

        try:
            service = (service or '').strip().lower()
            proto_map = {
                'ssh': ('ssh', 22),
                'ftp': ('ftp', 21),
                'telnet': ('telnet', 23),
                'http': ('http', 80),
                'http-basic': ('http', 80),
                'http-form': ('http-form', 80),
            }
            if service not in proto_map:
                print(f"\n{Color.RED}Nicht unterstützter Dienst '{service}'. "
                      f"Erlaubt: ssh, ftp, telnet, http, http-form{Color.RESET}")
                return []

            protocol, default_port = proto_map[service]
            port = int(port) if port else default_port

            usernames = self._load_credential_list(user_spec)
            passwords = self._load_credential_list(pass_spec)

            # Kombinationen aufbauen und auf das Limit begrenzen
            combos = [(u, p) for u in usernames for p in passwords]
            limited = len(combos) > max_attempts
            if limited:
                combos = combos[:max_attempts]
            total = len(combos)
            workers = max(1, min(int(workers), 32))

            print(f"\n{Color.GREEN}Starte Brute-Force gegen {ip}:{port} "
                  f"({service}){Color.RESET}")
            print(f"{Color.BLUE}Benutzer: {len(usernames)} | Passwörter: {len(passwords)} "
                  f"| Kombinationen: {total} | Threads: {workers}{Color.RESET}")
            print(f"{Color.YELLOW}Hinweis: Echte Login-Versuche – nur mit Genehmigung "
                  f"im eigenen Netz! (Abbruch mit Strg+C){Color.RESET}")
            if limited:
                print(f"{Color.YELLOW}Achtung: auf {max_attempts} Versuche begrenzt.{Color.RESET}")

            # Gemeinsamer, thread-sicherer Zustand
            lock = threading.Lock()
            print_lock = threading.Lock()
            stop_event = threading.Event()
            state = {'attempts': 0, 'unreachable': 0}
            found = []                 # (user, pwd, detail)
            found_users = set()        # Benutzer mit bereits gefundenem Treffer
            start = time.time()

            def worker(user, pwd):
                if stop_event.is_set():
                    return
                if stop_on_first and user in found_users:
                    return
                if delay:
                    time.sleep(delay)

                if protocol == 'http-form':
                    result, detail = self._test_http_form(ip, port, user, pwd)
                elif protocol == 'http':
                    result, detail = self._test_http(ip, port, user, pwd)
                else:
                    result, detail = self._test_credential(protocol, ip, port, user, pwd)

                # Zustand aktualisieren und Anzeige-Entscheidungen unter Lock treffen
                with lock:
                    state['attempts'] += 1
                    n = state['attempts']
                    is_hit = (result is True)
                    show_unreachable = False
                    if is_hit:
                        found.append((user, pwd, detail))
                        found_users.add(user)
                    elif result is None:
                        state['unreachable'] += 1
                        show_unreachable = (state['unreachable'] == 1)
                        # Dienst offenbar nicht erreichbar/testbar -> global abbrechen
                        if state['unreachable'] >= max(workers, 5) and not found:
                            stop_event.set()
                    show_progress = (n % 25 == 0)

                if is_hit:
                    with print_lock:
                        print(f"  {Color.RED}>>> TREFFER: {user} / "
                              f"{pwd if pwd else '<leer>'}  ({detail}){Color.RESET}", flush=True)
                elif show_unreachable:
                    with print_lock:
                        print(f"  {Color.YELLOW}nicht testbar: {detail}{Color.RESET}", flush=True)
                if show_progress:
                    with print_lock:
                        print(f"  ... {n}/{total} geprüft ({len(found)} Treffer)", flush=True)

            try:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [executor.submit(worker, u, p) for (u, p) in combos]
                    try:
                        for f in futures:
                            f.result()
                    except KeyboardInterrupt:
                        stop_event.set()
                        print(f"\n{Color.YELLOW}Abbruch – warte auf laufende Threads...{Color.RESET}")
            except KeyboardInterrupt:
                stop_event.set()

            if stop_event.is_set() and not found:
                print(f"\n{Color.YELLOW}Dienst scheint nicht erreichbar/testbar – abgebrochen.{Color.RESET}")

            found_pairs = [(u, p) for (u, p, _d) in found]
            self._print_brute_summary(found_pairs, state['attempts'], start)
            return found_pairs

        except Exception as e:
            logging.error(f"Fehler beim Brute-Force: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Brute-Force: {str(e)}{Color.RESET}")
            return []

    def _print_brute_summary(self, found, attempts, start):
        dur = time.time() - start
        print(f"\n{Color.BLUE}--- Brute-Force abgeschlossen ({attempts} Versuche, "
              f"{dur:.1f}s) ---{Color.RESET}")
        if found:
            print(f"{Color.RED}Gefundene gültige Zugangsdaten:{Color.RESET}")
            for u, p in found:
                print(f"  {Color.RED}{u} / {p if p else '<leer>'}{Color.RESET}")
            print(f"{Color.RED}-> Bitte diese Zugangsdaten ändern!{Color.RESET}")
        else:
            print(f"{Color.GREEN}Keine gültigen Zugangsdaten gefunden.{Color.RESET}")
    
    def _get_default_credentials(self, device_type, services):
        """Gibt Standardanmeldedaten basierend auf Gerätetyp und Diensten zurück"""
        credentials = {}
        
        # Prüfe auf SSH
        if 'ssh' in services.lower():
            credentials['SSH'] = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'root', 'password': 'root'},
                {'username': 'admin', 'password': 'password'}
            ]
        
        # Prüfe auf Telnet
        if 'telnet' in services.lower():
            credentials['Telnet'] = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'root', 'password': 'root'},
                {'username': 'user', 'password': 'user'}
            ]

        # Prüfe auf FTP
        if 'ftp' in services.lower():
            credentials['FTP'] = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'root', 'password': 'root'},
                {'username': 'anonymous', 'password': 'anonymous'},
                {'username': 'ftp', 'password': 'ftp'}
            ]
        
        # Prüfe auf HTTP/HTTPS (Webschnittstellen)
        if 'http' in services.lower():
            credentials['Web'] = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'administrator', 'password': 'password'},
                {'username': 'admin', 'password': '1234'}
            ]
        
        # Spezifische Gerätetypen
        if 'router' in device_type.lower() or 'gateway' in device_type.lower():
            credentials['Router'] = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': 'password'},
                {'username': 'admin', 'password': ''}
            ]
        
        elif 'camera' in device_type.lower():
            credentials['Kamera'] = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': '1234'},
                {'username': 'admin', 'password': 'password'}
            ]
        
        return credentials
    
    def test_port_knocking(self, ip, ports):
        """Führt einen Port-Knocking-Test durch"""
        try:
            print(f"\n{Color.GREEN}Starte Port-Knocking-Test für {ip} mit Sequenz {ports}...{Color.RESET}")
            
            import socket
            
            # Erstelle einen Socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Kurzes Timeout
            
            # Führe die Port-Knocking-Sequenz durch
            for i, port in enumerate(ports):
                try:
                    print(f"  Klopfe an Port {port}...")
                    sock.connect((ip, port))
                    sock.close()
                    print(f"  {Color.YELLOW}Port {port} ist offen.{Color.RESET}")
                except:
                    print(f"  {Color.BLUE}Port {port} ist geschlossen (erwartet).{Color.RESET}")
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                # Kurze Pause zwischen den Klopfversuchen
                time.sleep(0.5)
            
            # Prüfe per echtem nmap-Scan, ob nach der Klopfsequenz ein zuvor
            # verborgener Dienst geöffnet wurde.
            print(f"\n{Color.YELLOW}Prüfe auf versteckte Dienste nach der Klopfsequenz...{Color.RESET}")
            
            # Liste von Ports, die nach dem Klopfen überprüft werden sollen
            check_ports = [22, 23, 80, 443, 8080, 8443]
            
            import nmap
            nm = nmap.PortScanner()
            port_str = ','.join(map(str, check_ports))
            nm.scan(ip, port_str)
            
            if ip in nm.all_hosts():
                for port in check_ports:
                    port_str = str(port)
                    if 'tcp' in nm[ip] and port_str in nm[ip]['tcp']:
                        state = nm[ip]['tcp'][port_str]['state']
                        if state == 'open':
                            print(f"  {Color.GREEN}Port {port} ist jetzt offen! Möglicher versteckter Dienst gefunden.{Color.RESET}")
                            print(f"  Dienst: {nm[ip]['tcp'][port_str]['name']} {nm[ip]['tcp'][port_str].get('product', '')}")
            
            print(f"\n{Color.GREEN}Port-Knocking-Test abgeschlossen.{Color.RESET}")
        
        except Exception as e:
            logging.error(f"Fehler beim Port-Knocking-Test: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Port-Knocking-Test: {str(e)}{Color.RESET}")
    
    def classify_device(self, device_info):
        """Klassifiziert ein Gerät basierend auf seinen Eigenschaften"""
        try:
            # Regelbasierte Klassifikation
            device_type = "Unbekannt"
            
            # Extrahiere relevante Informationen
            services = device_info.get('services', '').lower()
            os_info = device_info.get('os', '').lower()
            vendor = device_info.get('vendor', '').lower()
            hostname = device_info.get('hostname', '').lower()
            
            # Hostname-basierte Klassifikation
            if hostname:
                if any(router in hostname for router in ['router', 'gateway', 'gw', 'ap', 'access-point']):
                    device_type = "Router/Gateway"
                elif any(camera in hostname for camera in ['cam', 'camera', 'ipcam', 'webcam']):
                    device_type = "IP-Kamera"
                elif any(printer in hostname for printer in ['print', 'printer', 'mfp', 'scanner']):
                    device_type = "Drucker"
                elif any(tv in hostname for tv in ['tv', 'television', 'smart-tv', 'roku', 'firetv']):
                    device_type = "Smart-TV"
            
            # Regelbasierte Klassifikation nach Hersteller
            if device_type == "Unbekannt":
                if any(router in vendor for router in ['cisco', 'juniper', 'mikrotik', 'ubiquiti', 'tp-link', 'd-link', 'asus', 'netgear', 'linksys', 'huawei']):
                    device_type = "Router/Gateway"
                elif any(camera in vendor for camera in ['hikvision', 'dahua', 'axis', 'bosch', 'samsung', 'sony', 'vivotek', 'panasonic', 'mobotix']):
                    device_type = "IP-Kamera"
                elif any(printer in vendor for printer in ['hp', 'canon', 'epson', 'brother', 'lexmark', 'xerox', 'kyocera', 'ricoh', 'konica']):
                    device_type = "Drucker"
                elif any(tv in vendor for tv in ['samsung', 'lg', 'sony', 'philips', 'panasonic', 'vizio', 'hisense', 'tcl']):
                    device_type = "Smart-TV"
            
            # Dienst-basierte Klassifikation
            if device_type == "Unbekannt":
                if 'rtsp' in services or 'onvif' in services or 'port 554' in services:
                    device_type = "IP-Kamera"
                elif 'cups' in services or 'ipp' in services or 'port 9100' in services:
                    device_type = "Drucker"
                elif 'mqtt' in services or 'coap' in services:
                    device_type = "IoT-Sensor"
                elif 'upnp' in services or 'dlna' in services or 'port 1900' in services or 'port 8008' in services or 'port 8009' in services:
                    device_type = "Media-Gerät"
                elif 'ssh' in services and 'telnet' in services and ('http' in services or 'https' in services):
                    device_type = "Netzwerkgerät"
                elif 'port 80' in services and 'port 443' in services and 'port 53' in services:
                    device_type = "Router/Gateway"
            
            # OS-basierte Klassifikation
            if device_type == "Unbekannt":
                if 'linux' in os_info:
                    if 'embedded' in os_info or 'busybox' in services:
                        device_type = "Embedded Linux-Gerät"
                    else:
                        device_type = "Linux-Server"
                elif 'windows' in os_info:
                    device_type = "Windows-Gerät"
                elif 'android' in os_info:
                    device_type = "Android-Gerät"
                elif 'ios' in os_info or 'macos' in os_info:
                    device_type = "Apple-Gerät"
            
            return device_type
        
        except Exception as e:
            logging.error(f"Fehler bei der Geräteklassifikation: {str(e)}")
            return "Unbekannt"
    
    def create_behavior_profile(self, ip, days=7):
        """Erstellt ein Verhaltensprofil für ein Gerät basierend auf historischen Daten"""
        try:
            print(f"\n{Color.GREEN}Erstelle Verhaltensprofil für {ip} (letzte {days} Tage)...{Color.RESET}")
            print(f"{Color.YELLOW}HINWEIS: Es liegt keine kontinuierliche Traffic-Erfassung vor. "
                  f"Die folgenden Verhaltenswerte sind BEISPIEL-/DEMODATEN und nicht real "
                  f"gemessen. Für echte Profile wäre eine fortlaufende Netzwerküberwachung "
                  f"(pcap/NetFlow) nötig.{Color.RESET}")
            
            # Berechne das Startdatum
            start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            # Lade Daten aus der Datenbank
            conn = sqlite3.connect(self.db_name)
            
            # Lade Geräteinformationen
            device_df = pd.read_sql_query("SELECT * FROM devices WHERE ip=?", conn, params=(ip,))
            
            if device_df.empty:
                print(f"\n{Color.YELLOW}Gerät mit IP {ip} nicht gefunden.{Color.RESET}")
                conn.close()
                return None
            
            # Lade Verhaltensdaten (simuliert)
            # In einer realen Anwendung würden hier echte Daten geladen werden
            
            # Simuliere einige Verhaltensdaten
            behavior_data = {
                'active_hours': self._simulate_active_hours(),
                'connection_frequency': np.random.randint(10, 100),
                'data_transfer': np.random.randint(1, 1000),
                'common_destinations': self._simulate_destinations(),
                'protocols': self._simulate_protocols()
            }
            
            # Erstelle ein Profil
            profile = {
                'ip': ip,
                'is_demo_data': True,
                'device_type': device_df.iloc[0]['device_type'] if 'device_type' in device_df.columns else 'Unbekannt',
                'active_hours': behavior_data['active_hours'],
                'connection_frequency': f"{behavior_data['connection_frequency']} Verbindungen pro Tag",
                'data_transfer': f"{behavior_data['data_transfer']} MB pro Tag",
                'common_destinations': ', '.join(behavior_data['common_destinations']),
                'protocols': ', '.join(behavior_data['protocols']),
                'created_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Speichere das Profil in der Datenbank
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS behavior_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_ip TEXT,
                    profile_data TEXT,
                    created_date TIMESTAMP
                )
            """)
            
            c.execute("""
                INSERT INTO behavior_profiles (device_ip, profile_data, created_date)
                VALUES (?, ?, ?)
            """, (
                ip,
                json.dumps(profile),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))
            
            conn.commit()
            conn.close()
            
            print(f"\n{Color.GREEN}Verhaltensprofil erstellt und gespeichert.{Color.RESET}")
            
            return profile
        
        except Exception as e:
            logging.error(f"Fehler beim Erstellen des Verhaltensprofils: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Erstellen des Verhaltensprofils: {str(e)}{Color.RESET}")
            return None
    
    def _simulate_active_hours(self):
        """Simuliert aktive Stunden für ein Gerät"""
        # Wähle zufällig 8-16 aktive Stunden
        num_hours = np.random.randint(8, 17)
        hours = sorted(np.random.choice(range(24), size=num_hours, replace=False))
        return [f"{h:02d}:00-{h:02d}:59" for h in hours]
    
    def _simulate_destinations(self):
        """Simuliert häufige Ziele für ein Gerät"""
        destinations = [
            "192.168.0.1", "8.8.8.8", "8.8.4.4", "cloudflare.com",
            "amazon.com", "google.com", "microsoft.com", "apple.com"
        ]
        num_dest = np.random.randint(2, 6)
        return list(np.random.choice(destinations, size=num_dest, replace=False))
    
    def _simulate_protocols(self):
        """Simuliert verwendete Protokolle für ein Gerät"""
        protocols = ["HTTP", "HTTPS", "DNS", "NTP", "SMTP", "DHCP", "MQTT", "CoAP", "SNMP"]
        num_proto = np.random.randint(2, 6)
        return list(np.random.choice(protocols, size=num_proto, replace=False))
        
    def run_nmap_scan(self, target, args=None, show_details=True):
        """Führt einen Nmap-Scan durch und zeigt die Ergebnisse an
        
        Args:
            target (str): Das Ziel des Scans (IP-Adresse oder Netzwerkbereich)
            args (str): Die Nmap-Argumente (optional)
            show_details (bool): Ob detaillierte Informationen angezeigt werden sollen (Standard: True)
            
        Returns:
            dict: Die Scan-Ergebnisse
        """
        try:
            import nmap
            import time
            
            # Standardargumente, wenn keine angegeben wurden
            if not args:
                args = "-sV -O -F"
            
            print(f"\n{Color.GREEN}Starte Nmap-Scan auf {target} mit Argumenten: {args}{Color.RESET}")
            
            # Starte den Scan
            start_time = time.time()
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments=args)
            scan_time = time.time() - start_time
            
            # Konvertiere die Ergebnisse in ein Format für die Anzeige
            scan_results = self.parse_nmap_results(nm, scan_time, args, target)
            
            # Zeige die Ergebnisse an
            self.display_scan_results(scan_results, show_details=show_details)
            
            # Speichere die Ergebnisse in der Datenbank
            self._save_scan_results_to_db(scan_results)
            
            return scan_results
        
        except Exception as e:
            logging.error(f"Fehler beim Nmap-Scan: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Nmap-Scan: {str(e)}{Color.RESET}")
            return {'devices': [], 'scan_time': 0, 'scan_args': args, 'target': target}
            
    def _save_scan_results_to_db(self, scan_results):
        """Speichert die Scan-Ergebnisse in der Datenbank
        
        Args:
            scan_results (dict): Die Ergebnisse des Scans
        """
        try:
            # Verbindung zur Datenbank herstellen
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            
            # Erstelle die Tabellen, falls sie nicht existieren
            c.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    mac TEXT,
                    vendor TEXT,
                    hostname TEXT,
                    os TEXT,
                    device_type TEXT,
                    services TEXT,
                    vulnerabilities TEXT,
                    last_scan TIMESTAMP,
                    UNIQUE(ip)
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    scan_args TEXT,
                    scan_time REAL,
                    devices_found INTEGER,
                    scan_date TIMESTAMP
                )
            ''')
            
            # Speichere die Scan-Historie
            c.execute('''
                INSERT INTO scan_history (target, scan_args, scan_time, devices_found, scan_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                scan_results.get('target', ''),
                scan_results.get('scan_args', ''),
                scan_results.get('scan_time', 0),
                len(scan_results.get('devices', [])),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))
            
            # Speichere die Geräte-Informationen
            for device in scan_results.get('devices', []):
                # Klassifiziere das Gerät
                device_type = self.classify_device(device)
                
                # Konvertiere komplexe Daten in JSON
                services_json = json.dumps(device.get('services', {}))
                vulnerabilities_json = json.dumps(device.get('vulnerabilities', []))
                
                # Füge das Gerät in die Datenbank ein oder aktualisiere es
                c.execute('''
                    INSERT OR REPLACE INTO devices 
                    (ip, mac, vendor, hostname, os, device_type, services, vulnerabilities, last_scan)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device.get('ip', ''),
                    device.get('mac', 'N/A'),
                    device.get('vendor', 'N/A'),
                    device.get('hostname', 'N/A'),
                    device.get('os', 'Unbekannt'),
                    device_type,
                    services_json,
                    vulnerabilities_json,
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
            
            # Commit und schließe die Verbindung
            conn.commit()
            conn.close()
            
            logging.info(f"Scan-Ergebnisse erfolgreich in der Datenbank gespeichert.")
            
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Scan-Ergebnisse in der Datenbank: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Speichern der Ergebnisse: {str(e)}{Color.RESET}")
    
    def parse_nmap_results(self, nmap_results, scan_time, scan_args, target):
        """Konvertiert nmap-Ergebnisse in ein Format für die Anzeige
        
        Args:
            nmap_results (PortScanner): Die Ergebnisse des nmap-Scans
            scan_time (float): Die Dauer des Scans in Sekunden
            scan_args (str): Die verwendeten Scan-Argumente
            target (str): Das Ziel des Scans
            
        Returns:
            dict: Die formatierten Scan-Ergebnisse
        """
        try:
            devices = []
            
            for host in nmap_results.all_hosts():
                device = {
                    'ip': host,
                    'mac': nmap_results[host].get('addresses', {}).get('mac', 'N/A'),
                    'vendor': nmap_results[host].get('vendor', {}).get(nmap_results[host].get('addresses', {}).get('mac', ''), 'N/A'),
                    'hostname': nmap_results[host].get('hostnames', [{'name': 'N/A'}])[0].get('name', 'N/A'),
                    'services': {},
                    'vulnerabilities': [],
                    'scripts': {},
                    'open_ports': []
                }
                
                # Extrahiere OS-Informationen
                if 'osmatch' in nmap_results[host] and nmap_results[host]['osmatch']:
                    device['os'] = nmap_results[host]['osmatch'][0].get('name', 'Unbekannt')
                else:
                    device['os'] = 'Unbekannt'
                
                # Extrahiere Dienste
                if 'tcp' in nmap_results[host]:
                    for port, port_info in nmap_results[host]['tcp'].items():
                        if port_info['state'] == 'open':
                            device['open_ports'].append(port)
                            device['services'][port] = {
                                'name': port_info.get('name', 'Unbekannt'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            }
                            
                            # Extrahiere Script-Ergebnisse
                            if 'script' in port_info:
                                for script_name, script_output in port_info['script'].items():
                                    device['scripts'][f"Port {port} - {script_name}"] = script_output
                
                # Extrahiere UDP-Dienste
                if 'udp' in nmap_results[host]:
                    for port, port_info in nmap_results[host]['udp'].items():
                        if port_info['state'] == 'open':
                            device['open_ports'].append(f"{port}/udp")
                            device['services'][f"{port}/udp"] = {
                                'name': port_info.get('name', 'Unbekannt'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            }
                            
                            # Extrahiere Script-Ergebnisse
                            if 'script' in port_info:
                                for script_name, script_output in port_info['script'].items():
                                    device['scripts'][f"Port {port}/udp - {script_name}"] = script_output
                
                # Extrahiere Schwachstellen aus Skript-Ergebnissen
                for script_name, script_output in device['scripts'].items():
                    # Erweiterte Schwachstellenerkennung für mehr Skript-Typen
                    if any(script_type in script_name.lower() for script_type in ['vulners', 'vuln', 'auth', 'brute', 'default']):
                        # Einfache Heuristik zur Extraktion von Schwachstellen
                        lines = script_output.split('\n')
                        for line in lines:
                            # Erkennung von CVE-IDs
                            if 'CVE-' in line:
                                cve_id = line.split('CVE-')[1].split()[0]
                                cve_id = f"CVE-{cve_id}"
                                severity = 'Hoch' if 'CRITICAL' in line or 'HIGH' in line else 'Mittel'
                                device['vulnerabilities'].append({
                                    'id': cve_id,
                                    'severity': severity,
                                    'description': line.strip()
                                })
                            # Erweiterte Erkennung von Sicherheitsproblemen
                            elif any(keyword in line.lower() for keyword in ['vulnerability', 'exploit', 'weakness', 'security', 'password', 'credentials']):
                                severity = 'Hoch' if any(high in line.lower() for high in ['critical', 'high', 'severe']) else 'Mittel'
                                device['vulnerabilities'].append({
                                    'id': 'SECURITY-ISSUE',
                                    'severity': severity,
                                    'description': line.strip()
                                })
                
                devices.append(device)
            
            return {
                'devices': devices,
                'scan_time': scan_time,
                'scan_args': scan_args,
                'target': target
            }
        
        except Exception as e:
            logging.error(f"Fehler beim Parsen der nmap-Ergebnisse: {str(e)}")
            return {'devices': [], 'scan_time': scan_time, 'scan_args': scan_args, 'target': target}
            
    def display_scan_results(self, scan_results, show_details=True):
        """Zeigt die Ergebnisse eines Netzwerk-Scans an
        
        Args:
            scan_results (dict): Die Ergebnisse des Scans
            show_details (bool): Ob detaillierte Informationen angezeigt werden sollen (Standard: True)
        """
        try:
            # Extrahiere grundlegende Informationen
            devices = scan_results.get('devices', [])
            scan_time = scan_results.get('scan_time', 0)
            scan_args = scan_results.get('scan_args', '')
            target = scan_results.get('target', '')
            
            print(f"\n{Color.GREEN}Scan abgeschlossen in {scan_time:.2f} Sekunden.{Color.RESET}")
            print(f"\n{Color.GREEN}Gefundene Geräte: {len(devices)}{Color.RESET}\n")
            
            if not devices:
                print(f"{Color.YELLOW}Keine Geräte gefunden.{Color.RESET}")
                return
            
            # Zeige Geräteliste
            print(f"{Color.BLUE}{'IP-Adresse':<16} {'MAC-Adresse':<24} {'Hersteller':<16} {'Hostname'}{Color.RESET}")
            print("-" * 80)
            
            for device in devices:
                ip = device.get('ip', 'N/A')
                mac = device.get('mac', 'N/A')
                vendor = device.get('vendor', 'N/A')
                hostname = device.get('hostname', 'N/A')
                
                print(f"{ip:<16} {mac:<24} {vendor:<16} {hostname}")
            
            # Zeige immer detaillierte Informationen an (ohne Nachfrage)
            if show_details:
                for device in devices:
                    ip = device.get('ip', 'N/A')
                    print(f"\n{Color.YELLOW}=== Details für {ip} ==={Color.RESET}")
                    
                    # Zeige Betriebssystem
                    os_info = device.get('os', 'Unbekannt')
                    print(f"OS: {os_info}")
                    
                    # Zeige Dienste
                    services = device.get('services', {})
                    if services:
                        print("Dienste:")
                        for port, service_info in services.items():
                            service_name = service_info.get('name', 'Unbekannt')
                            service_product = service_info.get('product', '')
                            service_version = service_info.get('version', '')
                            service_extra = service_info.get('extrainfo', '')
                            
                            service_details = f"{service_name}"
                            if service_product:
                                service_details += f" - {service_product}"
                            if service_version:
                                service_details += f" {service_version}"
                            if service_extra:
                                service_details += f" ({service_extra})"
                            
                            print(f"  Port {port}: {service_details}")
                    
                    # Zeige Schwachstellen, wenn vorhanden
                    vulnerabilities = device.get('vulnerabilities', [])
                    if vulnerabilities:
                        print(f"\n{Color.RED}Gefundene Schwachstellen:{Color.RESET}")
                        for vuln in vulnerabilities:
                            vuln_id = vuln.get('id', 'N/A')
                            vuln_severity = vuln.get('severity', 'Unbekannt')
                            vuln_description = vuln.get('description', 'Keine Beschreibung verfügbar')
                            
                            print(f"  - {vuln_id} ({vuln_severity}): {vuln_description}")
                    
                    # Zeige offene Ports
                    open_ports = device.get('open_ports', [])
                    if open_ports and not services:  # Nur anzeigen, wenn keine detaillierten Dienste verfügbar sind
                        print("\nOffene Ports:")
                        for port in open_ports:
                            print(f"  - {port}")
                    
                    # Zeige Script-Ergebnisse, wenn vorhanden
                    scripts = device.get('scripts', {})
                    if scripts:
                        print(f"\n{Color.BLUE}Script-Ergebnisse:{Color.RESET}")
                        for script_name, script_output in scripts.items():
                            print(f"\n  {script_name}:")
                            # Begrenze die Ausgabe auf 10 Zeilen pro Skript
                            lines = script_output.split('\n')[:10]
                            for line in lines:
                                print(f"    {line}")
                            if len(script_output.split('\n')) > 10:
                                print(f"    ... [weitere {len(script_output.split('\n')) - 10} Zeilen]")
        
        except Exception as e:
            logging.error(f"Fehler bei der Anzeige der Scan-Ergebnisse: {str(e)}")
            print(f"\n{Color.RED}Fehler bei der Anzeige der Ergebnisse: {str(e)}{Color.RESET}")
    
    def run_scan_profile(self, target, profile_name=None):
        """Führt einen Scan mit einem vordefinierten Profil durch
        
        Args:
            target (str): Das Ziel des Scans (IP-Adresse oder Netzwerkbereich)
            profile_name (str): Der Name des Profils (optional)
            
        Returns:
            dict: Die Scan-Ergebnisse
        """
        # Vordefinierte Profile
        profiles = {
            'quick': '-sV -F',
            'standard': '-sS -sV -O',
            'full': '-sS -sV -O -p-',
            'full_pentest': '-sS -sV -O -p- --script=default,vuln,auth,brute --script-timeout 5m',
            'stealth': '-sS -T2',
            'udp': '-sU -sV --top-ports 100',
            'comprehensive': '-sS -sU -sV -O -p- --script=default',
            'vulnerability': '-sV --script=vuln',
            'web': '-sV -p 80,443,8080,8443 --script=http-*'
        }
        
        # Wenn kein Profil angegeben wurde, zeige die verfügbaren Profile an
        if not profile_name:
            print(f"\n{Color.YELLOW}Verfügbare Profile:{Color.RESET}")
            for name, args in profiles.items():
                print(f"  - {name}: {args}")
            print(f"\n{Color.YELLOW}Verwende Standardprofil: 'standard'{Color.RESET}")
            profile_name = 'standard'
        
        # Wenn das Profil nicht existiert, verwende das Standardprofil
        if profile_name not in profiles:
            print(f"\n{Color.YELLOW}Profil '{profile_name}' nicht gefunden. Verwende Standardprofil: 'standard'{Color.RESET}")
            profile_name = 'standard'
        
        # Hole die Argumente für das Profil
        args = profiles[profile_name]
        
        print(f"\n{Color.GREEN}Verwende Profil: {profile_name} mit Argumenten: {args}{Color.RESET}")
        
        # Führe den Scan durch
        return self.run_nmap_scan(target, args, show_details=True)