#!/usr/bin/env python3
"""
Exporter module for IoT Security Scanner
This module handles exporting scan results to various formats
"""

import os
import logging
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

class Exporter:
    """
    Class for exporting scan results to various formats
    """

    def __init__(self, db, config):
        """
        Initialize the Exporter

        Args:
            db: Database instance
            config: ConfigParser instance
        """
        self.db = db
        self.config = config

        # Set up logging
        # Kein eigener Handler: Meldungen über den Root-Logger ausgeben, der in
        # _setup_logging konfiguriert ist (Datei = INFO+, Konsole = WARNING+).
        # Das verhindert doppelte Konsolenausgaben durch einen zweiten Handler.
        self.logger = logging.getLogger('exporter')
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = True
        # Falls von früheren Versionen/Instanzen ein eigener Handler hängt: entfernen
        for _h in list(self.logger.handlers):
            self.logger.removeHandler(_h)

        # Set up Jinja2 environment
        templates_dir = self._get_config_value('exporter', 'templates_dir', 'templates')

        # Create templates directory if it doesn't exist
        if not os.path.exists(templates_dir):
            os.makedirs(templates_dir)
            self.logger.info(f"Created templates directory: {templates_dir}")

        self.env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

        # Check if Metasploit is installed
        self.metasploit_available = self._check_metasploit_installation()
        
        # Get export directory from config
        self.export_dir = self._get_config_value('EXPORT', 'export_path', 'exports')
        
        # Add fallback methods if they don't exist in the database object
        self._add_fallback_methods()
    
    def _get_config_value(self, section, key, default=None):
        """
        Get a value from the config, handling different config object types
        
        Args:
            section (str): The section name
            key (str): The key name
            default: The default value if the key is not found
            
        Returns:
            The value from the config, or the default if not found
        """
        try:
            # Try ConfigParser style
            if hasattr(self.config, 'get'):
                return self.config.get(section, key, fallback=default)
            # Try dictionary style
            elif isinstance(self.config, dict):
                return self.config.get(section, {}).get(key, default)
            # Try attribute style
            elif hasattr(self.config, section) and hasattr(getattr(self.config, section), key):
                return getattr(getattr(self.config, section), key)
            else:
                return default
        except Exception:
            return default
    
    def _get_config_int(self, section, key, default=0):
        """
        Get an integer value from the config, handling different config object types
        
        Args:
            section (str): The section name
            key (str): The key name
            default (int): The default value if the key is not found
            
        Returns:
            int: The value from the config, or the default if not found
        """
        try:
            # Try ConfigParser style
            if hasattr(self.config, 'getint'):
                return self.config.getint(section, key, fallback=default)
            # Try getting as string and converting
            value = self._get_config_value(section, key)
            if value is not None:
                return int(value)
            return default
        except (ValueError, TypeError):
            return default
            
    def _add_fallback_methods(self):
        """
        Add fallback methods to the database object if they don't exist
        """
        # Check if get_vulnerabilities_by_device_id method exists
        if not hasattr(self.db, 'get_vulnerabilities_by_device_id'):
            self.logger.warning("Database object does not have get_vulnerabilities_by_device_id method. Using fallback.")
            # Add the method to the database object
            setattr(self.db, 'get_vulnerabilities_by_device_id', self._fallback_get_vulnerabilities_by_device_id)
            
        # Check if get_open_ports_by_device_id method exists
        if not hasattr(self.db, 'get_open_ports_by_device_id'):
            self.logger.warning("Database object does not have get_open_ports_by_device_id method. Using fallback.")
            # Add the method to the database object
            setattr(self.db, 'get_open_ports_by_device_id', self._fallback_get_open_ports_by_device_id)
            
    def _fallback_get_vulnerabilities_by_device_id(self, device_id):
        """
        Fallback method for getting vulnerabilities by device ID
        
        Args:
            device_id (str): The ID of the device to get vulnerabilities for
            
        Returns:
            list: List of vulnerabilities for the device
        """
        self.logger.info(f"Using fallback method to get vulnerabilities for device_id={device_id}")
        
        try:
            # Try to get vulnerabilities from the database using SQL query
            if hasattr(self.db, 'execute_query'):
                query = f"SELECT * FROM vulnerabilities WHERE device_id = '{device_id}'"
                return self.db.execute_query(query)
            
            # If no execute_query method, try to get from a vulnerabilities table attribute
            if hasattr(self.db, 'vulnerabilities'):
                return [v for v in self.db.vulnerabilities if v.get('device_id') == device_id]
                
            # Last resort: return empty list
            self.logger.warning(f"Could not retrieve vulnerabilities for device_id={device_id}. Returning empty list.")
            return []
            
        except Exception as e:
            self.logger.error(f"Error in fallback get_vulnerabilities_by_device_id: {str(e)}")
            return []
    
    def _fallback_get_open_ports_by_device_id(self, device_id):
        """
        Fallback method for getting open ports by device ID
        
        Args:
            device_id (str): The ID of the device to get open ports for
            
        Returns:
            list: List of open ports for the device
        """
        self.logger.info(f"Using fallback method to get open ports for device_id={device_id}")
        
        try:
            # Try to get open ports from the database using SQL query
            if hasattr(self.db, 'execute_query'):
                query = f"SELECT * FROM open_ports WHERE device_id = '{device_id}'"
                return self.db.execute_query(query)
            
            # If no execute_query method, try to get from an open_ports table attribute
            if hasattr(self.db, 'open_ports'):
                return [p for p in self.db.open_ports if p.get('device_id') == device_id]
                
            # Last resort: return empty list
            self.logger.warning(f"Could not retrieve open ports for device_id={device_id}. Returning empty list.")
            return []
            
        except Exception as e:
            self.logger.error(f"Error in fallback get_open_ports_by_device_id: {str(e)}")
            return []
            
    def _check_metasploit_installation(self):
        """
        Check if Metasploit is installed and available

        Returns:
            bool: True if Metasploit is installed, False otherwise
        """
        try:
            # Try to import the msfrpc module (top-level oder aus modules/)
            try:
                import msfrpc
            except ImportError:
                from modules import msfrpc

            # Get configuration values safely
            host = self._get_config_value('metasploit', 'host', '127.0.0.1')
            port = self._get_config_int('metasploit', 'port', 55553)
            username = self._get_config_value('metasploit', 'username', 'msf')
            password = self._get_config_value('metasploit', 'password', 'msf')

            # Check if the msfrpc server is running
            client = msfrpc.Msfrpc({'host': host, 'port': port})

            # Try to authenticate
            auth_result = client.login(username, password)

            if auth_result['result'] == 'success':
                self.logger.info("Metasploit RPC server is available and authentication successful")
                return True
            else:
                self.logger.info("Metasploit RPC server authentication failed")
                return False

        except ImportError:
            self.logger.info("msfrpc module not found. Metasploit RPC integration disabled.")
            return False
        except Exception as e:
            self.logger.info(f"Metasploit RPC server not reachable: {str(e)}")
            return False

    def generate_html_report(self, device_id=None):
        """
        Generate an HTML report for a specific device or all devices

        Args:
            device_id (str, optional): The ID of the device to generate a report for. 
                                       If None, generate a report for all devices.

        Returns:
            str: HTML content of the report
        """
        self.logger.info(f"Generating HTML report for device_id={device_id}")

        try:
            if device_id:
                return self.generate_device_detail_report(device_id)
            else:
                return self.generate_vulnerability_report()
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            return f"<h1>Error generating HTML report</h1><p>{str(e)}</p>"

    def generate_vulnerability_report(self, device_id=None, devices=None):
        """
        Generate a vulnerability report for a specific device or all devices

        Args:
            device_id (str, optional): The ID of the device to generate a report for.
                                       If None, generate a report for all devices.
            devices (list, optional): Bereits gefilterte Geräteliste (z. B. nur der
                                       letzte Scan). Hat Vorrang vor device_id.

        Returns:
            str: HTML content of the vulnerability report
        """
        self.logger.info(f"Generating vulnerability report for device_id={device_id}")

        try:
            # Get all devices or a specific device
            if devices is not None:
                pass  # bereits übergebene, gefilterte Liste verwenden
            elif device_id:
                devices = [self.db.get_device_by_id(device_id)]
                if not devices[0]:
                    self.logger.error(f"Device with ID {device_id} not found")
                    return f"<h1>Error: Device with ID {device_id} not found</h1>"
            else:
                devices = self.db.get_all_devices()

            # Get vulnerabilities for each device
            devices_with_vulns = []
            total_vulns = 0
            risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}

            for device in devices:
                vulns = self.db.get_vulnerabilities_by_device_id(device['id'])

                # Count vulnerabilities by risk level
                device_risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
                for vuln in vulns:
                    risk_level = vuln.get('risk_level', 'Info')
                    device_risk_counts[risk_level] += 1
                    risk_counts[risk_level] += 1

                # Add risk counts and total count to device
                device['risk_counts'] = device_risk_counts
                device['total_vulns'] = len(vulns)
                device['vulnerabilities'] = vulns
                devices_with_vulns.append(device)
                total_vulns += len(vulns)

            # Render the template
            template = self.env.get_template('vulnerability_report.html')
            return template.render(
                devices=devices_with_vulns,
                total_devices=len(devices_with_vulns),
                total_vulns=total_vulns,
                risk_counts=risk_counts,
                report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                title="Vulnerability Report"
            )

        except Exception as e:
            self.logger.error(f"Error generating vulnerability report: {str(e)}")
            return f"<h1>Error generating vulnerability report</h1><p>{str(e)}</p>"

    def generate_device_detail_report(self, device_id):
        """
        Generate a detailed report for a specific device

        Args:
            device_id (str): The ID of the device to generate a report for

        Returns:
            str: HTML content of the device detail report
        """
        self.logger.info(f"Generating detailed report for device_id={device_id}")

        try:
            # Get device information
            device = self.db.get_device_by_id(device_id)
            if not device:
                self.logger.error(f"Device with ID {device_id} not found")
                return f"<h1>Error: Device with ID {device_id} not found</h1>"

            # Get vulnerabilities for the device
            vulnerabilities = self.db.get_vulnerabilities_by_device_id(device_id)

            # Count vulnerabilities by risk level
            risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            for vuln in vulnerabilities:
                risk_level = vuln.get('risk_level', 'Info')
                risk_counts[risk_level] += 1

            # Get open ports for the device
            open_ports = self.db.get_open_ports_by_device_id(device_id)

            # Render the template
            template = self.env.get_template('detailed_report.html')
            return template.render(
                device=device,
                vulnerabilities=vulnerabilities,
                open_ports=open_ports,
                risk_counts=risk_counts,
                total_vulns=len(vulnerabilities),
                report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                title=f"Detailed Report - {device.get('hostname', device.get('ip_address', 'Unknown Device'))}"
            )

        except Exception as e:
            self.logger.error(f"Error generating device detail report: {str(e)}")
            return f"<h1>Error generating device detail report</h1><p>{str(e)}</p>"

    def generate_vulnerability_detail(self, vuln_id):
        """
        Generate a detailed report for a specific vulnerability

        Args:
            vuln_id (str): The ID of the vulnerability to generate a report for

        Returns:
            str: HTML content of the vulnerability detail report
        """
        self.logger.info(f"Generating vulnerability detail for vuln_id={vuln_id}")

        try:
            # Get vulnerability information
            vulnerability = self.db.get_vulnerability_by_id(vuln_id)
            if not vulnerability:
                self.logger.error(f"Vulnerability with ID {vuln_id} not found")
                return f"<h1>Error: Vulnerability with ID {vuln_id} not found</h1>"

            # Get device information
            device_id = vulnerability.get('device_id')
            device = self.db.get_device_by_id(device_id) if device_id else None

            # Get exploit information if available
            exploit_info = None
            if vulnerability.get('exploit_available') and vulnerability.get('exploit_id'):
                exploit_info = self.db.get_exploit_by_id(vulnerability.get('exploit_id'))

            # Render the template
            template = self.env.get_template('vulnerability_detail.html')
            return template.render(
                vulnerability=vulnerability,
                device=device,
                exploit_info=exploit_info,
                report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                title=f"Vulnerability Detail - {vulnerability.get('name', 'Unknown Vulnerability')}"
            )

        except Exception as e:
            self.logger.error(f"Error generating vulnerability detail: {str(e)}")
            return f"<h1>Error generating vulnerability detail</h1><p>{str(e)}</p>"

    def export_results(self, export_format='all', devices=None, label=None):
        """
        Export scan results in various formats

        Args:
            export_format (str): Format to export (html, csv, pdf, json, xml, or all)
            devices (list, optional): Bereits gefilterte Geräteliste. Wenn None,
                                      werden alle Geräte exportiert.
            label (str, optional): Präfix für die Dateinamen (z. B. 'last_scan'),
                                   um Exporte unterscheidbar zu machen.

        Returns:
            bool: True if export was successful, False otherwise
        """
        self.logger.info(f"Exporting results in format: {export_format}")

        try:
            # Create export directory if it doesn't exist
            if not os.path.exists(self.export_dir):
                os.makedirs(self.export_dir)
                self.logger.info(f"Created export directory: {self.export_dir}")

            # Create timestamp for unique filenames
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pfx = f"{label}_" if label else ""

            # Geräte: gefilterte Liste oder alle
            if devices is None:
                devices = self.db.get_all_devices()

            # Export based on format
            if export_format in ['html', 'all']:
                html_file = os.path.join(self.export_dir, f"{pfx}vulnerability_report_{timestamp}.html")
                with open(html_file, 'w') as f:
                    f.write(self.generate_vulnerability_report(devices=devices))
                self.logger.info(f"Exported HTML report to {html_file}")

            if export_format in ['csv', 'all']:
                csv_file = os.path.join(self.export_dir, f"{pfx}security_report_{timestamp}.csv")
                self.export_to_csv(csv_file, devices=devices)
                self.logger.info(f"Exported CSV report to {csv_file}")

            if export_format in ['pdf', 'all']:
                try:
                    pdf_file = os.path.join(self.export_dir, f"{pfx}security_report_{timestamp}.pdf")
                    self.export_to_pdf(pdf_file)
                    self.logger.info(f"Exported PDF report to {pdf_file}")
                except ImportError:
                    self.logger.warning("WeasyPrint library not installed. PDF export skipped.")

            if export_format in ['json', 'all']:
                json_file = os.path.join(self.export_dir, f"{pfx}security_report_{timestamp}.json")
                self.export_to_json(json_file, devices=devices)
                self.logger.info(f"Exported JSON report to {json_file}")

            if export_format in ['xml', 'all']:
                xml_file = os.path.join(self.export_dir, f"{pfx}security_report_{timestamp}.xml")
                self.export_to_xml(xml_file, devices=devices)
                self.logger.info(f"Exported XML report to {xml_file}")

            # Create a summary file with links to all exports
            summary_file = os.path.join(self.export_dir, f"{pfx}export_summary_{timestamp}.txt")
            with open(summary_file, 'w') as f:
                f.write(f"Export Summary - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                if label:
                    f.write(f"Scope: {label}\n")
                f.write(f"Total devices: {len(devices)}\n\n")
                f.write("Exported files:\n")
                if export_format in ['html', 'all']:
                    f.write(f"- HTML: {pfx}vulnerability_report_{timestamp}.html\n")
                if export_format in ['csv', 'all']:
                    f.write(f"- CSV: {pfx}security_report_{timestamp}.csv\n")
                if export_format in ['pdf', 'all']:
                    f.write(f"- PDF: {pfx}security_report_{timestamp}.pdf\n")
                if export_format in ['json', 'all']:
                    f.write(f"- JSON: {pfx}security_report_{timestamp}.json\n")
                if export_format in ['xml', 'all']:
                    f.write(f"- XML: {pfx}security_report_{timestamp}.xml\n")

            self.logger.info(f"Export completed successfully. Summary at {summary_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error exporting results: {str(e)}")
            return False

    def export_last_scan(self, export_format='all'):
        """Exportiert nur die Ergebnisse des zuletzt durchgeführten Scans.

        Bestimmt den neuesten scan_history-Eintrag und exportiert ausschließlich
        die Geräte, die in dessen Netzwerkbereich liegen.
        """
        self.logger.info("Exporting last scan only")
        try:
            if not hasattr(self.db, 'get_last_scan'):
                self.logger.warning("DB unterstützt get_last_scan nicht.")
                print("Funktion 'letzter Scan' wird von dieser Datenbank nicht unterstützt.")
                return False

            scan = self.db.get_last_scan()
            if not scan:
                print("Kein Scan im Verlauf gefunden. Bitte zuerst einen Scan durchführen.")
                return False

            devices = self.db.get_devices_for_last_scan()
            scan_date = scan.get('scan_date', '?')
            scan_type = scan.get('scan_type', '?')
            net = scan.get('network_range', '?')
            print(f"Letzter Scan: {scan_type} | {net} | {scan_date} "
                  f"-> {len(devices)} Gerät(e)")

            if not devices:
                print("Keine Geräte für den letzten Scan gefunden "
                      "(Netzwerkbereich passt zu keinem gespeicherten Gerät).")
                return False

            return self.export_results(export_format, devices=devices, label="last_scan")
        except Exception as e:
            self.logger.error(f"Error exporting last scan: {str(e)}")
            print(f"Fehler beim Export des letzten Scans: {str(e)}")
            return False
    
    def export_to_csv(self, filename, device_id=None, devices=None):
        """
        Export scan results to a CSV file

        Args:
            filename (str): The name of the file to export to
            device_id (str, optional): The ID of the device to export.
                                       If None, export all devices.
            devices (list, optional): Bereits gefilterte Geräteliste.

        Returns:
            bool: True if export was successful, False otherwise
        """
        self.logger.info(f"Exporting to CSV: {filename}, device_id={device_id}")

        try:
            # Get devices
            if devices is not None:
                pass
            elif device_id:
                devices = [self.db.get_device_by_id(device_id)]
                if not devices[0]:
                    self.logger.error(f"Device with ID {device_id} not found")
                    return False
            else:
                devices = self.db.get_all_devices()

            # Prepare data for CSV
            csv_data = []

            for device in devices:
                # Get vulnerabilities for the device
                vulnerabilities = self.db.get_vulnerabilities_by_device_id(device['id'])

                # If no vulnerabilities, add a row with just device info
                if not vulnerabilities:
                    row = {
                        'Device ID': device['id'],
                        'IP Address': device.get('ip_address', 'Unknown'),
                        'Hostname': device.get('hostname', 'Unknown'),
                        'MAC Address': device.get('mac_address', 'Unknown'),
                        'OS': device.get('os', 'Unknown'),
                        'Vulnerability ID': '',
                        'Vulnerability Name': '',
                        'Risk Level': '',
                        'Description': '',
                        'Solution': '',
                        'Exploit Available': '',
                    }
                    csv_data.append(row)
                else:
                    # Add a row for each vulnerability
                    for vuln in vulnerabilities:
                        row = {
                            'Device ID': device['id'],
                            'IP Address': device.get('ip_address', 'Unknown'),
                            'Hostname': device.get('hostname', 'Unknown'),
                            'MAC Address': device.get('mac_address', 'Unknown'),
                            'OS': device.get('os', 'Unknown'),
                            'Vulnerability ID': vuln.get('id', ''),
                            'Vulnerability Name': vuln.get('name', ''),
                            'Risk Level': vuln.get('risk_level', 'Info'),
                            'Description': vuln.get('description', ''),
                            'Solution': vuln.get('solution', ''),
                            'Exploit Available': 'Yes' if vuln.get('exploit_available') else 'No',
                        }
                        csv_data.append(row)

            # Write to CSV
            if csv_data:
                import csv
                with open(filename, 'w', newline='') as csvfile:
                    fieldnames = csv_data[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in csv_data:
                        writer.writerow(row)

                self.logger.info(f"Successfully exported {len(csv_data)} rows to {filename}")
                return True
            else:
                self.logger.warning("No data to export")
                return False

        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {str(e)}")
            return False

    def export_to_pdf(self, filename, device_id=None):
        """
        Export scan results to a PDF file

        Args:
            filename (str): The name of the file to export to
            device_id (str, optional): The ID of the device to export. 
                                       If None, export all devices.

        Returns:
            bool: True if export was successful, False otherwise
        """
        self.logger.info(f"Exporting to PDF: {filename}, device_id={device_id}")

        try:
            # Generate HTML content
            if device_id:
                html_content = self.generate_device_detail_report(device_id)
            else:
                html_content = self.generate_vulnerability_report()

            # Convert HTML to PDF
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(filename)

            self.logger.info(f"Successfully exported to PDF: {filename}")
            return True

        except ImportError:
            self.logger.error("WeasyPrint library not installed. Cannot export to PDF.")
            return False
        except Exception as e:
            self.logger.error(f"Error exporting to PDF: {str(e)}")
            return False

    def export_to_json(self, filename, device_id=None, devices=None):
        """
        Export scan results to a JSON file

        Args:
            filename (str): The name of the file to export to
            device_id (str, optional): The ID of the device to export.
                                       If None, export all devices.
            devices (list, optional): Bereits gefilterte Geräteliste.

        Returns:
            bool: True if export was successful, False otherwise
        """
        self.logger.info(f"Exporting to JSON: {filename}, device_id={device_id}")

        try:
            # Get devices
            if devices is not None:
                pass
            elif device_id:
                devices = [self.db.get_device_by_id(device_id)]
                if not devices[0]:
                    self.logger.error(f"Device with ID {device_id} not found")
                    return False
            else:
                devices = self.db.get_all_devices()

            # Prepare data structure
            export_data = {
                'report_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'devices': []
            }

            for device in devices:
                # Get vulnerabilities for the device
                vulnerabilities = self.db.get_vulnerabilities_by_device_id(device['id'])

                # Get open ports for the device
                open_ports = self.db.get_open_ports_by_device_id(device['id'])

                # Add device data
                device_data = {
                    'id': str(device['id']),  # Convert to string for JSON compatibility
                    'ip_address': device.get('ip_address', 'Unknown'),
                    'hostname': device.get('hostname', 'Unknown'),
                    'mac_address': device.get('mac_address', 'Unknown'),
                    'os': device.get('os', 'Unknown'),
                    'device_type': device.get('device_type', 'Unknown'),
                    'vendor': device.get('vendor', 'Unknown'),
                    'vulnerabilities': vulnerabilities,
                    'open_ports': open_ports,
                    'total_vulnerabilities': len(vulnerabilities)
                }

                export_data['devices'].append(device_data)

            # Write to JSON file
            import json
            with open(filename, 'w') as json_file:
                json.dump(export_data, json_file, indent=4)

            self.logger.info(f"Successfully exported to JSON: {filename}")
            return True

        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {str(e)}")
            return False

    def _safe_xml_value(self, value):
        """
        Convert a value to a string that is safe for XML
        
        Args:
            value: The value to convert
            
        Returns:
            str: The value as a string safe for XML
        """
        if value is None:
            return ""
        elif isinstance(value, (int, float, bool)):
            return str(value)
        elif isinstance(value, dict):
            return str(value)
        elif isinstance(value, list):
            return str(value)
        else:
            return str(value)
    
    def export_to_xml(self, filename, device_id=None, devices=None):
        """
        Export scan results to an XML file

        Args:
            filename (str): The name of the file to export to
            device_id (str, optional): The ID of the device to export.
                                       If None, export all devices.
            devices (list, optional): Bereits gefilterte Geräteliste.

        Returns:
            bool: True if export was successful, False otherwise
        """
        self.logger.info(f"Exporting to XML: {filename}, device_id={device_id}")

        try:
            # Get devices
            if devices is not None:
                pass
            elif device_id:
                devices = [self.db.get_device_by_id(device_id)]
                if not devices[0]:
                    self.logger.error(f"Device with ID {device_id} not found")
                    return False
            else:
                devices = self.db.get_all_devices()

            # Create XML structure
            from xml.etree.ElementTree import Element, SubElement, tostring
            from xml.dom import minidom

            root = Element('ScanReport')
            root.set('generated', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            devices_elem = SubElement(root, 'Devices')

            for device in devices:
                device_elem = SubElement(devices_elem, 'Device')
                device_elem.set('id', self._safe_xml_value(device.get('id', '')))

                # Add device details
                for key, value in device.items():
                    if key != 'id' and value is not None:
                        # Use a valid XML tag name
                        tag_name = key.replace('_', '').capitalize()
                        if not tag_name[0].isalpha():
                            tag_name = 'X' + tag_name
                        elem = SubElement(device_elem, tag_name)
                        elem.text = self._safe_xml_value(value)

                # Add vulnerabilities
                vulnerabilities = self.db.get_vulnerabilities_by_device_id(device['id'])
                vulns_elem = SubElement(device_elem, 'Vulnerabilities')

                for vuln in vulnerabilities:
                    vuln_elem = SubElement(vulns_elem, 'Vulnerability')
                    vuln_elem.set('id', self._safe_xml_value(vuln.get('id', '')))

                    for key, value in vuln.items():
                        if key != 'id' and key != 'device_id' and value is not None:
                            # Use a valid XML tag name
                            tag_name = key.replace('_', '').capitalize()
                            if not tag_name[0].isalpha():
                                tag_name = 'X' + tag_name
                            elem = SubElement(vuln_elem, tag_name)
                            elem.text = self._safe_xml_value(value)

                # Add open ports
                open_ports = self.db.get_open_ports_by_device_id(device['id'])
                ports_elem = SubElement(device_elem, 'OpenPorts')

                for port in open_ports:
                    port_elem = SubElement(ports_elem, 'Port')
                    port_elem.set('number', self._safe_xml_value(port.get('port_number', '')))

                    for key, value in port.items():
                        if key != 'id' and key != 'device_id' and key != 'port_number' and value is not None:
                            # Use a valid XML tag name
                            tag_name = key.replace('_', '').capitalize()
                            if not tag_name[0].isalpha():
                                tag_name = 'X' + tag_name
                            elem = SubElement(port_elem, tag_name)
                            elem.text = self._safe_xml_value(value)

            # Convert to pretty XML string
            rough_string = tostring(root, 'utf-8')
            reparsed = minidom.parseString(rough_string)
            pretty_xml = reparsed.toprettyxml(indent="  ")

            # Write to file
            with open(filename, 'w') as xml_file:
                xml_file.write(pretty_xml)

            self.logger.info(f"Successfully exported to XML: {filename}")
            return True

        except Exception as e:
            self.logger.error(f"Error exporting to XML: {str(e)}")
            return False

    def generate_executive_summary(self):
        """
        Generate an executive summary of the scan results

        Returns:
            str: HTML content of the executive summary
        """
        self.logger.info("Generating executive summary")

        try:
            # Get all devices
            devices = self.db.get_all_devices()

            # Count devices by type
            device_types = {}
            for device in devices:
                device_type = device.get('device_type', 'Unknown')
                device_types[device_type] = device_types.get(device_type, 0) + 1

            # Count vulnerabilities by risk level
            risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            total_vulns = 0

            # Get top 5 most vulnerable devices
            devices_with_vuln_count = []

            for device in devices:
                vulns = self.db.get_vulnerabilities_by_device_id(device['id'])

                # Count by risk level
                for vuln in vulns:
                    risk_level = vuln.get('risk_level', 'Info')
                    risk_counts[risk_level] += 1

                total_vulns += len(vulns)

                # Add to devices list with vulnerability count
                devices_with_vuln_count.append({
                    'id': device['id'],
                    'ip_address': device.get('ip_address', 'Unknown'),
                    'hostname': device.get('hostname', 'Unknown'),
                    'vuln_count': len(vulns)
                })

            # Sort by vulnerability count and get top 5
            top_vulnerable_devices = sorted(
                devices_with_vuln_count, 
                key=lambda x: x['vuln_count'], 
                reverse=True
            )[:5]

            # Get top 5 most common vulnerabilities
            all_vulns = []
            for device in devices:
                all_vulns.extend(self.db.get_vulnerabilities_by_device_id(device['id']))

            # Count occurrences of each vulnerability by name
            vuln_counts = {}
            for vuln in all_vulns:
                name = vuln.get('name', 'Unknown')
                vuln_counts[name] = vuln_counts.get(name, 0) + 1

            # Sort by count and get top 5
            top_vulnerabilities = [
                {'name': name, 'count': count}
                for name, count in sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)
            ][:5]

            # Render the template
            template = self.env.get_template('executive_summary.html')
            return template.render(
                total_devices=len(devices),
                device_types=device_types,
                risk_counts=risk_counts,
                total_vulns=total_vulns,
                top_vulnerable_devices=top_vulnerable_devices,
                top_vulnerabilities=top_vulnerabilities,
                report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                title="Executive Summary"
            )

        except Exception as e:
            self.logger.error(f"Error generating executive summary: {str(e)}")
            return f"<h1>Error generating executive summary</h1><p>{str(e)}</p>"

    def generate_remediation_plan(self):
        """
        Generate a remediation plan based on the scan results

        Returns:
            str: HTML content of the remediation plan
        """
        self.logger.info("Generating remediation plan")

        try:
            # Get all devices
            devices = self.db.get_all_devices()

            # Get all vulnerabilities
            all_vulns = []
            for device in devices:
                device_vulns = self.db.get_vulnerabilities_by_device_id(device['id'])
                for vuln in device_vulns:
                    vuln['device'] = {
                        'id': device['id'],
                        'ip_address': device.get('ip_address', 'Unknown'),
                        'hostname': device.get('hostname', 'Unknown')
                    }
                    all_vulns.append(vuln)

            # Sort vulnerabilities by risk level
            risk_priority = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            sorted_vulns = sorted(
                all_vulns, 
                key=lambda x: (risk_priority.get(x.get('risk_level', 'Info'), 5), x.get('name', ''))
            )

            # Group vulnerabilities by risk level
            grouped_vulns = {
                'Critical': [],
                'High': [],
                'Medium': [],
                'Low': [],
                'Info': []
            }

            for vuln in sorted_vulns:
                risk_level = vuln.get('risk_level', 'Info')
                grouped_vulns[risk_level].append(vuln)

            # Render the template
            template = self.env.get_template('remediation_plan.html')
            return template.render(
                grouped_vulns=grouped_vulns,
                total_vulns=len(all_vulns),
                report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                title="Remediation Plan"
            )

        except Exception as e:
            self.logger.error(f"Error generating remediation plan: {str(e)}")
            return f"<h1>Error generating remediation plan</h1><p>{str(e)}</p>"

    def serve_reports(self, host='127.0.0.1', port=8080):
        """
        Serve the reports via a web server

        Args:
            host (str): The host to bind the server to
            port (int): The port to bind the server to
        """
        self.logger.info(f"Starting web server on {host}:{port}")

        try:
            from flask import Flask, render_template_string, redirect, url_for, request

            app = Flask(__name__)

            @app.route('/')
            def index():
                return self.generate_vulnerability_report()

            @app.route('/device/<device_id>')
            def device_detail(device_id):
                return self.generate_device_detail_report(device_id)

            @app.route('/vulnerability/<vuln_id>')
            def vulnerability_detail(vuln_id):
                return self.generate_vulnerability_detail(vuln_id)

            @app.route('/executive-summary')
            def executive_summary():
                return self.generate_executive_summary()

            @app.route('/remediation-plan')
            def remediation_plan():
                return self.generate_remediation_plan()

            @app.route('/export', methods=['GET', 'POST'])
            def export():
                if request.method == 'POST':
                    export_format = request.form.get('format', 'html')
                    device_id = request.form.get('device_id', None)

                    if device_id == '':
                        device_id = None

                    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

                    if export_format == 'csv':
                        self.export_to_csv(f"{filename}.csv", device_id)
                        return f"Exported to {filename}.csv"
                    elif export_format == 'pdf':
                        self.export_to_pdf(f"{filename}.pdf", device_id)
                        return f"Exported to {filename}.pdf"
                    elif export_format == 'json':
                        self.export_to_json(f"{filename}.json", device_id)
                        return f"Exported to {filename}.json"
                    elif export_format == 'xml':
                        self.export_to_xml(f"{filename}.xml", device_id)
                        return f"Exported to {filename}.xml"

                # Render export form
                devices = self.db.get_all_devices()
                html = """
                <html>
                <head>
                    <title>Export Report</title>
                    <link rel="stylesheet" href="/static/style.css">
                </head>
                <body>
                    <h1>Export Report</h1>
                    <form method="post">
                        <div class="form-group">
                            <label for="format">Export Format:</label>
                            <select name="format" id="format">
                                <option value="csv">CSV</option>
                                <option value="pdf">PDF</option>
                                <option value="json">JSON</option>
                                <option value="xml">XML</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="device_id">Device (leave empty for all devices):</label>
                            <select name="device_id" id="device_id">
                                <option value="">All Devices</option>
                                {% for device in devices %}
                                <option value="{{ device.id }}">{{ device.hostname or device.ip_address }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <button type="submit">Export</button>
                    </form>
                </body>
                </html>
                """
                return render_template_string(html, devices=devices)

            # Start the server
            app.run(host=host, port=port)

        except ImportError:
            self.logger.error("Flask library not installed. Cannot serve reports.")
        except Exception as e:
            self.logger.error(f"Error serving reports: {str(e)}")

def main():
    """
    Main function to demonstrate the Exporter class
    """
    import argparse
    import configparser

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Export scan results')
    parser.add_argument('--config', default='iot_config.ini', help='Path to config file')
    parser.add_argument('--format', choices=['html', 'csv', 'pdf', 'json', 'xml'], default='html', help='Export format')
    parser.add_argument('--output', help='Output file name')
    parser.add_argument('--device', help='Device ID to export (leave empty for all devices)')
    parser.add_argument('--serve', action='store_true', help='Serve reports via web server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind the server to')

    args = parser.parse_args()

    # Load config
    config = configparser.ConfigParser()
    config.read(args.config)

    # Create exporter
    from modules.database import Database
    db = Database(config)
    exporter = Exporter(db, config)

    # Export or serve
    if args.serve:
        exporter.serve_reports(args.host, args.port)
    else:
        if args.format == 'html':
            if args.device:
                html = exporter.generate_device_detail_report(args.device)
            else:
                html = exporter.generate_vulnerability_report()

            output = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(output, 'w') as f:
                f.write(html)
            print(f"Exported to {output}")

        elif args.format == 'csv':
            output = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            exporter.export_to_csv(output, args.device)

        elif args.format == 'pdf':
            output = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            exporter.export_to_pdf(output, args.device)

        elif args.format == 'json':
            output = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            exporter.export_to_json(output, args.device)

        elif args.format == 'xml':
            output = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
            exporter.export_to_xml(output, args.device)

if __name__ == "__main__":
    main()