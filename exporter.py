#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exporter module for the IoT Netzwerkscanner
Handles exporting scan results to various formats
"""

import os
import json
import csv
import logging
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Union, Any, Tuple

class Exporter:
    """
    Class for exporting scan results to various formats
    """

    def __init__(self, db, config):
        """Initialize the Exporter
        
        Args:
            db: Database instance
            config: Configuration object or dict with export settings
        """
        self.db = db
        self.config = config
        self.logger = logging.getLogger('exporter')
        
        # Get export path from config
        if hasattr(config, 'get'):
            # It's a Config object
            self.export_path = config.get('EXPORT', 'export_path', fallback='exports')
        elif isinstance(config, dict) and 'EXPORT' in config and 'export_path' in config['EXPORT']:
            # It's a dict
            self.export_path = config['EXPORT']['export_path']
        else:
            # Default
            self.export_path = 'exports'
        
        # Create export directory if it doesn't exist
        os.makedirs(self.export_path, exist_ok=True)
    
    def export_devices(self, format_type='csv', filename=None):
        """Export devices to the specified format
        
        Args:
            format_type: Format to export to (csv, json, html, xlsx)
            filename: Optional filename to use
            
        Returns:
            str: Path to the exported file
        """
        # Get devices from database
        devices_df = self.db.get_devices()
        
        if devices_df.empty:
            self.logger.warning("No devices to export")
            return None
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"devices_{timestamp}"
        
        # Export based on format type
        if format_type == 'csv':
            return self._export_to_csv(devices_df, filename)
        elif format_type == 'json':
            return self._export_to_json(devices_df, filename)
        elif format_type == 'html':
            return self._export_to_html(devices_df, filename)
        elif format_type == 'xlsx':
            return self._export_to_excel(devices_df, filename)
        elif format_type == 'all':
            # Export to all formats
            results = {}
            for fmt in ['csv', 'json', 'html', 'xlsx']:
                results[fmt] = getattr(self, f"_export_to_{fmt if fmt != 'xlsx' else 'excel'}")(devices_df, filename)
            return results
        else:
            self.logger.error(f"Unsupported export format: {format_type}")
            return None
    
    def _export_to_csv(self, df, filename):
        """Export dataframe to CSV"""
        filepath = os.path.join(self.export_path, f"{filename}.csv")
        try:
            df.to_csv(filepath, index=False, encoding='utf-8')
            self.logger.info(f"Exported devices to CSV: {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {str(e)}")
            return None
    
    def _export_to_json(self, df, filename):
        """Export dataframe to JSON"""
        filepath = os.path.join(self.export_path, f"{filename}.json")
        try:
            # Convert DataFrame to dict records and handle NaN values
            records = df.replace({pd.NA: None}).to_dict(orient='records')
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(records, f, indent=4, ensure_ascii=False)
                
            self.logger.info(f"Exported devices to JSON: {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {str(e)}")
            return None
    
    def _export_to_html(self, df, filename):
        """Export dataframe to HTML"""
        filepath = os.path.join(self.export_path, f"{filename}.html")
        try:
            # Create a styled HTML table
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>IoT Netzwerkscanner - Device Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #2c3e50; }}
                    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                    th {{ background-color: #3498db; color: white; text-align: left; padding: 8px; }}
                    td {{ border: 1px solid #ddd; padding: 8px; }}
                    tr:nth-child(even) {{ background-color: #f2f2f2; }}
                    tr:hover {{ background-color: #ddd; }}
                    .timestamp {{ color: #7f8c8d; font-size: 0.8em; }}
                </style>
            </head>
            <body>
                <h1>IoT Netzwerkscanner - Device Report</h1>
                <p class="timestamp">Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                {df.to_html(index=False)}
            </body>
            </html>
            """
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            self.logger.info(f"Exported devices to HTML: {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error exporting to HTML: {str(e)}")
            return None
    
    def _export_to_excel(self, df, filename):
        """Export dataframe to Excel"""
        filepath = os.path.join(self.export_path, f"{filename}.xlsx")
        try:
            # Create a Pandas Excel writer using XlsxWriter as the engine
            with pd.ExcelWriter(filepath, engine='xlsxwriter') as writer:
                df.to_excel(writer, sheet_name='Devices', index=False)
                
                # Get the xlsxwriter workbook and worksheet objects
                workbook = writer.book
                worksheet = writer.sheets['Devices']
                
                # Add a header format
                header_format = workbook.add_format({
                    'bold': True,
                    'text_wrap': True,
                    'valign': 'top',
                    'fg_color': '#D7E4BC',
                    'border': 1
                })
                
                # Write the column headers with the defined format
                for col_num, value in enumerate(df.columns.values):
                    worksheet.write(0, col_num, value, header_format)
                    
                # Set column widths
                for i, col in enumerate(df.columns):
                    column_width = max(df[col].astype(str).map(len).max(), len(col)) + 2
                    worksheet.set_column(i, i, column_width)
            
            self.logger.info(f"Exported devices to Excel: {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error exporting to Excel: {str(e)}")
            return None
    
    def export_vulnerabilities(self, device_ip=None, format_type='csv', filename=None):
        """Export vulnerabilities to the specified format
        
        Args:
            device_ip: Optional IP to filter vulnerabilities by device
            format_type: Format to export to (csv, json, html, xlsx)
            filename: Optional filename to use
            
        Returns:
            str: Path to the exported file
        """
        # Get vulnerabilities from database
        vulns_df = self.db.get_vulnerabilities(device_ip)
        
        if vulns_df.empty:
            self.logger.warning("No vulnerabilities to export")
            return None
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            if device_ip:
                filename = f"vulnerabilities_{device_ip}_{timestamp}"
            else:
                filename = f"vulnerabilities_{timestamp}"
        
        # Export based on format type
        if format_type == 'csv':
            return self._export_to_csv(vulns_df, filename)
        elif format_type == 'json':
            return self._export_to_json(vulns_df, filename)
        elif format_type == 'html':
            return self._export_to_html(vulns_df, filename)
        elif format_type == 'xlsx':
            return self._export_to_excel(vulns_df, filename)
        elif format_type == 'all':
            # Export to all formats
            results = {}
            for fmt in ['csv', 'json', 'html', 'xlsx']:
                results[fmt] = getattr(self, f"_export_to_{fmt if fmt != 'xlsx' else 'excel'}")(vulns_df, filename)
            return results
        else:
            self.logger.error(f"Unsupported export format: {format_type}")
            return None
    
    def export_scan_history(self, limit=50, format_type='csv', filename=None):
        """Export scan history to the specified format
        
        Args:
            limit: Maximum number of scan history entries to export
            format_type: Format to export to (csv, json, html, xlsx)
            filename: Optional filename to use
            
        Returns:
            str: Path to the exported file
        """
        # Get scan history from database
        history_df = self.db.get_scan_history(limit)
        
        if history_df.empty:
            self.logger.warning("No scan history to export")
            return None
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scan_history_{timestamp}"
        
        # Export based on format type
        if format_type == 'csv':
            return self._export_to_csv(history_df, filename)
        elif format_type == 'json':
            return self._export_to_json(history_df, filename)
        elif format_type == 'html':
            return self._export_to_html(history_df, filename)
        elif format_type == 'xlsx':
            return self._export_to_excel(history_df, filename)
        elif format_type == 'all':
            # Export to all formats
            results = {}
            for fmt in ['csv', 'json', 'html', 'xlsx']:
                results[fmt] = getattr(self, f"_export_to_{fmt if fmt != 'xlsx' else 'excel'}")(history_df, filename)
            return results
        else:
            self.logger.error(f"Unsupported export format: {format_type}")
            return None