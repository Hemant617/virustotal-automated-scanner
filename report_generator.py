#!/usr/bin/env python3
"""
Report Generator - Creates HTML reports from VirusTotal scans
"""

from typing import Dict
from datetime import datetime


class ReportGenerator:
    """Generate HTML reports from VirusTotal scan data"""
    
    def generate_html_report(self, report: Dict, output_file: str):
        """Generate comprehensive HTML report"""
        html = self._generate_html(report)
        
        with open(output_file, 'w') as f:
            f.write(html)
    
    def _generate_html(self, report: Dict) -> str:
        """Generate HTML content"""
        scan_type = report.get('scan_type', 'unknown')
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VirusTotal Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 15px 50px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.8em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }}
        
        .header p {{
            opacity: 0.95;
            font-size: 1.2em;
        }}
        
        .verdict-banner {{
            padding: 30px;
            text-align: center;
            font-size: 2em;
            font-weight: bold;
            border-bottom: 3px solid #ddd;
        }}
        
        .verdict-clean {{
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            color: white;
        }}
        
        .verdict-suspicious {{
            background: linear-gradient(135deg, #f2994a 0%, #f2c94c 100%);
            color: white;
        }}
        
        .verdict-malicious {{
            background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
            color: white;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card h3 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .stat-malicious {{
            color: #e74c3c;
        }}
        
        .stat-suspicious {{
            color: #f39c12;
        }}
        
        .stat-clean {{
            color: #27ae60;
        }}
        
        .stat-undetected {{
            color: #95a5a6;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 15px;
            margin-bottom: 25px;
            font-size: 1.8em;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
        }}
        
        .info-item {{
            display: flex;
            justify-content: space-between;
            padding: 12px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }}
        
        .info-label {{
            font-weight: bold;
            color: #667eea;
        }}
        
        .info-value {{
            color: #555;
            word-break: break-all;
        }}
        
        .detection-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .detection-table th {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-size: 1.1em;
        }}
        
        .detection-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }}
        
        .detection-table tr:hover {{
            background: #f5f7fa;
        }}
        
        .detection-table tr:last-child td {{
            border-bottom: none;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .badge-malicious {{
            background: #e74c3c;
            color: white;
        }}
        
        .badge-suspicious {{
            background: #f39c12;
            color: white;
        }}
        
        .progress-bar {{
            width: 100%;
            height: 30px;
            background: #ecf0f1;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            transition: width 0.5s;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 25px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }}
        
        .footer a {{
            color: #667eea;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VirusTotal Scan Report</h1>
            <p>Comprehensive Security Analysis</p>
        </div>
        
        {self._generate_verdict_banner(report)}
        
        <div class="content">
            {self._generate_stats_section(report)}
            {self._generate_info_section(report)}
            {self._generate_detection_section(report)}
        </div>
        
        <div class="footer">
            <p>Generated by VirusTotal Automated Scanner</p>
            <p>Powered by <a href="https://www.virustotal.com" target="_blank">VirusTotal API</a></p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
        return html
    
    def _generate_verdict_banner(self, report: Dict) -> str:
        """Generate verdict banner"""
        verdict = report.get('verdict', 'UNKNOWN')
        
        if 'MALICIOUS' in verdict:
            css_class = 'verdict-malicious'
            icon = '⚠️'
        elif 'SUSPICIOUS' in verdict:
            css_class = 'verdict-suspicious'
            icon = '⚡'
        elif verdict == 'CLEAN':
            css_class = 'verdict-clean'
            icon = '✅'
        else:
            css_class = 'verdict-suspicious'
            icon = '❓'
        
        return f"""
        <div class="verdict-banner {css_class}">
            {icon} {verdict}
        </div>
        """
    
    def _generate_stats_section(self, report: Dict) -> str:
        """Generate statistics section"""
        malicious = report.get('malicious', 0)
        suspicious = report.get('suspicious', 0)
        undetected = report.get('undetected', 0)
        harmless = report.get('harmless', 0)
        total = report.get('total_engines', 0)
        
        detection_rate = ((malicious + suspicious) / total * 100) if total > 0 else 0
        
        return f"""
        <div class="section">
            <h2>📊 Detection Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3 class="stat-malicious">{malicious}</h3>
                    <p>Malicious</p>
                </div>
                <div class="stat-card">
                    <h3 class="stat-suspicious">{suspicious}</h3>
                    <p>Suspicious</p>
                </div>
                <div class="stat-card">
                    <h3 class="stat-clean">{harmless}</h3>
                    <p>Harmless</p>
                </div>
                <div class="stat-card">
                    <h3 class="stat-undetected">{undetected}</h3>
                    <p>Undetected</p>
                </div>
            </div>
            
            <div class="progress-bar">
                <div class="progress-fill" style="width: {detection_rate}%; background: {'#e74c3c' if detection_rate > 20 else '#27ae60'};">
                    {detection_rate:.1f}% Detection Rate
                </div>
            </div>
            
            <p style="text-align: center; color: #666; margin-top: 10px;">
                Scanned by {total} security engines
            </p>
        </div>
        """
    
    def _generate_info_section(self, report: Dict) -> str:
        """Generate information section"""
        scan_type = report.get('scan_type', 'unknown')
        
        if scan_type == 'file':
            return self._generate_file_info(report)
        elif scan_type == 'domain':
            return self._generate_domain_info(report)
        elif scan_type == 'ip':
            return self._generate_ip_info(report)
        else:
            return ""
    
    def _generate_file_info(self, report: Dict) -> str:
        """Generate file information section"""
        return f"""
        <div class="section">
            <h2>📄 File Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">File Name:</span>
                    <span class="info-value">{report.get('file_name', 'Unknown')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">File Size:</span>
                    <span class="info-value">{report.get('file_size', 0)} bytes</span>
                </div>
                <div class="info-item">
                    <span class="info-label">File Type:</span>
                    <span class="info-value">{report.get('file_type', 'Unknown')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">MD5:</span>
                    <span class="info-value">{report.get('md5', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">SHA-1:</span>
                    <span class="info-value">{report.get('sha1', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">SHA-256:</span>
                    <span class="info-value">{report.get('sha256', 'N/A')}</span>
                </div>
            </div>
        </div>
        """
    
    def _generate_domain_info(self, report: Dict) -> str:
        """Generate domain information section"""
        return f"""
        <div class="section">
            <h2>🌐 Domain Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Domain:</span>
                    <span class="info-value">{report.get('domain', 'Unknown')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Reputation:</span>
                    <span class="info-value">{report.get('reputation', 0)}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Registrar:</span>
                    <span class="info-value">{report.get('registrar', 'Unknown')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Creation Date:</span>
                    <span class="info-value">{report.get('creation_date', 'Unknown')}</span>
                </div>
            </div>
        </div>
        """
    
    def _generate_ip_info(self, report: Dict) -> str:
        """Generate IP information section"""
        return f"""
        <div class="section">
            <h2>🌍 IP Address Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">IP Address:</span>
                    <span class="info-value">{report.get('ip_address', 'Unknown')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Reputation:</span>
                    <span class="info-value">{report.get('reputation', 0)}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Country:</span>
                    <span class="info-value">{report.get('country', 'Unknown')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">ASN:</span>
                    <span class="info-value">{report.get('asn', 'Unknown')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">AS Owner:</span>
                    <span class="info-value">{report.get('as_owner', 'Unknown')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Network:</span>
                    <span class="info-value">{report.get('network', 'Unknown')}</span>
                </div>
            </div>
        </div>
        """
    
    def _generate_detection_section(self, report: Dict) -> str:
        """Generate detections section"""
        detections = report.get('detections', [])
        
        if not detections:
            return ""
        
        rows = []
        for detection in detections[:20]:
            badge_class = 'badge-malicious' if detection['category'] == 'malicious' else 'badge-suspicious'
            rows.append(f"""
            <tr>
                <td>{detection['engine']}</td>
                <td><span class="badge {badge_class}">{detection['category'].upper()}</span></td>
                <td>{detection['result']}</td>
            </tr>
            """)
        
        return f"""
        <div class="section">
            <h2>🔍 Detection Details</h2>
            <p style="margin-bottom: 15px; color: #666;">
                Showing {min(len(detections), 20)} of {len(detections)} detections
            </p>
            <table class="detection-table">
                <thead>
                    <tr>
                        <th>Security Engine</th>
                        <th>Category</th>
                        <th>Detection Result</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        """


if __name__ == "__main__":
    print("Report Generator module")
