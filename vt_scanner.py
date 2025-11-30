#!/usr/bin/env python3
"""
VirusTotal Automated Scanner - Main Module
Scans files, URLs, domains, and IPs using VirusTotal API
"""

import requests
import hashlib
import time
import json
from typing import Dict, List, Optional
from datetime import datetime
import os


class VirusTotalScanner:
    """Main class for VirusTotal scanning operations"""
    
    def __init__(self, api_key: str):
        """Initialize scanner with API key"""
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        self.rate_limit_delay = 15  # Free API: 4 requests per minute
        
    def scan_file(self, filepath: str) -> Dict:
        """Scan a file using VirusTotal"""
        print(f"[*] Scanning file: {filepath}")
        
        if not os.path.exists(filepath):
            return {"error": f"File not found: {filepath}"}
        
        # Calculate file hash first
        file_hash = self._calculate_file_hash(filepath)
        print(f"[*] File SHA-256: {file_hash}")
        
        # Check if file already scanned
        existing_report = self.get_file_report(file_hash)
        if existing_report and 'error' not in existing_report:
            print("[+] File already scanned, retrieving existing report")
            return existing_report
        
        # Upload file for scanning
        print("[*] Uploading file to VirusTotal...")
        url = f"{self.base_url}/files"
        
        try:
            with open(filepath, 'rb') as f:
                files = {"file": (os.path.basename(filepath), f)}
                response = requests.post(url, headers=self.headers, files=files)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                print(f"[+] File uploaded successfully. Analysis ID: {analysis_id}")
                
                # Wait for analysis to complete
                return self._wait_for_analysis(analysis_id)
            else:
                return {"error": f"Upload failed: {response.status_code} - {response.text}"}
                
        except Exception as e:
            return {"error": f"Error scanning file: {str(e)}"}
    
    def scan_url(self, url: str) -> Dict:
        """Scan a URL using VirusTotal"""
        print(f"[*] Scanning URL: {url}")
        
        endpoint = f"{self.base_url}/urls"
        payload = {"url": url}
        
        try:
            response = requests.post(endpoint, headers=self.headers, data=payload)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                print(f"[+] URL submitted successfully. Analysis ID: {analysis_id}")
                
                # Wait for analysis to complete
                return self._wait_for_analysis(analysis_id)
            else:
                return {"error": f"URL scan failed: {response.status_code} - {response.text}"}
                
        except Exception as e:
            return {"error": f"Error scanning URL: {str(e)}"}
    
    def scan_domain(self, domain: str) -> Dict:
        """Get domain report from VirusTotal"""
        print(f"[*] Scanning domain: {domain}")
        
        url = f"{self.base_url}/domains/{domain}"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_domain_report(data)
            else:
                return {"error": f"Domain scan failed: {response.status_code} - {response.text}"}
                
        except Exception as e:
            return {"error": f"Error scanning domain: {str(e)}"}
    
    def scan_ip(self, ip_address: str) -> Dict:
        """Get IP address report from VirusTotal"""
        print(f"[*] Scanning IP: {ip_address}")
        
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_ip_report(data)
            else:
                return {"error": f"IP scan failed: {response.status_code} - {response.text}"}
                
        except Exception as e:
            return {"error": f"Error scanning IP: {str(e)}"}
    
    def get_file_report(self, file_hash: str) -> Dict:
        """Get existing file report by hash"""
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_file_report(data)
            elif response.status_code == 404:
                return {"error": "File not found in VirusTotal database"}
            else:
                return {"error": f"Failed to get report: {response.status_code}"}
                
        except Exception as e:
            return {"error": f"Error getting file report: {str(e)}"}
    
    def _wait_for_analysis(self, analysis_id: str, max_wait: int = 300) -> Dict:
        """Wait for analysis to complete"""
        url = f"{self.base_url}/analyses/{analysis_id}"
        start_time = time.time()
        
        print("[*] Waiting for analysis to complete...")
        
        while time.time() - start_time < max_wait:
            try:
                response = requests.get(url, headers=self.headers)
                
                if response.status_code == 200:
                    data = response.json()
                    status = data['data']['attributes']['status']
                    
                    if status == 'completed':
                        print("[+] Analysis completed!")
                        return self._parse_analysis_report(data)
                    else:
                        print(f"[*] Status: {status}... waiting")
                        time.sleep(self.rate_limit_delay)
                else:
                    return {"error": f"Failed to check status: {response.status_code}"}
                    
            except Exception as e:
                return {"error": f"Error waiting for analysis: {str(e)}"}
        
        return {"error": "Analysis timeout"}
    
    def _parse_file_report(self, data: Dict) -> Dict:
        """Parse file scan report"""
        attributes = data['data']['attributes']
        stats = attributes['last_analysis_stats']
        
        report = {
            'scan_type': 'file',
            'scan_date': attributes.get('last_analysis_date', 'Unknown'),
            'file_name': attributes.get('meaningful_name', 'Unknown'),
            'file_size': attributes.get('size', 0),
            'file_type': attributes.get('type_description', 'Unknown'),
            'md5': attributes.get('md5', ''),
            'sha1': attributes.get('sha1', ''),
            'sha256': attributes.get('sha256', ''),
            'detection_stats': stats,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'total_engines': sum(stats.values()),
            'threat_label': attributes.get('popular_threat_classification', {}),
            'tags': attributes.get('tags', []),
            'detections': self._extract_detections(attributes.get('last_analysis_results', {})),
            'verdict': self._determine_verdict(stats)
        }
        
        return report
    
    def _parse_analysis_report(self, data: Dict) -> Dict:
        """Parse analysis report"""
        attributes = data['data']['attributes']
        stats = attributes.get('stats', {})
        
        report = {
            'scan_type': 'analysis',
            'scan_date': datetime.now().isoformat(),
            'status': attributes.get('status', 'unknown'),
            'detection_stats': stats,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'total_engines': sum(stats.values()) if stats else 0,
            'results': attributes.get('results', {}),
            'verdict': self._determine_verdict(stats)
        }
        
        return report
    
    def _parse_domain_report(self, data: Dict) -> Dict:
        """Parse domain scan report"""
        attributes = data['data']['attributes']
        stats = attributes.get('last_analysis_stats', {})
        
        report = {
            'scan_type': 'domain',
            'domain': data['data']['id'],
            'scan_date': attributes.get('last_analysis_date', 'Unknown'),
            'reputation': attributes.get('reputation', 0),
            'detection_stats': stats,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'total_engines': sum(stats.values()) if stats else 0,
            'categories': attributes.get('categories', {}),
            'whois': attributes.get('whois', 'Not available'),
            'registrar': attributes.get('registrar', 'Unknown'),
            'creation_date': attributes.get('creation_date', 'Unknown'),
            'last_update_date': attributes.get('last_update_date', 'Unknown'),
            'verdict': self._determine_verdict(stats)
        }
        
        return report
    
    def _parse_ip_report(self, data: Dict) -> Dict:
        """Parse IP address scan report"""
        attributes = data['data']['attributes']
        stats = attributes.get('last_analysis_stats', {})
        
        report = {
            'scan_type': 'ip',
            'ip_address': data['data']['id'],
            'scan_date': attributes.get('last_analysis_date', 'Unknown'),
            'reputation': attributes.get('reputation', 0),
            'detection_stats': stats,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'total_engines': sum(stats.values()) if stats else 0,
            'country': attributes.get('country', 'Unknown'),
            'asn': attributes.get('asn', 'Unknown'),
            'as_owner': attributes.get('as_owner', 'Unknown'),
            'network': attributes.get('network', 'Unknown'),
            'verdict': self._determine_verdict(stats)
        }
        
        return report
    
    def _extract_detections(self, results: Dict) -> List[Dict]:
        """Extract detection details from results"""
        detections = []
        
        for engine, result in results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                detections.append({
                    'engine': engine,
                    'category': result.get('category'),
                    'result': result.get('result', 'Unknown'),
                    'method': result.get('method', 'Unknown')
                })
        
        return detections
    
    def _determine_verdict(self, stats: Dict) -> str:
        """Determine overall verdict based on detection stats"""
        if not stats:
            return "UNKNOWN"
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        
        if total == 0:
            return "UNKNOWN"
        
        detection_rate = (malicious + suspicious) / total * 100
        
        if malicious > 0:
            if detection_rate >= 50:
                return "MALICIOUS (High Confidence)"
            elif detection_rate >= 20:
                return "MALICIOUS (Medium Confidence)"
            else:
                return "SUSPICIOUS"
        elif suspicious > 0:
            return "SUSPICIOUS"
        else:
            return "CLEAN"
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def batch_scan_files(self, file_list: List[str]) -> List[Dict]:
        """Scan multiple files"""
        results = []
        
        print(f"[*] Starting batch scan of {len(file_list)} files")
        
        for i, filepath in enumerate(file_list, 1):
            print(f"\n[*] Scanning file {i}/{len(file_list)}")
            result = self.scan_file(filepath)
            results.append({
                'file': filepath,
                'result': result
            })
            
            # Rate limiting
            if i < len(file_list):
                print(f"[*] Waiting {self.rate_limit_delay}s for rate limit...")
                time.sleep(self.rate_limit_delay)
        
        return results
    
    def export_report(self, report: Dict, output_file: str):
        """Export report to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report exported to {output_file}")
        except Exception as e:
            print(f"[-] Error exporting report: {str(e)}")


if __name__ == "__main__":
    print("VirusTotal Automated Scanner initialized")
