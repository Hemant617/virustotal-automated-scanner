#!/usr/bin/env python3
"""
VirusTotal Automated Scanner - Command Line Interface
"""

import argparse
import sys
import os
from vt_scanner import VirusTotalScanner
from report_generator import ReportGenerator
import json


def load_api_key(args):
    """Load API key from argument or environment variable"""
    api_key = args.api_key or os.environ.get('VT_API_KEY')
    
    if not api_key:
        print("[-] Error: VirusTotal API key required!")
        print("    Set VT_API_KEY environment variable or use --api-key argument")
        print("    Get your API key from: https://www.virustotal.com/gui/my-apikey")
        sys.exit(1)
    
    return api_key


def scan_file_command(args):
    """Handle file scan command"""
    api_key = load_api_key(args)
    scanner = VirusTotalScanner(api_key)
    
    if not os.path.exists(args.file):
        print(f"[-] Error: File not found: {args.file}")
        return 1
    
    print(f"\n{'='*80}")
    print("VIRUSTOTAL FILE SCAN")
    print(f"{'='*80}\n")
    
    report = scanner.scan_file(args.file)
    
    if 'error' in report:
        print(f"[-] Error: {report['error']}")
        return 1
    
    # Display results
    display_scan_results(report)
    
    # Export if requested
    if args.output:
        scanner.export_report(report, args.output)
    
    if args.html:
        generator = ReportGenerator()
        generator.generate_html_report(report, args.html)
        print(f"[+] HTML report generated: {args.html}")
    
    return 0


def scan_url_command(args):
    """Handle URL scan command"""
    api_key = load_api_key(args)
    scanner = VirusTotalScanner(api_key)
    
    print(f"\n{'='*80}")
    print("VIRUSTOTAL URL SCAN")
    print(f"{'='*80}\n")
    
    report = scanner.scan_url(args.url)
    
    if 'error' in report:
        print(f"[-] Error: {report['error']}")
        return 1
    
    display_scan_results(report)
    
    if args.output:
        scanner.export_report(report, args.output)
    
    if args.html:
        generator = ReportGenerator()
        generator.generate_html_report(report, args.html)
        print(f"[+] HTML report generated: {args.html}")
    
    return 0


def scan_domain_command(args):
    """Handle domain scan command"""
    api_key = load_api_key(args)
    scanner = VirusTotalScanner(api_key)
    
    print(f"\n{'='*80}")
    print("VIRUSTOTAL DOMAIN SCAN")
    print(f"{'='*80}\n")
    
    report = scanner.scan_domain(args.domain)
    
    if 'error' in report:
        print(f"[-] Error: {report['error']}")
        return 1
    
    display_domain_results(report)
    
    if args.output:
        scanner.export_report(report, args.output)
    
    if args.html:
        generator = ReportGenerator()
        generator.generate_html_report(report, args.html)
        print(f"[+] HTML report generated: {args.html}")
    
    return 0


def scan_ip_command(args):
    """Handle IP scan command"""
    api_key = load_api_key(args)
    scanner = VirusTotalScanner(api_key)
    
    print(f"\n{'='*80}")
    print("VIRUSTOTAL IP SCAN")
    print(f"{'='*80}\n")
    
    report = scanner.scan_ip(args.ip)
    
    if 'error' in report:
        print(f"[-] Error: {report['error']}")
        return 1
    
    display_ip_results(report)
    
    if args.output:
        scanner.export_report(report, args.output)
    
    if args.html:
        generator = ReportGenerator()
        generator.generate_html_report(report, args.html)
        print(f"[+] HTML report generated: {args.html}")
    
    return 0


def batch_scan_command(args):
    """Handle batch scan command"""
    api_key = load_api_key(args)
    scanner = VirusTotalScanner(api_key)
    
    # Read file list
    if not os.path.exists(args.list):
        print(f"[-] Error: File list not found: {args.list}")
        return 1
    
    with open(args.list, 'r') as f:
        files = [line.strip() for line in f if line.strip()]
    
    print(f"\n{'='*80}")
    print(f"VIRUSTOTAL BATCH SCAN - {len(files)} files")
    print(f"{'='*80}\n")
    
    results = scanner.batch_scan_files(files)
    
    # Display summary
    print(f"\n{'='*80}")
    print("BATCH SCAN SUMMARY")
    print(f"{'='*80}\n")
    
    malicious_count = 0
    suspicious_count = 0
    clean_count = 0
    
    for item in results:
        report = item['result']
        if 'error' not in report:
            verdict = report.get('verdict', 'UNKNOWN')
            if 'MALICIOUS' in verdict:
                malicious_count += 1
            elif 'SUSPICIOUS' in verdict:
                suspicious_count += 1
            elif verdict == 'CLEAN':
                clean_count += 1
    
    print(f"Total Files Scanned: {len(results)}")
    print(f"Malicious: {malicious_count}")
    print(f"Suspicious: {suspicious_count}")
    print(f"Clean: {clean_count}")
    
    # Export combined report
    if args.output:
        combined_report = {
            'scan_type': 'batch',
            'total_files': len(results),
            'summary': {
                'malicious': malicious_count,
                'suspicious': suspicious_count,
                'clean': clean_count
            },
            'results': results
        }
        scanner.export_report(combined_report, args.output)
    
    return 0


def display_scan_results(report: dict):
    """Display scan results in console"""
    print(f"Scan Type: {report.get('scan_type', 'Unknown').upper()}")
    print(f"Verdict: {report.get('verdict', 'UNKNOWN')}")
    print(f"\nDetection Statistics:")
    print(f"  Malicious: {report.get('malicious', 0)}/{report.get('total_engines', 0)}")
    print(f"  Suspicious: {report.get('suspicious', 0)}/{report.get('total_engines', 0)}")
    print(f"  Undetected: {report.get('undetected', 0)}/{report.get('total_engines', 0)}")
    print(f"  Harmless: {report.get('harmless', 0)}/{report.get('total_engines', 0)}")
    
    if 'file_name' in report:
        print(f"\nFile Information:")
        print(f"  Name: {report.get('file_name', 'Unknown')}")
        print(f"  Size: {report.get('file_size', 0)} bytes")
        print(f"  Type: {report.get('file_type', 'Unknown')}")
        print(f"  SHA-256: {report.get('sha256', 'Unknown')}")
    
    if report.get('detections'):
        print(f"\nDetections ({len(report['detections'])}):")
        for detection in report['detections'][:10]:
            print(f"  - {detection['engine']}: {detection['result']} ({detection['category']})")
        
        if len(report['detections']) > 10:
            print(f"  ... and {len(report['detections']) - 10} more")


def display_domain_results(report: dict):
    """Display domain scan results"""
    print(f"Domain: {report.get('domain', 'Unknown')}")
    print(f"Verdict: {report.get('verdict', 'UNKNOWN')}")
    print(f"Reputation: {report.get('reputation', 0)}")
    print(f"\nDetection Statistics:")
    print(f"  Malicious: {report.get('malicious', 0)}/{report.get('total_engines', 0)}")
    print(f"  Suspicious: {report.get('suspicious', 0)}/{report.get('total_engines', 0)}")
    print(f"  Undetected: {report.get('undetected', 0)}/{report.get('total_engines', 0)}")
    print(f"  Harmless: {report.get('harmless', 0)}/{report.get('total_engines', 0)}")
    
    print(f"\nDomain Information:")
    print(f"  Registrar: {report.get('registrar', 'Unknown')}")
    print(f"  Creation Date: {report.get('creation_date', 'Unknown')}")
    
    if report.get('categories'):
        print(f"\nCategories:")
        for source, category in list(report['categories'].items())[:5]:
            print(f"  - {source}: {category}")


def display_ip_results(report: dict):
    """Display IP scan results"""
    print(f"IP Address: {report.get('ip_address', 'Unknown')}")
    print(f"Verdict: {report.get('verdict', 'UNKNOWN')}")
    print(f"Reputation: {report.get('reputation', 0)}")
    print(f"\nDetection Statistics:")
    print(f"  Malicious: {report.get('malicious', 0)}/{report.get('total_engines', 0)}")
    print(f"  Suspicious: {report.get('suspicious', 0)}/{report.get('total_engines', 0)}")
    print(f"  Undetected: {report.get('undetected', 0)}/{report.get('total_engines', 0)}")
    print(f"  Harmless: {report.get('harmless', 0)}/{report.get('total_engines', 0)}")
    
    print(f"\nNetwork Information:")
    print(f"  Country: {report.get('country', 'Unknown')}")
    print(f"  ASN: {report.get('asn', 'Unknown')}")
    print(f"  AS Owner: {report.get('as_owner', 'Unknown')}")
    print(f"  Network: {report.get('network', 'Unknown')}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='VirusTotal Automated Scanner - Security scanning tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a file
  python cli.py scan-file suspicious.exe --api-key YOUR_API_KEY
  
  # Scan a URL
  python cli.py scan-url https://example.com -o report.json
  
  # Scan a domain
  python cli.py scan-domain example.com --html report.html
  
  # Scan an IP address
  python cli.py scan-ip 8.8.8.8
  
  # Batch scan multiple files
  python cli.py batch-scan files.txt -o batch_report.json
  
Environment Variables:
  VT_API_KEY    VirusTotal API key (alternative to --api-key)
        """
    )
    
    parser.add_argument('--api-key', help='VirusTotal API key')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan file command
    file_parser = subparsers.add_parser('scan-file', help='Scan a file')
    file_parser.add_argument('file', help='Path to file to scan')
    file_parser.add_argument('-o', '--output', help='Output JSON report file')
    file_parser.add_argument('--html', help='Generate HTML report')
    
    # Scan URL command
    url_parser = subparsers.add_parser('scan-url', help='Scan a URL')
    url_parser.add_argument('url', help='URL to scan')
    url_parser.add_argument('-o', '--output', help='Output JSON report file')
    url_parser.add_argument('--html', help='Generate HTML report')
    
    # Scan domain command
    domain_parser = subparsers.add_parser('scan-domain', help='Scan a domain')
    domain_parser.add_argument('domain', help='Domain to scan')
    domain_parser.add_argument('-o', '--output', help='Output JSON report file')
    domain_parser.add_argument('--html', help='Generate HTML report')
    
    # Scan IP command
    ip_parser = subparsers.add_parser('scan-ip', help='Scan an IP address')
    ip_parser.add_argument('ip', help='IP address to scan')
    ip_parser.add_argument('-o', '--output', help='Output JSON report file')
    ip_parser.add_argument('--html', help='Generate HTML report')
    
    # Batch scan command
    batch_parser = subparsers.add_parser('batch-scan', help='Batch scan multiple files')
    batch_parser.add_argument('list', help='Text file with list of files to scan')
    batch_parser.add_argument('-o', '--output', help='Output JSON report file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute command
    if args.command == 'scan-file':
        return scan_file_command(args)
    elif args.command == 'scan-url':
        return scan_url_command(args)
    elif args.command == 'scan-domain':
        return scan_domain_command(args)
    elif args.command == 'scan-ip':
        return scan_ip_command(args)
    elif args.command == 'batch-scan':
        return batch_scan_command(args)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
