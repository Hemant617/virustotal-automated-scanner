# 📖 Detailed Usage Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Scanning Files](#scanning-files)
3. [Scanning URLs](#scanning-urls)
4. [Scanning Domains](#scanning-domains)
5. [Scanning IP Addresses](#scanning-ip-addresses)
6. [Batch Scanning](#batch-scanning)
7. [Understanding Reports](#understanding-reports)
8. [API Rate Limits](#api-rate-limits)
9. [Troubleshooting](#troubleshooting)

## Getting Started

### Setting Up API Key

**Option 1: Environment Variable (Recommended)**
```bash
# Linux/Mac
export VT_API_KEY="your_api_key_here"

# Windows (Command Prompt)
set VT_API_KEY=your_api_key_here

# Windows (PowerShell)
$env:VT_API_KEY="your_api_key_here"
```

**Option 2: .env File**
```bash
# Copy example file
cp .env.example .env

# Edit .env and add your API key
nano .env
```

**Option 3: Command Line**
```bash
python cli.py scan-file file.exe --api-key YOUR_API_KEY
```

## Scanning Files

### Basic File Scan
```bash
python cli.py scan-file suspicious.exe
```

### Scan with JSON Report
```bash
python cli.py scan-file malware.pdf -o report.json
```

### Scan with HTML Report
```bash
python cli.py scan-file document.docx --html report.html
```

### Scan with Both Reports
```bash
python cli.py scan-file archive.zip -o report.json --html report.html
```

### What Gets Scanned?
- File content (uploaded to VirusTotal)
- File hash (MD5, SHA-1, SHA-256)
- File metadata (size, type)
- Checked against 70+ antivirus engines

### File Size Limits
- Free API: 32 MB per file
- Premium API: 650 MB per file

## Scanning URLs

### Basic URL Scan
```bash
python cli.py scan-url https://example.com
```

### Scan Suspicious Website
```bash
python cli.py scan-url https://suspicious-site.com -o url_report.json
```

### What Gets Checked?
- URL reputation
- Malicious content detection
- Phishing detection
- Malware distribution
- Historical data

## Scanning Domains

### Basic Domain Scan
```bash
python cli.py scan-domain example.com
```

### Domain with Full Report
```bash
python cli.py scan-domain suspicious-domain.com --html domain_report.html
```

### Information Retrieved
- Domain reputation score
- WHOIS information
- Registrar details
- Creation/update dates
- Category classifications
- Historical detections

## Scanning IP Addresses

### Basic IP Scan
```bash
python cli.py scan-ip 192.168.1.100
```

### IP with Reports
```bash
python cli.py scan-ip 8.8.8.8 -o ip_report.json --html ip_report.html
```

### Information Retrieved
- IP reputation score
- Geolocation (country)
- ASN (Autonomous System Number)
- AS Owner
- Network information
- Historical detections

## Batch Scanning

### Create File List
Create a text file (e.g., `files.txt`) with one file path per line:
```
/path/to/file1.exe
/path/to/file2.pdf
/path/to/file3.docx
/home/user/downloads/archive.zip
```

### Run Batch Scan
```bash
python cli.py batch-scan files.txt -o batch_report.json
```

### Batch Scan Features
- Automatic rate limiting
- Progress tracking
- Combined summary report
- Individual file results
- Error handling per file

### Batch Scan Output
```
================================================================================
VIRUSTOTAL BATCH SCAN - 4 files
================================================================================

[*] Scanning file 1/4
[*] Scanning file: /path/to/file1.exe
...
[*] Waiting 15s for rate limit...

BATCH SCAN SUMMARY
================================================================================
Total Files Scanned: 4
Malicious: 1
Suspicious: 1
Clean: 2
```

## Understanding Reports

### Console Output

**Verdict Types:**
- ✅ CLEAN - No threats detected
- ⚡ SUSPICIOUS - Some engines flagged
- ⚠️ MALICIOUS (Low/Medium/High) - Threat detected

**Detection Statistics:**
- Malicious: Confirmed threats
- Suspicious: Potentially unwanted
- Undetected: No threat found
- Harmless: Known safe

### JSON Report Structure
```json
{
  "scan_type": "file",
  "verdict": "MALICIOUS (High Confidence)",
  "malicious": 45,
  "suspicious": 5,
  "undetected": 15,
  "harmless": 5,
  "total_engines": 70,
  "file_name": "suspicious.exe",
  "sha256": "a1b2c3d4...",
  "detections": [...]
}
```

### HTML Report Features
- Visual statistics with charts
- Color-coded verdicts
- Detection breakdown table
- File/URL/Domain/IP information
- Responsive design
- Print-friendly layout

## API Rate Limits

### Free API Limits
- **Requests**: 4 per minute
- **Daily**: 500 requests
- **Monthly**: 15,500 requests

### Rate Limit Handling
The scanner automatically:
- Waits 15 seconds between requests
- Handles rate limit errors
- Retries failed requests
- Shows progress during waits

### Optimizing API Usage
1. **Check existing reports first** - Files already scanned return cached results
2. **Use batch scanning** - More efficient than individual scans
3. **Scan by hash** - Faster than uploading files
4. **Upgrade to premium** - Higher limits for heavy usage

## Troubleshooting

### Common Issues

**1. API Key Not Found**
```
Error: VirusTotal API key required!
```
**Solution**: Set VT_API_KEY environment variable or use --api-key

**2. Rate Limit Exceeded**
```
Error: Rate limit exceeded
```
**Solution**: Wait 1 minute or upgrade to premium API

**3. File Not Found**
```
Error: File not found: /path/to/file
```
**Solution**: Check file path and permissions

**4. Invalid API Key**
```
Error: 401 - Unauthorized
```
**Solution**: Verify API key is correct and active

**5. File Too Large**
```
Error: File size exceeds limit
```
**Solution**: Free API limit is 32MB, upgrade for larger files

### Debug Mode

Enable verbose output:
```bash
# Add debug prints to vt_scanner.py
# Or use Python's logging module
python -v cli.py scan-file file.exe
```

### Getting Help

1. Check error message carefully
2. Review [VirusTotal API docs](https://developers.virustotal.com/reference/overview)
3. Verify API key and limits
4. Check file permissions
5. Open GitHub issue with details

## Advanced Usage

### Custom Rate Limit
Edit `vt_scanner.py`:
```python
self.rate_limit_delay = 20  # Increase delay
```

### Scan by Hash Only
```python
from vt_scanner import VirusTotalScanner

scanner = VirusTotalScanner(api_key)
report = scanner.get_file_report("file_sha256_hash")
```

### Programmatic Usage
```python
from vt_scanner import VirusTotalScanner

# Initialize scanner
scanner = VirusTotalScanner("your_api_key")

# Scan file
report = scanner.scan_file("suspicious.exe")

# Check verdict
if "MALICIOUS" in report['verdict']:
    print("Threat detected!")
    
# Export report
scanner.export_report(report, "output.json")
```

## Best Practices

1. **Always use environment variables** for API keys
2. **Check existing reports** before uploading
3. **Respect rate limits** - don't spam requests
4. **Save reports** for future reference
5. **Verify file hashes** for integrity
6. **Use batch scanning** for multiple files
7. **Review HTML reports** for detailed analysis
8. **Keep API key secure** - never commit to git

---

For more information, see the main [README.md](README.md) or visit [VirusTotal Documentation](https://developers.virustotal.com/reference/overview).
