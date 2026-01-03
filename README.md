# 🛡️ VirusTotal Automated Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API_v3-394EFF.svg)
![Batch](https://img.shields.io/badge/Batch-Processing-green.svg)

**Enterprise-grade automated malware scanner leveraging 70+ antivirus engines for comprehensive threat detection**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-real-world-examples) • [Author](#-author)

</div>

---

## 🎯 The Problem

**Manual VirusTotal checks don't scale for SOC operations and security teams.**

In a typical security workflow:
- ❌ Analysts manually upload files one-by-one to VirusTotal
- ❌ No batch processing for multiple suspicious files
- ❌ Rate limits cause delays (4 requests/min on free tier)
- ❌ No automated reporting for incident response
- ❌ Results scattered across browser tabs
- ❌ No integration with existing security workflows

## ✅ The Solution

**Automated batch scanning with intelligent rate limiting, comprehensive reporting, and SIEM integration.**

This tool helps security teams:
- ✅ **Scan 100+ files/URLs per day** with zero manual intervention
- ✅ **Batch processing** with automatic rate limit handling
- ✅ **Generate reports** in JSON/HTML for incident response
- ✅ **Hash-based detection** to avoid re-scanning known files
- ✅ **Multi-target support** (files, URLs, domains, IPs)
- ✅ **SIEM integration** via JSON export

## 💼 How It Helps in Enterprise SOC

| Use Case | Traditional Approach | With This Tool |
|----------|---------------------|----------------|
| **Malware Analysis** | Manual upload to VirusTotal | Automated batch scanning |
| **Incident Response** | Copy-paste detection results | One-click HTML/JSON reports |
| **Threat Intelligence** | Manual domain/IP checks | Automated reputation analysis |
| **Email Security** | Manual attachment scanning | Batch scan all attachments |
| **Compliance Reporting** | Screenshot collection | Professional HTML reports |

---

## ✨ Features

### 🎯 Multi-Target Scanning
- **📄 File scanning** with hash-based detection (MD5, SHA-1, SHA-256)
- **🌐 URL scanning** for malicious websites and phishing
- **🔍 Domain reputation** checking for threat intelligence
- **🌍 IP address** threat analysis and geolocation

### 🔬 Comprehensive Analysis
- **70+ antivirus engines** (Kaspersky, Microsoft, Avast, etc.)
- **Detailed threat classification** (malicious, suspicious, clean)
- **Confidence-based verdicts** (High, Medium, Low)
- **Hash calculation** for file identification
- **Detection statistics** with percentage breakdowns

### ⚡ Batch Processing
- **Scan multiple files** at once from a file list
- **Automated rate limiting** (4 req/min for free API)
- **Progress tracking** with real-time updates
- **Combined reporting** for all scanned items
- **Error handling** and retry logic

### 📊 Rich Reporting
- **Console output** with color-coded verdicts
- **JSON export** for SIEM integration (Splunk, ELK, QRadar)
- **Beautiful HTML reports** with visual statistics
- **Detection breakdowns** by antivirus engine
- **Verdict summaries** with confidence levels

### 🧠 Smart Features
- **Automatic hash checking** (avoid re-scanning known files)
- **Rate limit handling** (respects API quotas)
- **Environment variable support** for API keys
- **Retry logic** for transient failures
- **File type detection** and metadata extraction

---

## 📋 Requirements

- Python 3.7+
- VirusTotal API key (free or premium)
- requests library
- colorama (for colored output)

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Hemant617/virustotal-automated-scanner.git
cd virustotal-automated-scanner

# Install dependencies
pip install -r requirements.txt
```

### Get Your VirusTotal API Key

1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Go to your [API key page](https://www.virustotal.com/gui/my-apikey)
3. Copy your API key

### Set Up API Key

**Method 1: Environment Variable (Recommended)**
```bash
export VT_API_KEY="your_api_key_here"
```

**Method 2: Command Line Argument**
```bash
python cli.py scan-file file.exe --api-key your_api_key_here
```

---

## 💻 Usage

### 1️⃣ Scan a File

```bash
# Basic file scan
python cli.py scan-file suspicious.exe

# With JSON report
python cli.py scan-file malware.pdf -o report.json

# With HTML report
python cli.py scan-file document.docx --html report.html
```

**Output:**
```
================================================================================
VIRUSTOTAL FILE SCAN
================================================================================

[*] Scanning file: suspicious.exe
[*] File SHA-256: a1b2c3d4e5f6789...
[+] File already scanned, retrieving existing report

Scan Type: FILE
Verdict: MALICIOUS (High Confidence)

Detection Statistics:
  Malicious: 45/70 (64%)
  Suspicious: 5/70 (7%)
  Undetected: 15/70 (21%)
  Harmless: 5/70 (7%)

File Information:
  Name: suspicious.exe
  Size: 524288 bytes (512 KB)
  Type: Win32 EXE
  MD5: 5d41402abc4b2a76b9719d911017c592
  SHA-1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
  SHA-256: a1b2c3d4e5f6789...

Top Detections (10):
  ✗ Kaspersky: Trojan.Win32.Generic (malicious)
  ✗ Microsoft: Trojan:Win32/Wacatac.B!ml (malicious)
  ✗ Avast: Win32:Malware-gen (malicious)
  ✗ BitDefender: Gen:Variant.Razy.123456 (malicious)
  ✗ ESET-NOD32: Win32/TrojanDownloader.Agent (malicious)
  ✗ Symantec: Trojan.Gen.2 (malicious)
  ✗ McAfee: Artemis!A1B2C3D4E5F6 (malicious)
  ✗ Sophos: Mal/Generic-S (malicious)
  ✗ TrendMicro: TROJ_GEN.R002C0DKO21 (malicious)
  ✗ Panda: Troj/Agent.ABC (malicious)

Recommendation: QUARANTINE IMMEDIATELY - High confidence malware detection
```

---

### 2️⃣ Scan a URL

```bash
# Scan a website
python cli.py scan-url https://suspicious-site.com

# With report export
python cli.py scan-url https://example.com -o url_report.json --html url_report.html
```

**Output:**
```
================================================================================
VIRUSTOTAL URL SCAN
================================================================================

[*] Scanning URL: https://suspicious-site.com
[+] URL submitted for analysis
[*] Waiting for scan to complete...

Scan Type: URL
Verdict: MALICIOUS (High Confidence)

Detection Statistics:
  Malicious: 12/70 (17%)
  Suspicious: 3/70 (4%)
  Undetected: 50/70 (71%)
  Harmless: 5/70 (7%)

URL Information:
  URL: https://suspicious-site.com
  Final URL: https://suspicious-site.com/index.php
  Status: Active
  Categories: phishing, malware

Top Detections (5):
  ✗ Google Safebrowsing: Phishing
  ✗ Kaspersky: Phishing
  ✗ Fortinet: Malicious
  ✗ ESET: Phishing
  ✗ Sophos: Malware

Recommendation: BLOCK URL - Confirmed phishing/malware site
```

---

### 3️⃣ Scan a Domain

```bash
# Check domain reputation
python cli.py scan-domain example.com

# Export results
python cli.py scan-domain suspicious-domain.com -o domain_report.json
```

**Output:**
```
================================================================================
VIRUSTOTAL DOMAIN SCAN
================================================================================

[*] Scanning domain: suspicious-domain.com

Scan Type: DOMAIN
Verdict: SUSPICIOUS (Medium Confidence)

Detection Statistics:
  Malicious: 3/70 (4%)
  Suspicious: 5/70 (7%)
  Undetected: 60/70 (86%)
  Harmless: 2/70 (3%)

Domain Information:
  Domain: suspicious-domain.com
  Registrar: GoDaddy
  Creation Date: 2025-12-01
  Last Updated: 2025-12-15
  Categories: newly registered, suspicious

WHOIS Information:
  Registrant: Privacy Protected
  Country: US
  Name Servers: ns1.suspicious-domain.com, ns2.suspicious-domain.com

Detections:
  ✗ Fortinet: Suspicious (suspicious)
  ✗ ESET: Potentially unwanted (suspicious)
  ✗ Sophos: Suspicious (suspicious)

Recommendation: MONITOR - Newly registered domain with suspicious indicators
```

---

### 4️⃣ Scan an IP Address

```bash
# Analyze IP reputation
python cli.py scan-ip 192.168.1.100

# With HTML report
python cli.py scan-ip 8.8.8.8 --html ip_report.html
```

**Output:**
```
================================================================================
VIRUSTOTAL IP SCAN
================================================================================

[*] Scanning IP: 192.168.1.100

Scan Type: IP
Verdict: MALICIOUS (High Confidence)

Detection Statistics:
  Malicious: 8/70 (11%)
  Suspicious: 2/70 (3%)
  Undetected: 58/70 (83%)
  Harmless: 2/70 (3%)

IP Information:
  IP Address: 192.168.1.100
  Country: Russia
  ASN: AS12345 (Example ISP)
  Network: 192.168.0.0/16

Threat Intelligence:
  Known for: Brute force attacks, port scanning
  First seen: 2025-11-15
  Last seen: 2026-01-03
  Reputation: Malicious

Detections:
  ✗ Kaspersky: Malicious (malicious)
  ✗ ESET: Malicious (malicious)
  ✗ Fortinet: Malicious (malicious)

Recommendation: BLOCK IP - Known malicious actor
```

---

### 5️⃣ Batch Scan Multiple Files

```bash
# Create a file list (files.txt)
cat > files.txt << EOF
/path/to/file1.exe
/path/to/file2.pdf
/path/to/file3.docx
/path/to/file4.zip
EOF

# Run batch scan
python cli.py batch-scan files.txt -o batch_report.json --html batch_report.html
```

**Output:**
```
================================================================================
BATCH SCAN PROGRESS
================================================================================

[1/4] Scanning: file1.exe
  ✗ MALICIOUS (45/70 detections)

[2/4] Scanning: file2.pdf
  ✓ CLEAN (0/70 detections)

[3/4] Scanning: file3.docx
  ⚠ SUSPICIOUS (5/70 detections)

[4/4] Scanning: file4.zip
  ✓ CLEAN (0/70 detections)

================================================================================
BATCH SCAN SUMMARY
================================================================================

Total Files Scanned: 4
Malicious: 1 (25%)
Suspicious: 1 (25%)
Clean: 2 (50%)

Malicious Files:
  - file1.exe (45/70 detections)

Suspicious Files:
  - file3.docx (5/70 detections)

Recommendation: Quarantine malicious files, investigate suspicious files
```

---

## 📊 Real-World Examples

### Example 1: Email Attachment Scanning

**Scenario**: SOC analyst receives suspicious email with 3 attachments

```bash
# Create file list
cat > email_attachments.txt << EOF
/tmp/invoice.pdf
/tmp/document.docx
/tmp/payment.exe
EOF

# Scan all attachments
python cli.py batch-scan email_attachments.txt --html email_scan_report.html
```

**Result:**
```
[1/3] invoice.pdf: ✓ CLEAN
[2/3] document.docx: ✓ CLEAN
[3/3] payment.exe: ✗ MALICIOUS (52/70 detections)

Verdict: Email contains malware (payment.exe)
Action: Quarantine email, block sender, alert user
```

---

### Example 2: Phishing URL Investigation

**Scenario**: User reports suspicious link in email

```bash
python cli.py scan-url https://secure-bank-login-verify.com
```

**Result:**
```
Verdict: MALICIOUS (High Confidence)
Detection: 15/70 engines flagged as phishing
Categories: phishing, credential theft
Domain Age: 2 days (newly registered)

Action: Block URL at firewall, add to threat intelligence feed
```

---

### Example 3: Incident Response - Compromised Host

**Scenario**: Host shows signs of compromise, scan all executables

```bash
# Find all .exe files
find /suspicious_host -name "*.exe" > suspicious_files.txt

# Batch scan
python cli.py batch-scan suspicious_files.txt -o incident_report.json
```

**Result:**
```
Total Files: 47
Malicious: 3 (6%)
  - C:\Windows\Temp\svchost.exe (backdoor)
  - C:\Users\Public\update.exe (trojan)
  - C:\ProgramData\system32.exe (ransomware)

Action: Isolate host, remove malware, forensic analysis
```

---

### Example 4: Threat Intelligence - Domain Reputation

**Scenario**: Investigate domains from firewall logs

```bash
# Create domain list
cat > domains.txt << EOF
suspicious-site.com
malware-download.net
phishing-bank.com
legitimate-site.com
EOF

# Scan each domain
for domain in $(cat domains.txt); do
  python cli.py scan-domain $domain -o ${domain}_report.json
done
```

**Result:**
```
suspicious-site.com: MALICIOUS (12/70)
malware-download.net: MALICIOUS (18/70)
phishing-bank.com: MALICIOUS (15/70)
legitimate-site.com: CLEAN (0/70)

Action: Block 3 malicious domains at DNS level
```

---

## 📊 HTML Report Features

The generated HTML reports include:

- 🎨 **Beautiful gradient design** with professional styling
- 📊 **Visual statistics** with progress bars and charts
- 🔍 **Detailed detection breakdown** by antivirus engine
- 📱 **Responsive layout** for mobile and desktop
- 🎯 **Color-coded verdicts** (red=malicious, yellow=suspicious, green=clean)
- 📈 **Detection rate visualization** with percentage bars
- 💡 **Security recommendations** based on findings
- 📋 **File metadata** (hashes, size, type)
- 🌍 **Threat intelligence** (IP geolocation, domain WHOIS)

**Sample HTML Report Screenshot:**
```
┌─────────────────────────────────────────────────────────┐
│  VirusTotal Scan Report                                 │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                          │
│  Verdict: MALICIOUS (High Confidence)                   │
│  ████████████████████████████████████░░░░░░░ 64%       │
│                                                          │
│  Detection Statistics:                                   │
│  ┌──────────────┬─────────┬──────────┐                 │
│  │ Category     │ Count   │ Percent  │                 │
│  ├──────────────┼─────────┼──────────┤                 │
│  │ Malicious    │ 45/70   │ 64%      │                 │
│  │ Suspicious   │ 5/70    │ 7%       │                 │
│  │ Undetected   │ 15/70   │ 21%      │                 │
│  │ Harmless     │ 5/70    │ 7%       │                 │
│  └──────────────┴─────────┴──────────┘                 │
│                                                          │
│  Top Detections:                                         │
│  ✗ Kaspersky: Trojan.Win32.Generic                     │
│  ✗ Microsoft: Trojan:Win32/Wacatac.B!ml                │
│  ✗ Avast: Win32:Malware-gen                            │
│                                                          │
│  Recommendation: QUARANTINE IMMEDIATELY                  │
└─────────────────────────────────────────────────────────┘
```

---

## 🔧 Module Overview

### `vt_scanner.py` - Core Scanning Engine
- Interfaces with VirusTotal API v3
- Handles file uploads and URL submissions
- Retrieves domain and IP reports
- Manages rate limiting (4 req/min for free API)
- Calculates file hashes (MD5, SHA-1, SHA-256)
- Parses and structures API responses
- Implements retry logic for transient failures

### `cli.py` - Command-Line Interface
- Multiple scan modes (file, URL, domain, IP, batch)
- Flexible output options (console, JSON, HTML)
- API key management (env var or CLI arg)
- Progress tracking for batch scans
- User-friendly commands with help text
- Error handling and user feedback

### `report_generator.py` - Report Generation Module
- Creates beautiful HTML reports with CSS
- Formats detection data for visualization
- Generates visual statistics and charts
- Provides verdict-based styling (color-coded)
- Exports JSON for SIEM integration
- Includes security recommendations

---

## 🎯 Verdict Classifications

| Verdict | Detection Rate | Description | Action |
|---------|---------------|-------------|--------|
| **CLEAN** | 0% malicious | No threats detected | Allow |
| **SUSPICIOUS** | 1-19% malicious | Some engines flagged | Investigate |
| **MALICIOUS (Low)** | 1-19% malicious | Multiple detections | Quarantine |
| **MALICIOUS (Medium)** | 20-49% malicious | Significant detections | Block |
| **MALICIOUS (High)** | 50%+ malicious | Strong consensus | Quarantine immediately |

### Detection Categories

- **Malicious**: Confirmed threat detected (malware, trojan, ransomware)
- **Suspicious**: Potentially unwanted program (PUP) or adware
- **Undetected**: No threat found by this engine
- **Harmless**: Known safe file/URL (whitelisted)

---

## 📁 Project Structure

```
virustotal-automated-scanner/
├── vt_scanner.py          # Core scanning engine
├── cli.py                 # Command-line interface
├── report_generator.py    # HTML report generation
├── requirements.txt       # Python dependencies
├── README.md             # Documentation
├── examples/             # Example files
│   ├── sample_files.txt  # Sample file list for batch scan
│   ├── malware.exe       # Test malware sample (EICAR)
│   └── clean.txt         # Clean test file
└── reports/              # Generated reports
    ├── *.json            # JSON reports for SIEM
    └── *.html            # HTML reports for viewing
```

---

## 🔐 API Key Management

### Free API Limitations
- **4 requests per minute**
- **500 requests per day**
- **32 MB file size limit**

### Premium API Benefits
- **1000 requests per minute**
- **Unlimited daily requests**
- **650 MB file size limit**
- **Priority scanning**

### Best Practices
- Store API key in environment variable (never commit to Git)
- Use `.gitignore` to exclude API key files
- Rotate API keys regularly
- Monitor API usage in VirusTotal dashboard

---

## 🧪 Testing

### Run with EICAR Test File
```bash
# Download EICAR test file (harmless malware test)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt

# Scan test file
python cli.py scan-file eicar.txt --html eicar_report.html
```

**Expected Result**: 60-70/70 engines should detect EICAR as malware

### Test Batch Scanning
```bash
# Create test file list
cat > test_files.txt << EOF
eicar.txt
README.md
requirements.txt
EOF

# Run batch scan
python cli.py batch-scan test_files.txt -o test_report.json
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👨‍💻 Author

**Hemant Kaushal**  
🔐 Aspiring SOC Analyst | Security Automation | Malware Analysis

- 📧 Email: hemuh877@gmail.com
- 💼 LinkedIn: [linkedin.com/in/hemantkaushal](https://linkedin.com/in/hemantkaushal)
- 💻 GitHub: [@Hemant617](https://github.com/Hemant617)
- 📱 Phone: +91 96342 22262
- 🌐 Portfolio: [hemant617.github.io](https://hemant617.github.io/)

### 🎓 Certifications
- Deloitte Cyber Job Simulation (Forage, Nov 2025)
- Deloitte Data Analytics Job Simulation (Forage, Nov 2025)
- Cisco Introduction to Cybersecurity (Nov 2025)

### 🚀 Other Security Projects
- [Threat Log Analyzer](https://github.com/Hemant617/threat-log-analyzer) - Real-time log analysis with 8+ threat types
- [VulnScan Pro](https://github.com/Hemant617/vulnscan-pro) - Automated vulnerability scanner
- [View All Projects](https://github.com/Hemant617)

---

## 🙏 Acknowledgments

- Built with Python 3
- Powered by VirusTotal API v3
- Inspired by enterprise malware analysis workflows
- Threat intelligence from 70+ antivirus vendors

---

<div align="center">

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Always ensure you have permission before scanning files or URLs. Do not upload sensitive or confidential files to VirusTotal.

**⭐ If you find this project useful, please consider giving it a star!**

**🤝 Open to collaboration on SOC automation and security tooling projects**

</div>
