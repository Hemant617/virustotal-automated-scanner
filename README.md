# 🛡️ VirusTotal Automated Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API_v3-394EFF.svg)

**A powerful Python-based automated security scanner that leverages the VirusTotal API to scan files, URLs, domains, and IP addresses for malware, viruses, and security threats. Generate comprehensive reports with detailed threat analysis.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Author](#-author)

</div>

---

## ✨ Features

- **Multi-Target Scanning**:
  - 📄 File scanning with hash-based detection
  - 🌐 URL scanning for malicious websites
  - 🔍 Domain reputation checking
  - 🌍 IP address threat analysis

- **Comprehensive Analysis**:
  - Detection by 70+ antivirus engines
  - Detailed threat classification
  - Confidence-based verdicts
  - Hash calculation (MD5, SHA-1, SHA-256)

- **Batch Processing**:
  - Scan multiple files at once
  - Automated rate limiting
  - Progress tracking
  - Combined reporting

- **Rich Reporting**:
  - Console output with color coding
  - JSON export for automation
  - Beautiful HTML reports
  - Detection statistics and breakdowns

- **Smart Features**:
  - Automatic hash checking (avoid re-scanning)
  - Rate limit handling (Free API: 4 req/min)
  - Error handling and retry logic
  - Environment variable support

## 📋 Requirements

- Python 3.7+
- VirusTotal API key (free or premium)
- requests library
- colorama (for colored output)

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/Hemant617/virustotal-automated-scanner.git
cd virustotal-automated-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Get your VirusTotal API key:
   - Sign up at [VirusTotal](https://www.virustotal.com/)
   - Go to your [API key page](https://www.virustotal.com/gui/my-apikey)
   - Copy your API key

4. Set up your API key (choose one method):

**Method 1: Environment Variable (Recommended)**
```bash
export VT_API_KEY="your_api_key_here"
```

**Method 2: Command Line Argument**
```bash
python cli.py scan-file file.exe --api-key your_api_key_here
```

## 💻 Usage

### Scan a File

```bash
# Basic file scan
python cli.py scan-file suspicious.exe

# With JSON report
python cli.py scan-file malware.pdf -o report.json

# With HTML report
python cli.py scan-file document.docx --html report.html
```

### Scan a URL

```bash
# Scan a website
python cli.py scan-url https://suspicious-site.com

# With report export
python cli.py scan-url https://example.com -o url_report.json --html url_report.html
```

### Scan a Domain

```bash
# Check domain reputation
python cli.py scan-domain example.com

# Export results
python cli.py scan-domain suspicious-domain.com -o domain_report.json
```

### Scan an IP Address

```bash
# Analyze IP reputation
python cli.py scan-ip 192.168.1.100

# With HTML report
python cli.py scan-ip 8.8.8.8 --html ip_report.html
```

### Batch Scan Multiple Files

```bash
# Create a file list (files.txt)
# /path/to/file1.exe
# /path/to/file2.pdf
# /path/to/file3.docx

# Run batch scan
python cli.py batch-scan files.txt -o batch_report.json
```

## 📊 Output Examples

### Console Output
```
================================================================================
VIRUSTOTAL FILE SCAN
================================================================================

[*] Scanning file: suspicious.exe
[*] File SHA-256: a1b2c3d4e5f6...
[+] File already scanned, retrieving existing report

Scan Type: FILE
Verdict: MALICIOUS (High Confidence)

Detection Statistics:
  Malicious: 45/70
  Suspicious: 5/70
  Undetected: 15/70
  Harmless: 5/70

File Information:
  Name: suspicious.exe
  Size: 524288 bytes
  Type: Win32 EXE
  SHA-256: a1b2c3d4e5f6...

Detections (10):
  - Kaspersky: Trojan.Win32.Generic (malicious)
  - Microsoft: Trojan:Win32/Wacatac (malicious)
  - Avast: Win32:Malware-gen (malicious)
  ...
```

### HTML Report Features
- 🎨 Beautiful gradient design
- 📊 Visual statistics with progress bars
- 🔍 Detailed detection breakdown
- 📱 Responsive layout
- 🎯 Color-coded verdicts
- 📈 Detection rate visualization

## 🔧 Module Overview

### `vt_scanner.py`
Core scanning engine that:
- Interfaces with VirusTotal API v3
- Handles file uploads and URL submissions
- Retrieves domain and IP reports
- Manages rate limiting
- Calculates file hashes
- Parses and structures results

### `cli.py`
Command-line interface providing:
- Multiple scan modes
- Flexible output options
- Batch processing
- API key management
- User-friendly commands

### `report_generator.py`
Report generation module that:
- Creates beautiful HTML reports
- Formats detection data
- Generates visual statistics
- Provides verdict-based styling

## 🎯 Scan Types & Verdicts

### Verdict Classifications

| Verdict | Description | Detection Rate |
|---------|-------------|----------------|
| CLEAN | No threats detected | 0% malicious |
| SUSPICIOUS | Some engines flagged | 1-19% malicious |
| MALICIOUS (Low) | Multiple detections | 1-19% malicious |
| MALICIOUS (Medium) | Significant detections | 20-49% malicious |
| MALICIOUS (High) | Strong consensus | 50%+ malicious |

### Detection Categories

- **Malicious**: Confirmed threat detected
- **Suspicious**: Potentially unwanted program (PUP)
- **Undetected**: No threat found
- **Harmless**: Known safe file/URL

## 📁 Project Structure

```
virustotal-automated-scanner/
├── vt_scanner.py          # Core scanning engine
├── cli.py                 # Command-line interface
├── report_generator.py    # HTML report generation
├── requirements.txt       # Python dependencies
├── README.md             # Documentation
├── examples/             # Example files
│   └── sample_files.txt
└── reports/              # Generated reports
    ├── *.json
    └── *.html
```

## 🔐 API Key Management

### Free API Limitations
- 4 requests per minute
- 500 requests per day
- 15.5K requests per month

### Premium API Benefits
- Higher rate limits
- Priority scanning
- Advanced features
- Detailed metadata

### Best Practices
- Store API key in environment variable
- Never commit API keys to version control
- Use `.env` files for local development
- Rotate keys periodically

## 🧪 Testing

Test with sample files:
```bash
# Create test file
echo "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" > eicar.txt

# Scan EICAR test file
python cli.py scan-file eicar.txt --html eicar_report.html
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**Hemant Kaushal**

- 🔐 Cybersecurity Analyst | SOC Operations | Incident Response
- 📧 Email: hemuh877@gmail.com
- 💼 LinkedIn: [linkedin.com/in/hemantkaushal](https://linkedin.com/in/hemantkaushal)
- 💻 GitHub: [@Hemant617](https://github.com/Hemant617)
- 📱 Phone: +91 96342 22262

### 🎓 Certifications
- Deloitte Cyber Job Simulation (Forage)
- Deloitte Data Analytics Job Simulation (Forage)
- Cisco Introduction to Cybersecurity

### 🚀 Other Projects
- [Threat Log Analyzer](https://github.com/Hemant617/threat-log-analyzer)
- [View All Projects](https://github.com/Hemant617)

## 🙏 Acknowledgments

- Built with [VirusTotal API v3](https://developers.virustotal.com/reference/overview)
- Uses 70+ antivirus engines
- Powered by Python 3

## 📧 Support

For questions or issues:
- Open an issue on GitHub
- Check [VirusTotal API documentation](https://developers.virustotal.com/reference/overview)
- Review [API rate limits](https://developers.virustotal.com/reference/public-vs-premium-api)

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have permission before scanning files or URLs. Respect VirusTotal's Terms of Service and API usage limits.

## 🔗 Useful Links

- [VirusTotal Website](https://www.virustotal.com/)
- [API Documentation](https://developers.virustotal.com/reference/overview)
- [Get API Key](https://www.virustotal.com/gui/my-apikey)
- [Community](https://www.virustotal.com/gui/community-overview)

---

<div align="center">

**⭐ If you find this project useful, please consider giving it a star!**

Made with ❤️ by [Hemant Kaushal](https://github.com/Hemant617)

</div>
