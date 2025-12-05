# 🔍 Website Vulnerability Scanner

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux%2FTermux-brightgreen.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

\ \ / / | |
\ \ /\ / /| | ___ ___ __ _ _ __
\ / / / _ \ '_ \ / |/ / ` | ' \
\ /\ / / |) | _ \ (| (| | | | |
/ / _|_./ |/____,|| |_|


A powerful automated web vulnerability scanner for ethical hacking and security testing. Detects SQL Injection, XSS, LFI, CSRF, SSRF, and IDOR vulnerabilities with automatic site crawling and detailed reporting.

---

## ✨ Features

### 🛡️ Vulnerability Detection
- **SQL Injection** (Error-based, Time-based, UNION)
- **Cross-Site Scripting** (Reflected, Stored, DOM-based)
- **Local File Inclusion** (LFI/RFI)
- **Cross-Site Request Forgery** (CSRF)
- **Server-Side Request Forgery** (SSRF)
- **Insecure Direct Object Reference** (IDOR)

### ⚡ Technical Features
- **Automatic Site Crawling** - Discovers all website pages
- **Multi-threaded Scanning** - Fast parallel processing
- **Detailed Reporting** - Generates comprehensive TXT reports
- **Colorful Terminal Output** - Easy-to-read interface
- **Easy Configuration** - Customizable payloads and settings
- **Cross-Platform** - Works on Kali Linux, Termux, Linux, Windows

---

## 🚀 Quick Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager
- Internet connection

### Installation Methods

#### Method 1: Quick Install (Recommended)
```bash
# Clone repository
git clone https://github.com/G0STK9M/website-vulnerability-scanner.git

# Navigate to directory
cd website-vulnerability-scanner

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x web_scanner.py


Basic Usage
# Scan a specific website
python3 web_scanner.py https://example.com

# Interactive mode (will prompt for URL)
python3 web_scanner.py

Advanced Usage
# Scan with custom timeout
python3 web_scanner.py http://target.com

# Save output to file
python3 web_scanner.py http://target.com > results.txt

# Scan multiple sites (using shell script)
for site in $(cat targets.txt); do python3 web_scanner.py $site; done

📊 Scan Process in Detail
Phase 1: Discovery
Initial Request - Verify site accessibility

Link Extraction - Parse HTML for links, forms, scripts

URL Normalization - Convert relative to absolute URLs

Duplicate Removal - Avoid scanning same page multiple times


Phase 2: Testing
For each URL with parameters (?query=):

SQL Injection Test - 15+ payloads including time-based
XSS Test - 10+ reflective payloads
LFI Test - Common file inclusion paths
SSRF Test - Internal service endpoints
IDOR Test - Parameter manipulation
For all pages:
CSRF Test - Missing token detection

Phase 3: Reporting
Vulnerability Aggregation - Collect all findings
Severity Classification - CRITICAL, HIGH, MEDIUM, LOW
Report Generation - TXT file with timestamps
Terminal Summary - Colorful quick overview

📝 Output Examples
   Terminal Output
============================================================
Tool Name  : Website Vulnerability Scanner
Tools Maker: G0$T×K9M
Version    : 2.0
============================================================
[+] Target URL: http://testphp.vulnweb.com
[+] Start Time: 2024-01-15 14:30:25
------------------------------------------------------------
[+] Starting site crawling...
[+] Found 35 URLs to scan
[+] Scanning: 35/35 (100.0%)
[+] Found 8 vulnerabilities!
------------------------------------------------------------

SCAN REPORT SUMMARY:
============================================================
By Severity:
  CRITICAL: 2
  HIGH: 3
  MEDIUM: 3
  LOW: 0

By Vulnerability Type:
  SQL Injection: 2
  XSS: 3
  LFI: 1
  CSRF: 2

[+] Report saved: scan_report_testphp_vulnweb_com_20240115_143025.txt

Report File Content
============================================================
WEB VULNERABILITY SCAN REPORT
============================================================

Target URL: http://testphp.vulnweb.com
Scan Time: 2024-01-15 14:30:25
Total Vulnerabilities: 8

------------------------------------------------------------
1. Vulnerability Type: SQL Injection
   Severity: CRITICAL
   URL: http://testphp.vulnweb.com/artists.php?artist=1'
   Parameter: artist
   Details: SQL error detected with payload: '
   Payload: '

2. Vulnerability Type: XSS (Reflected)
   Severity: HIGH
   URL: http://testphp.vulnweb.com/search.php?test=query
   Parameter: test
   Details: XSS payload reflected in URL parameter
   Payload: <script>alert('XSS')</script>

... [More vulnerabilities] ...

============================================================
SUMMARY:
============================================================
CRITICAL: 2
HIGH: 3
MEDIUM: 3
LOW: 0

============================================================
RECOMMENDATIONS:
============================================================
1. Use prepared statements for all SQL queries
2. Validate and sanitize all user inputs
3. Implement CSRF tokens on all forms
4. Enable strict file upload validation
5. Implement proper access controls
6. Use Content Security Policy (CSP) headers
7. Regular security testing and code reviews
issues

🛡️ Ethical Usage Guidelines
✅ DO:
Scan only websites you own
Get written permission before testing
Use for educational purposes
Follow bug bounty program rules
Report vulnerabilities responsibly
Respect rate limits


❌ DO NOT:
Scan without explicit permission
Perform denial-of-service attacks
Exploit found vulnerabilities
Access or modify unauthorized data
Violate laws or terms of service


Legal Disclaimer
THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY.
The author is not responsible for any misuse or damage.
Users must ensure they have proper authorization.
Always follow ethical hacking guidelines.


Compatibility
✅ Kali Linux
✅ Termux
✅ Ubuntu/Debian
✅ Windows (with Python)
✅ macOS
✅ Other Linux distributions


Made with ❤️ by G0$T×K9M
