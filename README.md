MEXTREME v1.1 - Professional Security Assessment Platform

https://via.placeholder.com/800x200/1a237e/ffffff?text=MEXTREME+v1.1+-+Professional+Security+Scanner

A production-ready, queue-managed web application security scanner with advanced vulnerability detection capabilities. Designed for professional security assessments and penetration testing.
Features
Comprehensive Reconnaissance

    Network Scanning: Port scanning, DNS enumeration, TLS analysis

    Subdomain Enumeration: Smart wildcard DNS detection with filtering

    Web Crawling: Queue-managed crawling with depth control

    Asset Discovery: Automatic detection of files, scripts, and resources

Advanced Vulnerability Detection

    SQL Injection: Error-based, timing-based, and union-based detection

    Cross-Site Scripting (XSS): Reflected XSS with context analysis

    Sensitive Data Exposure: Email discovery with smart filtering

    Security Misconfigurations: Missing headers, directory listings

    Database Fingerprinting: Automatic DB technology detection

Performance & Reliability

    Async Architecture: High-concurrency scanning with configurable limits

    Queue Management: Intelligent URL queue with growth control

    Rate Limiting: Respectful scanning with configurable delays

    Error Handling: Graceful handling of WAFs, redirects, and auth pages

Professional Reporting

    Interactive HTML Reports: Color-coded findings with expandable details

    JSON Export: Machine-readable output for automation

    Executive Summaries: Quick overview for decision-makers

    Progress Tracking: Real-time progress display with ETA

Prerequisites

    Python: 3.7 or higher (3.9+ recommended)

    Operating System: Linux, macOS, or Windows (WSL recommended for Windows)

    RAM: Minimum 2GB, 4GB+ recommended for large scans

    Disk Space: 100MB minimum for reports and logs

    Network: Stable internet connection

Quick Installation
Option 1: One-Line Install
bash

# Clone and install
git clone https://github.com/yourusername/mextreme.git && cd mextreme && pip install -r requirements.txt

Option 2: Step-by-Step
bash

# 1. Clone the repository
git clone https://github.com/yourusername/mextreme.git
cd mextreme

# 2. Install dependencies
pip install aiohttp dnspython urllib3

# 3. Make executable (Linux/macOS)
chmod +x mextreme.py

Option 3: Using requirements.txt
bash

git clone https://github.com/yourusername/mextreme.git
cd mextreme
pip install -r requirements.txt

requirements.txt contents:
txt

aiohttp>=3.8.0
dnspython>=2.3.0
urllib3>=2.0.0

Basic Usage
Simple Scan
bash

python mextreme.py https://example.com

Verbose Scan with All Details
bash

python mextreme.py https://example.com --verbose

Quick Assessment
bash

python mextreme.py https://example.com --quick

Custom Output Directory
bash

python mextreme.py https://example.com -o my_scan_results

Command Line Options
Option	Short	Description	Default
target	-	Target URL (required)	-
--output	-o	Custom output directory	mextreme_scans
--no-browser	-	Don't auto-open report	False
--quick	-	Quick scan mode	False
--verbose	-	Verbose output & debugging	False
--no-subdomains	-	Skip subdomain enumeration	False
--max-params	-	Max parameters per URL	10
--max-queue	-	Max crawl queue size	5000
🔧 Configuration Tuning

Edit the Config class in the script to customize:
python

# Scanning limits (adjust based on target size)
Config.REQUEST_CAP = 3000      # Maximum requests
Config.CRAWL_DEPTH = 3         # Crawl depth
Config.MAX_CONCURRENCY = 15    # Concurrent requests

# Detection sensitivity
Config.SQLI_CONFIDENCE_THRESHOLD = 0.7
Config.XSS_CONFIDENCE_THRESHOLD = 0.6

# Resource management
Config.MAX_QUEUE_SIZE = 5000   # Prevent memory issues

Scan Workflow
Phase 1: Network Reconnaissance
text

[PHASE 1] NETWORK RECONNAISSANCE
==================================
✓ IP Addresses: 3
✓ Open Ports: 5
✓ TLS Certificate: Valid (expires in 89 days)

Phase 2: Web Discovery
text

[PHASE 2] QUEUE-MANAGED WEB RECONNAISSANCE
===========================================
[CRAWL] Pages: 42 | Queue: 128 | Rate: 8.2/s | ETA: 15s
✓ Pages Discovered: 42
✓ Assets Discovered: 156
✓ Directory Listings: 2

Phase 3: Vulnerability Assessment
text

[PHASE 3] ADVANCED VULNERABILITY ASSESSMENT
============================================
✓ SQL Injection: 2 findings
✓ XSS: 1 finding
✓ Security Headers: 3 missing
✓ Email Exposure: 1 finding

Phase 4: Reporting
text

[PHASE 4] REPORTING
===================
✓ HTML Report: mextreme_scans/scan_20240115_143022/report.html
✓ JSON Export: mextreme_scans/scan_20240115_143022/report.json
✓ Executive Summary: mextreme_scans/scan_20240115_143022/executive_summary.md

Output Structure
text

mextreme_scans/
├── scan_20240115_143022_abc123/
│   ├── report.html              # Interactive HTML report
│   ├── report.json              # Machine-readable data
│   ├── executive_summary.md     # Quick overview
│   └── logs/
│       └── scan_20240115_143022.log
├── scan_20240116_093045_def456/
│   └── ...
└── scan_20240117_141512_ghi789/
    └── ...

Report Examples
HTML Report

https://via.placeholder.com/600x300/1565c0/ffffff?text=Interactive+HTML+Report+with+Color-Coded+Findings
Console Output
text

SCAN SUMMARY
===========================================================

Discovery Results:
  • Pages: 42
  • Assets: 156
  • Subdomains: 8
  • Open Ports: 5

Vulnerability Findings:
  • 🔴 CONFIRMED: 2
  • 🟡 LIKELY: 3
  • 🔵 POSSIBLE: 5
  • ⚪ INFO: 12

Statistics:
  • Duration: 2m 45s
  • Requests: 842
  • Rate: 5.1 requests/second

Reports saved to: mextreme_scans/scan_20240115_143022
===========================================================

Safety & Ethical Use
Do

    Scan only systems you own or have written permission to test

    Use --quick mode for initial assessments

    Respect rate limits and robots.txt

    Schedule scans during off-peak hours

    Verify findings manually before reporting

Don't

    Scan systems without authorization

    Use for DDoS or disruptive testing

    Ignore rate limiting warnings

    Share sensitive findings publicly

Responsible Disclosure Template
markdown

# Security Finding Report

**Target**: https://example.com
**Scan ID**: scan_20240115_143022
**Finding**: SQL Injection in search parameter
**URL**: https://example.com/search?q=test
**Confidence**: CONFIRMED (92%)
**Risk**: HIGH

**Evidence**: 
- Payload: `' OR '1'='1`
- Error: "You have an error in your SQL syntax"
- Response difference: 68%

**Remediation**: Use parameterized queries

🔍 Detection Capabilities
SQL Injection

    Error-based: MySQL, PostgreSQL, MSSQL, Oracle errors

    Timing-based: SLEEP(), pg_sleep(), WAITFOR DELAY

    Union-based: UNION SELECT detection

    Database Fingerprinting: Automatic DB type detection

Cross-Site Scripting (XSS)

    Context Analysis: Script tags, attributes, JavaScript contexts

    Encoding Detection: HTML entity encoding analysis

    Reflection Analysis: Payload reflection with context

Information Disclosure

    Email Addresses: Smart filtering of public/contact emails

    Directory Listings: Apache/Nginx/IIS directory indexing

    Security Headers: Missing CSP, HSTS, X-Frame-Options

    Technology Stack: Server, framework, CMS detection

**Performance Optimization**
For Large Sites (>1000 pages)
bash

python mextreme.py https://large-site.com \
  --max-queue 2000 \
  --max-params 5 \
  --quick

For API/Application Scans
bash

python mextreme.py https://api.example.com \
  --no-subdomains \
  --max-params 8

For Time-Constrained Assessments
bash

python mextreme.py https://target.com \
  --quick \
  --no-browser \
  -o rapid_assessment

**Troubleshooting**
Common Issues & Solutions
1. DNS Resolution Failures
bash

# Check DNS resolution
nslookup example.com
python -c "import dns.resolver; print(dns.resolver.resolve('example.com', 'A'))"

# Reinstall dnspython
pip install --upgrade dnspython

2. Memory Issues
bash

# Reduce queue size
python mextreme.py https://target.com --max-queue 1000

# Use quick mode
python mextreme.py https://target.com --quick

# Monitor memory usage
watch -n 1 "free -h"

3. SSL/TLS Problems
bash

# Update certificates
pip install --upgrade certifi

# Try with quick mode (fewer requests)
python mextreme.py https://target.com --quick

# Check TLS version
openssl s_client -connect example.com:443

4. Rate Limiting/Blocking
bash

# Increase delays between requests
# Edit Config.DELAY_BETWEEN_REQUESTS in the script

# Use fewer concurrent requests
# Edit Config.MAX_CONCURRENCY in the script

# Try quick scan first
python mextreme.py https://target.com --quick

Advanced Usage
Integration with CI/CD
bash

# Scan and check for critical findings
python mextreme.py https://staging.example.com --no-browser
if grep -q '"confidence_tier": "CONFIRMED"' mextreme_scans/*/report.json; then
  echo "Critical findings detected - failing build"
  exit 1
fi

Custom Wordlists

Edit the SUBDOMAIN_WORDLIST and COMMON_PATHS arrays in the script to add custom discovery paths.
Output Processing with jq
bash

# Extract all URLs found
cat mextreme_scans/*/report.json | jq '.discovery.pages_found'

# List confirmed vulnerabilities
cat mextreme_scans/*/report.json | jq '.findings.vulnerabilities[] | select(.confidence_tier == "CONFIRMED") | .type'

# Count by severity
cat mextreme_scans/*/report.json | jq '[.findings.vulnerabilities[].level] | group_by(.) | map({severity: .[0], count: length})'

Contributing

We welcome contributions! Here's how to get started:

    Fork the repository

    Create a feature branch
    bash

git checkout -b feature/awesome-improvement

Make your changes

Test thoroughly
bash

python mextreme.py https://testphp.vulnweb.com --quick --no-browser

    Submit a pull request

Development Setup
bash

# Create virtual environment
python -m venv venv

# Activate (Linux/macOS)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
pytest tests/

# Format code
black mextreme.py

# Lint
flake8 mextreme.py

Testing Guidelines

    Test with known vulnerable applications (DVWA, testphp.vulnweb.com)

    Verify no false positives on clean applications

    Ensure memory usage stays within limits

    Test edge cases (redirects, auth pages, rate limits)

Benchmarking
Target Size	Mode	Duration	Requests	Findings
Small (<50 pages)	Quick	1-2 min	~300	Baseline
Medium (50-500)	Standard	5-10 min	~1500	Typical
Large (500+)	Optimized	15-30 min	~3000	Comprehensive
Roadmap
Planned Features

    Brute Force Module: Directory and file brute forcing

    Authentication Testing: Login form testing

    API Security Testing: GraphQL, REST API scanning

    Plugin System: Extensible vulnerability modules

    Cloud Integration: AWS, Azure, GCP security checks

    CI/CD Templates: Ready-to-use pipeline templates

Current Version: v1.1

    ✅ Queue-managed crawling

    ✅ Advanced SQLi with DB fingerprinting

    ✅ Smart email exposure detection

    ✅ Professional reporting system

    ✅ Rate limiting and error handling

📄 License

This tool is provided for educational purposes and authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems.

Disclaimer: The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting security assessments.
Support
Getting Help

    Check Existing Issues: Search for similar problems

    Enable Debug Mode: Use --verbose for detailed logs

    Review Logs: Check the logs/ directory

    Community Support: Security forums and Discord channels

Reporting Bugs
bash

# Include these details when reporting issues:
python mextreme.py --version  # Add version info
python --version              # Python version
uname -a                      # OS information
cat /etc/issue                # Distribution info

Acknowledgments

    Security Community: For continuous research and sharing

    Open Source Tools: That inspired various features

    Test Applications: DVWA, WebGoat, and other practice targets

    Contributors: Everyone who helps improve this tool

Remember: Always test responsibly, document your findings, and help make the web a safer place.

Created with by RocketRaccoon - Professional Security Testing Tool

Professional security assessment platform focused on accurate, low-noise reconnaissance and vulnerability detection with evidence-based reporting.
