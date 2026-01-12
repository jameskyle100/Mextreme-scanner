MEXTREME v2.0 - Professional Security Assessment Platform

https://via.placeholder.com/800x200/1a237e/ffffff?text=MEXTREME+v1.1+-+Professional+Security+Scanner

A production-ready, queue-managed web application security scanner with advanced vulnerability detection capabilities. Designed for professional security assessments and penetration testing.

https://img.shields.io/badge/MEXTREME-v2.0-Evidence--Driven-blue
https://img.shields.io/badge/Python-3.7+-green
https://img.shields.io/badge/License-MIT-yellow
https://img.shields.io/badge/Security-Assessment-red

🎯 Overview

MEXTREME is an advanced, evidence-driven security assessment platform designed for accuracy and explainability. Unlike traditional scanners that focus on volume, MEXTREME emphasizes quality findings with structured evidence, making it ideal for professional security assessments and penetration testing.
Key Principles:

    Evidence-Driven Detection: Requires multiple evidence types for high-confidence findings

    Low-Noise Architecture: Minimizes false positives through strict confidence thresholds

    Explainable Results: Structured evidence collection for reproducibility

    Modular Detector System: Plugin-based architecture for extensibility

    Professional Reporting: Clean, actionable reports for stakeholders

✨ Features
🔍 Reconnaissance

    Network Scanning: Port scanning, DNS enumeration, TLS certificate analysis

    Web Crawling: Queue-managed crawling with strict growth control

    Subdomain Enumeration: Secure enumeration with wildcard DNS detection

    Directory Discovery: Common paths and sensitive file detection

🛡️ Vulnerability Detection

    SQL Injection: Error-based and timing-based detection with DB fingerprinting

    Cross-Site Scripting: Reflected XSS detection with context analysis

    Security Headers: Missing security headers detection

    Information Disclosure: Email exposure and directory listing detection

    Custom Detectors: Modular architecture for easy extension

📊 Reporting

    HTML Reports: Professional, visually appealing reports

    JSON Export: Machine-readable output for integration

    Executive Summary: High-level overview for management

    Risk Scoring: Calculated risk score (0-100) based on findings

⚡ Performance

    Async Architecture: High-performance asynchronous requests

    Rate Limiting: Configurable rate limiting to avoid detection

    Queue Management: Smart queue growth control to prevent memory issues

    Concurrency Control: Configurable concurrency levels

🚀 Installation
Prerequisites

    Python 3.7+

    Recommended: 4GB+ RAM

Quick Start
bash

# Clone the repository
git clone <repository-url>
cd mextreme

# Install dependencies
pip install -r requirements.txt

# Run a scan
python mextreme.py https://example.com

Dependencies
bash

# Core dependencies
pip install aiohttp dnspython

# Optional for enhanced features
pip install colorama  # Colored output

📖 Usage
Basic Scan
bash

python mextreme.py https://example.com

Advanced Options
bash

# Quick scan (limited coverage)
python mextreme.py https://example.com --quick

# Verbose output for debugging
python mextreme.py https://example.com --verbose

# Disable subdomain enumeration
python mextreme.py https://example.com --no-subdomains

# Custom output directory
python mextreme.py https://example.com -o custom_reports/

# Don't open browser after scan
python mextreme.py https://example.com --no-browser

Detector Management
bash

# List all available detectors
python mextreme.py --list-detectors

# Explain what will be scanned (without executing)
python mextreme.py https://example.com --explain

# Include specific detector tags
python mextreme.py https://example.com --tags injection,web

# Exclude specific detector tags
python mextreme.py https://example.com --exclude-tags info

# Enable/disable specific detectors
python mextreme.py https://example.com --enable-detector sqli-timing
python mextreme.py https://example.com --disable-detector email-exposure

Available Tags

    web: Web application vulnerabilities

    injection: Injection-based vulnerabilities

    info: Information disclosure findings

    recon: Reconnaissance findings

    timing: Timing-based detection

    low-noise: Low false-positive detectors

    evidence-driven: Evidence-requiring detectors

🏗️ Architecture
Core Components

    Configuration Manager (Config class)

        Centralized configuration with sensible defaults

        Runtime adjustable settings

        Evidence requirements per detector

    Data Models

        Vulnerability: Structured vulnerability data with evidence

        Endpoint: Web endpoint information

        TargetProfile: Complete target profile

        Detector: Base detector class for extensibility

    Network Scanner

        Port scanning with service detection

        DNS enumeration and analysis

        TLS certificate inspection

    Web Crawler

        Queue-managed crawling with growth control

        External domain filtering

        Parameter extraction and classification

    Detector Engine

        Modular detector architecture

        Evidence-based confidence scoring

        Configurable evidence requirements

    Report Generator

        Multi-format reporting (HTML, JSON, Markdown)

        Risk score calculation

        Executive summaries

Evidence-Driven Detection

MEXTREME uses a multi-evidence approach:
python

# Example: SQL Injection detector evidence requirements
evidence_requirements = {
    'sqli-error': {
        'min_confidence': 0.7,
        'required_evidence': ['sql_errors', 'response_diff'],
        'evidence_options': 2  # Need at least 2 evidence types
    }
}

Detector Pipeline

    Baseline Collection: Establish normal response patterns

    Payload Testing: Send test payloads with rate limiting

    Evidence Analysis: Analyze responses for multiple evidence types

    Confidence Scoring: Calculate confidence based on evidence

    Filtering: Apply thresholds and deduplication

    Reporting: Generate structured findings

📁 Output Structure
text

mextreme_scans/
├── scan_YYYYMMDD_HHMMSS/
│   ├── report.html              # Main HTML report
│   ├── report.json              # JSON data export
│   ├── executive_summary.md     # Executive summary
│   └── logs/
│       └── scan_YYYYMMDD_HHMMSS.log

Report Features

    Risk Score: Overall risk assessment (0-100)

    Confidence Tiers: CONFIRMED, LIKELY, POSSIBLE, INFO

    Evidence Display: Structured evidence for each finding

    Remediation Guidance: Actionable remediation steps

    References: OWASP and industry references

⚙️ Configuration
Key Configuration Options
python

# Scanning settings
REQUEST_CAP = 3000           # Maximum requests per scan
MAX_CONCURRENCY = 15         # Concurrent requests
TIMEOUT = 15                 # Request timeout in seconds
CRAWL_DEPTH = 3              # Maximum crawl depth

# Evidence thresholds
RESPONSE_DIFF_THRESHOLD = 0.1    # Minimum response difference
TIMING_THRESHOLD_MULTIPLIER = 2.0 # Timing attack threshold

# Output settings
OUTPUT_DIR = "mextreme_scans"
AUTO_OPEN_REPORT = True

# Risk scoring weights
RISK_WEIGHTS = {
    'confidence_tier': {
        'CONFIRMED': 1.0,
        'LIKELY': 0.7,
        'POSSIBLE': 0.4,
        'INFO': 0.1
    }
}

Environment Variables (Planned)
bash

export MEXTREME_OUTPUT_DIR="~/scans"
export MEXTREME_MAX_CONCURRENCY=20

🧩 Extending MEXTREME
Creating Custom Detectors
python

from detectors import Detector, DetectorTags
from typing import List

class CustomDetector(Detector):
    def __init__(self):
        super().__init__(
            id="custom-detector",
            name="Custom Vulnerability Detector",
            description="Detects custom vulnerabilities",
            category="custom",
            tags=[DetectorTags.WEB, DetectorTags.EVIDENCE_DRIVEN],
            severity_ceiling="HIGH",
            confidence_floor=0.7,
            evidence_requirements={
                'required_evidence': ['evidence1', 'evidence2'],
                'evidence_options': 2
            }
        )
    
    async def run(self, client, profile, endpoint) -> List[Vulnerability]:
        # Your detection logic here
        vulnerabilities = []
        
        # Collect evidence
        evidence = {
            'evidence1': True,
            'evidence2': "Evidence data"
        }
        
        if self.meets_evidence_requirements(evidence):
            confidence = self.calculate_confidence(evidence)
            
            if confidence >= self.confidence_floor:
                vuln = Vulnerability(
                    detector_id=self.id,
                    name=self.name,
                    url=endpoint.url,
                    confidence=confidence,
                    evidence=evidence,
                    # ... other fields
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

Registering Custom Detectors
python

# In main application
registry = DetectorRegistry()
registry.register(CustomDetector())

🛡️ Security Considerations
Safe Usage

    Legal Compliance: Only scan systems you own or have permission to test

    Rate Limiting: Built-in rate limiting to avoid DoS

    Respectful Scanning: External domain filtering enabled by default

    Evidence Preservation: All findings include evidence for verification

Privacy Features

    Email Filtering: Public contact emails can be suppressed

    Data Minimization: Only collects necessary evidence

    Local Storage: Reports stored locally only

📊 Performance Tips
For Large Targets
bash

# Increase timeouts and limits
python mextreme.py https://large-site.com --max-queue 10000 --max-params 20

# Quick reconnaissance first
python mextreme.py https://large-site.com --quick --no-subdomains

For Sensitive Environments
bash

# Reduce aggression
python mextreme.py https://sensitive-site.com \
  --max-concurrency 5 \
  --delay 0.5 \
  --no-subdomains

🔧 Troubleshooting
Common Issues

    "DNS resolution failed"

        Ensure network connectivity

        Check if dnspython is installed: pip install dnspython

    "Too many open files"

        Reduce concurrency: --max-concurrency 10

        Increase system limits: ulimit -n 4096

    "Scan too slow"

        Increase concurrency: --max-concurrency 30

        Reduce delay: Modify DELAY_BETWEEN_REQUESTS in config

    "Memory usage high"

        Reduce queue size: --max-queue 1000

        Enable quick scan: --quick

Debug Mode
bash

python mextreme.py https://example.com --verbose
# Check logs in mextreme_scans/logs/

🤝 Contributing

We welcome contributions! Please see our contributing guidelines for details.
Development Setup
bash

# Clone and setup
git clone <repository-url>
cd mextreme
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Code formatting
black mextreme.py

Adding New Features

    Fork the repository

    Create a feature branch

    Add tests for your feature

    Submit a pull request

📚 Documentation

    Architecture Overview

    Detector Development Guide

    API Reference

    Configuration Guide

📄 License

MIT License - see LICENSE file for details.
🏆 Acknowledgments

    Inspired by OWASP testing methodologies

    Built with async/await for performance

    Thanks to all contributors and testers

⚠️ Disclaimer

This tool is for authorized security testing and educational purposes only. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

Always obtain proper authorization before testing any system.
📞 Support

    Issues: GitHub Issues

    Discussions: GitHub Discussions

    Security Concerns: Please report responsibly

MEXTREME v2.0 - Because quality beats quantity in security assessment.

Created with ❤️ by the security community
