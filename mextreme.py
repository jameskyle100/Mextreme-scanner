#!/usr/bin/env python3
LOGO = r"""
███╗   ███╗███████╗██╗  ██╗████████╗██████╗ ███████╗███╗   ███╗███████╗
████╗ ████║██╔════╝██║  ██║╚══██╔══╝██╔══██╗██╔════╝████╗ ████║██╔════╝
██╔████╔██║█████╗  ███████║   ██║   ██████╔╝█████╗  ██╔████╔██║█████╗  
██║╚██╔╝██║██╔══╝  ██╔══██║   ██║   ██╔══██╗██╔══╝  ██║╚██╔╝██║██╔══╝  
██║ ╚═╝ ██║███████╗██║  ██║   ██║   ██║  ██║███████╗██║ ╚═╝ ██║███████╗
╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝

MEXTREME v2.0 - Evidence-Driven Security Assessment Platform
Version 2.0 | Low-Noise, Evidence-First Security Scanner
    ----Created by RocketRaccoon------
"""

import asyncio
import aiohttp
import sys
import os
import re
import time
import json
import signal
import socket
import random
import hashlib
import itertools
import concurrent.futures
import webbrowser
import platform
import argparse
import ssl
import ipaddress
import dns.resolver
import urllib3
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote, urlencode
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Tuple, Optional, Any, Callable
import string
from html import escape as html_escape
from collections import defaultdict
import math
import difflib
from enum import Enum

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ───────────────── CONFIGURATION ─────────────────

class Config:
    """Centralized configuration management"""
    
    # Scanning settings
    VERBOSE = True
    DEBUG = False
    REQUEST_CAP = 3000
    CRAWL_DEPTH = 3
    MAX_CRAWL_URLS = 2000
    MAX_CONCURRENCY = 15
    THREAD_POOL_SIZE = 30
    TIMEOUT = 15
    DELAY_BETWEEN_REQUESTS = 0.05
    MAX_PARAMS_PER_URL = 10
    
    # Crawler queue management
    MAX_QUEUE_SIZE = 5000
    QUEUE_CHECK_INTERVAL = 100
    
    # Output settings
    OUTPUT_DIR = "mextreme_scans"
    AUTO_OPEN_REPORT = True
    
    # Security settings
    USER_AGENT_ROTATION = False
    RATE_LIMITING = True
    MAX_RATE_PER_SECOND = 10
    
    # Detection thresholds
    RESPONSE_DIFF_THRESHOLD = 0.1
    TIMING_THRESHOLD_MULTIPLIER = 2.0
    
    # Timing SQLi settings
    MIN_BASELINE_TIME = 0.1
    MAX_BASELINE_TIME = 10.0
    TIMING_VARIANCE_THRESHOLD = 0.5
    
    # Email exposure handling
    EMAIL_EXPOSURE_MAX_FINDINGS = 3
    SUPPRESS_PUBLIC_EMAILS = True
    GROUP_EMAIL_FINDINGS = True
    
    # URL validation
    SKIP_EXTERNAL_DOMAINS = True
    EXTERNAL_DOMAIN_PATTERNS = [
        r'facebook\.com', r'twitter\.com', r'linkedin\.com',
        r'\.gov\.ph$', r'\.com\.ph$', r'youtube\.com',
        r'instagram\.com', r'\.google\.', r'\.microsoft\.'
    ]
    
    # Risk scoring weights
    RISK_WEIGHTS = {
        'confidence_tier': {
            'CONFIRMED': 1.0,
            'LIKELY': 0.7,
            'POSSIBLE': 0.4,
            'INFO': 0.1
        },
        'severity': {
            'CRITICAL': 1.0,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.2,
            'INFO': 0.05
        },
        'exposure_factor': {
            'open_ports': 0.1,
            'pages_found': 0.05,
            'subdomains': 0.05,
            'directory_listings': 0.15
        }
    }
    
    # Detection modes
    DETECTOR_MODES = {
        'default': True,      # Balanced detection
        'aggressive': False,  # More payloads, lower thresholds
        'conservative': False # Fewer payloads, higher thresholds
    }
    
    # NEW: Detector configuration
    ENABLED_DETECTORS = [
        'sqli-error',
        'sqli-timing',
        'xss-reflected',
        'security-headers',
        'directory-listing',
        'email-exposure'
    ]
    
    # NEW: Evidence requirements
    EVIDENCE_REQUIREMENTS = {
        'sqli-error': {
            'min_confidence': 0.7,
            'required_evidence': ['sql_errors', 'response_diff'],
            'evidence_options': 2  # Need at least 2 of the evidence types
        },
        'sqli-timing': {
            'min_confidence': 0.8,
            'required_evidence': ['timing_delay', 'reliable_baseline'],
            'evidence_options': 2
        },
        'xss-reflected': {
            'min_confidence': 0.6,
            'required_evidence': ['payload_reflection', 'context_analysis'],
            'evidence_options': 2
        }
    }
    
    # Modules to enable
    MODULES = {
        'recon': True,
        'detectors': True,
        'bruteforce': False,
        'reporting': True,
        'subdomain_enum': True
    }

# Exclusion patterns
EXCLUDE_PATTERNS = [
    r"logout", r"logoff", r"signout", r"exit", r"destroy", r"terminate",
    r"calendar", r"page=\d+", r"offset=\d+", r"limit=\d+", r"start=\d+",
    r"wp-admin", r"wp-login", r"administrator", r"admin\.php", r"logout\.php",
    r"\.jpg$", r"\.png$", r"\.gif$", r"\.css$", r"\.js$", r"\.pdf$"
]

# Asset extensions
ASSET_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp', '.svg',
    '.css', '.scss', '.less', '.sass',
    '.js', '.jsx', '.ts', '.tsx',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz',
    '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm',
    '.csv', '.xml', '.json', '.yaml', '.yml', '.txt', '.rtf', '.md'
}

# Content types that indicate assets
ASSET_CONTENT_TYPES = {
    'image/', 'application/javascript', 'text/css', 'font/',
    'application/pdf', 'application/zip', 'audio/', 'video/'
}

# Ignored parameters
IGNORED_PARAMETERS = {
    "ver", "version", "v", "cb", "cache", "_", "t", "time", "ts",
    "timestamp", "nonce", "rand", "random", "id", "ref", "referer",
    "source", "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "sessionid", "sid", "token",
    "callback", "jsonp", "format", "type", "mode"
}

# Port scanning
PORTS_TO_CHECK = [
    80, 443, 8080, 8443, 8000, 8888,
    21, 22, 23, 25, 53, 110, 143,
    3306, 3389, 5432, 27017,
    161, 162, 389, 636,
]

# Common paths
COMMON_PATHS = [
    "/admin", "/administrator", "/login", "/wp-login.php",
    "/phpmyadmin", "/mysql", "/sql", "/pma", "/myadmin",
    "/backend", "/cp", "/controlpanel", "/dashboard",
    "/user", "/users", "/account", "/accounts",
    "/config", "/configuration", "/settings", "/setup",
    "/install", "/update", "/upgrade", "/maintenance",
    "/backup", "/backups", "/backup.zip", "/backup.tar",
    "/backup.sql", "/database.sql", "/dump.sql",
    "/.git/", "/.svn/", "/.hg/", "/.bzr/",
    "/.env", "/env", "/environment",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/security.txt",
    "/.htaccess", ".htpasswd", "/web.config",
    "/wp-admin/", "/wp-content/", "/wp-includes/",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/readme.html", "/license.txt",
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/graphql", "/graphiql", "/playground",
    "/rest/", "/soap/", "/xmlrpc.php",
    "/swagger/", "/swagger-ui/", "/swagger.json",
    "/openapi.json", "/api-docs", "/docs",
    "/actuator/health", "/actuator/info", "/actuator/metrics",
    "/health", "/status", "/ping", "/ready", "/live",
    "/monitoring", "/metrics", "/prometheus",
    "/phpinfo.php", "/test.php", "/info.php", "/debug.php",
    "/console", "/_console", "/debug", "/_debug",
]

# Subdomain wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "test", "dev",
    "staging", "stage", "prod", "production", "uat", "qa",
    "secure", "portal", "cpanel", "whm", "webdisk", "webhost",
    "ns1", "ns2", "dns1", "dns2", "mx", "mx1", "mx2",
    "vpn", "ssh", "git", "svn", "jenkins", "jira",
    "blog", "news", "media", "cdn", "assets", "static",
    "img", "images", "photos", "video", "videos",
    "download", "uploads", "files", "storage",
    "shop", "store", "cart", "checkout", "payment",
    "support", "help", "docs", "documentation",
    "wiki", "knowledgebase", "forum", "community",
    "status", "monitor", "metrics", "analytics",
    "search", "query", "elastic", "solr"
]

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# Test headers
TEST_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

# ANSI colors
class Colors:
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

# NEW: Detector Tags
class DetectorTags(Enum):
    WEB = "web"
    INJECTION = "injection"
    TIMING = "timing"
    INFO = "info"
    RECON = "recon"
    LOW_NOISE = "low-noise"
    EVIDENCE_DRIVEN = "evidence-driven"

# ───────────────── DATA MODELS ─────────────────

@dataclass
class Vulnerability:
    """Vulnerability data model"""
    id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])
    detector_id: str = ""
    name: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    request: str = ""
    response: str = ""
    confidence: float = 0.0
    confidence_tier: str = "INFO"
    severity: str = "INFO"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    evidence: Dict = field(default_factory=dict)  # NEW: Structured evidence
    details: Dict = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    suppressed: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def to_dict(self):
        return asdict(self)

@dataclass
class Endpoint:
    """Endpoint data model"""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    headers: Dict = field(default_factory=dict)
    body: str = ""
    response_time: float = 0.0
    parameters: List[Dict] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    technology: Dict = field(default_factory=dict)
    discovered: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class NetworkInfo:
    """Network information model"""
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: Dict[int, Dict] = field(default_factory=dict)
    tls_certificate: Dict = field(default_factory=dict)
    dns_records: Dict = field(default_factory=dict)
    whois_info: Dict = field(default_factory=dict)
    server_banner: str = ""
    directory_listings: List[str] = field(default_factory=list)

@dataclass
class TargetProfile:
    """Target profile data model"""
    base_url: str
    domain: str = ""
    network_info: NetworkInfo = field(default_factory=NetworkInfo)
    pages: Dict[str, Endpoint] = field(default_factory=dict)
    assets: Dict[str, Endpoint] = field(default_factory=dict)
    subdomains: Set[str] = field(default_factory=set)
    discovered_paths: Set[str] = field(default_factory=set)
    robots_txt: str = ""
    sitemap_xml: str = ""
    technology_stack: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)
    risk_score: float = 0.0  # NEW: Overall risk score

# NEW: Detector Base Class
@dataclass
class Detector:
    """Base detector class"""
    id: str
    name: str
    description: str
    category: str
    tags: List[DetectorTags]
    severity_ceiling: str  # Maximum severity this detector can report
    confidence_floor: float  # Minimum confidence to report
    enabled: bool = True
    
    # Evidence requirements
    evidence_requirements: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate detector configuration"""
        valid_severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if self.severity_ceiling not in valid_severities:
            raise ValueError(f"Invalid severity ceiling: {self.severity_ceiling}")
        
        if not 0 <= self.confidence_floor <= 1:
            raise ValueError(f"Confidence floor must be between 0 and 1: {self.confidence_floor}")
    
    async def run(self, client, profile: TargetProfile, endpoint: Endpoint) -> List[Vulnerability]:
        """Run detector on an endpoint - to be implemented by subclasses"""
        raise NotImplementedError("Detector subclasses must implement run()")
    
    def meets_evidence_requirements(self, evidence: Dict) -> bool:
        """Check if evidence meets requirements"""
        if not self.evidence_requirements:
            return True
        
        required = self.evidence_requirements.get('required_evidence', [])
        options_needed = self.evidence_requirements.get('evidence_options', len(required))
        
        if not required:
            return True
        
        # Count how many required evidence types are present
        present_count = sum(1 for req in required if req in evidence and evidence[req])
        
        return present_count >= options_needed

# ───────────────── HELPER FUNCTIONS ─────────────────

def setup_logging():
    """Setup logging configuration"""
    import logging
    
    logger = logging.getLogger('mextreme')
    logger.setLevel(logging.DEBUG if Config.DEBUG else logging.INFO)
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    log_dir = os.path.join(Config.OUTPUT_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fh = logging.FileHandler(os.path.join(log_dir, f"scan_{timestamp}.log"))
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    return logger

logger = setup_logging()

def confidence_to_tier(score: float) -> str:
    """Convert confidence score to tier"""
    if score >= 0.9:
        return "CONFIRMED"
    elif score >= 0.7:
        return "LIKELY"
    elif score >= 0.4:
        return "POSSIBLE"
    else:
        return "INFO"

def confidence_to_severity(score: float, ceiling: str = "CRITICAL") -> str:
    """Convert confidence score to severity with ceiling"""
    if score >= 0.9 and ceiling in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        return "CRITICAL" if ceiling == "CRITICAL" else ceiling
    elif score >= 0.7 and ceiling in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        return "HIGH" if ceiling == "HIGH" else ceiling
    elif score >= 0.5 and ceiling in ["MEDIUM", "LOW", "INFO"]:
        return "MEDIUM" if ceiling == "MEDIUM" else ceiling
    elif score >= 0.3 and ceiling in ["LOW", "INFO"]:
        return "LOW" if ceiling == "LOW" else ceiling
    else:
        return "INFO"

def calculate_cvss_score(severity: str) -> Tuple[float, str]:
    """Calculate CVSS score based on severity"""
    if severity == "CRITICAL":
        return 9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    elif severity == "HIGH":
        return 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    elif severity == "MEDIUM":
        return 5.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    elif severity == "LOW":
        return 3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    else:
        return 1.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

def extract_technology(headers: Dict, body: str) -> Dict:
    """Extract technology stack from headers and body"""
    tech = {}
    
    if 'Server' in headers:
        tech['server'] = headers['Server']
    
    if 'X-Powered-By' in headers:
        tech['framework'] = headers['X-Powered-By']
    
    if 'X-AspNet-Version' in headers:
        tech['aspnet'] = headers['X-AspNet-Version']
    
    # CMS detection
    if any(pattern in body.lower() for pattern in ['wp-content', 'wp-includes', 'wordpress']):
        tech['cms'] = 'WordPress'
    elif 'joomla' in body.lower():
        tech['cms'] = 'Joomla'
    elif 'drupal' in body.lower():
        tech['cms'] = 'Drupal'
    
    return tech

def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text"""
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text)))

def should_exclude_url(url: str) -> bool:
    """Check if URL should be excluded from crawling"""
    for pattern in EXCLUDE_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    
    if Config.SKIP_EXTERNAL_DOMAINS:
        if '//' in url:
            parts = url.split('//')
            if len(parts) > 2:
                middle_part = parts[1]
                if '.' in middle_part and any(ext in middle_part for ext in ['.com', '.ph', '.gov', '.net', '.org']):
                    logger.debug(f"Skipping malformed URL with external domain: {url}")
                    return True
        
        for pattern in Config.EXTERNAL_DOMAIN_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                logger.debug(f"Skipping external pattern: {url}")
                return True
    
    return False

def is_asset_url(url: str, content_type: str = "") -> bool:
    """Check if URL points to an asset"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in ASSET_EXTENSIONS):
        return True
    
    if content_type:
        ct_lower = content_type.lower()
        if any(asset_type in ct_lower for asset_type in ASSET_CONTENT_TYPES):
            return True
    
    return False

def normalize_html_for_diff(html: str) -> str:
    """Normalize HTML for better diffing"""
    if not html:
        return ""
    
    html = re.sub(r'<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>', '', html, flags=re.IGNORECASE)
    html = re.sub(r'<style\b[^<]*(?:(?!</style>)<[^<]*)*</style>', '', html, flags=re.IGNORECASE)
    
    patterns_to_remove = [
        r'\bcsrf_token\b[^>]*>',
        r'timestamp["\']?\s*:\s*["\']?\d+',
        r'nonce["\']?\s*:\s*["\']?[a-zA-Z0-9+/=]+',
        r'_="[^"]*"',
        r'data-[a-z-]+="[^"]*"',
        r'<!--.*?-->',
    ]
    
    for pattern in patterns_to_remove:
        html = re.sub(pattern, '', html, flags=re.IGNORECASE)
    
    html = re.sub(r'\s+', ' ', html)
    
    analytics_patterns = ['google-analytics', 'googletagmanager', 'facebook', 'twitter', 'linkedin']
    for pattern in analytics_patterns:
        html = re.sub(f'<[^>]*{pattern}[^>]*>', '', html, flags=re.IGNORECASE)
    
    return html.strip()

def normalize_url(url: str) -> str:
    """Normalize URL to prevent crawler explosion"""
    try:
        parsed = urlparse(url)
        
        path = parsed.path
        while '//' in path:
            path = path.replace('//', '/')
        
        netloc = parsed.netloc
        if not netloc and parsed.path:
            if parsed.path.startswith('//'):
                return url
        
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            filtered_params = {}
            
            for key, values in params.items():
                if key.lower() not in IGNORED_PARAMETERS:
                    filtered_params[key] = values[0] if values else ''
            
            if len(filtered_params) > Config.MAX_PARAMS_PER_URL:
                filtered_params = dict(list(filtered_params.items())[:Config.MAX_PARAMS_PER_URL])
            
            sorted_params = sorted(filtered_params.items())
            
            if sorted_params:
                query = urlencode(sorted_params, doseq=False)
            else:
                query = ''
        else:
            query = ''
        
        normalized = f"{parsed.scheme}://{netloc}{path.rstrip('/') or '/'}"
        if query:
            normalized += f"?{query}"
        if parsed.fragment:
            normalized += f"#{parsed.fragment}"
        
        return normalized
    except Exception as e:
        logger.debug(f"URL normalization failed for {url}: {e}")
        return url

def detect_database_technology(body: str, headers: Dict) -> Optional[str]:
    """Detect database technology from response"""
    body_lower = body.lower()
    
    mysql_patterns = [
        r'mysql_',
        r'mysqli_',
        r'you have an error in your sql syntax',
        r'mysql server version',
        r'mysql_fetch',
        r'mysql_connect',
        r'mysql_error',
    ]
    
    for pattern in mysql_patterns:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return "MySQL"
    
    postgres_patterns = [
        r'postgresql',
        r'pg_',
        r'pq_',
        r'postgres',
    ]
    
    for pattern in postgres_patterns:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return "PostgreSQL"
    
    mssql_patterns = [
        r'microsoft.*sql server',
        r'sql server',
        r'oledb.*sql',
        r'odbc.*sql server',
        r'incorrect syntax near',
    ]
    
    for pattern in mssql_patterns:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return "MSSQL"
    
    oracle_patterns = [
        r'ora-\d{5}',
        r'oracle.*error',
        r'pl/sql',
        r'oracle.*database',
    ]
    
    for pattern in oracle_patterns:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return "Oracle"
    
    sqlite_patterns = [
        r'sqlite',
        r'sqlite3',
    ]
    
    for pattern in sqlite_patterns:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return "SQLite"
    
    return None

def filter_duplicate_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """Filter duplicate findings from the same root cause"""
    unique_vulns = []
    seen_patterns = set()
    
    for vuln in vulnerabilities:
        pattern_key = f"{vuln.detector_id}:{vuln.url}:{vuln.parameter}:{hashlib.md5(vuln.payload.encode()).hexdigest()[:16]}"
        
        if pattern_key in seen_patterns:
            logger.debug(f"Filtering duplicate finding: {vuln.name} on {vuln.url}")
            continue
        
        seen_patterns.add(pattern_key)
        unique_vulns.append(vuln)
    
    logger.info(f"Filtered {len(vulnerabilities) - len(unique_vulns)} duplicate findings")
    return unique_vulns

def calculate_risk_score(profile: TargetProfile, vulnerabilities: List[Vulnerability]) -> float:
    """Calculate overall risk score (0-100)"""
    base_score = 0.0
    
    # Factor 1: Vulnerability findings
    vuln_weight = 0.6
    vuln_score = 0.0
    
    for vuln in vulnerabilities:
        if vuln.suppressed:
            continue
        
        tier_weight = Config.RISK_WEIGHTS['confidence_tier'].get(vuln.confidence_tier, 0.1)
        severity_weight = Config.RISK_WEIGHTS['severity'].get(vuln.severity, 0.05)
        
        vuln_score += (tier_weight * severity_weight * 20)  # Max 20 per finding
    
    vuln_score = min(vuln_score, 60.0)  # Cap at 60
    
    # Factor 2: Exposure factors
    exposure_weight = 0.4
    exposure_score = 0.0
    
    # Open ports
    port_score = len(profile.network_info.xposure_factor']['open_ports']
    
    # Pages found
    page_score = min(len(profile.pages) * Config.RISK_WEIGHTS['exposure_factor']['pages_found'], 10)
    
    # Subdomains
    subdomain_score = min(len(profile.subdomains) * Config.RISK_WEIGHTS['exposure_factor']['subdomains'], 5)
    
    # Directory listings
    dir_score = len(profile.network_info.directory_listings) * Config.RISK_WEIGHTS['exposure_factor']['directory_listings']
    
    exposure_score = min(port_score + page_score + subdomain_score + dir_score, 40.0)
    
    # Combine scores
    base_score = vuln_score + exposure_score
    
    # Normalize to 0-100 scale
    risk_score = min(base_score, 100.0)
    
    return round(risk_score, 1)

# ───────────────── NETWORK SCANNER ─────────────────

class EnhancedNetworkScanner:
    """Network reconnaissance"""
    
    def __init__(self):
        self.results = NetworkInfo()
    
    def perform_recon(self, domain: str) -> NetworkInfo:
        logger.info(f"Performing reconnaissance on {domain}...")
        self.resolve_dns(domain)
        
        if self.results.ip_addresses:
            self.scan_ports(self.results.ip_addresses[0])
        
        self.check_tls_certificate(domain)
        self.grab_http_banner(domain)
        self.get_whois_info(domain)
        
        return self.results
    
    def resolve_dns(self, domain: str):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            self.results.ip_addresses = [str(r) for r in answers]
            
            record_types = ['MX', 'NS', 'TXT', 'CNAME', 'SOA']
            for rt in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rt)
                    self.results.dns_records[rt] = [str(r) for r in answers]
                except:
                    pass
        except Exception as e:
            logger.warning(f"DNS resolution failed: {e}")
    
    def scan_ports(self, ip: str):
        logger.info(f"Scanning ports on {ip}...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.THREAD_POOL_SIZE) as executor:
            futures = {executor.submit(self.check_port_service, ip, port): port for port in PORTS_TO_CHECK}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    port, service, banner = result
                    self.results.open_ports[port] = {
                        'service': service,
                        'banner': banner[:200] if banner else '',
                        'ip': ip
                    }
    
    def check_port_service(self, ip: str, port: int) -> Optional[Tuple[int, str, str]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                try:
                    sock.settimeout(3)
                    
                    if port in [80, 8080, 8000]:
                        sock.send(b"GET / HTTP/1.0\r\n\r\n")
                    elif port == 443:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        ssl_sock = context.wrap_socket(sock, server_hostname=ip)
                        ssl_sock.send(b"GET / HTTP/1.0\r\n\r\n")
                        sock = ssl_sock
                    elif port == 21:
                        sock.send(b"\r\n")
                    elif port == 22:
                        sock.send(b"SSH-2.0-MEXTREME\r\n")
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    service = self.identify_service(port, banner)
                    
                    return port, service, banner
                except:
                    return port, "Unknown", ""
            sock.close()
        except:
            pass
        return None
    
    def identify_service(self, port: int, banner: str) -> str:
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            27017: 'MongoDB', 8080: 'HTTP-Proxy'
        }
        
        if port in common_services:
            return common_services[port]
        
        banner_lower = banner.lower()
        if 'apache' in banner_lower:
            return 'Apache'
        elif 'nginx' in banner_lower:
            return 'Nginx'
        elif 'iis' in banner_lower:
            return 'IIS'
        elif 'openssh' in banner_lower:
            return 'OpenSSH'
        
        return 'Unknown'
    
    def check_tls_certificate(self, domain: str):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        self.results.tls_certificate = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert.get('version', ''),
                            'notBefore': cert.get('notBefore', ''),
                            'notAfter': cert.get('notAfter', ''),
                            'expires_in_days': self.get_cert_expiry_days(cert.get('notAfter', ''))
                        }
        except Exception as e:
            logger.debug(f"TLS certificate check failed: {e}")
    
    def get_cert_expiry_days(self, not_after: str) -> Optional[int]:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.utcnow()
            return (expiry - now).days
        except:
            return None
    
    def grab_http_banner(self, domain: str):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((domain, 80))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.results.server_banner = banner[:500]
            sock.close()
        except:
            pass
    
    def get_whois_info(self, domain: str):
        try:
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1]
                self.results.whois_info = {
                    'domain': domain,
                    'tld': tld,
                    'note': 'WHOIS lookup requires external library'
                }
        except:
            pass

# ───────────────── SECURE SUBDOMAIN ENUMERATOR ─────────────────

class SecureSubdomainEnumerator:
    """Secure subdomain enumeration"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.found_subdomains = set()
        self.wildcard_detected = False
        self.wildcard_ips = set()
        self.resolution_cache = {}
    
    async def enumerate(self, client) -> Set[str]:
        """Enumerate subdomains with strict validation"""
        if not Config.MODULES.get('subdomain_enum', True):
            logger.info("Subdomain enumeration disabled")
            return self.found_subdomains
        
        logger.info(f"Enumerating subdomains for {self.domain}...")
        
        await self.detect_wildcard_dns()
        
        if self.wildcard_detected:
            logger.warning(f"Wildcard DNS detected. Results filtered.")
        
        tasks = []
        for sub in SUBDOMAIN_WORDLIST:
            subdomain = f"{sub}.{self.domain}"
            tasks.append(self.check_subdomain(subdomain, client))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_subdomains = []
        for result in results:
            if isinstance(result, str) and result:
                if not self.is_wildcard_subdomain(result):
                    valid_subdomains.append(result)
        
        self.found_subdomains.update(valid_subdomains)
        logger.info(f"Found {len(self.found_subdomains)} valid subdomains")
        return self.found_subdomains
    
    async def detect_wildcard_dns(self):
        """Detect wildcard DNS with multiple random tests"""
        try:
            random_ips_set = set()
            
            for i in range(3):
                random_str = hashlib.md5(str(time.time() + i).encode()).hexdigest()[:16]
                test_subdomain = f"{random_str}.{self.domain}"
                
                try:
                    answers = dns.resolver.resolve(test_subdomain, 'A')
                    if answers:
                        for r in answers:
                            random_ips_set.add(str(r))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
            
            if len(random_ips_set) > 0:
                common_placeholder_ips = {'127.0.0.1', '0.0.0.0', '255.255.255.255'}
                if not random_ips_set.issubset(common_placeholder_ips):
                    self.wildcard_detected = True
                    self.wildcard_ips = random_ips_set
                    logger.debug(f"Wildcard DNS detected: IPs {self.wildcard_ips}")
                    
        except Exception as e:
            logger.debug(f"Wildcard detection failed: {e}")
    
    def is_wildcard_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain is a wildcard response"""
        if not self.wildcard_detected:
            return False
        
        try:
            if subdomain in self.resolution_cache:
                resolved_ips = self.resolution_cache[subdomain]
            else:
                answers = dns.resolver.resolve(subdomain, 'A')
                resolved_ips = {str(r) for r in answers}
                self.resolution_cache[subdomain] = resolved_ips
            
            if resolved_ips == self.wildcard_ips:
                return True
            
            if len(resolved_ips) > 0 and len(self.wildcard_ips) > 0:
                wildcard_first_octets = {ip.split('.')[0] for ip in self.wildcard_ips}
                resolved_first_octets = {ip.split('.')[0] for ip in resolved_ips}
                
                if wildcard_first_octets == resolved_first_octets:
                    logger.debug(f"Subdomain {subdomain} shares IP range with wildcard")
                    return True
                    
        except:
            pass
        
        return False
    
    async def check_subdomain(self, subdomain: str, client) -> Optional[str]:
        """Check if subdomain exists with HTTP validation"""
        try:
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                if not answers:
                    return None
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return None
            
            if self.is_wildcard_subdomain(subdomain):
                return None
            
            for scheme in ['https', 'http']:
                url = f"{scheme}://{subdomain}"
                
                try:
                    status, headers, body = await client.fetch(url, retries=1)
                    
                    if status is not None:
                        if self.has_meaningful_content(status, headers, body):
                            logger.debug(f"Found subdomain: {subdomain}")
                            return subdomain
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
                    
        except Exception as e:
            logger.debug(f"Subdomain check failed: {e}")
        
        return None
    
    def has_meaningful_content(self, status: int, headers: Dict, body: str) -> bool:
        """Check if response has meaningful content"""
        if status >= 500:
            return False
        
        if status == 404:
            return False
        
        default_indicators = [
            "default page", "under construction", "coming soon",
            "apache", "nginx", "iis", "welcome to", "index of",
            "test page", "placeholder"
        ]
        
        body_lower = body.lower()
        for indicator in default_indicators:
            if indicator in body_lower:
                return False
        
        content_type = headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type:
            return True
        
        if len(body) < 200:
            return False
        
        return True

# ───────────────── ASYNC HTTP CLIENT ─────────────────

class EnhancedAsyncHTTPClient:
    """HTTP client with rate limiting"""
    
    def __init__(self, scan_id: str):
        self.session = None
        self.request_count = 0
        self.scan_id = scan_id
        self.host_last_request = {}
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=Config.MAX_CONCURRENCY)
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=Config.TIMEOUT),
            connector=connector,
            headers={"User-Agent": USER_AGENTS[0]}
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def fetch(self, url: str, method: str = "GET", data: Any = None, 
                   headers: Dict = None, retries: int = 2) -> Tuple[Optional[int], Dict, str]:
        
        self.request_count += 1
        
        if self.request_count >= Config.REQUEST_CAP:
            logger.debug(f"Request cap reached, skipping: {url}")
            return None, {}, ""
        
        parsed = urlparse(url)
        host = parsed.netloc
        
        if host in self.host_last_request:
            elapsed = time.time() - self.host_last_request[host]
            if elapsed < 1.0 / Config.MAX_RATE_PER_SECOND:
                await asyncio.sleep(1.0 / Config.MAX_RATE_PER_SECOND - elapsed)
        
        request_headers = TEST_HEADERS.copy()
        if headers:
            request_headers.update(headers)
        
        await asyncio.sleep(Config.DELAY_BETWEEN_REQUESTS)
        
        for attempt in range(retries):
            try:
                start_time = time.time()
                async with self.session.request(
                    method, url, 
                    data=data, 
                    headers=request_headers, 
                    ssl=False
                ) as response:
                    response_time = time.time() - start_time
                    self.host_last_request[host] = time.time()
                    
                    body = await response.text(errors='ignore')
                    response_headers = dict(response.headers)
                    response_headers['X-Response-Time'] = str(response_time)
                    
                    return response.status, response_headers, body
                    
            except Exception as e:
                logger.debug(f"Request failed: {url} - {e}")
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    return None, {}, ""
        
        return None, {}, ""

# ───────────────── DETECTORS ─────────────────

# Base Evidence Analyzers
class EvidenceAnalyzer:
    """Base class for evidence analysis"""
    
    @staticmethod
    def analyze_sql_errors(payload_response: str, baseline: str) -> Dict:
        """Analyze SQL errors in response"""
        sql_error_patterns = [
            (r"You have an error in your SQL syntax", "MySQL syntax error"),
            (r"Warning: mysql", "MySQL warning"),
            (r"MySQL server version", "MySQL version disclosure"),
            (r"PostgreSQL.*ERROR", "PostgreSQL error"),
            (r"ORA-\d{5}", "Oracle error"),
            (r"Microsoft OLE DB Provider", "SQL Server error"),
            (r"Incorrect syntax near", "SQL syntax error"),
            (r"Unclosed quotation mark", "Unclosed quote"),
            (r"SQLSTATE\[", "SQLSTATE error"),
            (r"SQLite.*error", "SQLite error"),
            (r"Driver.*SQL", "SQL driver error"),
        ]
        
        errors_found = []
        
        for pattern, description in sql_error_patterns:
            payload_match = re.search(pattern, payload_response, re.IGNORECASE)
            if payload_match:
                baseline_match = re.search(pattern, baseline, re.IGNORECASE)
                if not baseline_match:
                    errors_found.append(description)
                else:
                    payload_count = len(re.findall(pattern, payload_response, re.IGNORECASE))
                    baseline_count = len(re.findall(pattern, baseline, re.IGNORECASE))
                    if payload_count > baseline_count:
                        errors_found.append(f"{description} (increased)")
        
        return {
            'found': len(errors_found) > 0,
            'errors': errors_found,
            'count': len(errors_found)
        }
    
    @staticmethod
    def analyze_response_diff(baseline: str, payload_response: str) -> Dict:
        """Analyze response differences"""
        if not baseline or not payload_response:
            return {'diff_percent': 1.0, 'significant_difference': True}
        
        norm_baseline = normalize_html_for_diff(baseline)
        norm_payload = normalize_html_for_diff(payload_response)
        
        baseline_len = len(norm_baseline)
        payload_len = len(norm_payload)
        
        if baseline_len == 0 or payload_len == 0:
            return {'diff_percent': 1.0, 'significant_difference': True}
        
        matcher = difflib.SequenceMatcher(None, norm_baseline[:5000], norm_payload[:5000])
        similarity = matcher.ratio()
        diff_percent = 1 - similarity
        
        structural_diff = diff_percent > Config.RESPONSE_DIFF_THRESHOLD
        
        error_keywords = ['error', 'exception', 'warning', 'mysql', 'sql', 'syntax']
        baseline_lower = baseline.lower()
        payload_lower = payload_response.lower()
        
        error_delta = 0
        for keyword in error_keywords:
            baseline_count = baseline_lower.count(keyword)
            payload_count = payload_lower.count(keyword)
            if payload_count > baseline_count:
                error_delta += (payload_count - baseline_count)
        
        max_error_contribution = 0.15
        error_boost = min(error_delta * 0.05, max_error_contribution)
        
        diff_percent = min(diff_percent + error_boost, 1.0)
        
        return {
            'diff_percent': diff_percent,
            'significant_difference': structural_diff or diff_percent > Config.RESPONSE_DIFF_THRESHOLD,
            'similarity': similarity,
            'error_boost_applied': error_boost
        }
    
    @staticmethod
    def analyze_timing(payload: str, baseline_time: float, payload_time: float, db_type: Optional[str]) -> Dict:
        """Analyze timing evidence"""
        match = False
        expected_delay = 0
        reliable = True
        
        if baseline_time < Config.MIN_BASELINE_TIME:
            reliable = False
            logger.debug(f"Baseline time {baseline_time:.2f}s too fast for reliable timing")
        elif baseline_time > Config.MAX_BASELINE_TIME:
            reliable = False
            logger.debug(f"Baseline time {baseline_time:.2f}s too slow for reliable timing")
        
        sleep_patterns = [
            (r'SLEEP\((\d+)\)', 1, ["MySQL", None]),
            (r'pg_sleep\((\d+)\)', 1, ["PostgreSQL"]),
            (r"WAITFOR DELAY '0:0:(\d+)'", 1, ["MSSQL"]),
            (r"DBMS_PIPE\.RECEIVE_MESSAGE\('a',(\d+)\)", 1, ["Oracle"]),
            (r'BENCHMARK\((\d+)', 0.000001, ["MySQL"]),
        ]
        
        for pattern, multiplier, supported_dbs in sleep_patterns:
            match_obj = re.search(pattern, payload, re.IGNORECASE)
            if match_obj:
                if db_type and supported_dbs and db_type not in supported_dbs:
                    logger.debug(f"Payload {pattern} not suitable for detected DB {db_type}")
                    reliable = False
                
                expected_delay = float(match_obj.group(1)) * multiplier
                break
        
        if expected_delay > 0 and reliable:
            time_difference = payload_time - baseline_time
            time_ratio = payload_time / baseline_time if baseline_time > 0 else 999
            
            if time_ratio >= Config.TIMING_THRESHOLD_MULTIPLIER:
                min_expected = expected_delay * 0.3
                max_expected = expected_delay * 3.0
                
                if min_expected <= time_difference <= max_expected:
                    match = True
                else:
                    logger.debug(f"Timing delay {time_difference:.2f}s outside expected range [{min_expected:.2f}, {max_expected:.2f}]")
            else:
                logger.debug(f"Time ratio {time_ratio:.1f} below threshold {Config.TIMING_THRESHOLD_MULTIPLIER}")
        
        return {
            'match': match,
            'expected_delay': expected_delay,
            'actual_delay': payload_time - baseline_time,
            'time_ratio': payload_time / baseline_time if baseline_time > 0 else 0,
            'reliable': reliable
        }
    
    @staticmethod
    def analyze_xss_reflection(payload: str, response: str, baseline: str) -> Dict:
        """Analyze XSS reflection evidence"""
        if payload not in response:
            return {'reflected': False}
        
        payload_pos = response.find(payload)
        if payload_pos == -1:
            return {'reflected': False}
        
        context_start = max(0, payload_pos - 100)
        context_end = min(len(response), payload_pos + len(payload) + 100)
        context = response[context_start:context_end]
        
        html_encoded = False
        encoded_patterns = ['&lt;', '&gt;', '&quot;', '&#x27;', '&#x2F;']
        for pattern in encoded_patterns:
            if pattern in context:
                html_encoded = True
                break
        
        partially_encoded = False
        if '<' in payload and '&lt;' in context:
            partially_encoded = True
        
        escaped = '\\"' in context or "\\'" in context
        
        in_script = False
        before = response[:payload_pos]
        script_start = before.rfind('<script')
        script_end = before.rfind('</script')
        if script_start > script_end:
            in_script = True
        
        in_attribute = False
        before_context = response[max(0, payload_pos-50):payload_pos]
        last_double_quote = before_context.rfind('"')
        last_single_quote = before_context.rfind("'")
        
        if last_double_quote > last_single_quote and last_double_quote != -1:
            in_attribute = True
        elif last_single_quote > last_double_quote and last_single_quote != -1:
            in_attribute = True
        
        javascript_context = False
        if 'javascript:' in context.lower() or 'onload=' in context.lower() or 'onerror=' in context.lower():
            javascript_context = True
        
        exploitable = False
        if in_script and not html_encoded:
            exploitable = True
        elif in_attribute and not html_encoded and not escaped:
            exploitable = True
        elif javascript_context and not html_encoded:
            exploitable = True
        elif not html_encoded and not escaped and not in_attribute and not partially_encoded:
            exploitable = True
        
        return {
            'reflected': True,
            'context': context,
            'html_encoded': html_encoded,
            'escaped': escaped,
            'partially_encoded': partially_encoded,
            'in_script': in_script,
            'in_attribute': in_attribute,
            'javascript_context': javascript_context,
            'exploitable': exploitable
        }

# SQL Injection Detector
class SQLInjectionDetector(Detector):
    """SQL Injection detector with evidence-based detection"""
    
    def __init__(self):
        super().__init__(
            id="sqli-error",
            name="SQL Injection (Error-Based)",
            description="Detects SQL injection vulnerabilities through error responses",
            category="injection",
            tags=[DetectorTags.WEB, DetectorTags.INJECTION, DetectorTags.EVIDENCE_DRIVEN, DetectorTags.LOW_NOISE],
            severity_ceiling="CRITICAL",
            confidence_floor=0.7,
            evidence_requirements={
                'required_evidence': ['sql_errors', 'response_diff', 'status_change'],
                'evidence_options': 2  # Need at least 2 types of evidence
            }
        )
        self.baseline_cache = {}
        self.db_type_cache = {}
    
    def get_payloads(self, db_type: Optional[str] = None) -> List[str]:
        """Get SQLi payloads based on detected DB"""
        generic_payloads = [
            "'", "\"", "`",
            "' OR '1'='1", "' OR 'a'='a",
            "' UNION SELECT NULL--",
            "' AND 1=1--", "' AND 1=2--",
        ]
        
        if not db_type:
            return generic_payloads
        
        targeted_payloads = generic_payloads.copy()
        
        if db_type == "MySQL":
            targeted_payloads.extend([
                "' AND SLEEP(1)--",
                "' OR SLEEP(1)--",
            ])
        elif db_type == "PostgreSQL":
            targeted_payloads.extend([
                "'; SELECT pg_sleep(1)--",
                "' OR pg_sleep(1)--",
            ])
        elif db_type == "MSSQL":
            targeted_payloads.extend([
                "' WAITFOR DELAY '0:0:1'--",
                "'; WAITFOR DELAY '0:0:1'--",
            ])
        
        return targeted_payloads
    
    async def get_baseline(self, url: str, client) -> Tuple[Optional[int], Dict, str, float]:
        """Get robust baseline"""
        if url in self.baseline_cache:
            return self.baseline_cache[url]
        
        samples = []
        sample_bodies = []
        
        for i in range(2):
            sample_start = time.time()
            sample_status, sample_headers, sample_body = await client.fetch(url)
            sample_time = time.time() - sample_start
            
            if sample_body:
                samples.append(sample_time)
                sample_bodies.append(sample_body)
            
            if i < 1:
                await asyncio.sleep(0.1)
        
        if not samples:
            result = (None, {}, "", 0.0)
            self.baseline_cache[url] = result
            return result
        
        samples_sorted = sorted(samples)
        baseline_time = samples_sorted[len(samples_sorted) // 2]
        baseline_body = sample_bodies[0] if sample_bodies else ""
        baseline_status = 200 if baseline_body else None
        
        result = (baseline_status, {}, baseline_body, baseline_time)
        self.baseline_cache[url] = result
        
        return result
    
    def detect_db_type(self, body: str, headers: Dict) -> Optional[str]:
        """Detect database type from response"""
        body_hash = hashlib.md5(body.encode()).hexdigest()
        cache_key = f"{body_hash}:{hashlib.md5(str(headers).encode()).hexdigest()}"
        
        if cache_key in self.db_type_cache:
            return self.db_type_cache[cache_key]
        
        db_type = detect_database_technology(body, headers)
        self.db_type_cache[cache_key] = db_type
        
        return db_type
    
    def calculate_confidence(self, evidence: Dict) -> float:
        """Calculate confidence based on evidence"""
        confidence = 0.0
        
        # SQL errors are strong evidence
        if evidence.get('sql_errors', {}).get('found', False):
            error_count = evidence['sql_errors'].get('count', 0)
            confidence += min(0.3 + (error_count * 0.1), 0.6)
        
        # Response difference
        if evidence.get('response_diff', {}).get('significant_difference', False):
            diff_percent = evidence['response_diff'].get('diff_percent', 0)
            confidence += min(diff_percent * 0.4, 0.4)
        
        # Status change
        if evidence.get('status_change', False):
            confidence += 0.2
        
        # Timing evidence (if present)
        if evidence.get('timing', {}).get('match', False):
            if evidence['timing'].get('reliable', False):
                confidence += 0.3
            else:
                confidence += 0.1
        
        # Cap at 0.95 to avoid "perfect" scores
        return min(confidence, 0.95)
    
    async def run(self, client, profile: TargetProfile, endpoint: Endpoint) -> List[Vulnerability]:
        """Run SQLi detection on endpoint"""
        vulnerabilities = []
        
        # Only test parameters that could be vulnerable
        test_params = [p for p in endpoint.parameters 
                      if p['type'] in ['identifier', 'generic', 'search', 'pagination']]
        
        if not test_params:
            return vulnerabilities
        
        # Get baseline
        baseline_status, baseline_headers, baseline_body, baseline_time = await self.get_baseline(
            endpoint.url, client
        )
        
        if not baseline_body:
            return vulnerabilities
        
        # Detect DB type for targeted payloads
        db_type = self.detect_db_type(baseline_body, baseline_headers)
        payloads = self.get_payloads(db_type)
        
        for param in test_params:
            for payload in payloads[:5]:  # Limit to 5 payloads per parameter
                test_url = self.build_test_url(endpoint.url, param['name'], payload)
                
                payload_start = time.time()
                payload_status, payload_headers, payload_body = await client.fetch(test_url)
                payload_time = time.time() - payload_start
                
                if not payload_body:
                    continue
                
                # Collect evidence
                evidence = {}
                
                # SQL errors
                sql_errors = EvidenceAnalyzer.analyze_sql_errors(payload_body, baseline_body)
                evidence['sql_errors'] = sql_errors
                
                # Response difference
                response_diff = EvidenceAnalyzer.analyze_response_diff(baseline_body, payload_body)
                evidence['response_diff'] = response_diff
                
                # Status change
                evidence['status_change'] = baseline_status != payload_status
                
                # Timing (if payload has timing)
                if any(keyword in payload for keyword in ['SLEEP', 'pg_sleep', 'WAITFOR', 'BENCHMARK']):
                    timing = EvidenceAnalyzer.analyze_timing(payload, baseline_time, payload_time, db_type)
                    evidence['timing'] = timing
                
                # Check evidence requirements
                if not self.meets_evidence_requirements(evidence):
                    continue
                
                # Calculate confidence
                confidence = self.calculate_confidence(evidence)
                
                if confidence >= self.confidence_floor:
                    cvss_score, cvss_vector = calculate_cvss_score(
                        confidence_to_severity(confidence, self.severity_ceiling)
                    )
                    
                    vuln = Vulnerability(
                        detector_id=self.id,
                        name=self.name,
                        url=endpoint.url,
                        parameter=param['name'],
                        payload=payload,
                        response=payload_body[:2000],
                        confidence=confidence,
                        confidence_tier=confidence_to_tier(confidence),
                        severity=confidence_to_severity(confidence, self.severity_ceiling),
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        evidence=evidence,
                        details={
                            "database_type": db_type,
                            "errors_found": sql_errors.get('errors', []),
                            "response_difference": f"{response_diff.get('diff_percent', 0):.1%}",
                            "baseline_time": f"{baseline_time:.2f}s",
                            "payload_time": f"{payload_time:.2f}s"
                        },
                        remediation="Use parameterized queries or prepared statements. Implement proper input validation and output encoding.",
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                        ]
                    )
                    
                    vulnerabilities.append(vuln)
                    break  # One finding per parameter is enough
        
        return vulnerabilities
    
    def build_test_url(self, url: str, param_name: str, payload: str) -> str:
        """Build test URL with payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        if param_name in params:
            params[param_name] = [payload]
        else:
            params[param_name] = [payload]
        
        query_parts = []
        for p, values in params.items():
            for v in values:
                query_parts.append(f"{p}={quote(str(v))}")
        
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts)}"

# XSS Detector
class XSSDetector(Detector):
    """Cross-Site Scripting detector"""
    
    def __init__(self):
        super().__init__(
            id="xss-reflected",
            name="Cross-Site Scripting (Reflected)",
            description="Detects reflected XSS vulnerabilities",
            category="injection",
            tags=[DetectorTags.WEB, DetectorTags.INJECTION, DetectorTags.EVIDENCE_DRIVEN],
            severity_ceiling="HIGH",
            confidence_floor=0.6,
            evidence_requirements={
                'required_evidence': ['payload_reflection', 'context_analysis'],
                'evidence_options': 2
            }
        )
        self.payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\" onload=\"alert('XSS')\"",
            "javascript:alert('XSS')",
        ]
    
    async def run(self, client, profile: TargetProfile, endpoint: Endpoint) -> List[Vulnerability]:
        """Run XSS detection on endpoint"""
        vulnerabilities = []
        
        test_params = [p for p in endpoint.parameters 
                      if p['type'] in ['generic', 'search', 'identifier', 'file']]
        
        if not test_params:
            return vulnerabilities
        
        # Get baseline
        baseline_status, baseline_headers, baseline_body, _ = await client.fetch(endpoint.url)
        
        if not baseline_body:
            return vulnerabilities
        
        for param in test_params:
            for payload in self.payloads[:3]:  # Limit to 3 payloads
                test_url = self.build_test_url(endpoint.url, param['name'], payload)
                
                payload_status, payload_headers, payload_body = await client.fetch(test_url)
                
                if not payload_body:
                    continue
                
                # Analyze reflection
                reflection = EvidenceAnalyzer.analyze_xss_reflection(payload, payload_body, baseline_body)
                
                if not reflection.get('reflected', False):
                    continue
                
                # Collect evidence
                evidence = {
                    'payload_reflection': True,
                    'context_analysis': {
                        'in_script': reflection.get('in_script', False),
                        'in_attribute': reflection.get('in_attribute', False),
                        'javascript_context': reflection.get('javascript_context', False),
                        'html_encoded': reflection.get('html_encoded', False),
                        'escaped': reflection.get('escaped', False),
                        'exploitable': reflection.get('exploitable', False)
                    }
                }
                
                # Check evidence requirements
                if not self.meets_evidence_requirements(evidence):
                    continue
                
                # Calculate confidence
                confidence = self.calculate_confidence(reflection)
                
                if confidence >= self.confidence_floor:
                    cvss_score, cvss_vector = calculate_cvss_score(
                        confidence_to_severity(confidence, self.severity_ceiling)
                    )
                    
                    vuln = Vulnerability(
                        detector_id=self.id,
                        name=self.name,
                        url=endpoint.url,
                        parameter=param['name'],
                        payload=payload,
                        response=payload_body[:2000],
                        confidence=confidence,
                        confidence_tier=confidence_to_tier(confidence),
                        severity=confidence_to_severity(confidence, self.severity_ceiling),
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        evidence=evidence,
                        details={
                            "context": reflection.get('context', ''),
                            "exploitable": reflection.get('exploitable', False),
                            "in_script_tag": reflection.get('in_script', False),
                            "in_html_attribute": reflection.get('in_attribute', False),
                            "html_encoded": reflection.get('html_encoded', False)
                        },
                        remediation="Implement proper output encoding. Use Content Security Policy (CSP). Validate and sanitize all user input.",
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ]
                    )
                    
                    vulnerabilities.append(vuln)
                    break
        
        return vulnerabilities
    
    def calculate_confidence(self, reflection: Dict) -> float:
        """Calculate XSS confidence"""
        confidence = 0.3
        
        if reflection.get('exploitable', False):
            confidence += 0.4
        
        if reflection.get('in_script', False):
            confidence += 0.2
        
        if reflection.get('javascript_context', False):
            confidence += 0.1
        
        if reflection.get('partially_encoded', False):
            confidence -= 0.2
        
        if not reflection.get('html_encoded', False):
            confidence += 0.1
        
        return min(confidence, 0.85)
    
    def build_test_url(self, url: str, param_name: str, payload: str) -> str:
        """Build test URL with payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        if param_name in params:
            params[param_name] = [payload]
        else:
            params[param_name] = [payload]
        
        query_parts = []
        for p, values in params.items():
            for v in values:
                query_parts.append(f"{p}={quote(str(v))}")
        
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts)}"

# Security Headers Detector
class SecurityHeadersDetector(Detector):
    """Security Headers detector"""
    
    def __init__(self):
        super().__init__(
            id="security-headers",
            name="Missing Security Headers",
            description="Detects missing security headers",
            category="info",
            tags=[DetectorTags.WEB, DetectorTags.INFO, DetectorTags.LOW_NOISE],
            severity_ceiling="LOW",
            confidence_floor=0.4
        )
        self.required_headers = {
            "Strict-Transport-Security": {
                "description": "HTTP Strict Transport Security (HSTS) not implemented",
                "remediation": "Implement HSTS to enforce HTTPS connections"
            },
            "Content-Security-Policy": {
                "description": "Content Security Policy (CSP) not implemented",
                "remediation": "Implement CSP to prevent XSS and other injection attacks"
            },
            "X-Frame-Options": {
                "description": "Clickjacking protection missing",
                "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN"
            },
            "X-Content-Type-Options": {
                "description": "MIME type sniffing not prevented",
                "remediation": "Set X-Content-Type-Options: nosniff"
            },
            "Referrer-Policy": {
                "description": "Referrer policy not set",
                "remediation": "Set Referrer-Policy to strict-origin-when-cross-origin or stricter"
            }
        }
    
    async def run(self, client, profile: TargetProfile, endpoint: Endpoint) -> List[Vulnerability]:
        """Run security headers check"""
        vulnerabilities = []
        
        headers = endpoint.headers
        content_type = headers.get("Content-Type", "").lower()
        
        # Only check HTML pages
        if not content_type.startswith("text/html"):
            return vulnerabilities
        
        missing = []
        details = {}
        
        for header, info in self.required_headers.items():
            if header not in headers:
                missing.append(info["description"])
                details[header] = {
                    "status": "missing",
                    "description": info["description"]
                }
        
        if missing:
            confidence = 0.4 + (len(missing) * 0.1)
            confidence = min(confidence, 0.9)
            
            cvss_score, cvss_vector = calculate_cvss_score("LOW")
            
            vuln = Vulnerability(
                detector_id=self.id,
                name=self.name,
                url=endpoint.url,
                confidence=confidence,
                confidence_tier=confidence_to_tier(confidence),
                severity="LOW",
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                evidence={"missing_headers": missing},
                details=details,
                remediation="Implement all recommended security headers. See OWASP Secure Headers Project.",
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://securityheaders.com/"
                ]
            )
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities

# Email Exposure Detector
class EmailExposureDetector(Detector):
    """Email address exposure detector"""
    
    def __init__(self):
        super().__init__(
            id="email-exposure",
            name="Email Address Exposure",
            description="Detects exposed email addresses",
            category="info",
            tags=[DetectorTags.WEB, DetectorTags.INFO, DetectorTags.LOW_NOISE],
            severity_ceiling="LOW",
            confidence_floor=0.3
        )
        self.public_emails = ['info@sibugay.gov.ph', 'alphaphpn@gmail.com']
    
    async def run(self, client, profile: TargetProfile, endpoint: Endpoint) -> List[Vulnerability]:
        """Run email exposure check"""
        vulnerabilities = []
        
        body = endpoint.body
        emails = extract_emails(body)
        
        if not emails or len(emails) > 5:
            return vulnerabilities
        
        # Skip public contact emails if configured
        if Config.SUPPRESS_PUBLIC_EMAILS and all(email in self.public_emails for email in emails):
            logger.debug(f"Suppressing public email finding: {emails}")
            return vulnerabilities
        
        # Determine if it's public contact info
        is_public = any(email in self.public_emails for email in emails)
        
        if is_public:
            confidence = 0.3
            severity = "INFO"
            suppressed = True
        else:
            confidence = 0.6
            severity = "LOW"
            suppressed = False
        
        cvss_score = 1.0 if is_public else 3.1
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" if is_public else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        
        vuln = Vulnerability(
            detector_id=self.id,
            name=self.name,
            url=endpoint.url,
            confidence=confidence,
            confidence_tier=confidence_to_tier(confidence),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            evidence={"emails_found": emails, "count": len(emails)},
            details={
                "emails": emails,
                "is_public_contact": is_public,
                "email_count": len(emails)
            },
            remediation="Consider obfuscating email addresses or using contact forms for sensitive emails. Use JavaScript-based email protection or image-based email display.",
            references=[
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
            ],
            suppressed=suppressed
        )
        
        vulnerabilities.append(vuln)
        
        return vulnerabilities

# Directory Listing Detector
class DirectoryListingDetector(Detector):
    """Directory listing detector"""
    
    def __init__(self):
        super().__init__(
            id="directory-listing",
            name="Directory Listing Enabled",
            description="Detects enabled directory listings",
            category="info",
            tags=[DetectorTags.WEB, DetectorTags.RECON, DetectorTags.LOW_NOISE],
            severity_ceiling="MEDIUM",
            confidence_floor=0.8
        )
    
    async def run(self, client, profile: TargetProfile, endpoint: Endpoint) -> List[Vulnerability]:
        """Run directory listing check"""
        vulnerabilities = []
        
        # Check if this URL is in directory listings
        if endpoint.url in profile.network_info.directory_listings:
            confidence = 0.8
            cvss_score, cvss_vector = calculate_cvss_score("MEDIUM")
            
            vuln = Vulnerability(
                detector_id=self.id,
                name=self.name,
                url=endpoint.url,
                confidence=confidence,
                confidence_tier=confidence_to_tier(confidence),
                severity="MEDIUM",
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                evidence={"directory_listing": True},
                details={
                    "description": "Directory listing exposes file and directory structure",
                    "risk": "Information disclosure"
                },
                remediation="Disable directory indexing in web server configuration (Apache: Options -Indexes, Nginx: autoindex off, IIS: Directory Browsing disabled).",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Review_Webserver_Metafiles_for_Information_Leakage",
                ]
            )
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities

# Detector Registry
class DetectorRegistry:
    """Manages detector registration and execution"""
    
    def __init__(self):
        self.detectors = {}
        self.register_default_detectors()
    
    def register_default_detectors(self):
        """Register all default detectors"""
        self.register(SQLInjectionDetector())
        self.register(XSSDetector())
        self.register(SecurityHeadersDetector())
        self.register(EmailExposureDetector())
        self.register(DirectoryListingDetector())
    
    def register(self, detector: Detector):
        """Register a detector"""
        self.detectors[detector.id] = detector
    
    def get_detector(self, detector_id: str) -> Optional[Detector]:
        """Get detector by ID"""
        return self.detectors.get(detector_id)
    
    def get_enabled_detectors(self, tags: Optional[List[str]] = None, 
                            exclude_tags: Optional[List[str]] = None) -> List[Detector]:
        """Get enabled detectors, optionally filtered by tags"""
        enabled = []
        
        for detector in self.detectors.values():
            if not detector.enabled:
                continue
            
            if detector.id not in Config.ENABLED_DETECTORS:
                continue
            
            # Filter by include tags
            if tags:
                detector_tags = {tag.value for tag in detector.tags}
                if not any(tag in detector_tags for tag in tags):
                    continue
            
            # Filter by exclude tags
            if exclude_tags:
                detector_tags = {tag.value for tag in detector.tags}
                if any(tag in detector_tags for tag in exclude_tags):
                    continue
            
            enabled.append(detector)
        
        return enabled
    
    async def run_detectors(self, client, profile: TargetProfile, 
                          detectors: List[Detector]) -> List[Vulnerability]:
        """Run multiple detectors"""
        all_vulnerabilities = []
        
        for detector in detectors:
            if Config.DEBUG:
                logger.info(f"  Running detector: {detector.name}")
            
            detector_vulns = []
            
            for url, endpoint in profile.pages.items():
                try:
                    vulns = await detector.run(client, profile, endpoint)
                    detector_vulns.extend(vulns)
                except Exception as e:
                    logger.error(f"Detector {detector.id} failed on {url}: {e}")
                    if Config.DEBUG:
                        import traceback
                        traceback.print_exc()
            
            if detector_vulns:
                logger.info(f"    ✓ {detector.name}: {len(detector_vulns)} findings")
                all_vulnerabilities.extend(detector_vulns)
        
        return all_vulnerabilities
    
    def get_detector_stats(self) -> Dict:
        """Get detector statistics"""
        stats = {
            'total': len(self.detectors),
            'enabled': len(self.get_enabled_detectors()),
            'by_category': defaultdict(int),
            'by_severity': defaultdict(int)
        }
        
        for detector in self.get_enabled_detectors():
            stats['by_category'][detector.category] += 1
            
            # Map severity ceiling to count
            stats['by_severity'][detector.severity_ceiling] += 1
        
        return stats
    
    def explain_scan_plan(self, profile: TargetProfile, 
                         tags: Optional[List[str]] = None,
                         exclude_tags: Optional[List[str]] = None) -> Dict:
        """Explain what will be scanned"""
        detectors = self.get_enabled_detectors(tags, exclude_tags)
        
        plan = {
            'detectors': [],
            'summary': {
                'detector_count': len(detectors),
                'endpoint_count': len(profile.pages),
                'estimated_requests': 0
            },
            'detector_details': []
        }
        
        for detector in detectors:
            detector_info = {
                'id': detector.id,
                'name': detector.name,
                'category': detector.category,
                'severity_ceiling': detector.severity_ceiling,
                'confidence_floor': detector.confidence_floor,
                'tags': [tag.value for tag in detector.tags],
                'evidence_requirements': detector.evidence_requirements
            }
            
            plan['detectors'].append(detector.id)
            plan['detector_details'].append(detector_info)
            
            # Estimate requests (very rough)
            endpoints_with_params = sum(1 for e in profile.pages.values() if e.parameters)
            plan['summary']['estimated_requests'] += endpoints_with_params * 5  # ~5 payloads per param
        
        return plan

# ───────────────── QUEUE-MANAGED WEB CRAWLER ─────────────────

class QueueManagedWebCrawler:
    """Web crawler with strict queue growth control"""
    
    def __init__(self, client, profile: TargetProfile, scan_id: str):
        self.client = client
        self.profile = profile
        self.scan_id = scan_id
        self.visited = set()
        self.to_crawl = []
        self.start_time = time.time()
        self.total_requests = 0
        self.url_variations = defaultdict(int)
        self.queue_growth_checks = 0
        
        self.progress_data = {
            'crawled': 0,
            'discovered': 0,
            'queue': 0,
            'eta': 0,
            'rate': 0
        }
    
    async def crawl(self) -> Tuple[Dict[str, Endpoint], Dict[str, Endpoint]]:
        """Main crawling with queue growth control"""
        logger.info("Starting queue-managed web crawling...")
        
        await self.parse_robots_and_sitemap()
        await self.discover_common_paths()
        
        self.to_crawl.append((self.profile.base_url, 0))
        self.visited.discard(normalize_url(self.profile.base_url))
        
        last_update = time.time()
        
        while self.to_crawl and len(self.visited) < Config.MAX_CRAWL_URLS:
            if len(self.to_crawl) > Config.MAX_QUEUE_SIZE:
                logger.warning(f"Queue size {len(self.to_crawl)} exceeds max {Config.MAX_QUEUE_SIZE}. Truncating.")
                self.to_crawl = self.to_crawl[:Config.MAX_QUEUE_SIZE]
            
            self.queue_growth_checks += 1
            if self.queue_growth_checks % Config.QUEUE_CHECK_INTERVAL == 0:
                self.analyze_queue_growth()
            
            if self.total_requests >= Config.REQUEST_CAP:
                logger.warning(f"Request cap reached ({Config.REQUEST_CAP})")
                break
            
            url, depth = self.to_crawl.pop(0)
            
            if self.should_exclude(url, depth):
                continue
            
            await self.process_url(url, depth)
            
            current_time = time.time()
            if current_time - last_update > 0.5:
                self.update_progress_display()
                last_update = current_time
        
        self.update_progress_display(final=True)
        logger.info(f"Crawling complete. Found {len(self.profile.pages)} pages")
        return self.profile.pages, self.profile.assets
    
    def analyze_queue_growth(self):
        """Analyze and control queue growth"""
        current_queue_size = len(self.to_crawl)
        
        if current_queue_size > 1000:
            logger.info(f"Queue size: {current_queue_size}. Applying aggressive filtering.")
            self.to_crawl.sort(key=lambda x: x[1])
            self.to_crawl = [item for item in self.to_crawl if item[1] <= 3]
            
            if len(self.to_crawl) > Config.MAX_QUEUE_SIZE:
                self.to_crawl = self.to_crawl[:Config.MAX_QUEUE_SIZE]
    
    def should_exclude(self, url: str, depth: int) -> bool:
        """Check if URL should be excluded"""
        normalized_url = normalize_url(url)
        
        if normalized_url in self.visited:
            return True
        
        if depth > Config.CRAWL_DEPTH:
            return True
        
        if should_exclude_url(normalized_url):
            return True
        
        parsed = urlparse(normalized_url)
        path_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        self.url_variations[path_key] += 1
        
        if self.url_variations[path_key] > 20:
            logger.debug(f"Skipping excessive variations of {path_key}")
            return True
        
        return False
    
    def update_progress_display(self, final: bool = False):
        """Update progress display"""
        elapsed = time.time() - self.start_time
        crawled = len(self.visited)
        
        rate = crawled / elapsed if elapsed > 0 else 0
        remaining = len(self.to_crawl)
        eta = remaining / rate if rate > 0 else 0
        
        self.progress_data.update({
            'crawled': crawled,
            'discovered': len(self.profile.pages) + len(self.profile.assets),
            'queue': remaining,
            'eta': int(eta),
            'rate': f"{rate:.1f}/s"
        })
        
        if final or Config.VERBOSE:
            sys.stdout.write('\r' + ' ' * 100 + '\r')
            sys.stdout.write(f"{Colors.CYAN}[CRAWL]{Colors.RESET} Pages: {len(self.profile.pages):4d} | "
                           f"Queue: {remaining:4d} | "
                           f"Rate: {rate:.1f}/s | "
                           f"ETA: {int(eta):4d}s")
            sys.stdout.flush()
            
            if final:
                sys.stdout.write('\n')
    
    async def parse_robots_and_sitemap(self):
        """Parse robots.txt and sitemap.xml"""
        base = self.profile.base_url.rstrip('/')
        
        robots_url = f"{base}/robots.txt"
        status, headers, body = await self.client.fetch(robots_url)
        if status == 200:
            self.profile.robots_txt = body
            self.extract_paths_from_robots(body, base)
        
        sitemap_url = f"{base}/sitemap.xml"
        status, headers, body = await self.client.fetch(sitemap_url)
        if status == 200:
            self.profile.sitemap_xml = body
            self.extract_paths_from_sitemap(body, base)
    
    def extract_paths_from_robots(self, content: str, base_url: str):
        """Extract paths from robots.txt"""
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('Allow:') or line.startswith('Disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    full_url = urljoin(base_url + '/', path.lstrip('/'))
                    self.profile.discovered_paths.add(full_url)
    
    def extract_paths_from_sitemap(self, content: str, base_url: str):
        """Extract paths from sitemap.xml"""
        urls = re.findall(r'<loc>(.*?)</loc>', content, re.IGNORECASE)
        for url in urls:
            if urlparse(url).netloc == urlparse(base_url).netloc:
                self.profile.discovered_paths.add(url)
    
    async def discover_common_paths(self):
        """Discover common paths"""
        base = self.profile.base_url.rstrip('/')
        
        await self.robust_check_directory_indexing(base)
        
        for file in ['robots.txt', 'sitemap.xml', '.git/config', '.env', 'wp-config.php']:
            url = f"{base}/{file}"
            await self.check_and_record_url(url, is_asset=True if '.' in file else False)
    
    async def robust_check_directory_indexing(self, base_url: str):
        """Check for directory indexing"""
        test_dirs = ['/uploads/', '/files/', '/assets/', '/images/', '/backup/']
        
        for directory in test_dirs:
            url = f"{base_url}{directory}"
            status, headers, body = await self.client.fetch(url)
            
            if status in [200, 403, 401]:
                indicators_found = []
                indicators = [
                    ('Index of', 'text'),
                    ('Directory listing for', 'text'),
                    ('<title>Index of', 'html_title'),
                    ('Parent Directory', 'link'),
                    ('[To Parent Directory]', 'link'),
                    ('<pre>', 'html_tag'),
                    ('<h1>Index of', 'html_heading'),
                ]
                
                for indicator, indicator_type in indicators:
                    if indicator in body:
                        indicators_found.append((indicator, indicator_type))
                
                if len(indicators_found) >= 2:
                    file_patterns = [
                        r'\d{1,3}\.\d{1,3}\w?\s+\d{1,2}-\w{3}-\d{4}\s+\d{1,2}:\d{2}\s+<a',
                        r'(\d+\.\d+[KMG]?)\s+(\d{1,2}-\w{3}-\d{4}\s+\d{1,2}:\d{2})\s+<a',
                    ]
                    
                    file_matches = 0
                    for pattern in file_patterns:
                        if re.search(pattern, body):
                            file_matches += 1
                    
                    if file_matches > 0 or len(indicators_found) >= 3:
                        self.profile.network_info.directory_listings.append(url)
                        logger.info(f"  {Colors.YELLOW}[!]{Colors.RESET} Directory indexing: {url}")
    
    async def check_and_record_url(self, url: str, is_asset: bool = False):
        """Check URL and record it"""
        status, headers, body = await self.client.fetch(url)
        
        if status in [200, 301, 302, 401, 403, 404, 500]:
            endpoint = Endpoint(
                url=url,
                status_code=status,
                content_type=headers.get('Content-Type', ''),
                content_length=len(body) if body else 0,
                headers=dict(headers),
                body=body or "",
                technology=extract_technology(headers, body or "")
            )
            
            if is_asset or is_asset_url(url, headers.get('Content-Type', '')):
                self.profile.assets[url] = endpoint
            else:
                self.profile.pages[url] = endpoint
                endpoint.parameters = self.extract_parameters(url)
    
    async def process_url(self, url: str, depth: int):
        """Process a single URL"""
        normalized_url = normalize_url(url)
        self.visited.add(normalized_url)
        self.total_requests += 1
        
        start_time = time.time()
        status, headers, body = await self.client.fetch(url)
        response_time = time.time() - start_time
        
        if status not in (200, 301, 302, 401, 403, 406, 429):
            logger.debug(f"Skipping {url} (status {status})")
            return
        
        if not body and status == 200:
            logger.debug(f"Skipping {url} (empty body)")
            return
        
        content_type = headers.get('Content-Type', '')
        is_asset = is_asset_url(url, content_type)
        
        endpoint = Endpoint(
            url=url,
            method="GET",
            status_code=status,
            content_type=content_type,
            content_length=len(body) if body else 0,
            headers=dict(headers),
            body=body or "",
            response_time=response_time,
            technology=extract_technology(headers, body or "")
        )
        
        if is_asset:
            self.profile.assets[url] = endpoint
        else:
            endpoint.parameters = self.extract_parameters(url)
            
            if body and status in (200, 301, 302, 401, 403):
                endpoint.links = self.extract_links(body, url)
                
                for link in endpoint.links:
                    if not self.should_exclude(link, depth + 1):
                        self.to_crawl.append((link, depth + 1))
            
            self.profile.pages[url] = endpoint
    
    def extract_parameters(self, url: str) -> List[Dict]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        if not parsed.query:
            return []
        
        params = []
        seen_params = set()
        
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            if key.lower() in IGNORED_PARAMETERS:
                continue
            
            norm_key = key.lower()
            if norm_key in seen_params:
                continue
            
            seen_params.add(norm_key)
            
            params.append({
                'name': key,
                'value': values[0] if values else '',
                'type': self.guess_parameter_type(key)
            })
        
        return params
    
    def guess_parameter_type(self, name: str) -> str:
        """Guess parameter type"""
        name_lower = name.lower()
        if any(p in name_lower for p in ['id', 'user', 'account', 'customer']):
            return 'identifier'
        elif any(p in name_lower for p in ['page', 'offset', 'limit', 'start']):
            return 'pagination'
        elif any(p in name_lower for p in ['search', 'query', 'q', 'filter']):
            return 'search'
        elif any(p in name_lower for p in ['sort', 'order', 'orderby']):
            return 'sorting'
        elif any(p in name_lower for p in ['token', 'key', 'secret', 'password']):
            return 'sensitive'
        elif any(p in name_lower for p in ['file', 'path', 'url', 'redirect']):
            return 'file'
        elif 'email' in name_lower:
            return 'email'
        else:
            return 'generic'
    
    def extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = set()
        
        href_pattern = r'href\s*=\s*["\']([^"\']*)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            link = match.group(1)
            full_url = self.normalize_link(link, base_url)
            if full_url:
                normalized = normalize_url(full_url)
                if not should_exclude_url(normalized):
                    links.add(normalized)
        
        src_pattern = r'src\s*=\s*["\']([^"\']*)["\']'
        for match in re.finditer(src_pattern, html, re.IGNORECASE):
            link = match.group(1)
            full_url = self.normalize_link(link, base_url)
            if full_url:
                normalized = normalize_url(full_url)
                if not should_exclude_url(normalized):
                    links.add(normalized)
        
        return list(links)
    
    def normalize_link(self, link: str, base_url: str) -> Optional[str]:
        """Normalize a link"""
        if not link or link.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
            return None
        
        if link.startswith('//'):
            logger.debug(f"Skipping protocol-relative external URL: {link}")
            return None
        
        if link.startswith('/'):
            parsed_base = urlparse(base_url)
            return f"{parsed_base.scheme}://{parsed_base.netloc}{link}"
        elif link.startswith('./'):
            return urljoin(base_url, link[2:])
        elif link.startswith('../'):
            return urljoin(base_url, link)
        elif not link.startswith(('http://', 'https://')):
            if '.' in link and any(ext in link for ext in ['.com', '.ph', '.gov', '.net', '.org']):
                logger.debug(f"Skipping external domain without protocol: {link}")
                return None
            return urljoin(base_url + '/', link)
        
        try:
            parsed = urlparse(link)
            base_parsed = urlparse(base_url)
            
            if parsed.netloc == base_parsed.netloc:
                return link
            else:
                logger.debug(f"Skipping external domain: {parsed.netloc}")
                return None
        except:
            pass
        
        return None

# ───────────────── DETECTOR ENGINE ─────────────────

class DetectorEngine:
    """Main detector engine"""
    
    def __init__(self, client, profile: TargetProfile):
        self.client = client
        self.profile = profile
        self.registry = DetectorRegistry()
        self.vulnerabilities = []
    
    async def run_scan(self, tags: Optional[List[str]] = None,
                      exclude_tags: Optional[List[str]] = None) -> List[Vulnerability]:
        """Run detector scan"""
        logger.info("Starting evidence-driven detector scan...")
        
        detectors = self.registry.get_enabled_detectors(tags, exclude_tags)
        
        if not detectors:
            logger.warning("No detectors enabled or matched filter criteria")
            return []
        
        logger.info(f"Running {len(detectors)} detectors:")
        for detector in detectors:
            logger.info(f"  • {detector.name} ({detector.category}, severity: {detector.severity_ceiling})")
        
        self.vulnerabilities = await self.registry.run_detectors(
            self.client, self.profile, detectors
        )
        
        # Filter duplicates
        self.vulnerabilities = filter_duplicate_vulnerabilities(self.vulnerabilities)
        
        # Group by detector
        by_detector = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_detector[vuln.detector_id].append(vuln)
        
        logger.info(f"\nDetector scan complete. Found {len(self.vulnerabilities)} issues:")
        for detector_id, vulns in by_detector.items():
            detector = self.registry.get_detector(detector_id)
            if detector:
                logger.info(f"  • {detector.name}: {len(vulns)} findings")
        
        return self.vulnerabilities
    
    def explain_scan(self, tags: Optional[List[str]] = None,
                    exclude_tags: Optional[List[str]] = None) -> Dict:
        """Explain what will be scanned"""
        return self.registry.explain_scan_plan(self.profile, tags, exclude_tags)

# ───────────────── INTEGRATED REPORT GENERATOR ─────────────────

class IntegratedReportGenerator:
    """Integrated report generator"""
    
    def __init__(self, profile: TargetProfile, vulnerabilities: List[Vulnerability], scan_id: str):
        self.profile = profile
        self.vulnerabilities = [v for v in vulnerabilities if not v.suppressed]
        self.scan_id = scan_id
        self.output_dir = os.path.join(Config.OUTPUT_DIR, scan_id)
    
    def generate_all_reports(self):
        """Generate all report formats"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        logger.info("Generating integrated reports...")
        
        # Calculate risk score
        self.profile.risk_score = calculate_risk_score(self.profile, self.vulnerabilities)
        
        html_file = self.generate_html_report()
        json_file = self.generate_json_report()
        self.generate_executive_summary()
        
        logger.info(f"Reports generated in: {self.output_dir}")
        return html_file, self.output_dir
    
    def generate_html_report(self) -> str:
        """Generate HTML report"""
        filename = os.path.join(self.output_dir, "report.html")
        
        vulns_by_tier = defaultdict(list)
        for vuln in self.vulnerabilities:
            vulns_by_tier[vuln.confidence_tier].append(vuln)
        
        total_vulns = len(self.vulnerabilities)
        confirmed = len(vulns_by_tier.get("CONFIRMED", []))
        likely = len(vulns_by_tier.get("LIKELY", []))
        possible = len(vulns_by_tier.get("POSSIBLE", []))
        info = len(vulns_by_tier.get("INFO", []))
        
        # Group by detector
        by_detector = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_detector[vuln.detector_id].append(vuln)
        
        html = self._generate_html_template(confirmed, likely, possible, info, total_vulns, by_detector)
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        
        logger.info(f"HTML report generated: {filename}")
        return filename
    
    def _generate_html_template(self, confirmed, likely, possible, info, total_vulns, by_detector):
        """Generate HTML template"""
        risk_color = "green"
        if self.profile.risk_score >= 70:
            risk_color = "red"
        elif self.profile.risk_score >= 40:
            risk_color = "orange"
        elif self.profile.risk_score >= 20:
            risk_color = "yellow"
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {self.profile.base_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #2c3e50 0%, #4a6491 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .section {{ margin: 25px 0; padding: 20px; border-left: 5px solid #3498db; background: #f8f9fa; border-radius: 8px; }}
        .vuln-card {{ margin: 15px 0; padding: 20px; border: 1px solid #dee2e6; border-radius: 8px; background: white; }}
        .tier-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
        .tier-confirmed {{ background: #e74c3c; color: white; }}
        .tier-likely {{ background: #e67e22; color: white; }}
        .tier-possible {{ background: #f1c40f; color: #333; }}
        .tier-info {{ background: #3498db; color: white; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
        .severity-critical {{ background: #e74c3c; color: white; }}
        .severity-high {{ background: #e67e22; color: white; }}
        .severity-medium {{ background: #f1c40f; color: #333; }}
        .severity-low {{ background: #3498db; color: white; }}
        .severity-info {{ background: #95a5a6; color: white; }}
        .risk-score {{ font-size: 3em; font-weight: bold; color: {risk_color}; text-align: center; margin: 20px 0; }}
        .evidence-box {{ background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; padding: 10px; margin: 10px 0; font-family: monospace; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; background: white; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background: #2c3e50; color: white; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .summary-card {{ padding: 20px; background: white; border-radius: 8px; box-shadow: 0 3px 10px rgba(0,0,0,0.1); text-align: center; }}
        .pre {{ background: #2c3e50; color: white; padding: 15px; border-radius: 8px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 13px; }}
        .toggle-btn {{ background: #2c3e50; color: white; border: none; padding: 8px 16px; border-radius: 5px; cursor: pointer; margin: 10px 0; }}
        .hidden {{ display: none; }}
        .note-box {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 5px; }}
        .detector-stats {{ display: flex; flex-wrap: wrap; gap: 15px; margin: 20px 0; }}
        .detector-stat {{ background: #e9ecef; padding: 15px; border-radius: 8px; flex: 1; min-width: 200px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Assessment Report</h1>
            <h2>Target: {self.profile.base_url}</h2>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Scan ID: {self.scan_id}</p>
            <p><strong>MEXTREME v2.0</strong> - Evidence-Driven Security Scanner</p>
        </div>
        
        <div class="section">
            <h2>📈 Executive Summary</h2>
            <div class="risk-score">
                Risk Score: {self.profile.risk_score}/100
            </div>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>CONFIRMED</h3>
                    <p style="font-size: 2em; color: #e74c3c;">{confirmed}</p>
                </div>
                <div class="summary-card">
                    <h3>LIKELY</h3>
                    <p style="font-size: 2em; color: #e67e22;">{likely}</p>
                </div>
                <div class="summary-card">
                    <h3>POSSIBLE</h3>
                    <p style="font-size: 2em; color: #f1c40f;">{possible}</p>
                </div>
                <div class="summary-card">
                    <h3>INFO</h3>
                    <p style="font-size: 2em; color: #3498db;">{info}</p>
                </div>
            </div>
            <p>Total findings: <strong>{total_vulns}</strong></p>
            
            <div class="detector-stats">
                <div class="detector-stat">
                    <h4>Discovery Results</h4>
                    <p>• Pages: {len(self.profile.pages)}</p>
                    <p>• Assets: {len(self.profile.assets)}</p>
                    <p>• Subdomains: {len(self.profile.subdomains)}</p>
                    <p>• Open Ports: {len(self.profile.network_info.open_ports)}</p>
                </div>
                <div class="detector-stat">
                    <h4>Scan Statistics</h4>
                    <p>• Duration: {self.profile.metadata.get('duration', 0):.1f}s</p>
                    <p>• Requests: {self.profile.metadata.get('total_requests', 0)}</p>
                    <p>• Detectors Run: {len(by_detector)}</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ Vulnerability Findings</h2>
            {self._generate_vulnerabilities_html() if total_vulns > 0 else '<div class="note-box"><p>🎉 No significant vulnerabilities detected.</p></div>'}
        </div>
        
        <div class="section">
            <h2>🔧 Recommendations</h2>
            <ul>
                <li><strong>Immediate Action:</strong> Address CONFIRMED and LIKELY findings</li>
                <li><strong>Input Validation:</strong> Implement strict input validation</li>
                <li><strong>Security Headers:</strong> Configure security headers</li>
                <li><strong>Access Control:</strong> Review and restrict access</li>
                <li><strong>Monitoring:</strong> Implement regular security assessments</li>
            </ul>
            <p><strong>Positioning Statement:</strong> MEXTREME is a low-noise, evidence-driven security assessment engine focused on accuracy, explainability, and report-quality findings — not template volume.</p>
        </div>
    </div>
    
    <script>
        function toggleDetails(id) {{
            const element = document.getElementById(id);
            element.classList.toggle('hidden');
        }}
    </script>
</body>
</html>
"""
    
    def _generate_vulnerabilities_html(self):
        """Generate HTML for vulnerabilities"""
        html = ""
        
        for tier in ["CONFIRMED", "LIKELY", "POSSIBLE", "INFO"]:
            tier_vulns = [v for v in self.vulnerabilities if v.confidence_tier == tier]
            if tier_vulns:
                html += f"<h3>{tier} Findings ({len(tier_vulns)})</h3>"
                for i, vuln in enumerate(tier_vulns, 1):
                    html += self._generate_vuln_card(vuln, i)
        
        return html
    
    def _generate_vuln_card(self, vuln: Vulnerability, index: int) -> str:
        """Generate HTML card for a vulnerability"""
        evidence_html = ""
        if vuln.evidence:
            evidence_html = "<div class='evidence-box'>"
            for key, value in vuln.evidence.items():
                if isinstance(value, dict):
                    evidence_html += f"<strong>{key}:</strong><br>"
                    for k, v in value.items():
                        evidence_html += f"&nbsp;&nbsp;{k}: {v}<br>"
                else:
                    evidence_html += f"<strong>{key}:</strong> {value}<br>"
            evidence_html += "</div>"
        
        return f"""
        <div class="vuln-card">
            <h4>#{index}: {html_escape(vuln.name)} 
                <span class="tier-badge tier-{vuln.confidence_tier.lower()}">{vuln.confidence_tier}</span>
                <span class="severity-badge severity-{vuln.severity.lower()}">{vuln.severity}</span>
            </h4>
            <p><strong>Detector:</strong> {html_escape(vuln.detector_id)}</p>
            <p><strong>URL:</strong> {html_escape(vuln.url)}</p>
            {f'<p><strong>Parameter:</strong> {html_escape(vuln.parameter)}</p>' if vuln.parameter else ''}
            {f'<p><strong>Payload:</strong> <code>{html_escape(vuln.payload)}</code></p>' if vuln.payload else ''}
            <p><strong>Confidence:</strong> {vuln.confidence:.0%} | <strong>CVSS:</strong> {vuln.cvss_score}/10</p>
            
            <h5>Evidence:</h5>
            {evidence_html}
            
            <button class="toggle-btn" onclick="toggleDetails('details-{vuln.id}')">Show Details</button>
            <div id="details-{vuln.id}" class="hidden">
                {f'<p><strong>Response:</strong></p><pre class="pre">{html_escape(vuln.response[:1000])}</pre>' if vuln.response else ''}
                {f'<p><strong>Remediation:</strong> {html_escape(vuln.remediation)}</p>' if vuln.remediation else ''}
                {f'<p><strong>References:</strong><ul>{"".join(f"<li>{html_escape(ref)}</li>" for ref in vuln.references)}</ul></p>' if vuln.references else ''}
            </div>
        </div>
        """
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        filename = os.path.join(self.output_dir, "report.json")
        
        report = {
            "metadata": {
                "scan_id": self.scan_id,
                "scan_date": datetime.now().isoformat(),
                "target": self.profile.base_url,
                "tool": "MEXTREME v2.0 - Evidence-Driven Security Scanner",
                "duration": self.profile.metadata.get("duration", 0),
                "requests": self.profile.metadata.get("total_requests", 0),
                "risk_score": self.profile.risk_score,
                "positioning": "Low-noise, evidence-driven security assessment engine focused on accuracy and explainability"
            },
            "reconnaissance": {
                "network": asdict(self.profile.network_info),
                "subdomains": list(self.profile.subdomains),
            },
            "discovery": {
                "pages_found": len(self.profile.pages),
                "assets_found": len(self.profile.assets),
                "directory_listings": self.profile.network_info.directory_listings
            },
            "findings": {
                "total": len(self.vulnerabilities),
                "risk_score": self.profile.risk_score,
                "by_confidence_tier": {
                    "CONFIRMED": len([v for v in self.vulnerabilities if v.confidence_tier == "CONFIRMED"]),
                    "LIKELY": len([v for v in self.vulnerabilities if v.confidence_tier == "LIKELY"]),
                    "POSSIBLE": len([v for v in self.vulnerabilities if v.confidence_tier == "POSSIBLE"]),
                    "INFO": len([v for v in self.vulnerabilities if v.confidence_tier == "INFO"])
                },
                "by_severity": {
                    "CRITICAL": len([v for v in self.vulnerabilities if v.severity == "CRITICAL"]),
                    "HIGH": len([v for v in self.vulnerabilities if v.severity == "HIGH"]),
                    "MEDIUM": len([v for v in self.vulnerabilities if v.severity == "MEDIUM"]),
                    "LOW": len([v for v in self.vulnerabilities if v.severity == "LOW"]),
                    "INFO": len([v for v in self.vulnerabilities if v.severity == "INFO"])
                },
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
            }
        }
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {filename}")
        return filename
    
    def generate_executive_summary(self):
        """Generate executive summary"""
        filename = os.path.join(self.output_dir, "executive_summary.md")
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# Executive Security Assessment Summary\n\n")
            f.write(f"**Target:** {self.profile.base_url}\n")
            f.write(f"**Scan ID:** {self.scan_id}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Risk Score:** {self.profile.risk_score}/100\n\n")
            
            f.write("## 🔍 Scan Overview\n\n")
            f.write(f"**Tool:** MEXTREME v2.0 - Evidence-Driven Security Scanner\n")
            f.write(f"**Positioning:** Low-noise, evidence-driven security assessment engine focused on accuracy, explainability, and report-quality findings — not template volume.\n\n")
            
            f.write("## 📊 Key Findings\n\n")
            
            critical_vulns = [v for v in self.vulnerabilities if v.confidence_tier in ["CONFIRMED", "LIKELY"]]
            if critical_vulns:
                f.write(f"**Critical Findings:** {len(critical_vulns)}\n")
                for vuln in critical_vulns[:5]:
                    f.write(f"- {vuln.name} ({vuln.severity}, {vuln.confidence:.0%} confidence) - {vuln.url}\n")
            else:
                f.write("**No critical findings detected.**\n")
            
            f.write("\n## 🎯 Technical Overview\n\n")
            f.write(f"- **Pages discovered:** {len(self.profile.pages)}\n")
            f.write(f"- **Assets discovered:** {len(self.profile.assets)}\n")
            f.write(f"- **Open ports:** {len(self.profile.network_info.open_ports)}\n")
            f.write(f"- **Subdomains:** {len(self.profile.subdomains)}\n")
            f.write(f"- **Directory listings:** {len(self.profile.network_info.directory_listings)}\n")
            f.write(f"- **Total requests:** {self.profile.metadata.get('total_requests', 0)}\n")
            f.write(f"- **Scan duration:** {self.profile.metadata.get('duration', 0):.1f}s\n\n")
            
            f.write("## 🛡️ Evidence-Driven Approach\n\n")
            f.write("This assessment used MEXTREME's evidence-driven detection engine, which requires:\n")
            f.write("1. **Multiple evidence types** for high-confidence findings\n")
            f.write("2. **Structured evidence collection** for reproducibility\n")
            f.write("3. **Configurable confidence thresholds** to reduce false positives\n")
            f.write("4. **Detector-based architecture** for modular, explainable testing\n\n")
            
            f.write("## 🚨 Risk Assessment\n\n")
            f.write(f"**Overall Risk Score:** {self.profile.risk_score}/100\n")
            if self.profile.risk_score >= 70:
                f.write("**Risk Level:** HIGH - Immediate remediation required\n")
            elif self.profile.risk_score >= 40:
                f.write("**Risk Level:** MEDIUM - Address within next patch cycle\n")
            elif self.profile.risk_score >= 20:
                f.write("**Risk Level:** LOW - Consider in future updates\n")
            else:
                f.write("**Risk Level:** MINIMAL - Maintain current security posture\n")
        
        logger.info(f"Executive summary generated: {filename}")
        return filename

# ───────────────── MAIN APPLICATION ─────────────────

class FinalMextremeScanner:
    """Final production-ready scanner with detector architecture"""
    
    def __init__(self):
        self.profile = None
        self.vulnerabilities = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.scan_id = None
        self.detector_engine = None
    
    async def scan(self, target_url: str, tags: Optional[List[str]] = None,
                  exclude_tags: Optional[List[str]] = None,
                  explain_only: bool = False) -> Dict:
        """Main scanning function"""
        self.scan_start_time = time.time()
        self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        target_url = target_url.rstrip('/')
        parsed = urlparse(target_url)
        
        if not parsed.scheme:
            target_url = f"https://{target_url}"
            parsed = urlparse(target_url)
        
        self.profile = TargetProfile(
            base_url=target_url,
            domain=parsed.netloc
        )
        
        self.display_banner()
        
        if explain_only:
            await self.explain_scan(target_url, tags, exclude_tags)
            return {"status": "explained"}
        
        # PHASE 1: Network Recon
        await self.phase1_enhanced_recon(parsed.netloc)
        
        # PHASE 2: Web Recon
        async with EnhancedAsyncHTTPClient(self.scan_id) as client:
            await self.phase1a_secure_subdomain_enum(client, parsed.netloc)
            await self.phase2_web_recon(client)
            
            # PHASE 3: Detector-Based Assessment
            if Config.MODULES['detectors'] and self.profile.pages:
                await self.phase3_detector_assessment(client, tags, exclude_tags)
        
        # PHASE 4: Reporting
        await self.phase4_reporting()
        
        return {
            "profile": self.profile,
            "vulnerabilities": self.vulnerabilities,
            "scan_id": self.scan_id,
            "duration": self.scan_end_time - self.scan_start_time,
            "risk_score": self.profile.risk_score
        }
    
    async def explain_scan(self, target_url: str, tags: Optional[List[str]] = None,
                          exclude_tags: Optional[List[str]] = None):
        """Explain what will be scanned"""
        print(f"\n{Colors.BLUE}[EXPLAIN MODE] Scan Plan for {target_url}{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
        
        # Create a minimal profile for explanation
        parsed = urlparse(target_url)
        profile = TargetProfile(base_url=target_url, domain=parsed.netloc)
        
        # Create detector engine for explanation
        engine = DetectorEngine(None, profile)
        plan = engine.explain_scan(tags, exclude_tags)
        
        print(f"\n{Colors.CYAN}📋 Detectors to Run:{Colors.RESET} {plan['summary']['detector_count']}")
        for detector in plan['detector_details']:
            tag_str = ", ".join(detector['tags'])
            print(f"  • {Colors.GREEN}{detector['name']}{Colors.RESET}")
            print(f"    Category: {detector['category']} | Max Severity: {detector['severity_ceiling']}")
            print(f"    Min Confidence: {detector['confidence_floor']} | Tags: {tag_str}")
        
        print(f"\n{Colors.CYAN}📊 Estimated Scan:{Colors.RESET}")
        print(f"  • Endpoints to test: {plan['summary']['endpoint_count']}")
        print(f"  • Estimated requests: ~{plan['summary']['estimated_requests']}")
        
        if tags:
            print(f"\n{Colors.CYAN}🔖 Included Tags:{Colors.RESET} {', '.join(tags)}")
        if exclude_tags:
            print(f"{Colors.CYAN}🚫 Excluded Tags:{Colors.RESET} {', '.join(exclude_tags)}")
        
        print(f"\n{Colors.YELLOW}💡 Evidence Requirements:{Colors.RESET}")
        print("  • SQL Injection: Requires 2+ evidence types (errors, response diff, timing)")
        print("  • XSS: Requires reflection + context analysis")
        print("  • Findings are suppressed if evidence requirements aren't met")
        
        print(f"\n{Colors.PURPLE}🎯 Positioning:{Colors.RESET}")
        print("  MEXTREME is a low-noise, evidence-driven security assessment engine")
        print("  focused on accuracy, explainability, and report-quality findings")
        print("  — not template volume.")
        
        print(f"\n{Colors.GREEN}✅ Ready to scan. Remove --explain to execute.{Colors.RESET}")
    
    def display_banner(self):
        print()
        print(Colors.CYAN + LOGO + Colors.RESET)
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{f'MEXTREME v2.0 - EVIDENCE-DRIVEN SECURITY ASSESSMENT':^70}{Colors.RESET}")
        print(f"{Colors.BOLD}{'Low-Noise | Evidence-First | Report-Quality':^70}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.CYAN}Target:{Colors.RESET} {self.profile.base_url}")
        print(f"{Colors.CYAN}Scan ID:{Colors.RESET} {self.scan_id}")
        print(f"{Colors.CYAN}Start Time:{Colors.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
    
    async def phase1_enhanced_recon(self, domain: str):
        """Network reconnaissance"""
        print(f"\n{Colors.BLUE}[PHASE 1] NETWORK RECONNAISSANCE{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*50}{Colors.RESET}")
        
        scanner = EnhancedNetworkScanner()
        self.profile.network_info = scanner.perform_recon(domain)
        
        print(f"{Colors.GREEN}  ✓ IP Addresses:{Colors.RESET} {len(self.profile.network_info.ip_addresses)}")
        print(f"{Colors.GREEN}  ✓ Open Ports:{Colors.RESET} {len(self.profile.network_info.open_ports)}")
    
    async def phase1a_secure_subdomain_enum(self, client, domain: str):
        """Secure subdomain enumeration"""
        print(f"\n{Colors.BLUE}[PHASE 1a] SECURE SUBDOMAIN ENUMERATION{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*50}{Colors.RESET}")
        
        if Config.MODULES.get('subdomain_enum', True):
            enumerator = SecureSubdomainEnumerator(domain)
            self.profile.subdomains = await enumerator.enumerate(client)
            
            print(f"{Colors.GREEN}  ✓ Subdomains Found:{Colors.RESET} {len(self.profile.subdomains)}")
            if enumerator.wildcard_detected:
                print(f"{Colors.YELLOW}  ⚠ Wildcard DNS detected - results filtered{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}  ℹ Subdomain enumeration disabled{Colors.RESET}")
    
    async def phase2_web_recon(self, client):
        """Web reconnaissance with queue management"""
        print(f"\n{Colors.BLUE}[PHASE 2] QUEUE-MANAGED WEB RECONNAISSANCE{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*50}{Colors.RESET}")
        print(f"{Colors.CYAN}  Strict queue growth control enabled{Colors.RESET}")
        print(f"{Colors.CYAN}  Max queue size: {Config.MAX_QUEUE_SIZE}{Colors.RESET}")
        print(f"{Colors.CYAN}  External domain filtering enabled{Colors.RESET}")
        
        crawler = QueueManagedWebCrawler(client, self.profile, self.scan_id)
        self.profile.pages, self.profile.assets = await crawler.crawl()
        
        print(f"\n{Colors.GREEN}  ✓ Pages Discovered:{Colors.RESET} {len(self.profile.pages)}")
        print(f"{Colors.GREEN}  ✓ Assets Discovered:{Colors.RESET} {len(self.profile.assets)}")
        print(f"{Colors.GREEN}  ✓ Max Queue Size:{Colors.RESET} {Config.MAX_QUEUE_SIZE}")
        
        self.profile.metadata['total_requests'] = client.request_count
    
    async def phase3_detector_assessment(self, client, tags: Optional[List[str]] = None,
                                        exclude_tags: Optional[List[str]] = None):
        """Detector-based vulnerability assessment"""
        print(f"\n{Colors.BLUE}[PHASE 3] DETECTOR-BASED VULNERABILITY ASSESSMENT{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*50}{Colors.RESET}")
        print(f"{Colors.CYAN}  Evidence-driven detection engine{Colors.RESET}")
        print(f"{Colors.CYAN}  Structured evidence collection{Colors.RESET}")
        print(f"{Colors.CYAN}  Configurable confidence thresholds{Colors.RESET}")
        
        self.detector_engine = DetectorEngine(client, self.profile)
        self.vulnerabilities = await self.detector_engine.run_scan(tags, exclude_tags)
        
        # Filter duplicates
        self.vulnerabilities = filter_duplicate_vulnerabilities(self.vulnerabilities)
        
        # Calculate statistics
        by_tier = defaultdict(list)
        by_severity = defaultdict(list)
        by_detector = defaultdict(list)
        
        for vuln in self.vulnerabilities:
            by_tier[vuln.confidence_tier].append(vuln)
            by_severity[vuln.severity].append(vuln)
            by_detector[vuln.detector_id].append(vuln)
        
        print(f"\n{Colors.GREEN}  ✓ CONFIRMED:{Colors.RESET} {len(by_tier.get('CONFIRMED', []))}")
        print(f"{Colors.YELLOW}  ✓ LIKELY:{Colors.RESET} {len(by_tier.get('LIKELY', []))}")
        print(f"{Colors.CYAN}  ✓ POSSIBLE:{Colors.RESET} {len(by_tier.get('POSSIBLE', []))}")
        print(f"{Colors.BLUE}  ✓ INFO:{Colors.RESET} {len(by_tier.get('INFO', []))}")
        print(f"{Colors.PURPLE}  ✓ Total Findings:{Colors.RESET} {len(self.vulnerabilities)}")
        
        # Show detector breakdown
        print(f"\n{Colors.CYAN}  Detector Breakdown:{Colors.RESET}")
        for detector_id, vulns in by_detector.items():
            detector = self.detector_engine.registry.get_detector(detector_id)
            if detector:
                print(f"    • {detector.name}: {len(vulns)}")
        
        # Show suppressed count
        suppressed = sum(1 for v in self.vulnerabilities if v.suppressed)
        if suppressed > 0:
            print(f"{Colors.CYAN}  ✓ Suppressed:{Colors.RESET} {suppressed} (public emails, etc.)")
    
    async def phase4_reporting(self):
        """Reporting with integrated generator"""
        print(f"\n{Colors.BLUE}[PHASE 4] REPORTING{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*50}{Colors.RESET}")
        
        self.scan_end_time = time.time()
        duration = self.scan_end_time - self.scan_start_time
        
        self.profile.metadata['duration'] = duration
        self.profile.metadata['vulnerabilities_found'] = len(self.vulnerabilities)
        self.profile.metadata['scan_id'] = self.scan_id
        
        if Config.MODULES['reporting']:
            reporter = IntegratedReportGenerator(self.profile, self.vulnerabilities, self.scan_id)
            html_report, report_dir = reporter.generate_all_reports()
            
            self.display_summary(report_dir)
            
            if Config.AUTO_OPEN_REPORT and html_report:
                self.open_report(html_report)
    
    def display_summary(self, report_dir: str):
        """Display scan summary"""
        duration = self.scan_end_time - self.scan_start_time
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{'SCAN SUMMARY':^70}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}📊 Discovery Results:{Colors.RESET}")
        print(f"  • Pages: {len(self.profile.pages)}")
        print(f"  • Assets: {len(self.profile.assets)}")
        print(f"  • Subdomains: {len(self.profile.subdomains)}")
        print(f"  • Open Ports: {len(self.profile.network_info.open_ports)}")
        
        print(f"\n{Colors.CYAN}⚠️  Vulnerability Findings:{Colors.RESET}")
        by_tier = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_tier[vuln.confidence_tier].append(vuln)
        
        for tier in ["CONFIRMED", "LIKELY", "POSSIBLE", "INFO"]:
            count = len(by_tier.get(tier, []))
            if count > 0:
                color = {
                    "CONFIRMED": Colors.RED,
                    "LIKELY": Colors.YELLOW,
                    "POSSIBLE": Colors.PURPLE,
                    "INFO": Colors.BLUE
                }[tier]
                print(f"  • {color}{tier}:{Colors.RESET} {count}")
        
        print(f"\n{Colors.CYAN}🎯 Risk Assessment:{Colors.RESET}")
        print(f"  • Risk Score: {self.profile.risk_score}/100")
        
        print(f"\n{Colors.CYAN}📈 Statistics:{Colors.RESET}")
        print(f"  • Duration: {duration:.1f}s")
        print(f"  • Requests: {self.profile.metadata.get('total_requests', 0)}")
        print(f"  • Detectors Run: {len(set(v.detector_id for v in self.vulnerabilities))}")
        
        print(f"\n{Colors.GREEN}📁 Reports saved to:{Colors.RESET} {report_dir}")
        print(f"\n{Colors.YELLOW}💡 Positioning:{Colors.RESET}")
        print("  MEXTREME is a low-noise, evidence-driven security assessment engine")
        print("  focused on accuracy, explainability, and report-quality findings")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
    
    def open_report(self, html_file: str):
        """Open HTML report in browser"""
        try:
            abs_path = os.path.abspath(html_file)
            
            if platform.system() == 'Darwin':
                os.system(f'open "{abs_path}"')
            elif platform.system() == 'Windows':
                os.system(f'start "" "{abs_path}"')
            else:
                os.system(f'xdg-open "{abs_path}"')
            
            print(f"{Colors.GREEN}📖 Report opened in browser{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️  Could not open browser: {e}{Colors.RESET}")

# ───────────────── COMMAND LINE INTERFACE ─────────────────

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="MEXTREME v2.0 - Evidence-Driven Security Assessment Platform"
    )
    
    parser.add_argument("target", nargs="?", help="Target URL to scan")
    parser.add_argument("-o", "--output", help="Output directory name")
    parser.add_argument("--no-browser", action="store_true", help="Don't open report in browser")
    parser.add_argument("--quick", action="store_true", help="Quick scan")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain enumeration")
    parser.add_argument("--max-params", type=int, default=10, help="Max parameters per URL")
    parser.add_argument("--max-queue", type=int, default=5000, help="Max crawler queue size")
    
    # NEW: Detector filtering options
    parser.add_argument("--tags", help="Comma-separated list of tags to include (web,injection,info,recon,timing,low-noise)")
    parser.add_argument("--exclude-tags", help="Comma-separated list of tags to exclude")
    
    # NEW: Explain mode
    parser.add_argument("--explain", action="store_true", help="Explain scan plan without executing")
    
    # NEW: Detector management
    parser.add_argument("--list-detectors", action="store_true", help="List all available detectors")
    parser.add_argument("--disable-detector", action="append", help="Disable specific detector by ID")
    parser.add_argument("--enable-detector", action="append", help="Enable specific detector by ID")
    
    return parser.parse_args()

async def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Handle list-detectors flag
    if args.list_detectors:
        print(f"\n{Colors.CYAN}Available Detectors:{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        # Create a dummy engine to list detectors
        engine = DetectorEngine(None, TargetProfile(base_url="example.com"))
        
        for detector_id, detector in engine.registry.detectors.items():
            tags_str = ", ".join([tag.value for tag in detector.tags])
            enabled = detector.id in Config.ENABLED_DETECTORS
            
            status = f"{Colors.GREEN}✓{Colors.RESET}" if enabled else f"{Colors.RED}✗{Colors.RESET}"
            print(f"{status} {Colors.BOLD}{detector.name}{Colors.RESET} ({detector.id})")
            print(f"  Description: {detector.description}")
            print(f"  Category: {detector.category} | Max Severity: {detector.severity_ceiling}")
            print(f"  Min Confidence: {detector.confidence_floor} | Tags: {tags_str}")
            if detector.evidence_requirements:
                reqs = detector.evidence_requirements.get('required_evidence', [])
                options = detector.evidence_requirements.get('evidence_options', len(reqs))
                print(f"  Evidence: Need {options} of {reqs}")
            print()
        
        print(f"{Colors.YELLOW}Usage:{Colors.RESET}")
        print("  python mextreme.py https://example.com --tags injection,web")
        print("  python mextreme.py https://example.com --exclude-tags info")
        print("  python mextreme.py https://example.com --explain")
        return
    
    if not args.target and not args.list_detectors:
        print(f"{Colors.RED}Error: Target URL is required{Colors.RESET}")
        print(f"\n{Colors.YELLOW}Usage:{Colors.RESET}")
        print("  python mextreme.py https://example.com")
        print("  python mextreme.py --list-detectors")
        print("  python mextreme.py https://example.com --explain")
        return
    
    if args.output:
        Config.OUTPUT_DIR = args.output
    
    if args.no_browser:
        Config.AUTO_OPEN_REPORT = False
    
    if args.quick:
        Config.MAX_CRAWL_URLS = 300
        Config.REQUEST_CAP = 800
        Config.CRAWL_DEPTH = 2
    
    if args.verbose:
        Config.VERBOSE = True
        Config.DEBUG = True
    
    if args.no_subdomains:
        Config.MODULES['subdomain_enum'] = False
    
    if args.max_params:
        Config.MAX_PARAMS_PER_URL = args.max_params
    
    if args.max_queue:
        Config.MAX_QUEUE_SIZE = args.max_queue
    
    # Handle detector management
    if args.disable_detector:
        for detector_id in args.disable_detector:
            if detector_id in Config.ENABLED_DETECTORS:
                Config.ENABLED_DETECTORS.remove(detector_id)
                print(f"{Colors.YELLOW}Disabled detector: {detector_id}{Colors.RESET}")
    
    if args.enable_detector:
        for detector_id in args.enable_detector:
            if detector_id not in Config.ENABLED_DETECTORS:
                Config.ENABLED_DETECTORS.append(detector_id)
                print(f"{Colors.GREEN}Enabled detector: {detector_id}{Colors.RESET}")
    
    # Parse tags
    tags = None
    if args.tags:
        tags = [tag.strip() for tag in args.tags.split(',')]
    
    exclude_tags = None
    if args.exclude_tags:
        exclude_tags = [tag.strip() for tag in args.exclude_tags.split(',')]
    
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
    
    scanner = FinalMextremeScanner()
    
    try:
        await scanner.scan(
            args.target,
            tags=tags,
            exclude_tags=exclude_tags,
            explain_only=args.explain
        )
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Scan interrupted{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error: {e}{Colors.RESET}")
        if Config.DEBUG:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print(f"{Colors.RED}Error: Python 3.7+ required{Colors.RESET}")
        sys.exit(1)
    
    try:
        import dns.resolver
    except ImportError:
        print(f"{Colors.YELLOW}Warning: dnspython not installed{Colors.RESET}")
        print(f"{Colors.CYAN}Install with: pip install dnspython{Colors.RESET}")
    
    asyncio.run(main())
