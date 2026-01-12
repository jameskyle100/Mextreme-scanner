#!/usr/bin/env python3
LOGO = r"""
███╗   ███╗███████╗██╗  ██╗████████╗██████╗ ███████╗███╗   ███╗███████╗
████╗ ████║██╔════╝██║  ██║╚══██╔══╝██╔══██╗██╔════╝████╗ ████║██╔════╝
██╔████╔██║█████╗  ███████║   ██║   ██████╔╝█████╗  ██╔████╔██║█████╗  
██║╚██╔╝██║██╔══╝  ██╔══██║   ██║   ██╔══██╗██╔══╝  ██║╚██╔╝██║██╔══╝  
██║ ╚═╝ ██║███████╗██║  ██║   ██║   ██║  ██║███████╗██║ ╚═╝ ██║███████╗
╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝

MEXTREME v1.1 - Professional Security Assessment Platform
Version 1.1 | Professional Security Testing Tool
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
from typing import List, Dict, Set, Tuple, Optional, Any
import string
from html import escape as html_escape
from collections import defaultdict
import math
import difflib

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
    
    # Crawler queue management (NEW: Queue growth control)
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
    SQLI_CONFIDENCE_THRESHOLD = 0.7
    XSS_CONFIDENCE_THRESHOLD = 0.6
    RESPONSE_DIFF_THRESHOLD = 0.1
    TIMING_THRESHOLD_MULTIPLIER = 2.0
    
    # Timing SQLi settings (NEW: Improved handling)
    MIN_BASELINE_TIME = 0.1  # Minimum baseline for reliable comparison
    MAX_BASELINE_TIME = 10.0  # Maximum baseline (too slow = unreliable)
    TIMING_VARIANCE_THRESHOLD = 0.5  # Allowable timing variance
    
    # NEW: Email exposure handling
    EMAIL_EXPOSURE_MAX_FINDINGS = 3  # Max email findings to report
    SUPPRESS_PUBLIC_EMAILS = True    # Auto-suppress public contact emails
    GROUP_EMAIL_FINDINGS = True      # Group duplicate email findings
    
    # NEW: URL validation
    SKIP_EXTERNAL_DOMAINS = True     # Skip external domains in crawler
    EXTERNAL_DOMAIN_PATTERNS = [     # Patterns to skip
        r'facebook\.com', r'twitter\.com', r'linkedin\.com',
        r'\.gov\.ph$', r'\.com\.ph$', r'youtube\.com',
        r'instagram\.com', r'\.google\.', r'\.microsoft\.'
    ]
    
    # Modules to enable
    MODULES = {
        'recon': True,
        'vuln_scan': True,
        'bruteforce': False,
        'exploit': False,
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

# ───────────────── DATA MODELS ─────────────────

@dataclass
class Vulnerability:
    """Vulnerability data model"""
    id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])
    type: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    request: str = ""
    response: str = ""
    confidence: float = 0.0
    confidence_tier: str = "INFO"
    level: str = "INFO"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    details: Dict = field(default_factory=dict)
    evidence: str = ""
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

def confidence_level(score: float) -> str:
    """Convert confidence score to severity level"""
    if score >= 0.9:
        return "CRITICAL"
    if score >= 0.7:
        return "HIGH"
    if score >= 0.5:
        return "MEDIUM"
    if score >= 0.3:
        return "LOW"
    return "INFO"

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
    """Check if URL should be excluded from crawling - FIXED VERSION"""
    for pattern in EXCLUDE_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    
    # NEW: Skip external domains that got malformed
    if Config.SKIP_EXTERNAL_DOMAINS:
        # Skip URLs with double slashes that contain domains
        if '//' in url:
            parts = url.split('//')
            if len(parts) > 2:
                # URL like https://domain.com//facebook.com
                middle_part = parts[1]
                if '.' in middle_part and any(ext in middle_part for ext in ['.com', '.ph', '.gov', '.net', '.org']):
                    logger.debug(f"Skipping malformed URL with external domain: {url}")
                    return True
        
        # Check for external domain patterns
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
    """Normalize URL to prevent crawler explosion - FIXED VERSION"""
    try:
        parsed = urlparse(url)
        
        # FIX: Fix malformed URLs with double slashes
        path = parsed.path
        while '//' in path:
            path = path.replace('//', '/')
        
        # FIX: Ensure proper netloc
        netloc = parsed.netloc
        if not netloc and parsed.path:
            # This handles malformed URLs like "//facebook.com"
            if parsed.path.startswith('//'):
                # This is actually an external URL, should be skipped
                return url
        
        # Normalize query parameters
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
        
        # Rebuild URL
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
    """Detect database technology from response (NEW: DB fingerprinting)"""
    body_lower = body.lower()
    
    # MySQL indicators
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
    
    # PostgreSQL indicators
    postgres_patterns = [
        r'postgresql',
        r'pg_',
        r'pq_',
        r'postgres',
    ]
    
    for pattern in postgres_patterns:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return "PostgreSQL"
    
    # Microsoft SQL Server indicators
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
    
    # Oracle indicators
    oracle_patterns = [
        r'ora-\d{5}',
        r'oracle.*error',
        r'pl/sql',
        r'oracle.*database',
    ]
    
    for pattern in oracle_patterns:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return "Oracle"
    
    # SQLite indicators
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
        if vuln.type == "Email Address Exposure":
            # Create a unique pattern key
            emails = tuple(sorted(vuln.details.get("emails_found", [])))
            pattern_key = f"email_{hash(emails)}"
            
            if pattern_key in seen_patterns:
                logger.debug(f"Filtering duplicate email finding: {vuln.url}")
                continue
            
            seen_patterns.add(pattern_key)
        
        unique_vulns.append(vuln)
    
    logger.info(f"Filtered {len(vulnerabilities) - len(unique_vulns)} duplicate findings")
    return unique_vulns

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
        self.resolution_cache = {}  # Cache DNS resolutions
    
    async def enumerate(self, client) -> Set[str]:
        """Enumerate subdomains with strict validation"""
        if not Config.MODULES.get('subdomain_enum', True):
            logger.info("Subdomain enumeration disabled")
            return self.found_subdomains
        
        logger.info(f"Enumerating subdomains for {self.domain}...")
        
        # Detect wildcard DNS
        await self.detect_wildcard_dns()
        
        if self.wildcard_detected:
            logger.warning(f"Wildcard DNS detected. Results filtered.")
        
        # Check subdomains
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
            
            # Test multiple random subdomains
            for i in range(3):  # Test 3 random subdomains
                random_str = hashlib.md5(str(time.time() + i).encode()).hexdigest()[:16]
                test_subdomain = f"{random_str}.{self.domain}"
                
                try:
                    answers = dns.resolver.resolve(test_subdomain, 'A')
                    if answers:
                        for r in answers:
                            random_ips_set.add(str(r))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
            
            # If all random subdomains resolve to same IP(s), it's likely a wildcard
            if len(random_ips_set) > 0:
                # Also check that the IPs aren't common "not found" IPs
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
            # Check cache first
            if subdomain in self.resolution_cache:
                resolved_ips = self.resolution_cache[subdomain]
            else:
                answers = dns.resolver.resolve(subdomain, 'A')
                resolved_ips = {str(r) for r in answers}
                self.resolution_cache[subdomain] = resolved_ips
            
            # If ALL resolved IPs match wildcard IPs, it's likely a wildcard
            # NEW: Require exact match, not just subset
            if resolved_ips == self.wildcard_ips:
                return True
            
            # NEW: Also check if IPs are in same subnet (e.g., load balancer)
            if len(resolved_ips) > 0 and len(self.wildcard_ips) > 0:
                # Check if first octet matches (crude but effective)
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
            # DNS resolution
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                if not answers:
                    return None
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return None
            
            # Skip if wildcard
            if self.is_wildcard_subdomain(subdomain):
                return None
            
            # HTTP validation
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
    """HTTP client with rate limiting - WITH FIXES"""
    
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
        
        # FIX 1: Always count request attempts
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
        self.queue_growth_checks = 0  # Track queue growth
        
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
        
        # FIX 3: Force root URL to always be processed
        self.visited.discard(normalize_url(self.profile.base_url))
        
        last_update = time.time()
        
        while self.to_crawl and len(self.visited) < Config.MAX_CRAWL_URLS:
            # NEW: Strict queue size control
            if len(self.to_crawl) > Config.MAX_QUEUE_SIZE:
                logger.warning(f"Queue size {len(self.to_crawl)} exceeds max {Config.MAX_QUEUE_SIZE}. Truncating.")
                self.to_crawl = self.to_crawl[:Config.MAX_QUEUE_SIZE]
            
            # NEW: Periodic queue growth check
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
            # Aggressive filtering when queue is large
            logger.info(f"Queue size: {current_queue_size}. Applying aggressive filtering.")
            
            # Sort by depth (shallow first)
            self.to_crawl.sort(key=lambda x: x[1])
            
            # Remove deep URLs
            self.to_crawl = [item for item in self.to_crawl if item[1] <= 3]
            
            # Limit to top N
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
            
            # Check even if status is not 200
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
        
        # Allow more status codes
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
        """Process a single URL - WITH FIXES"""
        normalized_url = normalize_url(url)
        self.visited.add(normalized_url)
        self.total_requests += 1
        
        start_time = time.time()
        status, headers, body = await self.client.fetch(url)
        response_time = time.time() - start_time
        
        # FIX 2: Allow redirects and auth pages
        # Old code: if not body or status != 200:
        # New code:
        if status not in (200, 301, 302, 401, 403, 406, 429):
            # FIX 4: Log why URLs are skipped
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
            
            # Only extract links from successful responses
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
        """Normalize a link - FIXED VERSION"""
        if not link or link.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
            return None
        
        # Handle protocol-relative URLs (//facebook.com)
        if link.startswith('//'):
            # This is an external URL, skip it
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
            # Check if it looks like a domain
            if '.' in link and any(ext in link for ext in ['.com', '.ph', '.gov', '.net', '.org']):
                # This looks like an external domain without protocol
                logger.debug(f"Skipping external domain without protocol: {link}")
                return None
            return urljoin(base_url + '/', link)
        
        try:
            parsed = urlparse(link)
            base_parsed = urlparse(base_url)
            
            # Check if it's the same domain
            if parsed.netloc == base_parsed.netloc:
                return link
            else:
                # External domain
                logger.debug(f"Skipping external domain: {parsed.netloc}")
                return None
        except:
            pass
        
        return None

# ───────────────── ADVANCED VULNERABILITY SCANNER ─────────────────

class AdvancedVulnerabilityScanner:
    """Advanced scanner with DB fingerprinting"""
    
    def __init__(self, client, profile: TargetProfile):
        self.client = client
        self.profile = profile
        self.vulnerabilities = []
        self.baseline_cache = {}
        self.database_type_cache = {}  # Cache database detection results
    
    async def comprehensive_scan(self) -> List[Vulnerability]:
        """Run all vulnerability scans"""
        logger.info("Starting advanced vulnerability scan...")
        
        await self.scan_sql_injection()
        await self.scan_xss()
        await self.scan_sensitive_data()
        await self.scan_security_headers()
        await self.scan_directory_listings()
        
        self.vulnerabilities = [v for v in self.vulnerabilities if not v.suppressed]
        
        logger.info(f"Vulnerability scan complete. Found {len(self.vulnerabilities)} issues")
        return self.vulnerabilities
    
    async def get_robust_baseline(self, url: str) -> Tuple[Optional[int], Dict, str, float]:
        """Get robust baseline with timing validation (NEW: Improved timing)"""
        if url in self.baseline_cache:
            return self.baseline_cache[url]
        
        # NEW: Take multiple samples for timing accuracy
        samples = []
        sample_bodies = []
        
        for i in range(3):  # Take 3 samples
            sample_start = time.time()
            sample_status, sample_headers, sample_body = await self.client.fetch(url)
            sample_time = time.time() - sample_start
            
            if sample_body:
                samples.append(sample_time)
                sample_bodies.append(sample_body)
            
            # Small delay between samples
            if i < 2:
                await asyncio.sleep(0.1)
        
        if not samples:
            result = (None, {}, "", 0.0)
            self.baseline_cache[url] = result
            return result
        
        # Use median time for stability
        samples_sorted = sorted(samples)
        baseline_time = samples_sorted[len(samples_sorted) // 2]
        
        # Use first successful body
        baseline_body = sample_bodies[0] if sample_bodies else ""
        baseline_status = 200 if baseline_body else None
        baseline_headers = {}
        
        result = (baseline_status, baseline_headers, baseline_body, baseline_time)
        self.baseline_cache[url] = result
        
        # NEW: Log if baseline timing is problematic
        if baseline_time < Config.MIN_BASELINE_TIME:
            logger.debug(f"Baseline time {baseline_time:.2f}s too fast for reliable timing SQLi")
        elif baseline_time > Config.MAX_BASELINE_TIME:
            logger.debug(f"Baseline time {baseline_time:.2f}s too slow for reliable timing SQLi")
        
        return result
    
    def detect_database_for_url(self, url: str, body: str, headers: Dict) -> Optional[str]:
        """Detect database technology for a URL (NEW: DB fingerprinting)"""
        if url in self.database_type_cache:
            return self.database_type_cache[url]
        
        db_type = detect_database_technology(body, headers)
        self.database_type_cache[url] = db_type
        
        if db_type:
            logger.debug(f"Detected {db_type} for {url}")
        
        return db_type
    
    def get_targeted_sqli_payloads(self, db_type: Optional[str]) -> List[str]:
        """Get targeted SQLi payloads based on detected DB (NEW)"""
        generic_payloads = [
            "'", "\"", "`",
            "' OR '1'='1", "' OR 'a'='a",
            "' UNION SELECT NULL--",
        ]
        
        if not db_type:
            # If DB unknown, try all timing payloads
            return generic_payloads + [
                "1' AND SLEEP(3)--",  # MySQL
                "1'; SELECT pg_sleep(3)--",  # PostgreSQL
                "' WAITFOR DELAY '0:0:3'--",  # MSSQL
            ]
        
        targeted_payloads = generic_payloads.copy()
        
        if db_type == "MySQL":
            targeted_payloads.extend([
                "1' AND SLEEP(3)--",
                "' OR SLEEP(3)--",
                "1' AND BENCHMARK(1000000,MD5('test'))--",
            ])
        elif db_type == "PostgreSQL":
            targeted_payloads.extend([
                "1'; SELECT pg_sleep(3)--",
                "' OR pg_sleep(3)--",
                "1'; SELECT pg_sleep(3) FROM pg_stat_activity--",
            ])
        elif db_type == "MSSQL":
            targeted_payloads.extend([
                "' WAITFOR DELAY '0:0:3'--",
                "1' WAITFOR DELAY '0:0:3'--",
                "1'; WAITFOR DELAY '0:0:3'--",
            ])
        elif db_type == "Oracle":
            targeted_payloads.extend([
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
                "1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
            ])
        elif db_type == "SQLite":
            targeted_payloads.extend([
                "' OR 1=1--",
                "1' OR 1=1--",
            ])
        
        return targeted_payloads
    
    async def scan_sql_injection(self) -> List[Vulnerability]:
        """Advanced SQL Injection scanning with DB fingerprinting"""
        logger.info("  Scanning for SQL Injection (advanced)...")
        vulns = []
        
        for url, endpoint in self.profile.pages.items():
            for param in endpoint.parameters:
                if param['type'] in ['identifier', 'generic', 'search', 'pagination']:
                    # Get robust baseline
                    baseline_status, baseline_headers, baseline_body, baseline_time = await self.get_robust_baseline(url)
                    
                    if not baseline_body:
                        continue
                    
                    # NEW: Detect database type for targeted payloads
                    db_type = self.detect_database_for_url(url, baseline_body, baseline_headers)
                    payloads = self.get_targeted_sqli_payloads(db_type)
                    
                    for payload in payloads:
                        test_url = self.build_test_url(url, param['name'], payload)
                        
                        payload_start = time.time()
                        payload_status, payload_headers, payload_body = await self.client.fetch(test_url)
                        payload_time = time.time() - payload_start
                        
                        if not payload_body:
                            continue
                        
                        comparison = self.enhanced_compare_responses(baseline_body, payload_body)
                        sql_errors = self.detect_sql_errors(payload_body, baseline_body)
                        
                        # NEW: Improved timing analysis with baseline validation
                        timing_analysis = self.robust_analyze_timing(
                            payload, baseline_time, payload_time, db_type
                        )
                        
                        confidence = self.calculate_sqli_confidence(
                            sql_errors, comparison, payload, timing_analysis, db_type
                        )
                        
                        if confidence >= Config.SQLI_CONFIDENCE_THRESHOLD:
                            vuln = Vulnerability(
                                type="SQL Injection",
                                url=url,
                                parameter=param['name'],
                                payload=payload,
                                response=payload_body[:2000],
                                confidence=confidence,
                                confidence_tier=confidence_to_tier(confidence),
                                level=confidence_level(confidence),
                                cvss_score=8.8 if confidence >= 0.7 else 5.0,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if confidence >= 0.7 else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                                details={
                                    "errors": sql_errors['errors'],
                                    "response_diff": comparison['diff_percent'],
                                    "status_diff": baseline_status != payload_status,
                                    "timing_delay": f"{payload_time - baseline_time:.2f}s",
                                    "baseline_time": f"{baseline_time:.2f}s",
                                    "payload_time": f"{payload_time:.2f}s",
                                    "timing_match": timing_analysis['match'],
                                    "database_type": db_type,
                                    "timing_reliable": timing_analysis['reliable']
                                },
                                remediation="Use parameterized queries or prepared statements",
                                references=[
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                                ]
                            )
                            vulns.append(vuln)
                            break
        
        self.vulnerabilities.extend(vulns)
        return vulns
    
    def enhanced_compare_responses(self, baseline: str, payload_response: str) -> Dict:
        """Compare responses with controlled error weighting"""
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
    
    def detect_sql_errors(self, payload_response: str, baseline: str) -> Dict:
        """Detect SQL errors in response"""
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
            'errors': errors_found
        }
    
    def robust_analyze_timing(self, payload: str, baseline_time: float, 
                            payload_time: float, db_type: Optional[str]) -> Dict:
        """Robust timing analysis with baseline validation (NEW)"""
        match = False
        expected_delay = 0
        reliable = True
        
        # NEW: Check if baseline timing is reliable
        if baseline_time < Config.MIN_BASELINE_TIME:
            reliable = False
            logger.debug(f"Baseline time {baseline_time:.2f}s too fast for reliable timing")
        elif baseline_time > Config.MAX_BASELINE_TIME:
            reliable = False
            logger.debug(f"Baseline time {baseline_time:.2f}s too slow for reliable timing")
        
        # Extract expected sleep time
        sleep_patterns = [
            (r'SLEEP\((\d+)\)', 1, ["MySQL", None]),  # MySQL SLEEP
            (r'pg_sleep\((\d+)\)', 1, ["PostgreSQL"]),  # PostgreSQL
            (r"WAITFOR DELAY '0:0:(\d+)'", 1, ["MSSQL"]),  # MSSQL
            (r"DBMS_PIPE\.RECEIVE_MESSAGE\('a',(\d+)\)", 1, ["Oracle"]),  # Oracle
            (r'BENCHMARK\((\d+)', 0.000001, ["MySQL"]),  # MySQL BENCHMARK (microseconds)
        ]
        
        for pattern, multiplier, supported_dbs in sleep_patterns:
            match_obj = re.search(pattern, payload, re.IGNORECASE)
            if match_obj:
                # NEW: Check if payload matches detected DB
                if db_type and supported_dbs and db_type not in supported_dbs:
                    logger.debug(f"Payload {pattern} not suitable for detected DB {db_type}")
                    reliable = False
                
                expected_delay = float(match_obj.group(1)) * multiplier
                break
        
        # Check if payload actually caused a delay
        if expected_delay > 0 and reliable:
            time_difference = payload_time - baseline_time
            time_ratio = payload_time / baseline_time if baseline_time > 0 else 999
            
            # NEW: More sophisticated timing validation
            if time_ratio >= Config.TIMING_THRESHOLD_MULTIPLIER:
                # Check if delay is within expected range
                min_expected = expected_delay * 0.3  # At least 30% of expected
                max_expected = expected_delay * 3.0  # At most 3x expected (network variance)
                
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
    
    def calculate_sqli_confidence(self, sql_errors: Dict, comparison: Dict, 
                                payload: str, timing: Dict, db_type: Optional[str]) -> float:
        """Calculate confidence score for SQL injection"""
        confidence = 0.0
        
        if sql_errors['found']:
            confidence += 0.6
        
        if comparison['significant_difference']:
            confidence += 0.3
        
        # Timing evidence with reliability check
        if timing['match']:
            if timing['reliable']:
                confidence += 0.5  # High confidence for reliable timing
            else:
                confidence += 0.3  # Lower confidence for unreliable timing
        elif any(keyword in payload for keyword in ['SLEEP', 'pg_sleep', 'WAITFOR', 'BENCHMARK']):
            # Timing payload but no delay
            confidence -= 0.1
        
        # NEW: Bonus for DB-specific payload matching detected DB
        if db_type:
            db_specific = False
            if db_type == "MySQL" and ("SLEEP" in payload or "BENCHMARK" in payload):
                db_specific = True
            elif db_type == "PostgreSQL" and "pg_sleep" in payload:
                db_specific = True
            elif db_type == "MSSQL" and "WAITFOR" in payload:
                db_specific = True
            elif db_type == "Oracle" and "DBMS_PIPE" in payload:
                db_specific = True
            
            if db_specific:
                confidence += 0.1
        
        if "' UNION SELECT" in payload:
            confidence += 0.1
        
        return max(0.0, min(confidence, 0.95))
    
    async def scan_xss(self) -> List[Vulnerability]:
        """Scan for XSS"""
        logger.info("  Scanning for XSS...")
        vulns = []
        
        for url, endpoint in self.profile.pages.items():
            for param in endpoint.parameters:
                if param['type'] in ['generic', 'search', 'identifier', 'file']:
                    baseline_status, baseline_headers, baseline_body, _ = await self.get_robust_baseline(url)
                    if not baseline_body:
                        continue
                    
                    for payload in self.get_xss_payloads():
                        test_url = self.build_test_url(url, param['name'], payload)
                        
                        payload_status, payload_headers, payload_body = await self.client.fetch(test_url)
                        if not payload_body:
                            continue
                        
                        reflection_analysis = self.enhanced_xss_reflection_analysis(payload, payload_body, baseline_body)
                        
                        if reflection_analysis['reflected']:
                            confidence = self.calculate_xss_confidence(reflection_analysis)
                            if confidence >= Config.XSS_CONFIDENCE_THRESHOLD:
                                if confidence >= 0.9:
                                    confidence = 0.85
                                
                                vuln = Vulnerability(
                                    type="Cross-Site Scripting (XSS)",
                                    url=url,
                                    parameter=param['name'],
                                    payload=payload,
                                    response=payload_body[:2000],
                                    confidence=confidence,
                                    confidence_tier=confidence_to_tier(confidence),
                                    level="LOW" if confidence < 0.7 else "MEDIUM",
                                    cvss_score=4.0 if confidence < 0.7 else 6.1,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                                    details={
                                        "context": reflection_analysis['context'],
                                        "escaped": reflection_analysis['escaped'],
                                        "html_encoded": reflection_analysis['html_encoded'],
                                        "in_script": reflection_analysis['in_script'],
                                        "in_attribute": reflection_analysis['in_attribute'],
                                        "exploitable": reflection_analysis['exploitable']
                                    },
                                    remediation="Implement proper output encoding and Content Security Policy",
                                    references=[
                                        "https://owasp.org/www-community/attacks/xss/",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                                    ]
                                )
                                vulns.append(vuln)
                                break
        
        self.vulnerabilities.extend(vulns)
        return vulns
    
    def get_xss_payloads(self):
        """Get XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\" onload=\"alert('XSS')\"",
            "javascript:alert('XSS')",
        ]
    
    def enhanced_xss_reflection_analysis(self, payload: str, response: str, baseline: str) -> Dict:
        """Analyze XSS reflection"""
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
    
    def calculate_xss_confidence(self, analysis: Dict) -> float:
        """Calculate XSS confidence"""
        confidence = 0.3
        
        if analysis['exploitable']:
            confidence += 0.4
        
        if analysis['in_script']:
            confidence += 0.2
        
        if analysis['javascript_context']:
            confidence += 0.1
        
        if analysis['partially_encoded']:
            confidence -= 0.2
        
        if not analysis['html_encoded']:
            confidence += 0.1
        
        return min(confidence, 0.85)
    
    async def scan_sensitive_data(self) -> List[Vulnerability]:
        """Scan for sensitive data - WITH GROUPING AND FILTERING"""
        logger.info("  Scanning for sensitive data...")
        vulns = []
        
        # Group emails by content hash to avoid duplicates
        email_findings = defaultdict(list)
        
        for url, endpoint in self.profile.pages.items():
            body = endpoint.body
            emails = extract_emails(body)
            
            if emails and len(emails) <= 5:
                # Create content hash for grouping
                content_hash = hashlib.md5(body.encode()).hexdigest()[:16]
                email_tuple = tuple(sorted(set(emails)))
                
                email_findings[(email_tuple, content_hash)].append(url)
        
        # Create one finding per unique email set
        processed_count = 0
        for (emails, content_hash), urls in email_findings.items():
            if processed_count >= Config.EMAIL_EXPOSURE_MAX_FINDINGS:
                break
                
            processed_count += 1
            
            # Skip public contact emails if configured
            public_emails = ['info@sibugay.gov.ph', 'alphaphpn@gmail.com']
            if Config.SUPPRESS_PUBLIC_EMAILS and all(email in public_emails for email in emails):
                logger.debug(f"Suppressing public email finding: {emails}")
                continue
            
            # Determine severity
            is_public = any(email in public_emails for email in emails)
            
            if is_public:
                confidence = 0.3
                level = "INFO"
                cvss_score = 1.0
                suppressed = True
            else:
                confidence = 0.6
                level = "LOW"
                cvss_score = 3.1
                suppressed = False
            
            # Take the shortest/cleanest URL as representative
            representative_url = min(urls, key=len)
            
            vuln = Vulnerability(
                type="Email Address Exposure",
                url=representative_url,
                response="",  # Don't store full response
                confidence=confidence,
                confidence_tier=confidence_to_tier(confidence),
                level=level,
                cvss_score=cvss_score,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" if cvss_score > 1.0 else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                details={
                    "emails_found": list(emails),
                    "affected_urls": urls[:10],  # Limit to first 10 URLs
                    "total_affected_urls": len(urls),
                    "grouping_key": content_hash,
                    "is_public_contact": is_public
                },
                remediation="Consider obfuscating email addresses or using contact forms for sensitive emails",
                references=[
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                ],
                suppressed=suppressed
            )
            vulns.append(vuln)
        
        self.vulnerabilities.extend(vulns)
        logger.info(f"  Email exposure findings: {len(vulns)} (grouped from {sum(len(urls) for urls in email_findings.values())} URLs)")
        return vulns
    
    async def scan_security_headers(self) -> List[Vulnerability]:
        """Scan for missing security headers"""
        logger.info("  Scanning security headers...")
        vulns = []
        
        for url, endpoint in self.profile.pages.items():
            headers = endpoint.headers
            content_type = headers.get("Content-Type", "").lower()
            
            if not content_type.startswith("text/html"):
                continue
            
            missing = []
            security_headers = {
                "Strict-Transport-Security": "HSTS not implemented",
                "Content-Security-Policy": "CSP not implemented",
                "X-Frame-Options": "Clickjacking protection missing",
                "X-Content-Type-Options": "MIME sniffing not prevented",
                "Referrer-Policy": "Referrer policy not set",
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    missing.append(message)
            
            if missing:
                vuln = Vulnerability(
                    type="Missing Security Headers",
                    url=url,
                    confidence=0.4,
                    confidence_tier="INFO",
                    level="LOW",
                    cvss_score=2.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    details={"missing_headers": missing},
                    remediation="Implement recommended security headers",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://securityheaders.com/"
                    ]
                )
                
                if vuln.level == "LOW":
                    vuln.suppressed = True
                
                vulns.append(vuln)
        
        self.vulnerabilities.extend(vulns)
        return vulns
    
    async def scan_directory_listings(self) -> List[Vulnerability]:
        """Scan directory listings"""
        logger.info("  Scanning directory listings...")
        vulns = []
        
        for dir_url in self.profile.network_info.directory_listings:
            vuln = Vulnerability(
                type="Directory Listing Enabled",
                url=dir_url,
                confidence=0.8,
                confidence_tier="LIKELY",
                level="MEDIUM",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                details={
                    "description": "Directory listing exposes file and directory structure",
                    "risk": "Information disclosure"
                },
                remediation="Disable directory indexing in web server configuration",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Review_Webserver_Metafiles_for_Information_Leakage",
                ]
            )
            vulns.append(vuln)
        
        self.vulnerabilities.extend(vulns)
        return vulns
    
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
        
        html = self._generate_html_template(confirmed, likely, possible, info, total_vulns)
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        
        logger.info(f"HTML report generated: {filename}")
        return filename
    
    def _generate_html_template(self, confirmed, likely, possible, info, total_vulns):
        """Generate HTML template"""
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
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; background: white; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background: #2c3e50; color: white; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .summary-card {{ padding: 20px; background: white; border-radius: 8px; box-shadow: 0 3px 10px rgba(0,0,0,0.1); text-align: center; }}
        .pre {{ background: #2c3e50; color: white; padding: 15px; border-radius: 8px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 13px; }}
        .toggle-btn {{ background: #2c3e50; color: white; border: none; padding: 8px 16px; border-radius: 5px; cursor: pointer; margin: 10px 0; }}
        .hidden {{ display: none; }}
        .note-box {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Assessment Report</h1>
            <h2>Target: {self.profile.base_url}</h2>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Scan ID: {self.scan_id}</p>
            <p><strong>MEXTREME v1.1</strong> - Professional Security Scanner</p>
        </div>
        
        <div class="section">
            <h2>📈 Executive Summary</h2>
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
        return f"""
        <div class="vuln-card">
            <h4>#{index}: {html_escape(vuln.type)} 
                <span class="tier-badge tier-{vuln.confidence_tier.lower()}">{vuln.confidence_tier}</span>
                <span class="severity-badge severity-{vuln.level.lower()}">{vuln.level}</span>
            </h4>
            <p><strong>URL:</strong> {html_escape(vuln.url)}</p>
            {f'<p><strong>Parameter:</strong> {html_escape(vuln.parameter)}</p>' if vuln.parameter else ''}
            {f'<p><strong>Payload:</strong> <code>{html_escape(vuln.payload)}</code></p>' if vuln.payload else ''}
            <p><strong>Confidence:</strong> {vuln.confidence:.0%}</p>
            <button class="toggle-btn" onclick="toggleDetails('details-{vuln.id}')">Show Details</button>
            <div id="details-{vuln.id}" class="hidden">
                {f'<p><strong>Evidence:</strong></p><pre class="pre">{html_escape(vuln.response[:1000])}</pre>' if vuln.response else ''}
                {f'<p><strong>Remediation:</strong> {html_escape(vuln.remediation)}</p>' if vuln.remediation else ''}
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
                "tool": "MEXTREME v1.1",
                "duration": self.profile.metadata.get("duration", 0),
                "requests": self.profile.metadata.get("total_requests", 0)
            },
            "reconnaissance": {
                "network": asdict(self.profile.network_info),
                "subdomains": list(self.profile.subdomains),
            },
            "discovery": {
                "pages_found": len(self.profile.pages),
                "assets_found": len(self.profile.assets),
            },
            "findings": {
                "total": len(self.vulnerabilities),
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
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Key Findings\n\n")
            
            critical_vulns = [v for v in self.vulnerabilities if v.confidence_tier in ["CONFIRMED", "LIKELY"]]
            if critical_vulns:
                f.write(f"**Critical Findings:** {len(critical_vulns)}\n")
                for vuln in critical_vulns[:5]:
                    f.write(f"- {vuln.type} ({vuln.level}) - {vuln.url}\n")
            else:
                f.write("**No critical findings detected.**\n")
            
            f.write("\n## Technical Overview\n\n")
            f.write(f"- Pages discovered: {len(self.profile.pages)}\n")
            f.write(f"- Assets discovered: {len(self.profile.assets)}\n")
            f.write(f"- Open ports: {len(self.profile.network_info.open_ports)}\n")
            f.write(f"- Subdomains: {len(self.profile.subdomains)}\n")
        
        logger.info(f"Executive summary generated: {filename}")
        return filename

# ───────────────── MAIN APPLICATION ─────────────────

class FinalMextremeScanner:
    """Final production-ready scanner"""
    
    def __init__(self):
        self.profile = None
        self.vulnerabilities = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.scan_id = None
    
    async def scan(self, target_url: str) -> Dict:
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
        
        # PHASE 1: Network Recon
        await self.phase1_enhanced_recon(parsed.netloc)
        
        # PHASE 2: Web Recon
        async with EnhancedAsyncHTTPClient(self.scan_id) as client:
            await self.phase1a_secure_subdomain_enum(client, parsed.netloc)
            await self.phase2_web_recon(client)
            
            # PHASE 3: Vulnerability Assessment
            if Config.MODULES['vuln_scan'] and self.profile.pages:
                await self.phase3_vuln_assessment(client)
        
        # PHASE 4: Reporting
        await self.phase4_reporting()
        
        return {
            "profile": self.profile,
            "vulnerabilities": self.vulnerabilities,
            "scan_id": self.scan_id,
            "duration": self.scan_end_time - self.scan_start_time
        }
    
    def display_banner(self):
        print()
        print(Colors.CYAN + LOGO + Colors.RESET)
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{f'MEXTREME v1.1 - PROFESSIONAL SECURITY SCANNER':^70}{Colors.RESET}")
        print(f"{Colors.BOLD}{'Production-ready':^70}{Colors.RESET}")
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
    
    async def phase3_vuln_assessment(self, client):
        """Advanced vulnerability assessment"""
        print(f"\n{Colors.BLUE}[PHASE 3] ADVANCED VULNERABILITY ASSESSMENT{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*50}{Colors.RESET}")
        print(f"{Colors.CYAN}  Database fingerprinting enabled{Colors.RESET}")
        print(f"{Colors.CYAN}  Improved timing SQLi detection{Colors.RESET}")
        print(f"{Colors.CYAN}  Email grouping and filtering enabled{Colors.RESET}")
        
        scanner = AdvancedVulnerabilityScanner(client, self.profile)
        self.vulnerabilities = await scanner.comprehensive_scan()
        
        # NEW: Filter duplicate findings
        self.vulnerabilities = filter_duplicate_vulnerabilities(self.vulnerabilities)
        
        by_tier = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_tier[vuln.confidence_tier].append(vuln)
        
        print(f"{Colors.GREEN}  ✓ CONFIRMED:{Colors.RESET} {len(by_tier.get('CONFIRMED', []))}")
        print(f"{Colors.YELLOW}  ✓ LIKELY:{Colors.RESET} {len(by_tier.get('LIKELY', []))}")
        print(f"{Colors.CYAN}  ✓ POSSIBLE:{Colors.RESET} {len(by_tier.get('POSSIBLE', []))}")
        print(f"{Colors.BLUE}  ✓ INFO:{Colors.RESET} {len(by_tier.get('INFO', []))}")
        print(f"{Colors.PURPLE}  ✓ Total Findings:{Colors.RESET} {len(self.vulnerabilities)}")
        
        # Show suppressed count
        suppressed = sum(1 for v in scanner.vulnerabilities if v.suppressed)
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
        
        print(f"\n{Colors.CYAN}📈 Statistics:{Colors.RESET}")
        print(f"  • Duration: {duration:.1f}s")
        print(f"  • Requests: {self.profile.metadata.get('total_requests', 0)}")
        
        print(f"\n{Colors.GREEN}📁 Reports saved to:{Colors.RESET} {report_dir}")
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
        description="MEXTREME v1.1 - Professional Security Assessment Platform"
    )
    
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("-o", "--output", help="Output directory name")
    parser.add_argument("--no-browser", action="store_true", help="Don't open report in browser")
    parser.add_argument("--quick", action="store_true", help="Quick scan")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain enumeration")
    parser.add_argument("--max-params", type=int, default=10, help="Max parameters per URL")
    parser.add_argument("--max-queue", type=int, default=5000, help="Max crawler queue size")
    
    return parser.parse_args()

async def main():
    """Main entry point"""
    args = parse_arguments()
    
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
    
    # NEW: Apply fixes by default
    Config.SKIP_EXTERNAL_DOMAINS = True
    Config.GROUP_EMAIL_FINDINGS = True
    Config.EMAIL_EXPOSURE_MAX_FINDINGS = 3
    Config.SUPPRESS_PUBLIC_EMAILS = True
    
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
    
    scanner = FinalMextremeScanner()
    
    try:
        await scanner.scan(args.target)
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
    
    asyncio.run(main())
