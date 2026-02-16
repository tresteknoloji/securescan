"""
Detection Engine - Banner/Fingerprint + CPE Normalization + Active Checks
Professional vulnerability detection system
"""
import asyncio
import httpx
import ssl
import socket
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ServiceType(Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    REDIS = "redis"
    MONGODB = "mongodb"
    RDP = "rdp"
    TELNET = "telnet"
    DNS = "dns"
    UNKNOWN = "unknown"


@dataclass
class ServiceFingerprint:
    """Detected service fingerprint"""
    port: int
    protocol: str = "tcp"
    service_type: ServiceType = ServiceType.UNKNOWN
    product: str = ""
    version: str = ""
    extra_info: str = ""
    banner: str = ""
    cpe: str = ""
    confidence: int = 0  # 0-100
    headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    favicon_hash: str = ""
    technologies: List[str] = field(default_factory=list)


@dataclass
class ActiveCheckResult:
    """Result of an active vulnerability check"""
    check_name: str
    vulnerable: bool
    severity: str = "info"
    evidence: str = ""
    description: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    solution: str = ""
    request: str = ""
    response: str = ""


class FingerprintEngine:
    """
    Service fingerprinting engine
    Detects services, versions, and technologies
    """
    
    # Known service banners patterns
    SERVICE_PATTERNS = {
        ServiceType.SSH: [
            (r"SSH-(\d+\.\d+)-OpenSSH[_-](\d+\.\d+\S*)", "OpenSSH"),
            (r"SSH-(\d+\.\d+)-dropbear[_-]?(\d+\.\d+\S*)?", "Dropbear"),
            (r"SSH-(\d+\.\d+)-(.+)", "SSH"),
        ],
        ServiceType.FTP: [
            (r"220[- ].*vsftpd (\d+\.\d+\.\d+)", "vsftpd"),
            (r"220[- ].*ProFTPD (\d+\.\d+\.\d+)", "ProFTPD"),
            (r"220[- ].*FileZilla Server (\d+\.\d+\.\d+)", "FileZilla"),
            (r"220[- ].*Pure-FTPd", "Pure-FTPd"),
            (r"220[- ].*Microsoft FTP Service", "Microsoft FTP"),
        ],
        ServiceType.SMTP: [
            (r"220[- ].*Postfix", "Postfix"),
            (r"220[- ].*Exim (\d+\.\d+)", "Exim"),
            (r"220[- ].*Microsoft ESMTP", "Microsoft Exchange"),
            (r"220[- ].*Sendmail (\d+\.\d+\.\d+)", "Sendmail"),
        ],
        ServiceType.MYSQL: [
            (r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB"),
            (r"(\d+\.\d+\.\d+).*MySQL", "MySQL"),
        ],
        ServiceType.REDIS: [
            (r"REDIS(\d+\.\d+\.\d+)", "Redis"),
            (r"-ERR.*redis", "Redis"),
        ],
        ServiceType.MONGODB: [
            (r"MongoDB", "MongoDB"),
        ],
    }
    
    # HTTP Server signatures
    HTTP_SERVER_PATTERNS = {
        "Apache": (r"Apache/?(\d+\.\d+\.?\d*)?", "apache", "apache_http_server"),
        "nginx": (r"nginx/?(\d+\.\d+\.?\d*)?", "nginx", "nginx"),
        "Microsoft-IIS": (r"Microsoft-IIS/?(\d+\.?\d*)?", "microsoft", "iis"),
        "LiteSpeed": (r"LiteSpeed/?(\d+\.\d+\.?\d*)?", "litespeed", "litespeed_web_server"),
        "Caddy": (r"Caddy/?(\d+\.\d+\.?\d*)?", "caddyserver", "caddy"),
        "OpenResty": (r"openresty/?(\d+\.\d+\.?\d*)?", "openresty", "openresty"),
        "Tomcat": (r"Apache-Coyote/?(\d+\.?\d*)?", "apache", "tomcat"),
        "Jetty": (r"Jetty\(?(\d+\.\d+\.?\d*)?\)?", "eclipse", "jetty"),
        "gunicorn": (r"gunicorn/?(\d+\.\d+\.?\d*)?", "gunicorn", "gunicorn"),
        "uvicorn": (r"uvicorn/?(\d+\.\d+\.?\d*)?", "uvicorn", "uvicorn"),
        "Werkzeug": (r"Werkzeug/?(\d+\.\d+\.?\d*)?", "palletsprojects", "werkzeug"),
    }
    
    # Technology detection patterns from headers
    TECH_PATTERNS = {
        "X-Powered-By": {
            r"PHP/?(\d+\.\d+\.?\d*)?": ("PHP", "php", "php"),
            r"ASP\.NET": ("ASP.NET", "microsoft", "asp.net"),
            r"Express": ("Express.js", "expressjs", "express"),
            r"Next\.js": ("Next.js", "vercel", "next.js"),
            r"Servlet/?(\d+\.?\d*)?": ("Java Servlet", "oracle", "servlet"),
        },
        "X-AspNet-Version": {
            r"(\d+\.\d+\.?\d*)": ("ASP.NET", "microsoft", "asp.net"),
        },
        "X-Generator": {
            r"Drupal (\d+)": ("Drupal", "drupal", "drupal"),
            r"WordPress (\d+\.\d+\.?\d*)?": ("WordPress", "wordpress", "wordpress"),
        },
    }
    
    # Known favicon hashes (MD5 of favicon content)
    FAVICON_HASHES = {
        "f276b19aabcb4ae8cda4d22625c6735f": ("Apache Tomcat", "apache", "tomcat"),
        "4644f2d45601037b8423d45e13194c93": ("Spring Boot", "pivotal", "spring_boot"),
        "9fa3a25d9c7a0d41a7dd82c0e5a1cba7": ("Jenkins", "jenkins", "jenkins"),
        "71e30c09bc467ab5e7a0b0e8a0e8c0e7": ("GitLab", "gitlab", "gitlab"),
        "2b6c6b6c6b6c6b6c6b6c6b6c6b6c6b6c": ("Grafana", "grafana", "grafana"),
    }
    
    def __init__(self):
        self.timeout = 10
    
    async def fingerprint_http(self, host: str, port: int, use_ssl: bool = False) -> ServiceFingerprint:
        """Fingerprint HTTP/HTTPS service"""
        fp = ServiceFingerprint(
            port=port,
            service_type=ServiceType.HTTPS if use_ssl else ServiceType.HTTP
        )
        
        scheme = "https" if use_ssl else "http"
        base_url = f"{scheme}://{host}:{port}"
        
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=self.timeout,
                follow_redirects=True
            ) as client:
                # Main request
                response = await client.get(base_url)
                fp.headers = dict(response.headers)
                
                # Server header
                server = response.headers.get("Server", "")
                if server:
                    fp.banner = server
                    self._parse_server_header(fp, server)
                
                # Technology detection from headers
                self._detect_technologies(fp, response.headers)
                
                # Parse HTML for additional info
                await self._parse_html_fingerprints(fp, response.text, base_url, client)
                
                # Favicon hash
                await self._get_favicon_hash(fp, base_url, client)
                
                # SSL certificate info
                if use_ssl:
                    fp.ssl_info = await self._get_ssl_info(host, port)
                
                fp.confidence = self._calculate_confidence(fp)
                
        except Exception as e:
            logger.debug(f"HTTP fingerprint error for {host}:{port}: {e}")
        
        return fp
    
    async def fingerprint_service(self, host: str, port: int) -> ServiceFingerprint:
        """Fingerprint a generic TCP service by grabbing banner"""
        fp = ServiceFingerprint(port=port)
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Send probe for some services
            probes = {
                21: None,  # FTP sends banner automatically
                22: None,  # SSH sends banner automatically
                25: b"EHLO test\r\n",
                110: None,
                143: None,
                3306: None,  # MySQL sends banner
                6379: b"INFO\r\n",  # Redis
                27017: None,  # MongoDB
            }
            
            probe = probes.get(port)
            if probe:
                writer.write(probe)
                await writer.drain()
            
            # Read banner
            try:
                banner = await asyncio.wait_for(reader.read(4096), timeout=3)
                fp.banner = banner.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            # Parse banner
            if fp.banner:
                self._parse_service_banner(fp)
            
            fp.confidence = self._calculate_confidence(fp)
            
        except Exception as e:
            logger.debug(f"Service fingerprint error for {host}:{port}: {e}")
        
        return fp
    
    def _parse_server_header(self, fp: ServiceFingerprint, server: str):
        """Parse Server header to extract product and version"""
        for name, (pattern, vendor, product) in self.HTTP_SERVER_PATTERNS.items():
            match = re.search(pattern, server, re.IGNORECASE)
            if match:
                fp.product = name
                fp.version = match.group(1) if match.lastindex and match.group(1) else ""
                fp.cpe = self._build_cpe(vendor, product, fp.version)
                fp.technologies.append(name)
                break
    
    def _detect_technologies(self, fp: ServiceFingerprint, headers):
        """Detect technologies from HTTP headers"""
        for header_name, patterns in self.TECH_PATTERNS.items():
            header_value = headers.get(header_name, "")
            if header_value:
                for pattern, (tech_name, vendor, product) in patterns.items():
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else ""
                        fp.technologies.append(f"{tech_name} {version}".strip())
                        if not fp.cpe:  # Don't override server CPE
                            fp.cpe = self._build_cpe(vendor, product, version)
    
    async def _parse_html_fingerprints(self, fp: ServiceFingerprint, html: str, base_url: str, client):
        """Parse HTML content for technology fingerprints"""
        # WordPress
        if 'wp-content' in html or 'wp-includes' in html:
            fp.technologies.append("WordPress")
            # Try to get version
            match = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+\.?\d*)"', html)
            if match:
                fp.technologies[-1] = f"WordPress {match.group(1)}"
        
        # Drupal
        if 'Drupal.settings' in html or '/sites/default/files' in html:
            fp.technologies.append("Drupal")
        
        # Joomla
        if '/media/jui/' in html or 'Joomla!' in html:
            fp.technologies.append("Joomla")
        
        # React
        if '__REACT_DEVTOOLS_GLOBAL_HOOK__' in html or 'react-root' in html or '_reactRootContainer' in html:
            fp.technologies.append("React")
        
        # Vue.js
        if '__VUE__' in html or 'vue-router' in html:
            fp.technologies.append("Vue.js")
        
        # Angular
        if 'ng-version' in html or 'angular' in html.lower():
            fp.technologies.append("Angular")
        
        # jQuery
        match = re.search(r'jquery[.-]?(\d+\.\d+\.?\d*)?(?:\.min)?\.js', html, re.IGNORECASE)
        if match:
            version = match.group(1) if match.group(1) else ""
            fp.technologies.append(f"jQuery {version}".strip())
        
        # Bootstrap
        if 'bootstrap' in html.lower():
            fp.technologies.append("Bootstrap")
    
    async def _get_favicon_hash(self, fp: ServiceFingerprint, base_url: str, client):
        """Get favicon and calculate hash"""
        try:
            # Try common favicon locations
            favicon_urls = [
                f"{base_url}/favicon.ico",
                f"{base_url}/favicon.png",
            ]
            
            for url in favicon_urls:
                try:
                    response = await client.get(url)
                    if response.status_code == 200 and len(response.content) > 0:
                        fp.favicon_hash = hashlib.md5(response.content).hexdigest()
                        
                        # Check known hashes
                        if fp.favicon_hash in self.FAVICON_HASHES:
                            tech_name, vendor, product = self.FAVICON_HASHES[fp.favicon_hash]
                            fp.technologies.append(tech_name)
                            if not fp.product:
                                fp.product = tech_name
                        break
                except:
                    continue
        except Exception as e:
            logger.debug(f"Favicon fetch error: {e}")
    
    async def _get_ssl_info(self, host: str, port: int) -> Dict[str, Any]:
        """Get SSL certificate information"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    ssl_info = {
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "cert_subject": dict(x[0] for x in cert.get('subject', [])) if cert else {},
                        "cert_issuer": dict(x[0] for x in cert.get('issuer', [])) if cert else {},
                        "cert_not_before": cert.get('notBefore') if cert else None,
                        "cert_not_after": cert.get('notAfter') if cert else None,
                        "cert_san": cert.get('subjectAltName', []) if cert else [],
                    }
        except Exception as e:
            logger.debug(f"SSL info error for {host}:{port}: {e}")
        
        return ssl_info
    
    def _parse_service_banner(self, fp: ServiceFingerprint):
        """Parse service banner to identify service"""
        banner = fp.banner.lower()
        
        # Check each service type
        for service_type, patterns in self.SERVICE_PATTERNS.items():
            for pattern, product in patterns:
                match = re.search(pattern, fp.banner, re.IGNORECASE)
                if match:
                    fp.service_type = service_type
                    fp.product = product
                    if match.lastindex:
                        fp.version = match.group(match.lastindex)
                    
                    # Build CPE
                    vendor = product.lower().replace(" ", "_")
                    fp.cpe = self._build_cpe(vendor, product.lower().replace(" ", "_"), fp.version)
                    return
        
        # Port-based defaults
        port_services = {
            21: ServiceType.FTP,
            22: ServiceType.SSH,
            23: ServiceType.TELNET,
            25: ServiceType.SMTP,
            3306: ServiceType.MYSQL,
            5432: ServiceType.POSTGRESQL,
            6379: ServiceType.REDIS,
            27017: ServiceType.MONGODB,
        }
        
        if fp.port in port_services:
            fp.service_type = port_services[fp.port]
    
    def _build_cpe(self, vendor: str, product: str, version: str = "") -> str:
        """Build CPE 2.3 string"""
        vendor = vendor.lower().replace(" ", "_")
        product = product.lower().replace(" ", "_")
        version = version.replace(" ", "_") if version else "*"
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    
    def _calculate_confidence(self, fp: ServiceFingerprint) -> int:
        """Calculate confidence score for fingerprint"""
        score = 0
        
        if fp.product:
            score += 30
        if fp.version:
            score += 30
        if fp.cpe:
            score += 20
        if fp.technologies:
            score += 10
        if fp.favicon_hash:
            score += 5
        if fp.ssl_info:
            score += 5
        
        return min(score, 100)


class CPEMatcher:
    """
    CPE to CVE matcher
    Matches detected services against CVE database
    """
    
    def __init__(self, db):
        self.db = db
    
    async def match_fingerprint(self, fp: ServiceFingerprint) -> List[Dict[str, Any]]:
        """Match a fingerprint against CVE database"""
        matches = []
        
        if not fp.cpe and not fp.product:
            return matches
        
        # Search by CPE
        if fp.cpe:
            cpe_matches = await self._search_by_cpe(fp.cpe)
            matches.extend(cpe_matches)
        
        # Search by product name and version
        if fp.product:
            product_matches = await self._search_by_product(fp.product, fp.version)
            matches.extend(product_matches)
        
        # Deduplicate
        seen = set()
        unique_matches = []
        for m in matches:
            if m['cve_id'] not in seen:
                seen.add(m['cve_id'])
                unique_matches.append(m)
        
        # Sort by CVSS score
        unique_matches.sort(key=lambda x: x.get('cvss_v3_score') or 0, reverse=True)
        
        return unique_matches[:50]  # Limit results
    
    async def _search_by_cpe(self, cpe: str) -> List[Dict[str, Any]]:
        """Search CVEs by CPE string"""
        # Extract vendor and product from CPE
        parts = cpe.split(":")
        if len(parts) < 5:
            return []
        
        vendor = parts[3]
        product = parts[4]
        version = parts[5] if len(parts) > 5 and parts[5] != "*" else None
        
        # Build search query
        query = {
            "cpe_matches.criteria": {
                "$regex": f":{vendor}:{product}:",
                "$options": "i"
            }
        }
        
        cursor = self.db.cves.find(query, {"_id": 0}).limit(100)
        results = await cursor.to_list(100)
        
        # Filter by version if available
        if version:
            results = self._filter_by_version(results, version)
        
        return results
    
    async def _search_by_product(self, product: str, version: str = "") -> List[Dict[str, Any]]:
        """Search CVEs by product name"""
        # Search in description
        query = {
            "description": {
                "$regex": product,
                "$options": "i"
            }
        }
        
        cursor = self.db.cves.find(query, {"_id": 0}).limit(50)
        results = await cursor.to_list(50)
        
        # Filter by version if available
        if version:
            results = self._filter_by_version(results, version)
        
        return results
    
    def _filter_by_version(self, cves: List[Dict], version: str) -> List[Dict]:
        """Filter CVEs by version range"""
        filtered = []
        
        for cve in cves:
            # Check CPE matches for version ranges
            cpe_matches = cve.get("cpe_matches", [])
            
            for match in cpe_matches:
                criteria = match.get("criteria", "")
                version_start = match.get("version_start", "")
                version_end = match.get("version_end", "")
                
                # Simple version comparison
                if self._version_in_range(version, version_start, version_end):
                    filtered.append(cve)
                    break
            else:
                # If no version range specified in CPE, include if product matches
                if not cpe_matches:
                    filtered.append(cve)
        
        return filtered
    
    def _version_in_range(self, version: str, start: str, end: str) -> bool:
        """Check if version is in range"""
        if not start and not end:
            return True
        
        try:
            v = self._parse_version(version)
            
            if start:
                s = self._parse_version(start)
                if v < s:
                    return False
            
            if end:
                e = self._parse_version(end)
                if v > e:
                    return False
            
            return True
        except:
            return True  # Include if can't parse
    
    def _parse_version(self, version: str) -> tuple:
        """Parse version string into comparable tuple"""
        parts = re.split(r'[.-]', version)
        result = []
        for part in parts:
            try:
                result.append(int(part))
            except ValueError:
                result.append(part)
        return tuple(result)


class ActiveChecker:
    """
    Active vulnerability checker
    Performs actual security tests
    """
    
    def __init__(self):
        self.timeout = 10
        self.checks = [
            self._check_path_traversal,
            self._check_sql_injection,
            self._check_xss,
            self._check_ssrf,
            self._check_open_redirect,
            self._check_sensitive_files,
            self._check_default_credentials,
            self._check_ssl_vulnerabilities,
            self._check_cors_misconfig,
            self._check_security_headers,
        ]
    
    async def run_checks(self, host: str, port: int, service_type: ServiceType) -> List[ActiveCheckResult]:
        """Run all applicable active checks"""
        results = []
        
        if service_type in [ServiceType.HTTP, ServiceType.HTTPS]:
            scheme = "https" if service_type == ServiceType.HTTPS else "http"
            base_url = f"{scheme}://{host}:{port}"
            
            for check in self.checks:
                try:
                    result = await check(base_url)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Active check error: {e}")
        
        return results
    
    async def _check_path_traversal(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for path traversal vulnerability"""
        payloads = [
            ("/../../../etc/passwd", "root:"),
            ("/../../../windows/win.ini", "[fonts]"),
            ("/..%2f..%2f..%2fetc/passwd", "root:"),
            ("/....//....//....//etc/passwd", "root:"),
            ("/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "root:"),
        ]
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for payload, indicator in payloads:
                try:
                    url = base_url + payload
                    response = await client.get(url)
                    
                    if indicator in response.text:
                        return ActiveCheckResult(
                            check_name="Path Traversal",
                            vulnerable=True,
                            severity="high",
                            evidence=f"Found '{indicator}' in response",
                            description="The application is vulnerable to path traversal attacks, allowing access to sensitive files.",
                            cve_id="CWE-22",
                            cvss_score=7.5,
                            solution="Sanitize user input and use allowlists for file paths.",
                            request=f"GET {url}",
                            response=response.text[:500]
                        )
                except:
                    continue
        
        return None
    
    async def _check_sql_injection(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for SQL injection indicators"""
        payloads = [
            ("'", ["sql syntax", "mysql", "postgresql", "sqlite", "ora-", "sql server"]),
            ("1' OR '1'='1", ["sql syntax", "mysql", "postgresql"]),
            ("1 AND 1=1", []),
            ("1' AND '1'='1", []),
        ]
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # Test on common parameters
            test_urls = [
                f"{base_url}?id={{}}", 
                f"{base_url}?page={{}}",
                f"{base_url}?user={{}}",
                f"{base_url}?search={{}}",
            ]
            
            for test_url in test_urls:
                for payload, indicators in payloads:
                    try:
                        url = test_url.format(payload)
                        response = await client.get(url)
                        
                        response_lower = response.text.lower()
                        for indicator in indicators:
                            if indicator in response_lower:
                                return ActiveCheckResult(
                                    check_name="SQL Injection",
                                    vulnerable=True,
                                    severity="critical",
                                    evidence=f"SQL error indicator '{indicator}' found in response",
                                    description="The application may be vulnerable to SQL injection attacks.",
                                    cve_id="CWE-89",
                                    cvss_score=9.8,
                                    solution="Use parameterized queries or prepared statements.",
                                    request=f"GET {url}",
                                    response=response.text[:500]
                                )
                    except:
                        continue
        
        return None
    
    async def _check_xss(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for reflected XSS"""
        payload = "<script>alert('xss')</script>"
        encoded_payload = "%3Cscript%3Ealert('xss')%3C/script%3E"
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            test_urls = [
                f"{base_url}?q={encoded_payload}",
                f"{base_url}?search={encoded_payload}",
                f"{base_url}?name={encoded_payload}",
            ]
            
            for url in test_urls:
                try:
                    response = await client.get(url)
                    
                    if payload in response.text:
                        return ActiveCheckResult(
                            check_name="Cross-Site Scripting (XSS)",
                            vulnerable=True,
                            severity="medium",
                            evidence="Unescaped script tag reflected in response",
                            description="The application reflects user input without proper encoding.",
                            cve_id="CWE-79",
                            cvss_score=6.1,
                            solution="Encode all user input before rendering in HTML.",
                            request=f"GET {url}",
                            response=response.text[:500]
                        )
                except:
                    continue
        
        return None
    
    async def _check_ssrf(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for SSRF vulnerability indicators"""
        # We use a safe canary URL
        payloads = [
            "http://127.0.0.1:22",
            "http://localhost:22",
            "http://[::1]:22",
            "http://0.0.0.0:22",
        ]
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            test_params = ["url", "uri", "path", "dest", "redirect", "out", "view", "fetch"]
            
            for param in test_params:
                for payload in payloads:
                    try:
                        url = f"{base_url}?{param}={payload}"
                        response = await client.get(url)
                        
                        # Check for SSH banner or internal service indicators
                        if "SSH-" in response.text or "OpenSSH" in response.text:
                            return ActiveCheckResult(
                                check_name="Server-Side Request Forgery (SSRF)",
                                vulnerable=True,
                                severity="high",
                                evidence="Application fetched internal resource",
                                description="The application can be used to access internal resources.",
                                cve_id="CWE-918",
                                cvss_score=8.6,
                                solution="Validate and restrict URLs that can be fetched.",
                                request=f"GET {url}",
                                response=response.text[:500]
                            )
                    except:
                        continue
        
        return None
    
    async def _check_open_redirect(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for open redirect vulnerability"""
        payloads = [
            "//evil.com",
            "https://evil.com",
            "/\\evil.com",
            "//evil.com/%2f..",
        ]
        
        async with httpx.AsyncClient(
            verify=False, 
            timeout=self.timeout,
            follow_redirects=False
        ) as client:
            test_params = ["url", "redirect", "next", "return", "returnTo", "go", "dest"]
            
            for param in test_params:
                for payload in payloads:
                    try:
                        url = f"{base_url}?{param}={payload}"
                        response = await client.get(url)
                        
                        location = response.headers.get("location", "")
                        if "evil.com" in location:
                            return ActiveCheckResult(
                                check_name="Open Redirect",
                                vulnerable=True,
                                severity="medium",
                                evidence=f"Redirect to external domain: {location}",
                                description="The application redirects to user-controlled URLs.",
                                cve_id="CWE-601",
                                cvss_score=6.1,
                                solution="Validate redirect URLs against an allowlist.",
                                request=f"GET {url}",
                                response=f"Location: {location}"
                            )
                    except:
                        continue
        
        return None
    
    async def _check_sensitive_files(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for exposed sensitive files"""
        sensitive_paths = [
            ("/.git/config", "[core]", "Git Repository Exposed"),
            ("/.env", "DB_", "Environment File Exposed"),
            ("/.env", "API_KEY", "Environment File Exposed"),
            ("/config.php.bak", "<?php", "PHP Backup File Exposed"),
            ("/web.config", "<configuration>", "ASP.NET Config Exposed"),
            ("/phpinfo.php", "PHP Version", "PHPInfo Exposed"),
            ("/.htaccess", "RewriteEngine", "Htaccess Exposed"),
            ("/server-status", "Apache Server Status", "Server Status Exposed"),
            ("/elmah.axd", "Error Log", "Error Log Exposed"),
            ("/backup.sql", "CREATE TABLE", "SQL Backup Exposed"),
            ("/dump.sql", "INSERT INTO", "SQL Dump Exposed"),
            ("/.DS_Store", None, "DS_Store Exposed"),
            ("/crossdomain.xml", "<cross-domain-policy>", "Crossdomain Policy"),
            ("/robots.txt", "Disallow:", "Robots.txt Found"),
            ("/sitemap.xml", "<urlset", "Sitemap Found"),
        ]
        
        found_issues = []
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for path, indicator, name in sensitive_paths:
                try:
                    url = base_url + path
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        if indicator is None or indicator in response.text:
                            found_issues.append((name, path))
                except:
                    continue
        
        if found_issues:
            # Return most critical finding
            critical_files = [".git", ".env", "backup", "dump", "config"]
            for name, path in found_issues:
                for critical in critical_files:
                    if critical in path.lower():
                        return ActiveCheckResult(
                            check_name="Sensitive File Exposure",
                            vulnerable=True,
                            severity="high",
                            evidence=f"Found: {path}",
                            description=f"Sensitive file accessible: {name}",
                            cve_id="CWE-538",
                            cvss_score=7.5,
                            solution="Remove or restrict access to sensitive files.",
                            request=f"GET {base_url}{path}",
                            response=f"Files found: {', '.join([p for _, p in found_issues])}"
                        )
            
            # Return info level for non-critical
            return ActiveCheckResult(
                check_name="Information Disclosure",
                vulnerable=True,
                severity="low",
                evidence=f"Found: {found_issues[0][1]}",
                description=f"Information files accessible",
                cve_id="CWE-200",
                cvss_score=3.7,
                solution="Review exposed files and restrict if necessary.",
                request=f"GET {base_url}{found_issues[0][1]}",
                response=f"Files found: {', '.join([p for _, p in found_issues])}"
            )
        
        return None
    
    async def _check_default_credentials(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for default credentials on common admin panels"""
        admin_paths = [
            "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
            "/adminer.php", "/manager/html", "/_admin", "/admin.php"
        ]
        
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("administrator", "administrator"),
        ]
        
        # Just check if admin panels exist for now
        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            for path in admin_paths:
                try:
                    url = base_url + path
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        # Check for login forms
                        if 'type="password"' in response.text.lower() or 'login' in response.text.lower():
                            return ActiveCheckResult(
                                check_name="Admin Panel Found",
                                vulnerable=True,
                                severity="info",
                                evidence=f"Admin panel at {path}",
                                description="Administrative interface is accessible.",
                                cve_id="CWE-287",
                                cvss_score=0,
                                solution="Restrict access to admin panels by IP or VPN.",
                                request=f"GET {url}",
                                response=f"Status: {response.status_code}"
                            )
                except:
                    continue
        
        return None
    
    async def _check_ssl_vulnerabilities(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for SSL/TLS vulnerabilities"""
        if not base_url.startswith("https"):
            return None
        
        host = base_url.replace("https://", "").split(":")[0].split("/")[0]
        port = 443
        if ":" in base_url.replace("https://", ""):
            port = int(base_url.replace("https://", "").split(":")[1].split("/")[0])
        
        issues = []
        
        # Check for weak protocols
        weak_protocols = [
            (ssl.PROTOCOL_TLS, ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2, "TLS 1.3 only"),
        ]
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check for weak versions
                    if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                        issues.append(f"Weak protocol: {version}")
                    
                    # Check for weak ciphers
                    if cipher:
                        cipher_name = cipher[0].upper()
                        weak_ciphers = ["RC4", "DES", "MD5", "NULL", "EXPORT", "ANON"]
                        for weak in weak_ciphers:
                            if weak in cipher_name:
                                issues.append(f"Weak cipher: {cipher_name}")
                                break
        except Exception as e:
            logger.debug(f"SSL check error: {e}")
        
        if issues:
            return ActiveCheckResult(
                check_name="SSL/TLS Vulnerability",
                vulnerable=True,
                severity="high" if "SSLv" in str(issues) else "medium",
                evidence="; ".join(issues),
                description="SSL/TLS configuration has security weaknesses.",
                cve_id="CWE-326",
                cvss_score=7.5 if "SSLv" in str(issues) else 5.3,
                solution="Disable weak protocols and ciphers. Use TLS 1.2+ only.",
                request=f"SSL handshake to {host}:{port}",
                response="; ".join(issues)
            )
        
        return None
    
    async def _check_cors_misconfig(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for CORS misconfiguration"""
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            try:
                # Test with arbitrary origin
                headers = {"Origin": "https://evil.com"}
                response = await client.get(base_url, headers=headers)
                
                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")
                
                if acao == "*":
                    return ActiveCheckResult(
                        check_name="CORS Misconfiguration",
                        vulnerable=True,
                        severity="medium",
                        evidence="Access-Control-Allow-Origin: *",
                        description="CORS policy allows any origin.",
                        cve_id="CWE-942",
                        cvss_score=5.3,
                        solution="Restrict CORS to specific trusted origins.",
                        request=f"GET {base_url} with Origin: https://evil.com",
                        response=f"ACAO: {acao}"
                    )
                
                if "evil.com" in acao and acac.lower() == "true":
                    return ActiveCheckResult(
                        check_name="CORS Misconfiguration",
                        vulnerable=True,
                        severity="high",
                        evidence=f"Reflects origin with credentials: {acao}",
                        description="CORS policy reflects arbitrary origins with credentials.",
                        cve_id="CWE-942",
                        cvss_score=8.1,
                        solution="Do not reflect arbitrary origins, especially with credentials.",
                        request=f"GET {base_url} with Origin: https://evil.com",
                        response=f"ACAO: {acao}, ACAC: {acac}"
                    )
            except:
                pass
        
        return None
    
    async def _check_security_headers(self, base_url: str) -> Optional[ActiveCheckResult]:
        """Check for missing security headers"""
        required_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME sniffing protection",
            "X-XSS-Protection": "XSS filter",
            "Strict-Transport-Security": "HTTPS enforcement",
            "Content-Security-Policy": "Content security policy",
        }
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            try:
                response = await client.get(base_url)
                
                missing = []
                for header, description in required_headers.items():
                    if header.lower() not in [h.lower() for h in response.headers.keys()]:
                        missing.append(header)
                
                if missing:
                    return ActiveCheckResult(
                        check_name="Missing Security Headers",
                        vulnerable=True,
                        severity="low",
                        evidence=f"Missing: {', '.join(missing)}",
                        description="Security headers are not configured.",
                        cve_id="CWE-693",
                        cvss_score=3.7,
                        solution="Add recommended security headers.",
                        request=f"GET {base_url}",
                        response=f"Missing headers: {', '.join(missing)}"
                    )
            except:
                pass
        
        return None


class DetectionEngine:
    """
    Main detection engine combining fingerprinting, CPE matching, and active checks
    """
    
    def __init__(self, db, nvd_api_key: Optional[str] = None):
        self.db = db
        self.fingerprinter = FingerprintEngine()
        self.cpe_matcher = CPEMatcher(db)
        self.active_checker = ActiveChecker()
    
    async def scan_target(self, host: str, ports: List[int], config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Full detection scan on a target
        """
        config = config or {}
        results = {
            "host": host,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "fingerprints": [],
            "vulnerabilities": [],
            "active_check_results": [],
        }
        
        # Fingerprint each port
        for port in ports:
            # Determine service type
            if port in [80, 8080, 8000, 3000]:
                fp = await self.fingerprinter.fingerprint_http(host, port, use_ssl=False)
            elif port in [443, 8443]:
                fp = await self.fingerprinter.fingerprint_http(host, port, use_ssl=True)
            else:
                fp = await self.fingerprinter.fingerprint_service(host, port)
            
            if fp.service_type != ServiceType.UNKNOWN or fp.banner:
                results["fingerprints"].append({
                    "port": fp.port,
                    "service_type": fp.service_type.value,
                    "product": fp.product,
                    "version": fp.version,
                    "cpe": fp.cpe,
                    "banner": fp.banner[:200] if fp.banner else "",
                    "technologies": fp.technologies,
                    "confidence": fp.confidence,
                })
                
                # Match CVEs
                if config.get("check_cve", True):
                    cve_matches = await self.cpe_matcher.match_fingerprint(fp)
                    for cve in cve_matches:
                        results["vulnerabilities"].append({
                            "port": fp.port,
                            "cve_id": cve.get("cve_id"),
                            "severity": cve.get("severity"),
                            "cvss_score": cve.get("cvss_v3_score") or cve.get("cvss_v2_score"),
                            "description": cve.get("description", "")[:500],
                            "is_kev": cve.get("is_kev", False),
                            "source": "cpe_match",
                            "matched_cpe": fp.cpe,
                            "matched_product": fp.product,
                            "matched_version": fp.version,
                        })
                
                # Run active checks
                if config.get("active_checks", True):
                    active_results = await self.active_checker.run_checks(host, port, fp.service_type)
                    for result in active_results:
                        results["active_check_results"].append({
                            "port": port,
                            "check_name": result.check_name,
                            "vulnerable": result.vulnerable,
                            "severity": result.severity,
                            "evidence": result.evidence,
                            "description": result.description,
                            "cve_id": result.cve_id,
                            "cvss_score": result.cvss_score,
                            "solution": result.solution,
                        })
                        
                        # Also add to vulnerabilities list
                        if result.vulnerable:
                            results["vulnerabilities"].append({
                                "port": port,
                                "title": result.check_name,
                                "severity": result.severity,
                                "cvss_score": result.cvss_score,
                                "description": result.description,
                                "cve_id": result.cve_id,
                                "solution": result.solution,
                                "source": "active_check",
                                "evidence": result.evidence,
                            })
        
        # Sort vulnerabilities by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results["vulnerabilities"].sort(
            key=lambda x: (severity_order.get(x.get("severity", "info"), 5), -(x.get("cvss_score") or 0))
        )
        
        return results
