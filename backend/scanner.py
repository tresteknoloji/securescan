"""
Vulnerability Scanner Engine
Uses Nmap for port scanning, Detection Engine for fingerprinting and active checks
"""
import asyncio
import subprocess
import ssl
import socket
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import logging
import httpx

logger = logging.getLogger(__name__)

# Import detection engine
try:
    from detection_engine import DetectionEngine, FingerprintEngine, ActiveChecker
    DETECTION_ENGINE_AVAILABLE = True
except ImportError:
    DETECTION_ENGINE_AVAILABLE = False
    logger.warning("Detection engine not available")

class VulnerabilityScanner:
    """Main scanner class that orchestrates vulnerability scanning"""
    
    def __init__(self, nvd_api_key: Optional[str] = None, db=None):
        self.nvd_api_key = nvd_api_key
        self.db = db
        self.detection_engine = None
        if DETECTION_ENGINE_AVAILABLE and db:
            self.detection_engine = DetectionEngine(db, nvd_api_key)
        
    async def scan_target(self, target: str, target_type: str, config: dict) -> Dict[str, Any]:
        """
        Scan a single target and return results
        Enhanced with detection engine for fingerprinting and active checks
        """
        results = {
            "target": target,
            "target_type": target_type,
            "vulnerabilities": [],
            "ports": [],
            "fingerprints": [],
            "active_checks": [],
            "ssl_info": None,
            "scan_time": datetime.now(timezone.utc).isoformat()
        }
        
        try:
            # Resolve domain to IP if needed
            ip_address = target
            if target_type == "domain":
                try:
                    ip_address = socket.gethostbyname(target)
                    results["resolved_ip"] = ip_address
                except socket.gaierror:
                    results["vulnerabilities"].append({
                        "severity": "info",
                        "title": "DNS Resolution Failed",
                        "description": f"Could not resolve domain {target} to IP address",
                        "port": None
                    })
                    return results
            
            # Port scanning with nmap
            port_range = config.get("port_range", "1-1000")
            scan_type = config.get("scan_type", "quick")
            
            port_results = await self._run_nmap_scan(ip_address, port_range, scan_type)
            results["ports"] = port_results.get("ports", [])
            results["vulnerabilities"].extend(port_results.get("vulnerabilities", []))
            
            # Extract open port numbers
            open_ports = [p["port"] for p in results["ports"] if p.get("state") == "open"]
            
            # Run detection engine if available
            if self.detection_engine and open_ports:
                logger.info(f"Running detection engine on {len(open_ports)} open ports")
                
                detection_results = await self.detection_engine.scan_target(
                    ip_address if target_type != "domain" else target,
                    open_ports,
                    config
                )
                
                # Add fingerprints
                results["fingerprints"] = detection_results.get("fingerprints", [])
                
                # Add active check results
                results["active_checks"] = detection_results.get("active_check_results", [])
                
                # Merge vulnerabilities (avoid duplicates)
                existing_cves = {v.get("cve_id") for v in results["vulnerabilities"] if v.get("cve_id")}
                for vuln in detection_results.get("vulnerabilities", []):
                    if vuln.get("cve_id") not in existing_cves:
                        results["vulnerabilities"].append(vuln)
            
            # SSL/TLS check (legacy, detection engine also does this)
            if config.get("check_ssl", True) and not self.detection_engine:
                ssl_results = await self._check_ssl(target if target_type == "domain" else ip_address)
                results["ssl_info"] = ssl_results.get("info")
                results["vulnerabilities"].extend(ssl_results.get("vulnerabilities", []))
            
            # Check for common vulnerabilities based on services (legacy)
            if config.get("check_cve", True) and not self.detection_engine:
                cve_vulns = await self._check_service_vulnerabilities(results["ports"])
                results["vulnerabilities"].extend(cve_vulns)
            
            # Sort vulnerabilities by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            results["vulnerabilities"].sort(
                key=lambda x: severity_order.get(x.get("severity", "info"), 5)
            )
                
        except Exception as e:
            logger.error(f"Error scanning target {target}: {str(e)}")
            results["error"] = str(e)
            
        return results
    
    async def _run_nmap_scan(self, target: str, port_range: str, scan_type: str) -> Dict[str, Any]:
        """Run nmap scan on target"""
        results = {"ports": [], "vulnerabilities": []}
        
        try:
            # Build nmap command based on scan type
            if scan_type == "quick":
                cmd = ["nmap", "-sV", "-T4", "--top-ports", "100", target]
            elif scan_type == "stealth":
                cmd = ["nmap", "-sS", "-sV", "-T2", "-p", port_range, target]
            else:  # full scan
                cmd = ["nmap", "-sV", "-sC", "-T4", "-p", port_range, target]
            
            # Run nmap with timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            except asyncio.TimeoutError:
                process.kill()
                results["vulnerabilities"].append({
                    "severity": "info",
                    "title": "Scan Timeout",
                    "description": "Port scan timed out after 5 minutes",
                    "port": None
                })
                return results
            
            output = stdout.decode()
            
            # Parse nmap output
            results["ports"] = self._parse_nmap_output(output)
            
            # Check for common vulnerabilities based on open ports
            for port_info in results["ports"]:
                vulns = self._check_port_vulnerabilities(port_info)
                results["vulnerabilities"].extend(vulns)
                
        except FileNotFoundError:
            logger.warning("Nmap not installed, using simulated scan")
            results = await self._simulated_scan(target, port_range)
        except Exception as e:
            logger.error(f"Nmap scan error: {str(e)}")
            results["vulnerabilities"].append({
                "severity": "info",
                "title": "Scan Error",
                "description": f"Error during port scan: {str(e)}",
                "port": None
            })
            
        return results
    
    async def _simulated_scan(self, target: str, port_range: str) -> Dict[str, Any]:
        """Simulated scan when nmap is not available"""
        results = {"ports": [], "vulnerabilities": []}
        
        # Common ports to check
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = self._get_common_service(port)
                    results["ports"].append({
                        "port": port,
                        "state": "open",
                        "protocol": "tcp",
                        "service": service,
                        "version": ""
                    })
                    
                    vulns = self._check_port_vulnerabilities({
                        "port": port,
                        "service": service,
                        "version": ""
                    })
                    results["vulnerabilities"].extend(vulns)
            except:
                pass
                
        return results
    
    def _get_common_service(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "microsoft-ds", 993: "imaps",
            995: "pop3s", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 8080: "http-proxy", 8443: "https-alt"
        }
        return services.get(port, "unknown")
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmap output to extract port information"""
        ports = []
        
        # Regex to match port lines
        port_pattern = r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+))?"
        
        for line in output.split('\n'):
            match = re.search(port_pattern, line)
            if match:
                ports.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4),
                    "version": match.group(5) if match.group(5) else ""
                })
                
        return ports
    
    def _check_port_vulnerabilities(self, port_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for vulnerabilities based on port and service"""
        vulnerabilities = []
        port = port_info.get("port")
        service = port_info.get("service", "").lower()
        version = port_info.get("version", "")
        
        # Dangerous ports
        dangerous_ports = {
            21: ("FTP Open", "high", "FTP port is open. FTP transmits data in clear text including credentials."),
            23: ("Telnet Open", "critical", "Telnet port is open. Telnet transmits all data including passwords in clear text."),
            445: ("SMB Open", "high", "SMB port is open. This service has been target of many critical vulnerabilities like EternalBlue."),
            3389: ("RDP Open", "medium", "Remote Desktop Protocol is exposed. Ensure strong authentication and consider VPN access only."),
        }
        
        if port in dangerous_ports:
            title, severity, desc = dangerous_ports[port]
            vulnerabilities.append({
                "severity": severity,
                "title": title,
                "description": desc,
                "port": port,
                "service": service
            })
        
        # Service-specific checks
        if service in ["http", "http-proxy"] and port not in [443, 8443]:
            vulnerabilities.append({
                "severity": "medium",
                "title": "Unencrypted HTTP Service",
                "description": f"HTTP service on port {port} is not encrypted. Consider using HTTPS.",
                "port": port,
                "service": service
            })
            
        if "mysql" in service:
            vulnerabilities.append({
                "severity": "high",
                "title": "MySQL Exposed",
                "description": "MySQL database port is exposed to network. Restrict access to trusted IPs only.",
                "port": port,
                "service": service
            })
            
        if "postgresql" in service:
            vulnerabilities.append({
                "severity": "high",
                "title": "PostgreSQL Exposed",
                "description": "PostgreSQL database port is exposed to network. Restrict access to trusted IPs only.",
                "port": port,
                "service": service
            })
            
        return vulnerabilities
    
    async def _check_ssl(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Check SSL/TLS configuration"""
        results = {"info": None, "vulnerabilities": []}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=host
            )
            conn.settimeout(10)
            
            try:
                conn.connect((host, port))
                cert = conn.getpeercert(binary_form=True)
                
                # Get SSL version
                ssl_version = conn.version()
                cipher = conn.cipher()
                
                results["info"] = {
                    "version": ssl_version,
                    "cipher": cipher[0] if cipher else None,
                    "bits": cipher[2] if cipher else None
                }
                
                # Check for weak protocols
                if ssl_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                    results["vulnerabilities"].append({
                        "severity": "high" if ssl_version.startswith("SSL") else "medium",
                        "title": f"Weak SSL/TLS Protocol: {ssl_version}",
                        "description": f"Server supports outdated {ssl_version} protocol which has known vulnerabilities.",
                        "port": port,
                        "solution": "Disable TLS 1.0, TLS 1.1, SSLv2 and SSLv3. Use TLS 1.2 or TLS 1.3 only."
                    })
                    
                # Check for weak ciphers
                if cipher and any(weak in cipher[0].upper() for weak in ["RC4", "DES", "MD5", "NULL", "EXPORT"]):
                    results["vulnerabilities"].append({
                        "severity": "high",
                        "title": f"Weak Cipher Suite: {cipher[0]}",
                        "description": "Server is using a weak cipher suite that may be vulnerable to attacks.",
                        "port": port,
                        "solution": "Configure server to use strong cipher suites only."
                    })
                    
                conn.close()
                
            except ssl.SSLError as e:
                results["vulnerabilities"].append({
                    "severity": "info",
                    "title": "SSL Connection Issue",
                    "description": f"Could not establish SSL connection: {str(e)}",
                    "port": port
                })
            except socket.timeout:
                results["vulnerabilities"].append({
                    "severity": "info",
                    "title": "SSL Connection Timeout",
                    "description": "SSL connection timed out",
                    "port": port
                })
                
        except Exception as e:
            results["vulnerabilities"].append({
                "severity": "info",
                "title": "SSL Check Failed",
                "description": f"Could not check SSL: {str(e)}",
                "port": port
            })
            
        return results
    
    async def _check_service_vulnerabilities(self, ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for CVE vulnerabilities based on detected services"""
        vulnerabilities = []
        
        for port_info in ports:
            service = port_info.get("service", "").lower()
            version = port_info.get("version", "")
            
            # Check for known vulnerable versions
            known_vulns = self._get_known_vulnerabilities(service, version)
            for vuln in known_vulns:
                vuln["port"] = port_info.get("port")
                vuln["service"] = service
                vulnerabilities.append(vuln)
                
        return vulnerabilities
    
    def _get_known_vulnerabilities(self, service: str, version: str) -> List[Dict[str, Any]]:
        """Get known vulnerabilities for a service/version combination"""
        vulnerabilities = []
        
        # Common known vulnerable versions
        known_issues = {
            "openssh": {
                "patterns": [r"[4-6]\.", r"7\.[0-3]"],
                "vulns": [{
                    "severity": "medium",
                    "title": "Outdated OpenSSH Version",
                    "description": "This version of OpenSSH may have known vulnerabilities. Update to the latest version.",
                    "cve_id": "Multiple CVEs"
                }]
            },
            "apache": {
                "patterns": [r"2\.2\.", r"2\.4\.[0-9]$", r"2\.4\.1[0-9]$"],
                "vulns": [{
                    "severity": "medium",
                    "title": "Potentially Vulnerable Apache Version",
                    "description": "This version of Apache httpd may have known vulnerabilities.",
                    "cve_id": "Multiple CVEs"
                }]
            },
            "nginx": {
                "patterns": [r"1\.[0-9]\.", r"1\.1[0-6]\."],
                "vulns": [{
                    "severity": "low",
                    "title": "Older Nginx Version",
                    "description": "Consider updating Nginx to the latest stable version.",
                    "cve_id": "N/A"
                }]
            }
        }
        
        service_lower = service.lower()
        version_lower = version.lower()
        
        for svc, data in known_issues.items():
            if svc in service_lower or svc in version_lower:
                for pattern in data["patterns"]:
                    if re.search(pattern, version_lower):
                        vulnerabilities.extend(data["vulns"])
                        break
                        
        return vulnerabilities


async def sync_cve_database(db, nvd_api_key: str, days_back: int = 30):
    """Sync CVE database from NVD with full pagination support"""
    logger.info("Starting CVE database sync from NVD...")
    
    try:
        async with httpx.AsyncClient() as client:
            # Calculate date range
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=days_back)
            
            headers = {}
            if nvd_api_key:
                headers["apiKey"] = nvd_api_key
            
            # NVD API returns max 2000 results per request
            # We need to paginate through all results
            results_per_page = 2000
            start_index = 0
            total_results = None
            synced_count = 0
            all_cves = []
            
            while True:
                params = {
                    "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                    "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page
                }
                
                logger.info(f"Fetching CVEs from index {start_index}...")
                
                response = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params=params,
                    headers=headers,
                    timeout=120
                )
                
                if response.status_code != 200:
                    logger.error(f"NVD API error: {response.status_code}")
                    break
                
                data = response.json()
                
                # Get total results on first request
                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    logger.info(f"Total CVEs to fetch: {total_results}")
                
                vulnerabilities = data.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    break
                
                # Collect all CVEs for bulk processing
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id")
                    
                    if not cve_id:
                        continue
                    
                    # Extract CVSS score
                    cvss_score = None
                    severity = "info"
                    
                    metrics = cve.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                        cvss_score = cvss_data.get("baseScore")
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                        cvss_score = cvss_data.get("baseScore")
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                        cvss_score = cvss_data.get("baseScore")
                    
                    # Determine severity from CVSS score
                    if cvss_score:
                        if cvss_score >= 9.0:
                            severity = "critical"
                        elif cvss_score >= 7.0:
                            severity = "high"
                        elif cvss_score >= 4.0:
                            severity = "medium"
                        elif cvss_score > 0:
                            severity = "low"
                    
                    # Extract description
                    descriptions = cve.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
                    
                    all_cves.append({
                        "cve_id": cve_id,
                        "description": description[:2000] if description else "",
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "published_date": cve.get("published"),
                        "modified_date": cve.get("lastModified"),
                        "synced_at": datetime.now(timezone.utc).isoformat()
                    })
                
                # Update start_index for next page
                start_index += results_per_page
                
                # Check if we've fetched all results
                if start_index >= total_results:
                    break
                
                # Rate limiting: NVD recommends 6 second delay without API key
                # With API key, 0.6 second delay
                if nvd_api_key:
                    await asyncio.sleep(0.6)
                else:
                    await asyncio.sleep(6)
            
            # Bulk upsert all CVEs
            logger.info(f"Saving {len(all_cves)} CVEs to database...")
            
            for cve_entry in all_cves:
                await db.cves.update_one(
                    {"cve_id": cve_entry["cve_id"]},
                    {"$set": cve_entry},
                    upsert=True
                )
                synced_count += 1
            
            logger.info(f"CVE sync completed. Synced {synced_count} CVEs out of {total_results} total.")
            return {"success": True, "synced": synced_count, "total": total_results}
                
    except Exception as e:
        logger.error(f"CVE sync error: {str(e)}")
        return {"success": False, "error": str(e)}


from datetime import timedelta
