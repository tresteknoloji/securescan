"""
Agent Gateway - WebSocket server for remote scanning agents
Handles agent connections, authentication, and task distribution
"""
import asyncio
import json
import hashlib
import secrets
import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Set
from fastapi import WebSocket, WebSocketDisconnect
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)

# Active agent connections: agent_id -> WebSocket
active_connections: Dict[str, WebSocket] = {}

# Pending tasks waiting to be sent to agents: agent_id -> List[task_id]
pending_tasks: Dict[str, Set[str]] = {}


def generate_agent_token() -> str:
    """Generate a secure random token for agent authentication"""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash token for secure storage"""
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token(plain_token: str, hashed_token: str) -> bool:
    """Verify a plain token against its hash"""
    return hash_token(plain_token) == hashed_token


class AgentGateway:
    """Manages WebSocket connections with remote agents"""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.connections: Dict[str, WebSocket] = {}
        self.heartbeat_interval = 30  # seconds
        self.task_timeout = 300  # 5 minutes
    
    async def authenticate_agent(self, token: str) -> Optional[dict]:
        """Authenticate agent by token and return agent data"""
        hashed = hash_token(token)
        agent = await self.db.agents.find_one(
            {"token": hashed, "is_active": True},
            {"_id": 0}
        )
        return agent
    
    async def handle_connection(self, websocket: WebSocket, token: str):
        """Handle incoming WebSocket connection from agent"""
        # Authenticate
        agent = await self.authenticate_agent(token)
        if not agent:
            await websocket.close(code=4001, reason="Invalid or inactive token")
            return
        
        agent_id = agent["id"]
        agent_name = agent["name"]
        
        # Accept connection
        await websocket.accept()
        logger.info(f"Agent connected: {agent_name} ({agent_id})")
        
        # Store connection
        self.connections[agent_id] = websocket
        
        # Update agent status
        client_ip = websocket.client.host if websocket.client else None
        await self.db.agents.update_one(
            {"id": agent_id},
            {"$set": {
                "status": "online",
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "ip_address": client_ip
            }}
        )
        
        # Send welcome message
        await self.send_to_agent(agent_id, {
            "type": "welcome",
            "agent_id": agent_id,
            "message": "Connected to SecureScan Gateway"
        })
        
        # Check for pending tasks
        await self.send_pending_tasks(agent_id)
        
        try:
            # Start heartbeat checker
            heartbeat_task = asyncio.create_task(self.heartbeat_checker(agent_id))
            
            # Message loop
            while True:
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=self.heartbeat_interval * 2
                    )
                    await self.handle_message(agent_id, json.loads(data))
                except asyncio.TimeoutError:
                    # No message received, check if connection is alive
                    try:
                        await websocket.send_json({"type": "ping"})
                    except Exception:
                        break
                        
        except WebSocketDisconnect:
            logger.info(f"Agent disconnected: {agent_name} ({agent_id})")
        except Exception as e:
            logger.error(f"Agent connection error: {e}")
        finally:
            # Cleanup
            heartbeat_task.cancel()
            if agent_id in self.connections:
                del self.connections[agent_id]
            
            # Update agent status
            await self.db.agents.update_one(
                {"id": agent_id},
                {"$set": {
                    "status": "offline",
                    "last_seen": datetime.now(timezone.utc).isoformat()
                }}
            )
    
    async def heartbeat_checker(self, agent_id: str):
        """Periodically update last_seen and check connection health"""
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            if agent_id in self.connections:
                await self.db.agents.update_one(
                    {"id": agent_id},
                    {"$set": {"last_seen": datetime.now(timezone.utc).isoformat()}}
                )
    
    async def handle_message(self, agent_id: str, message: dict):
        """Process message received from agent"""
        msg_type = message.get("type")
        
        if msg_type == "pong":
            # Heartbeat response
            await self.db.agents.update_one(
                {"id": agent_id},
                {"$set": {"last_seen": datetime.now(timezone.utc).isoformat()}}
            )
        
        elif msg_type == "system_info":
            # Agent reports its system information
            await self.db.agents.update_one(
                {"id": agent_id},
                {"$set": {
                    "os_info": message.get("os_info"),
                    "installed_tools": message.get("installed_tools", []),
                    "agent_version": message.get("agent_version"),
                    "internal_networks": message.get("detected_networks", [])
                }}
            )
            logger.info(f"Agent {agent_id} system info updated")
        
        elif msg_type == "task_started":
            # Agent started executing a task
            task_id = message.get("task_id")
            await self.db.agent_tasks.update_one(
                {"id": task_id},
                {"$set": {
                    "status": "running",
                    "started_at": datetime.now(timezone.utc).isoformat()
                }}
            )
            
            # Update agent status to busy
            await self.db.agents.update_one(
                {"id": agent_id},
                {"$set": {"status": "busy"}}
            )
        
        elif msg_type == "task_progress":
            # Task progress update
            task_id = message.get("task_id")
            progress = message.get("progress", 0)
            await self.db.agent_tasks.update_one(
                {"id": task_id},
                {"$set": {"progress": progress}}
            )
            
            # Also update related scan progress if applicable
            task = await self.db.agent_tasks.find_one({"id": task_id})
            if task and task.get("scan_id"):
                await self.db.scans.update_one(
                    {"id": task["scan_id"]},
                    {"$set": {"progress": progress}}
                )
        
        elif msg_type == "task_completed":
            # Task finished successfully
            task_id = message.get("task_id")
            result = message.get("result", {})
            
            await self.db.agent_tasks.update_one(
                {"id": task_id},
                {"$set": {
                    "status": "completed",
                    "progress": 100,
                    "result": result,
                    "completed_at": datetime.now(timezone.utc).isoformat()
                }}
            )
            
            # Update agent status back to online
            await self.db.agents.update_one(
                {"id": agent_id},
                {"$set": {"status": "online"}}
            )
            
            logger.info(f"Task {task_id} completed by agent {agent_id}")
            
            # Process scan results if this was a scan task
            task = await self.db.agent_tasks.find_one({"id": task_id})
            if task and task.get("scan_id"):
                await self.process_scan_results(task["scan_id"], result)
        
        elif msg_type == "task_failed":
            # Task failed
            task_id = message.get("task_id")
            error = message.get("error", "Unknown error")
            
            await self.db.agent_tasks.update_one(
                {"id": task_id},
                {"$set": {
                    "status": "failed",
                    "error_message": error,
                    "completed_at": datetime.now(timezone.utc).isoformat()
                }}
            )
            
            # Update agent status
            await self.db.agents.update_one(
                {"id": agent_id},
                {"$set": {"status": "online"}}
            )
            
            # Update scan status if applicable
            task = await self.db.agent_tasks.find_one({"id": task_id})
            if task and task.get("scan_id"):
                await self.db.scans.update_one(
                    {"id": task["scan_id"]},
                    {"$set": {
                        "status": "failed",
                        "failure_reason": f"Agent task failed: {error}",
                        "completed_at": datetime.now(timezone.utc).isoformat()
                    }}
                )
            
            logger.error(f"Task {task_id} failed: {error}")
        
        elif msg_type == "tool_installed":
            # Agent installed a new tool
            tool_name = message.get("tool")
            await self.db.agents.update_one(
                {"id": agent_id},
                {"$addToSet": {"installed_tools": tool_name}}
            )
            logger.info(f"Agent {agent_id} installed tool: {tool_name}")
    
    async def send_to_agent(self, agent_id: str, message: dict) -> bool:
        """Send message to specific agent"""
        if agent_id not in self.connections:
            return False
        
        try:
            await self.connections[agent_id].send_json(message)
            return True
        except Exception as e:
            logger.error(f"Failed to send to agent {agent_id}: {e}")
            return False
    
    async def send_pending_tasks(self, agent_id: str):
        """Send all pending tasks to newly connected agent"""
        cursor = self.db.agent_tasks.find(
            {"agent_id": agent_id, "status": "pending"},
            {"_id": 0}
        )
        tasks = await cursor.to_list(100)
        
        for task in tasks:
            await self.send_task_to_agent(agent_id, task)
    
    async def send_task_to_agent(self, agent_id: str, task: dict) -> bool:
        """Send a task to agent for execution"""
        message = {
            "type": "execute_task",
            "task_id": task["id"],
            "task_type": task["task_type"],
            "command": task["command"],
            "parameters": task.get("parameters", {})
        }
        
        if await self.send_to_agent(agent_id, message):
            await self.db.agent_tasks.update_one(
                {"id": task["id"]},
                {"$set": {"status": "sent"}}
            )
            return True
        return False
    
    async def create_task(
        self,
        agent_id: str,
        task_type: str,
        command: str,
        parameters: dict = None,
        scan_id: str = None
    ) -> dict:
        """Create a new task for an agent"""
        from models import AgentTask
        
        task = AgentTask(
            agent_id=agent_id,
            scan_id=scan_id,
            task_type=task_type,
            command=command,
            parameters=parameters or {}
        )
        
        task_dict = task.model_dump()
        task_dict["created_at"] = task_dict["created_at"].isoformat()
        
        await self.db.agent_tasks.insert_one(task_dict)
        
        # Try to send immediately if agent is connected
        if agent_id in self.connections:
            await self.send_task_to_agent(agent_id, task_dict)
        
        return task_dict
    
    async def process_scan_results(self, scan_id: str, result: dict):
        """
        Process scan results received from agent.
        Performs CVE matching, KEV checking, and vulnerability assessment.
        Now also processes SSL, NSE, and Web findings from enhanced agent scanning.
        """
        logger.info(f"Processing scan results for {scan_id}")
        
        # Get scan info
        scan = await self.db.scans.find_one({"id": scan_id})
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return
        
        iteration = scan.get("current_iteration", 1)
        ports = result.get("ports", [])
        targets_scanned = result.get("targets_scanned", [])
        
        # New enhanced findings from agent
        ssl_findings = result.get("ssl_findings", [])
        nse_findings = result.get("nse_findings", [])
        web_findings = result.get("web_findings", [])
        
        logger.info(f"Processing {len(ports)} ports, {len(ssl_findings)} SSL findings, "
                   f"{len(nse_findings)} NSE findings, {len(web_findings)} web findings")
        
        # Get target details for mapping
        target_ids = scan.get("target_ids", [])
        targets = await self.db.targets.find({"id": {"$in": target_ids}}, {"_id": 0}).to_list(100)
        target_map = {t["value"]: t for t in targets}
        
        all_vulnerabilities = []
        open_ports_by_target = {}
        
        # Process each port finding
        for port_info in ports:
            target_value = port_info.get("target", "")
            target_data = target_map.get(target_value, {})
            target_id = target_data.get("id", "")
            
            # Track open ports
            if port_info.get("state") == "open":
                if target_value not in open_ports_by_target:
                    open_ports_by_target[target_value] = []
                open_ports_by_target[target_value].append({
                    "port": port_info.get("port"),
                    "protocol": port_info.get("protocol", "tcp"),
                    "service": port_info.get("service", ""),
                    "version": port_info.get("version", "")
                })
            
            # Get vulnerabilities for this port/service
            port_vulns = await self._process_port_vulnerabilities(
                port_info, target_id, target_value, iteration, scan_id
            )
            all_vulnerabilities.extend(port_vulns)
        
        # Process SSL/TLS findings from agent
        for ssl_finding in ssl_findings:
            target_value = ssl_finding.get("target", "")
            target_data = target_map.get(target_value, {})
            target_id = target_data.get("id", "")
            
            all_vulnerabilities.append({
                "target_id": target_id,
                "target_value": target_value,
                "severity": ssl_finding.get("severity", "medium"),
                "title": ssl_finding.get("title", "SSL/TLS Issue"),
                "description": ssl_finding.get("description", ""),
                "port": ssl_finding.get("port"),
                "service": "ssl/tls",
                "evidence": ssl_finding.get("evidence", ""),
                "source": "ssl_scan"
            })
        
        # Process NSE vulnerability findings from agent
        for nse_finding in nse_findings:
            target_value = nse_finding.get("target", "")
            target_data = target_map.get(target_value, {})
            target_id = target_data.get("id", "")
            
            cve_id = nse_finding.get("cve_id")
            
            # If CVE found, try to get additional info from local database
            references = []
            cvss_score = None
            is_kev = False
            
            if cve_id:
                cve_doc = await self.db.cves.find_one({"cve_id": cve_id}, {"_id": 0})
                if cve_doc:
                    cvss_score = cve_doc.get("cvss_score")
                    is_kev = cve_doc.get("is_kev", False)
                    refs = cve_doc.get("references", [])
                    for ref in refs[:3]:
                        if isinstance(ref, dict):
                            references.append(ref.get("url", ""))
                        elif isinstance(ref, str):
                            references.append(ref)
            
            all_vulnerabilities.append({
                "target_id": target_id,
                "target_value": target_value,
                "severity": nse_finding.get("severity", "medium"),
                "title": nse_finding.get("title", "Vulnerability Detected"),
                "description": nse_finding.get("description", ""),
                "port": nse_finding.get("port"),
                "service": "nse",
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "is_kev": is_kev,
                "references": references,
                "evidence": nse_finding.get("evidence", ""),
                "source": "nse_scan"
            })
        
        # Process Web vulnerability findings from agent
        for web_finding in web_findings:
            target_value = web_finding.get("target", "")
            target_data = target_map.get(target_value, {})
            target_id = target_data.get("id", "")
            
            all_vulnerabilities.append({
                "target_id": target_id,
                "target_value": target_value,
                "severity": web_finding.get("severity", "medium"),
                "title": web_finding.get("title", "Web Vulnerability"),
                "description": web_finding.get("description", ""),
                "port": web_finding.get("port"),
                "service": "http",
                "evidence": web_finding.get("evidence", ""),
                "source": "web_scan"
            })
        
        # Deduplicate vulnerabilities by title and target
        seen = set()
        unique_vulnerabilities = []
        for vuln in all_vulnerabilities:
            key = (vuln.get("target_value"), vuln.get("title"), vuln.get("port"))
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
        
        all_vulnerabilities = unique_vulnerabilities
        
        # Save all vulnerabilities to database
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for vuln in all_vulnerabilities:
            from models import Vulnerability
            vuln_obj = Vulnerability(
                scan_id=scan_id,
                iteration=iteration,
                target_id=vuln.get("target_id", ""),
                target_value=vuln.get("target_value", ""),
                severity=vuln.get("severity", "info"),
                title=vuln.get("title", "Unknown"),
                description=vuln.get("description", ""),
                port=vuln.get("port"),
                service=vuln.get("service"),
                cve_id=vuln.get("cve_id"),
                cvss_score=vuln.get("cvss_score"),
                references=vuln.get("references", []),
                is_kev=vuln.get("is_kev", False),
                evidence=vuln.get("evidence", "")
            )
            vuln_dict = vuln_obj.model_dump()
            vuln_dict["created_at"] = vuln_dict["created_at"].isoformat()
            vuln_dict["source"] = vuln.get("source", "port_scan")
            await self.db.vulnerabilities.insert_one(vuln_dict)
            
            sev = vuln.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Update scan with results
        await self.db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "completed",
                "progress": 100,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "total_vulnerabilities": len(all_vulnerabilities),
                "critical_count": severity_counts["critical"],
                "high_count": severity_counts["high"],
                "medium_count": severity_counts["medium"],
                "low_count": severity_counts["low"],
                "info_count": severity_counts["info"],
                "open_ports_by_target": open_ports_by_target,
                "ssl_findings_count": len(ssl_findings),
                "nse_findings_count": len(nse_findings),
                "web_findings_count": len(web_findings)
            }}
        )
        
        logger.info(f"Scan {scan_id} completed with {len(all_vulnerabilities)} vulnerabilities "
                   f"(SSL: {len(ssl_findings)}, NSE: {len(nse_findings)}, Web: {len(web_findings)})")
    
    async def _process_port_vulnerabilities(
        self, port_info: dict, target_id: str, target_value: str, iteration: int, scan_id: str
    ) -> list:
        """
        Process vulnerabilities for a single port.
        Checks CVE database and KEV for matches.
        """
        vulnerabilities = []
        
        port = port_info.get("port")
        state = port_info.get("state", "")
        service = port_info.get("service", "").lower()
        version = port_info.get("version", "")
        protocol = port_info.get("protocol", "tcp")
        
        if state != "open":
            return vulnerabilities
        
        # 1. Check for dangerous/risky ports
        dangerous_ports = {
            21: ("FTP Service Exposed", "high", "FTP transmits credentials in clear text. Consider SFTP."),
            22: ("SSH Service Exposed", "info", "SSH accessible. Ensure strong authentication."),
            23: ("Telnet Service Exposed", "critical", "Telnet transmits all data in clear text. Disable immediately."),
            25: ("SMTP Service Exposed", "medium", "Mail server exposed. Verify not an open relay."),
            53: ("DNS Service Exposed", "low", "DNS accessible. Check for zone transfer."),
            80: ("HTTP Service Exposed", "info", "Web server on HTTP. Consider HTTPS."),
            110: ("POP3 Service Exposed", "medium", "POP3 unencrypted. Use POP3S."),
            111: ("RPC Service Exposed", "medium", "RPC portmapper exposed."),
            135: ("MSRPC Exposed", "medium", "Microsoft RPC exposed."),
            139: ("NetBIOS Exposed", "high", "NetBIOS can leak system info."),
            143: ("IMAP Service Exposed", "medium", "IMAP unencrypted. Use IMAPS."),
            445: ("SMB Service Exposed", "high", "SMB exposed. Target of critical exploits."),
            1433: ("MSSQL Exposed", "high", "SQL Server exposed to network."),
            1521: ("Oracle DB Exposed", "high", "Oracle listener exposed."),
            3306: ("MySQL Exposed", "high", "MySQL exposed to network."),
            3389: ("RDP Service Exposed", "high", "Remote Desktop exposed. BlueKeep risk."),
            5432: ("PostgreSQL Exposed", "high", "PostgreSQL exposed."),
            5900: ("VNC Exposed", "high", "VNC often has weak auth."),
            6379: ("Redis Exposed", "critical", "Redis often without auth."),
            8080: ("HTTP Alt Exposed", "low", "Alternative HTTP port."),
            27017: ("MongoDB Exposed", "critical", "MongoDB often without auth."),
        }
        
        if port in dangerous_ports:
            title, severity, desc = dangerous_ports[port]
            vulnerabilities.append({
                "target_id": target_id,
                "target_value": target_value,
                "severity": severity,
                "title": title,
                "description": desc,
                "port": port,
                "service": service,
                "evidence": f"Port {port}/{protocol} open - {service} {version}".strip()
            })
        
        # 2. CVE lookup based on service and version
        if version and service:
            cve_vulns = await self._lookup_cve_for_service(
                service, version, port, target_id, target_value
            )
            vulnerabilities.extend(cve_vulns)
        
        return vulnerabilities
    
    async def _lookup_cve_for_service(
        self, service: str, version: str, port: int, target_id: str, target_value: str
    ) -> list:
        """
        Look up CVEs in local database for a service/version combination.
        Also checks CISA KEV status.
        """
        vulnerabilities = []
        
        # Build search terms
        search_terms = []
        service_lower = service.lower()
        version_lower = version.lower()
        
        # Extract product and version info
        # Common patterns: "OpenSSH 8.9p1", "Apache httpd 2.4.52", "nginx 1.18.0"
        import re
        
        # Try to extract product name and version
        product_patterns = [
            r'(openssh)[_\s]*([\d.p]+)',
            r'(apache)[/\s]*([\d.]+)',
            r'(nginx)[/\s]*([\d.]+)',
            r'(mysql)[/\s]*([\d.]+)',
            r'(postgresql)[/\s]*([\d.]+)',
            r'(microsoft-ds|smb)',
            r'(proftpd)[/\s]*([\d.]+)',
            r'(vsftpd)[/\s]*([\d.]+)',
            r'(exim)[/\s]*([\d.]+)',
            r'(postfix)',
            r'(iis)[/\s]*([\d.]+)',
        ]
        
        for pattern in product_patterns:
            match = re.search(pattern, version_lower)
            if match:
                product = match.group(1)
                ver = match.group(2) if len(match.groups()) > 1 else ""
                search_terms.append(product)
                if ver:
                    search_terms.append(f"{product} {ver}")
                break
        
        # Also use service name
        if service_lower and service_lower not in search_terms:
            search_terms.append(service_lower)
        
        if not search_terms:
            return vulnerabilities
        
        # Search CVE database
        for term in search_terms[:3]:  # Limit searches
            try:
                # Search in CVE descriptions
                cve_query = {
                    "$or": [
                        {"description": {"$regex": term, "$options": "i"}},
                        {"cve_id": {"$regex": term, "$options": "i"}}
                    ]
                }
                
                # Get matching CVEs (limit to avoid too many)
                cves = await self.db.cves.find(
                    cve_query, 
                    {"_id": 0, "cve_id": 1, "description": 1, "cvss_score": 1, "severity": 1, "is_kev": 1, "references": 1}
                ).limit(10).to_list(10)
                
                for cve in cves:
                    # Skip if already added
                    if any(v.get("cve_id") == cve["cve_id"] for v in vulnerabilities):
                        continue
                    
                    cvss = cve.get("cvss_score", 0)
                    severity = cve.get("severity", "medium")
                    if not severity:
                        if cvss >= 9.0:
                            severity = "critical"
                        elif cvss >= 7.0:
                            severity = "high"
                        elif cvss >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                    
                    # Get references
                    refs = cve.get("references", [])
                    ref_urls = []
                    for ref in refs[:3]:
                        if isinstance(ref, dict):
                            ref_urls.append(ref.get("url", ""))
                        elif isinstance(ref, str):
                            ref_urls.append(ref)
                    
                    vulnerabilities.append({
                        "target_id": target_id,
                        "target_value": target_value,
                        "severity": severity,
                        "title": f"{cve['cve_id']} - {service}",
                        "description": cve.get("description", "")[:500],
                        "port": port,
                        "service": service,
                        "cve_id": cve["cve_id"],
                        "cvss_score": cvss,
                        "is_kev": cve.get("is_kev", False),
                        "references": ref_urls,
                        "evidence": f"Service: {service} Version: {version}"
                    })
                    
            except Exception as e:
                logger.error(f"CVE lookup error for {term}: {e}")
        
        return vulnerabilities
    
    def is_agent_online(self, agent_id: str) -> bool:
        """Check if agent is currently connected"""
        return agent_id in self.connections
    
    def get_online_agents(self) -> list:
        """Get list of currently connected agent IDs"""
        return list(self.connections.keys())


# Global gateway instance
_gateway_instance: Optional[AgentGateway] = None


def get_agent_gateway(db: AsyncIOMotorDatabase) -> AgentGateway:
    """Get or create agent gateway instance"""
    global _gateway_instance
    if _gateway_instance is None:
        _gateway_instance = AgentGateway(db)
    return _gateway_instance
