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
                    except:
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
        """Process scan results received from agent"""
        # This will be called when agent completes a scan task
        # Results include ports, services, vulnerabilities found
        
        logger.info(f"Processing scan results for {scan_id}")
        
        # The result contains raw nmap/scanner output
        # We need to process it like the local scanner does
        
        # Get scan info
        scan = await self.db.scans.find_one({"id": scan_id})
        if not scan:
            return
        
        # Import vulnerability processing logic
        # This will be similar to what scanner.py does
        vulnerabilities = result.get("vulnerabilities", [])
        ports = result.get("ports", [])
        
        # Save vulnerabilities
        for vuln_data in vulnerabilities:
            from models import Vulnerability
            vuln = Vulnerability(
                scan_id=scan_id,
                iteration=scan.get("current_iteration", 1),
                target_id=vuln_data.get("target_id", ""),
                target_value=vuln_data.get("target_value", ""),
                severity=vuln_data.get("severity", "info"),
                title=vuln_data.get("title", "Unknown"),
                description=vuln_data.get("description", ""),
                port=vuln_data.get("port"),
                service=vuln_data.get("service"),
                cve_id=vuln_data.get("cve_id"),
                cvss_score=vuln_data.get("cvss_score")
            )
            vuln_dict = vuln.model_dump()
            vuln_dict["created_at"] = vuln_dict["created_at"].isoformat()
            await self.db.vulnerabilities.insert_one(vuln_dict)
        
        # Update scan summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            sev = v.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        await self.db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "completed",
                "progress": 100,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "total_vulnerabilities": len(vulnerabilities),
                "critical_count": severity_counts["critical"],
                "high_count": severity_counts["high"],
                "medium_count": severity_counts["medium"],
                "low_count": severity_counts["low"],
                "info_count": severity_counts["info"]
            }}
        )
        
        logger.info(f"Scan {scan_id} completed with {len(vulnerabilities)} vulnerabilities")
    
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
