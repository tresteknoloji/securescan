"""
Vulnerability Scanner API Server
"""
from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, BackgroundTasks, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import asyncio

# Local imports
from models import (
    User, UserCreate, UserUpdate, UserResponse, LoginRequest, TokenResponse,
    Target, TargetCreate, TargetUpdate, TargetResponse,
    Scan, ScanCreate, ScanResponse, ScanConfig,
    Vulnerability, VulnerabilityResponse,
    SMTPConfig, SMTPConfigCreate, SMTPConfigResponse,
    BrandingSettings, BrandingSettingsCreate, BrandingSettingsResponse,
    DashboardStats, TRANSLATIONS,
    Agent, AgentCreate, AgentUpdate, AgentResponse, AgentWithToken,
    AgentTask, AgentTaskResponse
)
from auth import (
    verify_password, get_password_hash, create_access_token,
    get_current_user, require_role
)
from scanner import VulnerabilityScanner, sync_cve_database
from report_generator import generate_html_report, generate_pdf_report
from email_service import send_email, get_scan_complete_email
from risk_calculator import RiskCalculator, enrich_vulnerabilities_with_risk
from agent_gateway import AgentGateway, get_agent_gateway, generate_agent_token, hash_token

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI(title="Vulnerability Scanner API", version="1.0.0")

# Create router with /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# NVD API Key
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# ============== Auth Endpoints ==============
@api_router.post("/auth/register", response_model=TokenResponse)
async def register(data: UserCreate):
    """Register a new user"""
    # Check if email exists
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password and create user
    user = User(
        email=data.email,
        password_hash=get_password_hash(data.password),
        name=data.name,
        role=data.role,
        parent_id=data.parent_id,
        max_customers=data.max_customers,
        max_targets=data.max_targets,
        monthly_scan_limit=data.monthly_scan_limit
    )
    
    user_dict = user.model_dump()
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    user_dict['updated_at'] = user_dict['updated_at'].isoformat()
    
    await db.users.insert_one(user_dict)
    
    # Create access token
    access_token = create_access_token(
        data={"sub": user.id, "email": user.email, "role": user.role, "parent_id": user.parent_id}
    )
    
    return TokenResponse(
        access_token=access_token,
        user=UserResponse(**user.model_dump())
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(data: LoginRequest):
    """Login and get access token"""
    user_doc = await db.users.find_one({"email": data.email}, {"_id": 0})
    
    if not user_doc or not verify_password(data.password, user_doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user_doc.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is disabled")
    
    # Parse dates
    if isinstance(user_doc.get('created_at'), str):
        user_doc['created_at'] = datetime.fromisoformat(user_doc['created_at'])
    if isinstance(user_doc.get('updated_at'), str):
        user_doc['updated_at'] = datetime.fromisoformat(user_doc['updated_at'])
    
    access_token = create_access_token(
        data={"sub": user_doc['id'], "email": user_doc['email'], "role": user_doc['role'], "parent_id": user_doc.get('parent_id')}
    )
    
    return TokenResponse(
        access_token=access_token,
        user=UserResponse(**user_doc)
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user info"""
    user_doc = await db.users.find_one({"id": current_user['sub']}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    
    if isinstance(user_doc.get('created_at'), str):
        user_doc['created_at'] = datetime.fromisoformat(user_doc['created_at'])
    
    return UserResponse(**user_doc)

# ============== User Management Endpoints ==============
@api_router.get("/users", response_model=List[UserResponse])
async def get_users(current_user: dict = Depends(require_role(["admin", "reseller"]))):
    """Get users based on role permissions"""
    role = current_user.get("role")
    
    if role == "admin":
        # Admin sees all users
        users = await db.users.find({}, {"_id": 0}).to_list(1000)
    else:
        # Reseller sees only their customers
        users = await db.users.find({"parent_id": current_user['sub']}, {"_id": 0}).to_list(1000)
    
    for user in users:
        if isinstance(user.get('created_at'), str):
            user['created_at'] = datetime.fromisoformat(user['created_at'])
    
    return [UserResponse(**u) for u in users]

@api_router.post("/users", response_model=UserResponse)
async def create_user(data: UserCreate, current_user: dict = Depends(require_role(["admin", "reseller"]))):
    """Create a new user"""
    role = current_user.get("role")
    
    # Validate role creation permissions
    if role == "reseller":
        if data.role != "customer":
            raise HTTPException(status_code=403, detail="Resellers can only create customers")
        
        # Check customer limit
        reseller = await db.users.find_one({"id": current_user['sub']}, {"_id": 0})
        if reseller and reseller.get('max_customers'):
            customer_count = await db.users.count_documents({"parent_id": current_user['sub']})
            if customer_count >= reseller['max_customers']:
                raise HTTPException(status_code=403, detail="Customer limit reached")
        
        # Set parent_id to reseller
        data.parent_id = current_user['sub']
    
    # Check if email exists
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = User(
        email=data.email,
        password_hash=get_password_hash(data.password),
        name=data.name,
        role=data.role,
        parent_id=data.parent_id,
        max_customers=data.max_customers,
        max_targets=data.max_targets,
        monthly_scan_limit=data.monthly_scan_limit
    )
    
    user_dict = user.model_dump()
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    user_dict['updated_at'] = user_dict['updated_at'].isoformat()
    
    await db.users.insert_one(user_dict)
    
    return UserResponse(**user.model_dump())

@api_router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: str, data: UserUpdate, current_user: dict = Depends(require_role(["admin", "reseller"]))):
    """Update a user"""
    role = current_user.get("role")
    
    # Check access
    user_doc = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    
    if role == "reseller" and user_doc.get("parent_id") != current_user['sub']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Update fields
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
    
    await db.users.update_one({"id": user_id}, {"$set": update_data})
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0})
    if isinstance(updated.get('created_at'), str):
        updated['created_at'] = datetime.fromisoformat(updated['created_at'])
    
    return UserResponse(**updated)

@api_router.delete("/users/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(require_role(["admin", "reseller"]))):
    """Delete a user"""
    role = current_user.get("role")
    
    user_doc = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    
    if role == "reseller" and user_doc.get("parent_id") != current_user['sub']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    await db.users.delete_one({"id": user_id})
    return {"message": "User deleted"}

# ============== Target Endpoints ==============
@api_router.get("/targets", response_model=List[TargetResponse])
async def get_targets(current_user: dict = Depends(get_current_user)):
    """Get user's targets"""
    role = current_user.get("role")
    user_id = current_user['sub']
    
    if role == "admin":
        targets = await db.targets.find({}, {"_id": 0}).to_list(1000)
    elif role == "reseller":
        # Get all customer IDs
        customers = await db.users.find({"parent_id": user_id}, {"id": 1, "_id": 0}).to_list(1000)
        customer_ids = [c['id'] for c in customers]
        customer_ids.append(user_id)
        targets = await db.targets.find({"user_id": {"$in": customer_ids}}, {"_id": 0}).to_list(1000)
    else:
        targets = await db.targets.find({"user_id": user_id}, {"_id": 0}).to_list(1000)
    
    for t in targets:
        if isinstance(t.get('created_at'), str):
            t['created_at'] = datetime.fromisoformat(t['created_at'])
    
    return [TargetResponse(**t) for t in targets]

@api_router.post("/targets", response_model=TargetResponse)
async def create_target(data: TargetCreate, current_user: dict = Depends(get_current_user)):
    """Create a new target"""
    user_id = current_user['sub']
    
    # Check target limit
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if user and user.get('max_targets'):
        target_count = await db.targets.count_documents({"user_id": user_id})
        if target_count >= user['max_targets']:
            raise HTTPException(status_code=403, detail="Target limit reached")
    
    target = Target(
        user_id=user_id,
        name=data.name,
        target_type=data.target_type,
        value=data.value,
        description=data.description
    )
    
    target_dict = target.model_dump()
    target_dict['created_at'] = target_dict['created_at'].isoformat()
    target_dict['updated_at'] = target_dict['updated_at'].isoformat()
    
    await db.targets.insert_one(target_dict)
    
    return TargetResponse(**target.model_dump())

@api_router.put("/targets/{target_id}", response_model=TargetResponse)
async def update_target(target_id: str, data: TargetUpdate, current_user: dict = Depends(get_current_user)):
    """Update a target"""
    target = await db.targets.find_one({"id": target_id}, {"_id": 0})
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Check ownership
    if current_user.get("role") != "admin" and target.get("user_id") != current_user['sub']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
    
    await db.targets.update_one({"id": target_id}, {"$set": update_data})
    
    updated = await db.targets.find_one({"id": target_id}, {"_id": 0})
    if isinstance(updated.get('created_at'), str):
        updated['created_at'] = datetime.fromisoformat(updated['created_at'])
    
    return TargetResponse(**updated)

@api_router.delete("/targets/{target_id}")
async def delete_target(target_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a target"""
    target = await db.targets.find_one({"id": target_id}, {"_id": 0})
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    if current_user.get("role") != "admin" and target.get("user_id") != current_user['sub']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    await db.targets.delete_one({"id": target_id})
    return {"message": "Target deleted"}

# ============== Scan Endpoints ==============
@api_router.get("/scans", response_model=List[ScanResponse])
async def get_scans(current_user: dict = Depends(get_current_user)):
    """Get user's scans"""
    role = current_user.get("role")
    user_id = current_user['sub']
    
    if role == "admin":
        scans = await db.scans.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    elif role == "reseller":
        customers = await db.users.find({"parent_id": user_id}, {"id": 1, "_id": 0}).to_list(1000)
        customer_ids = [c['id'] for c in customers]
        customer_ids.append(user_id)
        scans = await db.scans.find({"user_id": {"$in": customer_ids}}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    else:
        scans = await db.scans.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    for s in scans:
        for field in ['created_at', 'started_at', 'completed_at']:
            if isinstance(s.get(field), str):
                s[field] = datetime.fromisoformat(s[field])
    
    return [ScanResponse(**s) for s in scans]

@api_router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Get a specific scan"""
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    for field in ['created_at', 'started_at', 'completed_at']:
        if isinstance(scan.get(field), str):
            scan[field] = datetime.fromisoformat(scan[field])
    
    return ScanResponse(**scan)

@api_router.post("/scans", response_model=ScanResponse)
async def create_scan(
    data: ScanCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create and start a new scan via agent"""
    user_id = current_user['sub']
    
    # Verify agent exists and belongs to user
    agent = await db.agents.find_one({"id": data.agent_id, "is_active": True}, {"_id": 0})
    if not agent:
        raise HTTPException(status_code=400, detail="Invalid agent ID")
    
    # Check agent ownership
    if current_user["role"] == "customer" and agent["customer_id"] != user_id:
        raise HTTPException(status_code=403, detail="Agent does not belong to you")
    
    # Check if agent is online
    gateway = get_agent_gateway(db)
    if not gateway.is_agent_online(data.agent_id):
        raise HTTPException(status_code=400, detail="Agent is offline. Please ensure the agent is running.")
    
    # Check scan limit
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if user and user.get('monthly_scan_limit'):
        if user.get('scans_used_this_month', 0) >= user['monthly_scan_limit']:
            raise HTTPException(status_code=403, detail="Monthly scan limit reached")
    
    # Verify targets belong to user
    targets = await db.targets.find({"id": {"$in": data.target_ids}}, {"_id": 0}).to_list(100)
    if len(targets) != len(data.target_ids):
        raise HTTPException(status_code=400, detail="Invalid target IDs")
    
    scan = Scan(
        user_id=user_id,
        name=data.name,
        target_ids=data.target_ids,
        agent_id=data.agent_id,
        config=data.config or ScanConfig()
    )
    
    scan_dict = scan.model_dump()
    scan_dict['created_at'] = scan_dict['created_at'].isoformat()
    
    await db.scans.insert_one(scan_dict)
    
    # Increment scan counter
    await db.users.update_one(
        {"id": user_id},
        {"$inc": {"scans_used_this_month": 1}}
    )
    
    # Update scan status to running
    await db.scans.update_one(
        {"id": scan.id},
        {"$set": {"status": "running", "started_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    # Create task for agent
    config = scan.config.model_dump()
    target_values = [t["value"] for t in targets]
    
    task = await gateway.create_task(
        agent_id=data.agent_id,
        task_type="port_scan",
        command="nmap_scan",  # Agent will interpret this
        parameters={
            "targets": target_values,
            "target_details": targets,
            "scan_type": config.get("scan_type", "quick"),
            "port_range": config.get("port_range", "1-1000"),
            "check_ssl": config.get("check_ssl", True),
            "check_cve": config.get("check_cve", True),
        },
        scan_id=scan.id
    )
    
    logger.info(f"Scan {scan.id} started via agent {data.agent_id}, task: {task['id']}")
    
    return ScanResponse(**scan.model_dump())

async def run_scan_wrapper(scan_id: str, targets: List[dict], config: dict):
    """Wrapper to run scan without blocking the event loop"""
    import concurrent.futures
    
    loop = asyncio.get_event_loop()
    
    # Update status to running immediately
    await db.scans.update_one(
        {"id": scan_id},
        {"$set": {"status": "running", "started_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    # Run the blocking scan in a thread pool executor
    with concurrent.futures.ThreadPoolExecutor() as executor:
        await loop.run_in_executor(
            executor,
            run_scan_sync,
            scan_id,
            targets,
            config
        )

def run_scan_sync(scan_id: str, targets: List[dict], config: dict):
    """Synchronous scan runner for thread pool execution"""
    import asyncio
    
    # Create new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(_run_scan_async(scan_id, targets, config))
    finally:
        loop.close()

async def send_scan_complete_email(thread_db, scan_id: str, severity_counts: dict, total_vulns: int):
    """
    Send email notification when scan completes.
    Uses the correct SMTP config based on user hierarchy:
    - Customer -> Reseller's SMTP
    - Admin's customer -> Admin's SMTP
    - Admin scan -> Admin's SMTP
    """
    try:
        # Get scan and user info
        scan = await thread_db.scans.find_one({"id": scan_id}, {"_id": 0})
        if not scan:
            return
        
        user = await thread_db.users.find_one({"id": scan.get("owner_id")}, {"_id": 0})
        if not user:
            return
        
        # Determine which SMTP config to use
        smtp_config = None
        
        if user.get("role") == "admin":
            # Admin scan - use admin's SMTP
            smtp_config = await thread_db.smtp_configs.find_one({"reseller_id": "admin", "is_active": True}, {"_id": 0})
        elif user.get("role") == "customer":
            # Customer - find parent (reseller or admin)
            parent_id = user.get("parent_id")
            if parent_id:
                # Check if parent is reseller with SMTP config
                smtp_config = await thread_db.smtp_configs.find_one({"reseller_id": parent_id, "is_active": True}, {"_id": 0})
            
            # Fallback to admin SMTP if no reseller SMTP
            if not smtp_config:
                smtp_config = await thread_db.smtp_configs.find_one({"reseller_id": "admin", "is_active": True}, {"_id": 0})
        elif user.get("role") == "reseller":
            # Reseller scan - use reseller's own SMTP
            smtp_config = await thread_db.smtp_configs.find_one({"reseller_id": user.get("id"), "is_active": True}, {"_id": 0})
            
            # Fallback to admin SMTP
            if not smtp_config:
                smtp_config = await thread_db.smtp_configs.find_one({"reseller_id": "admin", "is_active": True}, {"_id": 0})
        
        if not smtp_config:
            logger.warning(f"No SMTP config found for user {user.get('email')}, skipping email notification")
            return
        
        # Generate email content
        report_link = f"{os.environ.get('FRONTEND_URL', '')}/scans/{scan_id}"
        email_html = get_scan_complete_email(
            scan_name=scan.get("name", "Scan"),
            total_vulns=total_vulns,
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
            info=severity_counts.get("info", 0),
            report_link=report_link,
            lang=user.get("language", "en")
        )
        
        # Send email
        success = await send_email(
            smtp_config=smtp_config,
            to_email=user.get("email"),
            subject=f"Scan Complete: {scan.get('name')}",
            body_html=email_html
        )
        
        if success:
            logger.info(f"Scan complete email sent to {user.get('email')}")
        else:
            logger.error(f"Failed to send scan complete email to {user.get('email')}")
            
    except Exception as e:
        logger.error(f"Error sending scan complete email: {str(e)}")

async def _run_scan_async(scan_id: str, targets: List[dict], config: dict):
    """Actual scan logic running in separate thread"""
    # Create new MongoDB connection for this thread
    thread_client = AsyncIOMotorClient(mongo_url)
    thread_db = thread_client[os.environ['DB_NAME']]
    
    try:
        scanner = VulnerabilityScanner(nvd_api_key=NVD_API_KEY, db=thread_db)
        total_targets = len(targets)
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_vulns = 0
        
        for idx, target in enumerate(targets):
            # Scan target
            results = await scanner.scan_target(
                target.get("value"),
                target.get("target_type"),
                config
            )
            
            # Get target exposure level (default to internet for external scans)
            exposure = config.get("exposure_level", "internet")
            data_sensitivity = config.get("data_sensitivity", "normal")
            iteration = config.get("iteration", 1)
            
            # Save vulnerabilities with Real Risk Score
            for vuln_data in results.get("vulnerabilities", []):
                # Fetch CVE references from DB if cve_id exists and no references provided
                cve_id = vuln_data.get("cve_id")
                references = vuln_data.get("references", [])
                
                if cve_id and not references:
                    cve_doc = await thread_db.cves.find_one({"cve_id": cve_id}, {"_id": 0, "references": 1})
                    if cve_doc and cve_doc.get("references"):
                        # Filter to only http/https references
                        all_refs = cve_doc.get("references", [])
                        http_refs = []
                        for r in all_refs:
                            # Handle both object format {url: "..."} and string format
                            url = r.get("url") if isinstance(r, dict) else r if isinstance(r, str) else None
                            if url and (url.startswith("http://") or url.startswith("https://")):
                                http_refs.append(url)
                        references = http_refs[:3]  # Limit to 3 references
                
                # Calculate Real Risk Score
                risk_data = RiskCalculator.calculate_for_vulnerability(
                    vuln_data,
                    exposure=exposure,
                    data_sensitivity=data_sensitivity
                )
                
                vuln = Vulnerability(
                    scan_id=scan_id,
                    iteration=iteration,
                    target_id=target.get("id"),
                    target_value=target.get("value"),
                    severity=risk_data.get("risk_level", vuln_data.get("severity", "info")),
                    title=vuln_data.get("title", "Unknown"),
                    description=vuln_data.get("description", ""),
                    port=vuln_data.get("port"),
                    protocol=vuln_data.get("protocol"),
                    service=vuln_data.get("service"),
                    cve_id=cve_id,
                    cvss_score=vuln_data.get("cvss_score"),
                    solution=vuln_data.get("solution"),
                    references=references
                )
                
                vuln_dict = vuln.model_dump()
                vuln_dict['created_at'] = vuln_dict['created_at'].isoformat()
                
                # Add Real Risk data
                vuln_dict['real_risk_score'] = risk_data.get("real_risk_score", 0)
                vuln_dict['risk_level'] = risk_data.get("risk_level", "info")
                vuln_dict['recommendation_priority'] = risk_data.get("recommendation_priority", 5)
                vuln_dict['is_kev'] = risk_data.get("is_kev", False)
                vuln_dict['is_verified'] = risk_data.get("is_verified", False)
                vuln_dict['risk_factors'] = risk_data.get("factors_breakdown", {})
                vuln_dict['source'] = vuln_data.get("source", "scan")
                
                await thread_db.vulnerabilities.insert_one(vuln_dict)
                
                # Count by risk_level instead of original severity
                risk_level = risk_data.get("risk_level", "info").lower()
                if risk_level in severity_counts:
                    severity_counts[risk_level] += 1
                total_vulns += 1
            
            # Update progress
            progress = int((idx + 1) / total_targets * 100)
            
            # Save discovered ports for this target
            discovered_ports = results.get("ports", [])
            if discovered_ports:
                port_record = {
                    "scan_id": scan_id,
                    "iteration": iteration,
                    "target_id": target.get("id"),
                    "target_value": target.get("value"),
                    "ports": discovered_ports,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                await thread_db.scan_ports.insert_one(port_record)
            
            await thread_db.scans.update_one(
                {"id": scan_id},
                {"$set": {"progress": progress}}
            )
        
        # Calculate scan risk summary
        all_vulns = await thread_db.vulnerabilities.find({"scan_id": scan_id}, {"_id": 0}).to_list(1000)
        risk_summary = RiskCalculator.calculate_scan_summary(all_vulns)
        
        # Update scan as completed with risk summary
        await thread_db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "progress": 100,
                "total_vulnerabilities": total_vulns,
                "highest_risk_score": risk_summary.get("highest_risk_score", 0),
                "average_risk_score": risk_summary.get("average_risk_score", 0),
                "overall_risk_level": risk_summary.get("overall_risk_level", "info"),
                "kev_count": risk_summary.get("kev_count", 0),
                "verified_count": risk_summary.get("verified_count", 0),
                "priority_1_count": risk_summary.get("priority_1_count", 0),
                **{f"{k}_count": v for k, v in severity_counts.items()}
            }}
        )
        
        logger.info(f"Scan {scan_id} completed with {total_vulns} vulnerabilities, highest risk: {risk_summary.get('highest_risk_score')}")
        
        # Send email notification
        try:
            await send_scan_complete_email(thread_db, scan_id, severity_counts, total_vulns)
        except Exception as email_error:
            logger.error(f"Failed to send scan complete email: {email_error}")
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Scan {scan_id} failed: {error_msg}")
        await thread_db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "failed", 
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "failure_reason": error_msg
            }}
        )
    finally:
        thread_client.close()

@api_router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Cancel a running scan"""
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.get("status") != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")
    
    await db.scans.update_one(
        {"id": scan_id},
        {"$set": {"status": "cancelled", "completed_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    return {"message": "Scan cancelled"}

@api_router.post("/scans/{scan_id}/rescan")
async def rescan(scan_id: str, current_user: dict = Depends(get_current_user)):
    """
    Rescan - creates a new iteration under the same scan.
    Saves current results to history and starts a fresh scan via agent.
    """
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if current_user.get("role") != "admin" and scan.get("user_id") != current_user['sub']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if scan.get("status") == "running":
        raise HTTPException(status_code=400, detail="Scan is already running")
    
    # Check if scan has an agent assigned
    agent_id = scan.get("agent_id")
    if not agent_id:
        raise HTTPException(status_code=400, detail="Bu tarama bir agent'a atanmamış. Lütfen yeni bir tarama oluşturun.")
    
    # Check if agent is online
    gateway = get_agent_gateway(db)
    if not gateway.is_agent_online(agent_id):
        raise HTTPException(status_code=400, detail="Agent çevrimdışı. Lütfen agent'ın çalıştığından emin olun.")
    
    # Get current iteration
    current_iteration = scan.get("current_iteration", 1)
    
    # Save current results to history (if completed)
    if scan.get("status") == "completed":
        history_entry = {
            "iteration": current_iteration,
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
            "total_vulnerabilities": scan.get("total_vulnerabilities", 0),
            "critical_count": scan.get("critical_count", 0),
            "high_count": scan.get("high_count", 0),
            "medium_count": scan.get("medium_count", 0),
            "low_count": scan.get("low_count", 0),
            "info_count": scan.get("info_count", 0),
            "highest_risk_score": scan.get("highest_risk_score", 0),
            "overall_risk_level": scan.get("overall_risk_level", "info"),
        }
        
        # Get existing history
        history = scan.get("iteration_history", [])
        history.append(history_entry)
        
        # Update scan for new iteration
        new_iteration = current_iteration + 1
        
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "current_iteration": new_iteration,
                "iteration_history": history,
                "status": "running",
                "progress": 0,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": None,
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "highest_risk_score": 0,
                "average_risk_score": 0,
                "overall_risk_level": "info",
                "kev_count": 0,
                "verified_count": 0,
                "priority_1_count": 0,
            }}
        )
    else:
        new_iteration = current_iteration
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "running",
                "progress": 0,
                "started_at": datetime.now(timezone.utc).isoformat()
            }}
        )
    
    # Get targets for this scan
    target_ids = scan.get("target_ids", [])
    targets = await db.targets.find({"id": {"$in": target_ids}}, {"_id": 0}).to_list(100)
    
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets found")
    
    # Get config
    config = scan.get("config", {})
    if isinstance(config, dict):
        config_dict = config
    else:
        config_dict = config.model_dump() if hasattr(config, 'model_dump') else dict(config)
    
    # Create task for agent
    target_values = [t["value"] for t in targets]
    
    task = await gateway.create_task(
        agent_id=agent_id,
        task_type="port_scan",
        command="nmap_scan",
        parameters={
            "targets": target_values,
            "target_details": targets,
            "scan_type": config_dict.get("scan_type", "quick"),
            "port_range": config_dict.get("port_range", "1-1000"),
            "check_ssl": config_dict.get("check_ssl", True),
            "check_cve": config_dict.get("check_cve", True),
            "iteration": new_iteration,
        },
        scan_id=scan_id
    )
    
    logger.info(f"Rescan {scan_id} (iteration {new_iteration}) started via agent {agent_id}, task: {task['id']}")
    
    # Return updated scan
    updated_scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    return ScanResponse(**updated_scan)

@api_router.get("/scans/{scan_id}/history")
async def get_scan_history(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Get scan iteration history"""
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "current_iteration": scan.get("current_iteration", 1),
        "history": scan.get("iteration_history", [])
    }

@api_router.get("/scans/{scan_id}/vulnerabilities/{iteration}")
async def get_vulnerabilities_by_iteration(
    scan_id: str,
    iteration: int,
    current_user: dict = Depends(get_current_user)
):
    """Get vulnerabilities for a specific iteration"""
    vulns = await db.vulnerabilities.find(
        {"scan_id": scan_id, "iteration": iteration},
        {"_id": 0}
    ).to_list(10000)
    
    for v in vulns:
        if 'created_at' in v and hasattr(v['created_at'], 'isoformat'):
            v['created_at'] = v['created_at'].isoformat()
    
    return vulns

@api_router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a scan and its vulnerabilities"""
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if current_user.get("role") != "admin" and scan.get("user_id") != current_user['sub']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Delete vulnerabilities
    await db.vulnerabilities.delete_many({"scan_id": scan_id})
    # Delete scan
    await db.scans.delete_one({"id": scan_id})
    
    return {"message": "Scan deleted"}

# ============== Vulnerability Endpoints ==============
@api_router.get("/scans/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def get_vulnerabilities(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Get vulnerabilities for a scan"""
    vulns = await db.vulnerabilities.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)
    
    for v in vulns:
        if isinstance(v.get('created_at'), str):
            v['created_at'] = datetime.fromisoformat(v['created_at'])
    
    return [VulnerabilityResponse(**v) for v in vulns]

# ============== Report Endpoints ==============
@api_router.get("/scans/{scan_id}/report")
async def generate_report_get(
    scan_id: str,
    format: str = Query("pdf", enum=["pdf", "html"]),
    iteration: Optional[int] = Query(None, description="Specific iteration number, or latest if not provided"),
    theme: str = Query("dark", enum=["dark", "light"]),
    token: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    """Generate report for a scan (GET method) - on-demand generation"""
    return await _generate_report(scan_id, format, iteration, theme, current_user)

@api_router.get("/scans/{scan_id}/report/download")
async def download_report_direct(
    scan_id: str,
    format: str = Query("pdf", enum=["pdf", "html"]),
    iteration: Optional[int] = Query(None),
    theme: str = Query("dark", enum=["dark", "light"]),
    token: str = Query(...)
):
    """Download report with token in query param (for window.open) - on-demand generation"""
    from auth import decode_token
    
    try:
        current_user = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return await _generate_report(scan_id, format, iteration, theme, current_user)

@api_router.post("/scans/{scan_id}/report")
async def generate_report_post(
    scan_id: str,
    format: str = Query("pdf", enum=["pdf", "html"]),
    iteration: Optional[int] = Query(None),
    theme: str = Query("dark", enum=["dark", "light"]),
    current_user: dict = Depends(get_current_user)
):
    """Generate report for a scan (POST method) - on-demand generation"""
    return await _generate_report(scan_id, format, iteration, theme, current_user)

async def _generate_report(scan_id: str, format: str, iteration: Optional[int], theme: str, current_user: dict):
    """Generate report on-demand for a specific scan iteration"""
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Determine which iteration to use
    target_iteration = iteration if iteration is not None else scan.get("current_iteration", 1)
    
    # Get targets
    targets = await db.targets.find({"id": {"$in": scan.get("target_ids", [])}}, {"_id": 0}).to_list(100)
    
    # Get vulnerabilities - try with iteration first, fallback to all if none found
    vulns = await db.vulnerabilities.find(
        {"scan_id": scan_id, "iteration": target_iteration},
        {"_id": 0}
    ).to_list(10000)
    
    # Fallback: if no vulns found with iteration filter, get all vulns for scan
    if not vulns:
        vulns = await db.vulnerabilities.find(
            {"scan_id": scan_id},
            {"_id": 0}
        ).to_list(10000)
    
    # Get discovered ports - try with iteration first, fallback to all
    ports_data = await db.scan_ports.find(
        {"scan_id": scan_id, "iteration": target_iteration},
        {"_id": 0}
    ).to_list(100)
    
    if not ports_data:
        ports_data = await db.scan_ports.find(
            {"scan_id": scan_id},
            {"_id": 0}
        ).to_list(100)
    
    # Get branding
    user = await db.users.find_one({"id": current_user['sub']}, {"_id": 0})
    reseller_id = user.get('parent_id') or user.get('id')
    branding = await db.branding.find_one({"reseller_id": reseller_id}, {"_id": 0})
    
    lang = user.get('language', 'en')
    
    # Add iteration info to scan for report
    scan_for_report = dict(scan)
    scan_for_report['report_iteration'] = target_iteration
    
    if format == "html":
        html = generate_html_report(scan_for_report, targets, vulns, branding, lang, theme, ports_data)
        return HTMLResponse(content=html)
    else:
        pdf_bytes = await generate_pdf_report(scan_for_report, targets, vulns, branding, lang, theme, ports_data)
        # Return directly without saving to disk (on-demand generation)
        from fastapi.responses import Response
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report_{scan.get("name", scan_id)}_iter{target_iteration}.pdf"'
            }
        )

# ============== Dashboard Stats ==============
@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Get dashboard statistics"""
    role = current_user.get("role")
    user_id = current_user['sub']
    
    # Build query based on role
    if role == "admin":
        scan_query = {}
        target_query = {}
    elif role == "reseller":
        customers = await db.users.find({"parent_id": user_id}, {"id": 1, "_id": 0}).to_list(1000)
        customer_ids = [c['id'] for c in customers]
        customer_ids.append(user_id)
        scan_query = {"user_id": {"$in": customer_ids}}
        target_query = {"user_id": {"$in": customer_ids}}
    else:
        scan_query = {"user_id": user_id}
        target_query = {"user_id": user_id}
    
    # Get counts
    total_scans = await db.scans.count_documents(scan_query)
    running_scans = await db.scans.count_documents({**scan_query, "status": "running"})
    total_targets = await db.targets.count_documents(target_query)
    
    # Get vulnerability counts from completed scans
    pipeline = [
        {"$match": scan_query},
        {"$group": {
            "_id": None,
            "total": {"$sum": "$total_vulnerabilities"},
            "critical": {"$sum": "$critical_count"},
            "high": {"$sum": "$high_count"},
            "medium": {"$sum": "$medium_count"},
            "low": {"$sum": "$low_count"},
            "info": {"$sum": "$info_count"}
        }}
    ]
    
    vuln_stats = await db.scans.aggregate(pipeline).to_list(1)
    vuln_data = vuln_stats[0] if vuln_stats else {}
    
    # Get recent scans
    recent_scans = await db.scans.find(scan_query, {"_id": 0}).sort("created_at", -1).limit(5).to_list(5)
    for s in recent_scans:
        for field in ['created_at', 'started_at', 'completed_at']:
            if isinstance(s.get(field), str):
                s[field] = datetime.fromisoformat(s[field])
    
    # Vulnerability trend (last 7 days)
    trend = []
    for i in range(7):
        date = datetime.now(timezone.utc) - timedelta(days=i)
        date_str = date.strftime("%Y-%m-%d")
        
        day_pipeline = [
            {"$match": {
                **scan_query,
                "created_at": {"$regex": f"^{date_str}"}
            }},
            {"$group": {
                "_id": None,
                "total": {"$sum": "$total_vulnerabilities"}
            }}
        ]
        
        day_stats = await db.scans.aggregate(day_pipeline).to_list(1)
        trend.append({
            "date": date_str,
            "count": day_stats[0]["total"] if day_stats else 0
        })
    
    return DashboardStats(
        total_scans=total_scans,
        running_scans=running_scans,
        total_targets=total_targets,
        total_vulnerabilities=vuln_data.get("total", 0),
        critical_count=vuln_data.get("critical", 0),
        high_count=vuln_data.get("high", 0),
        medium_count=vuln_data.get("medium", 0),
        low_count=vuln_data.get("low", 0),
        info_count=vuln_data.get("info", 0),
        recent_scans=[ScanResponse(**s) for s in recent_scans],
        vulnerability_trend=trend
    )

# ============== Settings Endpoints ==============
@api_router.get("/settings/smtp", response_model=Optional[SMTPConfigResponse])
async def get_smtp_config(current_user: dict = Depends(require_role(["admin", "reseller"]))):
    """Get SMTP configuration"""
    reseller_id = "admin" if current_user.get("role") == "admin" else current_user['sub']
    config = await db.smtp_configs.find_one({"reseller_id": reseller_id}, {"_id": 0, "password": 0})
    
    if not config:
        return None
    
    return SMTPConfigResponse(**config)

@api_router.post("/settings/smtp", response_model=SMTPConfigResponse)
async def save_smtp_config(data: SMTPConfigCreate, current_user: dict = Depends(require_role(["admin", "reseller"]))):
    """Save SMTP configuration"""
    reseller_id = "admin" if current_user.get("role") == "admin" else current_user['sub']
    
    config = SMTPConfig(
        reseller_id=reseller_id,
        host=data.host,
        port=data.port,
        username=data.username,
        password=data.password,
        use_tls=data.use_tls,
        use_ssl=data.use_ssl,
        sender_name=data.sender_name,
        sender_email=data.sender_email
    )
    
    config_dict = config.model_dump()
    config_dict['created_at'] = config_dict['created_at'].isoformat()
    config_dict['updated_at'] = config_dict['updated_at'].isoformat()
    
    await db.smtp_configs.update_one(
        {"reseller_id": reseller_id},
        {"$set": config_dict},
        upsert=True
    )
    
    return SMTPConfigResponse(**{k: v for k, v in config.model_dump().items() if k != "password"})

@api_router.post("/settings/smtp/test")
async def test_smtp_config(
    test_email: str = Query(..., description="Email address to send test email"),
    current_user: dict = Depends(require_role(["admin", "reseller"]))
):
    """Test SMTP configuration by sending a test email"""
    reseller_id = "admin" if current_user.get("role") == "admin" else current_user['sub']
    config = await db.smtp_configs.find_one({"reseller_id": reseller_id}, {"_id": 0})
    
    if not config:
        raise HTTPException(status_code=404, detail="SMTP configuration not found")
    
    # Send test email
    test_html = """
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #3B82F6;">SMTP Test Email</h2>
        <p>This is a test email from your SecureScan vulnerability scanner.</p>
        <p>If you received this email, your SMTP configuration is working correctly.</p>
        <hr>
        <p style="color: #666; font-size: 12px;">This is an automated test message.</p>
    </body>
    </html>
    """
    
    success = await send_email(
        smtp_config=config,
        to_email=test_email,
        subject="SecureScan SMTP Test",
        body_html=test_html
    )
    
    if success:
        return {"success": True, "message": f"Test email sent to {test_email}"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send test email. Check SMTP settings.")

@api_router.get("/settings/branding", response_model=Optional[BrandingSettingsResponse])
async def get_branding(current_user: dict = Depends(get_current_user)):
    """Get branding settings"""
    user = await db.users.find_one({"id": current_user['sub']}, {"_id": 0})
    reseller_id = user.get('parent_id') or user.get('id')
    
    branding = await db.branding.find_one({"reseller_id": reseller_id}, {"_id": 0})
    
    if not branding:
        return None
    
    return BrandingSettingsResponse(**branding)

@api_router.post("/settings/branding", response_model=BrandingSettingsResponse)
async def save_branding(data: BrandingSettingsCreate, current_user: dict = Depends(require_role(["admin", "reseller"]))):
    """Save branding settings"""
    reseller_id = current_user['sub']
    
    branding = BrandingSettings(
        reseller_id=reseller_id,
        company_name=data.company_name,
        logo_url=data.logo_url,
        primary_color=data.primary_color,
        secondary_color=data.secondary_color,
        report_header_text=data.report_header_text,
        report_footer_text=data.report_footer_text
    )
    
    branding_dict = branding.model_dump()
    branding_dict['created_at'] = branding_dict['created_at'].isoformat()
    branding_dict['updated_at'] = branding_dict['updated_at'].isoformat()
    
    await db.branding.update_one(
        {"reseller_id": reseller_id},
        {"$set": branding_dict},
        upsert=True
    )
    
    return BrandingSettingsResponse(**branding.model_dump())

# ============== CVE Database Management ==============
from cve_manager import CVEManager, get_cve_manager

@api_router.get("/cve/stats")
async def get_cve_stats(current_user: dict = Depends(get_current_user)):
    """Get detailed CVE database statistics"""
    cve_mgr = get_cve_manager(db, NVD_API_KEY)
    return await cve_mgr.get_database_stats()

@api_router.get("/cve/sync-status")
async def get_cve_sync_status(current_user: dict = Depends(get_current_user)):
    """Get current sync status"""
    cve_mgr = get_cve_manager(db, NVD_API_KEY)
    return cve_mgr.sync_status

@api_router.post("/cve/sync/full")
async def trigger_full_cve_sync(
    current_user: dict = Depends(require_role(["admin"]))
):
    """Trigger full CVE database sync from NVD (240K+ CVEs)"""
    cve_mgr = get_cve_manager(db, NVD_API_KEY)
    
    if cve_mgr.sync_status["is_running"]:
        raise HTTPException(status_code=400, detail="Sync already in progress")
    
    # Run in background
    asyncio.create_task(cve_mgr.full_nvd_sync())
    
    return {"message": "Full CVE sync started. This may take several hours."}

@api_router.post("/cve/sync/incremental")
async def trigger_incremental_sync(
    days_back: int = Query(7, ge=1, le=90),
    current_user: dict = Depends(require_role(["admin"]))
):
    """Trigger incremental CVE sync (recent changes only)"""
    cve_mgr = get_cve_manager(db, NVD_API_KEY)
    
    if cve_mgr.sync_status["is_running"]:
        raise HTTPException(status_code=400, detail="Sync already in progress")
    
    asyncio.create_task(cve_mgr.incremental_sync(days_back))
    
    return {"message": f"Incremental CVE sync started for last {days_back} days."}

@api_router.post("/cve/sync/kev")
async def trigger_kev_sync(
    current_user: dict = Depends(require_role(["admin"]))
):
    """Sync CISA Known Exploited Vulnerabilities catalog"""
    cve_mgr = get_cve_manager(db, NVD_API_KEY)
    result = await cve_mgr.sync_cisa_kev()
    return result

@api_router.get("/cve/search")
async def search_cves(
    q: Optional[str] = Query(None, description="Search query (CVE ID or description)"),
    severity: Optional[str] = Query(None, enum=["critical", "high", "medium", "low", "info"]),
    is_kev: Optional[bool] = Query(None, description="Filter by CISA KEV status"),
    year: Optional[int] = Query(None, ge=1999, le=2030),
    min_cvss: Optional[float] = Query(None, ge=0, le=10),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    """Search and filter CVE database"""
    cve_mgr = get_cve_manager(db, NVD_API_KEY)
    return await cve_mgr.search_cves(
        query=q,
        severity=severity,
        is_kev=is_kev,
        year=year,
        min_cvss=min_cvss,
        skip=skip,
        limit=limit
    )

@api_router.get("/cve/{cve_id}")
async def get_cve_detail(
    cve_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed CVE information"""
    cve = await db.cves.find_one({"cve_id": cve_id.upper()}, {"_id": 0})
    
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    
    # Get KEV details if applicable
    if cve.get("is_kev"):
        cve_mgr = get_cve_manager(db, NVD_API_KEY)
        kev_details = await cve_mgr.get_kev_details(cve_id.upper())
        cve["kev_details"] = kev_details
    
    return cve

@api_router.get("/kev/list")
async def get_kev_list(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    """Get list of Known Exploited Vulnerabilities"""
    total = await db.kev_catalog.count_documents({})
    results = await db.kev_catalog.find({}, {"_id": 0}).skip(skip).limit(limit).to_list(limit)
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "results": results
    }

# Legacy endpoint - keeping for backward compatibility
@api_router.post("/cve/sync")
async def trigger_cve_sync_legacy(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_role(["admin"]))
):
    """Legacy: Trigger incremental CVE sync"""
    cve_mgr = get_cve_manager(db, NVD_API_KEY)
    asyncio.create_task(cve_mgr.incremental_sync(30))
    return {"message": "CVE sync started"}

@api_router.get("/cve/status")
async def get_cve_status(current_user: dict = Depends(get_current_user)):
    """Get CVE database status"""
    cve_mgr = get_cve_manager(db, NVD_API_KEY)
    stats = await cve_mgr.get_database_stats()
    return {
        "total_cves": stats["total_cves"],
        "kev_count": stats["kev_count"],
        "last_sync": stats["last_sync"]["completed_at"] if stats["last_sync"] else None,
        "is_syncing": stats["is_syncing"]
    }

# ============== Agent Endpoints ==============
@api_router.get("/agents", response_model=List[AgentResponse])
async def list_agents(current_user: dict = Depends(get_current_user)):
    """List agents for current user (customers see their agents, admins see all)"""
    query = {}
    if current_user["role"] == "customer":
        query["customer_id"] = current_user["sub"]
    elif current_user["role"] == "reseller":
        # Resellers see their own agents and their customers' agents
        customer_ids = await db.users.distinct("id", {"parent_id": current_user["sub"]})
        query["customer_id"] = {"$in": [current_user["sub"]] + customer_ids}
    
    agents = await db.agents.find(query, {"_id": 0, "token": 0}).to_list(100)
    
    # Check real-time connection status
    gateway = get_agent_gateway(db)
    for agent in agents:
        if gateway.is_agent_online(agent["id"]):
            agent["status"] = "online"
    
    return agents


@api_router.post("/agents", response_model=AgentWithToken)
async def create_agent(
    agent_data: AgentCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new agent for the customer"""
    # Only customers and admins can create agents
    if current_user["role"] == "reseller":
        raise HTTPException(status_code=403, detail="Resellers cannot create agents directly")
    
    # Generate secure token
    plain_token = generate_agent_token()
    hashed_token = hash_token(plain_token)
    
    agent = Agent(
        customer_id=current_user["sub"],
        name=agent_data.name,
        token=hashed_token
    )
    
    agent_dict = agent.model_dump()
    agent_dict["created_at"] = agent_dict["created_at"].isoformat()
    agent_dict["updated_at"] = agent_dict["updated_at"].isoformat()
    
    await db.agents.insert_one(agent_dict)
    logger.info(f"Agent created: {agent.name} for user {current_user['sub']}")
    
    # Generate install command
    base_url = os.environ.get("FRONTEND_URL", "https://your-panel.com")
    install_command = f'curl -sSL {base_url}/api/agent/install.sh | sudo bash -s {plain_token}'
    
    return AgentWithToken(
        id=agent.id,
        customer_id=agent.customer_id,
        name=agent.name,
        token=plain_token,  # Return plain token only once
        status=agent.status,
        is_active=agent.is_active,
        created_at=agent.created_at,
        install_command=install_command
    )


@api_router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str, current_user: dict = Depends(get_current_user)):
    """Get agent details"""
    agent = await db.agents.find_one({"id": agent_id}, {"_id": 0, "token": 0})
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check permission
    if current_user["role"] == "customer" and agent["customer_id"] != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check real-time status
    gateway = get_agent_gateway(db)
    if gateway.is_agent_online(agent_id):
        agent["status"] = "online"
    
    return agent


@api_router.put("/agents/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    update_data: AgentUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update agent settings"""
    agent = await db.agents.find_one({"id": agent_id}, {"_id": 0})
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check permission
    if current_user["role"] == "customer" and agent["customer_id"] != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
    update_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.agents.update_one({"id": agent_id}, {"$set": update_dict})
    
    updated_agent = await db.agents.find_one({"id": agent_id}, {"_id": 0, "token": 0})
    return updated_agent


@api_router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str, current_user: dict = Depends(get_current_user)):
    """Delete an agent"""
    agent = await db.agents.find_one({"id": agent_id}, {"_id": 0})
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check permission
    if current_user["role"] == "customer" and agent["customer_id"] != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    await db.agents.delete_one({"id": agent_id})
    await db.agent_tasks.delete_many({"agent_id": agent_id})
    
    logger.info(f"Agent deleted: {agent_id}")
    return {"message": "Agent deleted"}


@api_router.post("/agents/{agent_id}/regenerate-token", response_model=AgentWithToken)
async def regenerate_agent_token(agent_id: str, current_user: dict = Depends(get_current_user)):
    """Regenerate agent token (invalidates old token)"""
    agent = await db.agents.find_one({"id": agent_id}, {"_id": 0})
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check permission
    if current_user["role"] == "customer" and agent["customer_id"] != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Generate new token
    plain_token = generate_agent_token()
    hashed_token = hash_token(plain_token)
    
    await db.agents.update_one(
        {"id": agent_id},
        {"$set": {
            "token": hashed_token,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    base_url = os.environ.get("FRONTEND_URL", "https://your-panel.com")
    install_command = f'curl -sSL {base_url}/api/agent/install.sh | sudo bash -s {plain_token}'
    
    return AgentWithToken(
        id=agent["id"],
        customer_id=agent["customer_id"],
        name=agent["name"],
        token=plain_token,
        status=agent.get("status", "offline"),
        is_active=agent.get("is_active", True),
        created_at=agent["created_at"],
        install_command=install_command
    )


@api_router.get("/agents/{agent_id}/tasks", response_model=List[AgentTaskResponse])
async def list_agent_tasks(
    agent_id: str,
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    """Get task history for an agent"""
    agent = await db.agents.find_one({"id": agent_id}, {"_id": 0})
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check permission
    if current_user["role"] == "customer" and agent["customer_id"] != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    tasks = await db.agent_tasks.find(
        {"agent_id": agent_id},
        {"_id": 0}
    ).sort("created_at", -1).limit(limit).to_list(limit)
    
    return tasks


@api_router.post("/agents/{agent_id}/send-command")
async def send_agent_command(
    agent_id: str,
    command_type: str = Query(..., description="Command type: health_check, install_nmap, install_masscan"),
    current_user: dict = Depends(get_current_user)
):
    """Send a command to an agent"""
    agent = await db.agents.find_one({"id": agent_id}, {"_id": 0})
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check permission
    if current_user["role"] == "customer" and agent["customer_id"] != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    gateway = get_agent_gateway(db)
    
    if not gateway.is_agent_online(agent_id):
        raise HTTPException(status_code=400, detail="Agent is offline")
    
    # Create and send task based on command type
    commands = {
        "health_check": ("health_check", "echo 'Agent is healthy'", {}),
        "install_nmap": ("install_tool", "apt-get update && apt-get install -y nmap", {"tool": "nmap"}),
        "install_masscan": ("install_tool", "apt-get update && apt-get install -y masscan", {"tool": "masscan"}),
        "system_info": ("system_info", "uname -a && cat /etc/os-release", {}),
    }
    
    if command_type not in commands:
        raise HTTPException(status_code=400, detail=f"Invalid command type. Valid: {list(commands.keys())}")
    
    task_type, command, params = commands[command_type]
    task = await gateway.create_task(agent_id, task_type, command, params)
    
    return {"message": f"Command '{command_type}' sent to agent", "task_id": task["id"]}


# ============== Agent WebSocket ==============
@app.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket, token: str = Query(...)):
    """WebSocket endpoint for agent connections"""
    gateway = get_agent_gateway(db)
    await gateway.handle_connection(websocket, token)


# ============== Agent Install Script ==============
@api_router.get("/agent/install.sh")
async def get_agent_install_script():
    """Get the agent installation script"""
    base_url = os.environ.get("FRONTEND_URL", "https://your-panel.com")
    
    script = f'''#!/bin/bash
# SecureScan Agent Installer
# Usage: curl -sSL {base_url}/api/agent/install.sh | sudo bash -s YOUR_TOKEN

set -e

AGENT_TOKEN="${{1:-}}"
INSTALL_DIR="/opt/securescan-agent"
CONFIG_FILE="$INSTALL_DIR/config.json"
SERVICE_NAME="securescan-agent"
PANEL_URL="{base_url}"

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

log_info() {{ echo -e "${{GREEN}}[INFO]${{NC}} $1"; }}
log_warn() {{ echo -e "${{YELLOW}}[WARN]${{NC}} $1"; }}
log_error() {{ echo -e "${{RED}}[ERROR]${{NC}} $1"; }}

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo)"
    exit 1
fi

# Check token
if [ -z "$AGENT_TOKEN" ]; then
    log_error "Agent token is required"
    echo "Usage: curl -sSL {base_url}/api/agent/install.sh | sudo bash -s YOUR_TOKEN"
    exit 1
fi

log_info "Starting SecureScan Agent installation..."

# Install dependencies
log_info "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv curl nmap > /dev/null

# Create installation directory
log_info "Creating installation directory..."
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

# Create virtual environment
log_info "Setting up Python environment..."
python3 -m venv venv
source venv/bin/activate
pip install -q websockets aiohttp

# Create agent script
log_info "Installing agent..."
cat > $INSTALL_DIR/agent.py << 'AGENT_SCRIPT'
"""SecureScan Remote Agent"""
import asyncio
import json
import subprocess
import platform
import os
import socket
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SecureScan-Agent")

CONFIG_FILE = Path("/opt/securescan-agent/config.json")

class SecureScanAgent:
    def __init__(self, token: str, panel_url: str):
        self.token = token
        self.panel_url = panel_url.replace("https://", "wss://").replace("http://", "ws://")
        self.ws = None
        self.running = True
    
    def get_system_info(self):
        """Collect system information"""
        try:
            os_info = f"{{platform.system()}} {{platform.release()}}"
            
            # Check installed tools
            tools = []
            for tool in ["nmap", "masscan", "nikto", "sqlmap"]:
                try:
                    subprocess.run(["which", tool], capture_output=True, check=True)
                    tools.append(tool)
                except:
                    pass
            
            # Detect internal networks
            networks = []
            try:
                result = subprocess.run(
                    ["ip", "-4", "route", "show", "scope", "link"],
                    capture_output=True, text=True
                )
                for line in result.stdout.strip().split("\\n"):
                    if line:
                        network = line.split()[0]
                        if network and "/" in network:
                            networks.append(network)
            except:
                pass
            
            return {{
                "os_info": os_info,
                "installed_tools": tools,
                "detected_networks": networks,
                "agent_version": "1.1.0",
                "hostname": socket.gethostname(),
                "ip_address": self.get_public_ip()
            }}
        except Exception as e:
            logger.error(f"Error getting system info: {{e}}")
            return {{}}
    
    def get_public_ip(self):
        """Get the public IP address of this agent"""
        import urllib.request
        
        # Try multiple services to get public IP
        ip_services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
            "https://ipecho.net/plain",
        ]
        
        for service in ip_services:
            try:
                req = urllib.request.Request(service, headers={{"User-Agent": "SecureScan-Agent/1.1.0"}})
                response = urllib.request.urlopen(req, timeout=5)
                ip = response.read().decode('utf-8').strip()
                if ip and len(ip) < 50:  # Basic validation
                    return ip
            except:
                continue
        
        # Fallback to local IP if public IP detection fails
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return socket.gethostbyname(socket.gethostname())
    
    async def execute_task(self, task: dict):
        """Execute a task from the panel"""
        task_id = task.get("task_id")
        task_type = task.get("task_type")
        command = task.get("command")
        params = task.get("parameters", {{}})
        
        logger.info(f"Executing task {{task_id}}: {{task_type}}")
        
        # Notify task started
        await self.send({{"type": "task_started", "task_id": task_id}})
        
        try:
            if task_type == "port_scan":
                result = await self.run_port_scan(command, params, task_id)
            elif task_type == "install_tool":
                result = await self.install_tool(command, params)
            elif task_type == "health_check":
                result = {{"status": "healthy", "message": "Agent is running"}}
            elif task_type == "system_info":
                result = self.get_system_info()
            else:
                result = await self.run_command(command)
            
            # Send task_completed with retry - this is critical
            success = await self.send_with_retry({{
                "type": "task_completed",
                "task_id": task_id,
                "result": result
            }})
            if success:
                logger.info(f"Task {{task_id}} completed and reported")
            else:
                logger.error(f"Task {{task_id}} completed but failed to report to panel")
            
        except Exception as e:
            logger.error(f"Task {{task_id}} failed: {{e}}")
            await self.send_with_retry({{
                "type": "task_failed",
                "task_id": task_id,
                "error": str(e)
            }})
    
    async def run_command(self, command: str):
        """Run a shell command and return output"""
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return {{
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
            "returncode": process.returncode
        }}
    
    async def run_command_with_heartbeat(self, cmd: str, task_id: str, timeout: int = 300):
        """
        Run a long-running command while sending heartbeats to keep WebSocket alive.
        Sends heartbeat every 20 seconds during command execution.
        """
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Create heartbeat task - send every 20 seconds to keep Nginx/proxy happy
        async def send_heartbeats():
            while True:
                await asyncio.sleep(20)
                try:
                    await self.send({{"type": "heartbeat", "task_id": task_id}})
                    logger.info(f"Heartbeat sent for task {{task_id}}")
                except Exception as e:
                    logger.warning(f"Heartbeat failed: {{e}}")
                    break
        
        heartbeat_task = asyncio.create_task(send_heartbeats())
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            raise asyncio.TimeoutError(f"Command timed out after {{timeout}} seconds")
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass
    
    async def run_port_scan(self, command: str, params: dict, task_id: str):
        """Run comprehensive nmap scan with SSL/TLS, NSE scripts, and web checks"""
        # Get targets - can be single target or list
        targets = params.get("targets", [])
        if not targets:
            target = params.get("target", "")
            targets = [target] if target else []
        
        if not targets:
            return {{"error": "No targets specified", "ports": [], "vulnerabilities": []}}
        
        port_range = params.get("port_range", "1-1000")
        scan_type = params.get("scan_type", "quick")
        check_ssl = params.get("check_ssl", True)
        
        all_ports = []
        all_ssl_findings = []
        all_nse_findings = []
        all_web_findings = []
        
        total_targets = len(targets)
        
        for idx, target in enumerate(targets):
            if not target:
                continue
            
            base_progress = int((idx / total_targets) * 80)
            
            # Phase 1: Port Discovery & Service Detection (20% per target)
            await self.send({{"type": "task_progress", "task_id": task_id, "progress": base_progress + 5}})
            
            # Build nmap command with enhanced service detection
            if scan_type == "quick":
                cmd = f"nmap -sV -sC -T4 --top-ports 100 --version-intensity 5 {{target}}"
            elif scan_type == "stealth":
                cmd = f"nmap -sS -sV -T2 -p {{port_range}} --version-intensity 5 {{target}}"
            else:
                cmd = f"nmap -sV -sC -T4 -p {{port_range}} --version-intensity 7 --script=banner {{target}}"
            
            logger.info(f"Phase 1 - Port Scan: {{cmd}}")
            
            try:
                stdout, stderr = await self.run_command_with_heartbeat(cmd, task_id, timeout=600)
                output = stdout
            except asyncio.TimeoutError:
                logger.warning(f"Port scan timeout for {{target}}")
                output = ""
            
            # Parse nmap output
            ports = self.parse_nmap_output(output)
            
            # Add target info to ports
            for port in ports:
                port["target"] = target
            all_ports.extend(ports)
            
            # Get open ports for further scanning
            open_ports = [p["port"] for p in ports if p.get("state") == "open"]
            
            if not open_ports:
                continue
            
            # Phase 2: SSL/TLS Analysis (if enabled and SSL ports found)
            ssl_ports = [p for p in open_ports if p in [443, 8443, 993, 995, 465, 636, 989, 990] or any(
                "ssl" in ports[i].get("service", "").lower() or "https" in ports[i].get("service", "").lower()
                for i, pp in enumerate(ports) if pp["port"] == p
            )]
            
            # Also check common HTTPS ports
            for p in open_ports:
                if p not in ssl_ports and p in [443, 8443, 4443, 9443]:
                    ssl_ports.append(p)
            
            if check_ssl and ssl_ports:
                await self.send({{"type": "task_progress", "task_id": task_id, "progress": base_progress + 15}})
                
                ssl_port_str = ",".join(str(p) for p in ssl_ports[:5])  # Limit to 5 ports
                ssl_cmd = f"nmap -sV -p {{ssl_port_str}} --script=ssl-enum-ciphers,ssl-cert,ssl-date,ssl-known-key,ssl-dh-params {{target}}"
                
                logger.info(f"Phase 2 - SSL Scan: {{ssl_cmd}}")
                
                try:
                    ssl_stdout, ssl_stderr = await self.run_command_with_heartbeat(ssl_cmd, task_id, timeout=120)
                    ssl_output = ssl_stdout
                except asyncio.TimeoutError:
                    logger.warning(f"SSL scan timeout for {{target}}")
                    ssl_output = ""
                
                # Parse SSL findings
                ssl_findings = self.parse_ssl_findings(ssl_output, target)
                all_ssl_findings.extend(ssl_findings)
            
            # Phase 3: NSE Vulnerability Scripts (limited set for speed)
            await self.send({{"type": "task_progress", "task_id": task_id, "progress": base_progress + 25}})
            
            # Run vulnerability scripts on open ports - use faster script set
            # Avoid --script=vuln which runs too many slow scripts
            port_str = ",".join(str(p) for p in open_ports[:15])  # Limit to 15 ports
            nse_cmd = f"nmap -sV -p {{port_str}} --script=banner,http-title,ssh-hostkey,ssl-cert,ftp-anon,smb-vuln-ms17-010 -T4 {{target}}"
            
            logger.info(f"Phase 3 - NSE Scan: {{nse_cmd}}")
            
            try:
                nse_stdout, nse_stderr = await self.run_command_with_heartbeat(nse_cmd, task_id, timeout=120)
                nse_output = nse_stdout
                
                # Parse NSE findings
                nse_findings = self.parse_nse_findings(nse_output, target)
                all_nse_findings.extend(nse_findings)
            except asyncio.TimeoutError:
                logger.warning(f"NSE scan timeout for {{target}}")
            
            # Phase 4: Active Web Checks (for HTTP/HTTPS ports)
            await self.send({{"type": "task_progress", "task_id": task_id, "progress": base_progress + 35}})
            
            web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]]
            
            if web_ports:
                web_findings = await self.run_web_checks(target, web_ports, task_id)
                all_web_findings.extend(web_findings)
        
        # Final progress
        await self.send({{"type": "task_progress", "task_id": task_id, "progress": 90}})
        
        # Return comprehensive scan data
        return {{
            "ports": all_ports,
            "targets_scanned": targets,
            "ssl_findings": all_ssl_findings,
            "nse_findings": all_nse_findings,
            "web_findings": all_web_findings
        }}
    
    def parse_ssl_findings(self, output: str, target: str):
        """Parse SSL/TLS scan output for vulnerabilities"""
        findings = []
        current_port = None
        
        lines = output.split("\\n")
        
        for i, line in enumerate(lines):
            # Get port context
            import re
            port_match = re.search(r"(\\d+)/tcp", line)
            if port_match:
                current_port = int(port_match.group(1))
            
            # Check for weak SSL/TLS versions
            if "SSLv2" in line or "SSLv3" in line:
                findings.append({{
                    "target": target,
                    "port": current_port,
                    "type": "ssl",
                    "severity": "critical",
                    "title": "Deprecated SSL Protocol Supported",
                    "description": "Server supports SSLv2/SSLv3 which have known vulnerabilities (POODLE, DROWN).",
                    "evidence": line.strip()
                }})
            
            if "TLSv1.0" in line:
                findings.append({{
                    "target": target,
                    "port": current_port,
                    "type": "ssl",
                    "severity": "high",
                    "title": "TLS 1.0 Supported",
                    "description": "TLS 1.0 is deprecated and vulnerable to BEAST attack.",
                    "evidence": line.strip()
                }})
            
            if "TLSv1.1" in line:
                findings.append({{
                    "target": target,
                    "port": current_port,
                    "type": "ssl",
                    "severity": "medium",
                    "title": "TLS 1.1 Supported",
                    "description": "TLS 1.1 is deprecated. Use TLS 1.2 or higher.",
                    "evidence": line.strip()
                }})
            
            # Check for weak ciphers
            weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "SEED", "IDEA"]
            for cipher in weak_ciphers:
                if cipher in line.upper():
                    findings.append({{
                        "target": target,
                        "port": current_port,
                        "type": "ssl",
                        "severity": "high" if cipher in ["RC4", "DES", "NULL", "EXPORT"] else "medium",
                        "title": f"Weak Cipher Supported: {{cipher}}",
                        "description": f"Server supports weak cipher suite containing {{cipher}}.",
                        "evidence": line.strip()
                    }})
                    break
            
            # Check for certificate issues
            if "commonName" in line or "subject:" in line.lower():
                if "expired" in line.lower():
                    findings.append({{
                        "target": target,
                        "port": current_port,
                        "type": "ssl",
                        "severity": "high",
                        "title": "Expired SSL Certificate",
                        "description": "SSL certificate has expired.",
                        "evidence": line.strip()
                    }})
            
            if "self-signed" in line.lower() or "selfsigned" in line.lower():
                findings.append({{
                    "target": target,
                    "port": current_port,
                    "type": "ssl",
                    "severity": "medium",
                    "title": "Self-Signed Certificate",
                    "description": "Server uses a self-signed certificate which cannot be trusted.",
                    "evidence": line.strip()
                }})
            
            # Check for CRIME/BREACH
            if "compression" in line.lower() and ("enabled" in line.lower() or "yes" in line.lower()):
                findings.append({{
                    "target": target,
                    "port": current_port,
                    "type": "ssl",
                    "severity": "medium",
                    "title": "TLS Compression Enabled",
                    "description": "TLS compression is enabled, vulnerable to CRIME attack.",
                    "evidence": line.strip()
                }})
            
            # Check for weak DH params
            if "dh" in line.lower() and ("512" in line or "768" in line or "1024" in line):
                findings.append({{
                    "target": target,
                    "port": current_port,
                    "type": "ssl",
                    "severity": "high",
                    "title": "Weak Diffie-Hellman Parameters",
                    "description": "Server uses weak DH parameters (< 2048 bits), vulnerable to Logjam.",
                    "evidence": line.strip()
                }})
        
        return findings
    
    def parse_nse_findings(self, output: str, target: str):
        """
        Parse NSE vulnerability script output with proper filtering.
        - Filters out ERROR/failed script outputs
        - Exploit references are informational only
        - Requires actual VULNERABLE state confirmation
        """
        findings = []
        current_port = None
        
        lines = output.split("\\n")
        
        # Lines to skip - these are NOT vulnerabilities
        SKIP_PATTERNS = [
            "ERROR: Script execution failed",
            "ERROR:",
            "TIMEOUT",
            "timed out",
            "Could not",
            "Unable to",
            "Connection refused",
            "No route to host",
            "failed to",
            "not vulnerable",
            "NOT VULNERABLE",
            "State: NOT VULNERABLE",
        ]
        
        # Patterns that indicate CONFIRMED vulnerability (Nmap says VULNERABLE)
        CONFIRMED_VULN_PATTERNS = [
            "State: VULNERABLE",
            "VULNERABLE:",
            "IS VULNERABLE",
        ]
        
        # Exploit reference patterns (informational only, not severity boost)
        EXPLOIT_REF_PATTERNS = [
            "exploit-db.com",
            "packetstormsecurity",
            "github.com",
            "rapid7",
            "metasploit",
        ]
        
        import re
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Get port context
            port_match = re.search(r"(\\d+)/tcp", line)
            if port_match:
                current_port = int(port_match.group(1))
            
            # Skip error/failed lines - these are NOT vulnerabilities
            should_skip = False
            for skip_pattern in SKIP_PATTERNS:
                if skip_pattern.lower() in line.lower():
                    should_skip = True
                    break
            
            if should_skip:
                i += 1
                continue
            
            # Check for CONFIRMED VULNERABLE state
            is_confirmed = False
            for vuln_pattern in CONFIRMED_VULN_PATTERNS:
                if vuln_pattern in line:
                    is_confirmed = True
                    break
            
            # Extract CVE if present
            cve_match = re.search(r"(CVE-\\d{{4}}-\\d{{4,}})", line, re.IGNORECASE)
            cve_id = cve_match.group(1).upper() if cve_match else None
            
            # Check for specific NSE vulnerability scripts with VULNERABLE state
            if is_confirmed:
                # Look for script name and details
                script_match = re.search(r"\\|\\s*(\\S+-vuln-\\S+):", line) or re.search(r"(smb-vuln-\\S+|http-vuln-\\S+)", line)
                script_name = script_match.group(1) if script_match else "NSE Vulnerability"
                
                # Collect description from following lines
                description_lines = [line.strip()]
                for j in range(1, min(10, len(lines) - i)):
                    next_line = lines[i + j].strip()
                    if next_line.startswith("|") or next_line.startswith("  "):
                        description_lines.append(next_line.lstrip("| "))
                    else:
                        break
                
                description = " ".join(description_lines)[:500]
                
                # Determine severity based on actual vulnerability
                if "remote code execution" in description.lower() or "rce" in description.lower():
                    severity = "critical"
                    confidence = "confirmed"
                elif "ms17-010" in line.lower() or "eternalblue" in line.lower():
                    severity = "critical"
                    confidence = "confirmed"
                elif "ms08-067" in line.lower():
                    severity = "critical"
                    confidence = "confirmed"
                elif cve_id:
                    severity = "high"
                    confidence = "confirmed"
                else:
                    severity = "medium"
                    confidence = "confirmed"
                
                findings.append({{
                    "target": target,
                    "port": current_port,
                    "type": "nse",
                    "confidence": confidence,
                    "severity": severity,
                    "title": f"{{cve_id or script_name}} - CONFIRMED VULNERABLE",
                    "description": description,
                    "cve_id": cve_id,
                    "evidence": line.strip()
                }})
            
            # Check for exploit references - these are INFORMATIONAL only
            elif any(ref in line.lower() for ref in EXPLOIT_REF_PATTERNS):
                # Extract URL
                url_match = re.search(r"(https?://\\S+)", line)
                url = url_match.group(1) if url_match else line.strip()
                
                findings.append({{
                    "target": target,
                    "port": current_port,
                    "type": "nse",
                    "confidence": "informational",
                    "severity": "info",  # NOT high - just reference
                    "title": "Exploit Reference Found",
                    "description": f"Public exploit reference found. Does NOT confirm exploitability.",
                    "evidence": url[:200]
                }})
            
            # Check for FTP anonymous (confirmed by actual check)
            elif "ftp-anon" in line.lower() and "anonymous ftp login allowed" in line.lower():
                findings.append({{
                    "target": target,
                    "port": current_port or 21,
                    "type": "nse",
                    "confidence": "confirmed",
                    "severity": "medium",  # Downgraded from high - anonymous FTP is common
                    "title": "Anonymous FTP Login Allowed",
                    "description": "FTP server allows anonymous login. Check for sensitive files.",
                    "evidence": line.strip()
                }})
            
            i += 1
        
        return findings
    
    async def run_web_checks(self, target: str, ports: list, task_id: str):
        """Quick web vulnerability checks with frequent heartbeats."""
        findings = []
        
        import urllib.request
        import ssl
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        for port in ports[:3]:
            try:
                await self.send({{"type": "heartbeat", "task_id": task_id}})
                logger.info(f"Web check port {{port}}")
            except:
                pass
            
            protocol = "https" if port in [443, 8443, 4443] else "http"
            base_url = f"{{protocol}}://{{target}}:{{port}}"
            
            # Check sensitive files
            for path in ["/.env", "/.git/config"]:
                try:
                    url = f"{{base_url}}{{path}}"
                    req = urllib.request.Request(url, headers={{"User-Agent": "SecureScan/1.0"}})
                    resp = urllib.request.urlopen(req, timeout=3, context=ctx)
                    if resp.getcode() == 200:
                        findings.append({{
                            "target": target, "port": port, "type": "web",
                            "confidence": "confirmed", "severity": "high",
                            "title": f"Sensitive File: {{path}}",
                            "description": "Sensitive file exposed",
                            "evidence": f"{{url}} returned 200"
                        }})
                except:
                    pass
            
            # Check admin panels
            for path in ["/admin", "/phpmyadmin"]:
                try:
                    url = f"{{base_url}}{{path}}"
                    req = urllib.request.Request(url, headers={{"User-Agent": "SecureScan/1.0"}})
                    resp = urllib.request.urlopen(req, timeout=3, context=ctx)
                    if resp.getcode() == 200:
                        findings.append({{
                            "target": target, "port": port, "type": "web",
                            "confidence": "confirmed", "severity": "info",
                            "title": f"Admin Panel: {{path}}",
                            "description": "Admin panel accessible",
                            "evidence": f"{{url}} returned 200"
                        }})
                except:
                    pass
            
            try:
                await self.send({{"type": "heartbeat", "task_id": task_id}})
            except:
                pass
        
        logger.info("Web checks done")
        return findings


    def parse_nmap_output(self, output: str):
        """Parse nmap output to extract port info"""
        import re
        ports = []
        port_pattern = r"(\\d+)/(tcp|udp)\\s+(\\w+)\\s+(\\S+)(?:\\s+(.+))?"
        
        for line in output.split("\\n"):
            match = re.search(port_pattern, line)
            if match:
                ports.append({{
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4),
                    "version": match.group(5) if match.group(5) else ""
                }})
        return ports
    
    def check_port_vulnerabilities(self, ports: list, target: str):
        """Check for known vulnerabilities based on open ports and services"""
        vulnerabilities = []
        
        # Dangerous/risky ports
        dangerous_ports = {{
            21: ("FTP Service Exposed", "high", "FTP transmits credentials and data in clear text. Consider using SFTP instead."),
            22: ("SSH Service Exposed", "info", "SSH service is accessible. Ensure strong authentication and key-based login."),
            23: ("Telnet Service Exposed", "critical", "Telnet transmits all data including passwords in clear text. Disable immediately."),
            25: ("SMTP Service Exposed", "medium", "Mail server exposed. Verify it's not an open relay."),
            53: ("DNS Service Exposed", "low", "DNS service accessible. Check for zone transfer vulnerabilities."),
            80: ("HTTP Service Exposed", "info", "Web server running on HTTP. Consider enforcing HTTPS."),
            110: ("POP3 Service Exposed", "medium", "POP3 transmits credentials in clear text. Use POP3S instead."),
            111: ("RPC Service Exposed", "medium", "RPC portmapper exposed. Can leak service information."),
            135: ("MSRPC Service Exposed", "medium", "Microsoft RPC exposed. Common target for exploits."),
            139: ("NetBIOS Service Exposed", "high", "NetBIOS exposed. Can leak system information and be exploited."),
            143: ("IMAP Service Exposed", "medium", "IMAP transmits credentials in clear text. Use IMAPS instead."),
            443: ("HTTPS Service Exposed", "info", "Web server running on HTTPS."),
            445: ("SMB Service Exposed", "high", "SMB/CIFS exposed. Target of EternalBlue and other critical exploits."),
            512: ("rexec Service Exposed", "critical", "Remote execution service exposed without encryption."),
            513: ("rlogin Service Exposed", "critical", "Remote login service exposed without encryption."),
            514: ("rsh Service Exposed", "critical", "Remote shell service exposed without encryption."),
            1433: ("MSSQL Service Exposed", "high", "Microsoft SQL Server exposed to network."),
            1521: ("Oracle DB Exposed", "high", "Oracle database listener exposed to network."),
            2049: ("NFS Service Exposed", "high", "Network File System exposed. Check export permissions."),
            3306: ("MySQL Service Exposed", "high", "MySQL database exposed to network."),
            3389: ("RDP Service Exposed", "high", "Remote Desktop Protocol exposed. Target of BlueKeep and other exploits."),
            5432: ("PostgreSQL Exposed", "high", "PostgreSQL database exposed to network."),
            5900: ("VNC Service Exposed", "high", "VNC remote desktop exposed. Often has weak authentication."),
            5901: ("VNC Service Exposed", "high", "VNC remote desktop exposed. Often has weak authentication."),
            6379: ("Redis Service Exposed", "critical", "Redis often runs without authentication. Check configuration."),
            8080: ("HTTP Proxy/Alt Exposed", "low", "Alternative HTTP port open. May be proxy or admin interface."),
            8443: ("HTTPS Alt Exposed", "info", "Alternative HTTPS port open."),
            27017: ("MongoDB Exposed", "critical", "MongoDB exposed. Often runs without authentication by default."),
            27018: ("MongoDB Exposed", "critical", "MongoDB exposed. Often runs without authentication by default."),
        }}
        
        # Service-based vulnerabilities (regardless of port)
        risky_services = {{
            "telnet": ("Telnet Service Detected", "critical", "Telnet detected. All traffic is unencrypted."),
            "ftp": ("FTP Service Detected", "high", "FTP detected. Credentials transmitted in clear text."),
            "vnc": ("VNC Service Detected", "high", "VNC detected. Often has weak authentication."),
            "mysql": ("MySQL Service Detected", "medium", "MySQL database accessible from network."),
            "postgresql": ("PostgreSQL Detected", "medium", "PostgreSQL database accessible from network."),
            "mongodb": ("MongoDB Detected", "high", "MongoDB accessible. Verify authentication is enabled."),
            "redis": ("Redis Detected", "high", "Redis accessible. Verify authentication is enabled."),
            "smb": ("SMB Service Detected", "high", "SMB file sharing exposed."),
            "rdp": ("RDP Service Detected", "high", "Remote Desktop exposed to network."),
            "ms-wbt-server": ("RDP Service Detected", "high", "Remote Desktop exposed to network."),
        }}
        
        for port in ports:
            if port["state"] != "open":
                continue
                
            port_num = port["port"]
            service = port.get("service", "").lower()
            version = port.get("version", "")
            
            # Check dangerous ports
            if port_num in dangerous_ports:
                title, severity, desc = dangerous_ports[port_num]
                vulnerabilities.append({{
                    "target_value": target,
                    "severity": severity,
                    "title": title,
                    "description": desc,
                    "port": port_num,
                    "service": service,
                    "evidence": f"Port {{port_num}}/tcp open - {{service}} {{version}}".strip()
                }})
            
            # Check risky services (on non-standard ports)
            elif service in risky_services:
                title, severity, desc = risky_services[service]
                vulnerabilities.append({{
                    "target_value": target,
                    "severity": severity,
                    "title": f"{{title}} (Port {{port_num}})",
                    "description": desc,
                    "port": port_num,
                    "service": service,
                    "evidence": f"Port {{port_num}}/tcp open - {{service}} {{version}}".strip()
                }})
            
            # Check for outdated/vulnerable versions in version string
            if version:
                version_lower = version.lower()
                
                # OpenSSH vulnerabilities
                if "openssh" in version_lower:
                    # Check for old versions
                    import re
                    ssh_ver_match = re.search(r'openssh[_\s]*([\d.]+)', version_lower)
                    if ssh_ver_match:
                        ssh_ver = ssh_ver_match.group(1)
                        try:
                            major_ver = float(ssh_ver.split('.')[0] + '.' + ssh_ver.split('.')[1])
                            if major_ver < 7.0:
                                vulnerabilities.append({{
                                    "target_value": target,
                                    "severity": "high",
                                    "title": "Outdated OpenSSH Version",
                                    "description": f"OpenSSH {{ssh_ver}} is outdated and may have known vulnerabilities.",
                                    "port": port_num,
                                    "service": service,
                                    "evidence": version
                                }})
                        except:
                            pass
                
                # Apache vulnerabilities
                if "apache" in version_lower:
                    import re
                    apache_ver_match = re.search(r'apache[/\s]*([\d.]+)', version_lower)
                    if apache_ver_match:
                        apache_ver = apache_ver_match.group(1)
                        try:
                            parts = apache_ver.split('.')
                            if len(parts) >= 2:
                                major_minor = float(parts[0] + '.' + parts[1])
                                if major_minor < 2.4:
                                    vulnerabilities.append({{
                                        "target_value": target,
                                        "severity": "high",
                                        "title": "Outdated Apache Version",
                                        "description": f"Apache {{apache_ver}} is outdated and may have known vulnerabilities.",
                                        "port": port_num,
                                        "service": service,
                                        "evidence": version
                                    }})
                        except:
                            pass
                
                # nginx vulnerabilities
                if "nginx" in version_lower:
                    import re
                    nginx_ver_match = re.search(r'nginx[/\s]*([\d.]+)', version_lower)
                    if nginx_ver_match:
                        nginx_ver = nginx_ver_match.group(1)
                        try:
                            parts = nginx_ver.split('.')
                            if len(parts) >= 2:
                                major_minor = float(parts[0] + '.' + parts[1])
                                if major_minor < 1.18:
                                    vulnerabilities.append({{
                                        "target_value": target,
                                        "severity": "medium",
                                        "title": "Outdated Nginx Version",
                                        "description": f"Nginx {{nginx_ver}} may have known vulnerabilities. Consider updating.",
                                        "port": port_num,
                                        "service": service,
                                        "evidence": version
                                    }})
                        except:
                            pass
        
        return vulnerabilities
    
    async def install_tool(self, command: str, params: dict):
        """Install a tool and report back"""
        result = await self.run_command(command)
        if result["returncode"] == 0:
            tool_name = params.get("tool", "unknown")
            await self.send({{"type": "tool_installed", "tool": tool_name}})
        return result
    
    def is_ws_open(self):
        """Check if WebSocket connection is open - websockets 15.x compatible"""
        try:
            from websockets.protocol import State
            return self.ws is not None and self.ws.state == State.OPEN
        except:
            # Fallback for older versions
            return self.ws is not None
    
    async def send(self, message: dict):
        """Send message to panel with connection check"""
        try:
            if self.is_ws_open():
                await self.ws.send(json.dumps(message))
                return True
            else:
                logger.warning("WebSocket is not open, cannot send")
                return False
        except Exception as e:
            logger.error(f"Send error: {{e}}")
            return False
    
    async def send_with_retry(self, message: dict, max_retries: int = 3):
        """Send a message with retry logic for critical messages like task_completed"""
        for attempt in range(max_retries):
            try:
                if self.is_ws_open():
                    await self.ws.send(json.dumps(message))
                    return True
                else:
                    logger.warning(f"WebSocket not open, attempt {{attempt + 1}}/{{max_retries}}")
                    # Wait for reconnection
                    await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Send failed (attempt {{attempt + 1}}): {{e}}")
                await asyncio.sleep(2)
        return False
    
    async def connect(self):
        """Connect to the panel WebSocket"""
        import websockets
        
        ws_url = f"{{self.panel_url}}/ws/agent?token={{self.token}}"
        logger.info(f"Connecting to {{ws_url}}")
        
        while self.running:
            try:
                # Lower ping interval to keep connection alive through Nginx
                async with websockets.connect(
                    ws_url,
                    ping_interval=20,  # Send ping every 20 seconds (before Nginx 60s timeout)
                    ping_timeout=30,   # Wait 30 seconds for pong
                    close_timeout=10
                ) as ws:
                    self.ws = ws
                    logger.info("Connected to SecureScan panel")
                    
                    # Send system info on connect
                    sys_info = self.get_system_info()
                    sys_info["type"] = "system_info"
                    await self.send(sys_info)
                    
                    # Message loop
                    async for message in ws:
                        data = json.loads(message)
                        msg_type = data.get("type")
                        
                        if msg_type == "ping":
                            await self.send({{"type": "pong"}})
                        elif msg_type == "execute_task":
                            asyncio.create_task(self.execute_task(data))
                        elif msg_type == "welcome":
                            logger.info(f"Welcome: {{data.get('message')}}")
                            
            except Exception as e:
                logger.error(f"Connection error: {{e}}")
                logger.info("Reconnecting in 10 seconds...")
                await asyncio.sleep(10)

async def main():
    if not CONFIG_FILE.exists():
        logger.error("Config file not found")
        return
    
    with open(CONFIG_FILE) as f:
        config = json.load(f)
    
    agent = SecureScanAgent(config["token"], config["panel_url"])
    await agent.connect()

if __name__ == "__main__":
    asyncio.run(main())
AGENT_SCRIPT

# Create config file
log_info "Creating configuration..."
cat > $CONFIG_FILE << EOF
{{
    "token": "$AGENT_TOKEN",
    "panel_url": "$PANEL_URL"
}}
EOF

chmod 600 $CONFIG_FILE

# Create systemd service
log_info "Creating systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=SecureScan Remote Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
log_info "Starting agent service..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

log_info "======================================"
log_info "SecureScan Agent installed successfully!"
log_info "======================================"
log_info "Installation directory: $INSTALL_DIR"
log_info "Service name: $SERVICE_NAME"
log_info ""
log_info "Useful commands:"
log_info "  Status:  systemctl status $SERVICE_NAME"
log_info "  Logs:    journalctl -u $SERVICE_NAME -f"
log_info "  Restart: systemctl restart $SERVICE_NAME"
log_info "  Stop:    systemctl stop $SERVICE_NAME"
'''
    
    return Response(content=script, media_type="text/plain")


# ============== Translations ==============
@api_router.get("/translations/{lang}")
async def get_translations(lang: str):
    """Get translations for a language"""
    if lang not in TRANSLATIONS:
        lang = "en"
    return TRANSLATIONS[lang]

# ============== Health Check ==============
@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Create default admin user on startup
@app.on_event("startup")
async def create_default_admin():
    """Create default admin user if not exists"""
    admin = await db.users.find_one({"email": "admin@securescan.com"})
    if not admin:
        admin_user = User(
            email="admin@securescan.com",
            password_hash=get_password_hash("admin123"),
            name="System Admin",
            role="admin",
            language="tr"
        )
        admin_dict = admin_user.model_dump()
        admin_dict['created_at'] = admin_dict['created_at'].isoformat()
        admin_dict['updated_at'] = admin_dict['updated_at'].isoformat()
        await db.users.insert_one(admin_dict)
        logger.info("Default admin user created: admin@securescan.com / admin123")
