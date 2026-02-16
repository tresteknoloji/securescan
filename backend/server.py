"""
Vulnerability Scanner API Server
"""
from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, BackgroundTasks, Query
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
    DashboardStats, TRANSLATIONS
)
from auth import (
    verify_password, get_password_hash, create_access_token,
    get_current_user, require_role
)
from scanner import VulnerabilityScanner, sync_cve_database
from report_generator import generate_html_report, generate_pdf_report
from email_service import send_email, get_scan_complete_email
from risk_calculator import RiskCalculator, enrich_vulnerabilities_with_risk

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
    """Create and start a new scan"""
    user_id = current_user['sub']
    
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
    
    # Add iteration to config
    config_dict = scan.config.model_dump()
    config_dict["iteration"] = 1
    
    # Start scan in a separate task (non-blocking)
    asyncio.create_task(run_scan_wrapper(scan.id, targets, config_dict))
    
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
                        http_refs = [r for r in all_refs if isinstance(r, str) and (r.startswith("http://") or r.startswith("https://"))]
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
                "error_message": error_msg
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
    Saves current results to history and starts a fresh scan.
    """
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if current_user.get("role") != "admin" and scan.get("user_id") != current_user['sub']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if scan.get("status") == "running":
        raise HTTPException(status_code=400, detail="Scan is already running")
    
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
                "status": "pending",
                "progress": 0,
                "started_at": None,
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
            {"$set": {"status": "pending", "progress": 0}}
        )
    
    # Get targets for this scan
    target_ids = scan.get("target_ids", [])
    targets = await db.targets.find({"id": {"$in": target_ids}}, {"_id": 0}).to_list(100)
    targets = [{"id": t["id"], "value": t["value"], "target_type": t["target_type"]} for t in targets]
    
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets found")
    
    # Get config with new iteration
    config = scan.get("config", {})
    if isinstance(config, dict):
        config_dict = config
    else:
        config_dict = config.model_dump() if hasattr(config, 'model_dump') else dict(config)
    
    # Add iteration to config for tracking
    config_dict["iteration"] = new_iteration
    
    # Start scan in background
    asyncio.create_task(run_scan_wrapper(scan_id, targets, config_dict))
    
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
    except Exception as e:
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
    
    # Get branding
    user = await db.users.find_one({"id": current_user['sub']}, {"_id": 0})
    reseller_id = user.get('parent_id') or user.get('id')
    branding = await db.branding.find_one({"reseller_id": reseller_id}, {"_id": 0})
    
    lang = user.get('language', 'en')
    
    # Add iteration info to scan for report
    scan_for_report = dict(scan)
    scan_for_report['report_iteration'] = target_iteration
    
    if format == "html":
        html = generate_html_report(scan_for_report, targets, vulns, branding, lang, theme)
        return HTMLResponse(content=html)
    else:
        pdf_bytes = await generate_pdf_report(scan_for_report, targets, vulns, branding, lang, theme)
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
