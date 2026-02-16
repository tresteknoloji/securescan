"""
Database Models for Vulnerability Scanner
"""
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime, timezone
import uuid

# Enums as Literals
RoleType = Literal["admin", "reseller", "customer"]
SeverityType = Literal["info", "low", "medium", "high", "critical"]
ScanStatusType = Literal["pending", "running", "completed", "failed", "cancelled"]
TargetType = Literal["ip", "domain", "prefix"]

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

# ============== User Models ==============
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=generate_uuid)
    email: EmailStr
    password_hash: str
    name: str
    role: RoleType = "customer"
    parent_id: Optional[str] = None  # Reseller ID for customers, None for admin/reseller
    language: str = "tr"
    is_active: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    
    # Limits (for resellers and customers)
    max_customers: Optional[int] = None  # For resellers only
    max_targets: Optional[int] = None
    monthly_scan_limit: Optional[int] = None
    scans_used_this_month: int = 0

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: RoleType = "customer"
    parent_id: Optional[str] = None
    max_customers: Optional[int] = None
    max_targets: Optional[int] = None
    monthly_scan_limit: Optional[int] = None

class UserUpdate(BaseModel):
    name: Optional[str] = None
    language: Optional[str] = None
    is_active: Optional[bool] = None
    max_customers: Optional[int] = None
    max_targets: Optional[int] = None
    monthly_scan_limit: Optional[int] = None

class UserResponse(BaseModel):
    id: str
    email: EmailStr
    name: str
    role: RoleType
    parent_id: Optional[str] = None
    language: str
    is_active: bool
    created_at: datetime
    max_customers: Optional[int] = None
    max_targets: Optional[int] = None
    monthly_scan_limit: Optional[int] = None
    scans_used_this_month: int = 0

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# ============== Target Models ==============
class Target(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=generate_uuid)
    user_id: str
    name: str
    target_type: TargetType
    value: str  # IP address, domain, or prefix
    description: Optional[str] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

class TargetCreate(BaseModel):
    name: str
    target_type: TargetType
    value: str
    description: Optional[str] = None

class TargetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None

class TargetResponse(BaseModel):
    id: str
    user_id: str
    name: str
    target_type: TargetType
    value: str
    description: Optional[str] = None
    is_active: bool
    created_at: datetime

# ============== Scan Models ==============
class ScanConfig(BaseModel):
    port_range: str = "1-65535"  # Default all ports
    scan_type: str = "full"  # full, quick, stealth
    check_ssl: bool = True
    check_cve: bool = True
    pci_compliance: bool = True

class Scan(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=generate_uuid)
    user_id: str
    name: str
    target_ids: List[str]
    config: ScanConfig = Field(default_factory=ScanConfig)
    status: ScanStatusType = "pending"
    progress: int = 0  # 0-100
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utc_now)
    
    # Iteration tracking
    current_iteration: int = 1
    iteration_history: List[dict] = Field(default_factory=list)
    
    # Summary counts (for current iteration)
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

class ScanCreate(BaseModel):
    name: str
    target_ids: List[str]
    config: Optional[ScanConfig] = None

class ScanResponse(BaseModel):
    id: str
    user_id: str
    name: str
    target_ids: List[str]
    config: ScanConfig
    status: ScanStatusType
    progress: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    current_iteration: int = 1
    iteration_history: List[dict] = Field(default_factory=list)
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

# ============== Vulnerability/Finding Models ==============
class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=generate_uuid)
    scan_id: str
    target_id: str
    target_value: str
    severity: SeverityType
    title: str
    description: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    solution: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=utc_now)

class VulnerabilityResponse(BaseModel):
    id: str
    scan_id: str
    target_id: str
    target_value: str
    severity: SeverityType
    title: str
    description: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    solution: Optional[str] = None
    references: List[str] = []
    created_at: datetime

# ============== CVE Models ==============
class CVEEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    cve_id: str
    description: str
    severity: SeverityType
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    references: List[str] = Field(default_factory=list)
    affected_products: List[str] = Field(default_factory=list)
    synced_at: datetime = Field(default_factory=utc_now)

# ============== Report Models ==============
class Report(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=generate_uuid)
    scan_id: str
    user_id: str
    format: Literal["html", "pdf"] = "pdf"
    file_path: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)

class ReportResponse(BaseModel):
    id: str
    scan_id: str
    user_id: str
    format: str
    created_at: datetime

# ============== Settings Models ==============
class SMTPConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=generate_uuid)
    reseller_id: str
    host: str
    port: int = 587
    username: str
    password: str
    use_tls: bool = True
    use_ssl: bool = False
    sender_name: str
    sender_email: EmailStr
    is_active: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

class SMTPConfigCreate(BaseModel):
    host: str
    port: int = 587
    username: str
    password: str
    use_tls: bool = True
    use_ssl: bool = False
    sender_name: str
    sender_email: EmailStr

class SMTPConfigResponse(BaseModel):
    id: str
    reseller_id: str
    host: str
    port: int
    username: str
    use_tls: bool
    use_ssl: bool
    sender_name: str
    sender_email: EmailStr
    is_active: bool

class BrandingSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=generate_uuid)
    reseller_id: str
    company_name: str = "Vulnerability Scanner"
    logo_url: Optional[str] = None
    primary_color: str = "#3B82F6"
    secondary_color: str = "#1E293B"
    report_header_text: Optional[str] = None
    report_footer_text: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

class BrandingSettingsCreate(BaseModel):
    company_name: str
    logo_url: Optional[str] = None
    primary_color: str = "#3B82F6"
    secondary_color: str = "#1E293B"
    report_header_text: Optional[str] = None
    report_footer_text: Optional[str] = None

class BrandingSettingsResponse(BaseModel):
    id: str
    reseller_id: str
    company_name: str
    logo_url: Optional[str] = None
    primary_color: str
    secondary_color: str
    report_header_text: Optional[str] = None
    report_footer_text: Optional[str] = None

# ============== Dashboard Stats ==============
class DashboardStats(BaseModel):
    total_scans: int = 0
    running_scans: int = 0
    total_targets: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    recent_scans: List[ScanResponse] = []
    vulnerability_trend: List[Dict[str, Any]] = []

# ============== Translations ==============
TRANSLATIONS = {
    "tr": {
        "dashboard": "Kontrol Paneli",
        "targets": "Hedefler",
        "scans": "Taramalar",
        "reports": "Raporlar",
        "users": "Kullanıcılar",
        "settings": "Ayarlar",
        "login": "Giriş Yap",
        "logout": "Çıkış Yap",
        "new_scan": "Yeni Tarama",
        "add_target": "Hedef Ekle",
        "critical": "Kritik",
        "high": "Yüksek",
        "medium": "Orta",
        "low": "Düşük",
        "info": "Bilgi",
        "pending": "Bekliyor",
        "running": "Çalışıyor",
        "completed": "Tamamlandı",
        "failed": "Başarısız",
        "cancelled": "İptal Edildi",
        "ip_address": "IP Adresi",
        "domain": "Alan Adı",
        "prefix": "Alt Ağ (Prefix)",
        "vulnerabilities": "Zafiyetler",
        "total": "Toplam",
        "scan_name": "Tarama Adı",
        "target_name": "Hedef Adı",
        "start_scan": "Taramayı Başlat",
        "stop_scan": "Taramayı Durdur",
        "download_report": "Raporu İndir",
        "branding": "Marka Ayarları",
        "smtp_settings": "E-posta Ayarları",
        "profile": "Profil",
        "customers": "Müşteriler",
        "resellers": "Bayiler",
        "monthly_limit": "Aylık Limit",
        "targets_limit": "Hedef Limiti",
        "customers_limit": "Müşteri Limiti",
        "unlimited": "Limitsiz",
        "used": "Kullanılan",
        "remaining": "Kalan",
        "pci_compliance": "PCI Uyumluluk",
        "ssl_check": "SSL Kontrolü",
        "cve_check": "CVE Kontrolü",
        "all_ports": "Tüm Portlar",
        "quick_scan": "Hızlı Tarama",
        "full_scan": "Tam Tarama",
        "stealth_scan": "Gizli Tarama",
        "cve_database": "CVE Veritabanı",
        "solution": "Çözüm",
        "live_results": "Canlı Sonuçlar",
    },
    "en": {
        "dashboard": "Dashboard",
        "targets": "Targets",
        "scans": "Scans",
        "reports": "Reports",
        "users": "Users",
        "settings": "Settings",
        "login": "Login",
        "logout": "Logout",
        "new_scan": "New Scan",
        "add_target": "Add Target",
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "pending": "Pending",
        "running": "Running",
        "completed": "Completed",
        "failed": "Failed",
        "cancelled": "Cancelled",
        "ip_address": "IP Address",
        "domain": "Domain",
        "prefix": "Subnet (Prefix)",
        "vulnerabilities": "Vulnerabilities",
        "total": "Total",
        "scan_name": "Scan Name",
        "target_name": "Target Name",
        "start_scan": "Start Scan",
        "stop_scan": "Stop Scan",
        "download_report": "Download Report",
        "branding": "Branding",
        "smtp_settings": "Email Settings",
        "profile": "Profile",
        "customers": "Customers",
        "resellers": "Resellers",
        "monthly_limit": "Monthly Limit",
        "targets_limit": "Targets Limit",
        "customers_limit": "Customers Limit",
        "unlimited": "Unlimited",
        "used": "Used",
        "remaining": "Remaining",
        "pci_compliance": "PCI Compliance",
        "ssl_check": "SSL Check",
        "cve_check": "CVE Check",
        "all_ports": "All Ports",
        "quick_scan": "Quick Scan",
        "full_scan": "Full Scan",
        "stealth_scan": "Stealth Scan",
        "cve_database": "CVE Database",
        "solution": "Solution",
        "live_results": "Live Results",
    }
}
