# SecureScan - Vulnerability Scanning Panel

## Original Problem Statement
A Nessus-like vulnerability scanning panel with:
- **Scanning**: IP/domain scanning using Nmap with CVE detection
- **Reporting**: Live results, HTML/PDF reports with customization (logo, title, brand)
- **Roles**: Admin, Reseller, Customer roles
- **Data**: Scan history storage
- **Tech**: Modern, extensible with JWT auth and multi-language (TR/EN)

## Product Requirements
1. No public registration; Resellers create customer accounts
2. Light theme option for UI and reports
3. Corporate-style landing page
4. Footer: "© 2026 Tres Technology LLC"
5. Remove "Made with Emergent" branding
6. Multi-source detection engine (MITRE, CISA KEV, Exploit-DB)
7. Remote agent-based scanning (not on panel server)

## Architecture
```
/app/
├── backend/
│   ├── server.py          # FastAPI server + embedded agent code
│   ├── agent_gateway.py   # WebSocket agent management
│   ├── models.py          # Pydantic models
│   ├── scanner.py         # Vulnerability scanner logic
│   ├── cve_manager.py     # CVE database management
│   ├── report_generator.py # HTML/PDF report generation
│   └── templates/
│       └── report_template.html
└── frontend/
    └── src/
        ├── contexts/AppContext.jsx
        └── pages/
            ├── AgentsPage.jsx
            ├── ScanDetailPage.jsx
            ├── NewScanPage.jsx
            └── ...
```

## Scan Types
1. **quick** - Hızlı Tarama (Top 100 ports)
2. **full** - Tam Tarama (All 65535 ports)
3. **stealth** - Gizli Tarama (SYN scan)
4. **port_only** - Port Tarama (Sadece port ve servis tespiti, CVE/SSL yok)
5. **dns_recursive** - Recursive DNS (DNS amplification kontrolü, sadece IP/Prefix)

## Key Technical Details
- **Backend**: FastAPI, MongoDB (motor), JWT, asyncio, websockets
- **Frontend**: React, Tailwind CSS, Shadcn/UI, i18next
- **Agent**: Python script embedded in server.py, communicates via WebSocket

## Database Schema
- **Agent**: id, customer_id, name, token, status, last_seen, os_info, ip_address, agent_version
- **Vulnerability**: scan_id, iteration, cve_id, severity, references, evidence, source, confidence, is_kev

## Credentials
- **Admin**: admin@securescan.com / admin123

---

## Changelog

### 2026-02-20 - Agent v1.3.0 Release
**ADDED**: New Scan Types
- **Port Tarama (port_only)**: Fast port-only scan without CVE/SSL checks
- **Recursive DNS (dns_recursive)**: Checks for DNS recursive query vulnerability
  - Uses dig command to test recursive queries
  - Only works with IP and Prefix targets (domain targets rejected)
  - Reports DNS amplification attack risk if recursive enabled

### 2026-02-20 - Agent v1.2.1 Release
**FIXED**: SSL/TLS False Positive Issue
- Correct nmap ssl-enum-ciphers output parsing
- Uses nmap A-F grade system
- Only reports ciphers actually negotiated

### 2026-02-20 - Agent v1.2.0 Release
**FIXED**: WebSocket connection check compatibility with websockets 15.0.1
- Added `is_ws_open()` method using `State.OPEN` enum check

---

## Current Status
- Agent v1.3.0 ready with new scan types
- Pending user installation and testing

## Backlog

### P1
- [ ] Reseller "Login-as-Customer" feature
- [ ] Integrate Exploit-DB and GitHub Advisories

### P2
- [ ] Docker Compose for deployment
- [ ] Enhanced distro-aware vulnerability detection

---

## 3rd Party Integrations
- NVD (National Vulnerability Database)
- CISA KEV (Known Exploited Vulnerabilities)
- Nmap

## Test Files
- `/app/backend/tests/test_cve_matching.py`
- `/app/test_reports/iteration_3.json`
