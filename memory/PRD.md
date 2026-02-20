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
            └── ...
```

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

### 2026-02-20 - Agent v1.2.1 Release
**FIXED**: SSL/TLS False Positive Issue
- Root cause: Old code matched "NULL" or "DES" anywhere in the line, causing false positives
- Solution: Complete rewrite of `parse_ssl_findings()` function:
  - Now correctly parses nmap ssl-enum-ciphers output format
  - Uses regex patterns for ACTUAL cipher names (e.g., `TLS_RSA_WITH_NULL_SHA`)
  - Uses nmap's A-F grade system
  - Only reports ciphers that were actually negotiated by nmap
  - Added duplicate prevention with `reported_items` set
  - All findings now include `confidence: confirmed` field

### 2026-02-20 - Agent v1.2.0 Release
**FIXED**: WebSocket connection check compatibility with websockets 15.0.1
- Root cause: `self.ws.closed` attribute doesn't exist in websockets 15.x
- Solution: Added `is_ws_open()` method using `State.OPEN` enum check
- Impact: Agent can now properly send system_info, heartbeats, and scan results

### Previous Work
- Advanced scanning (SSL, NSE, Web checks)
- Vulnerability model enhancement (evidence, source, confidence fields)
- UI improvements (Start/End time, duration, badges for sources)
- Agent public IP reporting

---

## Current Issues Status

### ✅ RESOLVED - WebSocket Stability (v1.2.0)
- Agent connection check fixed with `State.OPEN` enum
- Pending user verification with v1.2.1 installation

### ✅ RESOLVED - SSL False Positives (v1.2.1)
- Correct nmap output parsing implemented
- Grade-based severity assignment
- Pending user verification

### 🔄 BLOCKED - Agent Info Regression
- Status: Waiting for v1.2.1 installation
- Should be resolved once agent can send system_info message

---

## Backlog (Future Tasks)

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
