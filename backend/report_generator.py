"""
Report Generator for vulnerability scan results
Generates HTML and PDF reports
"""
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Report templates directory
REPORTS_DIR = Path("/app/reports")
REPORTS_DIR.mkdir(exist_ok=True)


def get_severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        "critical": "#EF4444",
        "high": "#F97316",
        "medium": "#F59E0B",
        "low": "#EAB308",
        "info": "#3B82F6"
    }
    return colors.get(severity.lower(), "#94A3B8")


def get_severity_label(severity: str, lang: str = "en") -> str:
    """Get translated severity label"""
    labels = {
        "en": {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO"
        },
        "tr": {
            "critical": "KRİTİK",
            "high": "YÜKSEK",
            "medium": "ORTA",
            "low": "DÜŞÜK",
            "info": "BİLGİ"
        }
    }
    return labels.get(lang, labels["en"]).get(severity.lower(), severity.upper())


def get_first_http_reference(references: list) -> str:
    """Get first http/https reference URL from list, skip ftp and other protocols"""
    if not references:
        return ""
    for ref in references:
        if isinstance(ref, str) and (ref.startswith("http://") or ref.startswith("https://")):
            return ref
    return ""


def get_protocol_color(protocol: str) -> str:
    """Get color for protocol/service type"""
    colors = {
        "http": "#10B981",
        "https": "#059669",
        "ssh": "#6366F1",
        "ftp": "#F59E0B",
        "smtp": "#EC4899",
        "mysql": "#3B82F6",
        "postgresql": "#8B5CF6",
        "rdp": "#EF4444",
        "telnet": "#F97316",
    }
    return colors.get(protocol.lower(), "#64748B")


def generate_ports_section(ports_data: Optional[List[Dict[str, Any]]], l: dict, text_muted: str, card_bg: str, card_border: str, branding: Optional[Dict[str, Any]] = None, targets: Optional[List[Dict[str, Any]]] = None) -> str:
    """Generate HTML section for discovered ports"""
    if not ports_data:
        return f"<p style='color: {text_muted}; text-align: center; padding: 20px;'>{l.get('no_ports', 'No open ports discovered.')}</p>"
    
    primary_color = branding.get('primary_color', '#3B82F6') if branding else '#3B82F6'
    
    # Create a map of target_value to target_name
    target_names = {}
    if targets:
        for t in targets:
            target_names[t.get('value', '')] = t.get('name', '')
    
    html_parts = []
    
    for port_record in ports_data:
        target_value = port_record.get('target_value', 'Unknown')
        target_name = target_names.get(target_value, '')
        target_display = f"{target_value}" + (f" ({target_name})" if target_name and target_name != target_value else "")
        ports = port_record.get('ports', [])
        
        if not ports:
            continue
        
        html_parts.append(f'''
        <div style="background: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; margin-bottom: 16px; overflow: hidden;">
            <div style="padding: 12px 16px; border-bottom: 1px solid {card_border}; font-weight: 600;">
                <span style="font-family: 'JetBrains Mono', monospace; color: {primary_color};">{target_display}</span>
                <span style="color: {text_muted}; font-size: 14px; margin-left: 10px;">({len(ports)} {l.get('open_ports', 'open ports').lower()})</span>
            </div>
            <div style="padding: 16px;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="border-bottom: 1px solid {card_border};">
                            <th style="text-align: left; padding: 8px; color: {text_muted}; font-size: 12px; text-transform: uppercase;">{l.get('port', 'Port')}</th>
                            <th style="text-align: left; padding: 8px; color: {text_muted}; font-size: 12px; text-transform: uppercase;">{l.get('state', 'State')}</th>
                            <th style="text-align: left; padding: 8px; color: {text_muted}; font-size: 12px; text-transform: uppercase;">{l.get('service', 'Service')}</th>
                            <th style="text-align: left; padding: 8px; color: {text_muted}; font-size: 12px; text-transform: uppercase;">Version</th>
                        </tr>
                    </thead>
                    <tbody>
        ''')
        
        for port in ports:
            port_num = port.get('port', '')
            state = port.get('state', 'open')
            service = port.get('service', 'unknown')
            version = port.get('version', '')
            protocol = port.get('protocol', 'tcp')
            service_color = get_protocol_color(service)
            state_color = '#10B981' if state == 'open' else '#F59E0B'
            
            html_parts.append(f'''
                        <tr style="border-bottom: 1px solid {card_border};">
                            <td style="padding: 10px 8px; font-family: 'JetBrains Mono', monospace; font-weight: 600;">{port_num}/{protocol}</td>
                            <td style="padding: 10px 8px;"><span style="color: {state_color}; font-weight: 500;">{state}</span></td>
                            <td style="padding: 10px 8px;"><span style="color: {service_color}; font-weight: 500;">{service}</span></td>
                            <td style="padding: 10px 8px; color: {text_muted}; font-size: 13px;">{version or '-'}</td>
                        </tr>
            ''')
        
        html_parts.append('''
                    </tbody>
                </table>
            </div>
        </div>
        ''')
    
    return ''.join(html_parts) if html_parts else f"<p style='color: {text_muted}; text-align: center; padding: 20px;'>{l.get('no_ports', 'No open ports discovered.')}</p>"


def generate_findings_by_target(vulnerabilities: List[Dict[str, Any]], l: dict, text_muted: str, card_bg: str, card_border: str, branding: Optional[Dict[str, Any]], lang: str, targets: Optional[List[Dict[str, Any]]] = None) -> str:
    """Generate HTML section for findings grouped by target"""
    if not vulnerabilities:
        return f"<p style='color: {text_muted}; text-align: center; padding: 40px;'>{l.get('no_vulns', 'No vulnerabilities found.')}</p>"
    
    primary_color = branding.get('primary_color', '#3B82F6') if branding else '#3B82F6'
    
    # Create a map of target_value to target_name
    target_names = {}
    if targets:
        for t in targets:
            target_names[t.get('value', '')] = t.get('name', '')
    
    # Group vulnerabilities by target
    vulns_by_target = {}
    for vuln in vulnerabilities:
        target = vuln.get('target_value', 'Unknown')
        if target not in vulns_by_target:
            vulns_by_target[target] = []
        vulns_by_target[target].append(vuln)
    
    # Sort each target's vulns by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for target in vulns_by_target:
        vulns_by_target[target] = sorted(
            vulns_by_target[target], 
            key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5)
        )
    
    html_parts = []
    
    for target_value, target_vulns in vulns_by_target.items():
        # Get target name
        target_name = target_names.get(target_value, '')
        target_display = f"{target_value}" + (f" ({target_name})" if target_name and target_name != target_value else "")
        
        # Count by severity for this target
        target_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in target_vulns:
            sev = v.get("severity", "info").lower()
            if sev in target_severity:
                target_severity[sev] += 1
        
        # Target header with severity badges
        severity_badges = []
        if target_severity["critical"] > 0:
            severity_badges.append(f'<span style="background: rgba(239,68,68,0.2); color: #EF4444; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 4px;">{target_severity["critical"]} {get_severity_label("critical", lang)}</span>')
        if target_severity["high"] > 0:
            severity_badges.append(f'<span style="background: rgba(249,115,22,0.2); color: #F97316; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 4px;">{target_severity["high"]} {get_severity_label("high", lang)}</span>')
        if target_severity["medium"] > 0:
            severity_badges.append(f'<span style="background: rgba(245,158,11,0.2); color: #F59E0B; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 4px;">{target_severity["medium"]} {get_severity_label("medium", lang)}</span>')
        if target_severity["low"] > 0:
            severity_badges.append(f'<span style="background: rgba(234,179,8,0.2); color: #EAB308; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 4px;">{target_severity["low"]} {get_severity_label("low", lang)}</span>')
        if target_severity["info"] > 0:
            severity_badges.append(f'<span style="background: rgba(59,130,246,0.2); color: #3B82F6; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 4px;">{target_severity["info"]} {get_severity_label("info", lang)}</span>')
        
        html_parts.append(f'''
        <div style="margin-bottom: 24px;">
            <div style="background: {card_bg}; border: 1px solid {card_border}; border-radius: 8px 8px 0 0; padding: 16px; border-bottom: 2px solid {primary_color};">
                <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 18px; font-weight: 600; color: {primary_color};">{target_display}</span>
                    <div>{"".join(severity_badges)}</div>
                </div>
            </div>
        ''')
        
        # Vulnerability cards for this target
        for v in target_vulns:
            ref_link = get_first_http_reference(v.get('references', []))
            html_parts.append(f'''
            <div style="background: {card_bg}; border: 1px solid {card_border}; border-top: none; overflow: hidden;">
                <div style="display: flex; align-items: center; padding: 12px 16px; border-bottom: 1px solid {card_border};">
                    <span style="padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 700; margin-right: 16px; text-transform: uppercase; background: rgba({'239,68,68' if v.get('severity','').lower()=='critical' else '249,115,22' if v.get('severity','').lower()=='high' else '245,158,11' if v.get('severity','').lower()=='medium' else '234,179,8' if v.get('severity','').lower()=='low' else '59,130,246'},0.2); color: {'#EF4444' if v.get('severity','').lower()=='critical' else '#F97316' if v.get('severity','').lower()=='high' else '#F59E0B' if v.get('severity','').lower()=='medium' else '#EAB308' if v.get('severity','').lower()=='low' else '#3B82F6'};">{get_severity_label(v.get('severity', 'info'), lang)}</span>
                    <span style="font-size: 15px; font-weight: 600; flex: 1;">{v.get('title', 'Unknown')}</span>
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 13px; color: {text_muted};">
                        {f"Port: {v.get('port')}" if v.get('port') else ""}
                        {f" | {v.get('service', '')}" if v.get('service') else ""}
                    </span>
                </div>
                <div style="padding: 16px;">
                    <p style="margin-bottom: 12px; color: {text_muted};"><strong style="color: inherit;">{l['description']}:</strong> {v.get('description', 'No description available.')}</p>
                    {f"<p style='margin-bottom: 12px; color: {text_muted};'><strong>{l['solution']}:</strong> {v.get('solution')}</p>" if v.get('solution') else ""}
                    {f"<p style='margin-bottom: 12px;'><strong>{l['cve']}:</strong> <span style='font-family: JetBrains Mono, monospace; background: {card_border}; padding: 2px 8px; border-radius: 4px;'>{v.get('cve_id')}</span>" + (f" | CVSS: <strong>{v.get('cvss_score')}</strong>" if v.get('cvss_score') else "") + "</p>" if v.get('cve_id') else ""}
                    {f"<p style='margin-bottom: 8px;'><strong>Reference:</strong> <a href='{ref_link}' target='_blank' style='color: {primary_color};'>{ref_link}</a></p>" if ref_link else ""}
                </div>
            </div>
            ''')
        
        html_parts.append('</div>')
    
    return ''.join(html_parts)


def generate_html_report(
    scan: Dict[str, Any],
    targets: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    branding: Optional[Dict[str, Any]] = None,
    lang: str = "en",
    theme: str = "dark",
    ports_data: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Generate HTML report with dark/light theme support"""
    
    # Theme colors
    if theme == "light":
        bg_color = "#FFFFFF"
        bg_secondary = "#F8FAFC"
        text_color = "#1E293B"
        text_muted = "#64748B"
        border_color = "#E2E8F0"
        card_bg = "#FFFFFF"
        card_border = "#E2E8F0"
        cover_bg = "linear-gradient(135deg, #F8FAFC 0%, #E2E8F0 100%)"
        terminal_bg = "#F1F5F9"
    else:  # dark
        bg_color = "#0F172A"
        bg_secondary = "#1E293B"
        text_color = "#F8FAFC"
        text_muted = "#94A3B8"
        border_color = "#334155"
        card_bg = "#1E293B"
        card_border = "#334155"
        cover_bg = "linear-gradient(135deg, #020617 0%, #0F172A 100%)"
        terminal_bg = "#0F172A"
    
    # Default branding
    if not branding:
        branding = {
            "company_name": "Vulnerability Scanner",
            "logo_url": None,
            "primary_color": "#3B82F6",
            "secondary_color": "#1E293B",
            "report_header_text": "",
            "report_footer_text": ""
        }
    
    # Count by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    total_vulns = sum(severity_counts.values())
    
    # Get iteration info
    report_iteration = scan.get('report_iteration', scan.get('current_iteration', 1))
    total_iterations = scan.get('current_iteration', 1)
    
    # Labels based on language
    labels = {
        "en": {
            "title": "Vulnerability Scan Report",
            "executive_summary": "Executive Summary",
            "scan_details": "Scan Details",
            "scan_name": "Scan Name",
            "scan_date": "Scan Date",
            "targets_scanned": "Targets Scanned",
            "total_findings": "Total Findings",
            "vulnerability_summary": "Vulnerability Summary",
            "detailed_findings": "Detailed Findings",
            "severity": "Severity",
            "port": "Port",
            "service": "Service",
            "description": "Description",
            "solution": "Solution",
            "cve": "CVE",
            "no_vulns": "No vulnerabilities found.",
            "pci_compliance": "PCI Compliance",
            "compliant": "COMPLIANT",
            "non_compliant": "NON-COMPLIANT",
            "pci_note": "PCI DSS compliance requires no Critical or High severity vulnerabilities.",
            "iteration": "Iteration",
            "of": "of",
            "discovered_ports": "Discovered Ports & Services",
            "open_ports": "Open Ports",
            "no_ports": "No open ports discovered.",
            "state": "State",
            "protocol": "Protocol"
        },
        "tr": {
            "title": "Zafiyet Tarama Raporu",
            "executive_summary": "Yönetici Özeti",
            "scan_details": "Tarama Detayları",
            "scan_name": "Tarama Adı",
            "scan_date": "Tarama Tarihi",
            "targets_scanned": "Taranan Hedefler",
            "total_findings": "Toplam Bulgular",
            "vulnerability_summary": "Zafiyet Özeti",
            "detailed_findings": "Detaylı Bulgular",
            "severity": "Seviye",
            "port": "Port",
            "service": "Servis",
            "description": "Açıklama",
            "solution": "Çözüm",
            "cve": "CVE",
            "no_vulns": "Zafiyet bulunamadı.",
            "pci_compliance": "PCI Uyumluluk",
            "compliant": "UYUMLU",
            "non_compliant": "UYUMSUZ",
            "pci_note": "PCI DSS uyumluluğu için Kritik veya Yüksek seviye zafiyet bulunmamalıdır.",
            "iteration": "Yineleme",
            "of": "/",
            "discovered_ports": "Tespit Edilen Portlar ve Servisler",
            "open_ports": "Açık Portlar",
            "no_ports": "Açık port tespit edilmedi.",
            "state": "Durum",
            "protocol": "Protokol"
        }
    }
    
    l = labels.get(lang, labels["en"])
    
    # Check PCI compliance
    pci_compliant = severity_counts["critical"] == 0 and severity_counts["high"] == 0
    
    # Generate target list
    target_list = ", ".join([t.get("value", "") for t in targets[:10]])
    if len(targets) > 10:
        target_list += f" (+{len(targets) - 10} more)"
    
    # Sort vulnerabilities by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(vulnerabilities, key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))
    
    html = f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{l['title']} - {scan.get('name', 'Scan')}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Chivo:wght@400;700&family=Manrope:wght@400;500;600&family=JetBrains+Mono&display=swap');
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Manrope', sans-serif;
            background: {bg_color};
            color: {text_color};
            line-height: 1.6;
        }}
        
        .cover-page {{
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            background: {cover_bg};
            padding: 40px;
            page-break-after: always;
        }}
        
        .logo {{
            max-width: 200px;
            max-height: 100px;
            margin-bottom: 40px;
        }}
        
        .cover-title {{
            font-family: 'Chivo', sans-serif;
            font-size: 48px;
            font-weight: 700;
            color: {branding.get('primary_color', '#3B82F6')};
            text-align: center;
            margin-bottom: 20px;
        }}
        
        .cover-subtitle {{
            font-size: 24px;
            color: {text_muted};
            text-align: center;
            margin-bottom: 20px;
        }}
        
        .cover-iteration {{
            font-size: 16px;
            color: {text_muted};
            text-align: center;
            margin-bottom: 20px;
            padding: 8px 20px;
            background: {card_bg};
            border-radius: 20px;
            border: 1px solid {card_border};
        }}
        
        .cover-date {{
            font-size: 18px;
            color: {text_muted};
        }}
        
        .company-name {{
            font-size: 20px;
            color: {text_color};
            margin-top: 60px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px;
        }}
        
        h1, h2, h3 {{
            font-family: 'Chivo', sans-serif;
        }}
        
        h2 {{
            color: {branding.get('primary_color', '#3B82F6')};
            font-size: 28px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid {branding.get('primary_color', '#3B82F6')};
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
            margin-bottom: 40px;
        }}
        
        .summary-card {{
            background: {card_bg};
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border: 1px solid {card_border};
        }}
        
        .summary-card.critical {{ border-top: 4px solid #EF4444; }}
        .summary-card.high {{ border-top: 4px solid #F97316; }}
        .summary-card.medium {{ border-top: 4px solid #F59E0B; }}
        .summary-card.low {{ border-top: 4px solid #EAB308; }}
        .summary-card.info {{ border-top: 4px solid #3B82F6; }}
        
        .summary-count {{
            font-size: 36px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .summary-label {{
            font-size: 14px;
            color: {text_muted};
            text-transform: uppercase;
        }}
        
        .details-table {{
            width: 100%;
            margin-bottom: 40px;
        }}
        
        .details-table td {{
            padding: 12px 16px;
            border-bottom: 1px solid {card_border};
        }}
        
        .details-table td:first-child {{
            color: {text_muted};
            width: 200px;
        }}
        
        .pci-badge {{
            display: inline-block;
            padding: 8px 24px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 14px;
        }}
        
        .pci-compliant {{
            background: rgba(16, 185, 129, 0.2);
            color: #10B981;
            border: 1px solid #10B981;
        }}
        
        .pci-non-compliant {{
            background: rgba(239, 68, 68, 0.2);
            color: #EF4444;
            border: 1px solid #EF4444;
        }}
        
        .vuln-card {{
            background: {card_bg};
            border-radius: 8px;
            margin-bottom: 16px;
            border: 1px solid {card_border};
            overflow: hidden;
        }}
        
        .vuln-header {{
            display: flex;
            align-items: center;
            padding: 16px;
            border-bottom: 1px solid {card_border};
        }}
        
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 700;
            margin-right: 16px;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background: rgba(239, 68, 68, 0.2); color: #EF4444; }}
        .severity-high {{ background: rgba(249, 115, 22, 0.2); color: #F97316; }}
        .severity-medium {{ background: rgba(245, 158, 11, 0.2); color: #F59E0B; }}
        .severity-low {{ background: rgba(234, 179, 8, 0.2); color: #EAB308; }}
        .severity-info {{ background: rgba(59, 130, 246, 0.2); color: #3B82F6; }}
        
        .vuln-title {{
            font-size: 16px;
            font-weight: 600;
            flex: 1;
        }}
        
        .vuln-meta {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: {text_muted};
        }}
        
        .vuln-body {{
            padding: 16px;
        }}
        
        .vuln-body p {{
            margin-bottom: 12px;
            color: {text_muted};
        }}
        
        .vuln-body strong {{
            color: {text_color};
        }}
        
        .target-value {{
            font-family: 'JetBrains Mono', monospace;
            background: {bg_secondary};
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 13px;
        }}
        
        .footer {{
            text-align: center;
            padding: 40px;
            color: {text_muted};
            font-size: 14px;
            border-top: 1px solid {card_border};
            margin-top: 40px;
        }}
        
        @media print {{
            .cover-page {{
                page-break-after: always;
            }}
            
            .container {{
                padding: 20px;
            }}
            
            .vuln-card {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <!-- Cover Page -->
    <div class="cover-page">
        {"<img src='" + branding.get('logo_url') + "' alt='Logo' class='logo' />" if branding.get('logo_url') else ""}
        <h1 class="cover-title">{l['title']}</h1>
        <p class="cover-subtitle">{scan.get('name', 'Vulnerability Scan')}</p>
        <p class="cover-iteration">{l['iteration']} {report_iteration} {l['of']} {total_iterations}</p>
        <p class="cover-date">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p class="company-name">{branding.get('company_name', 'Vulnerability Scanner')}</p>
        {f"<p style='margin-top: 20px; color: {text_muted};'>{branding.get('report_header_text', '')}</p>" if branding.get('report_header_text') else ""}
    </div>
    
    <!-- Executive Summary -->
    <div class="container">
        <h2>{l['executive_summary']}</h2>
        
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="summary-count" style="color: #EF4444;">{severity_counts['critical']}</div>
                <div class="summary-label">{get_severity_label('critical', lang)}</div>
            </div>
            <div class="summary-card high">
                <div class="summary-count" style="color: #F97316;">{severity_counts['high']}</div>
                <div class="summary-label">{get_severity_label('high', lang)}</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-count" style="color: #F59E0B;">{severity_counts['medium']}</div>
                <div class="summary-label">{get_severity_label('medium', lang)}</div>
            </div>
            <div class="summary-card low">
                <div class="summary-count" style="color: #EAB308;">{severity_counts['low']}</div>
                <div class="summary-label">{get_severity_label('low', lang)}</div>
            </div>
            <div class="summary-card info">
                <div class="summary-count" style="color: #3B82F6;">{severity_counts['info']}</div>
                <div class="summary-label">{get_severity_label('info', lang)}</div>
            </div>
        </div>
        
        <!-- Scan Details -->
        <h2>{l['scan_details']}</h2>
        <table class="details-table">
            <tr>
                <td>{l['scan_name']}</td>
                <td>{scan.get('name', 'N/A')}</td>
            </tr>
            <tr>
                <td>{l['iteration']}</td>
                <td>{report_iteration} {l['of']} {total_iterations}</td>
            </tr>
            <tr>
                <td>{l['scan_date']}</td>
                <td>{scan.get('created_at', datetime.now(timezone.utc).isoformat())[:19].replace('T', ' ')} UTC</td>
            </tr>
            <tr>
                <td>{l['targets_scanned']}</td>
                <td><span class="target-value">{target_list}</span></td>
            </tr>
            <tr>
                <td>{l['total_findings']}</td>
                <td>{total_vulns}</td>
            </tr>
            <tr>
                <td>{l['pci_compliance']}</td>
                <td>
                    <span class="pci-badge {'pci-compliant' if pci_compliant else 'pci-non-compliant'}">
                        {l['compliant'] if pci_compliant else l['non_compliant']}
                    </span>
                    <br><small style="color: {text_muted};">{l['pci_note']}</small>
                </td>
            </tr>
        </table>
        
        <!-- Discovered Ports -->
        <h2>{l['discovered_ports']}</h2>
        {generate_ports_section(ports_data, l, text_muted, card_bg, card_border, branding, targets)}
        
        <!-- Detailed Findings -->
        <h2>{l['detailed_findings']}</h2>
        
        {generate_findings_by_target(sorted_vulns, l, text_muted, card_bg, card_border, branding, lang, targets)}
        
        <div class="footer">
            <p>{branding.get('report_footer_text', '')} | Generated by {branding.get('company_name', 'Vulnerability Scanner')}</p>
            <p>Report generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>
</body>
</html>"""
    
    return html


async def generate_pdf_report(
    scan: Dict[str, Any],
    targets: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    branding: Optional[Dict[str, Any]] = None,
    lang: str = "en",
    theme: str = "dark",
    ports_data: Optional[List[Dict[str, Any]]] = None
) -> bytes:
    """Generate PDF report from HTML with theme support"""
    from weasyprint import HTML, CSS
    
    html_content = generate_html_report(scan, targets, vulnerabilities, branding, lang, theme, ports_data)
    
    try:
        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes
    except Exception as e:
        logger.error(f"PDF generation error: {str(e)}")
        raise


async def save_report(
    scan_id: str,
    content: bytes,
    format: str = "pdf"
) -> str:
    """Save report to file system and return path"""
    filename = f"report_{scan_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.{format}"
    filepath = REPORTS_DIR / filename
    
    with open(filepath, "wb") as f:
        f.write(content)
    
    return str(filepath)
