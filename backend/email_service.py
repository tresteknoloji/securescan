"""
Email Service for sending notifications via SMTP
"""
import logging
from typing import Optional, Dict, Any
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

logger = logging.getLogger(__name__)


async def send_email(
    smtp_config: Dict[str, Any],
    to_email: str,
    subject: str,
    body_html: str,
    attachment: Optional[tuple] = None  # (filename, content_bytes)
) -> bool:
    """
    Send email using provided SMTP configuration
    """
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{smtp_config.get('sender_name', 'Scanner')} <{smtp_config.get('sender_email')}>"
        msg['To'] = to_email
        
        # Add HTML body
        html_part = MIMEText(body_html, 'html')
        msg.attach(html_part)
        
        # Add attachment if provided
        if attachment:
            filename, content = attachment
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(content)
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {filename}',
            )
            msg.attach(part)
        
        # Send email
        if smtp_config.get('use_ssl'):
            await aiosmtplib.send(
                msg,
                hostname=smtp_config.get('host'),
                port=smtp_config.get('port', 465),
                username=smtp_config.get('username'),
                password=smtp_config.get('password'),
                use_tls=True,
            )
        else:
            await aiosmtplib.send(
                msg,
                hostname=smtp_config.get('host'),
                port=smtp_config.get('port', 587),
                username=smtp_config.get('username'),
                password=smtp_config.get('password'),
                start_tls=smtp_config.get('use_tls', True),
            )
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        return False


def get_scan_complete_email(
    scan_name: str,
    total_vulns: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    info: int,
    report_link: str,
    lang: str = "en"
) -> str:
    """Generate scan complete email HTML"""
    
    if lang == "tr":
        title = "Tarama Tamamlandı"
        greeting = "Merhaba,"
        message = f"<strong>{scan_name}</strong> taraması başarıyla tamamlandı."
        summary_title = "Zafiyet Özeti"
        view_report = "Raporu Görüntüle"
        footer = "Bu email otomatik olarak gönderilmiştir."
        labels = {
            "critical": "Kritik",
            "high": "Yüksek",
            "medium": "Orta",
            "low": "Düşük",
            "info": "Bilgi",
            "total": "Toplam"
        }
    else:
        title = "Scan Complete"
        greeting = "Hello,"
        message = f"The scan <strong>{scan_name}</strong> has been completed successfully."
        summary_title = "Vulnerability Summary"
        view_report = "View Report"
        footer = "This is an automated message."
        labels = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "total": "Total"
        }
    
    return f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #0F172A;
            color: #F8FAFC;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: #1E293B;
            border-radius: 8px;
            padding: 30px;
        }}
        h1 {{
            color: #3B82F6;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .summary {{
            background: #020617;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        .severity-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #334155;
        }}
        .severity-row:last-child {{
            border-bottom: none;
            font-weight: bold;
        }}
        .critical {{ color: #EF4444; }}
        .high {{ color: #F97316; }}
        .medium {{ color: #F59E0B; }}
        .low {{ color: #EAB308; }}
        .info {{ color: #3B82F6; }}
        .btn {{
            display: inline-block;
            background: #3B82F6;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 6px;
            margin-top: 20px;
        }}
        .footer {{
            text-align: center;
            color: #64748B;
            font-size: 12px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p>{greeting}</p>
        <p>{message}</p>
        
        <div class="summary">
            <h3>{summary_title}</h3>
            <div class="severity-row">
                <span class="critical">{labels['critical']}</span>
                <span class="critical">{critical}</span>
            </div>
            <div class="severity-row">
                <span class="high">{labels['high']}</span>
                <span class="high">{high}</span>
            </div>
            <div class="severity-row">
                <span class="medium">{labels['medium']}</span>
                <span class="medium">{medium}</span>
            </div>
            <div class="severity-row">
                <span class="low">{labels['low']}</span>
                <span class="low">{low}</span>
            </div>
            <div class="severity-row">
                <span class="info">{labels['info']}</span>
                <span class="info">{info}</span>
            </div>
            <div class="severity-row">
                <span>{labels['total']}</span>
                <span>{total_vulns}</span>
            </div>
        </div>
        
        <a href="{report_link}" class="btn">{view_report}</a>
        
        <div class="footer">
            <p>{footer}</p>
        </div>
    </div>
</body>
</html>
"""
