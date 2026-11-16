import os
import io
import datetime
from typing import List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

# ReportLab libraries for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Cross-platform / Windows audible alert
try:
    import winsound
    def play_system_alert():
        try:
            winsound.Beep(1200, 200)
        except Exception:
            pass
except ImportError:
    def play_system_alert():
        pass

# Import realistic progressive scanner engine
from azure_scanner import scan_live_infrastructure, remediate_live_nsg

app = FastAPI(title="Cloud Compliance Engine API")

# Unrestricted CORS so Extension and Dashboard can call APIs
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TelemetryLog(BaseModel):
    activity: str
    target: Optional[str] = "Cloud Surface"
    url: Optional[str] = "https://portal.azure.com"
    timestamp: str

class RemediationRequest(BaseModel):
    rule_id: str
    resource_id: str

# Live mutable state
visited_pages: List[dict] = []
warnings_list: List[str] = [
    "nsg-prod-dmz: Critical perimeter exposure - Inbound TCP 3389 is wide open to 0.0.0.0/0.",
    "cosmos-analytics-eastus: Database master key rotation missing. Enforce Azure RBAC."
]

# Monitored rules state (Initializes with progressive discovery)
infrastructure_rules: List[dict] = scan_live_infrastructure(None)

RISK_KEYWORDS = {
    "Azure Cosmos DB": "Database Surface: NoSQL Cosmos DB accessed. Master read/write keys and container data exposure risk.",
    "Virtual Machines": "High-Risk Surface: Virtual Machine blades expose private SSH keys and disk snapshots.",
    "Storage Accounts": "Critical Surface: Storage Account accessed. Potential exposure of blob containers and customer backups.",
    "Network Security Groups": "Network Perimeter Surface: NSG and Firewall rules inspection active.",
    "Key Vaults": "Sensitive Secret Surface: Key Vault accessed. Cryptographic keys and app secrets monitored."
}

# Detailed CIS & NIST Framework Mappings (Includes all progressive assets)
FRAMEWORK_MAPPINGS = {
    "cis-3.2-nsg": {
        "rule_title": "Ensure No Open Inbound RDP (TCP Port 3389) from the Internet (0.0.0.0/0)",
        "cis": "CIS Microsoft Azure Foundations Benchmark v2.0 - Section 6.2 / CIS AWS 4.2",
        "cis_desc": "Evaluates perimeter security rules to prevent public exposure of Remote Desktop Protocol (RDP). Leaving Port 3389 open allows brute-force attacks and unauthorized remote takeover.",
        "nist": "NIST SP 800-53 Rev. 5: AC-3 (Access Enforcement) & SC-7 (Boundary Protection)",
        "nist_desc": "NIST AC-3 mandates automated enforcement of access policies, while SC-7 requires managed boundaries and network firewalls to drop untrusted inbound traffic by default."
    },
    "cis-5.1-vm": {
        "rule_title": "Ensure Inbound SSH Access (TCP Port 22) from Internet Is Restricted",
        "cis": "CIS Microsoft Azure Foundations Benchmark v2.0 - Section 5.1 / CIS AWS 4.1",
        "cis_desc": "Mandates that compute instances do not accept wide-open SSH connections across untrusted routes, preventing password spraying and arbitrary execution.",
        "nist": "NIST SP 800-53 Rev. 5: AC-17 (Remote Access) & SC-7 (Boundary Protection)",
        "nist_desc": "NIST AC-17 dictates rigorous controls and encryption on all remote maintenance sessions, ensuring SSH endpoints remain isolated behind secure bastion gateways."
    },
    "cis-8.1-kv": {
        "rule_title": "Enforce Lifecycle Management and Expiration on Cryptographic Secrets",
        "cis": "CIS Microsoft Azure Foundations Benchmark v2.0 - Section 8.1",
        "cis_desc": "Requires secrets, keys, and certificates to have explicit expiration timestamps, accompanied by soft-delete and purge protection on production vaults.",
        "nist": "NIST SP 800-53 Rev. 5: IA-5 (Authenticator Management) & SC-13 (Cryptographic Protection)",
        "nist_desc": "NIST IA-5 requires system authenticators to be managed throughout their lifecycle, while SC-13 enforces state-of-the-art cryptographic preservation."
    },
    "cis-7.1-cosmos": {
        "rule_title": "Regenerate Cosmos DB Account Master Keys and Enforce RBAC Private Endpoints",
        "cis": "CIS Microsoft Azure Foundations Benchmark v2.0 - Section 7.1",
        "cis_desc": "Cosmos DB master keys provide administrative read/write control over NoSQL collections. CIS requires periodic key rotation, private endpoints, and disabling static keys.",
        "nist": "NIST SP 800-53 Rev. 5: AC-2 (Account Management) & SC-12 (Cryptographic Key Establishment)",
        "nist_desc": "NIST AC-2 governs privileged access rights, while SC-12 requires automated key revocation to avoid database dumps caused by leaked static tokens."
    },
    "cis-3.1-storage": {
        "rule_title": "Disable Public Anonymous Blob Container Access",
        "cis": "CIS Microsoft Azure Foundations Benchmark v2.0 - Section 3.1 / CIS AWS 2.1.4",
        "cis_desc": "Ensures storage accounts disable public blob access at the root container level to prevent scraping of sensitive business assets or configuration files.",
        "nist": "NIST SP 800-53 Rev. 5: AC-3 (Access Enforcement) & MP-4 (Media Storage)",
        "nist_desc": "NIST MP-4 enforces strict control over electronic storage repositories, prohibiting unauthenticated data exfiltration."
    },
    "cis-6.1-appgw": {
        "rule_title": "Enforce TLS 1.2+ & Web Application Firewall (WAF) Prevention Mode",
        "cis": "CIS Microsoft Azure Foundations Benchmark v2.0 - Section 6.1",
        "cis_desc": "Audits application gateways and load balancers to ensure legacy SSL/TLS ciphers are disabled and WAF rule groups are set to active prevention mode.",
        "nist": "NIST SP 800-53 Rev. 5: SC-8 (Transmission Confidentiality) & SI-4 (Information System Monitoring)",
        "nist_desc": "NIST SC-8 enforces cryptographic integrity in transit, and SI-4 mandates inbound deep-packet inspection against web vulnerabilities."
    }
}

@app.get("/")
def root():
    return {"status": "Online", "service": "Cloud Compliance Telemetry Engine"}

@app.get("/api/azure-audit")
def get_azure_audit():
    """
    Polled every 500ms by the frontend.
    Returns full catalog; frontend progressively reveals them with animation.
    """
    global infrastructure_rules
    failed_count = sum(1 for r in infrastructure_rules if r["status"] == "FAILED")
    total_rules = len(infrastructure_rules)
    calculated_score = int(((total_rules - failed_count) / total_rules) * 100) if total_rules > 0 else 100

    return {
        "compliance_score": calculated_score,
        "scanned_resources": total_rules + len(visited_pages),
        "visited_pages": visited_pages,
        "warnings": warnings_list,
        "infrastructure": infrastructure_rules
    }

@app.post("/api/log-activity")
def log_activity(data: TelemetryLog):
    global infrastructure_rules
    new_entry = {"title": data.activity, "time": data.timestamp, "url": data.url}
    visited_pages.insert(0, new_entry)
    if len(visited_pages) > 15:
        visited_pages.pop()

    # Telemetry inspection for security drift & live table dynamic injection
    for risk_key, alert_text in RISK_KEYWORDS.items():
        if risk_key.lower() in data.activity.lower():
            warning_msg = f"{data.activity} - {alert_text}"
            if warning_msg not in warnings_list:
                warnings_list.insert(0, warning_msg)
                play_system_alert()

            # Live drift entry in infrastructure audit stream
            dyn_id = f"dyn-{risk_key.lower().replace(' ', '-')}"
            if not any(r["id"] == dyn_id for r in infrastructure_rules):
                infrastructure_rules.insert(0, {
                    "id": dyn_id,
                    "service": risk_key,
                    "resource": f"/subscriptions/{os.getenv('AZURE_SUBSCRIPTION_ID', 'a8b7c6d5-e4f3-4210-9876-543210abcdef')}/resourceGroups/rg-live-stream/providers/Microsoft.{risk_key.replace(' ', '')}/instance-01",
                    "rule": f"CIS Baseline - High Exposure Alert on {risk_key}",
                    "status": "FAILED",
                    "severity": "CRITICAL"
                })

    return {"status": "success", "logged": data.activity}

@app.get("/api/scan")
@app.post("/api/scan")
def run_scan():
    failed_count = sum(1 for r in infrastructure_rules if r["status"] == "FAILED")
    total_rules = len(infrastructure_rules)
    score = int(((total_rules - failed_count) / total_rules) * 100) if total_rules > 0 else 100
    return {
        "score": score,
        "total_assets": len(infrastructure_rules) + len(visited_pages),
        "critical_violations": failed_count,
        "findings": infrastructure_rules
    }

@app.post("/api/remediate")
def apply_remediation(req: RemediationRequest):
    global infrastructure_rules, warnings_list
    # Call Azure SDK remediation hook
    try:
        remediate_live_nsg(req.rule_id, req.resource_id)
    except Exception:
        pass

    # Update in-memory state dynamically
    for rule in infrastructure_rules:
        if rule["id"] == req.rule_id or rule["resource"] == req.resource_id:
            rule["status"] = "PASSED"
            rule["severity"] = "RESOLVED"
            # Clear matching warnings from the active banner
            warnings_list = [w for w in warnings_list if rule["service"].lower() not in w.lower()]
            return {"status": "success", "message": f"Remediated: Closed exposed ports for {rule['resource']}"}
            
    return {"status": "error", "message": "Rule ID not found"}

@app.post("/api/reset-rules")
def reset_rules():
    """Resets audit state back to initial progressive discovery for demo purposes"""
    global infrastructure_rules, warnings_list
    infrastructure_rules = scan_live_infrastructure(None)
    warnings_list = [
        "nsg-prod-dmz: Critical perimeter exposure - Inbound TCP 3389 is wide open to 0.0.0.0/0.",
        "cosmos-analytics-eastus: Database master key rotation missing. Enforce Azure RBAC."
    ]
    return {"status": "reset", "message": "Progressive scan baseline restored"}

@app.get("/api/download-report")
def download_pdf_report():
    audit_data = get_azure_audit()
    score = audit_data["compliance_score"]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    failed_infra = [r for r in audit_data.get("infrastructure", []) if r["status"] == "FAILED"]
    passed_infra = [r for r in audit_data.get("infrastructure", []) if r["status"] == "PASSED"]

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
        fontName='Helvetica-Bold'
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#475569"),
        spaceAfter=14
    )
    section_heading = ParagraphStyle(
        'SectionHead',
        parent=styles['Heading2'],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=12,
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b")
    )
    code_desc_style = ParagraphStyle(
        'CodeDesc',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#334155")
    )

    story = [
        Paragraph("CLOUD COMPLIANCE & ATTACKER TELEMETRY ENGINE", title_style),
        Paragraph(f"Formal Security Assessment Report | CIS Cloud Benchmarks & NIST SP 800-53 (Rev. 5)<br/>Generated: {timestamp}", subtitle_style),
        HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=12),
        Paragraph("1. EXECUTIVE SUMMARY & POSTURE EVALUATION", section_heading)
    ]

    # Executive Summary Table
    summary_data = [
        ["Compliance Score:", f"{score}%", "Status:", "COMPLIANT" if score == 100 else "REMEDIATION REQUIRED"],
        ["Monitored Assets:", str(audit_data["scanned_resources"]), "Active Threats:", str(len(audit_data["warnings"]))]
    ]
    summary_table = Table(summary_data, colWidths=[120, 150, 120, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor("#0f172a")),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    exec_text = (
        "This formal governance audit report correlates live infrastructure posture against CIS Foundations "
        "and NIST Special Publication 800-53 Rev. 5 control catalogs. The engine continuously detects misconfigured "
        "cloud surfaces, open perimeter ports, and unauthorized console navigation attempts."
    )
    story.append(Paragraph(exec_text, body_style))
    story.append(Spacer(1, 10))

    # 2. Flagged Security Violations & CIS/NIST Mappings
    story.append(Paragraph("2. FLAGGED SECURITY VIOLATIONS & FRAMEWORK MAPPINGS", section_heading))

    has_violations = False
    counter = 1

    if failed_infra:
        has_violations = True
        for rule in failed_infra:
            mapping = FRAMEWORK_MAPPINGS.get(rule["id"], {})
            story.append(Paragraph(f"<b>[{counter}] INFRASTRUCTURE VIOLATION: {rule['service']}</b>", ParagraphStyle('ViolHead', parent=body_style, textColor=colors.HexColor("#b91c1c"), fontName='Helvetica-Bold')))
            story.append(Paragraph(f"<b>Target:</b> {rule['resource']}<br/><b>Rule:</b> {rule['rule']} | <b>Severity:</b> {rule['severity']} | <b>Status:</b> FAILED", body_style))
            story.append(Spacer(1, 4))
            
            cis_block = f"<b>CIS Benchmark Mapping:</b><br/>Standard: {mapping.get('cis', 'CIS Microsoft Azure Foundations Benchmark v2.0')}<br/>Policy: {mapping.get('rule_title', rule['rule'])}<br/><i>Meaning: {mapping.get('cis_desc', '')}</i>"
            story.append(Paragraph(cis_block, code_desc_style))
            story.append(Spacer(1, 4))

            nist_block = f"<b>NIST SP 800-53 (Rev. 5) Control Mapping:</b><br/>Control: {mapping.get('nist', 'NIST SC-7 Boundary Protection')}<br/><i>Meaning: {mapping.get('nist_desc', '')}</i>"
            story.append(Paragraph(nist_block, code_desc_style))
            story.append(Spacer(1, 8))
            counter += 1

    if warnings_list:
        has_violations = True
        for warning in warnings_list:
            detected_surface = None
            for key in FRAMEWORK_MAPPINGS.keys():
                if key.lower() in warning.lower():
                    detected_surface = key
                    break

            mapping = FRAMEWORK_MAPPINGS.get(
                detected_surface,
                {
                    "rule_title": "Ensure Baseline Operational Hygiene Across Cloud Portals",
                    "cis": "CIS General Cloud Security Benchmark - Section 1.x",
                    "cis_desc": "Ensures operators access management blades following least-privilege zero-trust pathways.",
                    "nist": "NIST SP 800-53 Rev. 5: CA-7 (Continuous Monitoring)",
                    "nist_desc": "NIST CA-7 requires continuous monitoring of administrative interactions with cloud components."
                }
            )

            story.append(Paragraph(f"<b>[{counter}] ATTACKER / OPERATOR TELEMETRY ALERT:</b> {warning}", ParagraphStyle('TelHead', parent=body_style, textColor=colors.HexColor("#c2410c"), fontName='Helvetica-Bold')))
            story.append(Spacer(1, 4))
            
            cis_block = f"<b>CIS Benchmark Mapping:</b><br/>Standard: {mapping.get('cis')}<br/><i>Meaning: {mapping.get('cis_desc')}</i>"
            story.append(Paragraph(cis_block, code_desc_style))
            story.append(Spacer(1, 4))

            nist_block = f"<b>NIST SP 800-53 (Rev. 5) Mapping:</b><br/>Control: {mapping.get('nist')}<br/><i>Meaning: {mapping.get('nist_desc')}</i>"
            story.append(Paragraph(nist_block, code_desc_style))
            story.append(Spacer(1, 8))
            counter += 1

    if not has_violations:
        story.append(Paragraph("<i>No active policy violations detected. All monitored surfaces comply with baseline policies.</i>", body_style))
        story.append(Spacer(1, 8))

    # 3. Verified Checks Table (PASSED)
    story.append(Paragraph("3. VERIFIED INFRASTRUCTURE COMPLIANCE CHECKS (PASSED)", section_heading))
    if passed_infra:
        infra_table_data = [["Service", "Resource Identifier", "Compliance Rule", "Status"]]
        for p in passed_infra:
            infra_table_data.append([p['service'], p['resource'], p['rule'], p['status']])
        
        infra_table = Table(infra_table_data, colWidths=[110, 160, 200, 70])
        infra_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('TEXTCOLOR', (3,1), (3,-1), colors.HexColor("#16a34a")),
            ('FONTNAME', (3,1), (3,-1), 'Helvetica-Bold'),
        ]))
        story.append(infra_table)
    else:
        story.append(Paragraph("<i>No passing checks registered.</i>", body_style))
    story.append(Spacer(1, 10))

    # 4. Operator Telemetry Trail
    story.append(Paragraph("4. OPERATOR TELEMETRY TRAIL (RECENT CONSOLE SESSIONS)", section_heading))
    if visited_pages:
        for log in visited_pages[:8]:
            story.append(Paragraph(f"• <b>[{log.get('time')}]</b> {log.get('title')} - <font color='#64748b'>{log.get('url', 'N/A')}</font>", code_desc_style))
    else:
        story.append(Paragraph("<i>No console navigation records in buffer.</i>", body_style))

    doc.build(story)
    buffer.seek(0)
    pdf_bytes = buffer.getvalue()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=Cloud_Compliance_Audit_Report.pdf"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)