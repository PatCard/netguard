from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from datetime import datetime
import io

def calculate_security_score(vulnerabilities: list, weak_configs: list, hosts: list) -> dict:
    """
    Calcula un score de seguridad del 0 al 100 para cada host y la red completa.
    """
    host_scores = {}

    for host in hosts:
        ip = host["ip"]
        score = 100

        # Restar por configuraciones débiles
        host_weak = [w for w in weak_configs if w["host"] == ip]
        for wc in host_weak:
            for warning in wc["warnings"]:
                if warning["severity"] == "HIGH":
                    score -= 20
                else:
                    score -= 10

        # Restar por vulnerabilidades CVE
        host_vulns = [v for v in vulnerabilities if v["host"] == ip]
        for vuln in host_vulns:
            for cve in vuln.get("top_cves", []):
                severity = cve.get("severity", "")
                if severity == "CRITICAL":
                    score -= 25
                elif severity == "HIGH":
                    score -= 15
                elif severity == "MEDIUM":
                    score -= 8
                else:
                    score -= 3

        score = max(0, score)
        host_scores[ip] = {
            "ip": ip,
            "hostname": host.get("hostname", ""),
            "score": score,
            "grade": get_grade(score)
        }

    # Score global
    if host_scores:
        global_score = int(sum(h["score"] for h in host_scores.values()) / len(host_scores))
    else:
        global_score = 100

    return {
        "global_score": global_score,
        "global_grade": get_grade(global_score),
        "host_scores": list(host_scores.values())
    }

def get_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

def generate_pdf_report(audit_result: dict) -> bytes:
    """
    Genera un reporte PDF profesional de la auditoría de red.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    story = []

    # Colores
    primary = HexColor("#0f172a")
    accent  = HexColor("#0070f3")
    danger  = HexColor("#ef4444")
    warning = HexColor("#eab308")
    success = HexColor("#22c55e")

    # Título
    title_style = ParagraphStyle("title", parent=styles["Title"], textColor=primary, fontSize=24, spaceAfter=6)
    subtitle_style = ParagraphStyle("subtitle", parent=styles["Normal"], textColor=accent, fontSize=12, spaceAfter=20)
    story.append(Paragraph("🛡️ NetGuard", title_style))
    story.append(Paragraph(f"Reporte de Auditoría de Seguridad de Red", subtitle_style))
    story.append(Paragraph(f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles["Normal"]))
    story.append(Spacer(1, 0.3*inch))

    # Score global
    scores = calculate_security_score(
        audit_result.get("vulnerabilities", []),
        audit_result.get("weak_configs", []),
        audit_result.get("hosts", [])
    )

    global_score = scores["global_score"]
    grade = scores["global_grade"]
    score_color = success if global_score >= 75 else (warning if global_score >= 50 else danger)

    score_style = ParagraphStyle("score", parent=styles["Normal"], fontSize=14, spaceAfter=6)
    story.append(Paragraph(f"<b>Score de Seguridad Global: {global_score}/100 — Grado {grade}</b>", score_style))
    story.append(Spacer(1, 0.2*inch))

    # Resumen ejecutivo
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=primary)
    story.append(Paragraph("Resumen Ejecutivo", h2))

    summary_data = [
        ["Métrica", "Valor"],
        ["Red auditada", audit_result.get("network", "N/A")],
        ["Hosts activos", str(len(audit_result.get("hosts", [])))],
        ["Servicios vulnerables", str(len(audit_result.get("vulnerabilities", [])))],
        ["Configuraciones débiles", str(sum(len(w["warnings"]) for w in audit_result.get("weak_configs", [])))],
        ["Dispositivos nuevos", str(len(audit_result.get("new_devices", [])))],
    ]

    summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), primary),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#f8fafc")]),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))

    # Score por host
    story.append(Paragraph("Score de Seguridad por Host", h2))
    host_data = [["IP", "Hostname", "Score", "Grado"]]
    for hs in scores["host_scores"]:
        host_data.append([hs["ip"], hs["hostname"] or "-", str(hs["score"]), hs["grade"]])

    host_table = Table(host_data, colWidths=[2*inch, 2*inch, 1.5*inch, 1.5*inch])
    host_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#f8fafc")]),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(host_table)
    story.append(Spacer(1, 0.3*inch))

    # Configuraciones débiles
    if audit_result.get("weak_configs"):
        story.append(Paragraph("⚠️ Configuraciones Débiles", h2))
        for wc in audit_result["weak_configs"]:
            story.append(Paragraph(f"<b>{wc['host']}</b>", styles["Normal"]))
            for w in wc["warnings"]:
                story.append(Paragraph(f"• Puerto {w['port']}: {w['warning']} [{w['severity']}]", styles["Normal"]))
            story.append(Spacer(1, 0.1*inch))

    # Vulnerabilidades CVE
    if audit_result.get("vulnerabilities"):
        story.append(Paragraph("🔴 Vulnerabilidades CVE", h2))
        vuln_data = [["Host", "Puerto", "Servicio", "CVEs", "Top CVE"]]
        for v in audit_result["vulnerabilities"]:
            top = v["top_cves"][0] if v["top_cves"] else {}
            vuln_data.append([
                v["host"],
                str(v["port"]),
                v["service"],
                str(v["total_cves"]),
                f"{top.get('id','N/A')} [{top.get('severity','N/A')}]"
            ])

        vuln_table = Table(vuln_data, colWidths=[1.5*inch, 0.8*inch, 1.2*inch, 0.8*inch, 2.7*inch])
        vuln_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), danger),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#fff5f5")]),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(vuln_table)

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
