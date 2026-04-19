from fpdf import FPDF
import json
from datetime import datetime
from pathlib import Path

BRAND = "CosmoGrepperAI - Advanced Security Scanner"

class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 14)
        self.cell(0, 10, BRAND, ln=True, align="C")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Generated {datetime.utcnow().isoformat()}Z", align="C")

def severity_color(pdf, severity):
    if severity == 5:
        pdf.set_text_color(200, 0, 0)
    elif severity == 4:
        pdf.set_text_color(255, 100, 0)
    elif severity == 3:
        pdf.set_text_color(200, 150, 0)
    elif severity == 2:
        pdf.set_text_color(0, 100, 200)
    else:
        pdf.set_text_color(120, 120, 120)

def export_pdf(report_path: str, output_path: str):
    print("[+] Starting PDF export...")  # DEBUG LINE

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))

    pdf = PDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 15, "Security Scan Report", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Target: {report['target']}", ln=True)
    pdf.cell(0, 10, f"Generated: {report['generated_at']}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Findings", ln=True)
    pdf.ln(5)

    for f in report["findings"]:
        sev = f.get("severity_score", 1)

        severity_color(pdf, sev)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, f"[Severity {sev}] {f['title']}", ln=True)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", "", 11)
        pdf.multi_cell(0, 6, f"File: {f['file']} (line {f['line']})")
        pdf.multi_cell(0, 6, f"Risk Score: {f['risk']['risk_score']}")
        
        vuln_explain = f.get("vulnerability_explanation", "")
        if vuln_explain and vuln_explain.strip():
            pdf.ln(2)
            pdf.set_font("Arial", "B", 11)
            pdf.set_text_color(249, 115, 22)  # Orange/warning
            pdf.cell(0, 8, "Why This Code Is Vulnerable:", ln=True)
            pdf.set_font("Arial", "", 10)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 5, vuln_explain)

        mitigation = f.get("mitigation", "")
        if mitigation and mitigation.strip():
            pdf.ln(2)
            pdf.set_font("Arial", "B", 11)
            pdf.set_text_color(16, 185, 129)  # Success green
            pdf.cell(0, 8, "How To Fix (Mitigation):", ln=True)
            pdf.set_font("Arial", "", 10)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 5, mitigation)
        
        pdf.ln(5)

    pdf.output(output_path)
    print(f"[+] PDF exported to {output_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python export_pdf.py <report.json> <output.pdf>")
        sys.exit(1)

    export_pdf(sys.argv[1], sys.argv[2])
