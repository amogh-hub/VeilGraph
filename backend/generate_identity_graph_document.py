from __future__ import annotations

import io
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


PAGE_WIDTH, PAGE_HEIGHT = A4


def _field(pdf: canvas.Canvas, y: float, label: str, value: str) -> float:
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(72, y, f"{label}:")
    pdf.setFont("Helvetica", 11)
    pdf.drawString(220, y, value)
    return y - 28


def build_identity_graph_pdf() -> bytes:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.setTitle("Fictional Identity Reconstruction Dossier")
    pdf.setAuthor("VeilGraph synthetic benchmark generator")
    pdf.setSubject("Synthetic identity exposure graph demonstration")

    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(72, PAGE_HEIGHT - 70, "FICTIONAL IDENTITY RECONSTRUCTION DOSSIER")
    pdf.setFont("Helvetica", 9)
    pdf.drawString(72, PAGE_HEIGHT - 88, "Synthetic data only. Designed to test indirect identity reconstruction and audience-specific privacy transformation.")
    y = PAGE_HEIGHT - 130
    y = _field(pdf, y, "Citizen", "Aarav Testperson")
    y = _field(pdf, y, "Date of birth", "11 June 2007")
    y = _field(pdf, y, "Age", "19 years")
    y = _field(pdf, y, "Address", "12 Basalt Lane, Indiranagar, Bengaluru")
    y = _field(pdf, y, "PIN code", "560038")
    y = _field(pdf, y, "Employer", "Kaveri Analytics Pvt Ltd")
    y = _field(pdf, y, "Job title", "Junior Data Analyst")
    y = _field(pdf, y, "Mobile", "+91 98765 43210")
    y = _field(pdf, y, "Email", "aarav.test@example.org")
    y = _field(pdf, y, "Aadhaar-like", "1234 5678 9012")
    y = _field(pdf, y, "PAN-like", "ABCDE1234F")
    y = _field(pdf, y, "Case reference", "VG-2026-00421")
    pdf.setFont("Helvetica-Oblique", 10)
    pdf.drawString(72, y - 16, "Individually ordinary clues become identifying when linked across this dossier.")
    pdf.showPage()

    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(72, PAGE_HEIGHT - 70, "RELATIONSHIP AND CROSS-PAGE CLUES")
    y = PAGE_HEIGHT - 120
    y = _field(pdf, y, "Mother's name", "Meera Testperson")
    y = _field(pdf, y, "Emergency contact", "+91 99887 76655")
    y = _field(pdf, y, "Locality", "Indiranagar, Bengaluru")
    y = _field(pdf, y, "Employer", "Kaveri Analytics Pvt Ltd")
    y = _field(pdf, y, "Case reference", "VG-2026-00421")
    pdf.setFont("Helvetica", 10)
    pdf.drawString(72, y - 10, "The repeated employer and case reference connect this page to the same subject.")
    pdf.drawString(72, y - 28, "The related person's name creates an additional lookup path even after obvious contact fields are hidden.")
    pdf.save()
    return buffer.getvalue()


if __name__ == "__main__":
    target = Path(__file__).with_name("test_identity_graph_document.pdf")
    target.write_bytes(build_identity_graph_pdf())
    print(f"Generated {target} ({target.stat().st_size} bytes)")
