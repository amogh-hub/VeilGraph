from __future__ import annotations

import io
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib import colors


def build_test_pdf() -> bytes:
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title="Fictional Citizen Service Record",
        author="Fictional District Officer",
        creator="Synthetic Government Records System",
        subject="Safe test data for VeilGraph",
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("<b>FICTIONAL CITIZEN SERVICE RECORD</b>", styles["Title"]),
        Spacer(1, 12),
        Table(
            [
                ["Field", "Synthetic value"],
                ["Citizen", "Aarav Testperson"],
                ["Primary mobile", "+91 98765 43210"],
                ["Office contact", "080-2345-6789"],
                ["Case note", "Use only for VeilGraph tests"],
            ],
            colWidths=[150, 300],
            style=TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ]),
        ),
        Spacer(1, 18),
        Paragraph("Emergency contact: +91 99001 23456", styles["BodyText"]),
        PageBreak(),
        Paragraph("<b>FOLLOW-UP PAGE</b>", styles["Heading1"]),
        Spacer(1, 12),
        Paragraph("Repeated primary mobile for consistency check: +91 98765 43210", styles["BodyText"]),
        Paragraph("Secondary contact: 8765432109", styles["BodyText"]),
    ]
    document.build(story)
    return buffer.getvalue()


if __name__ == "__main__":
    target = Path(__file__).with_name("test_document.pdf")
    target.write_bytes(build_test_pdf())
    print(f"Generated {target} ({target.stat().st_size} bytes)")
