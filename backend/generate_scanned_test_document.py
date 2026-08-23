from __future__ import annotations

import io
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = []
    if bold:
        candidates.extend([
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ])
    candidates.extend([
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ])
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def _qr(text: str, size: int = 280) -> Image.Image:
    encoder = cv2.QRCodeEncoder_create()
    raw = encoder.encode(text)
    resized = cv2.resize(raw, (size, size), interpolation=cv2.INTER_NEAREST)
    return Image.fromarray(resized).convert("RGB")


def _base_page(title: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    page = Image.new("RGB", (1654, 2339), "white")
    draw = ImageDraw.Draw(page)
    draw.rectangle((70, 60, 1584, 2270), outline=(70, 80, 100), width=3)
    draw.text((110, 95), title, fill="black", font=_font(54, bold=True))
    draw.line((110, 175, 1540, 175), fill=(90, 100, 120), width=3)
    return page, draw


def build_scanned_pages() -> list[Image.Image]:
    page1, draw1 = _base_page("FICTIONAL SERVICE APPLICATION — SCANNED COPY")
    label_font = _font(34, bold=True)
    value_font = _font(38)
    rows = [
        ("Citizen", "Aarav Testperson"),
        ("Mobile", "+91 98765 43210"),
        ("Email", "aarav.test@example.org"),
        ("Aadhaar-like", "1234 5678 9012"),
        ("PAN-like", "ABCDE1234F"),
    ]
    y = 245
    for label, value in rows:
        draw1.text((125, y), f"{label}:", fill=(20, 25, 35), font=label_font)
        draw1.text((500, y), value, fill="black", font=value_font)
        y += 95

    draw1.text((125, 780), "Identity QR:", fill=(20, 25, 35), font=label_font)
    qr = _qr("VEILGRAPH-FICTIONAL-QR-AARAV-9876543210")
    page1.paste(qr, (500, 740))

    draw1.text((125, 1130), "Signature:", fill=(20, 25, 35), font=label_font)
    # Synthetic signature-like squiggle under the label.
    points = [(320, 1250), (390, 1195), (450, 1270), (530, 1175), (610, 1265), (720, 1190), (840, 1250)]
    draw1.line(points, fill=(15, 25, 70), width=8, joint="curve")
    draw1.arc((350, 1180, 610, 1330), start=190, end=350, fill=(15, 25, 70), width=6)
    draw1.text((125, 1450), "Case note: Synthetic data generated only for VeilGraph testing.", fill="black", font=_font(32))

    page2, draw2 = _base_page("FICTIONAL FOLLOW-UP — SCANNED COPY")
    draw2.text((125, 270), "Repeated mobile:", fill=(20, 25, 35), font=label_font)
    draw2.text((520, 270), "+91 98765 43210", fill="black", font=value_font)
    draw2.text((125, 380), "Secondary email:", fill=(20, 25, 35), font=label_font)
    draw2.text((520, 380), "review.team@example.org", fill="black", font=value_font)
    draw2.text((125, 490), "Office contact:", fill=(20, 25, 35), font=label_font)
    draw2.text((520, 490), "080-2345-6789", fill="black", font=value_font)
    draw2.text((125, 650), "This page intentionally repeats an identifier to prove cross-page protection.", fill="black", font=_font(30))
    return [page1, page2]


def build_scanned_pdf() -> bytes:
    pages = build_scanned_pages()
    buffer = io.BytesIO()
    pages[0].save(buffer, format="PDF", save_all=True, append_images=pages[1:], resolution=200.0)
    return buffer.getvalue()


def build_scanned_png() -> bytes:
    buffer = io.BytesIO()
    build_scanned_pages()[0].save(buffer, format="PNG")
    return buffer.getvalue()


if __name__ == "__main__":
    directory = Path(__file__).parent
    pdf_path = directory / "test_scanned_document.pdf"
    png_path = directory / "test_scanned_page.png"
    pdf_path.write_bytes(build_scanned_pdf())
    png_path.write_bytes(build_scanned_png())
    print(f"Generated {pdf_path} ({pdf_path.stat().st_size} bytes)")
    print(f"Generated {png_path} ({png_path.stat().st_size} bytes)")
