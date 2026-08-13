from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from reportlab import rl_config
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak

from app.extraction.structured_data import (
    StructuredDataset,
    StructuredTable,
    iter_cells,
    parse_structured_data,
    export_xlsx,
)


SUPPORTED_SYNTHETIC_EXPORT_FORMATS = ("csv", "json", "xlsx", "docx", "pdf")


@dataclass(frozen=True)
class SyntheticExportArtifact:
    data: bytes
    extension: str
    media_type: str
    report: dict[str, Any]


def _source_dataset(data: bytes, source_name: str) -> StructuredDataset:
    return parse_structured_data(data, source_name)


def _json_long_rows(dataset: StructuredDataset) -> StructuredTable:
    rows: list[list[Any]] = []
    for cell in iter_cells(dataset):
        locator = "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in cell.locator)
        rows.append([cell.record_index + 1, cell.header, locator, cell.value])
    return StructuredTable("Synthetic JSON", ["record", "field", "json_pointer", "value"], rows)


def _tables_for_cross_format(dataset: StructuredDataset) -> list[StructuredTable]:
    if dataset.format == "json":
        return [_json_long_rows(dataset)]
    return [StructuredTable(table.name, list(table.headers), [list(row) for row in table.rows]) for table in dataset.tables]


def _csv_bytes(dataset: StructuredDataset) -> bytes:
    tables = _tables_for_cross_format(dataset)
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    if len(tables) == 1:
        table = tables[0]
        writer.writerow(table.headers)
        writer.writerows(table.rows)
    else:
        writer.writerow(["sheet", "record", "field", "value"])
        for table in tables:
            for row_idx, row in enumerate(table.rows, start=1):
                for col_idx, header in enumerate(table.headers):
                    value = row[col_idx] if col_idx < len(row) else ""
                    writer.writerow([table.name, row_idx, header, value])
    return out.getvalue().encode("utf-8")


def _json_bytes(dataset: StructuredDataset) -> bytes:
    if dataset.format == "json":
        payload = dataset.json_root
    else:
        payload = {
            "schema": "veilgraph.synthetic-export.v1",
            "source_structured_format": dataset.format,
            "tables": [
                {
                    "name": table.name,
                    "headers": table.headers,
                    "rows": [
                        {header: (row[idx] if idx < len(row) else None) for idx, header in enumerate(table.headers)}
                        for row in table.rows
                    ],
                }
                for table in dataset.tables
            ],
        }
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _xlsx_bytes(dataset: StructuredDataset) -> bytes:
    tables = _tables_for_cross_format(dataset)
    converted = StructuredDataset(format="xlsx", tables=tables)
    return export_xlsx(converted)


def _display(value: Any, limit: int = 220) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\x00", "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _xml_escape(value: Any) -> str:
    text = _display(value)
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;"))


def _docx_paragraph(text: str = "", *, bold: bool = False, size_half_points: int | None = None, page_break: bool = False) -> str:
    if page_break:
        return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'
    rpr = ""
    if bold or size_half_points:
        bits = []
        if bold:
            bits.append("<w:b/>")
        if size_half_points:
            bits.append(f'<w:sz w:val="{int(size_half_points)}"/><w:szCs w:val="{int(size_half_points)}"/>')
        rpr = "<w:rPr>" + "".join(bits) + "</w:rPr>"
    return f'<w:p><w:r>{rpr}<w:t xml:space="preserve">{_xml_escape(text)}</w:t></w:r></w:p>'


def _docx_cell(value: Any, *, bold: bool = False) -> str:
    rpr = "<w:rPr><w:b/></w:rPr>" if bold else ""
    return (
        '<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr>'
        f'<w:p><w:r>{rpr}<w:t xml:space="preserve">{_xml_escape(value)}</w:t></w:r></w:p></w:tc>'
    )


def _docx_table(table: StructuredTable) -> str:
    headers = list(table.headers) or ["value"]
    rows = [list(row) for row in table.rows]
    grid = "".join('<w:gridCol w:w="2400"/>' for _ in headers)
    borders = ''.join(
        f'<w:{edge} w:val="single" w:sz="4" w:space="0" w:color="B8C2CC"/>'
        for edge in ("top", "left", "bottom", "right", "insideH", "insideV")
    )
    parts = [
        '<w:tbl>',
        '<w:tblPr><w:tblW w:w="0" w:type="auto"/><w:tblBorders>', borders, '</w:tblBorders></w:tblPr>',
        '<w:tblGrid>', grid, '</w:tblGrid>',
        '<w:tr>', ''.join(_docx_cell(h, bold=True) for h in headers), '</w:tr>',
    ]
    for row in rows:
        parts.extend([
            '<w:tr>',
            ''.join(_docx_cell(row[idx] if idx < len(row) else "") for idx in range(len(headers))),
            '</w:tr>',
        ])
    parts.append('</w:tbl>')
    return ''.join(parts)


def _docx_bytes(dataset: StructuredDataset, source_sha256: str) -> bytes:
    """Build deterministic OOXML directly so Phase 3 adds no runtime dependency."""
    tables = _tables_for_cross_format(dataset)
    body = [
        _docx_paragraph("VeilGraph Synthetic Twin Export", bold=True, size_half_points=32),
        _docx_paragraph(
            "This document is a representation of an already-generated Level 5 Synthetic Twin. "
            "It does not regenerate values and therefore does not reintroduce source records."
        ),
        _docx_paragraph(f"Synthetic source SHA-256: {source_sha256}"),
    ]
    for table_index, table in enumerate(tables):
        if table_index:
            body.append(_docx_paragraph(page_break=True))
        body.append(_docx_paragraph(table.name or f"Table {table_index + 1}", bold=True, size_half_points=26))
        body.append(_docx_table(table))
    body.append(
        '<w:sectPr><w:pgSz w:w="16838" w:h="11906" w:orient="landscape"/>'
        '<w:pgMar w:top="720" w:right="720" w:bottom="720" w:left="720" w:header="360" w:footer="360" w:gutter="0"/></w:sectPr>'
    )

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<w:body>' + ''.join(body) + '</w:body></w:document>'
    ).encode("utf-8")
    content_types = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>'''
    rels = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>'''
    core = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>VeilGraph Synthetic Twin Export</dc:title>
  <dc:subject>Verified synthetic data representation</dc:subject>
  <dc:creator>VeilGraph</dc:creator>
  <cp:lastModifiedBy>VeilGraph</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">1980-01-01T00:00:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">1980-01-01T00:00:00Z</dcterms:modified>
</cp:coreProperties>'''
    app = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>VeilGraph</Application>
  <AppVersion>13.1</AppVersion>
</Properties>'''

    members = {
        "[Content_Types].xml": content_types,
        "_rels/.rels": rels,
        "docProps/app.xml": app,
        "docProps/core.xml": core,
        "word/document.xml": document_xml,
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as target:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            target.writestr(info, members[name])
    return stream.getvalue()


def _pdf_bytes(dataset: StructuredDataset, source_sha256: str) -> bytes:
    stream = io.BytesIO()
    previous_invariant = rl_config.invariant
    rl_config.invariant = 1
    doc = SimpleDocTemplate(
        stream,
        pagesize=landscape(A4),
        leftMargin=24,
        rightMargin=24,
        topMargin=28,
        bottomMargin=28,
        title="VeilGraph Synthetic Twin Export",
        author="VeilGraph",
    )
    styles = getSampleStyleSheet()
    story: list[Any] = [
        Paragraph("VeilGraph Synthetic Twin Export", styles["Title"]),
        Spacer(1, 8),
        Paragraph(
            "Representation of an already-generated Level 5 Synthetic Twin. Values are not regenerated during export.",
            styles["BodyText"],
        ),
        Spacer(1, 4),
        Paragraph(f"Synthetic source SHA-256: {source_sha256}", styles["Code"]),
        Spacer(1, 12),
    ]
    tables = _tables_for_cross_format(dataset)
    for table_index, table in enumerate(tables):
        if table_index:
            story.append(PageBreak())
        story.append(Paragraph(table.name or f"Table {table_index + 1}", styles["Heading2"]))
        rows = [[_display(header, 80) for header in table.headers]]
        rows.extend([[_display(row[idx] if idx < len(row) else "", 120) for idx in range(len(table.headers))] for row in table.rows])
        if not rows or not table.headers:
            rows = [["No tabular fields"]]
        t = Table(rows, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9EDF3")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 6.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t)
    try:
        doc.build(story)
        return stream.getvalue()
    finally:
        rl_config.invariant = previous_invariant


def export_synthetic_representation(
    synthetic_bytes: bytes,
    source_name: str,
    target_format: str,
) -> SyntheticExportArtifact:
    target = target_format.strip().casefold().lstrip(".")
    if target not in SUPPORTED_SYNTHETIC_EXPORT_FORMATS:
        raise ValueError(f"Unsupported synthetic export format: {target_format}")
    dataset = _source_dataset(synthetic_bytes, source_name)
    source_sha = hashlib.sha256(synthetic_bytes).hexdigest()
    if target == "csv":
        data, media = _csv_bytes(dataset), "text/csv; charset=utf-8"
    elif target == "json":
        data, media = _json_bytes(dataset), "application/json"
    elif target == "xlsx":
        data, media = _xlsx_bytes(dataset), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif target == "docx":
        data, media = _docx_bytes(dataset, source_sha), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        data, media = _pdf_bytes(dataset, source_sha), "application/pdf"
    report = {
        "schema": "veilgraph.synthetic-format-export.v1",
        "source_synthetic_sha256": source_sha,
        "source_structured_format": dataset.format,
        "target_format": target,
        "record_count": dataset.record_count,
        "field_count": dataset.field_count,
        "export_sha256": hashlib.sha256(data).hexdigest(),
        "export_size_bytes": len(data),
        "semantic_boundary": (
            "Format conversion only. Synthetic values are not regenerated and the exporter has no access to the original source artifact."
        ),
    }
    return SyntheticExportArtifact(data=data, extension=f".{target}", media_type=media, report=report)
