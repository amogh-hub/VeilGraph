from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import posixpath
import re
import zipfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET

from PIL import Image, ImageDraw, ImageFont

from app.core.enums import DetectionSource, FileType
from app.extraction.document_processor import PageFrame, PositionedLine, PositionedToken, ProcessedDocument


class StructuredDataError(ValueError):
    pass


DATASET_EXTENSIONS = {".csv", ".json", ".xlsx"}
XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

_MAX_ROWS = 20_000
_MAX_COLUMNS = 256
_MAX_CELLS = 250_000
_MAX_CELL_CHARS = 32_768
_MAX_ZIP_FILES = 2_000
_MAX_ZIP_UNCOMPRESSED = 64 * 1024 * 1024

_FORBIDDEN_XLSX_MARKERS = (
    "vbaproject.bin",
    "externallinks/",
    "embeddings/",
    "activex/",
    "customxml/",
    "connections.xml",
    "querytables/",
)


@dataclass(frozen=True)
class StructuredCell:
    sheet_index: int
    record_index: int
    column_index: int
    header: str
    value: Any
    locator: tuple[Any, ...]

    @property
    def display_value(self) -> str:
        if self.value is None:
            return ""
        if isinstance(self.value, bool):
            return "true" if self.value else "false"
        if isinstance(self.value, float) and math.isfinite(self.value) and self.value.is_integer():
            return str(int(self.value))
        return str(self.value)


@dataclass
class StructuredTable:
    name: str
    headers: list[str]
    rows: list[list[Any]]


@dataclass
class StructuredDataset:
    format: str
    tables: list[StructuredTable]
    json_root: Any | None = None

    @property
    def record_count(self) -> int:
        if self.format == "json":
            return _json_record_count(self.json_root)
        return sum(len(table.rows) for table in self.tables)

    @property
    def field_count(self) -> int:
        if self.format == "json":
            return len({cell.header for cell in iter_cells(self)})
        return max((len(table.headers) for table in self.tables), default=0)

    @property
    def sheet_count(self) -> int:
        return len(self.tables) if self.format != "json" else 1


def _safe_text(data: bytes) -> str:
    if b"\x00" in data:
        raise StructuredDataError("Structured text contains NUL bytes")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise StructuredDataError("CSV/JSON structured inputs must be UTF-8 encoded") from exc


def _clean_header(value: Any, index: int) -> str:
    text = re.sub(r"\s+", " ", str(value or "").strip())
    if not text:
        text = f"column_{index + 1}"
    return text[:160]


def _dedupe_headers(headers: list[str]) -> list[str]:
    counts: dict[str, int] = {}
    result: list[str] = []
    for index, header in enumerate(headers):
        base = _clean_header(header, index)
        key = base.casefold()
        counts[key] = counts.get(key, 0) + 1
        result.append(base if counts[key] == 1 else f"{base}#{counts[key]}")
    return result


def _check_dimensions(rows: int, columns: int, cells: int) -> None:
    if rows > _MAX_ROWS:
        raise StructuredDataError(f"Dataset exceeds the secure {_MAX_ROWS:,}-record analysis limit")
    if columns > _MAX_COLUMNS:
        raise StructuredDataError(f"Dataset exceeds the secure {_MAX_COLUMNS}-column analysis limit")
    if cells > _MAX_CELLS:
        raise StructuredDataError(f"Dataset exceeds the secure {_MAX_CELLS:,}-cell analysis limit")


def _check_cell(value: Any) -> None:
    if value is None:
        return
    if len(str(value)) > _MAX_CELL_CHARS:
        raise StructuredDataError(f"A dataset cell exceeds the {_MAX_CELL_CHARS:,}-character limit")


def parse_csv(data: bytes) -> StructuredDataset:
    text = _safe_text(data)
    try:
        sample = text[:8192]
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|") if sample.strip() else csv.excel
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text, newline=""), dialect)
    rows = list(reader)
    if not rows:
        raise StructuredDataError("CSV contains no rows")
    headers = _dedupe_headers(rows[0])
    if not headers:
        raise StructuredDataError("CSV contains no columns")
    values: list[list[Any]] = []
    for raw in rows[1:]:
        row = list(raw[: len(headers)]) + [""] * max(0, len(headers) - len(raw))
        for value in row:
            _check_cell(value)
        values.append(row)
    _check_dimensions(len(values), len(headers), len(values) * len(headers))
    return StructuredDataset(format="csv", tables=[StructuredTable("Dataset", headers, values)])


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StructuredDataError(f"JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes) -> StructuredDataset:
    text = _safe_text(data)
    try:
        root = json.loads(text, object_pairs_hook=_no_duplicate_object)
    except StructuredDataError:
        raise
    except json.JSONDecodeError as exc:
        raise StructuredDataError(f"Invalid JSON: {exc.msg}") from exc
    if not isinstance(root, (dict, list)):
        raise StructuredDataError("JSON dataset root must be an object or array")
    cells = list(_iter_json_cells(root))
    if not cells:
        raise StructuredDataError("JSON dataset contains no scalar values")
    for cell in cells:
        _check_cell(cell.value)
    _check_dimensions(_json_record_count(root), len({cell.header for cell in cells}), len(cells))
    return StructuredDataset(format="json", tables=[StructuredTable("JSON", [], [])], json_root=root)


def _zip_guard(archive: zipfile.ZipFile) -> None:
    infos = archive.infolist()
    if len(infos) > _MAX_ZIP_FILES:
        raise StructuredDataError("XLSX contains too many ZIP members")
    total = 0
    for info in infos:
        normalized = posixpath.normpath(info.filename.replace("\\", "/")).lstrip("/")
        if normalized.startswith("../") or "/../" in normalized:
            raise StructuredDataError("XLSX contains an unsafe archive path")
        total += max(0, int(info.file_size))
        if total > _MAX_ZIP_UNCOMPRESSED:
            raise StructuredDataError("XLSX exceeds the secure uncompressed-size budget")
        lowered = normalized.casefold()
        if any(marker in lowered for marker in _FORBIDDEN_XLSX_MARKERS):
            raise StructuredDataError(f"XLSX contains unsupported active/external content: {normalized}")


def _xlsx_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    try:
        root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    except KeyError:
        return []
    except ET.ParseError as exc:
        raise StructuredDataError("Invalid XLSX shared strings") from exc
    values: list[str] = []
    for item in root.findall("{*}si"):
        values.append("".join(node.text or "" for node in item.findall(".//{*}t")))
    return values


def _xlsx_rel_targets(archive: zipfile.ZipFile) -> dict[str, str]:
    try:
        root = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    except (KeyError, ET.ParseError) as exc:
        raise StructuredDataError("XLSX workbook relationships are missing or invalid") from exc
    rels: dict[str, str] = {}
    for rel in root.findall("{*}Relationship"):
        rel_id = rel.attrib.get("Id")
        target = rel.attrib.get("Target")
        mode = rel.attrib.get("TargetMode", "Internal")
        if mode.casefold() == "external":
            raise StructuredDataError("XLSX external relationships are not accepted")
        if rel_id and target:
            rels[rel_id] = posixpath.normpath(target.lstrip("/")) if target.startswith("/") else posixpath.normpath(posixpath.join("xl", target))
    return rels


def _column_index(reference: str) -> int:
    letters = re.match(r"[A-Za-z]+", reference or "")
    if not letters:
        return 0
    value = 0
    for char in letters.group(0).upper():
        value = value * 26 + (ord(char) - 64)
    return max(0, value - 1)


def _parse_xlsx_cell(cell: ET.Element, shared: list[str]) -> Any:
    if cell.find("{*}f") is not None:
        raise StructuredDataError("Formula-bearing XLSX cells are fail-closed in secure dataset mode; export values-only XLSX")
    cell_type = cell.attrib.get("t", "n")
    if cell_type == "inlineStr":
        return "".join(node.text or "" for node in cell.findall(".//{*}t"))
    value_node = cell.find("{*}v")
    raw = value_node.text if value_node is not None and value_node.text is not None else ""
    if cell_type == "s":
        try:
            return shared[int(raw)]
        except (ValueError, IndexError) as exc:
            raise StructuredDataError("XLSX shared-string index is invalid") from exc
    if cell_type == "b":
        return raw == "1"
    if cell_type in {"str", "e"}:
        return raw
    if raw == "":
        return ""
    try:
        numeric = float(raw)
        return int(numeric) if numeric.is_integer() else numeric
    except ValueError:
        return raw


def parse_xlsx(data: bytes) -> StructuredDataset:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise StructuredDataError("Invalid XLSX ZIP container") from exc
    with archive:
        _zip_guard(archive)
        required = {"[Content_Types].xml", "xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
        if not required.issubset(set(archive.namelist())):
            raise StructuredDataError("XLSX container is missing required workbook parts")
        shared = _xlsx_shared_strings(archive)
        rels = _xlsx_rel_targets(archive)
        try:
            workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        except ET.ParseError as exc:
            raise StructuredDataError("Invalid XLSX workbook XML") from exc

        tables: list[StructuredTable] = []
        total_cells = 0
        total_rows = 0
        for sheet_index, sheet in enumerate(workbook.findall(".//{*}sheet")):
            name = re.sub(r"[\x00-\x1f]", "", sheet.attrib.get("name", f"Sheet{sheet_index + 1}"))[:31] or f"Sheet{sheet_index + 1}"
            rel_id = sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
            target = rels.get(rel_id or "")
            if not target:
                raise StructuredDataError(f"XLSX worksheet relationship is missing for {name}")
            try:
                root = ET.fromstring(archive.read(target))
            except (KeyError, ET.ParseError) as exc:
                raise StructuredDataError(f"XLSX worksheet {name} is missing or invalid") from exc
            raw_rows: list[list[Any]] = []
            max_col = 0
            for row in root.findall(".//{*}sheetData/{*}row"):
                values_by_col: dict[int, Any] = {}
                for cell in row.findall("{*}c"):
                    col = _column_index(cell.attrib.get("r", ""))
                    value = _parse_xlsx_cell(cell, shared)
                    _check_cell(value)
                    values_by_col[col] = value
                    max_col = max(max_col, col + 1)
                if values_by_col:
                    raw_rows.append([values_by_col.get(index, "") for index in range(max_col)])
            if not raw_rows:
                continue
            width = max(len(row) for row in raw_rows)
            headers = _dedupe_headers(list(raw_rows[0]) + [""] * (width - len(raw_rows[0])))
            values = [list(row) + [""] * (width - len(row)) for row in raw_rows[1:]]
            tables.append(StructuredTable(name=name, headers=headers, rows=values))
            total_rows += len(values)
            total_cells += len(values) * len(headers)
            _check_dimensions(total_rows, max((len(t.headers) for t in tables), default=0), total_cells)
        if not tables:
            raise StructuredDataError("XLSX contains no usable tabular worksheets")
        return StructuredDataset(format="xlsx", tables=tables)


def detect_structured_format(data: bytes, source_filename: str | None = None) -> str:
    extension = Path(source_filename or "").suffix.lower()
    if extension in DATASET_EXTENSIONS:
        return extension[1:]
    if data.startswith(b"PK\x03\x04"):
        return "xlsx"
    stripped = data.lstrip()
    if stripped.startswith((b"{", b"[")):
        return "json"
    return "csv"


def parse_structured_data(data: bytes, source_filename: str | None = None) -> StructuredDataset:
    fmt = detect_structured_format(data, source_filename)
    if fmt == "csv":
        return parse_csv(data)
    if fmt == "json":
        return parse_json(data)
    if fmt == "xlsx":
        return parse_xlsx(data)
    raise StructuredDataError(f"Unsupported structured-data format: {fmt}")


def _iter_json_leaves(value: Any, path: tuple[Any, ...]) -> Iterable[tuple[tuple[Any, ...], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_json_leaves(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_json_leaves(child, path + (index,))
    else:
        yield path, value


def _json_record_count(root: Any) -> int:
    if isinstance(root, list):
        return max(1, len(root))
    return 1


def _json_header(path: tuple[Any, ...]) -> str:
    parts = [str(part) for part in path if not isinstance(part, int)]
    return ".".join(parts[-4:]) if parts else "value"


def _iter_json_cells(root: Any) -> Iterable[StructuredCell]:
    if isinstance(root, list):
        for record_index, record in enumerate(root):
            for column_index, (path, value) in enumerate(_iter_json_leaves(record, (record_index,))):
                yield StructuredCell(0, record_index, column_index, _json_header(path), value, path)
    else:
        for column_index, (path, value) in enumerate(_iter_json_leaves(root, ())):
            yield StructuredCell(0, 0, column_index, _json_header(path), value, path)


def iter_cells(dataset: StructuredDataset) -> Iterable[StructuredCell]:
    if dataset.format == "json":
        assert dataset.json_root is not None
        yield from _iter_json_cells(dataset.json_root)
        return
    record_offset = 0
    for sheet_index, table in enumerate(dataset.tables):
        for row_index, row in enumerate(table.rows):
            for column_index, header in enumerate(table.headers):
                value = row[column_index] if column_index < len(row) else ""
                yield StructuredCell(sheet_index, record_offset + row_index, column_index, header, value, (sheet_index, row_index, column_index))
        record_offset += len(table.rows)


def _font(size: int = 18) -> ImageFont.ImageFont:
    for candidate in (
        "/System/Library/Fonts/Supplemental/Menlo.ttc",
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ):
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def _record_groups(dataset: StructuredDataset) -> list[list[StructuredCell]]:
    groups: dict[tuple[int, int], list[StructuredCell]] = {}
    for cell in iter_cells(dataset):
        groups.setdefault((cell.sheet_index, cell.record_index), []).append(cell)
    return [groups[key] for key in sorted(groups)]


@dataclass(frozen=True)
class VirtualStructuredCell:
    page_index: int
    line_char_start: int
    line_char_end: int
    value_char_start: int
    value_char_end: int
    cell: StructuredCell


def virtual_cell_index(dataset: StructuredDataset) -> list[VirtualStructuredCell]:
    refs: list[VirtualStructuredCell] = []
    for page_index, cells in enumerate(_record_groups(dataset)):
        offset = 0
        for cell in sorted(cells, key=lambda item: (item.sheet_index, item.column_index, item.header.casefold())):
            prefix = f"{cell.header}: "
            value = cell.display_value
            line = prefix + value
            refs.append(
                VirtualStructuredCell(
                    page_index=page_index,
                    line_char_start=offset,
                    line_char_end=offset + len(line),
                    value_char_start=offset + len(prefix),
                    value_char_end=offset + len(line),
                    cell=cell,
                )
            )
            offset += len(line) + 1
    return refs


_STRUCTURED_PREVIEW_WIDTH = 1200
_STRUCTURED_PREVIEW_MIN_HEIGHT = 300
_STRUCTURED_PREVIEW_TOP = 45.0
_STRUCTURED_PREVIEW_ROW_GAP = 31.0
_STRUCTURED_PREVIEW_TOKEN_HEIGHT = 23.0
_STRUCTURED_PREVIEW_HEADER_X = 50.0


def _structured_row_geometry(cell: StructuredCell, line_no: int) -> tuple[str, str, float, float, float, float]:
    """Return the single source of truth for TABLE IR and GUI preview geometry.

    Detector coordinates are persisted as evidence and later drawn back onto the
    record preview. Keeping extraction and rendering on the same geometry avoids
    presentation drift without changing any detector or privacy decision.
    """

    prefix = f"{cell.header}:"
    value = cell.display_value
    y0 = _STRUCTURED_PREVIEW_TOP + line_no * _STRUCTURED_PREVIEW_ROW_GAP
    header_width = min(480.0, max(110.0, len(prefix) * 10.0))
    value_x0 = header_width + 70.0
    value_width = min(900.0, max(60.0, len(value) * 10.0))
    return prefix, value, y0, header_width, value_x0, value_width


def _structured_preview_height(row_count: int) -> int:
    return max(_STRUCTURED_PREVIEW_MIN_HEIGHT, int(100.0 + row_count * _STRUCTURED_PREVIEW_ROW_GAP))


def structured_to_processed_document(data: bytes, source_filename: str | None = None) -> ProcessedDocument:
    dataset = parse_structured_data(data, source_filename)
    refs = virtual_cell_index(dataset)
    by_page: dict[int, list[VirtualStructuredCell]] = {}
    for ref in refs:
        by_page.setdefault(ref.page_index, []).append(ref)

    pages: list[PageFrame] = []
    for page_index in range(max(by_page.keys(), default=-1) + 1):
        page_refs = by_page.get(page_index, [])
        lines: list[PositionedLine] = []
        for line_no, ref in enumerate(page_refs):
            prefix, value, y0, header_width, value_x0, value_width = _structured_row_geometry(ref.cell, line_no)
            tokens = (
                PositionedToken(prefix, _STRUCTURED_PREVIEW_HEADER_X, y0, _STRUCTURED_PREVIEW_HEADER_X + header_width, y0 + _STRUCTURED_PREVIEW_TOKEN_HEIGHT, 1.0),
                PositionedToken(value, value_x0, y0, value_x0 + value_width, y0 + _STRUCTURED_PREVIEW_TOKEN_HEIGHT, 1.0),
            )
            lines.append(
                PositionedLine(
                    text=f"{prefix} {value}",
                    tokens=tokens,
                    source=DetectionSource.TEXT_LAYER,
                    page_index=page_index,
                    page_char_start=ref.line_char_start,
                )
            )
        # A tiny backing image avoids allocating a full rendered table for every
        # record. GUI previews are rendered lazily by render_structured_record().
        pages.append(PageFrame(
            page_index,
            float(_STRUCTURED_PREVIEW_WIDTH),
            float(_structured_preview_height(len(lines))),
            Image.new("RGB", (1, 1), "white"),
            tuple(lines),
            False,
        ))

    metadata = structured_summary(dataset)
    return ProcessedDocument(FileType.DATASET, tuple(pages), len(pages), 0, metadata=metadata)


def _schema_payload(dataset: StructuredDataset) -> dict[str, Any]:
    if dataset.format == "json":
        fields = sorted({cell.header for cell in iter_cells(dataset)})
        return {"format": "json", "fields": fields}
    return {
        "format": dataset.format,
        "sheets": [{"name_sha256": hashlib.sha256(table.name.encode()).hexdigest(), "headers": table.headers} for table in dataset.tables],
    }


def structured_summary(dataset: StructuredDataset) -> dict[str, Any]:
    schema_payload = _schema_payload(dataset)
    encoded = json.dumps(schema_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "structured_format": dataset.format.upper(),
        "structured_records": dataset.record_count,
        "structured_fields": dataset.field_count,
        "structured_sheets": dataset.sheet_count,
        "structured_cells": sum(1 for _ in iter_cells(dataset)),
        "structured_schema_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def render_structured_record(data: bytes, page_index: int, source_filename: str | None = None) -> Image.Image:
    dataset = parse_structured_data(data, source_filename)
    groups = _record_groups(dataset)
    if page_index < 0 or page_index >= len(groups):
        raise StructuredDataError("Dataset record index is out of range")
    cells = sorted(groups[page_index], key=lambda item: (item.sheet_index, item.column_index, item.header.casefold()))
    width = _STRUCTURED_PREVIEW_WIDTH
    height = _structured_preview_height(len(cells))
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    font = _font(16)
    bold = _font(17)
    sheet_name = dataset.tables[cells[0].sheet_index].name if dataset.format != "json" and cells else "JSON"
    draw.text((48, 15), f"{dataset.format.upper()} · {sheet_name} · record {page_index + 1}", fill="black", font=bold)
    for line_no, cell in enumerate(cells):
        prefix, value, y0, _header_width, value_x0, _value_width = _structured_row_geometry(cell, line_no)
        draw.text((_STRUCTURED_PREVIEW_HEADER_X, y0), prefix, fill=(55, 65, 81), font=font)
        draw.text((value_x0, y0), value, fill="black", font=font)
        draw.line((48, y0 + 25, width - 48, y0 + 25), fill=(225, 228, 234), width=1)
    return image


def _set_json_path(root: Any, path: tuple[Any, ...], value: Any) -> None:
    if not path:
        raise StructuredDataError("Cannot replace the JSON root scalar")
    cursor = root
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value


def _neutralize_formula_text(value: str) -> str:
    # CSV spreadsheet injection protection. The leading apostrophe is displayed
    # as text by spreadsheet applications and cannot execute as a formula.
    if value and value[0] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def apply_structured_replacements(
    data: bytes,
    replacements: list[tuple[int, int, int, str]],
    source_filename: str | None = None,
) -> StructuredDataset:
    dataset = parse_structured_data(data, source_filename)
    refs = virtual_cell_index(dataset)
    by_page: dict[int, list[VirtualStructuredCell]] = {}
    for ref in refs:
        by_page.setdefault(ref.page_index, []).append(ref)

    grouped: dict[tuple[Any, ...], tuple[VirtualStructuredCell, list[tuple[int, int, str]]]] = {}
    for page_index, char_start, char_end, replacement in replacements:
        matches = [
            ref for ref in by_page.get(page_index, [])
            if char_start >= ref.value_char_start and char_end <= ref.value_char_end and char_end > char_start
        ]
        if len(matches) != 1:
            raise StructuredDataError("Structured-data protection span does not resolve to exactly one scalar cell")
        ref = matches[0]
        relative_start = char_start - ref.value_char_start
        relative_end = char_end - ref.value_char_start
        key = tuple(ref.cell.locator)
        if key not in grouped:
            grouped[key] = (ref, [])
        grouped[key][1].append((relative_start, relative_end, replacement))

    updates: list[tuple[VirtualStructuredCell, str]] = []
    for ref, cell_replacements in grouped.values():
        original = ref.cell.display_value
        ordered = sorted(cell_replacements)
        for left, right in zip(ordered, ordered[1:]):
            if right[0] < left[1]:
                raise StructuredDataError("Overlapping structured-data replacements are not allowed")
        updated = original
        for rel_start, rel_end, replacement in reversed(ordered):
            if rel_start < 0 or rel_end <= rel_start or rel_end > len(original):
                raise StructuredDataError("Structured-data replacement references an invalid scalar span")
            updated = updated[:rel_start] + replacement + updated[rel_end:]
        updates.append((ref, updated))

    if dataset.format == "json":
        root = deepcopy(dataset.json_root)
        assert root is not None
        for ref, updated in updates:
            _set_json_path(root, ref.cell.locator, updated)
        dataset.json_root = root
        return dataset

    for ref, updated in updates:
        sheet_index, row_index, column_index = (int(item) for item in ref.cell.locator)
        dataset.tables[sheet_index].rows[row_index][column_index] = updated
    return dataset


def export_csv(dataset: StructuredDataset) -> bytes:
    if dataset.format != "csv" or len(dataset.tables) != 1:
        raise StructuredDataError("CSV export requires exactly one table")
    output = io.StringIO(newline="")
    writer = csv.writer(output, dialect="excel", lineterminator="\n")
    table = dataset.tables[0]
    writer.writerow(table.headers)
    for row in table.rows:
        writer.writerow([_neutralize_formula_text(str(value)) if isinstance(value, str) else value for value in row])
    return output.getvalue().encode("utf-8")


def export_json(dataset: StructuredDataset) -> bytes:
    if dataset.format != "json":
        raise StructuredDataError("JSON export requires a JSON dataset")
    return (json.dumps(dataset.json_root, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _column_letters(index: int) -> str:
    value = index + 1
    result = ""
    while value:
        value, rem = divmod(value - 1, 26)
        result = chr(65 + rem) + result
    return result


def _xml_cell(ref: str, value: Any) -> ET.Element:
    cell = ET.Element("c", {"r": ref})
    if isinstance(value, bool):
        cell.set("t", "b")
        ET.SubElement(cell, "v").text = "1" if value else "0"
    elif isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
        ET.SubElement(cell, "v").text = str(value)
    else:
        cell.set("t", "inlineStr")
        inline = ET.SubElement(cell, "is")
        text = ET.SubElement(inline, "t")
        string = str(value or "")
        if string != string.strip():
            text.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        text.text = string
    return cell


def _xml_bytes(root: ET.Element) -> bytes:
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _zip_write(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    archive.writestr(info, data)


def export_xlsx(dataset: StructuredDataset) -> bytes:
    if dataset.format != "xlsx":
        raise StructuredDataError("XLSX export requires an XLSX dataset")
    ns_main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    ns_rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    ns_pkg = "http://schemas.openxmlformats.org/package/2006/relationships"
    ET.register_namespace("", ns_main)
    ET.register_namespace("r", ns_rel)

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        types = ET.Element("Types", {"xmlns": "http://schemas.openxmlformats.org/package/2006/content-types"})
        ET.SubElement(types, "Default", {"Extension": "rels", "ContentType": "application/vnd.openxmlformats-package.relationships+xml"})
        ET.SubElement(types, "Default", {"Extension": "xml", "ContentType": "application/xml"})
        ET.SubElement(types, "Override", {"PartName": "/xl/workbook.xml", "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"})
        ET.SubElement(types, "Override", {"PartName": "/xl/styles.xml", "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"})
        for index in range(len(dataset.tables)):
            ET.SubElement(types, "Override", {"PartName": f"/xl/worksheets/sheet{index + 1}.xml", "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"})
        _zip_write(archive, "[Content_Types].xml", _xml_bytes(types))

        root_rels = ET.Element("Relationships", {"xmlns": ns_pkg})
        ET.SubElement(root_rels, "Relationship", {"Id": "rId1", "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument", "Target": "xl/workbook.xml"})
        _zip_write(archive, "_rels/.rels", _xml_bytes(root_rels))

        workbook = ET.Element(f"{{{ns_main}}}workbook")
        sheets = ET.SubElement(workbook, f"{{{ns_main}}}sheets")
        for index, table in enumerate(dataset.tables):
            ET.SubElement(sheets, f"{{{ns_main}}}sheet", {"name": table.name[:31] or f"Sheet{index + 1}", "sheetId": str(index + 1), f"{{{ns_rel}}}id": f"rId{index + 1}"})
        _zip_write(archive, "xl/workbook.xml", _xml_bytes(workbook))

        wb_rels = ET.Element("Relationships", {"xmlns": ns_pkg})
        for index in range(len(dataset.tables)):
            ET.SubElement(wb_rels, "Relationship", {"Id": f"rId{index + 1}", "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet", "Target": f"worksheets/sheet{index + 1}.xml"})
        ET.SubElement(wb_rels, "Relationship", {"Id": f"rId{len(dataset.tables) + 1}", "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles", "Target": "styles.xml"})
        _zip_write(archive, "xl/_rels/workbook.xml.rels", _xml_bytes(wb_rels))

        styles = ET.Element(f"{{{ns_main}}}styleSheet")
        fonts = ET.SubElement(styles, f"{{{ns_main}}}fonts", {"count": "1"})
        font = ET.SubElement(fonts, f"{{{ns_main}}}font")
        ET.SubElement(font, f"{{{ns_main}}}sz", {"val": "11"})
        ET.SubElement(font, f"{{{ns_main}}}name", {"val": "Calibri"})
        ET.SubElement(font, f"{{{ns_main}}}family", {"val": "2"})
        fills = ET.SubElement(styles, f"{{{ns_main}}}fills", {"count": "2"})
        fill0 = ET.SubElement(fills, f"{{{ns_main}}}fill")
        ET.SubElement(fill0, f"{{{ns_main}}}patternFill", {"patternType": "none"})
        fill1 = ET.SubElement(fills, f"{{{ns_main}}}fill")
        ET.SubElement(fill1, f"{{{ns_main}}}patternFill", {"patternType": "gray125"})
        borders = ET.SubElement(styles, f"{{{ns_main}}}borders", {"count": "1"})
        border = ET.SubElement(borders, f"{{{ns_main}}}border")
        for side in ("left", "right", "top", "bottom", "diagonal"):
            ET.SubElement(border, f"{{{ns_main}}}{side}")
        cell_style_xfs = ET.SubElement(styles, f"{{{ns_main}}}cellStyleXfs", {"count": "1"})
        ET.SubElement(cell_style_xfs, f"{{{ns_main}}}xf", {"numFmtId": "0", "fontId": "0", "fillId": "0", "borderId": "0"})
        cell_xfs = ET.SubElement(styles, f"{{{ns_main}}}cellXfs", {"count": "1"})
        ET.SubElement(cell_xfs, f"{{{ns_main}}}xf", {"numFmtId": "0", "fontId": "0", "fillId": "0", "borderId": "0", "xfId": "0"})
        cell_styles = ET.SubElement(styles, f"{{{ns_main}}}cellStyles", {"count": "1"})
        ET.SubElement(cell_styles, f"{{{ns_main}}}cellStyle", {"name": "Normal", "xfId": "0", "builtinId": "0"})
        ET.SubElement(styles, f"{{{ns_main}}}dxfs", {"count": "0"})
        _zip_write(archive, "xl/styles.xml", _xml_bytes(styles))

        for sheet_index, table in enumerate(dataset.tables):
            worksheet = ET.Element(f"{{{ns_main}}}worksheet")
            sheet_data = ET.SubElement(worksheet, f"{{{ns_main}}}sheetData")
            all_rows = [table.headers] + table.rows
            for row_index, row_values in enumerate(all_rows, start=1):
                row = ET.SubElement(sheet_data, f"{{{ns_main}}}row", {"r": str(row_index)})
                for column_index, value in enumerate(row_values):
                    row.append(_xml_cell(f"{_column_letters(column_index)}{row_index}", value))
            _zip_write(archive, f"xl/worksheets/sheet{sheet_index + 1}.xml", _xml_bytes(worksheet))
    return out.getvalue()


def export_structured_data(dataset: StructuredDataset) -> tuple[bytes, str, str]:
    if dataset.format == "csv":
        return export_csv(dataset), "text/csv; charset=utf-8", ".csv"
    if dataset.format == "json":
        return export_json(dataset), "application/json", ".json"
    if dataset.format == "xlsx":
        return export_xlsx(dataset), XLSX_MEDIA_TYPE, ".xlsx"
    raise StructuredDataError(f"Unsupported output dataset format: {dataset.format}")


def structured_visible_text(data: bytes, source_filename: str | None = None) -> str:
    dataset = parse_structured_data(data, source_filename)
    return "\n".join(f"{cell.header}: {cell.display_value}" for cell in iter_cells(dataset))


def schema_signature(data: bytes, source_filename: str | None = None) -> dict[str, Any]:
    dataset = parse_structured_data(data, source_filename)
    if dataset.format == "json":
        return {
            "format": "json",
            "records": dataset.record_count,
            "paths": sorted({cell.header for cell in iter_cells(dataset)}),
        }
    return {
        "format": dataset.format,
        "sheets": [
            {"name": table.name, "headers": list(table.headers), "rows": len(table.rows)}
            for table in dataset.tables
        ],
    }
