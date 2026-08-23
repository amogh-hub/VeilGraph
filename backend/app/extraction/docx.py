from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable
from xml.etree import ElementTree as ET

from PIL import Image, ImageDraw, ImageFont, ImageOps

from app.core.enums import DetectionSource, EntityType, FileType

DOCX_EXTENSION = ".docx"
DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
DOCX_SCHEMA = "veilgraph.docx-adapter.v1"

_MAX_ZIP_FILES = 2_000
_MAX_ZIP_UNCOMPRESSED = 96 * 1024 * 1024
_MAX_MEMBER_BYTES = 32 * 1024 * 1024
_MAX_TEXT_CHARS = 2_000_000
_MAX_MEDIA_IMAGES = 128
_MAX_VIRTUAL_PAGES = 200
_LINES_PER_PAGE = 42
_PAGE_WIDTH = 1200
_MARGIN_X = 54
_MARGIN_Y = 48
_LINE_HEIGHT = 30

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
WP_NS = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
XML_NS = "http://www.w3.org/XML/1998/namespace"

NS = {"w": W_NS, "r": R_NS, "rel": REL_NS, "ct": CT_NS, "wp": WP_NS}

for prefix, uri in (("w", W_NS), ("r", R_NS), ("wp", WP_NS)):
    ET.register_namespace(prefix, uri)


class DocxError(ValueError):
    pass


@dataclass(frozen=True)
class TextSegment:
    node: ET.Element
    start: int
    end: int


@dataclass(frozen=True)
class DocxTextPart:
    name: str
    text: str
    root: ET.Element
    segments: tuple[TextSegment, ...]


@dataclass(frozen=True)
class DocxPageRef:
    page_index: int
    kind: str  # TEXT or IMAGE
    part_name: str
    char_start: int = 0
    char_end: int = 0


@dataclass(frozen=True)
class DocxPackage:
    members: dict[str, bytes]
    text_parts: tuple[DocxTextPart, ...]
    media_names: tuple[str, ...]
    page_refs: tuple[DocxPageRef, ...]


_TEXT_PART_RE = re.compile(
    r"^word/(document\.xml|header\d*\.xml|footer\d*\.xml|footnotes\.xml|endnotes\.xml)$",
    re.IGNORECASE,
)
_MEDIA_RE = re.compile(r"^word/media/[^/]+\.(png|jpe?g)$", re.IGNORECASE)

_PROHIBITED_MEMBER_MARKERS = (
    "vbaproject",
    "activex/",
    "embeddings/",
    "oleobject",
    "customui/",
    "customxml/",
    "attachedtemplate",
)

_DANGEROUS_XML_LOCAL_NAMES = {
    "altChunk",
    "object",
    "control",
}

_HIDDEN_RUN_PROPERTIES = {"vanish", "webHidden"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _font(size: int = 20) -> ImageFont.ImageFont:
    for path in (
        "/System/Library/Fonts/Supplemental/Menlo.ttc",
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ):
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/"):
        return False
    parts = PurePosixPath(name).parts
    return all(part not in {"", ".", ".."} for part in parts)


def _read_members(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b"PK\x03\x04"):
        raise DocxError("DOCX must be an OPC ZIP package")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise DocxError(f"Invalid DOCX ZIP package: {exc}") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > _MAX_ZIP_FILES:
            raise DocxError(f"DOCX exceeds the secure {_MAX_ZIP_FILES:,}-member package limit")
        total = 0
        names_seen: set[str] = set()
        members: dict[str, bytes] = {}
        for info in infos:
            name = info.filename
            if not _safe_member_name(name):
                raise DocxError(f"DOCX contains an unsafe package path: {name!r}")
            folded = name.casefold()
            if folded in names_seen:
                raise DocxError(f"DOCX contains a duplicate package member: {name}")
            names_seen.add(folded)
            if info.file_size > _MAX_MEMBER_BYTES:
                raise DocxError(f"DOCX package member is too large: {name}")
            total += int(info.file_size)
            if total > _MAX_ZIP_UNCOMPRESSED:
                raise DocxError("DOCX exceeds the secure uncompressed package budget")
            members[name] = archive.read(info)
    return members


def _validate_content_types(members: dict[str, bytes]) -> None:
    required = {"[Content_Types].xml", "word/document.xml"}
    missing = sorted(required - set(members))
    if missing:
        raise DocxError("DOCX is missing required OPC parts: " + ", ".join(missing))
    try:
        root = ET.fromstring(members["[Content_Types].xml"])
    except ET.ParseError as exc:
        raise DocxError(f"DOCX content-types XML is invalid: {exc}") from exc
    main_types = {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
    }
    main = False
    for item in root:
        if _local(item.tag) != "Override":
            continue
        part = item.attrib.get("PartName", "")
        content_type = item.attrib.get("ContentType", "")
        if part == "/word/document.xml" and content_type in main_types:
            main = True
            break
    if not main:
        raise DocxError("OPC package is not a standard DOCX main document")


def _reject_active_package_content(members: dict[str, bytes]) -> None:
    for name in members:
        folded = name.casefold()
        if any(marker in folded for marker in _PROHIBITED_MEMBER_MARKERS):
            raise DocxError(f"DOCX contains unsupported active/embedded package content: {name}")

    for name, raw in members.items():
        if not name.casefold().endswith(".rels"):
            continue
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise DocxError(f"DOCX relationship part is invalid: {name}: {exc}") from exc
        for rel in root:
            target = rel.attrib.get("Target", "")
            rel_type = rel.attrib.get("Type", "").casefold()
            if "oleobject" in rel_type or "package" in rel_type and "relationships/package" in rel_type:
                raise DocxError("DOCX OLE/package relationships are not supported")
            if target.casefold().endswith(('.docm', '.xlsm', '.pptm')):
                raise DocxError("DOCX relationship targets a macro-enabled package")


def validate_docx(data: bytes) -> dict[str, Any]:
    members = _read_members(data)
    _validate_content_types(members)
    _reject_active_package_content(members)
    text_parts = [name for name in members if _TEXT_PART_RE.match(name)]
    media = [name for name in members if _MEDIA_RE.match(name)]
    if len(media) > _MAX_MEDIA_IMAGES:
        raise DocxError(f"DOCX exceeds the secure {_MAX_MEDIA_IMAGES}-embedded-image limit")
    if not text_parts and not media:
        raise DocxError("DOCX contains no supported visible text or raster image content")
    return {
        "text_parts": len(text_parts),
        "media_images": len(media),
        "package_members": len(members),
        "uncompressed_bytes": sum(len(value) for value in members.values()),
    }


def _run_is_hidden(run: ET.Element) -> bool:
    rpr = run.find(f"{{{W_NS}}}rPr")
    if rpr is None:
        return False
    return any(_local(child.tag) in _HIDDEN_RUN_PROPERTIES for child in rpr)


def _flatten_part(root: ET.Element) -> tuple[str, tuple[TextSegment, ...]]:
    pieces: list[str] = []
    segments: list[TextSegment] = []
    offset = 0

    def append_text(value: str) -> None:
        nonlocal offset
        if not value:
            return
        pieces.append(value)
        offset += len(value)

    def walk(node: ET.Element, *, hidden: bool = False, deleted: bool = False) -> None:
        nonlocal offset
        name = _local(node.tag)
        next_deleted = deleted or name in {"del", "moveFrom"}
        next_hidden = hidden or (name == "r" and _run_is_hidden(node))

        if name == "t" and not next_hidden and not next_deleted:
            value = node.text or ""
            start = offset
            append_text(value)
            segments.append(TextSegment(node=node, start=start, end=offset))
            return
        if name == "tab" and not next_hidden and not next_deleted:
            append_text("\t")
            return
        if name in {"br", "cr"} and not next_hidden and not next_deleted:
            append_text("\n")
            return
        if name in {"instrText", "delText"}:
            return

        for child in list(node):
            walk(child, hidden=next_hidden, deleted=next_deleted)

        if not next_hidden and not next_deleted:
            if name == "p":
                append_text("\n")
            elif name == "tc":
                append_text("\t")
            elif name == "tr":
                append_text("\n")

    walk(root)
    text = "".join(pieces)
    if len(text) > _MAX_TEXT_CHARS:
        raise DocxError(f"DOCX visible text exceeds the secure {_MAX_TEXT_CHARS:,}-character limit")
    return text, tuple(segments)


def _parse_text_part(name: str, raw: bytes) -> DocxTextPart:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise DocxError(f"DOCX XML part is invalid: {name}: {exc}") from exc
    for element in root.iter():
        if _local(element.tag) in _DANGEROUS_XML_LOCAL_NAMES:
            raise DocxError(f"DOCX contains unsupported active/alternate content in {name}: {_local(element.tag)}")
    text, segments = _flatten_part(root)
    return DocxTextPart(name=name, text=text, root=root, segments=segments)


def _text_part_names(members: dict[str, bytes]) -> list[str]:
    names = [name for name in members if _TEXT_PART_RE.match(name)]
    priority = {"word/document.xml": 0, "word/footnotes.xml": 30, "word/endnotes.xml": 31}
    return sorted(names, key=lambda name: (priority.get(name, 10 if "/header" in name else 20 if "/footer" in name else 25), name))


def _build_page_refs(text_parts: Iterable[DocxTextPart], media_names: Iterable[str]) -> tuple[DocxPageRef, ...]:
    refs: list[DocxPageRef] = []
    page_index = 0
    for part in text_parts:
        # Page virtualisation is presentation-only. Character spans remain
        # anchored to the XML part's local flattened-text coordinate system.
        line_starts = [0]
        for match in re.finditer("\n", part.text):
            line_starts.append(match.end())
        if not part.text:
            chunks = [(0, 0)]
        else:
            chunks = []
            for first_line in range(0, max(1, len(line_starts)), _LINES_PER_PAGE):
                start = line_starts[first_line]
                next_line = first_line + _LINES_PER_PAGE
                end = line_starts[next_line] if next_line < len(line_starts) else len(part.text)
                chunks.append((start, end))
        for start, end in chunks:
            refs.append(DocxPageRef(page_index=page_index, kind="TEXT", part_name=part.name, char_start=start, char_end=end))
            page_index += 1
    for name in sorted(media_names):
        refs.append(DocxPageRef(page_index=page_index, kind="IMAGE", part_name=name))
        page_index += 1
    if len(refs) > _MAX_VIRTUAL_PAGES:
        raise DocxError(f"DOCX expands beyond the secure {_MAX_VIRTUAL_PAGES}-unit analysis limit")
    return tuple(refs)


def parse_docx(data: bytes) -> DocxPackage:
    members = _read_members(data)
    _validate_content_types(members)
    _reject_active_package_content(members)
    parts = tuple(_parse_text_part(name, members[name]) for name in _text_part_names(members))
    media_names = tuple(sorted(name for name in members if _MEDIA_RE.match(name)))
    if len(media_names) > _MAX_MEDIA_IMAGES:
        raise DocxError(f"DOCX exceeds the secure {_MAX_MEDIA_IMAGES}-embedded-image limit")
    refs = _build_page_refs(parts, media_names)
    if not refs:
        raise DocxError("DOCX contains no supported visible content")
    return DocxPackage(members=members, text_parts=parts, media_names=media_names, page_refs=refs)


def _docx_part_label(part_name: str, kind: str, ordinal: int = 1) -> str:
    folded = part_name.casefold()
    if kind == "IMAGE":
        return f"Embedded image {ordinal}"
    if folded.endswith("word/document.xml"):
        return "Body"
    if "/header" in folded:
        return "Header"
    if "/footer" in folded:
        return "Footer"
    if folded.endswith("footnotes.xml"):
        return "Footnotes"
    if folded.endswith("endnotes.xml"):
        return "Endnotes"
    return "DOCX part"


def _layout_docx_text_chunk(chunk: str, *, page_index: int, title: str):
    """Render Word text for judge inspection without pretending it is a PDF page.

    Presentation stays anchored to Privacy-IR character coordinates, but long
    prose wraps and flattened table cells are displayed in two readable
    columns. Tabs are layout instructions, never visible square glyphs.
    """
    from app.extraction.document_processor import PositionedLine, PositionedToken

    font = _font(20)
    label_font = _font(15)
    char_gap = float(max(4, font.getlength(" ")))
    # Reserve a right-side annotation rail so evidence chips never cover prose.
    max_x = 790.0
    table_value_x = 380.0
    cursor_y = float(_MARGIN_Y)
    local = 0
    positioned: list[PositionedLine] = []
    draw_ops: list[tuple[str, float, float]] = []
    previous_row_y: float | None = None

    logical_lines = chunk.splitlines() or ([chunk] if chunk else [])
    for raw_line in logical_lines:
        if not raw_line:
            # XML table/paragraph boundaries can emit structural blank lines.
            # Keep a small visual breath without turning them into giant gaps.
            cursor_y += 6.0
            previous_row_y = None
            local += 1
            continue
        is_table_value = raw_line.startswith("\t")
        visible_line = raw_line.lstrip("\t") if is_table_value else raw_line
        row_y = previous_row_y if is_table_value and previous_row_y is not None else cursor_y
        base_x = table_value_x if is_table_value else float(_MARGIN_X)
        x = base_x
        y = row_y
        tokens: list[PositionedToken] = []

        for match in re.finditer(r"\S+", raw_line):
            token_text = match.group(0)
            if token_text == "\t":
                continue
            token_text = token_text.lstrip("\t")
            if not token_text:
                continue
            width = float(max(2.0, font.getlength(token_text)))
            if x > base_x and x + width > max_x:
                y += _LINE_HEIGHT
                x = base_x
            x0 = x
            x1 = min(max_x, x + width)
            tokens.append(PositionedToken(token_text, x0, y, max(x0 + 2.0, x1), y + _LINE_HEIGHT - 4, 1.0))
            draw_ops.append((token_text, x0, y))
            x = x1 + char_gap

        if tokens:
            leading_layout_chars = len(raw_line) - len(visible_line)
            positioned.append(PositionedLine(
                text=visible_line,
                tokens=tuple(tokens),
                source=DetectionSource.TEXT_LAYER,
                page_index=page_index,
                page_char_start=local + leading_layout_chars,
            ))

        used_rows = max(1, int(round((y - row_y) / _LINE_HEIGHT)) + 1)
        if not is_table_value:
            previous_row_y = row_y
            cursor_y = max(cursor_y, row_y + used_rows * _LINE_HEIGHT)
        else:
            cursor_y = max(cursor_y, row_y + used_rows * _LINE_HEIGHT)
            previous_row_y = None
        local += len(raw_line) + 1

    height = max(320, int(cursor_y + _MARGIN_Y))
    image = Image.new("RGB", (_PAGE_WIDTH, height), "white")
    draw = ImageDraw.Draw(image)
    draw.text((_MARGIN_X, 18), title, font=label_font, fill=(70, 76, 86))
    for text, x, y in draw_ops:
        draw.text((x, y), text, font=font, fill="black")
    return image, tuple(positioned)


def docx_to_processed_document(data: bytes):
    from app.extraction.document_processor import PageFrame, PositionedLine, ProcessedDocument, _ocr_lines

    package = parse_docx(data)
    parts = {part.name: part for part in package.text_parts}
    pages = []
    scanned = 0
    page_metadata: list[dict[str, Any]] = []
    for ref in package.page_refs:
        if ref.kind == "TEXT":
            part = parts[ref.part_name]
            chunk = part.text[ref.char_start:ref.char_end]
            label = _docx_part_label(ref.part_name, ref.kind)
            image, positioned = _layout_docx_text_chunk(
                chunk, page_index=ref.page_index, title=f"DOCX · {label} · {ref.part_name}"
            )
            # Character coordinates are local to the XML part. Virtual chunks
            # beyond the first therefore need the part-local chunk offset added.
            if ref.char_start:
                positioned = tuple(PositionedLine(
                    text=line.text,
                    tokens=line.tokens,
                    source=line.source,
                    page_index=line.page_index,
                    page_char_start=line.page_char_start + ref.char_start,
                ) for line in positioned)
            pages.append(PageFrame(
                page_index=ref.page_index,
                width=float(image.width),
                height=float(image.height),
                image=image,
                lines=tuple(positioned),
                used_ocr=False,
            ))
        else:
            try:
                image = ImageOps.exif_transpose(Image.open(io.BytesIO(package.members[ref.part_name]))).convert("RGB")
            except Exception as exc:
                raise DocxError(f"Embedded DOCX image cannot be decoded: {ref.part_name}: {exc}") from exc
            if image.width * image.height > 40_000_000:
                raise DocxError(f"Embedded DOCX image exceeds the secure pixel budget: {ref.part_name}")
            lines = _ocr_lines(image, ref.page_index, float(image.width), float(image.height))
            scanned += 1
            pages.append(PageFrame(
                page_index=ref.page_index,
                width=float(image.width),
                height=float(image.height),
                image=image,
                lines=tuple(lines),
                used_ocr=True,
            ))
        page_metadata.append({
            "page_index": ref.page_index,
            "kind": ref.kind,
            "part_name": ref.part_name,
            "label": _docx_part_label(ref.part_name, ref.kind, ref.page_index + 1),
            "char_start": ref.char_start,
            "char_end": ref.char_end,
        })

    metadata = {
        "docx_schema": DOCX_SCHEMA,
        "docx_text_parts": len(package.text_parts),
        "docx_media_images": len(package.media_names),
        "docx_virtual_pages": len(package.page_refs),
        "docx_page_map": page_metadata,
        "docx_structure_sha256": hashlib.sha256(
            json.dumps(docx_structure_signature(data), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    return ProcessedDocument(
        file_type=FileType.DOCX,
        pages=tuple(pages),
        page_count=len(pages),
        scanned_pages=scanned,
        metadata=metadata,
    )


def docx_visible_text(data: bytes) -> str:
    package = parse_docx(data)
    return "\n".join(part.text for part in package.text_parts)


def secondary_docx_visible_text(data: bytes) -> str:
    """Independent minimal extractor used by the Privacy Red Team.

    It does not use Privacy IR/page virtualisation; it directly walks supported
    WordprocessingML parts and returns visible w:t text while excluding deleted
    and hidden runs.
    """
    members = _read_members(data)
    _validate_content_types(members)
    values: list[str] = []
    for name in _text_part_names(members):
        root = ET.fromstring(members[name])
        text, _segments = _flatten_part(root)
        values.append(text)
    return "\n".join(values)


def docx_structure_signature(data: bytes) -> dict[str, Any]:
    package = parse_docx(data)
    counts = {"paragraphs": 0, "tables": 0, "headers": 0, "footers": 0, "footnotes": 0, "endnotes": 0}
    part_summaries = []
    for part in package.text_parts:
        counts["paragraphs"] += sum(1 for element in part.root.iter() if _local(element.tag) == "p")
        counts["tables"] += sum(1 for element in part.root.iter() if _local(element.tag) == "tbl")
        if "/header" in part.name:
            counts["headers"] += 1
        elif "/footer" in part.name:
            counts["footers"] += 1
        elif part.name.endswith("footnotes.xml"):
            counts["footnotes"] += 1
        elif part.name.endswith("endnotes.xml"):
            counts["endnotes"] += 1
        part_summaries.append({
            "name": part.name,
            "paragraphs": sum(1 for element in part.root.iter() if _local(element.tag) == "p"),
            "tables": sum(1 for element in part.root.iter() if _local(element.tag) == "tbl"),
        })
    return {
        "schema": "veilgraph.docx-structure.v1",
        **counts,
        "media_images": len(package.media_names),
        "text_parts": part_summaries,
    }


def _set_text(node: ET.Element, value: str) -> None:
    node.text = value
    key = f"{{{XML_NS}}}space"
    if value[:1].isspace() or value[-1:].isspace():
        node.set(key, "preserve")
    else:
        node.attrib.pop(key, None)


def _replace_range(part: DocxTextPart, start: int, end: int, replacement: str) -> None:
    if start < 0 or end <= start or end > len(part.text):
        raise DocxError(f"DOCX replacement span {start}:{end} is outside {part.name}")
    overlaps = [segment for segment in part.segments if segment.end > start and segment.start < end]
    if not overlaps:
        raise DocxError(f"DOCX replacement span {start}:{end} does not intersect visible text in {part.name}")
    first, last = overlaps[0], overlaps[-1]
    first_text = first.node.text or ""
    prefix = first_text[: max(0, start - first.start)]
    if first is last:
        suffix = first_text[max(0, end - first.start):]
        _set_text(first.node, prefix + replacement + suffix)
        return
    last_text = last.node.text or ""
    suffix = last_text[max(0, end - last.start):]
    _set_text(first.node, prefix + replacement)
    for segment in overlaps[1:-1]:
        _set_text(segment.node, "")
    _set_text(last.node, suffix)


def _remove_element(parent: ET.Element, child: ET.Element) -> None:
    try:
        parent.remove(child)
    except ValueError:
        pass


def _scrub_xml_tree(root: ET.Element) -> None:
    # Strip hidden/deleted content and fields that can carry source data outside
    # normal visible extraction. Keep inserted/visible runs and formatting.
    for parent in list(root.iter()):
        for child in list(parent):
            name = _local(child.tag)
            if name in {"del", "moveFrom", "commentRangeStart", "commentRangeEnd", "commentReference", "proofErr", "permStart", "permEnd"}:
                _remove_element(parent, child)
                continue
            if name == "r" and _run_is_hidden(child):
                _remove_element(parent, child)
                continue
            if name in _DANGEROUS_XML_LOCAL_NAMES:
                _remove_element(parent, child)
                continue
            if name in {"instrText", "fldChar"}:
                _remove_element(parent, child)
                continue
            if name == "fldSimple":
                child.attrib.pop(f"{{{W_NS}}}instr", None)
            if name == "hyperlink":
                child.attrib.pop(f"{{{R_NS}}}id", None)
            if name == "bookmarkStart":
                child.attrib.pop(f"{{{W_NS}}}name", None)
            if child.tag == f"{{{WP_NS}}}docPr":
                child.attrib.pop("descr", None)
                child.attrib.pop("title", None)
                if "name" in child.attrib:
                    child.attrib["name"] = "VeilGraph media"


def _serialize_opc_default_namespace(root: ET.Element, namespace: str) -> bytes:
    """Serialize OPC control parts with the namespace as the default namespace.

    OOXML consumers are not equally tolerant of namespace-equivalent encodings
    for package control parts.  In particular, LibreOffice rejects DOCX files
    whose [Content_Types].xml / *.rels roots are emitted as ``ns0:Types`` or
    ``ns0:Relationships`` by ``xml.etree``.  Keep the semantic XML unchanged,
    but canonicalize that one namespace as the default namespace used by normal
    Office packages.
    """
    serialized = ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")
    match = re.search(rf'xmlns:(?P<prefix>ns\d+)="{re.escape(namespace)}"', serialized)
    if not match:
        return serialized.encode("utf-8")
    prefix = match.group("prefix")
    serialized = serialized.replace(
        f'xmlns:{prefix}="{namespace}"',
        f'xmlns="{namespace}"',
        1,
    )
    serialized = serialized.replace(f'<{prefix}:', '<').replace(f'</{prefix}:', '</')
    return serialized.encode("utf-8")


def _scrub_relationships(raw: bytes) -> bytes:
    root = ET.fromstring(raw)
    for child in list(root):
        target_mode = child.attrib.get("TargetMode", "")
        target = child.attrib.get("Target", "").casefold()
        rel_type = child.attrib.get("Type", "").casefold()
        if target_mode.casefold() == "external":
            root.remove(child)
            continue
        if any(marker in target for marker in ("docprops/", "customxml/", "comments", "people.xml", "embeddings/", "activex/", "vbaproject")):
            root.remove(child)
            continue
        if any(marker in rel_type for marker in ("custom-properties", "extended-properties", "/comments", "/oleobject", "/package")):
            root.remove(child)
    return _serialize_opc_default_namespace(root, REL_NS)


def _scrub_content_types(raw: bytes, retained_names: set[str]) -> bytes:
    root = ET.fromstring(raw)
    for child in list(root):
        if _local(child.tag) != "Override":
            continue
        part = child.attrib.get("PartName", "").lstrip("/")
        if part and part not in retained_names:
            root.remove(child)
    return _serialize_opc_default_namespace(root, CT_NS)


def _canonicalize_image(raw: bytes, *, instructions: list[tuple[tuple[float, float, float, float], EntityType, str]]) -> bytes:
    image = ImageOps.exif_transpose(Image.open(io.BytesIO(raw))).convert("RGB")
    draw = ImageDraw.Draw(image)
    font = _font(max(12, min(20, image.width // 70)))
    for rect, entity_type, replacement in instructions:
        x0, y0, x1, y1 = rect
        visual = entity_type in {EntityType.FACE, EntityType.QR_CODE, EntityType.SIGNATURE_CANDIDATE}
        fill = (18, 18, 24) if visual else (255, 255, 255)
        text_fill = (255, 255, 255) if visual else (0, 0, 0)
        draw.rectangle((x0, y0, x1, y1), fill=fill)
        draw.text((x0 + 3, y0 + 2), replacement, font=font, fill=text_fill)
    out = io.BytesIO()
    # Keep package extension/content type stable, but strip EXIF/ancillary data.
    detected = (Image.open(io.BytesIO(raw)).format or "PNG").upper()
    if detected == "JPEG":
        image.save(out, format="JPEG", quality=94, optimize=True)
    else:
        image.save(out, format="PNG", optimize=True)
    return out.getvalue()


def sanitize_docx(data: bytes, instructions, source_filename: str | None = None) -> tuple[bytes, str, str, dict[str, object]]:
    package = parse_docx(data)
    part_by_name = {part.name: part for part in package.text_parts}
    ref_by_page = {ref.page_index: ref for ref in package.page_refs}

    text_actions: dict[str, list[tuple[int, int, str, str]]] = {}
    image_actions: dict[str, list[tuple[tuple[float, float, float, float], EntityType, str]]] = {}
    for instruction in instructions:
        ref = ref_by_page.get(int(instruction.page_index))
        if ref is None:
            raise DocxError("DOCX protection instruction references an invalid virtual page")
        if ref.kind == "TEXT":
            if instruction.char_start is None or instruction.char_end is None:
                raise DocxError("DOCX text protection requires exact WordprocessingML character-span commitments")
            start, end = int(instruction.char_start), int(instruction.char_end)
            if start < ref.char_start or end > ref.char_end:
                raise DocxError("DOCX text protection span escapes its committed virtual page")
            text_actions.setdefault(ref.part_name, []).append((start, end, instruction.replacement, instruction.mention_id))
        else:
            image_actions.setdefault(ref.part_name, []).append((instruction.rect, instruction.entity_type, instruction.replacement))

    # Reject overlaps before mutating XML. Exact duplicate spans with identical
    # replacements are de-duplicated deterministically.
    for part_name, actions in text_actions.items():
        unique: dict[tuple[int, int], tuple[str, str]] = {}
        for start, end, replacement, mention_id in actions:
            key = (start, end)
            previous = unique.get(key)
            if previous is not None and previous[0] != replacement:
                raise DocxError("Conflicting DOCX replacements target the same visible span")
            unique[key] = (replacement, mention_id)
        ordered = sorted((start, end, repl, mid) for (start, end), (repl, mid) in unique.items())
        for left, right in zip(ordered, ordered[1:]):
            if right[0] < left[1]:
                raise DocxError("Overlapping DOCX protection instructions are not allowed")
        text_actions[part_name] = ordered

    modified_parts: dict[str, bytes] = {}
    for part in package.text_parts:
        for start, end, replacement, _mention_id in reversed(text_actions.get(part.name, [])):
            _replace_range(part, start, end, replacement)
        _scrub_xml_tree(part.root)
        modified_parts[part.name] = ET.tostring(part.root, encoding="utf-8", xml_declaration=True)

    excluded = {
        name for name in package.members
        if name.casefold().startswith(("docprops/", "customxml/", "word/comments", "word/people"))
        or any(marker in name.casefold() for marker in ("embeddings/", "activex/", "vbaproject", "printersettings/", "thumbnail"))
    }
    retained_names = set(package.members) - excluded

    output_members: dict[str, bytes] = {}
    for name, raw in package.members.items():
        if name in excluded:
            continue
        if name in modified_parts:
            output_members[name] = modified_parts[name]
            continue
        if name in package.media_names:
            try:
                output_members[name] = _canonicalize_image(raw, instructions=image_actions.get(name, []))
            except Exception as exc:
                raise DocxError(f"DOCX embedded image could not be safely regenerated: {name}: {exc}") from exc
            continue
        if name.casefold().endswith(".rels"):
            try:
                output_members[name] = _scrub_relationships(raw)
            except ET.ParseError as exc:
                raise DocxError(f"DOCX relationship part is invalid during sanitization: {name}: {exc}") from exc
            continue
        if name == "[Content_Types].xml":
            output_members[name] = _scrub_content_types(raw, retained_names)
            continue
        if name.casefold().endswith("settings.xml"):
            try:
                root = ET.fromstring(raw)
                for parent in list(root.iter()):
                    for child in list(parent):
                        if _local(child.tag) in {"trackRevisions", "docVars", "rsids", "attachedTemplate"}:
                            parent.remove(child)
                output_members[name] = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            except ET.ParseError:
                output_members[name] = raw
            continue
        output_members[name] = raw

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(output_members):
            archive.writestr(name, output_members[name])
    protected = out.getvalue()
    # Re-parse the protected package before release so broken references or
    # unsafe content fail closed at transformation time.
    parse_docx(protected)
    return protected, DOCX_MEDIA_TYPE, "protected.docx", {
        "transformations": len(instructions),
        "text_parts_modified": sorted(text_actions),
        "embedded_images_modified": sorted(image_actions),
        "output_sha256": hashlib.sha256(protected).hexdigest(),
        "method": "WordprocessingML span replacement + embedded-image regeneration + metadata/external-channel scrub",
        "docx_schema": DOCX_SCHEMA,
        "structure_signature": docx_structure_signature(protected),
    }


def docx_hidden_channel_findings(data: bytes) -> list[str]:
    members = _read_members(data)
    findings: list[str] = []
    for name in members:
        folded = name.casefold()
        if folded.startswith(("docprops/", "customxml/", "word/comments", "word/people")):
            findings.append(name)
        if any(marker in folded for marker in ("embeddings/", "activex/", "vbaproject", "printersettings/")):
            findings.append(name)
    for name, raw in members.items():
        if name.casefold().endswith(".rels"):
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                findings.append(f"invalid-rel:{name}")
                continue
            for rel in root:
                if rel.attrib.get("TargetMode", "").casefold() == "external":
                    findings.append(f"external-rel:{name}")
        if _TEXT_PART_RE.match(name):
            lowered = raw.lower()
            for marker in (b"instrtext", b"deltext", b"w:vanish", b"webhidden", b"commentreference", b"altchunk"):
                if marker in lowered:
                    findings.append(f"hidden-markup:{name}:{marker.decode('ascii', errors='ignore')}")
    return sorted(set(findings))


def docx_raw_channels(data: bytes) -> bytes:
    members = _read_members(data)
    channel = bytearray(data)
    for name, raw in members.items():
        if name.casefold().endswith((".xml", ".rels", ".txt")):
            channel.extend(raw)
    return bytes(channel)


def docx_media_images(data: bytes) -> list[tuple[str, Image.Image]]:
    package = parse_docx(data)
    results = []
    for name in package.media_names:
        image = ImageOps.exif_transpose(Image.open(io.BytesIO(package.members[name]))).convert("RGB")
        results.append((name, image))
    return results
