from __future__ import annotations

import codecs
import re
from dataclasses import dataclass
from pathlib import Path


class TextFormatError(ValueError):
    pass


TEXT_EXTENSIONS = {".txt", ".md", ".rtf"}


@dataclass(frozen=True)
class DecodedText:
    text: str
    extension: str
    media_type: str
    source_encoding: str
    canonicalized: bool = False


def _printable_ratio(text: str) -> float:
    if not text:
        return 1.0
    allowed_controls = {"\n", "\r", "\t", "\f"}
    printable = sum(ch.isprintable() or ch in allowed_controls for ch in text)
    return printable / len(text)


def _decode_plain_bytes(data: bytes) -> tuple[str, str]:
    if data.startswith(codecs.BOM_UTF8):
        text = data.decode("utf-8-sig")
        encoding = "utf-8-sig"
    elif data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
        text = data.decode("utf-16")
        encoding = "utf-16"
    else:
        try:
            text = data.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            # Common legacy text produced by office tools on Windows/macOS.
            text = data.decode("cp1252")
            encoding = "cp1252"
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if "\x00" in text:
        raise TextFormatError("Text input contains embedded NUL bytes")
    if _printable_ratio(text) < 0.97:
        raise TextFormatError("Text input contains too many binary/control characters")
    return text, encoding


# Conservative RTF-to-text parser. It intentionally extracts visible textual
# content only and ignores metadata/control destinations. Protected RTF output
# is regenerated from this plain representation, preventing hidden source
# fields or metadata from surviving the redaction pipeline.
_DESTINATIONS = {
    "fonttbl", "colortbl", "datastore", "themedata", "stylesheet", "info",
    "pict", "object", "filetbl", "listtable", "listoverridetable", "generator",
    "xmlnstbl", "rsidtbl", "protusertbl", "mmathpr", "latentstyles",
}
_SPECIAL_WORDS = {
    "par": "\n",
    "line": "\n",
    "tab": "\t",
    "emdash": "—",
    "endash": "–",
    "bullet": "•",
    "lquote": "‘",
    "rquote": "’",
    "ldblquote": "“",
    "rdblquote": "”",
}
_TOKEN_RE = re.compile(
    r"\\([a-zA-Z]+)(-?\d+)? ?"  # control word
    r"|\\'([0-9a-fA-F]{2})"       # hex escaped byte
    r"|\\([^a-zA-Z])"             # escaped symbol
    r"|([{}])"                       # group braces
    r"|([^\\{}]+)",                # plain text
    re.DOTALL,
)


def rtf_to_text(data: bytes) -> str:
    try:
        source = data.decode("latin-1")
    except UnicodeDecodeError as exc:
        raise TextFormatError(f"Invalid RTF byte stream: {exc}") from exc
    if not re.match(r"^\s*\{\\rtf\d+", source):
        raise TextFormatError("RTF extension does not contain an RTF document header")

    stack: list[tuple[bool, int]] = []
    ignorable = False
    ucskip = 1
    curskip = 0
    out: list[str] = []

    for match in _TOKEN_RE.finditer(source):
        word, arg, hex_byte, symbol, brace, text = match.groups()
        if brace == "{":
            stack.append((ignorable, ucskip))
            continue
        if brace == "}":
            if stack:
                ignorable, ucskip = stack.pop()
            curskip = 0
            continue
        if word:
            lower = word.lower()
            if lower in _DESTINATIONS:
                ignorable = True
                continue
            if lower == "uc" and arg is not None:
                ucskip = max(0, int(arg))
                continue
            if lower == "u" and arg is not None:
                if not ignorable:
                    code = int(arg)
                    if code < 0:
                        code += 65536
                    try:
                        out.append(chr(code))
                    except ValueError:
                        out.append("�")
                curskip = ucskip
                continue
            if lower in _SPECIAL_WORDS and not ignorable:
                out.append(_SPECIAL_WORDS[lower])
            continue
        if hex_byte is not None:
            if curskip:
                curskip -= 1
                continue
            if not ignorable:
                out.append(bytes([int(hex_byte, 16)]).decode("cp1252", errors="replace"))
            continue
        if symbol is not None:
            if symbol == "*":
                ignorable = True
                continue
            if symbol in "{}\\" and not ignorable:
                if curskip:
                    curskip -= 1
                else:
                    out.append(symbol)
            elif symbol == "~" and not ignorable:
                out.append(" ")
            elif symbol == "_" and not ignorable:
                out.append("‑")
            continue
        if text is not None and not ignorable:
            if curskip:
                skipped = min(curskip, len(text))
                text = text[skipped:]
                curskip -= skipped
            if text:
                out.append(text)

    result = "".join(out)
    result = result.replace("\r\n", "\n").replace("\r", "\n")
    result = re.sub(r"\n{3,}", "\n\n", result)
    result = result.strip("\n")
    if _printable_ratio(result) < 0.97:
        raise TextFormatError("RTF visible text contains too many control characters")
    return result


def _rtf_escape_text(text: str) -> str:
    pieces: list[str] = []
    for char in text:
        if char == "\\":
            pieces.append(r"\\")
        elif char == "{":
            pieces.append(r"\{")
        elif char == "}":
            pieces.append(r"\}")
        elif char == "\n":
            pieces.append(r"\par" + "\n")
        elif char == "\t":
            pieces.append(r"\tab ")
        else:
            code = ord(char)
            if 32 <= code <= 126:
                pieces.append(char)
            elif code <= 0xFFFF:
                signed = code if code < 32768 else code - 65536
                pieces.append(rf"\u{signed}?")
            else:
                # RTF Unicode escapes are UTF-16 code units.
                raw = char.encode("utf-16-le")
                for i in range(0, len(raw), 2):
                    unit = int.from_bytes(raw[i:i+2], "little")
                    signed = unit if unit < 32768 else unit - 65536
                    pieces.append(rf"\u{signed}?")
    return "".join(pieces)


def text_to_canonical_rtf(text: str) -> bytes:
    body = _rtf_escape_text(text)
    # Intentionally contains no author/info/comments/objects/attachments.
    source = "{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Helvetica;}}\\f0\\fs22 " + body + "}"
    return source.encode("ascii", errors="strict")


def decode_text_document(data: bytes, filename: str | None = None) -> DecodedText:
    if filename is None:
        # During protected-output rescans the filename is unavailable. RTF can
        # still be identified by its magic header; all other TEXT payloads are
        # treated as UTF text.
        extension = ".rtf" if re.match(br"^\s*\{\\rtf\d+", data) else ".txt"
    else:
        extension = Path(filename).suffix.lower()
        if extension not in TEXT_EXTENSIONS:
            extension = ".rtf" if re.match(br"^\s*\{\\rtf\d+", data) else ".txt"

    if extension == ".rtf":
        return DecodedText(
            text=rtf_to_text(data),
            extension=extension,
            media_type="application/rtf",
            source_encoding="rtf/ansi-unicode",
            canonicalized=True,
        )

    text, encoding = _decode_plain_bytes(data)
    media_type = "text/markdown; charset=utf-8" if extension == ".md" else "text/plain; charset=utf-8"
    return DecodedText(text=text, extension=extension, media_type=media_type, source_encoding=encoding)


def encode_protected_text(text: str, filename: str | None = None, source_data: bytes | None = None) -> tuple[bytes, str, str]:
    extension = Path(filename or "").suffix.lower()
    if not extension and source_data is not None and re.match(br"^\s*\{\\rtf\d+", source_data):
        extension = ".rtf"
    if extension == ".rtf":
        return text_to_canonical_rtf(text), "application/rtf", ".rtf"
    if extension == ".md":
        return text.encode("utf-8"), "text/markdown; charset=utf-8", ".md"
    return text.encode("utf-8"), "text/plain; charset=utf-8", ".txt"
