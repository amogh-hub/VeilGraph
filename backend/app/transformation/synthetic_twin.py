from __future__ import annotations

import hashlib
import math
import random
import re
import statistics
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from typing import Any

from app.core.enums import EntityType
from app.extraction.structured_data import (
    StructuredDataError,
    StructuredDataset,
    StructuredTable,
    export_structured_data,
    iter_cells,
    parse_structured_data,
    virtual_cell_index,
)
from app.transformation.sanitizer import ProtectionInstruction


_SYNTHETIC_FIRST = (
    "Aarav", "Aditi", "Arjun", "Diya", "Ishaan", "Kavya", "Mira", "Nikhil",
    "Rhea", "Rohan", "Sana", "Tara", "Vihaan", "Zoya", "Kiran", "Neel",
)
_SYNTHETIC_LAST = (
    "Basu", "Desai", "Ghosh", "Iyer", "Joshi", "Kapoor", "Mehta", "Nair",
    "Pillai", "Rao", "Sethi", "Shah", "Varma", "Bhat", "Menon", "Sen",
)
_SYNTHETIC_CITIES = (
    "Mysuru", "Pune", "Kochi", "Jaipur", "Indore", "Surat", "Nagpur", "Bhubaneswar",
    "Coimbatore", "Lucknow", "Vadodara", "Visakhapatnam",
)
_SYNTHETIC_STREETS = (
    "Lakeview Road", "Cedar Lane", "Orchid Street", "Maple Avenue", "Riverbend Road",
    "Garden Lane", "Sunrise Street", "Hillview Avenue", "Parkside Road", "Silver Oak Lane",
)

_HEADER_HINTS: tuple[tuple[re.Pattern[str], EntityType], ...] = (
    (re.compile(r"\b(?:full[ _-]?name|given[ _-]?name|first[ _-]?name|surname|last[ _-]?name|person|patient|employee|customer)[ _-]?name\b|^name$", re.I), EntityType.PERSON_NAME),
    (re.compile(r"\bemail\b", re.I), EntityType.EMAIL),
    (re.compile(r"\b(?:phone|mobile|telephone|contact[ _-]?number)\b", re.I), EntityType.PHONE),
    (re.compile(r"\b(?:address|street|road|lane)\b", re.I), EntityType.STREET_ADDRESS),
    (re.compile(r"\b(?:city|locality|town|district)\b", re.I), EntityType.LOCALITY),
    (re.compile(r"\b(?:zip|zipcode|postal|postcode|pin)\b", re.I), EntityType.POSTCODE),
    (re.compile(r"\b(?:dob|date[ _-]?of[ _-]?birth|birth[ _-]?date)\b", re.I), EntityType.DATE_OF_BIRTH),
    (re.compile(r"\bage\b", re.I), EntityType.AGE),
    (re.compile(r"\b(?:gender|sex)\b", re.I), EntityType.DEMOGRAPHIC_ATTRIBUTE),
    (re.compile(r"\bpassport\b", re.I), EntityType.PASSPORT_NUMBER),
    (re.compile(r"\b(?:driver|driving).*(?:licen[cs]e)|(?:licen[cs]e).*(?:number|no)\b", re.I), EntityType.DRIVER_LICENSE_NUMBER),
    (re.compile(r"\b(?:national[ _-]?id|id[ _-]?(?:card|number)|identity[ _-]?(?:card|number))\b", re.I), EntityType.NATIONAL_ID),
    (re.compile(r"\b(?:tax[ _-]?id|pan)\b", re.I), EntityType.TAX_IDENTIFIER),
    (re.compile(r"\b(?:social|ssn)\b", re.I), EntityType.SOCIAL_IDENTIFIER),
    (re.compile(r"\b(?:card[ _-]?number|credit[ _-]?card|debit[ _-]?card|payment[ _-]?card)\b", re.I), EntityType.PAYMENT_CARD_NUMBER),
    (re.compile(r"\b(?:date|timestamp|time)\b", re.I), EntityType.GENERIC_DATE),
)


_IDENTITY_REUSE_PROHIBITED_TYPES = {
    EntityType.PERSON_NAME,
    EntityType.EMAIL,
    EntityType.PHONE,
    EntityType.AADHAAR_LIKE,
    EntityType.PAN_LIKE,
    EntityType.NATIONAL_ID,
    EntityType.PASSPORT_NUMBER,
    EntityType.DRIVER_LICENSE_NUMBER,
    EntityType.TAX_IDENTIFIER,
    EntityType.SOCIAL_IDENTIFIER,
    EntityType.PAYMENT_CARD_NUMBER,
    EntityType.CASE_REFERENCE,
    EntityType.DATE_OF_BIRTH,
    EntityType.STREET_ADDRESS,
    EntityType.BUILDING_NUMBER,
    EntityType.POSTCODE,
}

_DISTRIBUTIONAL_ENTITY_TYPES = {
    EntityType.AGE,
    EntityType.LOCALITY,
    EntityType.DEMOGRAPHIC_ATTRIBUTE,
    EntityType.GENERIC_DATE,
    EntityType.JOB_TITLE,
}


@dataclass(frozen=True)
class SyntheticTwinResult:
    data: bytes
    media_type: str
    extension: str
    report: dict[str, Any]
    replacement_by_mention: dict[str, str]


def _seed_from(data: bytes, source_filename: str | None, release_salt: bytes | None = None) -> int:
    digest = hashlib.sha256(
        b"veilgraph.synthetic-twin.v1\x00"
        + (source_filename or "").encode("utf-8")
        + b"\x00"
        + data
        + b"\x00"
        + (release_salt or b"")
    ).digest()
    return int.from_bytes(digest[:8], "big")


def _header_type(header: str) -> EntityType | None:
    for pattern, entity_type in _HEADER_HINTS:
        if pattern.search(header):
            return entity_type
    return None


def _derangement(size: int, rng: random.Random) -> list[int]:
    if size <= 1:
        return list(range(size))
    values = list(range(size))
    for _ in range(64):
        rng.shuffle(values)
        if all(index != value for index, value in enumerate(values)):
            return values[:]
    # Deterministic fallback with no fixed points for n > 1.
    return list(range(1, size)) + [0]


def _safe_float(value: Any) -> float | None:
    if isinstance(value, bool) or value in {None, ""}:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _parse_date(value: Any) -> tuple[datetime, str] | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    formats = (
        "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%Y/%m/%d",
        "%d %B %Y", "%d %b %Y", "%B %d, %Y", "%b %d, %Y",
    )
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt), fmt
        except ValueError:
            continue
    return None


def _format_like_number(original: Any, value: float) -> Any:
    if isinstance(original, int) and not isinstance(original, bool):
        return int(round(value))
    if isinstance(original, float):
        return round(value, 4)
    text = str(original)
    if re.fullmatch(r"[-+]?\d+", text.strip()):
        return str(int(round(value)))
    if re.fullmatch(r"[-+]?(?:\d+\.\d*|\d*\.\d+)", text.strip()):
        decimals = len(text.rsplit(".", 1)[1]) if "." in text else 2
        return f"{value:.{min(decimals, 6)}f}"
    return value


def _normalised_row(values: list[Any]) -> tuple[str, ...]:
    return tuple(re.sub(r"\s+", " ", str(value if value is not None else "").strip().casefold()) for value in values)


def _pearson(left: list[float], right: list[float]) -> float | None:
    pairs = [(a, b) for a, b in zip(left, right) if math.isfinite(a) and math.isfinite(b)]
    if len(pairs) < 3:
        return None
    xs, ys = zip(*pairs)
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    dx = [x - mx for x in xs]
    dy = [y - my for y in ys]
    denom = math.sqrt(sum(v * v for v in dx) * sum(v * v for v in dy))
    if denom <= 1e-12:
        return 0.0
    return max(-1.0, min(1.0, sum(a * b for a, b in zip(dx, dy)) / denom))


def _categorical_fidelity(original: list[Any], synthetic: list[Any]) -> float:
    """Compare categorical distribution, allowing privacy-safe category renaming.

    Exact category labels are preferred when semantics are intentionally retained.
    For protected categorical identifiers (for example locality), L5 may rename the
    categories while preserving their frequency shape.  We therefore measure both
    label-aware total-variation fidelity and anonymous frequency-shape fidelity.
    """
    if not original:
        return 1.0

    def counts(values: list[Any]) -> dict[str, int]:
        result: dict[str, int] = {}
        for value in values:
            key = str(value)
            result[key] = result.get(key, 0) + 1
        return result

    a, b = counts(original), counts(synthetic)
    n = max(1, len(original))
    keys = set(a) | set(b)
    label_tv = 0.5 * sum(abs(a.get(key, 0) / n - b.get(key, 0) / n) for key in keys)
    label_score = max(0.0, 1.0 - label_tv)

    ashape = sorted((count / n for count in a.values()), reverse=True)
    bshape = sorted((count / n for count in b.values()), reverse=True)
    width = max(len(ashape), len(bshape))
    ashape += [0.0] * (width - len(ashape))
    bshape += [0.0] * (width - len(bshape))
    shape_tv = 0.5 * sum(abs(left - right) for left, right in zip(ashape, bshape))
    shape_score = max(0.0, 1.0 - shape_tv)
    return max(label_score, shape_score)


def _time_order_fidelity(original: list[Any], synthetic: list[Any]) -> float | None:
    before = [_parse_date(value) for value in original]
    after = [_parse_date(value) for value in synthetic]
    pairs = [
        (left[0], right[0])
        for left, right in zip(before, after)
        if left is not None and right is not None
    ]
    if len(pairs) < 2:
        return None
    concordant = 0
    total = 0
    for i in range(len(pairs)):
        for j in range(i + 1, len(pairs)):
            before_delta = (pairs[i][0] - pairs[j][0]).total_seconds()
            after_delta = (pairs[i][1] - pairs[j][1]).total_seconds()
            if before_delta == 0 and after_delta == 0:
                concordant += 1
            elif before_delta * after_delta > 0:
                concordant += 1
            total += 1
    return concordant / max(1, total)


def _synthetic_value(entity_type: EntityType, original: str, index: int, rng: random.Random, entity_key: str) -> str:
    token = hashlib.sha256(f"{entity_key}:{index}".encode()).hexdigest()
    number = int(token[:10], 16)
    first = _SYNTHETIC_FIRST[number % len(_SYNTHETIC_FIRST)]
    last = _SYNTHETIC_LAST[(number // len(_SYNTHETIC_FIRST)) % len(_SYNTHETIC_LAST)]
    city = _SYNTHETIC_CITIES[(number // 17) % len(_SYNTHETIC_CITIES)]
    street = _SYNTHETIC_STREETS[(number // 31) % len(_SYNTHETIC_STREETS)]
    if entity_type == EntityType.PERSON_NAME:
        return f"{first} {last}"
    if entity_type == EntityType.PERSON_TITLE:
        return ("Mr", "Ms", "Dr", "Mx")[number % 4]
    if entity_type == EntityType.EMAIL:
        return f"{first.lower()}.{last.lower()}.{number % 997:03d}@example.test"
    if entity_type == EntityType.PHONE:
        return f"+91 70000 {10000 + number % 89999:05d}"
    if entity_type == EntityType.STREET_ADDRESS:
        return f"{10 + number % 380}, {street}, {city}"
    if entity_type == EntityType.BUILDING_NUMBER:
        return str(10 + number % 380)
    if entity_type == EntityType.LOCALITY:
        return city
    if entity_type == EntityType.POSTCODE:
        return f"{100000 + number % 899999:06d}"
    if entity_type == EntityType.AGE:
        match = re.search(r"\d{1,3}", original)
        base = int(match.group()) if match else 30
        delta = (-3, -2, -1, 1, 2, 3)[number % 6]
        return str(max(1, min(99, base + delta)))
    if entity_type in {EntityType.DATE_OF_BIRTH, EntityType.GENERIC_DATE}:
        parsed = _parse_date(original)
        if parsed:
            dt, fmt = parsed
            shifted = dt + timedelta(days=365 * (1 + number % 4) + (number % 23))
            return shifted.strftime(fmt)
        return f"{1 + number % 28:02d}/{1 + (number // 7) % 12:02d}/{1990 + number % 30}"
    if entity_type == EntityType.DEMOGRAPHIC_ATTRIBUTE:
        lowered = original.strip().casefold()
        if lowered in {"m", "male", "man"}:
            return "Male"
        if lowered in {"f", "female", "woman"}:
            return "Female"
        return ("Category A", "Category B", "Category C")[number % 3]
    if entity_type == EntityType.PASSPORT_NUMBER:
        return f"V{1000000 + number % 8999999:07d}"
    if entity_type == EntityType.DRIVER_LICENSE_NUMBER:
        return f"VG-DL-{100000 + number % 899999:06d}"
    if entity_type in {EntityType.NATIONAL_ID, EntityType.AADHAAR_LIKE}:
        return f"VG-ID-{10000000 + number % 89999999:08d}"
    if entity_type in {EntityType.TAX_IDENTIFIER, EntityType.PAN_LIKE}:
        return f"VGTAX{1000 + number % 8999:04d}X"
    if entity_type == EntityType.SOCIAL_IDENTIFIER:
        return f"VG-SS-{100000 + number % 899999:06d}"
    if entity_type == EntityType.PAYMENT_CARD_NUMBER:
        # Deliberately non-Luhn, non-live synthetic credential.
        digits = f"9900{number % 10**12:012d}"[:16]
        return " ".join(digits[pos:pos + 4] for pos in range(0, 16, 4))
    if entity_type == EntityType.EMPLOYER:
        return f"Synthetic Organisation {1 + number % 97}"
    if entity_type == EntityType.JOB_TITLE:
        return ("Analyst", "Engineer", "Research Associate", "Operations Specialist")[number % 4]
    if entity_type == EntityType.CASE_REFERENCE:
        return f"SYN-CASE-{10000 + number % 89999:05d}"
    return f"Synthetic-{number % 100000:05d}"


def _forbidden_alpha_fragments(forbidden: set[str]) -> set[str]:
    """Source tokens that would make a generated identity look linkable.

    Exact aggregate values such as ages may legitimately recur in a synthetic
    population, but distinctive alphabetic fragments from names, addresses and
    other sensitive values must not be recycled into a generated identity.
    """
    fragments: set[str] = set()
    generic_tokens = {"example", "sample", "test", "demo", "synthetic", "invalid"}
    for value in forbidden:
        fragments.update(
            token.casefold()
            for token in re.findall(r"[^\W\d_]{5,}", value, flags=re.UNICODE)
            if token.casefold() not in generic_tokens
        )
    return fragments


def _safe_synthetic_value(
    entity_type: EntityType,
    original: str,
    index: int,
    rng: random.Random,
    entity_key: str,
    forbidden: set[str],
) -> str:
    forbidden_fragments = _forbidden_alpha_fragments(forbidden)
    for attempt in range(64):
        candidate = _synthetic_value(entity_type, original, index + attempt * 997, rng, f"{entity_key}:{attempt}")
        folded = candidate.casefold().strip()
        has_source_fragment = any(
            re.search(rf"\b{re.escape(fragment)}\b", folded)
            for fragment in forbidden_fragments
        )
        if (
            folded
            and folded not in forbidden
            and folded != original.casefold().strip()
            and not has_source_fragment
        ):
            return candidate
    # Fail closed with a product-scoped value rather than reusing a source value.
    return f"VG-SYN-{hashlib.sha256((entity_key + original).encode()).hexdigest()[:12].upper()}"


def _synthesise_table(
    table: StructuredTable,
    rng: random.Random,
    sensitive_by_position: dict[tuple[int, int], list[ProtectionInstruction]],
    sheet_index: int,
    entity_replacements: dict[str, str],
    replacement_by_mention: dict[str, str],
    forbidden: set[str],
) -> StructuredTable:
    rows = deepcopy(table.rows)
    n = len(rows)
    if n == 0:
        return StructuredTable(table.name, list(table.headers), rows)
    donor = _derangement(n, rng)

    columns: list[list[Any]] = []
    for col in range(len(table.headers)):
        columns.append([row[col] if col < len(row) else "" for row in table.rows])

    for col, header in enumerate(table.headers):
        original_col = columns[col]
        hinted = _header_type(header)
        numeric_values = [_safe_float(value) for value in original_col]
        numeric_count = sum(value is not None for value in numeric_values)
        parsed_dates = [_parse_date(value) for value in original_col]
        date_count = sum(item is not None for item in parsed_dates)
        unique_nonempty = {str(value) for value in original_col if str(value).strip()}
        unique_ratio = len(unique_nonempty) / max(1, sum(bool(str(value).strip()) for value in original_col))
        categorical = unique_ratio <= 0.50 and len(unique_nonempty) <= 32

        if hinted is not None:
            if hinted == EntityType.AGE and numeric_count >= max(3, int(n * 0.70)):
                observed = [value for value in numeric_values if value is not None]
                spread = statistics.pstdev(observed) if len(observed) >= 2 else 2.0
                for row_index in range(n):
                    source_index = donor[row_index]
                    base = numeric_values[source_index]
                    if base is None:
                        rows[row_index][col] = "Age protected"
                        continue
                    jitter = rng.choice((-2, -1, 1, 2)) if spread >= 2 else rng.choice((-1, 1))
                    rows[row_index][col] = _format_like_number(original_col[source_index], max(1, min(99, base + jitter)))
            elif hinted in {EntityType.GENERIC_DATE, EntityType.DATE_OF_BIRTH} and date_count >= max(2, int(n * 0.60)):
                # One release-wide shift for the column preserves ordering and
                # intervals while ensuring no original exact date is retained.
                shift_days = 181 + rng.randrange(120, 730)
                for row_index, parsed in enumerate(parsed_dates):
                    if parsed is None:
                        rows[row_index][col] = _safe_synthetic_value(
                            hinted, str(original_col[row_index]), row_index, rng,
                            f"date:{sheet_index}:{col}:{row_index}", forbidden,
                        )
                    else:
                        dt, fmt = parsed
                        rows[row_index][col] = (dt + timedelta(days=shift_days)).strftime(fmt)
            elif hinted in _DISTRIBUTIONAL_ENTITY_TYPES and categorical:
                # Preserve the source marginal counts without retaining the source
                # categorical label. The mapping is population-level, not identity-level.
                category_map: dict[str, str] = {}
                for row_index, raw in enumerate(original_col):
                    source = str(raw)
                    folded_source = source.casefold()
                    if folded_source not in category_map:
                        category_map[folded_source] = _safe_synthetic_value(
                            hinted, source, len(category_map), rng,
                            f"category:{sheet_index}:{col}:{folded_source}", forbidden,
                        )
                    rows[row_index][col] = category_map[folded_source]
            else:
                for row_index in range(n):
                    source = str(original_col[row_index])
                    key = f"header:{sheet_index}:{col}:{row_index}:{header}"
                    rows[row_index][col] = _safe_synthetic_value(hinted, source, row_index, rng, key, forbidden)
            continue

        if numeric_count >= max(3, int(n * 0.70)):
            observed = [value for value in numeric_values if value is not None]
            spread = statistics.pstdev(observed) if len(observed) >= 2 else max(1.0, abs(observed[0]) * 0.05 if observed else 1.0)
            noise_scale = max(1e-6, spread * 0.035)
            for row_index in range(n):
                source_index = donor[row_index]
                base = numeric_values[source_index]
                if base is None:
                    rows[row_index][col] = original_col[source_index]
                    continue
                jitter = rng.gauss(0.0, noise_scale)
                candidate = base + jitter
                rows[row_index][col] = _format_like_number(original_col[source_index], candidate)
            continue

        if date_count >= max(2, int(n * 0.60)):
            shift_days = 91 + rng.randrange(0, 730)
            for row_index in range(n):
                source_index = donor[row_index]
                parsed = parsed_dates[source_index]
                if parsed is None:
                    rows[row_index][col] = original_col[source_index]
                else:
                    dt, fmt = parsed
                    rows[row_index][col] = (dt + timedelta(days=shift_days)).strftime(fmt)
            continue

        if categorical:
            shift = 1 + rng.randrange(max(1, n - 1)) if n > 1 else 0
            for row_index in range(n):
                rows[row_index][col] = original_col[(row_index + shift) % n]
            continue

        # High-cardinality/free-text values are never copied verbatim.
        for row_index, value in enumerate(original_col):
            text = str(value or "")
            if not text:
                rows[row_index][col] = ""
            else:
                digest = hashlib.sha256(f"{sheet_index}:{col}:{row_index}:{text}".encode()).hexdigest()
                rows[row_index][col] = f"Synthetic {header[:28]} {int(digest[:8], 16) % 100000:05d}"

    # Apply entity-bound synthetic values last. This preserves repeated-entity
    # consistency across cells and lets the proof manifest commit exact output values.
    for (row_index, col), instructions in sensitive_by_position.items():
        if row_index >= n or col >= len(table.headers):
            continue
        source_text = str(table.rows[row_index][col] if col < len(table.rows[row_index]) else "")
        cell_value = str(rows[row_index][col])
        header = table.headers[col]
        hinted = _header_type(header)
        if hinted is not None:
            # Header-aware synthesis already produced the complete safe scalar.
            # Commit that exact generated scalar for every mention in the cell.
            generated = str(rows[row_index][col])
            if generated.casefold().strip() in forbidden:
                generated = _safe_synthetic_value(hinted, source_text, row_index, rng, f"cell:{sheet_index}:{row_index}:{col}", forbidden)
                rows[row_index][col] = generated
            for instruction in instructions:
                replacement_by_mention[instruction.mention_id] = generated
        else:
            unique_replacements: list[str] = []
            for instruction in instructions:
                replacement = _safe_synthetic_value(
                    instruction.entity_type, source_text, row_index, rng,
                    f"{instruction.entity_id}:{instruction.mention_id}", forbidden,
                )
                replacement_by_mention[instruction.mention_id] = replacement
                if replacement not in unique_replacements:
                    unique_replacements.append(replacement)
            rows[row_index][col] = " | ".join(unique_replacements)

    return StructuredTable(table.name, list(table.headers), rows)


def _json_set(root: Any, path: tuple[Any, ...], value: Any) -> None:
    node = root
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value


def _synthesise_json(
    dataset: StructuredDataset,
    rng: random.Random,
    sensitive_by_locator: dict[tuple[Any, ...], list[ProtectionInstruction]],
    entity_replacements: dict[str, str],
    replacement_by_mention: dict[str, str],
    forbidden: set[str],
) -> StructuredDataset:
    root = deepcopy(dataset.json_root)
    assert root is not None
    cells = list(iter_cells(dataset))

    by_header: dict[str, list[Any]] = {}
    for cell in cells:
        by_header.setdefault(cell.header, []).append(cell.value)

    profiles: dict[str, dict[str, Any]] = {}
    global_donor = _derangement(max(1, dataset.record_count), rng)
    for header, values in by_header.items():
        numeric_values = [_safe_float(value) for value in values]
        parsed_dates = [_parse_date(value) for value in values]
        nonempty_count = max(1, sum(bool(str(value).strip()) for value in values))
        unique_nonempty = {str(value) for value in values if str(value).strip()}
        profiles[header] = {
            "values": values,
            "numeric_values": numeric_values,
            "numeric_count": sum(value is not None for value in numeric_values),
            "parsed_dates": parsed_dates,
            "date_count": sum(item is not None for item in parsed_dates),
            "categorical": len(unique_nonempty) / nonempty_count <= 0.50 and len(unique_nonempty) <= 32,
            "donor": global_donor if len(values) == dataset.record_count else _derangement(len(values), rng),
            "date_shift": 181 + rng.randrange(120, 730),
            "category_map": {},
        }

    position_by_header: dict[str, int] = {header: 0 for header in by_header}

    for cell in cells:
        header = cell.header
        profile = profiles[header]
        values: list[Any] = profile["values"]
        position = position_by_header[header]
        position_by_header[header] += 1
        hinted = _header_type(header)
        instructions = sensitive_by_locator.get(tuple(cell.locator), [])
        source = cell.display_value
        generated: Any = None

        if hinted is not None:
            if hinted == EntityType.AGE and profile["numeric_count"] >= max(3, int(len(values) * 0.70)):
                donor = profile["donor"]
                source_index = donor[position]
                base = profile["numeric_values"][source_index]
                if base is None:
                    generated = "Age protected"
                else:
                    observed = [value for value in profile["numeric_values"] if value is not None]
                    spread = statistics.pstdev(observed) if len(observed) >= 2 else 2.0
                    jitter = rng.choice((-2, -1, 1, 2)) if spread >= 2 else rng.choice((-1, 1))
                    generated = _format_like_number(values[source_index], max(1, min(99, base + jitter)))
            elif hinted in {EntityType.GENERIC_DATE, EntityType.DATE_OF_BIRTH} and profile["date_count"] >= max(2, int(len(values) * 0.60)):
                parsed = profile["parsed_dates"][position]
                if parsed is None:
                    generated = _safe_synthetic_value(hinted, source, position, rng, f"json-date:{header}:{position}", forbidden)
                else:
                    dt, fmt = parsed
                    generated = (dt + timedelta(days=profile["date_shift"])).strftime(fmt)
            elif hinted in _DISTRIBUTIONAL_ENTITY_TYPES and profile["categorical"]:
                category_map: dict[str, str] = profile["category_map"]
                source_key = str(cell.value).casefold()
                if source_key not in category_map:
                    category_map[source_key] = _safe_synthetic_value(
                        hinted, source, len(category_map), rng,
                        f"json-category:{header}:{source_key}", forbidden,
                    )
                generated = category_map[source_key]
            else:
                generated = _safe_synthetic_value(
                    hinted, source, position, rng, f"json:{cell.locator}", forbidden,
                )
        elif isinstance(cell.value, bool) or cell.value is None:
            generated = cell.value
        elif profile["numeric_count"] >= max(3, int(len(values) * 0.70)):
            donor = profile["donor"]
            source_index = donor[position]
            base = profile["numeric_values"][source_index]
            if base is None:
                generated = values[source_index]
            else:
                observed = [value for value in profile["numeric_values"] if value is not None]
                spread = statistics.pstdev(observed) if len(observed) >= 2 else max(1.0, abs(base) * 0.05)
                generated = _format_like_number(values[source_index], base + rng.gauss(0.0, max(1e-6, spread * 0.035)))
        elif profile["date_count"] >= max(2, int(len(values) * 0.60)):
            parsed = profile["parsed_dates"][position]
            if parsed is None:
                generated = cell.value
            else:
                dt, fmt = parsed
                generated = (dt + timedelta(days=profile["date_shift"])).strftime(fmt)
        elif profile["categorical"] and len(values) > 1:
            donor = profile["donor"]
            generated = values[donor[position]]
        elif str(cell.value):
            digest = hashlib.sha256(f"json:{cell.locator}:{cell.value}".encode()).hexdigest()
            generated = f"Synthetic {header[:24]} {int(digest[:8], 16) % 100000:05d}"
        else:
            generated = ""

        if instructions:
            if hinted is not None:
                # The header-level model already created the correct full scalar;
                # bind every detector mention to that exact committed value.
                safe_generated = str(generated)
                if safe_generated.casefold().strip() in forbidden:
                    safe_generated = _safe_synthetic_value(
                        hinted, source, position, rng, f"json-cell:{cell.locator}", forbidden,
                    )
                    generated = safe_generated
                for instruction in instructions:
                    replacement_by_mention[instruction.mention_id] = safe_generated
            else:
                replacements: list[str] = []
                for instruction in instructions:
                    replacement = _safe_synthetic_value(
                        instruction.entity_type, source, position, rng,
                        f"{instruction.entity_id}:{instruction.mention_id}", forbidden,
                    )
                    replacement_by_mention[instruction.mention_id] = replacement
                    if replacement not in replacements:
                        replacements.append(replacement)
                generated = " | ".join(replacements)

        _json_set(root, tuple(cell.locator), generated)

    return StructuredDataset(format="json", tables=[StructuredTable("JSON", [], [])], json_root=root)


def _instruction_locations(dataset: StructuredDataset, instructions: list[ProtectionInstruction]) -> tuple[
    dict[tuple[int, int, int], list[ProtectionInstruction]], dict[tuple[Any, ...], list[ProtectionInstruction]]
]:
    refs = virtual_cell_index(dataset)
    by_position: dict[tuple[int, int, int], list[ProtectionInstruction]] = {}
    by_locator: dict[tuple[Any, ...], list[ProtectionInstruction]] = {}
    for instruction in instructions:
        if instruction.char_start is None or instruction.char_end is None:
            raise StructuredDataError("Synthetic Twin requires exact structured scalar-span commitments")
        matches = [
            ref for ref in refs
            if ref.page_index == instruction.page_index
            and int(instruction.char_start) >= ref.value_char_start
            and int(instruction.char_end) <= ref.value_char_end
        ]
        if len(matches) != 1:
            raise StructuredDataError(f"Synthetic Twin could not bind mention {instruction.mention_id} to exactly one source cell")
        ref = matches[0]
        by_locator.setdefault(tuple(ref.cell.locator), []).append(instruction)
        if dataset.format != "json":
            sheet, row, col = (int(part) for part in ref.cell.locator)
            by_position.setdefault((sheet, row, col), []).append(instruction)
    return by_position, by_locator


def _dataset_rows(dataset: StructuredDataset) -> list[list[Any]]:
    if dataset.format == "json":
        grouped: dict[int, list[Any]] = {}
        for cell in iter_cells(dataset):
            grouped.setdefault(cell.record_index, []).append(cell.value)
        return [grouped[index] for index in sorted(grouped)]
    return [list(row) for table in dataset.tables for row in table.rows]


def _utility_report(original: StructuredDataset, synthetic: StructuredDataset, identity_source_values: set[str]) -> dict[str, Any]:
    original_rows = _dataset_rows(original)
    synthetic_rows = _dataset_rows(synthetic)
    original_row_set = {_normalised_row(row) for row in original_rows}
    copied_rows = sum(_normalised_row(row) in original_row_set for row in synthetic_rows)
    exact_row_copy_rate = copied_rows / max(1, len(synthetic_rows))

    source_sensitive = {value.casefold().strip() for value in identity_source_values if value.strip()}
    synthetic_visible = "\n".join(str(cell.value) for cell in iter_cells(synthetic)).casefold()
    reused_sensitive = sorted(value for value in source_sensitive if len(value) >= 4 and value in synthetic_visible)

    numeric_mean_scores: list[float] = []
    numeric_std_scores: list[float] = []
    corr_scores: list[float] = []
    category_scores: list[float] = []
    time_scores: list[float] = []

    def series_by_key(dataset: StructuredDataset) -> dict[str, list[Any]]:
        grouped: dict[str, list[Any]] = {}
        if dataset.format == "json":
            for cell in iter_cells(dataset):
                grouped.setdefault(cell.header, []).append(cell.value)
            return grouped
        for table_index, table in enumerate(dataset.tables):
            for col, header in enumerate(table.headers):
                key = f"{table_index}:{header}"
                grouped[key] = [row[col] if col < len(row) else "" for row in table.rows]
        return grouped

    before_series = series_by_key(original)
    after_series = series_by_key(synthetic)
    numeric_series: dict[str, tuple[list[float], list[float]]] = {}

    for key in sorted(set(before_series) & set(after_series)):
        before_values = before_series[key]
        after_values = after_series[key]
        if len(before_values) != len(after_values) or not before_values:
            continue
        time_score = _time_order_fidelity(before_values, after_values)
        if time_score is not None:
            time_scores.append(time_score)

        bnums = [_safe_float(value) for value in before_values]
        anums = [_safe_float(value) for value in after_values]
        pairs = [(a, b) for a, b in zip(bnums, anums) if a is not None and b is not None]
        if len(pairs) >= max(3, int(len(before_values) * 0.60)):
            bx = [a for a, _ in pairs]
            ax = [b for _, b in pairs]
            bmean, amean = statistics.fmean(bx), statistics.fmean(ax)
            bstd = statistics.pstdev(bx) if len(bx) >= 2 else 0.0
            astd = statistics.pstdev(ax) if len(ax) >= 2 else 0.0
            scale = max(abs(bmean), bstd, 1.0)
            numeric_mean_scores.append(max(0.0, 1.0 - abs(amean - bmean) / scale))
            numeric_std_scores.append(max(0.0, 1.0 - abs(astd - bstd) / max(bstd, 1.0)))
            numeric_series[key] = (bx, ax)
        else:
            unique = {str(value) for value in before_values if str(value).strip()}
            if unique and len(unique) <= 32 and len(unique) / max(1, len(before_values)) <= 0.50:
                category_scores.append(_categorical_fidelity(before_values, after_values))

    numeric_keys = sorted(numeric_series)
    for left in range(len(numeric_keys)):
        for right in range(left + 1, len(numeric_keys)):
            bx_left, ax_left = numeric_series[numeric_keys[left]]
            bx_right, ax_right = numeric_series[numeric_keys[right]]
            if len(bx_left) != len(bx_right) or len(ax_left) != len(ax_right):
                continue
            before_corr = _pearson(bx_left, bx_right)
            after_corr = _pearson(ax_left, ax_right)
            if before_corr is not None and after_corr is not None:
                corr_scores.append(max(0.0, 1.0 - abs(before_corr - after_corr) / 2.0))

    schema_preserved = (
        original.format == synthetic.format
        and original.record_count == synthetic.record_count
        and original.field_count == synthetic.field_count
        and original.sheet_count == synthetic.sheet_count
    )
    mean_fidelity = statistics.fmean(numeric_mean_scores) if numeric_mean_scores else 1.0
    std_fidelity = statistics.fmean(numeric_std_scores) if numeric_std_scores else 1.0
    correlation_fidelity = statistics.fmean(corr_scores) if corr_scores else 1.0
    category_fidelity = statistics.fmean(category_scores) if category_scores else 1.0
    time_fidelity = statistics.fmean(time_scores) if time_scores else 1.0
    utility = int(100 * (
        0.18 * (1.0 if schema_preserved else 0.0)
        + 0.17 * mean_fidelity
        + 0.13 * std_fidelity
        + 0.22 * correlation_fidelity
        + 0.15 * category_fidelity
        + 0.15 * time_fidelity
    ))
    privacy = round(100 * max(0.0, 1.0 - 0.70 * exact_row_copy_rate - 0.30 * min(1.0, len(reused_sensitive) / max(1, len(source_sensitive)))))
    return {
        "schema_preserved": schema_preserved,
        "record_count_original": original.record_count,
        "record_count_synthetic": synthetic.record_count,
        "exact_row_copies": copied_rows,
        "exact_row_copy_rate": round(exact_row_copy_rate, 6),
        "sensitive_source_values": len(source_sensitive),
        "sensitive_reuse_scope": "Exact-reuse metric covers source identity/unique-marker classes; distributional attributes such as age, locality and gender may legitimately recur in a synthetic population.",
        "sensitive_exact_reuse_count": len(reused_sensitive),
        "sensitive_exact_reuse_rate": round(len(reused_sensitive) / max(1, len(source_sensitive)), 6),
        "numeric_mean_fidelity": round(mean_fidelity, 6),
        "numeric_std_fidelity": round(std_fidelity, 6),
        "numeric_correlation_fidelity": round(correlation_fidelity, 6),
        "categorical_distribution_fidelity": round(category_fidelity, 6),
        "time_order_fidelity": round(time_fidelity, 6),
        "utility_score": max(0, min(100, utility)),
        "privacy_score": max(0, min(100, privacy)),
        "measurement_note": "Product utility/privacy evidence for this generated twin; not a formal differential-privacy or legal-anonymity guarantee.",
    }


def synthesize_structured_twin(
    data: bytes,
    instructions: list[ProtectionInstruction],
    source_filename: str | None = None,
    *,
    release_salt: bytes | None = None,
) -> SyntheticTwinResult:
    original = parse_structured_data(data, source_filename)
    by_position, by_locator = _instruction_locations(original, instructions)
    seed = _seed_from(data, source_filename, release_salt)
    rng = random.Random(seed)
    entity_replacements: dict[str, str] = {}
    replacement_by_mention: dict[str, str] = {}

    # Extract source sensitive substrings before synthesis for privacy screening.
    refs = virtual_cell_index(original)
    sensitive_source_values: set[str] = set()
    identity_source_values: set[str] = set()
    for instruction in instructions:
        for ref in refs:
            if (
                ref.page_index == instruction.page_index
                and instruction.char_start is not None and instruction.char_end is not None
                and int(instruction.char_start) >= ref.value_char_start
                and int(instruction.char_end) <= ref.value_char_end
            ):
                start = int(instruction.char_start) - ref.value_char_start
                end = int(instruction.char_end) - ref.value_char_start
                value = ref.cell.display_value[start:end].strip()
                if value:
                    sensitive_source_values.add(value)
                    if instruction.entity_type in _IDENTITY_REUSE_PROHIBITED_TYPES:
                        identity_source_values.add(value)
                break

    forbidden = {value.casefold().strip() for value in sensitive_source_values if value.strip()}
    if original.format == "json":
        synthetic = _synthesise_json(original, rng, by_locator, entity_replacements, replacement_by_mention, forbidden)
    else:
        tables: list[StructuredTable] = []
        for sheet_index, table in enumerate(original.tables):
            table_sensitive: dict[tuple[int, int], list[ProtectionInstruction]] = {}
            for (sheet, row, col), items in by_position.items():
                if sheet == sheet_index:
                    table_sensitive[(row, col)] = items
            tables.append(_synthesise_table(
                table, rng, table_sensitive, sheet_index,
                entity_replacements, replacement_by_mention, forbidden,
            ))
        synthetic = StructuredDataset(format=original.format, tables=tables)

    report = _utility_report(original, synthetic, identity_source_values)
    report.update({
        "schema": "veilgraph.synthetic-twin.v1",
        "engine": "local deterministic schema-aware synthesizer",
        "seed_commitment_sha256": hashlib.sha256(str(seed).encode()).hexdigest(),
        "release_randomized": release_salt is not None,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "synthetic_mention_bindings": len(replacement_by_mention),
        "time_sequence_policy": "Date-like columns are shifted while preserving order/interval structure when parseable.",
        "constraint_policy": "Schema/record shape preserved; detected identity fields are regenerated; low-cardinality analytical categories preserve marginals; numeric columns use shared donor ordering plus bounded perturbation.",
    })
    protected, media_type, extension = export_structured_data(synthetic)
    report["output_sha256"] = hashlib.sha256(protected).hexdigest()
    return SyntheticTwinResult(protected, media_type, extension, report, replacement_by_mention)
