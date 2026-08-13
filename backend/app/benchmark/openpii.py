from __future__ import annotations

import ast
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from app.benchmark.veilbench import BenchmarkCase, GoldSpan, benchmark_cases
from app.core.enums import EntityType


# Mapping covers the explicit VeilGraph v2 PII taxonomy. Unmapped labels remain
# counted and disclosed rather than silently treated as negatives.
# Unmapped OpenPII labels are counted and reported, never silently treated as
# negatives. This prevents inflated metrics through accidental label dropping.
_LABEL_MAP: dict[str, EntityType] = {
    "FIRSTNAME": EntityType.PERSON_NAME,
    "LASTNAME": EntityType.PERSON_NAME,
    "GIVENNAME": EntityType.PERSON_NAME,
    "SURNAME": EntityType.PERSON_NAME,
    "FULLNAME": EntityType.PERSON_NAME,
    "NAME": EntityType.PERSON_NAME,
    "EMAIL": EntityType.EMAIL,
    "EMAILADDRESS": EntityType.EMAIL,
    "PHONE": EntityType.PHONE,
    "PHONENUMBER": EntityType.PHONE,
    "TELEPHONENUMBER": EntityType.PHONE,
    "MOBILE": EntityType.PHONE,
    "DATEOFBIRTH": EntityType.DATE_OF_BIRTH,
    "DOB": EntityType.DATE_OF_BIRTH,
    "AGE": EntityType.AGE,
    "STREET": EntityType.STREET_ADDRESS,
    "STREETADDRESS": EntityType.STREET_ADDRESS,
    "ADDRESS": EntityType.STREET_ADDRESS,
    "CITY": EntityType.LOCALITY,
    "COUNTY": EntityType.LOCALITY,
    "DISTRICT": EntityType.LOCALITY,
    "POSTCODE": EntityType.POSTCODE,
    "ZIPCODE": EntityType.POSTCODE,
    "ZIP": EntityType.POSTCODE,
    "PINCODE": EntityType.POSTCODE,
    "EMPLOYER": EntityType.EMPLOYER,
    "COMPANY": EntityType.EMPLOYER,
    "ORGANIZATION": EntityType.EMPLOYER,
    "ORGANISATION": EntityType.EMPLOYER,
    "JOBTITLE": EntityType.JOB_TITLE,
    "OCCUPATION": EntityType.JOB_TITLE,
    "AADHAAR": EntityType.AADHAAR_LIKE,
    "PAN": EntityType.PAN_LIKE,
    "TITLE": EntityType.PERSON_TITLE,
    "DATE": EntityType.GENERIC_DATE,
    "BUILDINGNUM": EntityType.BUILDING_NUMBER,
    "IDCARDNUM": EntityType.NATIONAL_ID,
    "NATIONALID": EntityType.NATIONAL_ID,
    "PASSPORTNUM": EntityType.PASSPORT_NUMBER,
    "PASSPORTNUMBER": EntityType.PASSPORT_NUMBER,
    "DRIVERLICENSENUM": EntityType.DRIVER_LICENSE_NUMBER,
    "DRIVERLICENSENUMBER": EntityType.DRIVER_LICENSE_NUMBER,
    "TAXNUM": EntityType.TAX_IDENTIFIER,
    "TAXID": EntityType.TAX_IDENTIFIER,
    "SOCIALNUM": EntityType.SOCIAL_IDENTIFIER,
    "SSN": EntityType.SOCIAL_IDENTIFIER,
    "CREDITCARDNUMBER": EntityType.PAYMENT_CARD_NUMBER,
    "CARDNUMBER": EntityType.PAYMENT_CARD_NUMBER,
    "GENDER": EntityType.DEMOGRAPHIC_ATTRIBUTE,
    "SEX": EntityType.DEMOGRAPHIC_ATTRIBUTE,
}


def _canonical_label(raw: str) -> str:
    value = str(raw).strip().upper()
    value = re.sub(r"^[BIO]-", "", value)
    value = re.sub(r"_\d+$", "", value)
    return re.sub(r"[^A-Z0-9]", "", value)


def _parse_maybe_literal(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("[", "{")):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                try:
                    return ast.literal_eval(stripped)
                except (ValueError, SyntaxError):
                    return value
    return value


def _new_schema_spans(row: dict[str, Any], text: str) -> list[tuple[str, int, int, str]]:
    mask = _parse_maybe_literal(row.get("privacy_mask"))
    if not isinstance(mask, list):
        return []
    spans = []
    for item in mask:
        if not isinstance(item, dict):
            continue
        try:
            label = str(item["label"])
            start = int(item["start"])
            end = int(item["end"])
        except (KeyError, TypeError, ValueError):
            continue
        value = str(item.get("value", text[start:end]))
        if 0 <= start < end <= len(text):
            spans.append((label, start, end, value))
    return spans


def _old_schema_spans(row: dict[str, Any], text: str) -> list[tuple[str, int, int, str]]:
    raw = _parse_maybe_literal(row.get("span_labels"))
    if not isinstance(raw, list):
        return []
    spans = []
    for item in raw:
        if not isinstance(item, (list, tuple)) or len(item) < 3:
            continue
        try:
            start, end = int(item[0]), int(item[1])
        except (TypeError, ValueError):
            continue
        label = str(item[2])
        if label == "O" or not (0 <= start < end <= len(text)):
            continue
        spans.append((label, start, end, text[start:end]))
    return spans


def row_to_case(row: dict[str, Any], index: int) -> tuple[BenchmarkCase | None, Counter[str]]:
    text = row.get("source_text") or row.get("unmasked_text")
    if not isinstance(text, str) or not text.strip():
        return None, Counter({"invalid_row": 1})
    raw_spans = _new_schema_spans(row, text) or _old_schema_spans(row, text)
    counters: Counter[str] = Counter()
    gold: list[GoldSpan] = []
    for label, start, end, value in raw_spans:
        canonical = _canonical_label(label)
        mapped = _LABEL_MAP.get(canonical)
        if mapped is None:
            counters[f"unmapped:{canonical or 'UNKNOWN'}"] += 1
            continue
        counters[f"mapped:{canonical}"] += 1
        gold.append(GoldSpan(mapped, value, start, end))
    if not gold:
        counters["row_without_supported_gold"] += 1
        return None, counters
    language = str(row.get("language") or row.get("lang") or "unknown")
    return (
        BenchmarkCase(
            case_id=f"openpii-{index:07d}",
            domain=f"openpii/{language}",
            text=text,
            gold=tuple(gold),
            source="ai4privacy-openpii",
        ),
        counters,
    )


def load_openpii_jsonl(path: Path, *, limit: int = 500, language: str | None = "en") -> tuple[list[BenchmarkCase], Counter[str]]:
    if limit <= 0:
        raise ValueError("OpenPII benchmark limit must be positive")
    cases: list[BenchmarkCase] = []
    counters: Counter[str] = Counter()
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if len(cases) >= limit:
                break
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                counters["invalid_json"] += 1
                continue
            if language:
                row_language = str(row.get("language") or row.get("lang") or "").casefold()
                if row_language and row_language not in {language.casefold(), "english" if language.casefold() == "en" else language.casefold()}:
                    counters["language_filtered"] += 1
                    continue
            case, row_counts = row_to_case(row, index)
            counters.update(row_counts)
            if case is not None:
                cases.append(case)
    return cases, counters


def benchmark_openpii(path: Path, *, limit: int = 500, language: str | None = "en") -> dict:
    cases, counters = load_openpii_jsonl(path, limit=limit, language=language)
    if not cases:
        raise ValueError("No OpenPII rows with VeilGraph-supported labels were found")
    result = benchmark_cases(cases)
    mapped = sum(value for key, value in counters.items() if key.startswith("mapped:"))
    unmapped = sum(value for key, value in counters.items() if key.startswith("unmapped:"))
    result["dataset"] = {
        "name": "Ai4Privacy OpenPII",
        "input_file": path.name,
        "sample_limit": limit,
        "language_filter": language,
        "mapped_gold_spans": mapped,
        "unmapped_gold_spans": unmapped,
        "label_accounting": dict(sorted(counters.items())),
        "evaluation_scope": "Only OpenPII entity classes explicitly mapped to VeilGraph's currently claimed taxonomy are scored. Unmapped labels are counted and disclosed.",
    }
    return result
