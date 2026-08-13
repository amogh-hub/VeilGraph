# VeilGraph Judge Showcase Dataset v1 — Data Card

**ID:** VG-JUDGE-SHOWCASE-1.0  
**Role:** judge demonstration + development evidence  
**Real personal data:** none  
**Untouched holdout:** no  
**Tuning allowed:** yes

## What it contains

11 fictional files spanning TXT, MD, RTF, digital PDF, scanned PDF, PNG, DOCX, CSV, JSON, XLSX and MP4. Ground truth covers direct identifiers, quasi/contextual identifiers, relationships, mock credential-like values and visual identifiers.

## Recommended judge demonstrations

- `04_case_packet.pdf` → L1 vs L4 reconstruction-risk story.
- `05_scanned_application.pdf` → OCR + QR/signature evidence.
- `07_case_report.docx` → body/table/header/footer + stable pseudonyms.
- `10_research_records.xlsx` → L5 Synthetic Twin.
- `11_privacy_clip.mp4` → video temporal/visual protection.

## Privacy note

All names, phone numbers, identifiers, organisations, case references and scenarios are synthetic. `example.org` is used for email domains. Aadhaar/PAN-like strings are labelled as mock evaluation values and are not assertions about real people.

## Limitation

This set is intentionally understandable and presentation-friendly. It must not be cited as proof of unseen-data generalization.
