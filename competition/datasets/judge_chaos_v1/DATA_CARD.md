# VeilGraph Judge Chaos / Generalization Dataset v1 — Data Card

**ID:** VG-JUDGE-CHAOS-1.0  
**Role:** adversarial development + regression  
**Real personal data:** none  
**Untouched holdout:** no  
**Tuning allowed:** yes

## Why it exists

A curated demo proves only that demo. This split intentionally stresses arbitrary-input behavior with blank rows, tabs, Unicode/mixed script, dense inline fields, repeated identities, two-column PDFs, low-contrast scans, rotation, long OCR lines, DOCX header/footer/table routing, messy structured files and transient video evidence.

## Required use

Every failure discovered here must be recorded as:

`case → failure → root cause → fix → regression test`

The goal is to improve robustness before the judges supply their own files.

## Limitation

Because this dataset may be used during development, its score is a regression signal, **not** final scientific generalization evidence. Final evidence requires a separately frozen, untouched external holdout.
