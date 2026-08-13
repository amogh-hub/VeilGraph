# VeilGraph Phase 1 Judge-Readiness Benchmark

Detection quality uses unique entity/value pairs per file; repeated mentions are scored under Evidence Quality so long videos/repeated headers cannot dominate the metric.

## VG-JUDGE-SHOWCASE-1.0

- Precision: **0.9974**
- Recall: **1.0000**
- F1: **0.9987**
- F2: **0.9995**
- Explicit-negative-control FPR: **0.0000** (0/8)
- Evidence accuracy: **0.9731**
- Out-of-bounds detections: **2**

### Per format

| Format | P | R | F1 | F2 |
|---|---:|---:|---:|---:|
| CSV | 1.000 | 1.000 | 1.000 | 1.000 |
| DOCX | 1.000 | 1.000 | 1.000 | 1.000 |
| JSON | 1.000 | 1.000 | 1.000 | 1.000 |
| MD | 1.000 | 1.000 | 1.000 | 1.000 |
| MP4 | 1.000 | 1.000 | 1.000 | 1.000 |
| PDF | 0.955 | 1.000 | 0.977 | 0.991 |
| PNG | 1.000 | 1.000 | 1.000 | 1.000 |
| RTF | 1.000 | 1.000 | 1.000 | 1.000 |
| TXT | 1.000 | 1.000 | 1.000 | 1.000 |
| XLSX | 1.000 | 1.000 | 1.000 | 1.000 |

### Per entity

| Entity | P | R | F1 | F2 |
|---|---:|---:|---:|---:|
| AADHAAR_LIKE | 1.000 | 1.000 | 1.000 | 1.000 |
| AGE | 1.000 | 1.000 | 1.000 | 1.000 |
| CASE_REFERENCE | 1.000 | 1.000 | 1.000 | 1.000 |
| EMAIL | 1.000 | 1.000 | 1.000 | 1.000 |
| EMPLOYER | 1.000 | 1.000 | 1.000 | 1.000 |
| GENERIC_DATE | 1.000 | 1.000 | 1.000 | 1.000 |
| LOCALITY | 1.000 | 1.000 | 1.000 | 1.000 |
| PAN_LIKE | 1.000 | 1.000 | 1.000 | 1.000 |
| PERSON_NAME | 1.000 | 1.000 | 1.000 | 1.000 |
| PHONE | 1.000 | 1.000 | 1.000 | 1.000 |
| POSTCODE | 1.000 | 1.000 | 1.000 | 1.000 |
| QR_CODE | 0.750 | 1.000 | 0.857 | 0.938 |
| SIGNATURE_CANDIDATE | 1.000 | 1.000 | 1.000 | 1.000 |

## VG-JUDGE-CHAOS-1.0

- Precision: **0.9519**
- Recall: **0.9340**
- F1: **0.9429**
- F2: **0.9375**
- Explicit-negative-control FPR: **0.0000** (0/6)
- Evidence accuracy: **0.8611**
- Out-of-bounds detections: **1**

### Per format

| Format | P | R | F1 | F2 |
|---|---:|---:|---:|---:|
| CSV | 1.000 | 1.000 | 1.000 | 1.000 |
| DOCX | 1.000 | 1.000 | 1.000 | 1.000 |
| JPEG | 1.000 | 1.000 | 1.000 | 1.000 |
| JSON | 1.000 | 1.000 | 1.000 | 1.000 |
| MD | 1.000 | 1.000 | 1.000 | 1.000 |
| MP4 | 1.000 | 1.000 | 1.000 | 1.000 |
| PDF | 1.000 | 0.941 | 0.970 | 0.952 |
| PNG | 0.375 | 0.333 | 0.353 | 0.341 |
| RTF | 1.000 | 1.000 | 1.000 | 1.000 |
| TXT | 1.000 | 1.000 | 1.000 | 1.000 |
| XLSX | 1.000 | 1.000 | 1.000 | 1.000 |

### Per entity

| Entity | P | R | F1 | F2 |
|---|---:|---:|---:|---:|
| AADHAAR_LIKE | 0.000 | 0.000 | 0.000 | 0.000 |
| AGE | 0.833 | 1.000 | 0.909 | 0.962 |
| CASE_REFERENCE | 1.000 | 1.000 | 1.000 | 1.000 |
| EMAIL | 1.000 | 0.944 | 0.971 | 0.955 |
| EMPLOYER | 1.000 | 1.000 | 1.000 | 1.000 |
| GENERIC_DATE | 0.500 | 1.000 | 0.667 | 0.833 |
| LOCALITY | 0.929 | 0.929 | 0.929 | 0.929 |
| PAN_LIKE | 1.000 | 0.500 | 0.667 | 0.556 |
| PERSON_NAME | 0.947 | 0.947 | 0.947 | 0.947 |
| PHONE | 0.933 | 0.933 | 0.933 | 0.933 |
| POSTCODE | 1.000 | 1.000 | 1.000 | 1.000 |
| QR_CODE | 1.000 | 1.000 | 1.000 | 1.000 |
| SIGNATURE_CANDIDATE | 1.000 | 1.000 | 1.000 | 1.000 |

## Scientific boundary

Showcase and Chaos are development/regression datasets. They are not external holdouts and must never be cited as untouched generalization evidence.
