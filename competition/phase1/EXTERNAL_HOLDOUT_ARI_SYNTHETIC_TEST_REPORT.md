# VeilGraph External Holdout — Ari Synthetic Test

## Scientific status

- Broad PII v5 was byte-for-byte frozen before requesting any synthetic test row.
- Only `data_source == synthetic` rows from the test split are evaluated.
- The ai4privacy portion is excluded from this final v5 holdout.
- Raw test rows are not persisted in the VeilGraph repository.
- Thresholds and taxonomy mapping were declared before acquisition.

## Provenance

- Dataset: `Ari-S-123/pii-detection-english-consolidated`
- Pinned data revision: `61e7c4fcd6c569d4cc89db9cba79deab833df085`
- Observed repository HEAD: `a3c2add092a3bfaa7dd541fdfa1185b5777f0749`
- Test artifact byte identity verified: **True**
- Synthetic test records: **1201**
- Dataset-viewer canonical stream SHA-256: `a2fab6a1aac4138357eecc53342f0fda1bddca3ebb7e01a34e4b3f8c96af381e`
- Test Parquet LFS SHA-256 declared by repository: `768d415110c5726142c38bfe82270bb6109670977c9f4ac6a7e46f4f6838e471`

## Cross-taxonomy metrics

- Exact precision: **0.3472**
- Exact recall: **0.5021**
- Exact F1: **0.4105**
- Exact F2: **0.4610**
- Relaxed compatible-span precision: **0.4029**
- Relaxed compatible-span recall: **0.5807**
- Relaxed compatible-span F1: **0.4757**
- Relaxed compatible-span F2: **0.5336**
- Critical shared recall: **0.5280**
- Contextual shared recall: **0.6886**
- No-entity FP document rate: **0.8824**

## Predeclared quality gate: **FAIL**

| Check | Value | Required | Status |
|---|---:|---:|---|
| exact_f1 | 0.4105 | ≥ 0.5000 | FAIL |
| relaxed_f1 | 0.4757 | ≥ 0.6500 | FAIL |
| critical_recall | 0.5280 | ≥ 0.7500 | FAIL |
| contextual_relaxed_recall | 0.6886 | ≥ 0.5500 | PASS |
| no_entity_fp_doc_rate | 0.8824 | ≤ 0.2000 | FAIL |

## Per-label relaxed recall

| External label | Gold | Covered | Recall |
|---|---:|---:|---:|
| CITY | 120 | 31 | 0.2583 |
| CREDITCARDNUMBER | 83 | 69 | 0.8313 |
| DATE | 220 | 179 | 0.8136 |
| DOB | 407 | 405 | 0.9951 |
| DRIVERLICENSENUM | 116 | 73 | 0.6293 |
| EMAIL | 325 | 303 | 0.9323 |
| FIRSTNAME | 783 | 351 | 0.4483 |
| IDCARDNUM | 335 | 127 | 0.3791 |
| LASTNAME | 9 | 2 | 0.2222 |
| PASSPORTNUM | 151 | 132 | 0.8742 |
| PHONENUMBER | 854 | 358 | 0.4192 |
| SSN | 107 | 60 | 0.5607 |
| STREET | 392 | 204 | 0.5204 |
| TAXNUM | 135 | 55 | 0.4074 |
| TITLE | 4 | 3 | 0.7500 |
| ZIPCODE | 273 | 153 | 0.5604 |

## Challenge-dimension relaxed recall

| Dimension | Gold | Covered | Recall |
|---|---:|---:|---:|
| adversarial | 444 | 239 | 0.5383 |
| basic | 970 | 682 | 0.7031 |
| contextual | 788 | 442 | 0.5609 |
| evolving | 272 | 159 | 0.5846 |
| multilingual | 959 | 605 | 0.6309 |
| noisy | 881 | 378 | 0.4291 |

## Non-shared external labels

These labels are disclosed and excluded from the primary VeilGraph cross-taxonomy metric because no equivalent VeilGraph entity class was predeclared:

- `AADHAAR`: 24
- `ACCOUNTNUMBER`: 150
- `AMOUNT`: 3
- `BIC`: 19
- `BITCOINADDRESS`: 160
- `BUSINESS_REGISTRATION`: 1
- `COMPANYNAME`: 14
- `CREDITCARDISSUER`: 1
- `CVV`: 20
- `ETHEREUMADDRESS`: 8
- `IBAN`: 61
- `IPV4`: 3
- `MASKEDNUMBER`: 68
- `MIDDLENAME`: 1
- `NATIONAL_INSURANCE`: 31
- `PASSWORD`: 9
- `PIN`: 136
- `STATE`: 4
- `TIME`: 1
- `UPI_ID`: 240
- `USERNAME`: 63
- `VEHICLEVIN`: 17
- `VEHICLEVRM`: 85
