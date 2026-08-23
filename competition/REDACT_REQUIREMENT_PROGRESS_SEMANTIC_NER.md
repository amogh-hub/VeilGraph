# RE-DACT requirement progress — Local Semantic NER v1

## Newly implemented
- Local NLP semantic candidate detection for unlabelled prose.
- Versioned local linear span classifier with no runtime network dependency.
- PERSON_NAME, STREET_ADDRESS, EMPLOYER and JOB_TITLE semantic context coverage.
- Fail-closed review for semantic person-name candidates.
- Context-aware Aadhaar-like false-positive suppression.
- Frozen-corpus before/after VeilBench comparison.

## Claim boundary
The curated VeilBench result is corpus-specific internal regression evidence. It is not a universal accuracy claim and does not complete the explicit open-source testing-dataset requirement. PIIMB/OpenPII measurement remains required.
