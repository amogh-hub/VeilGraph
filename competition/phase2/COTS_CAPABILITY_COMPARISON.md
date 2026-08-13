# VeilGraph — COTS / Industry Baseline Capability Comparison

**Snapshot date:** 2026-08-12  
**Comparison type:** documented capability comparison, not a claim of independently measured vendor accuracy, latency, pricing or legal compliance.

| Capability | VeilGraph | Microsoft Presidio | AWS Comprehend PII | Google Sensitive Data Protection | Azure AI Language PII |
|---|---|---|---|---|---|
| Local/offline competition mode | Yes | Can be self-hosted | Cloud service | Cloud service | Cloud service |
| Text PII detection | Yes | Yes | Yes | Yes | Yes |
| Structured/tabular privacy workflow | Yes | Presidio Structured exists | Primarily text PII API | Table/content de-identification supported | Text/document workflows |
| Image/OCR privacy path | Yes | Presidio image redactor exists | Not the cited PII text workflow | Image inspection/redaction available in product family | Document-oriented PII focuses native docs |
| Native PDF/DOCX structure-preserving path | Yes | Requires composition of modules/custom pipeline | Not the cited text PII workflow | Storage/content workflows vary by type | Native document PII supports PDF/DOCX and structure-preserving redaction |
| Video privacy workflow | Yes | Not a core cited module | Not the cited PII workflow | Not the cited de-identification content workflow | Not the cited PII workflow |
| L1–L5 user privacy gradation | Yes | Operator-driven anonymization | Detection/redaction | Configurable de-identification transforms | Configurable redaction/entity filtering |
| Relationship/identity-reconstruction graph | Yes | No equivalent claimed here | No equivalent claimed here | No equivalent claimed here | No equivalent claimed here |
| Genuine structured Synthetic Twin level | Yes | No equivalent claimed here | No equivalent claimed here | No equivalent claimed here | No equivalent claimed here |
| Independent fail-closed Privacy Red Team | Yes | No equivalent claimed here | No equivalent claimed here | No equivalent claimed here | No equivalent claimed here |
| Signed proof package + audit hash chain | Yes | No equivalent claimed here | No equivalent claimed here | No equivalent claimed here | No equivalent claimed here |
| Cryptographic local-workspace erasure lifecycle | Yes | Deployment-dependent | Provider-managed | Provider-managed | Provider-managed |

## Official source references
- Microsoft Presidio documentation: https://microsoft.github.io/presidio/
- Presidio text anonymization: https://microsoft.github.io/presidio/text_anonymization/
- AWS Comprehend PII: https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html
- Google Sensitive Data Protection de-identification: https://docs.cloud.google.com/sensitive-data-protection/docs/deidentify-sensitive-data
- Azure AI Language text PII: https://learn.microsoft.com/azure/ai-services/language-service/personally-identifiable-information/text-pii-overview
- Azure AI Language document-based PII: https://learn.microsoft.com/azure/ai-services/language-service/personally-identifiable-information/document-based-pii-overview

## Claim boundary
This table is intended for SIH requirement traceability and architectural comparison. It must not be presented as proof that VeilGraph is globally more accurate or faster than these products. Accuracy comparisons require a common dataset/taxonomy/protocol, and cloud latency/pricing comparisons require controlled vendor-account measurements.

## Frozen quantitative follow-up
The common quantitative comparison methodology is frozen in `COTS_BENCHMARK_PROTOCOL.md`. Commercial measurements are executed in Phase 3 only when the relevant vendor access is actually available; unavailable measurements remain explicitly `NOT EXECUTED` rather than estimated.
