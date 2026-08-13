# RE-DACT Requirement Progress — Universal Privacy IR

## Newly closed architectural requirement

**Ability to work on a variety of input sources:** foundation complete.

All supported source formats now normalize to `veilgraph.privacy-ir.v1` before the privacy pipeline. The same detection, Identity Exposure Graph, audience policy, transformation and proof layers can therefore be reused by future TXT/MD/RTF, CSV/XLSX/JSON and video adapters.

This is architecture evidence, not a claim that those future formats are already supported. Format support is marked complete only after its adapter, transformation path and tests exist.
