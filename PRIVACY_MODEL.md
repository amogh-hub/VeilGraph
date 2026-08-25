# VeilGraph Browser Privacy Model

VeilGraph treats privacy as a release-authorization problem, not only a regex-redaction problem.

The local browser/companion pipeline combines direct identifiers, credentials, quasi-identifiers,
DOM/accessibility semantics and visual findings into relationship-aware exposure evidence. It then
compiles the minimum task context required by the agent, creates a new flattened sanitized visual
representation, and subjects the exact candidate release to 12 mandatory fail-closed attacks.

The central reasoner cannot receive raw browser capture types. It receives only the signed
`BrowserReleasePayload`. Identity exposure, policy floor, task utility and minimization are evidence
fields, not guarantees of mathematical anonymity.

See `ARCHITECTURE.md`, `SECURITY.md`, and `THREAT_MODEL.md`.
