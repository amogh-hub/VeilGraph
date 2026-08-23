"""Universal Privacy IR.

The IR is intentionally in-memory and content-addressed. Plaintext is never
serialized into audit metadata or database rows by this module.
"""

from .privacy_ir import (
    IRTextSpan,
    IRUnit,
    PrivacyIR,
    build_privacy_ir,
    privacy_ir_summary,
    to_processed_document,
)

__all__ = [
    "IRTextSpan",
    "IRUnit",
    "PrivacyIR",
    "build_privacy_ir",
    "privacy_ir_summary",
    "to_processed_document",
]
