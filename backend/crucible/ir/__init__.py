"""The normalised security baseline model - the vendor-neutral IR.

The single most consequential artefact in the project. Parsers write into it;
rules, reports, remediation, fleet analysis and the verification sandbox read
only from it.

Contract: schemas/ir/v1.0.0/ir.schema.json
Specification: docs/03-ir-schema.md
"""

from crucible.ir.builder import IRBuilder
from crucible.ir.model import Coverage, IRDocument, Resolution

__all__ = ["Coverage", "IRBuilder", "IRDocument", "Resolution"]
