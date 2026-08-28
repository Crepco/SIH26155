"""Crucible - AI-driven multi-vendor network security compliance auditor.

Compliance you can prove.

The whole system pivots on one idea: a vendor-neutral intermediate representation
that sits between parsing and everything else. Parsers write into it; rules,
reports, remediation and analysis read only from it.

Five invariants hold everywhere in this package:

1. The AI never decides pass or fail. It only writes parsers.
2. Every finding carries line-level evidence.
3. Fail closed - unparsed input can never produce a pass.
4. Coverage is published, not hidden.
5. Findings have three honest states, never two.

See docs/02-architecture.md.
"""

__version__ = "0.1.0"

# The IR schema version this build reads and writes. A report records it so that
# a September audit can still be explained in March.
IR_SCHEMA_VERSION = "1.0.0"

# Recorded in every ledger entry. Changing how findings are serialised without
# bumping this would silently invalidate historical verification.
CANONICALISATION_VERSION = "1"

__all__ = ["__version__", "IR_SCHEMA_VERSION", "CANONICALISATION_VERSION"]
