"""The deterministic tiers of the parsing cascade that are not vendor parsers.

Tier 1 lives here: structural inference over a file no Tier-0 parser claimed.
Applying a signed adapter pack is also deterministic and lives in
:mod:`crucible.adapters`. Nothing in this package consults a model; the model
layer is :mod:`crucible.training`, and an import contract forbids reaching it
from here.

Specification: docs/05-parsing-cascade.md
"""

from crucible.cascade.structure import Grammar, Node, StructureReport, analyse, claim_structural

__all__ = ["Grammar", "Node", "StructureReport", "analyse", "claim_structural"]
