"""Tiers 2 and 3 - the model layer and the training loop.

The only package allowed to consult a model, and it never produces a verdict:
it produces candidate *parsers* (adapter-pack mappings) that the deterministic
pipeline applies. Import contracts in pyproject.toml forbid the parsers, the
IR, the policy engine, the cascade and the pack applier from importing it.

Specification: docs/05-parsing-cascade.md, docs/06-adapter-packs.md
"""

from crucible.training.proposer import (
    LexicalProposer,
    OllamaProposer,
    Proposal,
    Proposer,
    build_mapping,
    default_proposer,
)
from crucible.training.session import DEFAULT_ACCEPT_ABOVE, Family, TrainingSession

__all__ = [
    "DEFAULT_ACCEPT_ABOVE",
    "Family",
    "LexicalProposer",
    "OllamaProposer",
    "Proposal",
    "Proposer",
    "TrainingSession",
    "build_mapping",
    "default_proposer",
]
