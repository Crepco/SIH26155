"""Tier 0 - deterministic parsers.

A Tier-0 parser has exactly two obligations and no others:

1. Write facts into the IR **with provenance**.
2. Account for **every line** it consumed.

It may not guess, and it may not skip. A line it does not understand falls
through to the next tier, which is a normal and expected outcome rather than an
error - and, crucially, ends as UNKNOWN rather than as a silent PASS.

Specification: docs/05-parsing-cascade.md
"""

from crucible.parsers.base import PARSERS, Line, ParseContext, get_parser, iter_lines

__all__ = ["PARSERS", "Line", "ParseContext", "get_parser", "iter_lines"]

# Importing the modules is what registers them. Kept at the bottom so the public
# names above are bound before any parser module imports back into this package.
from crucible.parsers import (  # noqa: F401  (import for side effect)
    arista_eos,
    cisco_ios,
    fortios,
    junos,
    routeros,
    show_output,
)
