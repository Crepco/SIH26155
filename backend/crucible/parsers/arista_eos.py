"""Arista EOS.

EOS is IOS-style, so it reuses the same walker rather than duplicating it. The
differences are small and all in the management plane: EOS puts SSH, Telnet and
the HTTP API in their own named blocks instead of scattering ``ip ssh`` and
``ip http`` globals at the top level.

Reusing the walker is the right call and also a small risk: a dialect flag makes
it easy to let genuinely different behaviour hide behind a shared code path. The
rule we hold to is that a dialect may change *where* a fact is read from, never
*what the fact means*.
"""

from __future__ import annotations

from crucible.parsers.base import ParseContext, register
from crucible.parsers.cisco_ios import parse_ios_style

__all__ = ["parse_arista_eos"]


@register("arista")
def parse_arista_eos(ctx: ParseContext) -> None:
    parse_ios_style(ctx, dialect="arista")
