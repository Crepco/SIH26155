"""Parser plumbing shared by every Tier-0 module.

The registry is keyed by vendor because that is what the fingerprinter returns.
There is no plugin discovery and no entry-point magic: six parsers ship in the
box, and the seventh vendor is meant to arrive as an adapter pack rather than as
a module. That is the whole claim of the project, so the code should not make
adding a module look like the natural path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator

from crucible.ingest.bundle import SourceFile
from crucible.ir.builder import IRBuilder

__all__ = ["PARSERS", "Line", "ParseContext", "get_parser", "iter_lines", "register"]


@dataclass(frozen=True, slots=True)
class Line:
    """One source line, pre-split into the forms a parser actually wants."""

    number: int
    raw: str
    #: Leading and trailing whitespace removed. What a matcher compares against.
    text: str
    #: Count of leading spaces. Indentation is structural in IOS-style configs,
    #: so it is measured once here rather than re-derived at every call site.
    indent: int

    @property
    def is_blank(self) -> bool:
        return not self.text

    def startswith(self, *prefixes: str) -> bool:
        return self.text.startswith(prefixes)


def iter_lines(source: SourceFile) -> Iterator[Line]:
    for number, raw in enumerate(source.lines, start=1):
        stripped = raw.strip()
        yield Line(
            number=number,
            raw=raw,
            text=stripped,
            indent=len(raw) - len(raw.lstrip(" ")),
        )


@dataclass(slots=True)
class ParseContext:
    """What a parser is handed: one file, one builder, and nothing else.

    Parsers do not see the whole bundle. Keeping the surface this narrow is what
    stops a parser from quietly correlating across files and producing a fact it
    cannot cite to a single line.
    """

    source: SourceFile
    builder: IRBuilder

    @property
    def filename(self) -> str:
        return self.source.name

    def lines(self) -> Iterator[Line]:
        return iter_lines(self.source)

    def set(self, path: str, value: object, line: int, **kwargs: object) -> None:
        self.builder.set(path, value, file=self.filename, line=line, **kwargs)  # type: ignore[arg-type]

    def append(self, path: str, value: object, line: int, **kwargs: object) -> int:
        return self.builder.append(path, value, file=self.filename, line=line, **kwargs)  # type: ignore[arg-type]

    def claim(self, line: int) -> None:
        self.builder.claim(self.filename, line, 0)

    def claim_structural(self, *lines: int) -> None:
        """Mark lines that were understood but carry no security fact.

        Block delimiters, comments and blank lines. Claiming them is honest: the
        parser did understand them, and pretending otherwise would understate
        coverage as badly as skipping them would overstate it.
        """
        for line in lines:
            self.builder.claim(self.filename, line, 0)


ParserFn = Callable[[ParseContext], None]

#: vendor -> parse function.
PARSERS: dict[str, ParserFn] = {}


def register(vendor: str) -> Callable[[ParserFn], ParserFn]:
    def decorator(fn: ParserFn) -> ParserFn:
        PARSERS[vendor] = fn
        return fn

    return decorator


def get_parser(vendor: str) -> ParserFn | None:
    """Return the Tier-0 parser for a vendor, or ``None``.

    ``None`` is a supported answer, not a failure: an unrecognised vendor is the
    case the training loop exists for, and the file simply carries on down the
    cascade.
    """
    return PARSERS.get(vendor)
