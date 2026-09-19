"""Tier 1 - structural inference.

Before any model runs, work out the *shape* of a file nobody recognised. Three
grammars cover almost everything in this domain:

=====================  ======================================  ======================
Grammar                Signature                               Examples
=====================  ======================================  ======================
brace hierarchy        balanced ``{`` ``}``, statements end ``;``  Junos, VyOS, EdgeOS
indent / marker blocks leading whitespace, ``!`` or ``#`` lines  IOS, EOS, FortiOS, VRP
flat path-prefixed     every command starts with a path token  RouterOS, set-format
=====================  ======================================  ======================

XML and JSON are recognised first and never treated as text.

The output is a tree with **no meaning attached**. Each line becomes a
:class:`Node` that knows its depth and the chain of block headers above it, so a
line such as ``protocol inbound telnet`` arrives at Tier 2 as "a statement inside
``user-interface vty 0 4``" rather than as a bare string. That context is worth
more to a proposer than any amount of surrounding text, and it costs no
inference.

Tier 1 claims only lines whose meaning is purely structural: blank lines,
comments, separators and block delimiters. It never claims a statement, because
a statement's *meaning* is exactly what Tier 1 does not know - claiming it would
inflate coverage with lines nobody understood.
"""

from __future__ import annotations

import enum
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from crucible.ir.builder import IRBuilder

__all__ = ["Grammar", "Node", "NodeKind", "StructureReport", "analyse", "claim_structural"]

#: Tier recorded against lines Tier 1 claims.
TIER = 1


class Grammar(enum.Enum):
    BRACE = "brace_hierarchy"
    INDENT = "indent_blocks"
    MARKER = "marker_blocks"
    FLAT = "flat_path_prefixed"
    XML = "xml"
    JSON = "json"
    UNKNOWN = "unknown"


class NodeKind(enum.Enum):
    BLANK = "blank"
    COMMENT = "comment"
    SEPARATOR = "separator"
    BLOCK_OPEN = "block_open"
    BLOCK_CLOSE = "block_close"
    STATEMENT = "statement"

    @property
    def structural(self) -> bool:
        """Lines whose whole meaning is their position in the file."""
        return self in (
            NodeKind.BLANK,
            NodeKind.COMMENT,
            NodeKind.SEPARATOR,
            NodeKind.BLOCK_CLOSE,
        )


@dataclass(frozen=True, slots=True)
class Node:
    """One line, placed in the tree."""

    line: int
    text: str
    kind: NodeKind
    depth: int
    #: Block headers above this line, outermost first, with brace and
    #: punctuation stripped: ``("system", "services")`` for a Junos statement,
    #: ``("user-interface vty 0 4",)`` for a VRP one, ``("/ip service",)`` for a
    #: flat RouterOS-style command.
    context: tuple[str, ...] = ()

    @property
    def statement(self) -> str:
        """The statement with trailing terminators removed."""
        return self.text.rstrip(";{ ").strip()


@dataclass(slots=True)
class StructureReport:
    """Tier 1's view of one file."""

    file: str
    grammar: Grammar
    #: Basis points, like every confidence that might end up hashed.
    confidence_bp: int
    nodes: list[Node] = field(default_factory=list)
    #: For flat grammars: the token every command path starts with.
    path_token: str | None = None
    comment_prefix: str | None = None

    def statements(self) -> list[Node]:
        return [n for n in self.nodes if n.kind in (NodeKind.STATEMENT, NodeKind.BLOCK_OPEN)]

    def node(self, line: int) -> Node | None:
        index = line - 1
        if 0 <= index < len(self.nodes) and self.nodes[index].line == line:
            return self.nodes[index]
        return next((n for n in self.nodes if n.line == line), None)

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "grammar": self.grammar.value,
            "confidence_bp": self.confidence_bp,
            "path_token": self.path_token,
            "comment_prefix": self.comment_prefix,
            "statements": len(self.statements()),
            "structural": sum(1 for n in self.nodes if n.kind.structural),
        }


# -- classification ---------------------------------------------------------

_CLOSERS = {"}", "};", "end", "exit", "quit", "return", "next", "exit-address-family", "!"}
_COMMENT_PREFIXES = ("!", "#", "//", "/*", "*", ";")
_FLAT_VERBS = re.compile(r"^(/[\w/-]+(?:\s+[\w-]+)*?)\s+(set|add|remove|print|enable|disable)\b")
_SET_FORMAT = re.compile(r"^(set|delete|deactivate)\s+\S+")


def _is_comment(text: str) -> bool:
    """A comment in any of the grammars above. Separators are handled first."""
    return bool(text) and text.startswith(_COMMENT_PREFIXES)


def _detect(lines: Sequence[str]) -> tuple[Grammar, float, str | None, str | None]:
    """Pick the grammar that best explains the file, with a confidence."""
    content = [line for line in lines if line.strip()]
    if not content:
        return Grammar.UNKNOWN, 0.0, None, None

    head = content[0].lstrip()
    if head.startswith("<?xml") or (head.startswith("<") and any("</" in line for line in content)):
        return Grammar.XML, 0.99, None, None
    if head.startswith(("{", "[")):
        try:
            json.loads("\n".join(lines))
            return Grammar.JSON, 0.99, None, None
        except ValueError:
            pass

    stripped = [line.strip() for line in content]
    n = len(stripped)
    opens = sum(1 for s in stripped if s.endswith("{"))
    closes = sum(1 for s in stripped if s in ("}", "};"))
    semis = sum(1 for s in stripped if s.endswith(";"))
    slash = sum(1 for s in stripped if s.startswith("/") and not s.startswith(("//", "/*")))
    set_format = sum(1 for s in stripped if _SET_FORMAT.match(s))
    hash_separators = sum(1 for s in stripped if s == "#")
    bang_separators = sum(1 for s in stripped if s == "!")
    indented = sum(1 for line in content if line[:1] in (" ", "\t"))

    scores: dict[Grammar, float] = {
        Grammar.BRACE: ((min(opens, closes) * 2 + semis) / n if opens and closes else 0.0),
        Grammar.FLAT: max(slash, set_format) / n,
        Grammar.MARKER: (hash_separators * 3 + indented) / n if hash_separators >= 2 else 0.0,
        Grammar.INDENT: (indented + bang_separators * 2) / n,
    }
    grammar, score = max(scores.items(), key=lambda item: item[1])
    if score < 0.15:
        return Grammar.UNKNOWN, round(score, 3), None, None

    ranked = sorted(scores.values(), reverse=True)
    margin = (ranked[0] - ranked[1]) / ranked[0] if ranked[0] else 0.0
    confidence = round(min(1.0, 0.35 + 0.35 * min(score, 1.0) + 0.3 * margin), 3)

    path_token = None
    if grammar is Grammar.FLAT:
        path_token = "/" if slash >= set_format else "set"
    comment_prefix = None
    if grammar in (Grammar.INDENT,) and bang_separators:
        comment_prefix = "!"
    elif grammar in (Grammar.FLAT, Grammar.BRACE):
        comment_prefix = "#"
    return grammar, confidence, path_token, comment_prefix


def _clean_header(text: str) -> str:
    return text.rstrip("{ ").rstrip(";").strip()


def analyse(file: str, lines: Sequence[str]) -> StructureReport:
    """Build Tier 1's tree for one file."""
    grammar, confidence, path_token, comment_prefix = _detect(lines)
    report = StructureReport(
        file=file,
        grammar=grammar,
        confidence_bp=round(confidence * 10000),
        path_token=path_token,
        comment_prefix=comment_prefix,
    )

    if grammar in (Grammar.XML, Grammar.JSON):
        # Parsed structurally by a dedicated reader, never line by line.
        for number, raw in enumerate(lines, start=1):
            report.nodes.append(Node(number, raw.strip(), NodeKind.STATEMENT, 0))
        return report

    brace_stack: list[str] = []
    indent_stack: list[tuple[int, str]] = []

    for number, raw in enumerate(lines, start=1):
        text = raw.strip()
        indent = len(raw) - len(raw.lstrip(" \t"))

        if not text:
            report.nodes.append(Node(number, text, NodeKind.BLANK, len(brace_stack)))
            continue

        if grammar is Grammar.MARKER and text == "#":
            indent_stack.clear()
            report.nodes.append(Node(number, text, NodeKind.SEPARATOR, 0))
            continue

        if grammar is Grammar.INDENT and text == "!":
            indent_stack.clear()
            report.nodes.append(Node(number, text, NodeKind.SEPARATOR, 0))
            continue

        if _is_comment(text):
            report.nodes.append(Node(number, text, NodeKind.COMMENT, len(brace_stack)))
            continue

        if grammar is Grammar.BRACE:
            if text in ("}", "};"):
                if brace_stack:
                    brace_stack.pop()
                report.nodes.append(Node(number, text, NodeKind.BLOCK_CLOSE, len(brace_stack)))
                continue
            context = tuple(brace_stack)
            if text.endswith("{"):
                report.nodes.append(Node(number, text, NodeKind.BLOCK_OPEN, len(context), context))
                brace_stack.append(_clean_header(text))
                continue
            report.nodes.append(Node(number, text, NodeKind.STATEMENT, len(context), context))
            continue

        if grammar is Grammar.FLAT:
            match = _FLAT_VERBS.match(text)
            context = (match.group(1),) if match else ()
            if not match and _SET_FORMAT.match(text):
                context = (" ".join(text.split()[:3]),)
            report.nodes.append(Node(number, text, NodeKind.STATEMENT, 0, context))
            continue

        # Indentation and marker grammars: a line's parent is the nearest line
        # above it with strictly less indentation.
        if text.lower() in _CLOSERS and indent_stack:
            while indent_stack and indent_stack[-1][0] >= indent:
                indent_stack.pop()
            report.nodes.append(Node(number, text, NodeKind.BLOCK_CLOSE, len(indent_stack)))
            continue
        while indent_stack and indent_stack[-1][0] >= indent:
            indent_stack.pop()
        context = tuple(header for _, header in indent_stack)
        report.nodes.append(Node(number, text, NodeKind.STATEMENT, len(context), context))
        indent_stack.append((indent, _clean_header(text)))

    # A statement that turned out to have children is a block header.
    parents = {n.context[-1] for n in report.nodes if n.context}
    if grammar in (Grammar.INDENT, Grammar.MARKER):
        report.nodes = [
            Node(n.line, n.text, NodeKind.BLOCK_OPEN, n.depth, n.context)
            if n.kind is NodeKind.STATEMENT
            and _clean_header(n.text) in parents
            and _has_children(report.nodes, n)
            else n
            for n in report.nodes
        ]
    return report


def _has_children(nodes: list[Node], parent: Node) -> bool:
    header = _clean_header(parent.text)
    after = parent.line  # nodes are 1-indexed and in order
    for node in nodes[after : after + 1]:
        if node.context[-1:] == (header,):
            return True
    return False


def claim_structural(builder: IRBuilder, report: StructureReport) -> int:
    """Claim, at Tier 1, the lines whose meaning is purely structural.

    Only lines no earlier tier claimed. Returns how many lines were claimed, so
    a caller can say what Tier 1 contributed.
    """
    claimed = 0
    for node in report.nodes:
        if node.kind.structural and not builder.is_claimed(report.file, node.line):
            builder.claim(report.file, node.line, TIER)
            claimed += 1
    return claimed
