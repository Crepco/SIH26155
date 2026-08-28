"""The assertion language: tokeniser, parser and three-valued evaluator.

Deliberately small. This is a compliance tool, and an expression a reviewer
cannot read in five seconds is a liability. There are no function definitions,
no loops with side effects, no regular expressions over raw text and no way to
read a file. A rule reads the IR and nothing else.

The important part is not the grammar - it is that evaluation is **Kleene
three-valued**. ``mgmt.idle_timeout_min <= 10`` on a device where nothing about
timeouts was ever parsed is not ``False``. It is ``UNKNOWN``, and it reaches the
report as UNKNOWN. That single decision is invariant 3 expressed as code: a
parser miss can never become a silent PASS.

Grammar::

    expr       := or_expr
    or_expr    := and_expr ('or' and_expr)*
    and_expr   := not_expr ('and' not_expr)*
    not_expr   := 'not' not_expr | comparison
    comparison := primary (('==' | '!=' | '<' | '<=' | '>' | '>=' | 'in') primary)?
    primary    := literal | path | call | '(' expr ')'
    call       := NAME '(' expr (',' expr)* ')'
    literal    := NUMBER | STRING | 'true' | 'false' | 'null' | '[' ... ']'

One deliberate wrinkle, because it removes an ambiguity that would otherwise bite
every rule author: **inside a list literal, bare words are strings.**
``user.hash in [scrypt, pbkdf2]`` compares against two strings, not two IR paths.
Outside a list, a bare word is a path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from crucible.common.errors import RuleError
from crucible.ir.model import IRDocument

__all__ = ["UNKNOWN", "EvalResult", "Expression", "compile_expression"]


class _Unknown:
    """The third truth value. A singleton so it can be compared with ``is``."""

    _instance: "_Unknown | None" = None

    def __new__(cls) -> "_Unknown":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self) -> bool:
        # Refusing to be truthy is the point: any code that tries to collapse
        # UNKNOWN into a pass or a fail by accident fails loudly instead.
        raise TypeError("UNKNOWN has no boolean value; handle the third state explicitly")


UNKNOWN = _Unknown()

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<string>"[^"]*"|'[^']*')
  | (?P<op><=|>=|==|!=|<|>)
  | (?P<punct>[(),\[\]])
    # A name may carry dots and hyphens (IR paths, and vendor tokens such as
    # diffie-hellman-group1-sha1) and numeric indexes. Indexes are matched as a
    # unit so that a closing list bracket is never swallowed into a name.
  | (?P<name>[A-Za-z_][A-Za-z0-9_.-]*(?:\[\d+\][A-Za-z0-9_.-]*)*)
    """,
    re.VERBOSE,
)

_KEYWORDS = {"and", "or", "not", "in", "true", "false", "null"}


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: str
    position: int


def _tokenise(source: str) -> list[_Token]:
    tokens: list[_Token] = []
    position = 0
    while position < len(source):
        match = _TOKEN_RE.match(source, position)
        if match is None:
            raise RuleError(f"unexpected character at {position} in {source!r}")
        position = match.end()
        kind = match.lastgroup or ""
        if kind == "ws":
            continue
        value = match.group()
        if kind == "name" and value.lower() in _KEYWORDS:
            kind = value.lower()
        tokens.append(_Token(kind=kind, value=value, position=match.start()))
    return tokens


# --------------------------------------------------------------------------
# AST
# --------------------------------------------------------------------------


@dataclass(slots=True)
class EvalResult:
    """The outcome of evaluating an assertion, plus what it looked at.

    ``touched`` is why findings can cite lines: every IR path the expression
    successfully read is recorded, and the engine turns those into evidence.
    ``missing`` is why an UNKNOWN can explain itself rather than just shrugging.
    """

    value: Any
    touched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    #: Paths that ``defined()`` looked for and did not find. Kept apart from
    #: ``missing`` because these did not make the result unknown - they *are*
    #: the result. A rule that fails because a control is absent has no line to
    #: cite, and this is what lets the report say which control was absent
    #: instead of printing an empty evidence block.
    absent: list[str] = field(default_factory=list)

    @property
    def is_unknown(self) -> bool:
        return self.value is UNKNOWN


class _Node:
    def evaluate(self, scope: "_Scope") -> Any:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass(slots=True)
class _Scope:
    ir: IRDocument
    element: Any = None
    in_element: bool = False
    touched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)

    def child(self, element: Any) -> "_Scope":
        return _Scope(
            ir=self.ir,
            element=element,
            in_element=True,
            touched=self.touched,
            missing=self.missing,
            absent=self.absent,
        )


#: Top-level IR sections. Used to tell an IR path from a loop variable inside a
#: quantifier body, which is the one place the two could be confused.
_IR_ROOTS = {
    "device", "mgmt", "aaa", "snmp", "logging", "ntp",
    "interfaces", "acls", "routing", "services", "crypto",
}


@dataclass(slots=True)
class _Literal(_Node):
    value: Any

    def evaluate(self, scope: _Scope) -> Any:
        return self.value


@dataclass(slots=True)
class _ListLiteral(_Node):
    items: list[_Node]

    def evaluate(self, scope: _Scope) -> Any:
        return [item.evaluate(scope) for item in self.items]


@dataclass(slots=True)
class _Path(_Node):
    path: str

    def evaluate(self, scope: _Scope) -> Any:
        root = self.path.split(".")[0].split("[")[0]

        # Inside a quantifier, a path whose root is not an IR section refers to
        # the element being iterated. ``iface.acl_in`` and a bare ``algo`` both
        # resolve against the current item.
        if scope.in_element and root not in _IR_ROOTS:
            remainder = self.path.split(".", 1)
            if len(remainder) == 1:
                return scope.element
            value = scope.element
            for part in remainder[1].split("."):
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    scope.missing.append(self.path)
                    return UNKNOWN
            if value is None:
                # Same rule as for a top-level path: a field the parser filled
                # in as absent is not a value to compare against. This is what
                # makes ``defined(iface.acl_in)`` false on an interface with no
                # inbound filter, rather than true-because-the-key-exists.
                return UNKNOWN
            return value

        resolution = scope.ir.resolve(self.path)
        if not resolution.found:
            scope.missing.append(self.path)
            return UNKNOWN
        scope.touched.append(self.path)
        if resolution.value is None:
            # The parser looked and found nothing. That is still not a fact we
            # can compare against, so it stays UNKNOWN - but it is not recorded
            # as missing, because the device was genuinely read.
            return UNKNOWN
        return resolution.value


@dataclass(slots=True)
class _Not(_Node):
    operand: _Node

    def evaluate(self, scope: _Scope) -> Any:
        value = self.operand.evaluate(scope)
        if value is UNKNOWN:
            return UNKNOWN
        return not _truthy(value)


@dataclass(slots=True)
class _And(_Node):
    left: _Node
    right: _Node

    def evaluate(self, scope: _Scope) -> Any:
        left = self.left.evaluate(scope)
        # Kleene: one definite false settles it, even if the other side is
        # unknown. This is what stops a single unparsed field from turning an
        # otherwise decided FAIL into an UNKNOWN.
        if left is not UNKNOWN and not _truthy(left):
            return False
        right = self.right.evaluate(scope)
        if right is not UNKNOWN and not _truthy(right):
            return False
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        return True


@dataclass(slots=True)
class _Or(_Node):
    left: _Node
    right: _Node

    def evaluate(self, scope: _Scope) -> Any:
        left = self.left.evaluate(scope)
        if left is not UNKNOWN and _truthy(left):
            return True
        right = self.right.evaluate(scope)
        if right is not UNKNOWN and _truthy(right):
            return True
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        return False


@dataclass(slots=True)
class _Compare(_Node):
    op: str
    left: _Node
    right: _Node

    def evaluate(self, scope: _Scope) -> Any:
        left = self.left.evaluate(scope)
        right = self.right.evaluate(scope)
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        try:
            if self.op == "==":
                return left == right
            if self.op == "!=":
                return left != right
            if self.op == "in":
                return left in right if isinstance(right, (list, tuple, set, str)) else False
            if self.op == "<":
                return left < right
            if self.op == "<=":
                return left <= right
            if self.op == ">":
                return left > right
            if self.op == ">=":
                return left >= right
        except TypeError:
            # Comparing a string to a number is a rule bug, not a device
            # finding. Reporting UNKNOWN keeps a broken rule from producing a
            # confident wrong verdict.
            return UNKNOWN
        raise RuleError(f"unsupported operator {self.op}")


@dataclass(slots=True)
class _Call(_Node):
    name: str
    args: list[_Node]

    def evaluate(self, scope: _Scope) -> Any:
        handler = _FUNCTIONS.get(self.name)
        if handler is None:
            raise RuleError(f"unknown function {self.name}()")
        return handler(self, scope)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return bool(value)


# --------------------------------------------------------------------------
# Built-in functions
# --------------------------------------------------------------------------


def _fn_defined(node: _Call, scope: _Scope) -> Any:
    """``defined(path)`` - the explicit "absence is a violation" escape hatch.

    A rule author who wants a missing setting to count as a failure has to say
    so with this, which keeps the intent in the rule file rather than hidden in
    the evaluator.

    One case is *not* a violation, though, and getting it wrong would break
    invariant 3: when the whole section is absent, we did not read the device.
    ``defined(mgmt.mgmt_acl)`` is False on a device whose management plane we
    parsed and which has no ACL - that is a real finding. On a device where
    nothing under ``mgmt`` was ever parsed, the answer is UNKNOWN, because we
    have no basis for either claim. Returning False there would let a device we
    could not read generate confident failures.
    """
    if len(node.args) != 1:
        raise RuleError("defined() takes exactly one argument")
    argument = node.args[0]
    if not isinstance(argument, _Path):
        raise RuleError("defined() takes a path")

    if not scope.in_element:
        root = argument.path.split(".")[0].split("[")[0]
        if root in _IR_ROOTS and not scope.ir.resolve(root).found:
            scope.missing.append(root)
            return UNKNOWN

    before = len(scope.missing)
    value = argument.evaluate(scope)
    # Absence is this function's answer, not a failure to decide, so the paths
    # are moved out of `missing` rather than left to make the rule UNKNOWN.
    scope.absent.extend(scope.missing[before:])
    del scope.missing[before:]
    if value is UNKNOWN and argument.path not in scope.absent:
        scope.absent.append(argument.path)
    return value is not UNKNOWN


def _fn_empty(node: _Call, scope: _Scope) -> Any:
    if len(node.args) != 1:
        raise RuleError("empty() takes exactly one argument")
    value = node.args[0].evaluate(scope)
    if value is UNKNOWN:
        return UNKNOWN
    if value is None:
        return True
    try:
        return len(value) == 0
    except TypeError:
        return False


def _fn_count(node: _Call, scope: _Scope) -> Any:
    if len(node.args) != 1:
        raise RuleError("count() takes exactly one argument")
    value = node.args[0].evaluate(scope)
    if value is UNKNOWN:
        return UNKNOWN
    try:
        return len(value)
    except TypeError:
        return UNKNOWN


def _quantify(node: _Call, scope: _Scope, *, require_all: bool) -> Any:
    if len(node.args) != 2:
        raise RuleError(f"{node.name}() takes a collection and a condition")
    collection = node.args[0].evaluate(scope)
    if collection is UNKNOWN:
        return UNKNOWN
    if not isinstance(collection, (list, tuple)):
        return UNKNOWN

    saw_unknown = False
    for element in collection:
        result = node.args[1].evaluate(scope.child(element))
        if result is UNKNOWN:
            saw_unknown = True
            continue
        if require_all and not _truthy(result):
            return False
        if not require_all and _truthy(result):
            return True

    # An empty collection satisfies "all" and fails "any" - standard, and worth
    # knowing when writing a rule about interfaces on a device that has none.
    if saw_unknown:
        return UNKNOWN
    return require_all


def _fn_all(node: _Call, scope: _Scope) -> Any:
    return _quantify(node, scope, require_all=True)


def _fn_any(node: _Call, scope: _Scope) -> Any:
    return _quantify(node, scope, require_all=False)


def _fn_subset(node: _Call, scope: _Scope) -> Any:
    if len(node.args) != 2:
        raise RuleError("subset() takes two collections")
    left = node.args[0].evaluate(scope)
    right = node.args[1].evaluate(scope)
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN
    try:
        return set(left).issubset(set(right))
    except TypeError:
        return UNKNOWN


_FUNCTIONS: dict[str, Callable[[_Call, _Scope], Any]] = {
    "defined": _fn_defined,
    "empty": _fn_empty,
    "count": _fn_count,
    "all": _fn_all,
    "any": _fn_any,
    "subset": _fn_subset,
}


# --------------------------------------------------------------------------
# Recursive descent parser
# --------------------------------------------------------------------------


class _Parser:
    def __init__(self, tokens: list[_Token], source: str) -> None:
        self.tokens = tokens
        self.source = source
        self.index = 0

    def peek(self) -> _Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> _Token:
        token = self.peek()
        if token is None:
            raise RuleError(f"unexpected end of expression in {self.source!r}")
        self.index += 1
        return token

    def accept(self, kind: str, value: str | None = None) -> _Token | None:
        token = self.peek()
        if token and token.kind == kind and (value is None or token.value == value):
            self.index += 1
            return token
        return None

    def expect(self, kind: str, value: str | None = None) -> _Token:
        token = self.accept(kind, value)
        if token is None:
            found = self.peek()
            raise RuleError(
                f"expected {value or kind} in {self.source!r}, "
                f"found {found.value if found else 'end of expression'}"
            )
        return token

    # -- grammar ------------------------------------------------------------

    def parse(self) -> _Node:
        node = self.parse_or()
        if self.peek() is not None:
            raise RuleError(f"trailing input in {self.source!r}: {self.peek().value!r}")  # type: ignore[union-attr]
        return node

    def parse_or(self) -> _Node:
        node = self.parse_and()
        while self.accept("or"):
            node = _Or(node, self.parse_and())
        return node

    def parse_and(self) -> _Node:
        node = self.parse_not()
        while self.accept("and"):
            node = _And(node, self.parse_not())
        return node

    def parse_not(self) -> _Node:
        if self.accept("not"):
            return _Not(self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self) -> _Node:
        left = self.parse_primary()
        token = self.peek()
        if token and (token.kind == "op" or token.kind == "in"):
            self.take()
            operator = "in" if token.kind == "in" else token.value
            return _Compare(operator, left, self.parse_primary())
        return left

    def parse_primary(self, *, bare_words_are_strings: bool = False) -> _Node:
        token = self.take()

        if token.kind == "punct" and token.value == "(":
            node = self.parse_or()
            self.expect("punct", ")")
            return node

        if token.kind == "punct" and token.value == "[":
            items: list[_Node] = []
            if not self.accept("punct", "]"):
                while True:
                    items.append(self.parse_primary(bare_words_are_strings=True))
                    if self.accept("punct", ","):
                        continue
                    self.expect("punct", "]")
                    break
            return _ListLiteral(items)

        if token.kind == "number":
            text = token.value
            if "." in text:
                raise RuleError(
                    f"decimal literal {text!r}: assertions use integers so that results "
                    "are reproducible byte-for-byte"
                )
            return _Literal(int(text))

        if token.kind == "string":
            return _Literal(token.value[1:-1])

        if token.kind == "true":
            return _Literal(True)
        if token.kind == "false":
            return _Literal(False)
        if token.kind == "null":
            return _Literal(None)

        if token.kind == "name":
            if self.accept("punct", "("):
                args: list[_Node] = []
                if not self.accept("punct", ")"):
                    while True:
                        args.append(self.parse_or())
                        if self.accept("punct", ","):
                            continue
                        self.expect("punct", ")")
                        break
                return _Call(token.value, args)
            if bare_words_are_strings:
                return _Literal(token.value)
            return _Path(token.value)

        raise RuleError(f"unexpected token {token.value!r} in {self.source!r}")


class Expression:
    """A compiled assertion, reusable across every device in a fleet."""

    __slots__ = ("source", "_root")

    def __init__(self, source: str, root: _Node) -> None:
        self.source = source
        self._root = root

    def evaluate(self, ir: IRDocument) -> EvalResult:
        scope = _Scope(ir=ir)
        value = self._root.evaluate(scope)
        # De-duplicate while preserving order: a rule that reads the same path
        # twice should cite one line, not two.
        touched = list(dict.fromkeys(scope.touched))
        missing = list(dict.fromkeys(scope.missing))
        absent = [p for p in dict.fromkeys(scope.absent) if p not in touched]
        return EvalResult(value=value, touched=touched, missing=missing, absent=absent)

    def __repr__(self) -> str:
        return f"Expression({self.source!r})"


def compile_expression(source: str) -> Expression:
    """Compile an assertion. Raises :class:`RuleError` on anything malformed.

    Compilation happens at rule-load time, so a broken assertion stops the whole
    rule set from loading rather than failing quietly on device 147 of 200.
    """
    if not source or not source.strip():
        raise RuleError("empty assertion")
    tokens = _tokenise(source)
    return Expression(source, _Parser(tokens, source).parse())
