"""Core value types.

The three-state finding model lives here, and it is the reason this module is
worth reading. Most compliance tools have two states. Two states force a tool to
lie: everything it failed to understand becomes a pass, and an auditor signs off
on a device that was never checked.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Native rule severity. Ordering is meaningful - it drives report grouping
    and it decides what the verification sandbox bothers to prove."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def verifiable(self) -> bool:
        """Only HIGH and CRITICAL are worth booting a twin for.

        Verifying 312 findings is pointless. Verifying the nine that could
        actually get you owned is the product.
        """
        return self in (Severity.CRITICAL, Severity.HIGH)

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls(raw.strip().lower())
        except ValueError as exc:
            raise ValueError(f"unknown severity: {raw!r}") from exc


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Verdict(enum.Enum):
    """The result of evaluating one rule against one device.

    Three-valued, never two. ``UNKNOWN`` is what invariant 3 looks like in code:
    a null path in an assertion yields UNKNOWN, and UNKNOWN is never quietly
    promoted to PASS.
    """

    PASS = "pass"  # noqa: S105  (a verdict, not a credential)
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"

    @property
    def is_finding(self) -> bool:
        """A finding is something the report must show and the ledger must commit
        to. Passes are recorded; they are not findings."""
        return self in (Verdict.FAIL, Verdict.UNKNOWN)


class FindingState(enum.Enum):
    """How strong the evidence behind a finding actually is.

    We never fabricate certainty we do not have, so this is printed as three
    visually distinct things in the report and never collapsed into two.
    """

    #: Reproduced live against a disposable twin. Probe, response and capture
    #: are attached to the finding.
    DEMONSTRATED = "demonstrated"

    #: The rule matched parsed facts. Not runtime-testable, or the twin could
    #: not model the property. Honest, and clearly weaker than DEMONSTRATED.
    ASSERTED = "asserted"

    #: The engine could not interpret the relevant configuration, so it refuses
    #: to claim either pass or fail.
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where a fact in the IR came from.

    Invariant 2 in one dataclass. A fact without provenance may not appear in a
    finding, so the IR builder refuses to write one.
    """

    file: str
    line: int
    raw: str
    tier: int
    adapter_pack: str | None = None
    #: Basis points, 0-10000. Deliberately an integer: floats are not permitted
    #: anywhere in a hashed structure, or the ledger stops being reproducible.
    confidence_bp: int = 10000

    def __post_init__(self) -> None:
        if self.line < 1:
            raise ValueError(f"line numbers are 1-indexed, got {self.line}")
        if self.tier not in (0, 1, 2, 3):
            raise ValueError(f"tier must be 0-3, got {self.tier}")
        if not 0 <= self.confidence_bp <= 10000:
            raise ValueError(f"confidence out of range: {self.confidence_bp}")

    @property
    def confidence(self) -> float:
        return self.confidence_bp / 10000.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "raw": self.raw,
            "tier": self.tier,
            "adapter_pack": self.adapter_pack,
            "confidence_bp": self.confidence_bp,
        }


@dataclass(frozen=True, slots=True)
class Evidence:
    """The citation printed under a finding.

    This is the answer to "how do I know your AI didn't invent this?" - the
    finding points at a file, a line number and the raw text that triggered it.

    ``context`` carries the surrounding lines, redacted, as
    ``(line number, text, is_the_cited_line)``. A bare quoted line proves the
    tool read *something*; the same line sitting in its real block, at its real
    number, is what lets a reader open the file and check. It costs a few lines
    of storage and it is the difference between a citation and a screenshot.
    """

    ir_path: str
    file: str
    line: int
    raw: str
    tier: int
    context: tuple[tuple[int, str, bool], ...] = ()
    #: The adapter pack that produced the fact, when one did. Committed to in
    #: the ledger leaf, so a report can be traced to the learned knowledge
    #: behind it and a compromised pack audited backwards (docs/06).
    adapter_pack: str | None = None

    @classmethod
    def from_provenance(
        cls,
        ir_path: str,
        prov: Provenance,
        context: tuple[tuple[int, str, bool], ...] = (),
    ) -> Evidence:
        return cls(
            ir_path=ir_path,
            file=prov.file,
            line=prov.line,
            raw=prov.raw,
            tier=prov.tier,
            context=context,
            adapter_pack=prov.adapter_pack,
        )

    def cite(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ir_path": self.ir_path,
            "file": self.file,
            "line": self.line,
            "raw": self.raw,
            "tier": self.tier,
            "adapter_pack": self.adapter_pack,
            "context": [{"line": n, "text": t, "cited": c} for n, t, c in self.context],
        }


@dataclass(slots=True)
class Finding:
    """One rule, one device, one outcome - with everything needed to defend it."""

    rule_id: str
    title: str
    severity: Severity
    verdict: Verdict
    state: FindingState
    rationale: str
    frameworks: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    remediation_target: str | None = None
    #: Populated when the assertion could not be decided: which IR paths were
    #: missing. An UNKNOWN that cannot say what it was missing is not actionable.
    missing_paths: list[str] = field(default_factory=list)
    #: Crucible output, once a twin has been booted for this finding.
    proof: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "verdict": self.verdict.value,
            "state": self.state.value,
            "rationale": self.rationale,
            "frameworks": list(self.frameworks),
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": list(self.remediation),
            "remediation_target": self.remediation_target,
            "missing_paths": list(self.missing_paths),
            "proof": self.proof,
        }
