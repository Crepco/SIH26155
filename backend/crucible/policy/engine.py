"""Evaluating rules against the IR.

This is where a verdict is produced, and it is the only place in the system that
is allowed to produce one. Nothing here consults a model, reads raw text, or
makes a judgement call: it applies a compiled assertion to parsed facts and
records what the assertion looked at.

The mapping from verdict to finding state is the visible face of invariant 5::

    FAIL    + a probe that ran and reproduced it   ->  DEMONSTRATED
    FAIL    + no probe, or no sandbox              ->  ASSERTED
    UNKNOWN                                        ->  UNKNOWN
    PASS                                           ->  recorded, not a finding

Nothing can reach DEMONSTRATED from this module alone. Promotion happens only
when the sandbox attaches a proof, so a finding can never claim to have been
demonstrated by a run that never booted a twin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from crucible.common.types import Evidence, Finding, FindingState, Severity, Verdict
from crucible.ir.model import IRDocument
from crucible.policy.expr import UNKNOWN
from crucible.policy.ruleset import Rule, RuleSet

__all__ = ["DeviceEvaluation", "evaluate_device"]

#: How many evidence citations a single finding carries. A finding that cites
#: forty lines is not more convincing than one that cites three; it is less
#: readable, and readability is what makes a report get acted on.
MAX_EVIDENCE = 5


@dataclass(slots=True)
class DeviceEvaluation:
    """Every rule outcome for one device."""

    findings: list[Finding] = field(default_factory=list)
    passed: list[Finding] = field(default_factory=list)
    not_applicable: list[Finding] = field(default_factory=list)

    @property
    def all_results(self) -> list[Finding]:
        return [*self.findings, *self.passed, *self.not_applicable]

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severity]

    def counts(self) -> dict[str, int]:
        return {
            "fail": sum(1 for f in self.findings if f.verdict is Verdict.FAIL),
            "unknown": sum(1 for f in self.findings if f.verdict is Verdict.UNKNOWN),
            "pass": len(self.passed),
            "not_applicable": len(self.not_applicable),
        }

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            if finding.verdict is Verdict.FAIL:
                counts[finding.severity.value] += 1
        return counts

    @property
    def score(self) -> int:
        """A compliance percentage over the controls that actually ran.

        UNKNOWN counts against the score. It has to: a tool that scored only
        what it understood would reward a parser for failing, and would hand a
        device with 40% coverage a perfect grade.
        """
        decided = len(self.findings) + len(self.passed)
        if decided == 0:
            return 0
        return round(100 * len(self.passed) / decided)


def _evidence_for(ir: IRDocument, paths: list[str]) -> list[Evidence]:
    """Turn the paths an assertion read into citations an auditor can check."""
    evidence: list[Evidence] = []
    for path in paths:
        provenance = ir.provenance.get(path)
        if provenance is None:
            # A path resolved from a container that was written as a whole -
            # ``interfaces`` rather than ``interfaces[2].acl_in``. Fall back to
            # the first element citation so the finding still points somewhere
            # real rather than nowhere.
            prefix = f"{path}["
            for key, candidate in ir.provenance.items():
                if key.startswith(prefix):
                    provenance = candidate
                    break
        if provenance is not None:
            evidence.append(Evidence.from_provenance(path, provenance))
        if len(evidence) >= MAX_EVIDENCE:
            break
    return evidence


def _state_for(verdict: Verdict) -> FindingState:
    if verdict is Verdict.UNKNOWN:
        return FindingState.UNKNOWN
    # Everything starts asserted. Only the sandbox may promote it, and only by
    # attaching a proof artefact.
    return FindingState.ASSERTED


def evaluate_device(
    ir: IRDocument, ruleset: RuleSet, *, role: str | None = None
) -> DeviceEvaluation:
    """Run every applicable rule against one device."""
    evaluation = DeviceEvaluation()
    vendor = ir.vendor

    for rule in ruleset:
        if not rule.applies(vendor, role):
            evaluation.not_applicable.append(
                _finding(rule, ir, Verdict.NOT_APPLICABLE, [], [], vendor)
            )
            continue

        result = rule.assertion.evaluate(ir)

        if result.value is UNKNOWN:
            verdict = Verdict.UNKNOWN
        elif _is_true(result.value):
            verdict = Verdict.PASS
        else:
            verdict = Verdict.FAIL

        # A FAIL caused by absence has no line to cite, so the paths that were
        # looked for and not found travel with the finding instead. "The
        # configuration never mentions a management ACL" is actionable;
        # an empty evidence block is not.
        unresolved = result.missing if verdict is Verdict.UNKNOWN else result.absent
        finding = _finding(rule, ir, verdict, result.touched, unresolved, vendor)

        if verdict is Verdict.PASS:
            evaluation.passed.append(finding)
        else:
            evaluation.findings.append(finding)

    # Most severe first. This is the order the report prints and the order an
    # administrator reads, so it is fixed here rather than left to the renderer.
    evaluation.findings.sort(key=lambda f: (f.severity.rank, f.verdict is Verdict.UNKNOWN, f.rule_id))
    return evaluation


def _is_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return bool(value)


def _finding(
    rule: Rule,
    ir: IRDocument,
    verdict: Verdict,
    touched: list[str],
    missing: list[str],
    vendor: str,
) -> Finding:
    target, commands = rule.remediation_for(vendor)
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        verdict=verdict,
        state=_state_for(verdict),
        rationale=rule.rationale,
        frameworks=list(rule.frameworks),
        evidence=_evidence_for(ir, touched),
        remediation=commands if verdict is Verdict.FAIL else [],
        remediation_target=target if verdict is Verdict.FAIL else None,
        missing_paths=list(missing),
    )
