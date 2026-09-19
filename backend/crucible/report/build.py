"""Assembling an audit report.

A report is built once and rendered many ways - JSON, Markdown, PDF - so that
every format shows the same findings, the same coverage figure and the same
verification hash. Rendering from a shared object rather than from three
separate paths is what keeps the PDF an auditor signs identical to the JSON a
pipeline consumes.

The what-if projection is computed here too: the score the device would have if
the printed remediation were applied. It is a projection, labelled as one, and
it is what turns "312 findings" into a decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from crucible import IR_SCHEMA_VERSION, __version__
from crucible.common.canonical import utc_now_rfc3339
from crucible.common.types import Finding, FindingState, Verdict
from crucible.ir.model import IRDocument
from crucible.ledger.merkle import leaf_hash, merkle_root
from crucible.policy.engine import DeviceEvaluation
from crucible.report.remediation import RemediationPlan, build_plan

__all__ = ["AuditReport", "build_report"]


@dataclass(slots=True)
class AuditReport:
    """Everything a renderer needs, and nothing it has to recompute."""

    report_id: str
    generated_at: str
    device_id: str
    device: dict[str, Any]
    coverage: dict[str, Any]
    evaluation: DeviceEvaluation
    plan: RemediationPlan
    rule_set_digest: str
    frameworks: list[str]
    parser_applied: bool
    #: Signed adapter packs whose knowledge produced facts in this report.
    adapter_packs: list[str] = field(default_factory=list)
    leaves: list[str] = field(default_factory=list)
    merkle_root: str = ""
    #: Filled in once the report is committed to the ledger.
    verification_hash: str = ""
    ledger_seq: int | None = None
    tool_version: str = __version__
    ir_schema_version: str = IR_SCHEMA_VERSION
    offline: bool = True

    # -- summary ----------------------------------------------------------

    @property
    def score(self) -> int:
        return self.evaluation.score

    @property
    def findings(self) -> list[Finding]:
        return self.evaluation.findings

    def state_counts(self) -> dict[str, int]:
        counts = {state.value: 0 for state in FindingState}
        for finding in self.findings:
            counts[finding.state.value] += 1
        return counts

    def projected_score(self) -> int:
        """The score after applying the printed remediation.

        UNKNOWN findings are deliberately *not* projected as fixed. We cannot
        promise that a control we could not evaluate will pass once unrelated
        commands are applied, and a projection that quietly assumed so would be
        the same false comfort this tool exists to remove.
        """
        fixable = {step.rule_id for step in self.plan.steps}
        remaining = [
            finding
            for finding in self.findings
            if not (finding.verdict is Verdict.FAIL and finding.rule_id in fixable)
        ]
        decided = len(remaining) + len(self.evaluation.passed) + len(fixable)
        if decided == 0:
            return 0
        return round(100 * (len(self.evaluation.passed) + len(fixable)) / decided)

    # -- serialisation ----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "device_id": self.device_id,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "ir_schema_version": self.ir_schema_version,
            "rule_set_digest": self.rule_set_digest,
            "offline": self.offline,
            "device": self.device,
            "parser_applied": self.parser_applied,
            "adapter_packs": self.adapter_packs,
            "coverage": self.coverage,
            "summary": {
                "score": self.score,
                "projected_score": self.projected_score(),
                "counts": self.evaluation.counts(),
                "by_severity": self.evaluation.severity_counts(),
                "by_state": self.state_counts(),
                "frameworks": self.frameworks,
            },
            "findings": [f.to_dict() for f in self.findings],
            "passed": [f.rule_id for f in self.evaluation.passed],
            "remediation": {
                "target": self.plan.target,
                "command_count": self.plan.command_count,
                "unsupported": self.plan.unsupported,
                "phases": [
                    {
                        "phase": phase,
                        "name": steps[0].phase_name,
                        "steps": [
                            {
                                "rule_id": s.rule_id,
                                "title": s.title,
                                "severity": s.severity,
                                "commands": s.commands,
                            }
                            for s in steps
                        ],
                    }
                    for phase, steps in self.plan.phases()
                ],
            },
            "integrity": {
                "merkle_root": self.merkle_root,
                "verification_hash": self.verification_hash,
                "ledger_seq": self.ledger_seq,
            },
        }


def _leaf_material(finding: Finding) -> dict[str, Any]:
    """What the ledger commits to for one finding.

    The verdict *and* its evidence. Committing to the verdict alone would leave
    the cited file, line and raw text rewritable without breaking the root -
    and those are exactly what makes the finding checkable.
    """
    return {
        "rule_id": finding.rule_id,
        "verdict": finding.verdict.value,
        "state": finding.state.value,
        "severity": finding.severity.value,
        "evidence": [e.to_dict() for e in finding.evidence],
        "missing_paths": finding.missing_paths,
    }


def build_report(
    *,
    report_id: str,
    device_id: str,
    ir: IRDocument,
    evaluation: DeviceEvaluation,
    rule_set_digest: str,
    frameworks: list[str],
    parser_applied: bool = True,
    adapter_packs: list[str] | None = None,
) -> AuditReport:
    """Assemble a report and compute its Merkle root."""
    plan = build_plan(evaluation.findings)
    leaves = [leaf_hash(_leaf_material(f)) for f in evaluation.findings]

    return AuditReport(
        report_id=report_id,
        generated_at=utc_now_rfc3339(),
        device_id=device_id,
        device=dict(ir.device),
        coverage=ir.coverage.to_dict(),
        evaluation=evaluation,
        plan=plan,
        rule_set_digest=rule_set_digest,
        frameworks=frameworks,
        parser_applied=parser_applied,
        adapter_packs=list(adapter_packs or []),
        leaves=leaves,
        merkle_root=merkle_root(leaves),
    )
