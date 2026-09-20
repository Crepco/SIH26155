"""Drift: what changed between two audits of the same device.

A compliance report is a photograph. The thing an operator actually needs to
know is whether the posture moved, and in which direction - a device that was
compliant in March and is not in September is the failure mode this catches,
and no single report can show it.

Compares two audit JSON documents, which every run already writes. The IR
exports are optional; when both are given, fact-level changes are listed too,
so "the timeout went from 10 to 30" is visible rather than just "one more
control fails".

Exit code 1 when the posture regressed, so this belongs in a pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["DriftReport", "compare"]


@dataclass(slots=True)
class Change:
    rule_id: str
    title: str
    before: str
    after: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "before": self.before,
            "after": self.after,
        }


@dataclass(slots=True)
class FactChange:
    ir_path: str
    before: Any
    after: Any
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ir_path": self.ir_path,
            "before": self.before,
            "after": self.after,
            "line": self.line,
        }


@dataclass(slots=True)
class DriftReport:
    device_id: str
    before_id: str = ""
    after_id: str = ""
    before_at: str = ""
    after_at: str = ""
    score_before: int = 0
    score_after: int = 0
    coverage_before: float = 0.0
    coverage_after: float = 0.0
    regressions: list[Change] = field(default_factory=list)
    improvements: list[Change] = field(default_factory=list)
    other_changes: list[Change] = field(default_factory=list)
    fact_changes: list[FactChange] = field(default_factory=list)
    rule_set_changed: bool = False

    @property
    def regressed(self) -> bool:
        return bool(self.regressions)

    @property
    def unchanged(self) -> bool:
        return not (self.regressions or self.improvements or self.other_changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "before": {"report_id": self.before_id, "generated_at": self.before_at},
            "after": {"report_id": self.after_id, "generated_at": self.after_at},
            "score": {"before": self.score_before, "after": self.score_after},
            "coverage": {"before": self.coverage_before, "after": self.coverage_after},
            "rule_set_changed": self.rule_set_changed,
            "regressions": [c.to_dict() for c in self.regressions],
            "improvements": [c.to_dict() for c in self.improvements],
            "other_changes": [c.to_dict() for c in self.other_changes],
            "fact_changes": [c.to_dict() for c in self.fact_changes],
        }

    def text(self) -> str:
        lines = [
            "",
            f"  {self.device_id}",
            f"  {self.before_at}  ->  {self.after_at}",
            f"  score    {self.score_before}%  ->  {self.score_after}%",
            f"  coverage {self.coverage_before}%  ->  {self.coverage_after}%",
            "",
        ]
        if self.rule_set_changed:
            lines.append(
                "  NOTE: the rule set changed between these audits, so some differences\n"
                "        are the standard moving rather than the device."
            )
            lines.append("")
        if self.unchanged and not self.fact_changes:
            lines.append("  Nothing changed.")
            lines.append("")
            return "\n".join(lines)

        for label, changes in (
            ("REGRESSED", self.regressions),
            ("FIXED", self.improvements),
            ("CHANGED", self.other_changes),
        ):
            for change in changes:
                lines.append(
                    f"    {label:10} {change.rule_id:14} {change.before} -> {change.after}"
                )
                lines.append(f"               {change.title}")
        if self.fact_changes:
            lines.append("")
            lines.append("    facts:")
            for fact in self.fact_changes:
                where = f" (line {fact.line})" if fact.line else ""
                lines.append(f"      {fact.ir_path:30} {fact.before!r} -> {fact.after!r}{where}")
        lines.append("")
        return "\n".join(lines)


def _findings(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = {f["rule_id"]: f for f in report.get("findings", [])}
    for rule_id in report.get("passed", []):
        entries.setdefault(rule_id, {"rule_id": rule_id, "verdict": "pass", "title": rule_id})
    return entries


def compare(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    before_ir: dict[str, Any] | None = None,
    after_ir: dict[str, Any] | None = None,
) -> DriftReport:
    """Two audit documents in, one account of what moved out."""
    if before.get("device_id") != after.get("device_id"):
        raise ValueError(
            f"these are different devices: {before.get('device_id')} and {after.get('device_id')}"
        )

    report = DriftReport(
        device_id=str(after.get("device_id", "")),
        before_id=str(before.get("report_id", "")),
        after_id=str(after.get("report_id", "")),
        before_at=str(before.get("generated_at", "")),
        after_at=str(after.get("generated_at", "")),
        score_before=int(before.get("summary", {}).get("score", 0)),
        score_after=int(after.get("summary", {}).get("score", 0)),
        coverage_before=_coverage(before),
        coverage_after=_coverage(after),
        rule_set_changed=before.get("rule_set_digest") != after.get("rule_set_digest"),
    )

    old_findings = _findings(before)
    new_findings = _findings(after)
    for rule_id in sorted(set(old_findings) | set(new_findings)):
        old = old_findings.get(rule_id, {}).get("verdict", "absent")
        new = new_findings.get(rule_id, {}).get("verdict", "absent")
        if old == new:
            continue
        # A control that now passes is only a rule id in the new report, so the
        # readable title comes from the report that still had it as a finding.
        titles = [
            new_findings.get(rule_id, {}).get("title"),
            old_findings.get(rule_id, {}).get("title"),
        ]
        title = next((str(t) for t in titles if t and t != rule_id), rule_id)
        change = Change(rule_id=rule_id, title=title, before=old, after=new)
        if new == "fail" and old != "fail":
            report.regressions.append(change)
        elif old == "fail" and new in ("pass", "not_applicable"):
            report.improvements.append(change)
        else:
            report.other_changes.append(change)

    if before_ir and after_ir:
        report.fact_changes = _fact_changes(before_ir, after_ir)
    return report


def _coverage(report: dict[str, Any]) -> float:
    coverage = report.get("coverage", {})
    total = coverage.get("total_lines", 0)
    parsed = coverage.get("parsed_lines", 0)
    return round(100.0 * parsed / total, 1) if total else 0.0


def _fact_changes(before: dict[str, Any], after: dict[str, Any]) -> list[FactChange]:
    """Fact-level differences, read from two IR exports."""
    old_provenance = before.get("provenance", {})
    new_provenance = after.get("provenance", {})
    changes = []
    for path in sorted(set(old_provenance) | set(new_provenance)):
        old_value = _resolve(before, path)
        new_value = _resolve(after, path)
        if old_value == new_value:
            continue
        line = (new_provenance.get(path) or {}).get("line")
        changes.append(FactChange(ir_path=path, before=old_value, after=new_value, line=line))
    return changes


def _resolve(document: dict[str, Any], path: str) -> Any:
    """Read a dotted IR path out of an exported IR document."""
    import re

    current: Any = document
    for part in path.split("."):
        match = re.match(r"^([A-Za-z_][\w]*)\[(\d+)\]$", part)
        if match:
            current = (current or {}).get(match.group(1))
            index = int(match.group(2))
            if not isinstance(current, list) or index >= len(current):
                return None
            current = current[index]
            continue
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current
