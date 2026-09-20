"""Compute precision, recall, fact accuracy and the UNKNOWN rate.

Definitions, stated because everyone's differ (docs/16):

* A **true positive** is a control the labeller marked ``fail`` and the engine
  reported ``fail``.
* A **false positive** is a control the engine reported ``fail`` that the
  labeller marked ``pass``. A control the labeller marked ``unknown`` is
  excluded from precision entirely: the labeller is saying the file does not
  decide it, so neither answer is evidence about the engine.
* A **false negative** is a control the labeller marked ``fail`` that the
  engine reported ``pass``. Reporting ``unknown`` where the labeller found a
  failure is counted separately as a **miss through caution** - it is a gap,
  but it is not a silent pass, and conflating the two would hide the
  difference that matters most.

The last distinction is the whole three-state model, expressed as arithmetic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from crucible.common.types import Verdict
from crucible.ingest.bundle import load
from crucible.pipeline import build_ir
from crucible.policy.engine import evaluate_device
from crucible.policy.ruleset import RuleSet
from crucible.validation.labels import Label

__all__ = ["DeviceScore", "ValidationReport", "validate"]


@dataclass(slots=True)
class DeviceScore:
    config_id: str
    vendor: str = "unknown"
    coverage: float = 0.0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    cautious_misses: int = 0
    agreements: int = 0
    compared: int = 0
    unknown_reported: int = 0
    facts_checked: int = 0
    facts_right: int = 0
    citations_checked: int = 0
    citations_agreed: int = 0
    disagreements: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_id": self.config_id,
            "vendor": self.vendor,
            "coverage": self.coverage,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "cautious_misses": self.cautious_misses,
            "agreement": round(self.agreements / self.compared, 3) if self.compared else 0.0,
            "unknown_reported": self.unknown_reported,
            "facts_checked": self.facts_checked,
            "facts_right": self.facts_right,
            "citations_checked": self.citations_checked,
            "citations_agreed": self.citations_agreed,
            "disagreements": self.disagreements,
        }


@dataclass(slots=True)
class ValidationReport:
    devices: list[DeviceScore] = field(default_factory=list)
    human_reviewed: bool = True

    def _sum(self, attribute: str) -> int:
        return sum(getattr(d, attribute) for d in self.devices)

    @property
    def precision(self) -> float:
        reported = self._sum("true_positives") + self._sum("false_positives")
        return self._sum("true_positives") / reported if reported else 0.0

    @property
    def recall(self) -> float:
        real = (
            self._sum("true_positives")
            + self._sum("false_negatives")
            + self._sum("cautious_misses")
        )
        return self._sum("true_positives") / real if real else 0.0

    @property
    def agreement(self) -> float:
        compared = self._sum("compared")
        return self._sum("agreements") / compared if compared else 0.0

    @property
    def fact_accuracy(self) -> float:
        checked = self._sum("facts_checked")
        return self._sum("facts_right") / checked if checked else 0.0

    @property
    def citation_agreement(self) -> float:
        checked = self._sum("citations_checked")
        return self._sum("citations_agreed") / checked if checked else 0.0

    @property
    def unknown_rate(self) -> float:
        compared = self._sum("compared")
        return self._sum("unknown_reported") / compared if compared else 0.0

    @property
    def mean_coverage(self) -> float:
        return (
            round(sum(d.coverage for d in self.devices) / len(self.devices), 1)
            if self.devices
            else 0.0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "devices": len(self.devices),
            "human_reviewed_labels": self.human_reviewed,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "agreement": round(self.agreement, 3),
            "fact_accuracy": round(self.fact_accuracy, 3),
            "citation_agreement": round(self.citation_agreement, 3),
            "unknown_rate": round(self.unknown_rate, 3),
            "mean_coverage": self.mean_coverage,
            "counts": {
                "true_positives": self._sum("true_positives"),
                "false_positives": self._sum("false_positives"),
                "false_negatives": self._sum("false_negatives"),
                "cautious_misses": self._sum("cautious_misses"),
                "controls_compared": self._sum("compared"),
                "facts_checked": self._sum("facts_checked"),
            },
            "per_device": [d.to_dict() for d in self.devices],
        }

    def text(self) -> str:
        lines = [
            "",
            f"  devices audited        {len(self.devices)}",
            f"  controls compared      {self._sum('compared')}",
            f"  mean coverage          {self.mean_coverage}%",
            f"  precision              {self.precision:.2f}"
            f"   ({self._sum('true_positives')} true / "
            f"{self._sum('false_positives')} false positives)",
            f"  recall                 {self.recall:.2f}"
            f"   ({self._sum('false_negatives')} missed as PASS, "
            f"{self._sum('cautious_misses')} missed as UNKNOWN)",
            f"  verdict agreement      {self.agreement:.2f}",
            f"  fact accuracy          {self.fact_accuracy:.2f}"
            f"   ({self._sum('facts_right')}/{self._sum('facts_checked')} facts read"
            " with the labelled value)",
            f"  citation agreement     {self.citation_agreement:.2f}"
            f"   ({self._sum('citations_agreed')}/{self._sum('citations_checked')} cite the"
            " same line; another line may justify the same fact)",
            f"  UNKNOWN rate           {self.unknown_rate:.2f}",
            "",
        ]
        if not self.human_reviewed:
            lines.append(
                "  NOTE: these labels have not been reviewed by a person, so every number\n"
                "        above is provisional. Quote it that way or not at all."
            )
            lines.append("")
        return "\n".join(lines)


def validate(
    labels: Sequence[Label],
    ruleset: RuleSet,
    *,
    devices_root: str | Path,
) -> ValidationReport:
    """Audit each labelled configuration and compare with its label."""
    report = ValidationReport(human_reviewed=all(label.human_reviewed for label in labels))
    root = Path(devices_root)

    for label in labels:
        target = root / label.config_id
        if not target.exists():
            raise FileNotFoundError(f"no configuration for {label.config_id} under {root}")
        parsed = build_ir(load(target)[0])
        evaluation = evaluate_device(parsed.ir, ruleset)
        actual = {finding.rule_id: finding.verdict for finding in evaluation.all_results}

        score = DeviceScore(
            config_id=label.config_id,
            vendor=parsed.ir.vendor,
            coverage=parsed.ir.coverage.percent,
        )

        for rule_id, expected in label.verdicts.items():
            verdict = actual.get(rule_id)
            if verdict is None:
                continue
            got = verdict.value
            score.compared += 1
            score.agreements += int(got == expected)
            score.unknown_reported += int(verdict is Verdict.UNKNOWN)

            if expected == "fail" and verdict is Verdict.FAIL:
                score.true_positives += 1
            elif expected == "fail" and verdict is Verdict.PASS:
                score.false_negatives += 1
            elif expected == "fail" and verdict is Verdict.UNKNOWN:
                score.cautious_misses += 1
            elif expected == "pass" and verdict is Verdict.FAIL:
                score.false_positives += 1

            if got != expected:
                score.disagreements.append(
                    {"rule_id": rule_id, "expected": expected, "reported": got}
                )

        for fact in label.facts:
            resolution = parsed.ir.resolve(fact.path)
            score.facts_checked += 1
            # A label of null means "no such fact should be recorded", so a
            # path nobody wrote is agreement, not a miss.
            if fact.value is None and not resolution.found:
                score.facts_right += 1
                continue
            if not (resolution.found and resolution.value == fact.value):
                score.disagreements.append(
                    {
                        "ir_path": fact.path,
                        "expected": fact.value,
                        "reported": resolution.value if resolution.found else "<not parsed>",
                    }
                )
                continue
            score.facts_right += 1
            # Citation agreement is a separate question from value accuracy.
            # Two lines can each justify the same fact - a labeller citing
            # "transport input ssh" and a parser citing "ip ssh version 2" are
            # both right - so a difference is recorded, not scored as an error.
            if fact.line is not None and resolution.provenance is not None:
                score.citations_checked += 1
                if resolution.provenance.line == fact.line:
                    score.citations_agreed += 1
                else:
                    score.disagreements.append(
                        {
                            "ir_path": fact.path,
                            "expected_line": fact.line,
                            "reported_line": resolution.provenance.line,
                            "note": "both lines may justify the fact",
                        }
                    )

        report.devices.append(score)

    return report
