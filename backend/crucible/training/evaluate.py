"""Measure Tier 2 against a vendor it has never seen. A number, not a claim.

The held-out vendor (MikroTik RouterOS, corpus/MANIFEST.md) has a hand-written
Tier-0 parser in this build. That parser is the ground truth: switch it off,
let the proposer read every line cold, and compare what it proposes with what
the parser records for the same line.

The vocabulary contains no RouterOS syntax (a test enforces it), so this is
transfer from other vendors' grammars, not recall of this one.

Reported:

* **field accuracy**: of the lines the parser maps to a pack-writable IR
  path, the fraction where the proposal names the same path;
* **value agreement**: of those, the fraction where the proposed extraction
  yields the same value the parser recorded;
* **precision at the apply threshold**: of proposals confident enough to be
  auto-accepted, the fraction that are right. This is the number that matters
  operationally, because it is what reaches a pack without a human.
* **false auto-applies**: confident proposals on lines the parser says carry
  no pack-writable fact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from crucible.ingest.bundle import DeviceBundle
from crucible.ir.paths import PACK_PATHS
from crucible.pipeline import build_ir
from crucible.training.proposer import LexicalProposer, Proposer
from crucible.training.session import DEFAULT_ACCEPT_ABOVE

__all__ = ["HeldOutReport", "evaluate_held_out"]

_INDEX = re.compile(r"\[\d+\]")


@dataclass(slots=True)
class HeldOutReport:
    vendor: str
    proposer: str
    threshold: float
    lines_with_truth: int = 0
    field_correct: int = 0
    value_correct: int = 0
    confident: int = 0
    confident_correct: int = 0
    false_auto_applies: int = 0
    rows: list[dict[str, Any]] = field(default_factory=list)

    @property
    def field_accuracy(self) -> float:
        return self.field_correct / self.lines_with_truth if self.lines_with_truth else 0.0

    @property
    def value_agreement(self) -> float:
        return self.value_correct / self.lines_with_truth if self.lines_with_truth else 0.0

    @property
    def precision_at_threshold(self) -> float:
        return self.confident_correct / self.confident if self.confident else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "proposer": self.proposer,
            "threshold": self.threshold,
            "lines_with_truth": self.lines_with_truth,
            "field_accuracy": round(self.field_accuracy, 3),
            "value_agreement": round(self.value_agreement, 3),
            "confident_proposals": self.confident,
            "precision_at_threshold": round(self.precision_at_threshold, 3),
            "false_auto_applies": self.false_auto_applies,
            "rows": self.rows,
        }

    def text(self) -> str:
        return (
            f"  held-out vendor   {self.vendor}   proposer {self.proposer}\n"
            f"  lines with truth  {self.lines_with_truth}\n"
            f"  field accuracy    {self.field_correct}/{self.lines_with_truth}"
            f"  ({self.field_accuracy:.0%})\n"
            f"  value agreement   {self.value_correct}/{self.lines_with_truth}"
            f"  ({self.value_agreement:.0%})\n"
            f"  auto-accept >= {self.threshold:.2f}: {self.confident_correct}/{self.confident}"
            f" correct ({self.precision_at_threshold:.0%}),"
            f" {self.false_auto_applies} on lines with no fact"
        )


def _truth(bundle: DeviceBundle) -> tuple[dict[tuple[str, int], dict[str, Any]], str]:
    """(file, line) -> {IR path: value} from the vendor's own Tier-0 parser."""
    parsed = build_ir(bundle)
    truth: dict[tuple[str, int], dict[str, Any]] = {}
    for path, prov in parsed.ir.provenance.items():
        if prov.tier != 0:
            continue
        base = _INDEX.sub("", path)
        if base not in PACK_PATHS:
            continue
        value = parsed.ir.resolve(path).value
        truth.setdefault((prov.file, prov.line), {})[base] = value
    return truth, parsed.identity.vendor


def evaluate_held_out(
    bundle: DeviceBundle,
    *,
    proposer: Proposer | None = None,
    threshold: float = DEFAULT_ACCEPT_ABOVE,
) -> HeldOutReport:
    truth, vendor = _truth(bundle)
    proposer = proposer or LexicalProposer()
    cold = build_ir(bundle, hold_out=[vendor])
    report = HeldOutReport(vendor=vendor, proposer=proposer.name, threshold=threshold)

    for name, numbers in cold.unclaimed.items():
        structure = cold.structure.get(name)
        if structure is None:
            continue
        for number in numbers:
            node = structure.node(number)
            if node is None or not node.text:
                continue
            proposal = proposer.propose(node.text, node.context)
            expected = truth.get((name, number), {})
            proposed_path = proposal.ir_path if proposal else None
            field_ok = proposed_path in expected
            value_ok = (
                field_ok
                and proposal is not None
                and proposal.preview == expected.get(proposed_path or "")
            )
            # List-valued truth is compared element-wise: the parser records
            # the whole list, the proposal one element of it.
            if (
                field_ok
                and proposal is not None
                and isinstance(expected.get(proposed_path or ""), list)
            ):
                value_ok = proposal.preview in expected[proposed_path or ""]
            confident = proposal is not None and proposal.confidence >= threshold

            if expected:
                report.lines_with_truth += 1
                report.field_correct += int(field_ok)
                report.value_correct += int(bool(value_ok))
            if confident:
                report.confident += 1
                report.confident_correct += int(bool(field_ok and value_ok))
                if not expected:
                    report.false_auto_applies += 1
            report.rows.append(
                {
                    "line": number,
                    "text": cold.ir.sources.get(name, [""] * number)[number - 1].strip(),
                    "expected": sorted(expected),
                    "proposed": proposed_path,
                    "confidence": round(proposal.confidence, 3) if proposal else None,
                    "field_ok": field_ok,
                    "value_ok": bool(value_ok),
                }
            )
    return report
