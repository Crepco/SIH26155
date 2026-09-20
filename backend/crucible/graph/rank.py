"""Remediation ranked by consequence, not by severity count.

Every tool in this category hands an administrator a list sorted by severity.
That list is unusable at fleet scale: thirty medium findings and one shadowed
ACE all look like work, and the one that matters is buried.

Here a fix is ranked by **how many attack paths it severs**. One management ACL
on the right device can cut every path to it at once; a timeout setting cuts
none. The output is "six fixes, in this order", which is a thing somebody can
actually do before lunch.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from crucible.graph.correlate import Correlation

__all__ = ["RankedFix", "rank_fixes"]

#: What a correlation is worth when it severs no path at all: credential reuse
#: and NTP drift are real findings, they just are not path problems.
_WEIGHT = {"critical": 8, "high": 5, "medium": 2, "low": 1}


@dataclass(slots=True)
class RankedFix:
    """One action, and what it is worth."""

    id: str
    action: str
    devices: list[str]
    paths_severed: int
    correlations: list[str] = field(default_factory=list)
    severity: str = "medium"
    rule_id: str | None = None

    @property
    def score(self) -> int:
        return self.paths_severed * 10 + _WEIGHT.get(self.severity, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "devices": self.devices,
            "paths_severed": self.paths_severed,
            "correlations": self.correlations,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "score": self.score,
        }


def rank_fixes(correlations: Sequence[Correlation]) -> list[RankedFix]:
    """Group correlations into distinct actions and order them by paths severed.

    Two candidate actions exist for every exposure: harden the target (one ACL,
    every path), or filter at the entry point (one path each, but it protects
    everything behind it). Both are offered, ranked by what they cut.
    """
    fixes: dict[str, RankedFix] = {}

    def fix(key: str, **kwargs: Any) -> RankedFix:
        if key not in fixes:
            fixes[key] = RankedFix(id=key, **kwargs)
        return fixes[key]

    for correlation in correlations:
        if correlation.id.startswith("FLEET-EXPOSURE"):
            target = correlation.devices[-1] if correlation.devices else "device"
            target = next(
                (d for d in correlation.devices if correlation.id.upper().find(d.upper()) >= 0),
                target,
            )
            entry = fix(
                f"mgmt-acl:{target}",
                action=f"Apply a management ACL on {target}",
                devices=[target],
                paths_severed=0,
                severity="critical",
                rule_id="CIS-NET-1.4.1",
            )
            entry.paths_severed += len(correlation.paths)
            entry.correlations.append(correlation.id)

            for path in correlation.paths:
                source_device, _, interface = path.source.partition(":")
                edge = fix(
                    f"filter:{source_device}:{interface}",
                    action=f"Filter inbound management traffic on {interface} of {source_device}",
                    devices=[source_device],
                    paths_severed=0,
                    severity="high",
                    rule_id="CIS-NET-6.1.1",
                )
                edge.paths_severed += 1
                if correlation.id not in edge.correlations:
                    edge.correlations.append(correlation.id)
            continue

        if correlation.id.startswith("FLEET-CREDENTIAL"):
            entry = fix(
                correlation.id,
                action="Give each device a distinct credential, or move to central AAA",
                devices=list(correlation.devices),
                paths_severed=0,
                severity=correlation.severity,
                rule_id="CIS-NET-5.1.1",
            )
            entry.correlations.append(correlation.id)
            continue

        if correlation.id == "FLEET-NTP-DRIFT":
            entry = fix(
                correlation.id,
                action="Authenticate NTP on every device, not most of them",
                devices=list(correlation.devices),
                paths_severed=0,
                severity=correlation.severity,
                rule_id="CIS-NET-4.1.1",
            )
            entry.correlations.append(correlation.id)
            continue

        if correlation.id.startswith("FLEET-SHADOW"):
            entry = fix(
                correlation.id,
                action=correlation.remediation[0] if correlation.remediation else correlation.title,
                devices=list(correlation.devices),
                paths_severed=0,
                severity=correlation.severity,
            )
            entry.correlations.append(correlation.id)

    ranked = sorted(fixes.values(), key=lambda f: (-f.score, f.id))
    return ranked
