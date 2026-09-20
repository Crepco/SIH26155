"""The fleet report: one object the CLI, the API, the console and the PDF share.

Assembled from the graph, its correlations and the ranked fixes, so that the
screen, the JSON and the printed page cannot disagree about what the fleet
looks like.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from crucible.graph.build import DeviceInput, build_fleet
from crucible.graph.correlate import Correlation, correlate
from crucible.graph.model import FleetGraph
from crucible.graph.rank import RankedFix, rank_fixes

__all__ = ["FleetReport", "build_fleet_report"]


@dataclass(slots=True)
class FleetReport:
    graph: FleetGraph
    correlations: list[Correlation] = field(default_factory=list)
    fixes: list[RankedFix] = field(default_factory=list)

    @property
    def paths(self) -> int:
        return sum(len(c.paths) for c in self.correlations)

    def counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for correlation in self.correlations:
            counts[correlation.severity] = counts.get(correlation.severity, 0) + 1
        return counts

    def headline(self) -> str:
        """The sentence the fleet view exists to make sayable."""
        if not self.correlations:
            return "No cross-device exposure found in this fleet."
        top = self.fixes[0] if self.fixes else None
        if top is not None and top.paths_severed > 1:
            return (
                f"{len(self.correlations)} cross-device findings over {self.paths} attack paths. "
                f"One fix - {top.action} - severs {top.paths_severed} of them."
            )
        return f"{len(self.correlations)} cross-device findings no per-device audit can see."

    def to_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline(),
            "counts": self.counts(),
            "paths": self.paths,
            "correlations": [c.to_dict() for c in self.correlations],
            "fixes": [f.to_dict() for f in self.fixes],
            "graph": self.graph.to_dict(),
        }


def build_fleet_report(devices: Sequence[DeviceInput]) -> FleetReport:
    graph = build_fleet(list(devices))
    correlations = correlate(graph, devices)
    return FleetReport(graph=graph, correlations=correlations, fixes=rank_fixes(correlations))
