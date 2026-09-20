"""Stage 5 - the fleet graph.

Every tool in this category audits device by device. Breaches are emergent: a
device can be fully compliant while the network it sits in is trivially
breachable. This package reads the IR of every audited device together and
answers the questions no per-device benchmark can ask.

Reads the IR and nothing else - no configuration text reaches here, which is
why the same four correlations work across six vendors with no vendor-specific
code. Specification: docs/08-fleet-graph.md
"""

from crucible.graph.build import DeviceInput, build_fleet
from crucible.graph.correlate import Correlation, Path, correlate
from crucible.graph.model import Edge, EdgeKind, FleetGraph, Node, NodeKind
from crucible.graph.rank import RankedFix, rank_fixes
from crucible.graph.report import FleetReport, build_fleet_report

__all__ = [
    "Correlation",
    "DeviceInput",
    "Edge",
    "EdgeKind",
    "FleetGraph",
    "FleetReport",
    "Node",
    "NodeKind",
    "Path",
    "RankedFix",
    "build_fleet",
    "build_fleet_report",
    "correlate",
    "rank_fixes",
]
