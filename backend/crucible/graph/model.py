"""The fleet as a graph: devices, interfaces, segments, credentials, services.

Small and explicit rather than a dependency. NetworkX would do this too, but the
whole graph is a few hundred nodes on a laptop-sized fleet, and an offline
bundle that ships one fewer package is worth more here than an algorithm
library we would use three functions from.

Everything in this package reads the IR and only the IR. It never sees a
configuration line, which is what makes the same correlations work across six
vendors without a word of vendor-specific code.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Edge", "EdgeKind", "FleetGraph", "Node", "NodeKind"]


class NodeKind:
    DEVICE = "device"
    INTERFACE = "interface"
    SEGMENT = "segment"
    CREDENTIAL = "credential"
    SERVICE = "service"


class EdgeKind:
    HAS_INTERFACE = "HAS_INTERFACE"
    MEMBER_OF = "MEMBER_OF"
    CONNECTS_TO = "CONNECTS_TO"
    SHARES_CREDENTIAL = "SHARES_CREDENTIAL"
    TRUSTS = "TRUSTS"


@dataclass(slots=True)
class Node:
    id: str
    kind: str
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "label": self.label, **self.attrs}


@dataclass(slots=True)
class Edge:
    src: str
    dst: str
    kind: str
    #: True when the relationship was deduced from addressing rather than read
    #: from the configuration. Anything that depends only on inferred edges is
    #: reported at lower confidence, and says so (docs/08, "Honest limits").
    inferred: bool = False
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind,
            "inferred": self.inferred,
            **self.attrs,
        }


class FleetGraph:
    """Nodes, edges, and the few traversals the correlations need."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adjacency: dict[str, list[Edge]] = {}

    # -- building ----------------------------------------------------------

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is not None:
            existing.attrs.update(node.attrs)
            return existing
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)
        self._adjacency.setdefault(edge.src, []).append(edge)
        self._adjacency.setdefault(edge.dst, []).append(edge)

    # -- reading -----------------------------------------------------------

    def of_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def neighbours(self, node_id: str, kind: str | None = None) -> Iterator[tuple[Node, Edge]]:
        for edge in self._adjacency.get(node_id, ()):
            other = edge.dst if edge.src == node_id else edge.src
            node = self.nodes.get(other)
            if node is None:
                continue
            if kind is None or node.kind == kind:
                yield node, edge

    def device_of(self, interface_id: str) -> Node | None:
        return next(
            (n for n, e in self.neighbours(interface_id) if e.kind == EdgeKind.HAS_INTERFACE),
            None,
        )

    def label(self, node_id: str) -> str:
        node = self.nodes.get(node_id)
        return node.label if node else node_id

    # -- serialisation -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "counts": {
                "devices": len(self.of_kind(NodeKind.DEVICE)),
                "interfaces": len(self.of_kind(NodeKind.INTERFACE)),
                "segments": len(self.of_kind(NodeKind.SEGMENT)),
                "edges": len(self.edges),
            },
        }
