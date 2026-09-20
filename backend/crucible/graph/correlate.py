"""Four correlations, each invisible to a per-device checklist.

A device can be one hundred per cent compliant while the network it sits in is
trivially breachable. These four are chosen because no single-device benchmark
can see any of them (docs/08):

1. **Management plane exposure** - an edge device permits traffic into the
   segment where a hardened device's management interface lives. Both devices
   pass their own audit.
2. **NTP authentication drift** - most of the fleet authenticates time, a few
   do not, and log correlation quietly stops being trustworthy.
3. **Credential reuse** - the same credential material on several devices, a
   lateral-movement highway no per-device control can see.
4. **ACL shadowing** - a permissive entry above a restrictive one, so the
   restrictive rule exists, passes the checklist, and never fires.

Everything here reads the IR through the graph. Confidence is reported, and a
result that rests only on inferred adjacency says so.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from crucible.graph.build import MANAGEMENT_SERVICES
from crucible.graph.model import FleetGraph, Node, NodeKind

__all__ = ["Correlation", "Path", "correlate"]

#: How far a path may run before we stop looking. Fleet topologies are wide,
#: not deep, and a six-hop path nobody can follow is not actionable.
MAX_HOPS = 6
#: Entry points named per segment, and paths printed per finding. A report
#: that lists four hundred equivalent ways in is not more convincing than one
#: that lists ten and says how many there are.
MAX_ENTRIES_PER_SEGMENT = 8
MAX_PATHS_REPORTED = 10


@dataclass(frozen=True, slots=True)
class Path:
    """One route from somewhere untrusted to something that should not be reachable."""

    source: str
    target: str
    hops: tuple[str, ...]
    inferred: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "hops": list(self.hops),
            "inferred": self.inferred,
        }


@dataclass(slots=True)
class Correlation:
    """A finding that only exists when devices are read together."""

    id: str
    title: str
    severity: str
    summary: str
    devices: list[str] = field(default_factory=list)
    paths: list[Path] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    #: "asserted" when read from configuration, "inferred" when the conclusion
    #: depends on adjacency we deduced from addressing.
    confidence: str = "asserted"
    remediation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "summary": self.summary,
            "devices": self.devices,
            "paths": [p.to_dict() for p in self.paths],
            "evidence": self.evidence,
            "confidence": self.confidence,
            "remediation": self.remediation,
        }


# -- 1. management plane exposure ---------------------------------------------


def _permits(entries: Sequence[dict[str, Any]] | None, port: int) -> bool | None:
    """Does this ACL permit traffic to ``port`` from anywhere? ``None`` if unreadable.

    Ordered evaluation, first match wins - the same way the device does it.
    """
    if not entries:
        return None
    for entry in entries:
        protocol = (entry.get("protocol") or "").lower()
        if protocol not in ("ip", "tcp", "any", ""):
            continue
        destination_port = entry.get("dst_port")
        if destination_port and not _port_matches(str(destination_port), port):
            continue
        if protocol == "ip" and destination_port is None and entry.get("action") == "deny":
            return False
        if entry.get("action") == "permit":
            return True
        if entry.get("action") == "deny":
            return False
    return False


def _port_matches(expression: str, port: int) -> bool:
    text = expression.strip().lower()
    names = {"ssh": 22, "telnet": 23, "http": 80, "www": 80, "https": 443, "snmp": 161}
    if text.startswith("eq "):
        value = text[3:].strip()
        return names.get(value, _int(value)) == port
    if "-" in text:
        low, _, high = text.partition("-")
        low_port = names.get(low.strip(), _int(low))
        high_port = names.get(high.strip(), _int(high))
        return low_port <= port <= high_port
    return False


def _int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return -1


def _ingress_blocked(interface: Node, port: int) -> bool:
    """Traffic entering here is filtered for this port.

    An ACL we could not read is not treated as a filter: the whole system
    fails closed, and "there might be a filter" is not evidence that there is
    one.
    """
    return _permits(interface.attrs.get("acl_entries"), port) is False


def _entry_groups(graph: FleetGraph) -> dict[str, list[Node]]:
    """Untrusted interfaces, grouped by the segment they sit on.

    Two interfaces on one segment reach the rest of the fleet identically, so
    the search runs once per segment rather than once per interface. On a
    fleet of two hundred devices that is the difference between a report in a
    second and a report in two minutes.
    """
    groups: dict[str, list[Node]] = {}
    for node in graph.of_kind(NodeKind.INTERFACE):
        if node.attrs.get("trust") != "untrusted" or node.attrs.get("shutdown"):
            continue
        for segment, _edge in graph.neighbours(node.id, NodeKind.SEGMENT):
            groups.setdefault(segment.id, []).append(node)
    return groups


#: Where a sweep arrived: the interface, the hops after the entry point, and
#: whether any hop along the way was inferred rather than read from a config.
Arrival = tuple[Node, tuple[str, ...], bool]


def _reachable(graph: FleetGraph, start_id: str, port: int) -> dict[str, Arrival]:
    """One breadth-first sweep: every device reachable from a segment, and how.

    Returns device id -> arrival. A device already reached by a shorter path is
    not revisited, so the first arrival is the path reported.
    """
    start = graph.nodes.get(start_id)
    if start is None:
        return {}
    found: dict[str, Arrival] = {}
    seen = {start.id}
    queue: list[tuple[Node, tuple[str, ...], bool, int]] = [(start, (start.label,), False, 0)]

    while queue:
        segment, hops, inferred, depth = queue.pop(0)
        if depth >= MAX_HOPS:
            continue
        for interface, member_edge in graph.neighbours(segment.id, NodeKind.INTERFACE):
            if interface.attrs.get("shutdown") or _ingress_blocked(interface, port):
                continue
            device = graph.device_of(interface.id)
            if device is None:
                continue
            reached = inferred or bool(member_edge.inferred)
            device_id = str(device.attrs["device_id"])
            if device_id not in found:
                found[device_id] = (interface, (*hops, f"{device_id}:{interface.label}"), reached)
            for onward, _edge in graph.neighbours(device.id, NodeKind.INTERFACE):
                if onward.id == interface.id or onward.attrs.get("shutdown"):
                    continue
                for next_segment, onward_edge in graph.neighbours(onward.id, NodeKind.SEGMENT):
                    if next_segment.id in seen:
                        continue
                    seen.add(next_segment.id)
                    queue.append(
                        (
                            next_segment,
                            (*hops, f"{device_id}:{onward.label}", next_segment.label),
                            reached or bool(onward_edge.inferred),
                            depth + 1,
                        )
                    )
    return found


def _exposure(graph: FleetGraph) -> list[Correlation]:
    """One finding per exposed device and service, listing every way in."""
    groups = _entry_groups(graph)
    if not groups:
        return []

    ports = sorted({port for _path, port in MANAGEMENT_SERVICES.values()})
    # segment -> port -> reachability map, computed once.
    sweeps: dict[str, dict[int, dict[str, tuple[Node, tuple[str, ...], bool]]]] = {
        segment_id: {port: _reachable(graph, segment_id, port) for port in ports}
        for segment_id in groups
    }

    findings: list[Correlation] = []
    for target in graph.of_kind(NodeKind.DEVICE):
        services = [s for s in target.attrs.get("services", []) if s in MANAGEMENT_SERVICES]
        if not services or target.attrs.get("mgmt_acl"):
            continue
        device_id = str(target.attrs["device_id"])

        for service in services:
            port = MANAGEMENT_SERVICES[service][1]
            paths: list[Path] = []
            for segment_id, entries in groups.items():
                arrival = sweeps[segment_id][port].get(device_id)
                if arrival is None:
                    continue
                interface, hops, inferred = arrival
                for entry in entries[:MAX_ENTRIES_PER_SEGMENT]:
                    if entry.attrs.get("device") == device_id and entry.id == interface.id:
                        # The service is exposed on the untrusted interface itself.
                        source = f"{entry.attrs['device']}:{entry.label}"
                        paths.append(
                            Path(source=source, target=source, hops=(source,), inferred=False)
                        )
                        continue
                    source = f"{entry.attrs['device']}:{entry.label}"
                    paths.append(
                        Path(
                            source=source,
                            target=f"{device_id}:{interface.label}",
                            hops=(source, *hops),
                            inferred=inferred,
                        )
                    )
            if not paths:
                continue

            sources = sorted({p.source for p in paths})
            shown = paths[:MAX_PATHS_REPORTED]
            findings.append(
                Correlation(
                    id=f"FLEET-EXPOSURE-{device_id}-{service}".upper(),
                    title=(
                        f"{target.label}: {service} management is reachable from "
                        f"{len(sources)} untrusted entry point"
                        f"{'' if len(sources) == 1 else 's'}"
                    ),
                    severity="critical",
                    summary=(
                        f"{target.label} restricts management access with no ACL, and "
                        f"{service} is reachable from "
                        + ", ".join(sources[:4])
                        + (f" and {len(sources) - 4} more" if len(sources) > 4 else "")
                        + ". Every device on those paths passes its own audit: no per-device "
                        "benchmark can see a path that crosses devices."
                    ),
                    devices=sorted({device_id, *(p.source.split(":", 1)[0] for p in paths)})[:12],
                    paths=shown,
                    confidence="inferred" if any(p.inferred for p in paths) else "asserted",
                    remediation=[
                        f"Apply a management ACL on {target.label} (CIS-NET-1.4.1 prints the "
                        "vendor commands), which severs every path at once.",
                        *[f"Or filter {service} inbound on {source}" for source in sources[:3]],
                    ],
                    evidence=[
                        {
                            "device": device_id,
                            "ir_path": "mgmt.mgmt_acl",
                            "detail": "no management ACL, so any reachable host may try",
                        },
                        *[
                            {
                                "device": source.split(":", 1)[0],
                                "ir_path": "interfaces[]",
                                "detail": f"untrusted interface {source.split(':', 1)[1]}",
                            }
                            for source in sources[:3]
                        ],
                    ],
                )
            )
    return findings


# -- 2. NTP authentication drift ------------------------------------------------


def _ntp_drift(graph: FleetGraph) -> list[Correlation]:
    devices = graph.of_kind(NodeKind.DEVICE)
    authenticated = [d for d in devices if d.attrs.get("ntp_authenticated") is True]
    drifted = [d for d in devices if d.attrs.get("ntp_authenticated") is not True]
    if not authenticated or not drifted:
        return []
    return [
        Correlation(
            id="FLEET-NTP-DRIFT",
            title="Time synchronisation is authenticated on some devices and not others",
            severity="high",
            summary=(
                f"{len(authenticated)} of {len(devices)} devices authenticate NTP; "
                f"{len(drifted)} do not. Log correlation across the fleet is only as "
                "trustworthy as its least trustworthy clock, and every one of these devices "
                "passes 'NTP is configured' on its own."
            ),
            devices=sorted(d.attrs["device_id"] for d in drifted),
            confidence="asserted",
            evidence=[
                {
                    "device": d.attrs["device_id"],
                    "ir_path": "ntp.authenticated",
                    "detail": "not authenticated"
                    if d.attrs.get("ntp_authenticated") is False
                    else "not stated in the configuration",
                }
                for d in drifted
            ],
            remediation=[
                "Authenticate NTP on every device in the fleet, not most of them "
                "(rule CIS-NET-4.1.1 prints the vendor commands)."
            ],
        )
    ]


# -- 3. credential reuse ---------------------------------------------------------


def _credential_reuse(graph: FleetGraph) -> list[Correlation]:
    findings = []
    for node in graph.of_kind(NodeKind.CREDENTIAL):
        accounts = node.attrs.get("accounts", [])
        devices = sorted({a.split(":", 1)[0] for a in accounts})
        findings.append(
            Correlation(
                id=f"FLEET-CREDENTIAL-{node.attrs['fingerprint'][:8]}",
                title=f"The same credential is configured on {len(devices)} devices",
                severity="high",
                summary=(
                    f"{', '.join(accounts)} share one credential. Recovering it once - from the "
                    "weakest device, or from a cleartext protocol - is administrative access to "
                    "all of them. No per-device benchmark can see this, because from any single "
                    "device the credential looks fine."
                ),
                devices=devices,
                confidence="asserted",
                evidence=[
                    {
                        "device": account.split(":", 1)[0],
                        "ir_path": "aaa.local_users[].hash_fingerprint",
                        "detail": f"account {account.split(':', 1)[1]}",
                    }
                    for account in accounts
                ],
                remediation=[
                    "Give each device a distinct local credential, or move administrative "
                    "authentication to the central AAA service (rule CIS-NET-5.1.1).",
                ],
            )
        )
    return findings


# -- 4. ACL shadowing --------------------------------------------------------------


def _network_of(value: str | None) -> Any:
    if not value or value == "any":
        return ipaddress.ip_network("0.0.0.0/0")
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _covers(earlier: dict[str, Any], later: dict[str, Any]) -> bool:
    """Does an earlier entry match everything a later one would?"""
    early_protocol = (earlier.get("protocol") or "").lower()
    late_protocol = (later.get("protocol") or "").lower()
    if early_protocol not in ("ip", "any", late_protocol):
        return False
    early_port = earlier.get("dst_port")
    if early_port and early_port != later.get("dst_port"):
        return False
    for field_name in ("src", "dst"):
        early_net = _network_of(earlier.get(field_name))
        late_net = _network_of(later.get(field_name))
        if early_net is None or late_net is None:
            return False
        if not late_net.subnet_of(early_net):
            return False
    return True


def _acl_shadowing(graph: FleetGraph, devices: Iterable[Any]) -> list[Correlation]:
    findings = []
    for device in devices:
        for acl in device.ir.resolve("acls").value or []:
            entries = acl.get("entries") or []
            for index, later in enumerate(entries):
                for earlier in entries[:index]:
                    if not _covers(earlier, later):
                        continue
                    same = earlier.get("action") == later.get("action")
                    findings.append(
                        Correlation(
                            id=f"FLEET-SHADOW-{device.device_id}-{acl['name']}-{later.get('seq')}",
                            title=(
                                f"ACL {acl['name']} entry {later.get('seq')} on "
                                f"{device.device_id} never fires"
                            ),
                            severity="medium" if same else "high",
                            summary=(
                                f"Entry {earlier.get('seq')} ({earlier.get('raw')}) matches "
                                f"everything entry {later.get('seq')} ({later.get('raw')}) would. "
                                + (
                                    "The later entry is redundant."
                                    if same
                                    else "The restrictive entry exists, passes a checklist, and "
                                    "is never reached."
                                )
                            ),
                            devices=[device.device_id],
                            confidence="asserted",
                            evidence=[
                                {
                                    "device": device.device_id,
                                    "ir_path": f"acls[{acl['name']}].entries[{later.get('seq')}]",
                                    "detail": str(later.get("raw")),
                                }
                            ],
                            remediation=[
                                f"Re-order {acl['name']}: place entry {later.get('seq')} "
                                f"above entry {earlier.get('seq')}, or narrow entry "
                                f"{earlier.get('seq')}.",
                            ],
                        )
                    )
                    break
    return findings


# -- the whole set -------------------------------------------------------------------


def correlate(graph: FleetGraph, devices: Iterable[Any] = ()) -> list[Correlation]:
    findings = [
        *_exposure(graph),
        *_ntp_drift(graph),
        *_credential_reuse(graph),
        *_acl_shadowing(graph, devices),
    ]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda c: (order.get(c.severity, 9), c.id))
    return findings
