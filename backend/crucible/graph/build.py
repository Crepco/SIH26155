"""Building the fleet graph from parsed IR documents.

Adjacency is inferred from addressing: two interfaces whose addresses fall in
the same subnet are treated as connected. That is an inference, not a reading
of the configuration, so every such edge is marked ``inferred`` and anything
that depends only on inferred edges is reported at lower confidence.

An address without a prefix (several vendors print one) is placed in a subnet
another interface declares, when one contains it, and otherwise assumed to be
a /24 - recorded as inferred either way.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from crucible.graph.model import Edge, EdgeKind, FleetGraph, Node, NodeKind
from crucible.ir.model import IRDocument

__all__ = ["DeviceInput", "build_fleet"]

#: Words that mark an interface as facing something we do not control. Matched
#: against the zone and the description, which is all a configuration gives us.
_UNTRUSTED = re.compile(
    r"\b(untrust|internet|isp|wan|outside|public|external|uplink-to-isp|transit)\b", re.I
)
_MANAGEMENT = re.compile(r"\b(mgmt|management|oob|out-of-band)\b", re.I)
#: Management services the IR knows about, and the port each answers on.
MANAGEMENT_SERVICES = {
    "telnet": ("mgmt.telnet_enabled", 23),
    "http": ("mgmt.http_enabled", 80),
    "https": ("mgmt.https_enabled", 443),
    "ssh": ("mgmt.ssh.enabled", 22),
}


@dataclass(frozen=True, slots=True)
class DeviceInput:
    """One audited device, as the graph needs it."""

    device_id: str
    ir: IRDocument
    score: int | None = None


def _network(address: str, declared: list[Any]) -> tuple[Any, bool]:
    """(network, inferred). ``None`` when the address cannot be read."""
    text = address.strip()
    if not text:
        return None, False
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False), False
        host = ipaddress.ip_address(text)
    except ValueError:
        return None, False
    for candidate in declared:
        if host in candidate:
            return candidate, True
    if host.version == 4:
        return ipaddress.ip_network(f"{host}/24", strict=False), True
    return ipaddress.ip_network(f"{host}/64", strict=False), True


def _declared_networks(devices: list[DeviceInput]) -> list[Any]:
    networks: list[Any] = []
    for device in devices:
        for interface in device.ir.resolve("interfaces").value or []:
            for address in interface.get("addresses") or []:
                if "/" in str(address):
                    try:
                        networks.append(ipaddress.ip_network(str(address), strict=False))
                    except ValueError:
                        continue
    return networks


def _trust(interface: dict[str, Any], networks: list[Any]) -> str:
    text = f"{interface.get('zone') or ''} {interface.get('description') or ''}"
    if interface.get("is_mgmt") or _MANAGEMENT.search(text):
        return "management"
    if _UNTRUSTED.search(text):
        return "untrusted"
    for network in networks:
        if network is not None and network.version == 4 and network.is_global:
            # A globally routable address on an interface is the clearest
            # signal available that it faces something we do not control.
            return "untrusted"
    return "internal"


def build_fleet(devices: list[DeviceInput]) -> FleetGraph:
    graph = FleetGraph()
    declared = _declared_networks(devices)
    credentials: dict[str, list[str]] = {}

    for device in devices:
        ir = device.ir
        services = {
            name: ir.resolve(path).value
            for name, (path, _port) in MANAGEMENT_SERVICES.items()
            if ir.resolve(path).value is True
        }
        device_node = graph.add_node(
            Node(
                id=f"device:{device.device_id}",
                kind=NodeKind.DEVICE,
                label=str(ir.device.get("hostname") or device.device_id),
                attrs={
                    "device_id": device.device_id,
                    "vendor": ir.vendor,
                    "os": ir.device.get("os"),
                    "score": device.score,
                    "mgmt_acl": ir.resolve("mgmt.mgmt_acl").value,
                    "services": sorted(services),
                    "ntp_authenticated": ir.resolve("ntp.authenticated").value,
                    "ntp_servers": ir.resolve("ntp.servers").value or [],
                    "logging_servers": ir.resolve("logging.servers").value or [],
                    "aaa_servers": ir.resolve("aaa.servers").value or [],
                    "coverage": ir.coverage.percent,
                },
            )
        )

        acls = {acl["name"]: acl for acl in (ir.resolve("acls").value or []) if acl.get("name")}
        for index, interface in enumerate(ir.resolve("interfaces").value or []):
            networks = []
            inferred_any = False
            for address in interface.get("addresses") or []:
                network, inferred = _network(str(address), declared)
                if network is not None:
                    networks.append(network)
                    inferred_any = inferred_any or inferred

            interface_id = f"iface:{device.device_id}:{interface.get('name')}"
            trust = _trust(interface, networks)
            interface_node = graph.add_node(
                Node(
                    id=interface_id,
                    kind=NodeKind.INTERFACE,
                    label=str(interface.get("name")),
                    attrs={
                        "device": device.device_id,
                        "addresses": list(interface.get("addresses") or []),
                        "zone": interface.get("zone"),
                        "description": interface.get("description"),
                        "acl_in": interface.get("acl_in"),
                        "acl_entries": acls.get(str(interface.get("acl_in")), {}).get("entries"),
                        "is_mgmt": bool(interface.get("is_mgmt")) or trust == "management",
                        "shutdown": bool(interface.get("shutdown")),
                        "trust": trust,
                        "ir_path": f"interfaces[{index}]",
                    },
                )
            )
            graph.add_edge(Edge(device_node.id, interface_node.id, EdgeKind.HAS_INTERFACE))

            for network in networks:
                segment = graph.add_node(
                    Node(
                        id=f"segment:{network}",
                        kind=NodeKind.SEGMENT,
                        label=str(network),
                        attrs={"cidr": str(network), "global": bool(network.is_global)},
                    )
                )
                graph.add_edge(
                    Edge(interface_node.id, segment.id, EdgeKind.MEMBER_OF, inferred=inferred_any)
                )

        for user in ir.resolve("aaa.local_users").value or []:
            digest = user.get("hash_fingerprint")
            if digest:
                credentials.setdefault(str(digest), []).append(
                    f"{device.device_id}:{user.get('name')}"
                )

        # Services the device depends on. A syslog or NTP server it trusts is
        # part of its security posture even when we never audited that host.
        for kind, addresses in (
            ("syslog", device_node.attrs["logging_servers"]),
            ("ntp", device_node.attrs["ntp_servers"]),
            ("aaa", device_node.attrs["aaa_servers"]),
        ):
            for address in addresses:
                service = graph.add_node(
                    Node(
                        id=f"service:{kind}:{address}",
                        kind=NodeKind.SERVICE,
                        label=f"{kind} {address}",
                        attrs={"service": kind, "address": str(address)},
                    )
                )
                graph.add_edge(
                    Edge(device_node.id, service.id, EdgeKind.TRUSTS, attrs={"service": kind})
                )

    # Interfaces sharing a segment are adjacent. Inferred, always.
    for segment in graph.of_kind(NodeKind.SEGMENT):
        members = [n for n, _e in graph.neighbours(segment.id, NodeKind.INTERFACE)]
        for i, left in enumerate(members):
            for right in members[i + 1 :]:
                if left.attrs.get("device") == right.attrs.get("device"):
                    continue
                graph.add_edge(
                    Edge(
                        left.id,
                        right.id,
                        EdgeKind.CONNECTS_TO,
                        inferred=True,
                        attrs={"via": segment.attrs["cidr"]},
                    )
                )

    for digest, holders in credentials.items():
        if len(holders) < 2:
            continue
        node = graph.add_node(
            Node(
                id=f"credential:{digest[:16]}",
                kind=NodeKind.CREDENTIAL,
                label=f"shared credential {digest[:8]}",
                attrs={"fingerprint": digest[:16], "accounts": sorted(holders)},
            )
        )
        for holder in holders:
            device_id = holder.split(":", 1)[0]
            graph.add_edge(
                Edge(
                    f"device:{device_id}",
                    node.id,
                    EdgeKind.SHARES_CREDENTIAL,
                    attrs={"account": holder.split(":", 1)[1]},
                )
            )

    return graph
