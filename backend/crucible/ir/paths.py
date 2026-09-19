"""The IR paths that learned knowledge may write to, and what shape each holds.

An adapter pack names IR paths, and a pack may only name paths that exist in
the IR version it declares (docs/06). This table is that list for IR 1.0.0,
taken from ``schemas/ir/v1.0.0/ir.schema.json``. A test checks that every entry
here really is a leaf of the frozen schema, so the two cannot drift.

Deliberately excluded: interface, ACL and local-user records. Those are
structured, multi-line objects whose meaning depends on block context that a
line-level mapping cannot capture safely. They remain Tier-0 territory.
"""

from __future__ import annotations

from typing import Literal

__all__ = ["DEVICE_PATHS", "LIST_PATHS", "PACK_PATHS", "Kind", "kind_of"]

Kind = Literal["bool", "int", "str", "list"]

#: path -> the shape of value it holds.
PACK_PATHS: dict[str, Kind] = {
    # management plane
    "mgmt.telnet_enabled": "bool",
    "mgmt.http_enabled": "bool",
    "mgmt.https_enabled": "bool",
    "mgmt.idle_timeout_min": "int",
    "mgmt.login_banner": "bool",
    "mgmt.mgmt_acl": "str",
    "mgmt.ssh.enabled": "bool",
    "mgmt.ssh.version": "int",
    "mgmt.ssh.ciphers": "list",
    "mgmt.ssh.kex": "list",
    "mgmt.ssh.macs": "list",
    "mgmt.ssh.max_attempts": "int",
    # AAA
    "aaa.enabled": "bool",
    "aaa.servers": "list",
    "aaa.accounting": "bool",
    "aaa.password_policy.min_length": "int",
    "aaa.password_policy.complexity": "bool",
    "aaa.password_policy.max_age_days": "int",
    # SNMP
    "snmp.version": "int",
    "snmp.communities": "list",
    "snmp.acl": "str",
    "snmp.traps": "list",
    # logging and time
    "logging.servers": "list",
    "logging.level": "str",
    "logging.timestamps": "bool",
    "logging.buffered": "bool",
    "ntp.servers": "list",
    "ntp.authenticated": "bool",
    "ntp.source": "str",
    # routing and services
    "routing.neighbour_authentication": "bool",
    "services.discovery_protocols": "bool",
    "services.source_routing": "bool",
    "services.proxy_arp": "bool",
    # identity, written through the device record
    "device.hostname": "str",
    "device.model": "str",
    "device.serial": "str",
    "device.version": "str",
}

LIST_PATHS = frozenset(p for p, k in PACK_PATHS.items() if k == "list")
DEVICE_PATHS = frozenset(p for p in PACK_PATHS if p.startswith("device."))


def kind_of(path: str) -> Kind | None:
    return PACK_PATHS.get(path)
