"""Fortinet FortiOS.

``config`` / ``edit`` / ``set`` / ``next`` / ``end``, arbitrarily nested. A small
grammar, so the parser is a stack of section names rather than a state machine,
and a ``set`` line is interpreted by the path it sits under.

Note ``admintimeout``: Fortinet measures the idle timeout in minutes like Cisco
does, but calls it something else entirely. That single fact is the argument for
the whole IR - three vendors, three spellings, one ``mgmt.idle_timeout_min``.
"""

from __future__ import annotations

import re

from crucible.parsers.base import ParseContext, register

__all__ = ["parse_fortios"]

_RE_CONFIG = re.compile(r"^config (.+)$")
_RE_EDIT = re.compile(r'^edit "?([^"]+)"?$')
_RE_SET = re.compile(r"^set (\S+)\s*(.*)$")

DEFAULT_COMMUNITIES = {"public", "private", "fortinet", "admin"}

#: Keys we positively recognise as carrying no security posture. Listing them
#: explicitly is the difference between "we understood this line and it does not
#: matter" and "we never looked at it" - and only the first may count as parsed.
_KNOWN_IRRELEVANT = {
    "vdom",
    "type",
    "schedule",
    "srcintf",
    "dstintf",
    "action",
    "name",
    "timezone",
    "facility",
    "status",
    "syncinterval",
    "description",
    "admin-sport",
    "query-v1-status",
    "ntpsync",
}


def _unquote(value: str) -> str:
    return value.strip().strip('"')


@register("fortinet")
def parse_fortios(ctx: ParseContext) -> None:
    ntp_lines: list[int] = []
    stack: list[str] = []
    current_edit: str | None = None
    interface: dict[str, object] | None = None
    interface_line = 0
    community_is_default: tuple[bool, int] | None = None
    snmp_enabled = False

    def path() -> str:
        return " ".join(stack)

    def flush_interface() -> None:
        nonlocal interface
        if interface is None:
            return
        index = ctx.append("interfaces", interface, interface_line)
        if interface.get("_acl_line"):
            ctx.set(
                f"interfaces[{index}].acl_in",
                interface.get("acl_in"),
                int(str(interface.pop("_acl_line"))),
            )
        if interface.get("_shutdown_line"):
            ctx.set(
                f"interfaces[{index}].shutdown",
                interface.get("shutdown"),
                int(str(interface.pop("_shutdown_line"))),
            )
        interface = None

    for line in ctx.lines():
        number = line.number
        text = line.text

        if line.is_blank or text.startswith("#"):
            ctx.claim(number)
            continue

        match = _RE_CONFIG.match(text)
        if match:
            stack.append(match.group(1))
            ctx.claim(number)
            continue

        if text == "end":
            if stack:
                stack.pop()
            current_edit = None
            ctx.claim(number)
            continue

        if text == "next":
            if path() == "system interface":
                flush_interface()
            current_edit = None
            ctx.claim(number)
            continue

        match = _RE_EDIT.match(text)
        if match:
            current_edit = match.group(1)
            if path() == "system interface":
                interface = {
                    "name": current_edit,
                    "description": None,
                    "addresses": [],
                    "acl_in": None,
                    "acl_out": None,
                    "zone": None,
                    "shutdown": False,
                    "is_mgmt": False,
                }
                interface_line = number
            ctx.claim(number)
            continue

        match = _RE_SET.match(text)
        if not match:
            continue

        key, value = match.group(1), _unquote(match.group(2))
        section = path()

        if section == "system global":
            if key == "admintimeout" and value.isdigit():
                ctx.set("mgmt.idle_timeout_min", int(value), number)
                continue
            if key == "admin-telnet":
                ctx.set("mgmt.telnet_enabled", value == "enable", number)
                continue
            if key == "admin-ssh-v1":
                # FortiOS expresses SSH version as "is v1 permitted", so a
                # disabled v1 is the same fact as "version 2" elsewhere.
                ctx.set("mgmt.ssh.version", 2 if value == "disable" else 1, number)
                ctx.set("mgmt.ssh.enabled", True, number, claim=False)
                continue
            if key == "admin-https-redirect":
                ctx.set("mgmt.https_enabled", value == "enable", number)
                continue
            if key == "hostname":
                ctx.builder.set_device("hostname", value, file=ctx.filename, line=number)
                continue
            if key == "admin-http":
                ctx.set("mgmt.http_enabled", value == "enable", number)
                continue

        if section == "system interface" and interface is not None:
            if key == "ip":
                addresses = interface["addresses"]
                assert isinstance(addresses, list)
                addresses.append(value.split()[0])
                ctx.claim(number)
                continue
            if key == "alias":
                interface["description"] = value
                if "mgmt" in value.lower() or "management" in value.lower():
                    interface["is_mgmt"] = True
                ctx.claim(number)
                continue
            if key == "status":
                interface["shutdown"] = value == "down"
                interface["_shutdown_line"] = number
                ctx.claim(number)
                continue
            if key == "allowaccess":
                services = value.split()
                # allowaccess is the management ACL in Fortinet vocabulary: it
                # decides which planes answer on this interface.
                if "http" in services:
                    ctx.set("mgmt.http_enabled", True, number, claim=False)
                if "telnet" in services:
                    ctx.set("mgmt.telnet_enabled", True, number, claim=False)
                interface["_allowaccess"] = services
                ctx.claim(number)
                continue
            if key == "trusthost1":
                interface["acl_in"] = "trusthost"
                interface["_acl_line"] = number
                ctx.set("mgmt.mgmt_acl", "trusthost", number)
                continue

        if section == "system snmp community":
            if key == "name":
                community_is_default = (value.lower() in DEFAULT_COMMUNITIES, number)
                marker = "default" if value.lower() in DEFAULT_COMMUNITIES else "custom"
                ctx.append("snmp.communities", marker, number, secret=value)
                ctx.set("snmp.version", 2, number, claim=False, secret=value)
                continue

        if section == "system snmp user":
            if key == "security-level":
                ctx.set("snmp.version", 3, number)
                continue

        if section == "system snmp sysinfo" and key == "status":
            snmp_enabled = value == "enable"
            ctx.claim(number)
            continue

        if section == "log syslogd setting" and key == "server":
            ctx.append("logging.servers", value, number)
            continue

        if section.startswith("system ntp"):
            ntp_lines.append(number)
            if key == "server":
                ctx.append("ntp.servers", value, number)
                continue
            if key == "authentication":
                ctx.set("ntp.authenticated", value == "enable", number)
                continue
            if key == "ntpsync":
                ctx.claim(number)
                continue

        if section == "system admin" and current_edit:
            if key == "password":
                # FortiOS stores an opaque blob; the algorithm is not disclosed
                # in the export, so recording "unknown" is the honest answer and
                # the control reports UNKNOWN rather than guessing.
                index = ctx.append(
                    "aaa.local_users",
                    {"name": current_edit, "privilege": None, "hash": None},
                    number,
                )
                ctx.set(f"aaa.local_users[{index}].hash", None, number)
                continue
            if key == "accprofile":
                ctx.claim(number)
                continue

        # Deliberately no catch-all here. A `set` key we do not recognise is a
        # line we did not interpret, and it stays uncounted so that it shows up
        # against coverage and in the report appendix. Claiming it would inflate
        # the one number this tool asks an auditor to trust.
        if key in _KNOWN_IRRELEVANT:
            ctx.claim(number)

    flush_interface()

    # Closed world: the NTP section was read and no authentication setting
    # appeared in it. FortiOS spells that "no authentication", which is a
    # finding rather than a silence.
    if ntp_lines and not ctx.builder.has("ntp.authenticated"):
        ctx.set("ntp.authenticated", False, ntp_lines[0], claim=False)

    if snmp_enabled and community_is_default is None:
        # SNMP is on with no community in the export - we know it runs, we do
        # not know how it authenticates. Deliberately left unwritten so the rule
        # reports UNKNOWN.
        pass
