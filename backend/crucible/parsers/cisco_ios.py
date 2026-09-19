"""Cisco IOS / IOS-XE, and the IOS-style grammar Arista EOS shares.

Block-structured, ``!`` separators, indentation is meaningful. The parser walks
the file once, tracking which top-level block it is inside, and writes a fact
only when it can name the line that justifies it.

Two behaviours here are worth defending in review:

**Telnet is decided from the transport lines, not from a single keyword.** A
device can carry ``no ip telnet server`` and still accept Telnet on a vty whose
``transport input`` allows it. Reading only the first would report a clean pass
on a device that is wide open, which is invariant 3 failing quietly.

**The lowest ``exec-timeout`` across vtys wins.** An auditor cares about the
weakest line, not the average one, and a device with fifteen tight vtys and one
loose one is a device with a loose vty.
"""

from __future__ import annotations

import re

from crucible.common.redaction import hash_algorithm_of
from crucible.parsers.base import Line, ParseContext, register

__all__ = ["parse_ios_style"]

_RE_HOSTNAME = re.compile(r"^hostname (\S+)")
# The qualifier between `secret` and the digest is either a Cisco type number
# (`secret 9 $9$...`) or, on Arista EOS, the algorithm spelled out
# (`secret sha512 $6$...`). Reading the second form as the digest reported the
# algorithm as unknown on a device that had actually done the right thing.
_RE_USERNAME = re.compile(
    r"^username (\S+)(?: privilege (\d+))?(?: role \S+)? (secret|password)"
    r"(?: (\d+|sha512|sha256|md5|bcrypt))? (\S+)"
)
_NAMED_ALGORITHMS = {"sha512", "sha256", "md5", "bcrypt"}
_RE_TACACS_HOST = re.compile(r"^tacacs-server host (\S+)")
_RE_RADIUS_HOST = re.compile(r"^radius-server host (\S+)")
_RE_AAA_ADDRESS = re.compile(r"^address ipv4 (\S+)")
_RE_SSH_VERSION = re.compile(r"^ip ssh version (\d)")
_RE_SSH_RETRIES = re.compile(r"^ip ssh authentication-retries (\d+)")
_RE_EXEC_TIMEOUT = re.compile(r"^exec-timeout (\d+)(?: (\d+))?")
_RE_TRANSPORT_INPUT = re.compile(r"^transport input (.+)")
_RE_ACCESS_CLASS = re.compile(r"^access-class (\S+) in")
_RE_INTERFACE = re.compile(r"^interface (\S+)")
_RE_IP_ADDRESS = re.compile(r"^ip address (\S+) (\S+)")
_RE_IP_ADDRESS_CIDR = re.compile(r"^ip address (\S+/\d+)")
_RE_ACCESS_GROUP = re.compile(r"^ip access-group (\S+) (in|out)")
_RE_ACCESS_VLAN = re.compile(r"^switchport access vlan (\d+)")
_RE_DESCRIPTION = re.compile(r"^description (.+)")
_RE_ACL_HEADER = re.compile(r"^ip access-list (?:(standard|extended) )?(\S+)")
_RE_ACL_ENTRY = re.compile(r"^(?:(\d+) )?(permit|deny)\s+(.*)$")
_RE_LOGGING_HOST = re.compile(r"^logging (?:host )?(\d+\.\d+\.\d+\.\d+)")
_RE_LOGGING_TRAP = re.compile(r"^logging trap (\S+)")
_RE_SNMP_COMMUNITY = re.compile(r"^snmp-server community (\S+)(?: (RO|RW))?", re.I)
_RE_SNMP_GROUP_V3 = re.compile(r"^snmp-server group \S+ v3")
_RE_NTP_SERVER = re.compile(r"^ntp server (\S+)")
_RE_BANNER = re.compile(r"^banner (motd|login|exec) (.)")
_RE_VLAN = re.compile(r"^vlan (\d+)")

#: Community strings any scanner tries first. Detected at parse time, because the
#: stored value is redacted and a rule can never see the literal.
DEFAULT_COMMUNITIES = {"public", "private", "cisco", "admin", "secret", "community"}

#: Sub-commands we positively recognise as carrying no security posture.
#:
#: The allowlist exists so that "we understood this line and it does not matter"
#: is distinguishable from "we never looked at it". Only the first may count as
#: parsed - otherwise the coverage figure, which is the number this tool asks an
#: auditor to trust, quietly becomes a lie.
_BENIGN_SUBCOMMANDS = (
    "switchport ",
    "logging synchronous",
    "name ",
    "speed ",
    "duplex ",
    "mtu ",
    "channel-group ",
    "spanning-tree ",
    "storm-control ",
    "load-interval ",
    "no switchport",
    "authentication mode ",
    "encapsulation ",
    "vrf ",
    "standby ",
    "priority ",
    "remark ",
)


class _State:
    """Accumulated readings that only make sense once the whole file is seen."""

    def __init__(self) -> None:
        self.vty_timeouts: list[tuple[int, int]] = []  # (minutes, line)
        self.telnet_lines: list[tuple[bool, int]] = []  # (allows telnet, line)
        self.telnet_server: tuple[bool, int] | None = None
        self.mgmt_acl: tuple[str, int] | None = None
        self.interfaces: list[dict[str, object]] = []
        self.interface_lines: list[int] = []


def _finish_interface(ctx: ParseContext, state: _State) -> None:
    """Flush the interface under construction into the IR."""
    if not state.interfaces:
        return
    current = state.interfaces[-1]
    index = ctx.append("interfaces", current, state.interface_lines[-1])
    for key in ("acl_in", "acl_out", "shutdown", "is_mgmt"):
        if key in current and f"_{key}_line" in current:
            ctx.set(
                f"interfaces[{index}].{key}",
                current[key],
                int(str(current.pop(f"_{key}_line"))),
            )
    for key in list(current):
        if isinstance(key, str) and key.startswith("_"):
            current.pop(key)


def parse_ios_style(ctx: ParseContext, *, dialect: str = "cisco") -> None:
    """Parse an IOS-style hierarchical configuration into the IR.

    ``dialect`` selects the handful of places Arista EOS diverges: management
    services live in their own blocks rather than as ``ip ssh`` globals.
    """
    state = _State()
    block: str = ""
    block_arg: str = ""
    banner_delimiter: str | None = None

    lines = list(ctx.lines())
    for line in lines:
        number = line.number

        # --- banner bodies are opaque text, but they are still lines ------
        if banner_delimiter is not None:
            ctx.claim(number)
            if banner_delimiter in line.text:
                banner_delimiter = None
            continue

        if line.is_blank or line.text.startswith("!"):
            ctx.claim(number)
            continue

        # --- top-level statements ----------------------------------------
        if line.indent == 0:
            # Any unindented line closes the interface under construction -
            # including the *next* interface line. Flushing only on a non-
            # interface line silently dropped every interface but the last.
            if state.interfaces:
                _finish_interface(ctx, state)
                state.interfaces.clear()
                state.interface_lines.clear()
            block, block_arg = _top_level(ctx, state, line, dialect)
            if line.text.startswith("banner "):
                match = _RE_BANNER.match(line.text)
                if match:
                    banner_delimiter = match.group(2)
            continue

        # --- indented statements, interpreted in block context ------------
        _in_block(ctx, state, line, block, block_arg, dialect)

    if state.interfaces:
        _finish_interface(ctx, state)

    _resolve_management_plane(ctx, state, dialect)


def _top_level(ctx: ParseContext, state: _State, line: Line, dialect: str) -> tuple[str, str]:
    """Handle an unindented line. Returns the block context it opens."""
    text = line.text
    number = line.number

    match = _RE_HOSTNAME.match(text)
    if match:
        ctx.builder.set_device("hostname", match.group(1), file=ctx.filename, line=number)
        return "", ""

    match = _RE_INTERFACE.match(text)
    if match:
        name = match.group(1)
        state.interfaces.append(
            {
                "name": name,
                "description": None,
                "addresses": [],
                "acl_in": None,
                "acl_out": None,
                "vlan": None,
                "shutdown": False,
                "is_mgmt": name.lower().startswith(("management", "vlan900", "mgmt")),
            }
        )
        state.interface_lines.append(number)
        ctx.claim(number)
        return "interface", name

    match = _RE_ACL_HEADER.match(text)
    if match:
        acl_name = match.group(2)
        ctx.append("acls", {"name": acl_name, "entries": []}, number)
        return "acl", acl_name

    if text.startswith("line "):
        ctx.claim(number)
        return "line", text[5:].strip()

    if dialect == "arista":
        if text == "management ssh":
            ctx.set("mgmt.ssh.enabled", True, number)
            return "management-ssh", ""
        if text == "management telnet":
            ctx.claim(number)
            return "management-telnet", ""
        if text.startswith("management api http-commands"):
            ctx.claim(number)
            return "management-api", ""

    # --- single-line globals ---------------------------------------------
    if text == "aaa new-model" or text.startswith("aaa authentication login"):
        ctx.set("aaa.enabled", True, number)
        return "", ""
    if text.startswith("no aaa root"):
        ctx.claim(number)
        return "", ""
    if text.startswith("aaa accounting"):
        ctx.set("aaa.accounting", True, number)
        return "", ""

    match = _RE_USERNAME.match(text)
    if match:
        name, privilege, kind, qualifier, secret = match.groups()
        if qualifier in _NAMED_ALGORITHMS:
            algorithm = qualifier
        else:
            algorithm = hash_algorithm_of(secret, qualifier)
        if kind == "password" and qualifier is None:
            algorithm = "plaintext"
        index = ctx.append(
            "aaa.local_users",
            {
                "name": name,
                "privilege": int(privilege) if privilege else None,
                "hash": algorithm,
            },
            number,
        )
        ctx.set(f"aaa.local_users[{index}].hash", algorithm, number)
        return "", ""

    for pattern in (_RE_TACACS_HOST, _RE_RADIUS_HOST):
        match = pattern.match(text)
        if match:
            ctx.append("aaa.servers", match.group(1), number)
            return "", ""
    if text.startswith(("tacacs server", "radius server")):
        ctx.claim(number)
        return "aaa-server", text.split()[-1]

    match = _RE_SSH_VERSION.match(text)
    if match:
        ctx.set("mgmt.ssh.version", int(match.group(1)), number)
        ctx.set("mgmt.ssh.enabled", True, number, claim=False)
        return "", ""

    match = _RE_SSH_RETRIES.match(text)
    if match:
        ctx.set("mgmt.ssh.max_attempts", int(match.group(1)), number)
        return "", ""

    if text.startswith("no ip telnet server"):
        state.telnet_server = (False, number)
        ctx.claim(number)
        return "", ""
    if text == "ip telnet server":
        state.telnet_server = (True, number)
        ctx.claim(number)
        return "", ""

    if text == "ip http server":
        ctx.set("mgmt.http_enabled", True, number)
        return "", ""
    if text == "no ip http server":
        ctx.set("mgmt.http_enabled", False, number)
        return "", ""
    if text == "ip http secure-server":
        ctx.set("mgmt.https_enabled", True, number)
        return "", ""
    if text == "no ip http secure-server":
        ctx.set("mgmt.https_enabled", False, number)
        return "", ""

    match = _RE_LOGGING_TRAP.match(text)
    if match:
        ctx.set("logging.level", match.group(1), number)
        return "", ""
    match = _RE_LOGGING_HOST.match(text)
    if match:
        ctx.append("logging.servers", match.group(1), number)
        return "", ""

    match = _RE_SNMP_COMMUNITY.match(text)
    if match:
        community = match.group(1)
        # Store a marker, never the string. What a rule needs to know is whether
        # a v1/v2c community exists at all, and whether it is a default one.
        marker = "default" if community.lower() in DEFAULT_COMMUNITIES else "custom"
        ctx.append("snmp.communities", marker, number, secret=community)
        ctx.set("snmp.version", 2, number, claim=False, secret=community)
        return "", ""
    if _RE_SNMP_GROUP_V3.match(text) or text.startswith("snmp-server user"):
        ctx.set("snmp.version", 3, number)
        return "", ""
    if text.startswith("snmp-server "):
        ctx.claim(number)
        return "", ""

    match = _RE_NTP_SERVER.match(text)
    if match:
        ctx.append("ntp.servers", match.group(1), number)
        if " key " in text:
            ctx.set("ntp.authenticated", True, number, claim=False)
        return "", ""
    if text == "ntp authenticate":
        ctx.set("ntp.authenticated", True, number)
        return "", ""
    if text.startswith(("ntp authentication-key", "ntp trusted-key")):
        ctx.claim(number)
        return "", ""

    if text.startswith("banner "):
        ctx.set("mgmt.login_banner", True, number)
        return "", ""

    if text in ("no cdp run", "no lldp run"):
        ctx.set("services.discovery_protocols", False, number)
        return "", ""
    if text in ("cdp run", "lldp run"):
        ctx.set("services.discovery_protocols", True, number)
        return "", ""

    if text.startswith("no ip source-route"):
        ctx.set("services.source_routing", False, number)
        return "", ""
    if text == "ip source-route":
        ctx.set("services.source_routing", True, number)
        return "", ""

    if _RE_VLAN.match(text):
        ctx.claim(number)
        return "vlan", text

    # Structural lines that carry no security fact but were understood.
    if text.startswith(
        (
            "version ",
            "service ",
            "no service ",
            "boot-",
            "clock timezone",
            "ip domain-name",
            "ip name-server",
            "dns domain",
            "spanning-tree",
            "crypto key",
            "ip route ",
            "ip routing",
            "no ip routing",
            "enable secret",
            "enable password",
            "transceiver ",
            "end",
            "exit",
            "ip ssh ",
            "ip forward-protocol",
            "aaa authorization",
        )
    ):
        if text.startswith("enable "):
            parts = text.split()
            algorithm = hash_algorithm_of(parts[-1], parts[2] if len(parts) > 3 else None)
            ctx.set("aaa.enable_secret_hash", algorithm, number)
        else:
            ctx.claim(number)
        return "", ""

    return "", ""


def _in_block(
    ctx: ParseContext, state: _State, line: Line, block: str, block_arg: str, dialect: str
) -> None:
    """Handle an indented line in the context of the block that opened it."""
    text = line.text
    number = line.number

    if block == "line":
        match = _RE_EXEC_TIMEOUT.match(text)
        if match and block_arg.startswith("vty"):
            state.vty_timeouts.append((int(match.group(1)), number))
            ctx.claim(number)
            return
        match = _RE_TRANSPORT_INPUT.match(text)
        if match and block_arg.startswith("vty"):
            allowed = match.group(1).split()
            state.telnet_lines.append(("telnet" in allowed or "all" in allowed, number))
            ctx.claim(number)
            return
        match = _RE_ACCESS_CLASS.match(text)
        if match:
            state.mgmt_acl = (match.group(1), number)
            ctx.claim(number)
            return
        _claim_if_benign(ctx, line)
        return

    if block == "management-ssh" and dialect == "arista":
        match = re.match(r"^idle-timeout (\d+)", text)
        if match:
            state.vty_timeouts.append((int(match.group(1)), number))
            ctx.claim(number)
            return
        if text == "shutdown":
            ctx.set("mgmt.ssh.enabled", False, number)
            return
        _claim_if_benign(ctx, line)
        return

    if block == "management-telnet" and dialect == "arista":
        if text == "shutdown":
            state.telnet_server = (False, number)
        elif text == "no shutdown":
            state.telnet_server = (True, number)
        ctx.claim(number)
        return

    if block == "management-api" and dialect == "arista":
        if text == "no shutdown":
            ctx.set("mgmt.http_enabled", True, number)
            return
        if text == "shutdown":
            ctx.set("mgmt.http_enabled", False, number)
            return
        _claim_if_benign(ctx, line)
        return

    if block == "interface" and state.interfaces:
        current = state.interfaces[-1]
        match = _RE_DESCRIPTION.match(text)
        if match:
            current["description"] = match.group(1)
            ctx.claim(number)
            return
        match = _RE_ACCESS_GROUP.match(text)
        if match:
            key = "acl_in" if match.group(2) == "in" else "acl_out"
            current[key] = match.group(1)
            current[f"_{key}_line"] = number
            ctx.claim(number)
            return
        match = _RE_IP_ADDRESS_CIDR.match(text) or _RE_IP_ADDRESS.match(text)
        if match:
            addresses = current["addresses"]
            assert isinstance(addresses, list)
            addresses.append(match.group(1))
            if "management" in str(current.get("description", "")).lower():
                current["is_mgmt"] = True
            ctx.claim(number)
            return
        match = _RE_ACCESS_VLAN.match(text)
        if match:
            current["vlan"] = int(match.group(1))
            ctx.claim(number)
            return
        if text == "shutdown":
            current["shutdown"] = True
            current["_shutdown_line"] = number
            ctx.claim(number)
            return
        if text == "no shutdown":
            current["shutdown"] = False
            current["_shutdown_line"] = number
            ctx.claim(number)
            return
        _claim_if_benign(ctx, line)
        return

    if block == "acl":
        match = _RE_ACL_ENTRY.match(text)
        if match:
            sequence, action, remainder = match.groups()
            acls = ctx.builder._sections.get("acls", [])
            if acls:
                acls[-1]["entries"].append(
                    {
                        "seq": int(sequence) if sequence else len(acls[-1]["entries"]) * 10 + 10,
                        "action": action,
                        "raw": text,
                        "match": remainder,
                        "log": "log" in remainder.split(),
                    }
                )
            ctx.claim(number)
            return
        _claim_if_benign(ctx, line)
        return

    if block == "aaa-server":
        match = _RE_AAA_ADDRESS.match(text)
        if match:
            ctx.append("aaa.servers", match.group(1), number)
            return
        _claim_if_benign(ctx, line)
        return

    if block == "vlan":
        _claim_if_benign(ctx, line)
        return


def _claim_if_benign(ctx: ParseContext, line: Line) -> None:
    """Count a sub-command only if we recognise it as security-irrelevant.

    Anything else stays uninterpreted and is listed verbatim in the report, so a
    reader can check for themselves that nothing important was skipped.
    """
    if line.text.startswith(_BENIGN_SUBCOMMANDS):
        ctx.claim(line.number)


def _resolve_management_plane(ctx: ParseContext, state: _State, dialect: str) -> None:
    """Turn accumulated vty readings into single IR facts.

    Nothing is written when nothing was observed. A device whose configuration
    never mentions a session timeout gets ``UNKNOWN`` on that control, not a
    default, because a default here would be us inventing a fact.
    """
    if state.vty_timeouts:
        minutes, line = min(state.vty_timeouts, key=lambda item: item[0])
        ctx.set("mgmt.idle_timeout_min", minutes, line, claim=False)

    if state.telnet_lines:
        enabled = any(allows for allows, _ in state.telnet_lines)
        line = next(
            (ln for allows, ln in state.telnet_lines if allows is enabled),
            state.telnet_lines[0][1],
        )
        ctx.set("mgmt.telnet_enabled", enabled, line, claim=False)
    elif state.telnet_server is not None:
        enabled, line = state.telnet_server
        ctx.set("mgmt.telnet_enabled", enabled, line, claim=False)

    if state.mgmt_acl is not None:
        name, line = state.mgmt_acl
        ctx.set("mgmt.mgmt_acl", name, line, claim=False)
    else:
        # An ACL applied inbound on a management interface is the same control
        # by a different route, and a real deployment uses whichever the
        # platform prefers.
        for interface in ctx.builder._sections.get("interfaces", []):
            if interface.get("is_mgmt") and interface.get("acl_in"):
                provenance = ctx.builder._provenance
                index = ctx.builder._sections["interfaces"].index(interface)
                source = provenance.get(f"interfaces[{index}].acl_in")
                if source is not None:
                    ctx.set("mgmt.mgmt_acl", interface["acl_in"], source.line, claim=False)
                break


@register("cisco")
def parse_cisco_ios(ctx: ParseContext) -> None:
    parse_ios_style(ctx, dialect="cisco")
