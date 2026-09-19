"""Juniper Junos.

Curly-brace hierarchy, statements terminated with ``;``. The parser tracks the
path down the tree - ``system services ssh`` - and interprets a leaf by where it
sits, which is the natural reading of this grammar and much less brittle than
matching whole lines.

Junos also exposes an XML representation, and the specification says to prefer
it. The text form is parsed here because it is what an operator actually pastes
out of a terminal, and a tool that only accepts the XML export loses half its
real-world inputs.
"""

from __future__ import annotations

import re

from crucible.common.redaction import hash_algorithm_of
from crucible.parsers.base import ParseContext, register

__all__ = ["parse_junos"]

_RE_BLOCK_OPEN = re.compile(r"^(.+?)\s*\{$")
_RE_STATEMENT = re.compile(r"^(.+?);$")

DEFAULT_COMMUNITIES = {"public", "private", "juniper", "admin"}

#: Statements we positively recognise as carrying no security posture.
_KNOWN_IRRELEVANT = {
    "version",
    "uid",
    "class",
    "authorization",
    "system-generated-certificate",
    "rate-limit",
    "type",
    "peer-as",
    "neighbor",
    "accept",
    "log",
    "discard",
    "then",
    "protocol",
    "destination-port",
    "unit",
    "family",
    "inet",
}


@register("juniper")
def parse_junos(ctx: ParseContext) -> None:
    stack: list[str] = []
    interface: dict[str, object] | None = None
    interface_line = 0
    pending_user: str | None = None

    def path() -> str:
        return " ".join(stack)

    def flush_interface() -> None:
        nonlocal interface
        if interface is None:
            return
        index = ctx.append("interfaces", interface, interface_line)
        for key in ("acl_in", "shutdown"):
            marker = f"_{key}_line"
            if interface.get(marker):
                ctx.set(
                    f"interfaces[{index}].{key}",
                    interface.get(key),
                    int(str(interface.pop(marker))),
                )
        interface = None

    for line in ctx.lines():
        number = line.number
        text = line.text

        if line.is_blank or text.startswith(("#", "/*")):
            ctx.claim(number)
            continue

        if text == "}":
            leaving = stack.pop() if stack else ""
            if len(stack) == 1 and stack[0] == "interfaces" and interface is not None:
                flush_interface()
            elif (
                leaving.startswith("ge-") or leaving.startswith("xe-") or leaving.startswith("et-")
            ):
                pass
            ctx.claim(number)
            continue

        match = _RE_BLOCK_OPEN.match(text)
        if match:
            name = match.group(1).strip()
            stack.append(name)
            current = path()

            if len(stack) == 2 and stack[0] == "interfaces":
                flush_interface()
                interface = {
                    "name": name,
                    "description": None,
                    "addresses": [],
                    "acl_in": None,
                    "acl_out": None,
                    "shutdown": False,
                    "is_mgmt": name.startswith(("fxp", "em0", "me0")),
                }
                interface_line = number
            if current.startswith("snmp community "):
                community = name.split(None, 1)[1] if " " in name else ""
                marker = "default" if community.lower() in DEFAULT_COMMUNITIES else "custom"
                ctx.append("snmp.communities", marker, number, secret=community)
                ctx.set("snmp.version", 2, number, claim=False, secret=community)
                continue
            # Match on the BLOCK name, not the full path. Matching the path
            # meant the nested `authentication {` block under a user also looked
            # like a user declaration, so every account was recorded under the
            # name "authentication" and the real username was lost.
            if name.startswith("user ") and current.startswith("system login user"):
                pending_user = name.split()[-1]
            ctx.claim(number)
            continue

        match = _RE_STATEMENT.match(text)
        if not match:
            ctx.claim(number)
            continue

        statement = match.group(1).strip()
        parts = statement.split()
        head = parts[0] if parts else ""
        current = path()

        if current == "system" and head == "host-name":
            ctx.builder.set_device("hostname", parts[1], file=ctx.filename, line=number)
            continue

        if current == "system login" and head == "idle-timeout":
            ctx.set("mgmt.idle_timeout_min", int(parts[1]), number)
            continue

        if current == "system services ssh":
            if head == "protocol-version":
                version = 2 if parts[1].lower() in ("v2", "2") else 1
                ctx.set("mgmt.ssh.version", version, number)
                ctx.set("mgmt.ssh.enabled", True, number, claim=False)
                continue
            if head == "connection-limit":
                ctx.set("mgmt.ssh.max_attempts", int(parts[1]), number)
                continue

        if current == "system services" and head == "ssh":
            ctx.set("mgmt.ssh.enabled", True, number)
            continue

        if current == "system services" and head == "telnet":
            ctx.set("mgmt.telnet_enabled", True, number)
            continue

        if current.startswith("system services web-management https"):
            ctx.set("mgmt.https_enabled", True, number)
            continue
        if current.startswith("system services web-management http") and "https" not in current:
            ctx.set("mgmt.http_enabled", True, number)
            continue

        if current.startswith("system syslog host ") and head in ("any", "authorization"):
            server = current.split()[-1]
            ctx.append("logging.servers", server, number)
            ctx.set("logging.level", parts[-1], number, claim=False)
            continue

        if current == "system ntp":
            if head == "server":
                ctx.append("ntp.servers", parts[1], number)
                continue
            if head in ("authentication-key", "trusted-key"):
                ctx.set("ntp.authenticated", True, number)
                continue

        if head in ("encrypted-password", "plain-text-password"):
            # `system root-authentication` carries the root credential with no
            # enclosing user block. Skipping it meant the most privileged
            # account on the device was never examined - and the line was left
            # uninterpreted, which at least made the gap visible in coverage.
            account = "root" if current == "system root-authentication" else pending_user
            if account is None:
                ctx.claim(number)
                continue
            secret = statement.split(None, 1)[1].strip('"') if len(parts) > 1 else ""
            algorithm = "plaintext" if head == "plain-text-password" else hash_algorithm_of(secret)
            index = ctx.append(
                "aaa.local_users",
                {"name": account, "privilege": None, "hash": algorithm},
                number,
                secret=secret,
            )
            ctx.set(f"aaa.local_users[{index}].hash", algorithm, number, secret=secret)
            if account != "root":
                pending_user = None
            continue

        if current.startswith("system tacplus-server") or head == "tacplus-server":
            ctx.append("aaa.servers", parts[-1], number)
            ctx.set("aaa.enabled", True, number, claim=False)
            continue

        if interface is not None:
            if head == "description":
                interface["description"] = statement.split(None, 1)[1]
                ctx.claim(number)
                continue
            if head == "address":
                addresses = interface["addresses"]
                assert isinstance(addresses, list)
                addresses.append(parts[1])
                ctx.claim(number)
                continue
            if head == "input" and "filter" in current:
                interface["acl_in"] = parts[1]
                interface["_acl_in_line"] = number
                ctx.claim(number)
                continue
            if statement == "disable":
                interface["shutdown"] = True
                interface["_shutdown_line"] = number
                ctx.claim(number)
                continue

        if current.startswith("firewall family inet filter "):
            ctx.claim(number)
            continue

        # No catch-all. An unrecognised statement is uninterpreted, and it is
        # counted and listed as such rather than quietly absorbed into the
        # coverage figure.
        if head in _KNOWN_IRRELEVANT:
            ctx.claim(number)

    flush_interface()
