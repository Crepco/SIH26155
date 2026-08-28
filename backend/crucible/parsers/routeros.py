"""MikroTik RouterOS.

Flat, path-prefixed commands. No hierarchy at all: every line carries its own
full context, which makes this the simplest grammar of the six and a good
demonstration of how little a Tier-0 parser has to be.

RouterOS is also the vendor held out of development for the unseen-vendor
demonstration. This module exists so the *comparison* is honest - it is what a
hand-written parser for this vendor looks like, against which a learned adapter
pack can be measured.
"""

from __future__ import annotations

import re

from crucible.parsers.base import ParseContext, register

__all__ = ["parse_routeros"]

_RE_COMMAND = re.compile(r"^(/\S+(?:\s+\S+)*?)\s+(set|add|remove)\s+(.*)$")
_RE_KV = re.compile(r'(\S+?)=("[^"]*"|\S+)')

DEFAULT_COMMUNITIES = {"public", "private", "mikrotik", "admin"}

#: Command roots we positively recognise as carrying no security posture.
_KNOWN_IRRELEVANT_ROOTS = {"/system", "/interface"}

#: RouterOS names its management services on one line each. Mapping them to the
#: IR is the whole of this parser.
_SERVICE_TO_PATH = {
    "telnet": "mgmt.telnet_enabled",
    "ssh": "mgmt.ssh.enabled",
    "www": "mgmt.http_enabled",
    "www-ssl": "mgmt.https_enabled",
}


def _pairs(remainder: str) -> dict[str, str]:
    return {k: v.strip('"') for k, v in _RE_KV.findall(remainder)}


@register("mikrotik")
def parse_routeros(ctx: ParseContext) -> None:
    interfaces: dict[str, dict[str, object]] = {}
    interface_lines: dict[str, int] = {}

    for line in ctx.lines():
        number = line.number
        text = line.text

        if line.is_blank or text.startswith("#"):
            ctx.claim(number)
            continue

        match = _RE_COMMAND.match(text)
        if not match:
            continue

        command_path, _verb, remainder = match.groups()
        values = _pairs(remainder)

        if command_path == "/system identity" and "name" in values:
            ctx.builder.set_device("hostname", values["name"], file=ctx.filename, line=number)
            continue

        if command_path.startswith("/ip service"):
            # "/ip service set telnet disabled=no" - the service name is a bare
            # token before the key/value pairs, not a keyed field.
            tokens = remainder.split()
            service = tokens[0] if tokens and "=" not in tokens[0] else None
            if service in _SERVICE_TO_PATH and "disabled" in values:
                enabled = values["disabled"] == "no"
                ctx.set(_SERVICE_TO_PATH[service], enabled, number)
                continue
            ctx.claim(number)
            continue

        if command_path.startswith("/snmp community"):
            name = values.get("name", "")
            marker = "default" if name.lower() in DEFAULT_COMMUNITIES else "custom"
            ctx.append("snmp.communities", marker, number)
            ctx.set("snmp.version", 2, number, claim=False)
            continue

        if command_path == "/snmp" and "enabled" in values:
            ctx.claim(number)
            continue

        if command_path.startswith("/system ntp client servers") and "address" in values:
            ctx.append("ntp.servers", values["address"], number)
            continue

        if command_path.startswith("/system logging action") and "remote" in values:
            ctx.append("logging.servers", values["remote"], number)
            continue

        if command_path.startswith("/ip address") and "interface" in values:
            name = values["interface"]
            entry = interfaces.setdefault(
                name,
                {
                    "name": name,
                    "description": None,
                    "addresses": [],
                    "acl_in": None,
                    "acl_out": None,
                    "shutdown": False,
                    "is_mgmt": False,
                },
            )
            interface_lines.setdefault(name, number)
            addresses = entry["addresses"]
            assert isinstance(addresses, list)
            if "address" in values:
                addresses.append(values["address"])
            ctx.claim(number)
            continue

        if command_path.startswith("/interface ethernet") and "comment" in values:
            comment = values["comment"]
            for name, entry in interfaces.items():
                if entry.get("description") is None and name in text:
                    entry["description"] = comment
            ctx.claim(number)
            continue

        if command_path.startswith("/ip firewall filter"):
            # Firewall rules are the RouterOS equivalent of an ACL. Recording
            # the input chain lets the management-ACL control apply here too.
            if values.get("chain") == "input" and values.get("action") == "accept":
                if "dst-port" in values and "src-address" in values:
                    ctx.set("mgmt.mgmt_acl", "input-chain", number)
                    continue
            ctx.claim(number)
            continue

        if command_path.startswith("/user"):
            name = values.get("name")
            if name:
                index = ctx.append(
                    "aaa.local_users", {"name": name, "privilege": None, "hash": None}, number
                )
                ctx.set(f"aaa.local_users[{index}].hash", None, number)
                continue
            ctx.claim(number)
            continue

        # No catch-all: a command path we do not recognise stays uninterpreted
        # and is counted against coverage.
        if command_path.split()[0] in _KNOWN_IRRELEVANT_ROOTS:
            ctx.claim(number)

    for name, entry in interfaces.items():
        ctx.append("interfaces", entry, interface_lines[name])
