"""Palo Alto Networks PAN-OS, from the XML running configuration.

XML is parsed as XML, never as text - but the IR demands a line number for
every fact, and ``xml.etree`` does not keep one. So the tree is built here with
``expat`` directly, recording the line every element opens and closes on.

Security: a configuration file is untrusted input. Document type declarations
are refused outright, which rules out entity-expansion ("billion laughs") and
external-entity attacks without depending on the parser's defaults.

Coverage is accounted for the same way as every other grammar. Lines that open
or close a container are structure and are claimed. A leaf element this parser
understands becomes a fact on its line. A leaf element it does not understand
stays uninterpreted and is listed in the report - which is most of a real
PAN-OS configuration, and saying so is the point.
"""

from __future__ import annotations

import xml.parsers.expat
from dataclasses import dataclass, field

from crucible.common.errors import ParseError
from crucible.common.redaction import hash_algorithm_of
from crucible.parsers.base import ParseContext, register

__all__ = ["parse_panos"]

DEFAULT_COMMUNITIES = {"public", "private", "community", "admin", "default", "paloalto"}


@dataclass(slots=True)
class _El:
    tag: str
    attrs: dict[str, str]
    line: int
    end_line: int = 0
    text: str = ""
    children: list[_El] = field(default_factory=list)
    parent: _El | None = field(default=None, repr=False)

    @property
    def name(self) -> str | None:
        return self.attrs.get("name")

    def child(self, *path: str) -> _El | None:
        node: _El | None = self
        for tag in path:
            if node is None:
                return None
            node = next((c for c in node.children if c.tag == tag), None)
        return node

    def all(self, tag: str) -> list[_El]:
        return [c for c in self.children if c.tag == tag]

    def walk(self) -> list[_El]:
        out = [self]
        for c in self.children:
            out.extend(c.walk())
        return out


def _tree(text: str) -> _El:
    parser = xml.parsers.expat.ParserCreate()
    root = _El("#document", {}, 1)
    stack = [root]

    def refuse_dtd(*_args: object) -> None:
        raise ParseError("PAN-OS configuration contains a DTD; refused")

    def start(tag: str, attrs: dict[str, str]) -> None:
        node = _El(tag, dict(attrs), parser.CurrentLineNumber, parent=stack[-1])
        stack[-1].children.append(node)
        stack.append(node)

    def end(_tag: str) -> None:
        node = stack.pop()
        node.end_line = parser.CurrentLineNumber
        node.text = node.text.strip()

    def data(chunk: str) -> None:
        stack[-1].text += chunk

    parser.StartDoctypeDeclHandler = refuse_dtd
    parser.EntityDeclHandler = refuse_dtd
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = data
    try:
        parser.Parse(text, True)
    except xml.parsers.expat.ExpatError as exc:
        raise ParseError(f"PAN-OS configuration is not well-formed XML: {exc}") from exc
    return root


def _prefix_length(mask: str) -> int | None:
    try:
        octets = [int(o) for o in mask.strip().split(".")]
    except ValueError:
        return None
    if len(octets) != 4 or any(not 0 <= o <= 255 for o in octets):
        return None
    bits = "".join(f"{o:08b}" for o in octets)
    if "01" in bits:
        return None  # not a contiguous mask
    return bits.count("1")


def _yes(value: str) -> bool | None:
    lowered = value.strip().lower()
    if lowered == "yes":
        return True
    if lowered == "no":
        return False
    return None


@register("paloalto")
def parse_panos(ctx: ParseContext) -> None:
    lines = ctx.source.lines
    root = _tree(ctx.source.text)
    config = root.child("config")
    if config is None:
        return

    understood: set[int] = set()

    def fact(path: str, value: object, node: _El, **kwargs: object) -> None:
        ctx.set(path, value, node.line, **kwargs)
        understood.add(node.line)

    device = config.child("devices", "entry")
    system = device.child("deviceconfig", "system") if device else None

    # -- identity and management plane ---------------------------------------
    if system is not None:
        hostname = system.child("hostname")
        if hostname is not None and hostname.text:
            ctx.builder.set_device("hostname", hostname.text, file=ctx.filename, line=hostname.line)
            understood.add(hostname.line)

        service = system.child("service")
        if service is not None:
            for tag, path in (
                ("disable-telnet", "mgmt.telnet_enabled"),
                ("disable-http", "mgmt.http_enabled"),
                ("disable-https", "mgmt.https_enabled"),
                ("disable-ssh", "mgmt.ssh.enabled"),
            ):
                node = service.child(tag)
                if node is not None:
                    disabled = _yes(node.text)
                    if disabled is not None:
                        fact(path, not disabled, node)

        banner = system.child("login-banner")
        if banner is not None:
            fact("mgmt.login_banner", bool(banner.text), banner)

        # The dedicated management port: an interface in the IR, so the fleet
        # graph can see where the management plane lives.
        mgmt_ip = system.child("ip-address")
        mgmt_mask = system.child("netmask")
        if mgmt_ip is not None and mgmt_ip.text:
            prefix = _prefix_length(mgmt_mask.text) if mgmt_mask is not None else None
            mgmt_address = f"{mgmt_ip.text}/{prefix}" if prefix is not None else mgmt_ip.text
            ctx.append(
                "interfaces",
                {
                    "name": "management",
                    "description": "dedicated management port",
                    "addresses": [mgmt_address],
                    "acl_in": None,
                    "acl_out": None,
                    "zone": "management",
                    "shutdown": False,
                    "is_mgmt": True,
                },
                mgmt_ip.line,
            )
            understood.add(mgmt_ip.line)
            if mgmt_mask is not None and prefix is not None:
                understood.add(mgmt_mask.line)

        permitted = system.child("permitted-ip")
        if permitted is not None and permitted.all("entry"):
            fact("mgmt.mgmt_acl", "permitted-ip", permitted)

        snmp = system.child("snmp-setting", "access-setting", "version")
        if snmp is not None:
            v2c = snmp.child("v2c")
            v3 = snmp.child("v3")
            if v2c is not None:
                community = v2c.child("snmp-community-string")
                if community is not None and community.text:
                    marker = (
                        "default" if community.text.lower() in DEFAULT_COMMUNITIES else "custom"
                    )
                    ctx.append("snmp.communities", marker, community.line, secret=community.text)
                    ctx.set("snmp.version", 2, community.line, claim=False, secret=community.text)
                    understood.add(community.line)
            elif v3 is not None:
                fact("snmp.version", 3, v3)

        ntp = system.child("ntp-servers")
        if ntp is not None:
            authenticated: list[bool] = []
            for server in ntp.children:
                address = server.child("ntp-server-address")
                if address is not None and address.text:
                    ctx.append("ntp.servers", address.text, address.line)
                    understood.add(address.line)
                auth = server.child("authentication-type")
                if auth is not None:
                    kinds = {c.tag for c in auth.children}
                    authenticated.append(bool(kinds) and "none" not in kinds)
                    understood.update(c.line for c in auth.children)
            if authenticated and auth is not None:
                fact("ntp.authenticated", all(authenticated), auth)

    setting = device.child("deviceconfig", "setting", "management") if device else None
    if setting is not None:
        timeout = setting.child("idle-timeout")
        if timeout is not None and timeout.text.isdigit():
            fact("mgmt.idle_timeout_min", int(timeout.text), timeout)

    # -- local accounts and password policy ----------------------------------
    users = config.child("mgt-config", "users")
    if users is not None:
        for entry in users.all("entry"):
            phash = entry.child("phash")
            superuser = entry.child("permissions", "role-based", "superuser")
            privilege = 15 if superuser is not None and _yes(superuser.text) else 1
            index = ctx.append(
                "aaa.local_users",
                {"name": entry.name or "", "privilege": privilege, "hash": None},
                entry.line,
            )
            understood.add(entry.line)
            if phash is not None and phash.text:
                fact(
                    f"aaa.local_users[{index}].hash",
                    hash_algorithm_of(phash.text),
                    phash,
                    secret=phash.text,
                )
            if superuser is not None:
                understood.add(superuser.line)

    complexity = config.child("mgt-config", "password-complexity")
    if complexity is not None:
        enabled = complexity.child("enabled")
        if enabled is not None and _yes(enabled.text) is not None:
            fact("aaa.password_policy.complexity", bool(_yes(enabled.text)), enabled)
        length = complexity.child("minimum-length")
        if length is not None and length.text.isdigit():
            fact("aaa.password_policy.min_length", int(length.text), length)

    # -- logging ---------------------------------------------------------------
    syslog = config.child("shared", "log-settings", "syslog")
    if syslog is not None:
        for profile in syslog.all("entry"):
            servers = profile.child("server")
            for server in servers.all("entry") if servers is not None else []:
                address = server.child("server")
                if address is not None and address.text:
                    ctx.append("logging.servers", address.text, address.line)
                    understood.add(address.line)

    # -- interfaces and zones --------------------------------------------------
    zones: dict[str, str] = {}
    vsys = device.child("vsys") if device else None
    for vsys_entry in vsys.all("entry") if vsys is not None else []:
        zone_root = vsys_entry.child("zone")
        for zone in zone_root.all("entry") if zone_root is not None else []:
            layer3 = zone.child("network", "layer3")
            for member in layer3.all("member") if layer3 is not None else []:
                zones[member.text] = zone.name or ""
                understood.add(member.line)

    ethernet = device.child("network", "interface", "ethernet") if device else None
    for entry in ethernet.all("entry") if ethernet is not None else []:
        layer3 = entry.child("layer3")
        addresses = []
        ip = layer3.child("ip") if layer3 is not None else None
        for address in ip.all("entry") if ip is not None else []:
            if address.name:
                addresses.append(address.name)
                understood.add(address.line)
        comment = entry.child("comment")
        if comment is not None:
            understood.add(comment.line)
        description = comment.text if comment is not None else None
        ctx.append(
            "interfaces",
            {
                "name": entry.name or "",
                "description": description,
                "addresses": addresses,
                # PAN-OS filters by zone, not by interface ACL: traffic entering
                # a zoned interface must match the security policy of its zone.
                # An interface in no zone passes no traffic at all.
                "acl_in": f"zone-policy:{zones[entry.name or '']}"
                if (entry.name or "") in zones
                else None,
                "acl_out": None,
                "zone": zones.get(entry.name or ""),
                "shutdown": False,
                "is_mgmt": False,
            },
            entry.line,
        )
        understood.add(entry.line)

    # -- line accounting ------------------------------------------------------
    # Structure is understood: the declaration, and any line that only opens
    # or closes a container. A leaf we did not map stays uninterpreted.
    for number, raw in enumerate(lines, start=1):
        text = raw.strip()
        if not text or text.startswith(("<?xml", "<!--")):
            ctx.claim(number)
    for node in root.walk()[1:]:
        # A container is structure only when its children sit on other lines.
        # "<from><member>trust</member></from>" is one line of rule semantics
        # this parser does not read, so it stays uninterpreted.
        multiline = node.children and any(c.line != node.line for c in node.children)
        if multiline:
            ctx.claim(node.line)
            if node.end_line and node.end_line != node.line:
                ctx.claim(node.end_line)
        elif node.line in understood:
            ctx.claim(node.line)
            if node.end_line and node.end_line != node.line:
                ctx.claim(node.end_line)
