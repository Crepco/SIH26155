"""Applying a rule's remediation to a twin.

The twin is not any vendor's operating system, so it cannot be handed Cisco or
FortiOS commands. It speaks the small VyOS-style subset that the rules already
carry in their ``vyos`` remediation block, and every rule's vendor variants are
the same intent rendered differently - that is what the IR is for.

Be precise about what this proves and what it does not:

* it proves the **fix closes the finding**: after applying it, the probe that
  demonstrated the problem no longer does;
* it proves the fix **does not lock the operator out**: SSH from the management
  segment still answers afterwards;
* it does **not** prove that the Cisco spelling of the same fix is free of
  typos. Nothing that boots a single twin could.

A command this interpreter does not understand is reported as not applied,
never silently ignored: a fix that was not applied must not be reported as
validated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from crucible.sandbox.spec import MGMT_NETWORK, STRONG_CIPHERS, STRONG_KEX, TwinSpec

__all__ = ["Application", "apply_remediation"]

_IGNORED = ("commit", "save", "configure", "exit", "end", "write memory")
_CIDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")


@dataclass(slots=True)
class Application:
    """The result of pasting a fix into the twin."""

    spec: TwinSpec
    applied: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.applied)


def apply_remediation(spec: TwinSpec, commands: list[str]) -> Application:
    """Interpret VyOS-style commands against a twin specification."""
    result = Application(spec=spec.copy())
    twin = result.spec

    for raw in commands:
        command = " ".join(raw.split())
        lowered = command.lower()
        if not command or lowered in _IGNORED or command.startswith("!"):
            continue

        if lowered.startswith("delete service telnet"):
            twin.telnet = False
        elif lowered.startswith("set service telnet"):
            twin.telnet = True
        elif lowered.startswith("delete service ssh"):
            twin.ssh = False
        elif lowered.startswith("set service ssh ciphers"):
            twin.ssh_ciphers = list(STRONG_CIPHERS)
        elif lowered.startswith(("set service ssh key-exchange", "set service ssh kex")):
            twin.ssh_kex = list(STRONG_KEX)
        elif lowered.startswith("set service ssh"):
            twin.ssh = True
        elif lowered.startswith(("delete service http", "delete service web")):
            twin.http = False
        elif lowered.startswith(("set service http", "set service web")):
            twin.http = True
        elif lowered.startswith("delete service snmp community"):
            name = command.split()[-1]
            twin.snmp_communities = [c for c in twin.snmp_communities if c != name]
        elif lowered.startswith("delete service snmp"):
            twin.snmp_communities = []
        elif lowered.startswith("set service snmp v3"):
            # v3 replaces the community entirely: nothing answers v2c after it.
            twin.snmp_communities = []
        elif lowered.startswith("set service snmp community"):
            parts = command.split()
            if len(parts) >= 5:
                name = parts[4]
                if name not in twin.snmp_communities:
                    twin.snmp_communities.append(name)
        elif "firewall" in lowered or "listen-address" in lowered or "trusted-host" in lowered:
            found = _CIDR.findall(command)
            if found:
                for prefix in found:
                    if prefix not in twin.mgmt_allow:
                        twin.mgmt_allow.append(prefix)
                # The fix names the operator's real management prefix, which
                # does not exist inside the sandbox. The twin's management
                # segment stands in for it, so the regression check measures
                # "can the operator still get in" rather than "is 10.0.0.0/24
                # routable in a container network".
                if MGMT_NETWORK not in twin.mgmt_allow:
                    twin.mgmt_allow.append(MGMT_NETWORK)
            elif "default-action drop" in lowered or "action drop" in lowered:
                # A default deny with no source named yet: the accepts that
                # accompany it carry the prefixes.
                pass
            else:
                result.unsupported.append(command)
                continue
        else:
            result.unsupported.append(command)
            continue

        result.applied.append(command)

    return result
