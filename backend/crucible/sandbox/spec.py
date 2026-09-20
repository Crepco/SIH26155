"""The twin specification: the security properties of a device, renderable.

The IR is vendor-neutral, so a twin is built from the IR and not from any
vendor's configuration. What a twin models is deliberately small - the
management-plane properties that a probe can actually test:

=========================  ==========================================
IR                         twin
=========================  ==========================================
mgmt.telnet_enabled        telnetd listening, or not
mgmt.ssh.enabled / kex     sshd with those algorithms offered
mgmt.http_enabled          an http server on 80
snmp.communities           snmpd answering that community
mgmt.mgmt_acl              packet filter permitting only the mgmt net
=========================  ==========================================

Everything else is listed in :meth:`TwinSpec.unsupported` and the findings that
depend on it stay ASSERTED. A property the twin cannot model is never quietly
demonstrated, and never quietly dismissed either: it is named.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from crucible.ir.model import IRDocument

__all__ = ["TwinSpec", "spec_from_ir"]

#: Algorithms a probe should find only on a device that has not been hardened.
WEAK_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1")
WEAK_CIPHERS = ("3des-cbc", "aes128-cbc")
STRONG_KEX = ("curve25519-sha256", "diffie-hellman-group14-sha256")
STRONG_CIPHERS = ("chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com")

#: The segment the twin's management interface sits in, inside the sandbox.
MGMT_NETWORK = "10.90.0.0/24"


@dataclass(slots=True)
class TwinSpec:
    """What to boot. Data only: the harness renders it, nothing here executes."""

    device_id: str
    hostname: str = "twin"
    telnet: bool = False
    ssh: bool = True
    ssh_kex: list[str] = field(default_factory=lambda: list(STRONG_KEX))
    ssh_ciphers: list[str] = field(default_factory=lambda: list(STRONG_CIPHERS))
    http: bool = False
    snmp_communities: list[str] = field(default_factory=list)
    #: Source prefixes permitted to reach the management services. Empty means
    #: no restriction at all, which is what "no management ACL" looks like.
    mgmt_allow: list[str] = field(default_factory=list)
    #: IR paths the twin could not model, with why.
    not_modelled: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "telnet": self.telnet,
            "ssh": self.ssh,
            "ssh_kex": list(self.ssh_kex),
            "ssh_ciphers": list(self.ssh_ciphers),
            "http": self.http,
            "snmp_communities": list(self.snmp_communities),
            "mgmt_allow": list(self.mgmt_allow),
        }

    def copy(self) -> TwinSpec:
        return TwinSpec(**{**self.to_dict(), "not_modelled": dict(self.not_modelled)})

    def unsupported(self) -> dict[str, str]:
        return dict(self.not_modelled)


def spec_from_ir(ir: IRDocument, device_id: str) -> TwinSpec:
    """Render the IR into something bootable.

    Only what the IR actually says. A field the IR never recorded leaves the
    twin at its safe default and is listed as not modelled, so a probe that
    finds nothing there proves nothing and says so.
    """
    spec = TwinSpec(device_id=device_id, hostname=str(ir.device.get("hostname") or device_id))

    telnet = ir.resolve("mgmt.telnet_enabled")
    if telnet.known:
        spec.telnet = bool(telnet.value)
    else:
        spec.not_modelled["mgmt.telnet_enabled"] = "the configuration never says"

    ssh = ir.resolve("mgmt.ssh.enabled")
    spec.ssh = bool(ssh.value) if ssh.known else True

    kex = ir.resolve("mgmt.ssh.kex")
    if kex.known and kex.value:
        spec.ssh_kex = [str(algorithm) for algorithm in kex.value]
    else:
        # Nothing is known about the algorithms, so the twin offers the
        # platform default. A weak-algorithm probe against this twin can
        # therefore only ever return "not demonstrated".
        spec.not_modelled["mgmt.ssh.kex"] = "no algorithms in the configuration"

    ciphers = ir.resolve("mgmt.ssh.ciphers")
    if ciphers.known and ciphers.value:
        spec.ssh_ciphers = [str(algorithm) for algorithm in ciphers.value]

    http = ir.resolve("mgmt.http_enabled")
    if http.known:
        spec.http = bool(http.value)
    else:
        spec.not_modelled["mgmt.http_enabled"] = "the configuration never says"

    communities = ir.resolve("snmp.communities")
    if communities.known and communities.value:
        # The IR stores a marker, never the string. A "default" marker means a
        # well-known community, and the twin uses the canonical one so the
        # probe tests the real property rather than a string we invented.
        spec.snmp_communities = [
            "public" if marker == "default" else f"custom-{index}"
            for index, marker in enumerate(communities.value)
        ]

    acl = ir.resolve("mgmt.mgmt_acl")
    if acl.known and acl.value:
        spec.mgmt_allow = [MGMT_NETWORK]

    for path, reason in (
        ("mgmt.idle_timeout_min", "a session timeout is not observable in a 15-second run"),
        ("ntp.authenticated", "NTP authentication needs a peer the sandbox does not provide"),
        ("aaa.local_users", "credential hashing is a static property with no runtime probe"),
    ):
        spec.not_modelled[path] = reason

    return spec
