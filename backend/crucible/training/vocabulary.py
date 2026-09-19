"""What each IR field looks like, described from the vendors we already parse.

This is the precedent a Tier-2 proposer is given: for every IR path a pack may
write, a plain description, weighted keywords, and example statements taken
from the grammars of Cisco IOS, Arista EOS, Juniper Junos and Fortinet FortiOS.

**It contains no MikroTik RouterOS and no Huawei VRP syntax.** RouterOS is the
held-out vendor (corpus/MANIFEST.md) and VRP is the unseen-vendor fixture; if
either leaked in here, a proposer that "learned" them would only be recalling
this file. ``tests/test_training.py`` enforces the exclusion, so the transfer
measured on those vendors is real transfer.
"""

from __future__ import annotations

from dataclasses import dataclass

from crucible.ir.paths import PACK_PATHS, Kind

__all__ = ["VOCABULARY", "FieldSpec"]


@dataclass(frozen=True, slots=True)
class FieldSpec:
    path: str
    kind: Kind
    description: str
    #: word -> weight. Words are matched against line tokens and their parts.
    keywords: dict[str, float]
    #: Statements from known vendors that set this field.
    examples: tuple[str, ...]


def _f(path: str, description: str, keywords: dict[str, float], *examples: str) -> FieldSpec:
    return FieldSpec(path, PACK_PATHS[path], description, keywords, examples)


VOCABULARY: tuple[FieldSpec, ...] = (
    # -- management plane --------------------------------------------------
    _f(
        "mgmt.telnet_enabled",
        "Telnet management access is enabled",
        {"telnet": 3.0, "transport": 1.0, "inbound": 0.8, "input": 0.6, "server": 0.4},
        "transport input telnet ssh",
        "ip telnet server",
        "management telnet",
        "services telnet",
        "set admin-telnet enable",
    ),
    _f(
        "mgmt.ssh.enabled",
        "SSH management access is enabled",
        {"ssh": 3.0, "sshd": 2.0, "secure": 0.6, "shell": 0.6, "server": 0.4},
        "ip ssh server enable",
        "management ssh",
        "services ssh",
        "set admin-ssh-port 22",
        "transport input ssh",
    ),
    _f(
        "mgmt.ssh.version",
        "SSH protocol version accepted",
        {"ssh": 1.5, "version": 2.5, "protocol": 1.0, "v2": 1.0, "v1": 1.0},
        "ip ssh version 2",
        "protocol-version v2",
        "set admin-ssh-v1 disable",
    ),
    _f(
        "mgmt.http_enabled",
        "Plaintext HTTP management interface is enabled",
        {"http": 3.0, "web": 1.5, "www": 1.5, "server": 0.6, "gui": 1.0},
        "ip http server",
        "management api http-commands",
        "web-management http",
        "set admin-http-port 80",
    ),
    _f(
        "mgmt.https_enabled",
        "HTTPS management interface is enabled",
        {"https": 3.0, "secure-server": 2.5, "ssl": 1.5, "tls": 1.0},
        "ip http secure-server",
        "web-management https",
        "set admin-https-port 443",
    ),
    _f(
        "mgmt.idle_timeout_min",
        "Idle session timeout for management sessions, in minutes",
        {"timeout": 3.0, "idle": 2.0, "exec": 1.0, "admintimeout": 3.0, "session": 0.6},
        "exec-timeout 10 0",
        "idle-timeout 10",
        "set admintimeout 10",
    ),
    _f(
        "mgmt.login_banner",
        "A login banner is configured",
        {"banner": 3.0, "motd": 2.0, "announcement": 2.0, "login": 0.8, "message": 0.8},
        "banner motd ^C",
        "banner login",
        "announcement Authorised access only",
        "set pre-login-banner enable",
    ),
    _f(
        "mgmt.mgmt_acl",
        "Access list restricting who may reach the management plane",
        {"access-class": 3.0, "trusthost": 3.0, "acl": 1.5, "allowed": 0.8},
        "access-class MGMT in",
        "set trusthost1 10.0.0.0 255.0.0.0",
        "ip access-group MGMT in",
    ),
    _f(
        "mgmt.ssh.max_attempts",
        "Authentication attempts allowed per SSH connection",
        {"retries": 2.5, "attempts": 2.5, "authentication": 1.0, "tries": 2.0},
        "ip ssh authentication-retries 3",
        "set admin-lockout-threshold 3",
    ),
    # -- AAA ----------------------------------------------------------------
    _f(
        "aaa.enabled",
        "Centralised authentication (AAA) is enabled",
        {"aaa": 3.0, "authentication": 1.0, "authentication-order": 2.5, "authorization": 1.0},
        "aaa new-model",
        "authentication-order [ tacplus password ]",
        "aaa authentication login default group tacacs+ local",
    ),
    _f(
        "aaa.servers",
        "A TACACS+ or RADIUS server used for authentication",
        {"tacacs": 3.0, "radius": 3.0, "tacplus": 3.0, "tacacs-server": 3.0, "host": 0.6},
        "tacacs-server host 10.0.0.9",
        "radius-server host 10.0.0.9",
        "tacplus-server 10.0.0.9",
    ),
    _f(
        "aaa.accounting",
        "Command and session accounting is enabled",
        {"accounting": 3.0, "commands": 0.8, "exec": 0.5},
        "aaa accounting exec default start-stop group tacacs+",
        "accounting destination tacplus",
    ),
    _f(
        "aaa.password_policy.min_length",
        "Minimum local password length",
        {"min-length": 3.0, "minimum": 2.0, "length": 2.0, "password": 1.0},
        "security passwords min-length 12",
        "set minimum-length 12",
        "minimum-length 12",
    ),
    # -- SNMP ---------------------------------------------------------------
    _f(
        "snmp.communities",
        "An SNMPv1/v2c community string (stored only as default/custom)",
        {"community": 3.0, "snmp": 1.5, "snmp-server": 1.5, "read": 0.5, "ro": 0.5, "rw": 0.5},
        "snmp-server community public RO",
        "community public authorization read-only",
        "set name public",
    ),
    _f(
        "snmp.version",
        "SNMP protocol version in use",
        {"snmp": 1.5, "version": 2.5, "v3": 1.5, "v2c": 1.5, "v1": 1.0},
        "snmp-server group ADMIN v3 priv",
        "snmp-server host 10.0.0.9 version 2c",
        "set query-v1-status disable",
    ),
    _f(
        "snmp.traps",
        "SNMP trap destinations or trap types",
        {"trap": 3.0, "traps": 3.0, "notification": 1.5},
        "snmp-server enable traps",
        "trap-group monitoring",
    ),
    # -- logging and time ---------------------------------------------------
    _f(
        "logging.servers",
        "A remote syslog server",
        {"syslog": 3.0, "logging": 2.0, "log": 1.5, "host": 0.8, "remote": 1.0},
        "logging host 10.0.0.5",
        "logging server 10.0.0.5",
        "host 10.0.0.5",
        "set server 10.0.0.5",
    ),
    _f(
        "logging.timestamps",
        "Log messages carry timestamps",
        {"timestamps": 3.0, "timestamp": 3.0, "datetime": 1.5, "time-format": 2.0},
        "service timestamps log datetime msec",
        "time-format year",
    ),
    _f(
        "logging.buffered",
        "Local log buffering is enabled",
        {"buffered": 3.0, "buffer": 2.5, "memory": 1.0},
        "logging buffered 64000",
        "logging buffered 32768 informational",
    ),
    _f(
        "logging.level",
        "Severity threshold for remote logging",
        {"severity": 2.0, "level": 2.0, "trap": 1.0, "informational": 1.0, "notice": 1.0},
        "logging trap informational",
        "set severity information",
    ),
    _f(
        "ntp.servers",
        "An NTP time server",
        {"ntp": 3.0, "ntp-server": 3.0, "server": 0.8, "time": 0.8, "peer": 0.5},
        "ntp server 10.0.0.1",
        "ntpserver 10.0.0.1",
        "set server 10.0.0.1",
        "server 10.0.0.1 prefer",
    ),
    _f(
        "ntp.authenticated",
        "NTP authentication is enforced",
        {"ntp": 1.5, "authenticate": 3.0, "authentication": 2.5, "authentication-key": 2.5},
        "ntp authenticate",
        "ntp authentication-key 1 md5 KEY",
        "set authentication enable",
    ),
    _f(
        "ntp.source",
        "Source interface for NTP traffic",
        {"ntp": 2.0, "source": 3.0},
        "ntp source Loopback0",
        "ntp source Vlan10",
    ),
    # -- routing and services -----------------------------------------------
    _f(
        "routing.neighbour_authentication",
        "Routing protocol neighbours authenticate",
        {"neighbor": 1.5, "authentication-key": 2.5, "md5": 2.5, "password": 1.0},
        "neighbor 10.0.0.1 password KEY",
        "authentication-key KEY",
        "ip ospf message-digest-key 1 md5 KEY",
    ),
    _f(
        "services.discovery_protocols",
        "CDP or LLDP neighbour discovery is enabled",
        {"cdp": 3.0, "lldp": 3.0, "discovery": 1.5, "neighbor": 0.5},
        "cdp run",
        "lldp run",
        "protocols lldp",
    ),
    _f(
        "services.source_routing",
        "IP source routing is permitted",
        {"source-route": 3.0, "source": 1.0, "route": 0.8},
        "ip source-route",
        "set source-route enable",
    ),
    _f(
        "services.proxy_arp",
        "Proxy ARP is enabled",
        {"proxy-arp": 3.0, "proxy": 2.0, "arp": 2.0},
        "ip proxy-arp",
        "proxy-arp",
    ),
    # -- identity -----------------------------------------------------------
    _f(
        "device.hostname",
        "The device hostname",
        {"hostname": 3.0, "host-name": 3.0, "name": 0.6, "system": 0.4},
        "hostname core-sw-01",
        "host-name edge-01",
        "set hostname fw-01",
    ),
)
