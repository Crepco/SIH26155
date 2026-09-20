"""The probes: what turns an assertion into a demonstration.

Each one connects to a twin and reports what came back. They are written
against the wire format rather than shelling out to nmap, ssh or snmpwalk, for
three reasons: the offline bundle stays small, the sandbox image needs nothing
but Python, and the *response bytes* are the proof artefact - a tool's summary
of them is not.

Every probe returns a :class:`ProbeResult` carrying the request, the response
and how long it took. That object is what gets attached to a finding and
hashed into the ledger, so a reader can see the evidence rather than trust the
verdict.

No probe ever runs against anything but a twin on a sandbox network. The
harness passes the address; nothing here discovers targets.
"""

from __future__ import annotations

import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "PROBES",
    "ProbeResult",
    "http_mgmt_exposed",
    "run_probe",
    "snmp_default_community",
    "ssh_weak_kex",
    "telnet_reachable",
]

DEFAULT_TIMEOUT = 4.0

#: Key exchange algorithms and ciphers that make an SSH session attackable.
WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "rsa1024-sha1",
}
WEAK_CIPHERS = {
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
}


@dataclass(slots=True)
class ProbeResult:
    """What a probe did, and what came back."""

    probe: str
    target: str
    port: int
    confirmed: bool
    detail: str
    request: str = ""
    response: str = ""
    duration_ms: int = 0
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe": self.probe,
            "target": self.target,
            "port": self.port,
            "confirmed": self.confirmed,
            "detail": self.detail,
            "request": self.request,
            "response": self.response[:600],
            "duration_ms": self.duration_ms,
            "error": self.error,
            **({"extra": self.extra} if self.extra else {}),
        }


def _readable(data: bytes, limit: int = 300) -> str:
    window = data[:limit]
    printable = sum(1 for byte in window if 32 <= byte < 127 or byte in (9, 10, 13))
    if window and printable / len(window) < 0.8:
        # A Telnet option negotiation is not text. Replacement characters in a
        # report are worse than useless; hex is what a reader can check.
        return "hex " + window[:64].hex(" ")
    return "".join(chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "." for byte in window)


def _timed(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


# -- telnet --------------------------------------------------------------------


def telnet_reachable(host: str, port: int = 23, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Does anything answer on the Telnet port, and what does it say?

    A connection that is accepted is the finding: Telnet negotiates in
    cleartext, so anyone on the path has the credentials that follow.
    """
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(256)
            except TimeoutError:
                banner = b""
        return ProbeResult(
            probe="telnet_reachable",
            target=host,
            port=port,
            confirmed=True,
            detail="the port accepted a connection"
            + (" and sent a banner" if banner else " (no banner within the timeout)"),
            request=f"TCP connect {host}:{port}",
            response=_readable(banner) if banner else "<connected, no banner>",
            duration_ms=_timed(start),
        )
    except OSError as exc:
        return ProbeResult(
            probe="telnet_reachable",
            target=host,
            port=port,
            confirmed=False,
            detail="the connection was refused or timed out",
            request=f"TCP connect {host}:{port}",
            duration_ms=_timed(start),
            error=str(exc),
        )


# -- ssh -----------------------------------------------------------------------


def _read_line(sock: socket.socket, limit: int = 512) -> bytes:
    data = b""
    while b"\n" not in data and len(data) < limit:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def _name_lists(payload: bytes, count: int = 2) -> list[list[str]]:
    """Read the first ``count`` name-lists out of an SSH_MSG_KEXINIT payload."""
    offset = 17  # message code (1) + cookie (16)
    lists: list[list[str]] = []
    for _ in range(count):
        if offset + 4 > len(payload):
            break
        (length,) = struct.unpack(">I", payload[offset : offset + 4])
        offset += 4
        raw = payload[offset : offset + length].decode("ascii", errors="replace")
        offset += length
        lists.append([name for name in raw.split(",") if name])
    return lists


def ssh_weak_kex(host: str, port: int = 22, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Ask the server what it will negotiate, and look for the weak entries.

    The server announces its algorithms before any authentication, so this
    needs no credential: read the banner, send ours, read SSH_MSG_KEXINIT.
    """
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = _read_line(sock).strip()
            sock.sendall(b"SSH-2.0-Crucible_probe\r\n")
            header = sock.recv(4)
            if len(header) < 4:
                raise OSError("no key exchange packet")
            (packet_length,) = struct.unpack(">I", header)
            body = b""
            while len(body) < packet_length and len(body) < 65536:
                chunk = sock.recv(min(4096, packet_length - len(body)))
                if not chunk:
                    break
                body += chunk
            padding = body[0]
            payload = body[1 : len(body) - padding]

        if not payload or payload[0] != 20:  # SSH_MSG_KEXINIT
            raise OSError("the server did not send SSH_MSG_KEXINIT")

        kex, host_keys = [*_name_lists(payload, 2), [], []][:2]
        del host_keys
        ciphers = [*_name_lists(payload, 3), [], [], []][2]
        weak_kex = sorted(set(kex) & WEAK_KEX)
        weak_ciphers = sorted(set(ciphers) & WEAK_CIPHERS)
        confirmed = bool(weak_kex or weak_ciphers)
        return ProbeResult(
            probe="weak_ssh_kex",
            target=host,
            port=port,
            confirmed=confirmed,
            detail=(
                "the server offers " + ", ".join(weak_kex + weak_ciphers)
                if confirmed
                else "no weak key exchange or cipher was offered"
            ),
            request="SSH-2.0-Crucible_probe, then read SSH_MSG_KEXINIT",
            response=f"{banner.decode('ascii', 'replace')} | kex: {','.join(kex[:6])}",
            duration_ms=_timed(start),
            extra={"weak_kex": weak_kex, "weak_ciphers": weak_ciphers, "offered_kex": kex},
        )
    except OSError as exc:
        return ProbeResult(
            probe="weak_ssh_kex",
            target=host,
            port=port,
            confirmed=False,
            detail="no SSH service answered",
            request=f"TCP connect {host}:{port}",
            duration_ms=_timed(start),
            error=str(exc),
        )


# -- http ------------------------------------------------------------------------


def http_mgmt_exposed(host: str, port: int = 80, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Is there a plaintext management interface listening?"""
    start = time.monotonic()
    request = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: crucible-probe\r\n\r\n"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request.encode("ascii"))
            response = sock.recv(512)
        status = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        return ProbeResult(
            probe="http_mgmt_exposed",
            target=host,
            port=port,
            confirmed=bool(response),
            detail=f"answered in cleartext: {status}" if response else "no response",
            request=request.strip().replace("\r\n", " | "),
            response=_readable(response),
            duration_ms=_timed(start),
        )
    except OSError as exc:
        return ProbeResult(
            probe="http_mgmt_exposed",
            target=host,
            port=port,
            confirmed=False,
            detail="the connection was refused or timed out",
            request=f"TCP connect {host}:{port}",
            duration_ms=_timed(start),
            error=str(exc),
        )


# -- snmp -------------------------------------------------------------------------


def _ber(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def _integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return _ber(0x02, raw)


def snmp_get_request(community: str, request_id: int = 0x43727563) -> bytes:
    """A SNMPv2c GetRequest for sysDescr.0, encoded by hand."""
    oid = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])  # 1.3.6.1.2.1.1.1.0
    varbind = _ber(0x30, oid + bytes([0x05, 0x00]))
    varbinds = _ber(0x30, varbind)
    pdu = _ber(0xA0, _integer(request_id) + _integer(0) + _integer(0) + varbinds)
    return _ber(0x30, _integer(1) + _ber(0x04, community.encode()) + pdu)


def snmp_default_community(
    host: str,
    port: int = 161,
    community: str = "public",
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult:
    """Does the device answer a well-known community string?

    A reply is the whole finding: an unauthenticated reader has the device's
    description, and usually its interfaces and ACL names too.
    """
    start = time.monotonic()
    request = snmp_get_request(community)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request, (host, port))
        data, _peer = sock.recvfrom(2048)
        # A response PDU (0xA2) means the community was accepted.
        confirmed = 0xA2 in data[:64]
        return ProbeResult(
            probe="default_snmp_community",
            target=host,
            port=port,
            confirmed=confirmed,
            detail=(
                f"the device answered the community {community!r}"
                if confirmed
                else "a datagram came back but not a GetResponse"
            ),
            request=f"SNMPv2c GetRequest sysDescr.0 community={community}",
            response=_readable(data),
            duration_ms=_timed(start),
        )
    except OSError as exc:
        return ProbeResult(
            probe="default_snmp_community",
            target=host,
            port=port,
            confirmed=False,
            detail="no answer to the community",
            request=f"SNMPv2c GetRequest sysDescr.0 community={community}",
            duration_ms=_timed(start),
            error=str(exc),
        )
    finally:
        sock.close()


# -- reachability from somewhere it should not be ------------------------------------


def acl_bypass(host: str, port: int = 22, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Can the management plane be reached from the untrusted segment at all?

    Run from a prober that sits outside the management network. A completed
    handshake means no filter stood in the way.
    """
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(1.0)
            try:
                greeting = sock.recv(128)
            except (TimeoutError, OSError):
                greeting = b""
        return ProbeResult(
            probe="acl_bypass",
            target=host,
            port=port,
            confirmed=True,
            detail="a host on the untrusted segment reached the management service",
            request=f"TCP connect {host}:{port} from the untrusted segment",
            response=_readable(greeting) if greeting else "<connected>",
            duration_ms=_timed(start),
        )
    except OSError as exc:
        return ProbeResult(
            probe="acl_bypass",
            target=host,
            port=port,
            confirmed=False,
            detail="the untrusted segment could not reach the management service",
            request=f"TCP connect {host}:{port} from the untrusted segment",
            duration_ms=_timed(start),
            error=str(exc),
        )


#: probe name -> (function, default port). The names are the ones rules use in
#: their ``verify.probe`` field; a rule naming anything else is not verifiable.
PROBES: dict[str, tuple[Callable[..., ProbeResult], int]] = {
    "telnet_reachable": (telnet_reachable, 23),
    "weak_ssh_kex": (ssh_weak_kex, 22),
    "http_mgmt_exposed": (http_mgmt_exposed, 80),
    "default_snmp_community": (snmp_default_community, 161),
    "acl_bypass": (acl_bypass, 22),
}


def run_probe(name: str, host: str, port: int | None = None, **kwargs: Any) -> ProbeResult:
    entry = PROBES.get(name)
    if entry is None:
        return ProbeResult(
            probe=name,
            target=host,
            port=port or 0,
            confirmed=False,
            detail="no such probe: this finding cannot be demonstrated",
            error="unknown probe",
        )
    function, default_port = entry
    return function(host, port or default_port, **kwargs)
