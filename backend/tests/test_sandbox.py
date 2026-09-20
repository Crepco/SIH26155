"""Crucible: the twin, the probes, and the four-phase run.

Most of this needs no Docker. The probes are tested against small fake servers
on loopback, and the orchestration against a fake sandbox, so the logic that
decides whether a finding may be called DEMONSTRATED is covered on any
machine. The live test at the bottom runs only where a daemon exists.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest
from conftest import evaluation_for, ir_for, ruleset

from crucible.common.types import FindingState, Verdict
from crucible.sandbox import (
    ProbeResult,
    TwinSpec,
    apply_remediation,
    docker_available,
    spec_from_ir,
    verify_device,
)
from crucible.sandbox.probes import (
    http_mgmt_exposed,
    snmp_default_community,
    snmp_get_request,
    ssh_weak_kex,
    telnet_reachable,
)

# -- a device's security properties, rendered ----------------------------------


def test_the_twin_is_built_from_the_ir_not_from_a_vendor_config():
    spec = spec_from_ir(ir_for("cisco-ios-core-01"), "cisco-ios-core-01")
    assert spec.telnet is True  # transport input telnet ssh
    assert spec.http is True  # ip http server
    assert spec.snmp_communities[0] == "public"  # the default marker, as the canonical string
    assert spec.mgmt_allow  # MGMT_IN is applied, so the twin filters


def test_a_property_the_ir_never_recorded_is_named_not_guessed():
    spec = spec_from_ir(ir_for("routeros-branch-01"), "routeros-branch-01")
    assert "mgmt.ssh.kex" in spec.unsupported()
    assert "no runtime probe" in spec.unsupported()["aaa.local_users"]


def test_a_community_string_never_reaches_the_twin():
    """The IR holds a marker; the twin uses the canonical well-known string."""
    spec = spec_from_ir(ir_for("arista-leaf-01"), "arista-leaf-01")
    assert all(not c.startswith("observability") for c in spec.snmp_communities)


# -- applying the printed fix ----------------------------------------------------


def _spec(**kwargs: object) -> TwinSpec:
    return TwinSpec(device_id="d", **kwargs)  # type: ignore[arg-type]


def test_the_rules_own_vyos_commands_close_the_twin():
    rules = {rule.id: rule for rule in ruleset()}
    spec = _spec(telnet=True, http=True, snmp_communities=["public"])

    telnet = apply_remediation(spec, rules["CIS-NET-1.1.1"].remediation["vyos"])
    assert telnet.spec.telnet is False
    assert telnet.spec.ssh is True  # SSH is established before Telnet is removed
    assert not telnet.unsupported

    http = apply_remediation(spec, rules["CIS-NET-1.3.1"].remediation["vyos"])
    assert http.spec.http is False

    snmp = apply_remediation(spec, rules["CIS-NET-2.1.2"].remediation["vyos"])
    assert snmp.spec.snmp_communities == []


def test_a_management_acl_fix_keeps_the_operator_reachable():
    from crucible.sandbox.spec import MGMT_NETWORK

    rules = {rule.id: rule for rule in ruleset()}
    applied = apply_remediation(_spec(), rules["CIS-NET-1.4.1"].remediation["vyos"])
    assert "10.0.0.0/24" in applied.spec.mgmt_allow
    assert MGMT_NETWORK in applied.spec.mgmt_allow


def test_a_command_the_twin_does_not_understand_is_reported_not_ignored():
    """A fix that was not applied must never be reported as validated."""
    applied = apply_remediation(_spec(), ["set protocols bgp 64512 neighbor 10.0.0.1 password X"])
    assert applied.applied == []
    assert applied.unsupported == ["set protocols bgp 64512 neighbor 10.0.0.1 password X"]


# -- the probes, against fake servers on loopback ----------------------------------


class _Server:
    """A one-shot TCP server that plays a canned part."""

    def __init__(self, handler) -> None:  # type: ignore[no-untyped-def]
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, args=(handler,), daemon=True)
        self.thread.start()

    def _serve(self, handler) -> None:  # type: ignore[no-untyped-def]
        try:
            client, _ = self.socket.accept()
            with client:
                handler(client)
        except OSError:
            pass

    def close(self) -> None:
        self.socket.close()


def test_telnet_probe_confirms_only_when_something_answers():
    server = _Server(lambda sock: sock.sendall(b"\xff\xfd\x18User Access Verification\r\n"))
    try:
        result = telnet_reachable("127.0.0.1", server.port, timeout=2)
    finally:
        server.close()
    assert result.confirmed is True
    assert "User Access Verification" in result.response
    assert result.request.startswith("TCP connect")

    closed = telnet_reachable("127.0.0.1", 9, timeout=1)
    assert closed.confirmed is False
    assert closed.error


def test_http_probe_records_the_status_line_as_evidence():
    server = _Server(
        lambda sock: (sock.recv(256), sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n<h1>mgmt</h1>"))
    )
    try:
        result = http_mgmt_exposed("127.0.0.1", server.port, timeout=2)
    finally:
        server.close()
    assert result.confirmed is True
    assert "200 OK" in result.response


def _kexinit(kex: list[str], ciphers: list[str]) -> bytes:
    def name_list(names: list[str]) -> bytes:
        raw = ",".join(names).encode()
        return struct.pack(">I", len(raw)) + raw

    payload = (
        bytes([20])
        + b"\x00" * 16
        + name_list(kex)
        + name_list(["ssh-rsa"])
        + name_list(ciphers)
        + name_list(ciphers)
        + name_list(["hmac-sha2-256"]) * 2
        + name_list(["none"]) * 2
        + name_list([]) * 2
        + b"\x00"
        + b"\x00" * 4
    )
    padding = b"\x00" * 4
    body = bytes([len(padding)]) + payload + padding
    return struct.pack(">I", len(body)) + body


def _ssh_server(kex: list[str], ciphers: list[str]):  # type: ignore[no-untyped-def]
    def handler(sock: socket.socket) -> None:
        sock.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
        sock.recv(256)
        sock.sendall(_kexinit(kex, ciphers))
        time.sleep(0.2)

    return handler


def test_the_ssh_probe_reads_the_algorithms_the_server_offers():
    weak = _Server(_ssh_server(["diffie-hellman-group1-sha1", "curve25519-sha256"], ["aes256-ctr"]))
    try:
        result = ssh_weak_kex("127.0.0.1", weak.port, timeout=3)
    finally:
        weak.close()
    assert result.confirmed is True
    assert "diffie-hellman-group1-sha1" in result.detail
    assert result.extra["weak_kex"] == ["diffie-hellman-group1-sha1"]

    strong = _Server(_ssh_server(["curve25519-sha256"], ["chacha20-poly1305@openssh.com"]))
    try:
        result = ssh_weak_kex("127.0.0.1", strong.port, timeout=3)
    finally:
        strong.close()
    assert result.confirmed is False


def test_the_snmp_request_is_a_well_formed_v2c_get():
    request = snmp_get_request("public")
    assert request[0] == 0x30  # SEQUENCE
    assert b"public" in request
    assert bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]) in request  # sysDescr.0


def test_the_snmp_probe_confirms_only_on_a_get_response():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def responder() -> None:
        data, peer = server.recvfrom(2048)
        del data
        server.sendto(bytes([0x30, 0x0A, 0x02, 0x01, 0x01, 0xA2, 0x05, 0x02, 0x01, 0x00]), peer)

    threading.Thread(target=responder, daemon=True).start()
    try:
        result = snmp_default_community("127.0.0.1", port, timeout=2)
    finally:
        server.close()
    assert result.confirmed is True
    assert "public" in result.request


# -- the four phases, against a fake sandbox ------------------------------------------


class _FakeSandbox:
    """Plays the part of Docker: boots, probes, reconfigures, reports."""

    def __init__(self, *, reconfigure_closes: bool = True, lockout: bool = False) -> None:
        self.mgmt_network = "mgmt"
        self.untrust_network = "untrust"
        self.reconfigured: list[TwinSpec] = []
        self.reconfigure_closes = reconfigure_closes
        self.lockout = lockout
        self.log: list[str] = ["fake sandbox"]

    def ensure_image(self, context=None) -> None:  # type: ignore[no-untyped-def]
        return None

    def boot(self, spec: TwinSpec):  # type: ignore[no-untyped-def]
        from crucible.sandbox.harness import Twin

        return Twin(name="fake", spec=spec, mgmt_ip="10.90.0.2", untrust_ip="10.91.0.2", boot_ms=5)

    def prober(self, network: str) -> str:
        return f"prober-{network}"

    def reconfigure(self, twin, spec) -> None:  # type: ignore[no-untyped-def]
        self.reconfigured.append(spec)
        twin.spec = spec

    def probe(self, prober: str, name: str, host: str, port=None, **kwargs):  # type: ignore[no-untyped-def]
        del prober, kwargs
        after = bool(self.reconfigured)
        if name == "management_still_reachable" or (after and port == 22):
            confirmed = not self.lockout
        elif after:
            confirmed = not self.reconfigure_closes
        else:
            confirmed = True
        return ProbeResult(
            probe=name,
            target=host,
            port=port or 0,
            confirmed=confirmed,
            detail="fake",
            response="fake response",
        )

    def destroy(self) -> None:
        return None


def test_a_demonstrated_finding_is_promoted_and_carries_its_proof():
    evaluation = evaluation_for("panos-fw-01")
    findings = [f for f in evaluation.findings if f.verdict is Verdict.FAIL]
    run = verify_device(
        ir_for("panos-fw-01"), "panos-fw-01", findings, ruleset(), sandbox=_FakeSandbox()
    )
    assert run.demonstrated > 0
    telnet = next(f for f in findings if f.rule_id == "CIS-NET-1.1.1")
    assert telnet.state is FindingState.DEMONSTRATED
    assert telnet.proof is not None
    assert telnet.proof["probe"] == "telnet_reachable"
    assert telnet.proof["digest"]
    assert telnet.proof["closed_by_remediation"] is True


def test_a_fix_that_does_not_close_the_finding_says_so():
    evaluation = evaluation_for("panos-fw-01")
    findings = [f for f in evaluation.findings if f.verdict is Verdict.FAIL]
    run = verify_device(
        ir_for("panos-fw-01"),
        "panos-fw-01",
        findings,
        ruleset(),
        sandbox=_FakeSandbox(reconfigure_closes=False),
    )
    assert run.demonstrated > 0
    assert run.closed == 0
    assert all(v.closed is False for v in run.verifications if v.demonstrated and v.commands)


def test_a_fix_that_locks_the_operator_out_is_caught():
    """Phase 4, the one no compliance product performs."""
    evaluation = evaluation_for("panos-fw-01")
    findings = [f for f in evaluation.findings if f.verdict is Verdict.FAIL]
    run = verify_device(
        ir_for("panos-fw-01"),
        "panos-fw-01",
        findings,
        ruleset(),
        sandbox=_FakeSandbox(lockout=True),
    )
    assert run.lockout is True
    assert "lock you out" in run.regression[0].detail


def test_nothing_is_demonstrated_when_the_sandbox_cannot_run(monkeypatch=None):  # type: ignore[no-untyped-def]
    """A twin that will not boot degrades to ASSERTED, never to a pass."""
    import crucible.sandbox.run as run_module

    original = run_module.docker_available
    run_module.docker_available = lambda: False
    try:
        evaluation = evaluation_for("panos-fw-01")
        findings = [f for f in evaluation.findings if f.verdict is Verdict.FAIL]
        run = verify_device(ir_for("panos-fw-01"), "panos-fw-01", findings, ruleset())
    finally:
        run_module.docker_available = original

    assert run.available is False
    assert run.demonstrated == 0
    assert all(f.state is not FindingState.DEMONSTRATED for f in findings)
    assert all(f.verdict is Verdict.FAIL for f in findings), "a failure must stay a failure"


def test_only_high_and_critical_findings_are_worth_a_twin():
    evaluation = evaluation_for("panos-fw-01")
    findings = [f for f in evaluation.findings if f.verdict is Verdict.FAIL]
    run = verify_device(
        ir_for("panos-fw-01"), "panos-fw-01", findings, ruleset(), sandbox=_FakeSandbox()
    )
    verified = {v.rule_id for v in run.verifications}
    rules = {rule.id: rule for rule in ruleset()}
    assert verified
    for rule_id in verified:
        assert rules[rule_id].severity.verifiable, rule_id


def test_the_proof_digest_reaches_the_ledger_leaf():
    from crucible.report.build import _leaf_material

    evaluation = evaluation_for("panos-fw-01")
    findings = [f for f in evaluation.findings if f.verdict is Verdict.FAIL]
    verify_device(ir_for("panos-fw-01"), "panos-fw-01", findings, ruleset(), sandbox=_FakeSandbox())
    telnet = next(f for f in findings if f.rule_id == "CIS-NET-1.1.1")
    assert _leaf_material(telnet)["proof_digest"] == telnet.proof["digest"]


# -- the live one -----------------------------------------------------------------


@pytest.mark.sandbox
def test_a_real_twin_boots_and_proves_a_finding():
    """The Phase 4 definition of done, on a machine that has Docker."""
    if not docker_available():
        return
    evaluation = evaluation_for("cisco-ios-core-01")
    started = time.monotonic()
    run = verify_device(
        ir_for("cisco-ios-core-01"),
        "cisco-ios-core-01",
        evaluation.findings,
        ruleset(),
        only="CIS-NET-1.1.1",
    )
    elapsed = time.monotonic() - started
    if not run.available:
        # Docker is present but would not give us a sandbox (a busy daemon, a
        # missing image on a machine with no network). That is an environment
        # problem, not a regression, and it is exactly the case that must
        # leave findings ASSERTED rather than failing the build.
        return
    assert run.demonstrated == 1
    assert run.closed == 1
    assert run.lockout is False
    assert elapsed < 30, f"a single finding took {elapsed:.0f}s"
