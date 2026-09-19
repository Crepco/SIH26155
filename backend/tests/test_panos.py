"""PAN-OS: XML parsed as XML, with line numbers, and never trusted."""

from __future__ import annotations

import pytest
from conftest import evaluation_for, ir_for, parsed

from crucible.common.errors import ParseError
from crucible.common.types import Verdict

DEVICE = "panos-fw-01"


def test_management_plane_facts_come_from_their_own_lines():
    ir = ir_for(DEVICE)
    telnet = ir.resolve("mgmt.telnet_enabled")
    assert telnet.value is True
    assert telnet.provenance is not None
    assert telnet.provenance.raw.strip() == "<disable-telnet>no</disable-telnet>"
    assert ir.resolve("mgmt.http_enabled").value is True
    assert ir.resolve("mgmt.idle_timeout_min").value == 60
    assert ir.resolve("ntp.authenticated").value is False
    assert ir.resolve("logging.servers").value == ["10.0.0.5"]


def test_the_community_string_is_detected_and_never_kept():
    ir = ir_for(DEVICE)
    assert ir.resolve("snmp.communities").value == ["default"]
    assert ir.resolve("snmp.version").value == 2
    blob = "\n".join(line for lines in ir.sources.values() for line in lines)
    assert "public" not in blob


def test_password_hash_algorithms_are_read_and_digests_are_not_kept():
    ir = ir_for(DEVICE)
    users = {u["name"]: u for u in ir.resolve("aaa.local_users").value}
    assert users["admin"]["privilege"] == 15
    assert ir.resolve("aaa.local_users[0].hash").value == "md5"
    assert ir.resolve("aaa.local_users[1].hash").value == "sha256"
    blob = "\n".join(line for lines in ir.sources.values() for line in lines)
    assert "qzwsbltr" not in blob and "saltsalt" not in blob


def test_zone_policy_counts_as_inbound_filtering():
    """PAN-OS filters by zone; an interface in a zone is not an unfiltered one."""
    interfaces = {i["name"]: i for i in ir_for(DEVICE).resolve("interfaces").value}
    assert interfaces["ethernet1/1"]["acl_in"] == "zone-policy:untrust"
    assert interfaces["ethernet1/1"]["zone"] == "untrust"
    assert interfaces["management"]["is_mgmt"] is True
    assert interfaces["management"]["addresses"] == ["10.0.0.10/24"]


def test_security_rules_this_parser_does_not_read_stay_uninterpreted():
    """Inline containers carry meaning; claiming them as structure would inflate coverage."""
    raw = {e["raw"].strip() for e in ir_for(DEVICE).coverage.unparsed_sample}
    assert "<from><member>trust</member></from>" in raw
    assert "<action>allow</action>" in raw


def test_rules_decide_on_pan_os_exactly_as_on_every_other_vendor():
    verdicts = {f.rule_id: f.verdict for f in evaluation_for(DEVICE).all_results}
    assert verdicts["CIS-NET-1.1.1"] is Verdict.FAIL
    assert verdicts["CIS-NET-2.1.2"] is Verdict.FAIL
    assert verdicts["CIS-NET-6.1.1"] is Verdict.PASS  # zoned interfaces are filtered


def test_the_fingerprint_is_confident():
    identity = parsed(DEVICE).identity
    assert identity.vendor == "paloalto"
    assert identity.confidence >= 0.9


def test_a_document_type_declaration_is_refused():
    """Billion laughs: an untrusted file must never get to expand entities."""
    from crucible.ingest.bundle import DeviceBundle, SourceFile
    from crucible.ir.builder import IRBuilder
    from crucible.parsers.base import ParseContext
    from crucible.parsers.panos import parse_panos

    bomb = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>\n'
        '<config urldb="x"><devices><entry name="localhost.localdomain">'
        "<deviceconfig><system><hostname>&lol2;</hostname></system></deviceconfig>"
        "</entry></devices></config>\n"
    )
    source = SourceFile(name="bomb/running-config.xml", text=bomb)
    bundle = DeviceBundle(device_id="bomb", files=[source])
    builder = IRBuilder()
    builder.register_file(source.name, source.lines)
    with pytest.raises(ParseError, match="DTD"):
        parse_panos(ParseContext(source=bundle.files[0], builder=builder))
