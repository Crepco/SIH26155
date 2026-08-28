"""Multi-vendor consistency - the test that proves the IR is doing its job.

One security intention, five grammars, one set of semantics. If the same control
produces different verdicts on Cisco and Junos for configurations that say the
same thing, the normalisation is wrong and every claim downstream of it is built
on sand.

This is the first item in the validation plan for exactly that reason.
"""

from __future__ import annotations

from conftest import ALL_DEVICES, ir_for, parsed

from crucible.policy.expr import UNKNOWN, compile_expression


def _evaluate(device: str, assertion: str):  # type: ignore[no-untyped-def]
    return compile_expression(assertion).evaluate(ir_for(device))


def test_every_fixture_is_fingerprinted_to_the_expected_vendor():
    expected = {
        "cisco-ios-core-01": ("cisco", "IOS"),
        "arista-leaf-01": ("arista", "EOS"),
        "fortios-fw-01": ("fortinet", "FortiOS"),
        "junos-edge-01": ("juniper", "JUNOS"),
        "routeros-branch-01": ("mikrotik", "RouterOS"),
    }
    for device, (vendor, os_name) in expected.items():
        identity = parsed(device).identity
        assert identity.vendor == vendor, f"{device}: read as {identity.vendor}"
        assert identity.os == os_name
        assert identity.recognised, f"{device}: confidence {identity.confidence} too low"


def test_telnet_semantics_agree_across_vendors():
    """``no ip telnet server`` and ``set admin-telnet enable`` mean the same thing.

    Cisco, FortiOS and RouterOS each leave Telnet reachable in these fixtures and
    each say so in a completely different syntax. Arista disables it. Junos never
    mentions it, which must read as UNKNOWN rather than as either answer.
    """
    assert _evaluate("cisco-ios-core-01", "mgmt.telnet_enabled").value is True
    assert _evaluate("fortios-fw-01", "mgmt.telnet_enabled").value is True
    assert _evaluate("routeros-branch-01", "mgmt.telnet_enabled").value is True
    assert _evaluate("arista-leaf-01", "mgmt.telnet_enabled").value is False
    assert _evaluate("junos-edge-01", "mgmt.telnet_enabled").value is UNKNOWN


def test_idle_timeout_normalises_three_different_spellings():
    """exec-timeout, admintimeout and idle-timeout all become one IR field.

    This single assertion is the argument for the whole architecture: three
    vendors, three vocabularies, one ``mgmt.idle_timeout_min``, and one rule.
    """
    assert _evaluate("cisco-ios-core-01", "mgmt.idle_timeout_min").value == 30
    assert _evaluate("fortios-fw-01", "mgmt.idle_timeout_min").value == 30
    assert _evaluate("junos-edge-01", "mgmt.idle_timeout_min").value == 10
    assert _evaluate("arista-leaf-01", "mgmt.idle_timeout_min").value == 10


def test_one_rule_decides_the_same_way_on_every_vendor_that_states_it():
    """The CIS timeout control, applied unchanged to four grammars."""
    assertion = "mgmt.idle_timeout_min <= 10"
    verdicts = {device: _evaluate(device, assertion).value for device in ALL_DEVICES}

    assert verdicts["cisco-ios-core-01"] is False
    assert verdicts["fortios-fw-01"] is False
    assert verdicts["junos-edge-01"] is True
    assert verdicts["arista-leaf-01"] is True
    # RouterOS has no session timeout setting in the export, so the honest
    # answer is that we do not know - not that it complies.
    assert verdicts["routeros-branch-01"] is UNKNOWN


def test_default_snmp_community_detected_in_four_grammars():
    """``public`` is spelled four ways and detected four times.

    The literal is redacted before storage, so detection happens at parse time
    and the IR carries a marker. A rule can therefore find a default community
    without the community string ever being kept.
    """
    for device in ("cisco-ios-core-01", "fortios-fw-01", "junos-edge-01", "routeros-branch-01"):
        communities = _evaluate(device, "snmp.communities").value
        assert "default" in communities, f"{device}: default community not detected"

    # Arista's fixture uses a non-default community, so the same rule passes.
    assert "default" not in _evaluate("arista-leaf-01", "snmp.communities").value


def test_no_community_string_is_ever_stored():
    """Redaction is not best-effort. The literals must be gone.

    A community string in the IR would end up in a report, a ledger leaf and an
    exported adapter pack - three places it must never reach.
    """
    for device in ALL_DEVICES:
        ir = ir_for(device)
        communities = ir.resolve("snmp.communities")
        if communities.found:
            assert set(communities.value) <= {"default", "custom"}, (
                f"{device}: raw community strings reached the IR"
            )
        blob = "\n".join(p.raw for p in ir.provenance.values())
        for secret in ("public", "s3cr3t-rw", "hunter2", "readonly123"):
            assert secret not in blob, f"{device}: {secret!r} survived redaction into evidence"


def test_logging_server_normalises_across_all_five_vendors():
    """Five grammars, one syslog destination, one IR list."""
    for device in ALL_DEVICES:
        servers = _evaluate(device, "logging.servers").value
        assert servers == ["10.0.0.5"], f"{device}: read syslog servers as {servers}"


def test_interfaces_normalise_to_a_common_shape():
    for device in ALL_DEVICES:
        interfaces = _evaluate(device, "interfaces").value
        assert interfaces, f"{device}: no interfaces parsed"
        for interface in interfaces:
            assert {"name", "addresses", "acl_in", "shutdown"} <= interface.keys()
            assert isinstance(interface["name"], str) and interface["name"]
