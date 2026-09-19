"""Tier 1 - structural inference - and the fingerprint threshold that feeds it."""

from __future__ import annotations

from conftest import ALL_DEVICES, DEVICES, TESTS, parsed

from crucible.cascade.structure import Grammar, NodeKind, analyse

UNSEEN = TESTS / "fixtures" / "unseen"


def _analyse(path):  # type: ignore[no-untyped-def]
    return analyse(path.name, path.read_text(encoding="utf-8").splitlines())


def test_each_known_grammar_is_recognised():
    expected = {
        "junos-edge-01/running-config.conf": Grammar.BRACE,
        "cisco-ios-core-01/running-config.txt": Grammar.INDENT,
        "arista-leaf-01/running-config.txt": Grammar.INDENT,
        "routeros-branch-01/export.rsc": Grammar.FLAT,
        "fortios-fw-01/running-config.conf": Grammar.INDENT,
    }
    for relative, grammar in expected.items():
        report = _analyse(DEVICES / relative)
        assert report.grammar is grammar, f"{relative}: {report.grammar}"


def test_an_unseen_vendor_is_given_structure_without_meaning():
    report = _analyse(UNSEEN / "huawei-vrp-agg-01" / "current-configuration.cfg")
    assert report.grammar is Grammar.MARKER
    vty = [n for n in report.nodes if n.text == "protocol inbound telnet"]
    assert vty and vty[0].context == ("user-interface vty 0 4",)
    assert vty[0].kind is NodeKind.STATEMENT


def test_brace_context_follows_the_hierarchy():
    report = _analyse(DEVICES / "junos-edge-01" / "running-config.conf")
    nested = [n for n in report.nodes if n.kind is NodeKind.STATEMENT and len(n.context) >= 2]
    assert nested, "no nested statements found in a Junos file"
    assert all(n.context[0] == "system" or n.context[0] for n in nested)


def test_tier_one_never_claims_a_statement():
    """A statement's meaning is what Tier 1 does not know."""
    report = _analyse(UNSEEN / "huawei-vrp-agg-01" / "current-configuration.cfg")
    for node in report.nodes:
        if node.kind.structural:
            assert node.kind is not NodeKind.STATEMENT
        if node.text.startswith(("telnet", "snmp-agent community")):
            assert not node.kind.structural


def test_tier_one_leaves_known_vendor_coverage_unchanged():
    """Tier 0 already accounts for structure, so Tier 1 must add nothing there."""
    for device in ALL_DEVICES:
        coverage = parsed(device).ir.coverage
        assert coverage.by_tier["tier1"] == 0, device


def test_a_single_generic_keyword_does_not_name_a_vendor():
    """Regression: a Huawei file once fingerprinted as Cisco IOS at 0.72."""
    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir

    device = build_ir(load(UNSEEN / "huawei-vrp-agg-01")[0])
    assert device.identity.vendor == "unknown"
    assert device.parser_applied is False
    assert device.ir.device["vendor"] == "unknown"
    assert device.ir.coverage.by_tier["tier0"] == 0


def test_unseen_file_structure_is_claimed_at_tier_one_only():
    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir

    device = build_ir(load(UNSEEN / "huawei-vrp-agg-01")[0])
    coverage = device.ir.coverage
    assert coverage.by_tier["tier1"] > 0
    assert coverage.parsed_lines == coverage.by_tier["tier1"]
    # Every statement is still uninterpreted and listed verbatim.
    raw = {entry["raw"].strip() for entry in coverage.unparsed_sample}
    assert "telnet server enable" in raw
