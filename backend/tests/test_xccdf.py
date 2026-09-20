"""Importing DISA STIGs, against two real published benchmarks.

The fixtures are unmodified DISA files: BIND 9 v4r1.16 (XCCDF 1.1, 2014, no
CCIs) and Mozilla Firefox v5r1 (2021, with CCIs and SRG ids). Testing against
real benchmarks rather than a hand-written sample is the point: the format
has quirks, and a sample we wrote would only prove we can read our own writing.
"""

from __future__ import annotations

import pytest
from conftest import RULES, TESTS

from crucible.common.errors import RuleError
from crucible.policy.ruleset import load_rules
from crucible.policy.xccdf import (
    import_benchmark,
    load_benchmark,
    load_bindings,
    parse_benchmark,
)

XCCDF = TESTS / "fixtures" / "xccdf"
BIND = XCCDF / "U_BIND_9_V4R1_16_Manual-xccdf.xml"
FIREFOX = XCCDF / "U_MOZ_Firefox_V5R1_Manual-xccdf.xml"


def test_an_xccdf_1_1_benchmark_parses_whole():
    benchmark = load_benchmark(BIND)
    assert benchmark.id == "BIND_DNS"
    assert benchmark.version == "4"
    assert "1.17" in benchmark.release
    assert len(benchmark.controls) == 51
    assert benchmark.by_severity() == {"critical": 5, "medium": 26, "low": 20}


def test_a_control_keeps_its_identifiers_and_its_discussion():
    control = next(c for c in load_benchmark(BIND).controls if c.stig_id == "DNS4440")
    assert control.vuln_id == "V-3617"
    assert control.rule_id == "SV-3617r1_rule"
    assert control.severity == "low"
    assert control.discussion.startswith("If an intruder gains control of named")
    assert "<VulnDiscussion>" not in control.discussion
    assert control.fix_text


def test_ccis_and_srg_ids_are_read_from_a_modern_benchmark():
    benchmark = load_benchmark(FIREFOX)
    assert len(benchmark.controls) == 27
    control = next(c for c in benchmark.controls if c.stig_id == "DTBF003")
    assert control.ccis == ("CCI-000366",)
    assert control.srg == "SRG-APP-000516"
    assert control.severity == "critical"  # DISA CAT I


def test_without_a_binding_nothing_is_evaluated():
    """The honest default: a prose check is not a machine check."""
    result = import_benchmark(load_benchmark(FIREFOX))
    assert result.machine_checkable == 0
    assert result.manual == 27
    assert all(c["status"].startswith("manual review") for c in result.catalogue)
    assert "27 controls, 0 machine-checkable" in result.summary()


def test_a_bound_control_becomes_a_rule_the_engine_can_load():
    result = import_benchmark(
        load_benchmark(BIND),
        load_bindings(XCCDF / "bindings-mechanism.yaml"),
        reference_rules=load_rules(RULES),
    )
    assert result.machine_checkable == 2
    assert result.manual == 49

    ruleset = load_rules_from_text(result.rules_yaml())
    ids = {rule.id for rule in ruleset}
    assert ids == {"STIG-DNS0440", "STIG-DNS0485"}

    logging_rule = next(r for r in ruleset if r.id == "STIG-DNS0485")
    assert "STIG:DNS0485" in logging_rule.frameworks
    assert "STIG-VULN:V-4488" in logging_rule.frameworks
    assert "NIST-SP800-53:AU-4" in logging_rule.frameworks
    # remediation_from reused the CIS rule's per-vendor commands
    assert "cisco_ios" in logging_rule.remediation


def test_an_unbound_control_carries_the_stig_fix_text_as_manual():
    result = import_benchmark(
        load_benchmark(BIND),
        load_bindings(XCCDF / "bindings-mechanism.yaml"),
        reference_rules=load_rules(RULES),
    )
    rule = next(r for r in result.rules if r["id"] == "STIG-DNS0440")
    assert list(rule["remediation"]) == ["manual"]
    assert rule["remediation"]["manual"][0]


def test_the_catalogue_accounts_for_every_control():
    import json

    result = import_benchmark(
        load_benchmark(BIND),
        load_bindings(XCCDF / "bindings-mechanism.yaml"),
        reference_rules=load_rules(RULES),
    )
    catalogue = json.loads(result.catalogue_json())
    assert catalogue["counts"]["controls"] == 51
    assert catalogue["counts"]["machine_checkable"] == 2
    assert catalogue["counts"]["manual"] == 49
    assert len(catalogue["controls"]) == 51
    evaluated = [c for c in catalogue["controls"] if c["bound"]]
    assert {c["crucible_id"] for c in evaluated} == {"STIG-DNS0440", "STIG-DNS0485"}


def test_a_binding_naming_an_unknown_rule_is_an_error():
    bindings = load_bindings(XCCDF / "bindings-mechanism.yaml")
    with pytest.raises(RuleError, match="remediation_from"):
        import_benchmark(load_benchmark(BIND), bindings, reference_rules=[])


def test_a_benchmark_with_a_doctype_is_refused():
    bomb = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE Benchmark [<!ENTITY lol "lol">]>\n'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="x"></Benchmark>'
    )
    with pytest.raises(RuleError, match="document type"):
        parse_benchmark(bomb)


def test_something_that_is_not_a_benchmark_is_refused():
    with pytest.raises(RuleError, match="Benchmark"):
        parse_benchmark('<?xml version="1.0"?><html><body>not a benchmark</body></html>')


def load_rules_from_text(text: str):  # type: ignore[no-untyped-def]
    import tempfile
    from pathlib import Path

    path = Path(tempfile.mkdtemp()) / "imported.yaml"
    path.write_text(text, encoding="utf-8")
    return load_rules(path)


# -- ISO 27001 ------------------------------------------------------------------


def test_every_hand_authored_control_maps_to_iso_27001():
    ruleset = load_rules(RULES)
    for rule in ruleset:
        assert any(f.startswith("ISO27001:A.") for f in rule.frameworks), rule.id


def test_each_framework_selects_the_same_rules_from_one_parse():
    ruleset = load_rules(RULES)
    for framework in ("CIS", "NIST", "STIG", "ISO"):
        assert len(ruleset.for_framework(framework)) == len(ruleset), framework
    assert ruleset.for_framework("PCI").rules == []


def test_no_standard_text_is_reproduced_only_identifiers():
    """Licence line in the README, enforced here."""
    ruleset = load_rules(RULES)
    for rule in ruleset:
        for identifier in rule.frameworks:
            assert len(identifier) < 40, identifier
            assert " " not in identifier, identifier
