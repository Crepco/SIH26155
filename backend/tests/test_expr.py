"""The assertion language, and especially its third truth value."""

from __future__ import annotations

import pytest
from conftest import ir_for

from crucible.common.errors import RuleError
from crucible.common.types import Provenance
from crucible.ir.model import Coverage, IRDocument
from crucible.policy.expr import UNKNOWN, compile_expression


def _ir(sections: dict) -> IRDocument:  # type: ignore[type-arg]
    """A hand-built IR, so logic tests do not depend on any parser."""
    provenance = {}
    for section, values in sections.items():
        if isinstance(values, dict):
            for key in values:
                provenance[f"{section}.{key}"] = Provenance(
                    file="t.cfg", line=1, raw="x", tier=0
                )
    return IRDocument(
        device={"vendor": "test"},
        sections=sections,
        coverage=Coverage(total_lines=1, parsed_lines=1, unparsed_lines=0),
        provenance=provenance,
    )


def _eval(assertion: str, sections: dict):  # type: ignore[type-arg,no-untyped-def]
    return compile_expression(assertion).evaluate(_ir(sections)).value


# -- Kleene logic ----------------------------------------------------------


def test_comparison_with_a_missing_path_is_unknown_not_false():
    """The single most important behaviour in the language.

    ``10 <= 10`` is true, ``30 <= 10`` is false, and ``<missing> <= 10`` is
    neither. Returning false here would report a device as non-compliant on a
    setting nobody ever read; returning true would be worse.
    """
    assert _eval("mgmt.idle_timeout_min <= 10", {"mgmt": {"idle_timeout_min": 10}}) is True
    assert _eval("mgmt.idle_timeout_min <= 10", {"mgmt": {"idle_timeout_min": 30}}) is False
    assert _eval("mgmt.idle_timeout_min <= 10", {"mgmt": {}}) is UNKNOWN


def test_a_parsed_none_is_also_unknown():
    """A field the parser explicitly left empty is still not comparable."""
    assert _eval("mgmt.idle_timeout_min <= 10", {"mgmt": {"idle_timeout_min": None}}) is UNKNOWN


def test_and_short_circuits_on_a_definite_false():
    """One definite false settles a conjunction even beside an unknown.

    Without this, a single unparsed field would drag an otherwise decided
    failure into UNKNOWN, and real violations would disappear from reports.
    """
    sections = {"mgmt": {"telnet_enabled": True}}
    assert _eval("mgmt.telnet_enabled == false and mgmt.http_enabled == false", sections) is False


def test_or_short_circuits_on_a_definite_true():
    sections = {"mgmt": {"telnet_enabled": False}}
    assert _eval("mgmt.telnet_enabled == false or mgmt.http_enabled == false", sections) is True


def test_and_is_unknown_when_neither_side_settles_it():
    assert _eval("mgmt.a == 1 and mgmt.b == 2", {"mgmt": {}}) is UNKNOWN


def test_not_of_unknown_is_unknown():
    assert _eval("not mgmt.telnet_enabled", {"mgmt": {}}) is UNKNOWN


def test_unknown_refuses_to_be_truthy():
    """Guards against a caller accidentally collapsing the third state."""
    with pytest.raises(TypeError):
        bool(UNKNOWN)


# -- defined() -------------------------------------------------------------


def test_defined_distinguishes_absent_field_from_absent_section():
    """A parsed section with a missing field is a finding; an unparsed section is not.

    ``mgmt`` present but without ``mgmt_acl`` means we read the management plane
    and there is no ACL - a real failure. No ``mgmt`` at all means we never read
    it, and claiming a failure would be inventing one.
    """
    assert _eval("defined(mgmt.mgmt_acl)", {"mgmt": {"mgmt_acl": "MGMT_IN"}}) is True
    assert _eval("defined(mgmt.mgmt_acl)", {"mgmt": {"telnet_enabled": False}}) is False
    assert _eval("defined(mgmt.mgmt_acl)", {}) is UNKNOWN


def test_defined_reports_which_path_was_absent():
    result = compile_expression("defined(mgmt.mgmt_acl)").evaluate(
        _ir({"mgmt": {"telnet_enabled": False}})
    )
    assert result.value is False
    assert "mgmt.mgmt_acl" in result.absent


# -- collections and quantifiers -------------------------------------------


def test_empty_and_count():
    assert _eval("empty(snmp.communities)", {"snmp": {"communities": []}}) is True
    assert _eval("empty(snmp.communities)", {"snmp": {"communities": ["default"]}}) is False
    assert _eval("empty(snmp.communities)", {"snmp": {}}) is UNKNOWN
    assert _eval("count(logging.servers) > 0", {"logging": {"servers": ["10.0.0.5"]}}) is True


def test_all_and_any_bind_the_element_to_any_loop_variable_name():
    """`iface`, `user`, `algo` - the name is the author's choice, not ours."""
    sections = {
        "interfaces": [
            {"name": "e1", "shutdown": False, "acl_in": "IN"},
            {"name": "e2", "shutdown": True, "acl_in": None},
        ]
    }
    assert _eval("all(interfaces, iface.shutdown == true or defined(iface.acl_in))", sections) is True
    assert _eval("any(anything, anything.shutdown == true)", sections) is UNKNOWN
    assert _eval("any(interfaces, x.shutdown == true)", sections) is True


def test_all_is_false_when_one_element_violates():
    sections = {
        "interfaces": [
            {"name": "e1", "shutdown": False, "acl_in": "IN"},
            {"name": "e2", "shutdown": False, "acl_in": None},
        ]
    }
    assert _eval("all(interfaces, defined(iface.acl_in))", sections) is False


def test_bare_words_inside_a_list_are_strings():
    """`[scrypt, pbkdf2]` is two strings, not two IR paths.

    Without this rule every rule author would have to quote vendor tokens, and
    the first one who forgot would get a silently wrong comparison.
    """
    sections = {"aaa": {"local_users": [{"name": "a", "hash": "scrypt"}]}}
    assert _eval("all(aaa.local_users, user.hash in [scrypt, pbkdf2, sha512])", sections) is True
    sections = {"aaa": {"local_users": [{"name": "a", "hash": "reversible"}]}}
    assert _eval("all(aaa.local_users, user.hash in [scrypt, pbkdf2, sha512])", sections) is False


# -- compilation errors ----------------------------------------------------


def test_malformed_assertions_fail_at_compile_time():
    """A broken rule stops the run, rather than failing on device 147 of 200."""
    for bad in ("", "mgmt.x ==", "all(interfaces)", "unknown_function(mgmt.x)", "mgmt.x == )"):
        with pytest.raises(RuleError):
            expression = compile_expression(bad)
            expression.evaluate(_ir({"mgmt": {"x": 1}}))


def test_decimal_literals_are_rejected():
    """Floats are banned so that ledger hashes stay reproducible."""
    with pytest.raises(RuleError):
        compile_expression("mgmt.idle_timeout_min <= 10.5")


# -- evidence tracking -----------------------------------------------------


def test_evaluation_records_the_paths_it_read():
    """Touched paths become the citations under a finding."""
    result = compile_expression("mgmt.telnet_enabled == false").evaluate(
        ir_for("cisco-ios-core-01")
    )
    assert result.touched == ["mgmt.telnet_enabled"]


def test_evaluation_is_deterministic():
    """Same IR, same assertion, same answer - every time.

    An audit that is not reproducible is not an audit.
    """
    ir = ir_for("cisco-ios-core-01")
    expression = compile_expression(
        "mgmt.telnet_enabled == false and mgmt.idle_timeout_min <= 10"
    )
    results = [expression.evaluate(ir) for _ in range(10)]
    assert len({str(r.value) for r in results}) == 1
    assert len({tuple(r.touched) for r in results}) == 1
