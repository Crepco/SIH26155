"""Reporting, and the ordering rule that makes a report safe to act on.

The lockout tests are the ones that matter. A report that tells an administrator
to disable Telnet on a device they are connected to over Telnet is worse than no
report: it teaches people that following the tool is dangerous, and after that
nothing gets fixed.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from conftest import ALL_DEVICES, evaluation_for, ir_for, ruleset

from crucible.common.types import Verdict
from crucible.report.build import build_report
from crucible.report.remediation import build_plan
from crucible.report.text import render_markdown


def _report(device: str):  # type: ignore[no-untyped-def]
    return build_report(
        report_id=f"AUDIT-TEST-{device}",
        device_id=device,
        ir=ir_for(device),
        evaluation=evaluation_for(device),
        rule_set_digest=ruleset().version_digest,
        frameworks=ruleset().frameworks(),
    )


# -- remediation ordering --------------------------------------------------


def test_ssh_is_enabled_before_telnet_is_disabled():
    """The safe path is established before the weak one is removed.

    This is the single ordering rule that decides whether a remote
    administrator survives applying the report.
    """
    plan = build_plan(evaluation_for("cisco-ios-core-01").findings)
    commands = plan.flat_commands()

    ssh_index = next(
        i for i, c in enumerate(commands) if "ip ssh" in c or "transport input ssh" in c
    )
    telnet_index = next((i for i, c in enumerate(commands) if "no ip telnet" in c), len(commands))
    assert ssh_index < telnet_index, "Telnet is disabled before SSH is confirmed working"


def test_management_access_is_narrowed_last():
    """Restricting who can reach the management plane is the highest-risk step.

    It goes last, when the safe path already exists, so that a mistake in an ACL
    is recoverable over a session that is still up.
    """
    for device in ALL_DEVICES:
        plan = build_plan(evaluation_for(device).findings)
        phases = [phase for phase, _ in plan.phases()]
        if 3 in phases:
            assert phases[-1] == 3, f"{device}: management restriction is not the final phase"


def test_phases_are_monotonic_in_the_printed_order():
    for device in ALL_DEVICES:
        plan = build_plan(evaluation_for(device).findings)
        observed = [step.phase for step in plan.steps]
        assert observed == sorted(observed), f"{device}: phases printed out of order"


def test_only_failures_get_remediation():
    """An UNKNOWN has no fix, because we do not know what is wrong.

    Printing commands for something we could not evaluate would be guessing at
    an administrator's expense.
    """
    for device in ALL_DEVICES:
        for finding in evaluation_for(device).findings:
            if finding.verdict is not Verdict.FAIL:
                assert not finding.remediation, (
                    f"{device} {finding.rule_id}: {finding.verdict.value} carries remediation"
                )


def test_remediation_matches_the_device_vendor():
    """A Cisco report never prints FortiOS syntax."""
    expected = {
        "cisco-ios-core-01": "cisco_ios",
        "arista-leaf-01": "cisco_ios",
        "fortios-fw-01": "fortios",
        "junos-edge-01": "juniper",
        "routeros-branch-01": "routeros",
    }
    for device, target in expected.items():
        for finding in evaluation_for(device).findings:
            if finding.remediation:
                assert finding.remediation_target in (target, "arista_eos"), (
                    f"{device} {finding.rule_id} rendered for {finding.remediation_target}"
                )


def test_findings_without_vendor_remediation_are_named_not_dropped():
    """A gap the report admits to is a gap someone can close."""
    for device in ALL_DEVICES:
        evaluation = evaluation_for(device)
        plan = build_plan(evaluation.findings)
        covered = {s.rule_id for s in plan.steps} | set(plan.unsupported)
        failures = {f.rule_id for f in evaluation.findings if f.verdict is Verdict.FAIL}
        assert failures <= covered, f"{device}: failures silently dropped from the plan"


# -- report assembly -------------------------------------------------------


def test_every_finding_gets_a_merkle_leaf():
    for device in ALL_DEVICES:
        report = _report(device)
        assert len(report.leaves) == len(report.findings)
        assert report.merkle_root


def test_the_root_changes_if_a_cited_line_is_altered():
    """Evidence is inside the commitment, not beside it.

    If only the verdict were committed to, someone could rewrite the cited line
    number and raw text without breaking the root - and those are exactly what
    make a finding checkable.
    """
    report = _report("cisco-ios-core-01")
    original = report.merkle_root

    finding = next(f for f in report.findings if f.evidence)
    finding.evidence[0] = type(finding.evidence[0])(
        ir_path=finding.evidence[0].ir_path,
        file=finding.evidence[0].file,
        line=finding.evidence[0].line + 1,
        raw=finding.evidence[0].raw,
        tier=finding.evidence[0].tier,
    )
    rebuilt = build_report(
        report_id=report.report_id,
        device_id=report.device_id,
        ir=ir_for("cisco-ios-core-01"),
        evaluation=report.evaluation,
        rule_set_digest=report.rule_set_digest,
        frameworks=report.frameworks,
    )
    assert rebuilt.merkle_root != original


def test_projection_never_assumes_unknowns_will_pass():
    """We cannot promise a control we could not evaluate will pass.

    A projection that quietly assumed so would be exactly the false comfort this
    tool exists to remove.
    """
    for device in ALL_DEVICES:
        report = _report(device)
        unknowns = sum(1 for f in report.findings if f.verdict is Verdict.UNKNOWN)
        if unknowns:
            assert report.projected_score() < 100, (
                f"{device}: projected 100% while {unknowns} controls remain UNKNOWN"
            )


def test_projection_is_at_least_the_current_score():
    for device in ALL_DEVICES:
        report = _report(device)
        assert report.projected_score() >= report.score


# -- rendering -------------------------------------------------------------


def test_markdown_publishes_coverage_and_lists_uninterpreted_lines():
    """Invariant 4 has to survive the trip to the page."""
    report = _report("junos-edge-01")
    markdown = render_markdown(report)

    assert "## 3. Coverage" in markdown
    assert "uninterpreted" in markdown
    assert "Appendix C" in markdown
    for entry in report.coverage["unparsed_sample"]:
        assert str(entry["line"]) in markdown


def test_markdown_cites_a_line_for_every_evidenced_finding():
    report = _report("cisco-ios-core-01")
    markdown = render_markdown(report)
    for finding in report.findings:
        for item in finding.evidence:
            assert item.cite() in markdown, f"{finding.rule_id}: citation missing from the report"


def test_markdown_says_when_a_serial_was_not_supplied():
    """A blank field invites a reader to assume it was not required."""
    markdown = render_markdown(_report("junos-edge-01"))
    assert "not present in the supplied files" in markdown


def test_no_device_secret_reaches_a_rendered_report():
    """The last checkpoint before a report leaves the host.

    Note what is *not* checked here: the literal "public" does appear in a
    rendered report, inside our own remediation command `no snmp-server
    community public`. That is a published default from the rule file, not a
    value read off the device, and telling an administrator which community to
    remove is the point of the fix. The test below draws that line properly.
    """
    for device in ALL_DEVICES:
        markdown = render_markdown(_report(device))
        for secret in ("s3cr3t-rw", "hunter2", "readonly123", "070C285F4D06", "mERr$9cTjUIEq"):
            assert secret not in markdown, f"{device}: {secret!r} reached the report"


def test_no_community_string_reaches_a_finding_citation():
    """Device-read secrets must not appear as evidence, only in our own fixes.

    Drawn deliberately narrowly: evidence quotes the device, so a community
    string there is a disclosure. Remediation quotes us, so a well-known default
    there is instruction.
    """
    for device in ALL_DEVICES:
        for finding in evaluation_for(device).findings:
            for item in finding.evidence:
                assert "public" not in item.raw, (
                    f"{device} {finding.rule_id}: a community string was quoted as evidence"
                )


def test_pdf_renders_and_is_not_empty():
    output = Path(tempfile.mkdtemp()) / "report.pdf"
    from crucible.report import render_pdf

    render_pdf(_report("cisco-ios-core-01"), str(output))
    assert output.exists()
    assert output.stat().st_size > 4000
    assert output.read_bytes().startswith(b"%PDF")
