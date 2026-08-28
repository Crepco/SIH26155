"""Markdown rendering.

The plain-text twin of the PDF. It exists for two reasons that are not
cosmetic: it diffs cleanly between audits of the same device, which is how
drift becomes visible, and it is readable over SSH on a machine that has no PDF
viewer - which describes most of the hosts this tool will run on.

Section order is the same as the PDF, deliberately. A reader who learns one
learns the other.
"""

from __future__ import annotations

from crucible.common.types import FindingState, Verdict
from crucible.report.build import AuditReport

__all__ = ["render_markdown"]

_STATE_MARK = {
    FindingState.DEMONSTRATED: "PROVEN",
    FindingState.ASSERTED: "ASSERTED",
    FindingState.UNKNOWN: "UNKNOWN",
}


def render_markdown(report: AuditReport) -> str:
    out: list[str] = []
    add = out.append

    device = report.device
    add(f"# Compliance audit - {device.get('hostname') or report.device_id}")
    add("")
    add(f"**Report** `{report.report_id}` | generated {report.generated_at}")
    add("")

    # -- 1. device identity ------------------------------------------------
    add("## 1. Device identity")
    add("")
    add("| Field | Value |")
    add("|-------|-------|")
    for label, key in (
        ("Hostname", "hostname"),
        ("Vendor", "vendor"),
        ("OS", "os"),
        ("Version", "version"),
        ("Model", "model"),
        ("Serial", "serial"),
    ):
        value = device.get(key)
        # A serial we could not find is stated as such. Leaving the cell blank
        # invites a reader to assume the field was not required.
        add(f"| {label} | {value if value else '_not present in the supplied files_'} |")
    confidence = device.get("fingerprint_confidence_bp", 0) / 100
    add(f"| Fingerprint confidence | {confidence:.0f}% |")
    add("")

    # -- 2. posture --------------------------------------------------------
    counts = report.evaluation.counts()
    severities = report.evaluation.severity_counts()
    add("## 2. Posture summary")
    add("")
    add(f"- **Compliance score: {report.score}%** (projected after remediation: "
        f"{report.projected_score()}%)")
    add(f"- Failed: {counts['fail']} | Unknown: {counts['unknown']} | "
        f"Passed: {counts['pass']} | Not applicable: {counts['not_applicable']}")
    add(f"- By severity: critical {severities['critical']}, high {severities['high']}, "
        f"medium {severities['medium']}, low {severities['low']}")
    add(f"- Frameworks evaluated: {', '.join(report.frameworks)}")
    add("")

    # -- 3. coverage -------------------------------------------------------
    coverage = report.coverage
    total = coverage["total_lines"]
    parsed = coverage["parsed_lines"]
    percent = round(100.0 * parsed / total, 1) if total else 0.0
    add("## 3. Coverage")
    add("")
    add(f"**Parsed {parsed:,} of {total:,} lines ({percent}%). "
        f"{coverage['unparsed_lines']:,} lines uninterpreted** - listed in Appendix C.")
    add("")
    if not report.parser_applied:
        add("> No deterministic parser was applied to this device: the vendor could not be")
        add("> identified with enough confidence. Every control below is therefore UNKNOWN")
        add("> rather than passing by default.")
        add("")
    add("Commercial tools do not publish this number. It is the honest measure of how much of")
    add("the device was actually examined, and every uninterpreted line is a control that")
    add("could not be evaluated rather than one that quietly passed.")
    add("")

    # -- 4. findings -------------------------------------------------------
    add("## 4. Findings")
    add("")
    if not report.findings:
        add("No findings. Every applicable control passed on parsed facts.")
        add("")
    for finding in report.findings:
        mark = _STATE_MARK[finding.state]
        add(f"### `{finding.rule_id}` - {finding.title}")
        add("")
        add(f"**{finding.severity.value.upper()}** | {finding.verdict.value.upper()} | "
            f"state: {mark}")
        add("")
        add(f"{finding.rationale}")
        add("")
        add(f"Frameworks: {', '.join(finding.frameworks)}")
        add("")
        if finding.evidence:
            add("Evidence:")
            add("")
            for item in finding.evidence:
                add(f"- `{item.cite()}` (tier {item.tier}) - `{item.raw.strip()}`")
            add("")
        if finding.missing_paths:
            label = (
                "Could not evaluate - these facts were never parsed:"
                if finding.verdict is Verdict.UNKNOWN
                else "Failed because the configuration never sets:"
            )
            add(label)
            add("")
            for path in finding.missing_paths:
                add(f"- `{path}`")
            add("")
        if finding.remediation:
            add(f"Remediation ({finding.remediation_target}):")
            add("")
            add("```")
            for command in finding.remediation:
                add(command)
            add("```")
            add("")

    # -- 5. remediation ----------------------------------------------------
    add("## 5. Remediation plan")
    add("")
    if not report.plan.steps:
        add("Nothing to apply.")
        add("")
    else:
        add(f"{report.plan.command_count} commands across {len(report.plan.phases())} phases, "
            f"rendered for `{report.plan.target}`.")
        add("")
        add("**Ordered so that applying it top to bottom cannot lock you out.** The safe path")
        add("is established before the weak services it replaces are disabled, and management")
        add("access is narrowed last.")
        add("")
        for phase, steps in report.plan.phases():
            add(f"### Phase {phase} - {steps[0].phase_name}")
            add("")
            add("```")
            for step in steps:
                add(f"! {step.rule_id} ({step.severity}) - {step.title}")
                for command in step.commands:
                    add(command)
                add("!")
            add("```")
            add("")
    if report.plan.unsupported:
        add(f"No remediation is available for `{report.device.get('vendor')}` for: "
            f"{', '.join(report.plan.unsupported)}. Printing another platform's syntax would")
        add("be worse than printing nothing, so these are listed rather than guessed.")
        add("")

    # -- appendices --------------------------------------------------------
    add("## Appendix A - Rule set")
    add("")
    add(f"- Rule set digest: `{report.rule_set_digest}`")
    add(f"- IR schema version: `{report.ir_schema_version}`")
    add(f"- Tool version: `{report.tool_version}`")
    add("")

    add("## Appendix C - Uninterpreted lines")
    add("")
    sample = coverage.get("unparsed_sample") or []
    if not sample:
        add("Every line of every supplied file was interpreted.")
    else:
        add("Verbatim, so that a reader can check for themselves that nothing important was")
        add("skipped:")
        add("")
        add("```")
        for entry in sample:
            add(f"{entry['file']}:{entry['line']}: {entry['raw']}")
        add("```")
    add("")

    add("---")
    add("")
    add(f"Report `{report.report_id}` | Merkle root `{report.merkle_root}`")
    if report.verification_hash:
        add(f"| Ledger entry {report.ledger_seq} | **Verification hash "
            f"`{report.verification_hash}`**")
    add("")
    add("Generated offline. No configuration data left this host.")
    add("")
    return "\n".join(out)
