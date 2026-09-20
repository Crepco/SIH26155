"""PDF rendering - deliverable 4.

*One PDF per device: device identity including serial and hardware, pass/fail
with severity, and device-specific step-by-step remediation CLI.*

ReportLab, because it is pure Python with no system dependencies, which is what
makes it installable from an offline bundle on a machine that has never had a
network. A PDF toolchain that needs system packages would quietly break the one
claim this project cannot afford to break.

Every page carries the verification hash in the footer. The test that matters is
not whether the PDF renders - it is whether someone unfamiliar with the project
can act on the remediation without narration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

from crucible.common.types import FindingState, Verdict
from crucible.graph.report import FleetReport
from crucible.report.build import AuditReport

__all__ = ["render_fleet_pdf", "render_pdf"]

# Three states, three visual treatments, never collapsed into two. A reader who
# remembers only one thing should remember that grey is not green.
STATE_COLOURS = {
    FindingState.DEMONSTRATED: colors.HexColor("#B3261E"),
    FindingState.ASSERTED: colors.HexColor("#B26B00"),
    FindingState.UNKNOWN: colors.HexColor("#5F6368"),
}

SEVERITY_COLOURS = {
    "critical": colors.HexColor("#8E1B16"),
    "high": colors.HexColor("#B3261E"),
    "medium": colors.HexColor("#B26B00"),
    "low": colors.HexColor("#1A73E8"),
    "info": colors.HexColor("#5F6368"),
}

INK = colors.HexColor("#1B2A38")
RULE = colors.HexColor("#D6DCE2")
MUTED = colors.HexColor("#5F6368")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontSize=20, leading=24, textColor=INK, alignment=TA_LEFT
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontSize=12.5,
            leading=15,
            textColor=INK,
            spaceBefore=14,
            spaceAfter=5,
        ),
        "h3": ParagraphStyle(
            "h3",
            parent=base["Heading3"],
            fontSize=10.5,
            leading=13,
            textColor=INK,
            spaceBefore=9,
            spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", parent=base["BodyText"], fontSize=9, leading=12.5, textColor=INK
        ),
        "muted": ParagraphStyle(
            "muted", parent=base["BodyText"], fontSize=8, leading=11, textColor=MUTED
        ),
        "mono": ParagraphStyle(
            "mono",
            parent=base["Code"],
            fontName="Courier",
            fontSize=7.6,
            leading=9.6,
            textColor=INK,
            backColor=colors.HexColor("#F4F6F8"),
            borderPadding=4,
        ),
    }


class _Doc(BaseDocTemplate):
    """Document template that stamps the verification hash on every page."""

    def __init__(self, path: str, report: AuditReport, **kwargs: Any) -> None:
        super().__init__(path, pagesize=A4, **kwargs)
        self.report = report
        frame = Frame(18 * mm, 20 * mm, A4[0] - 36 * mm, A4[1] - 40 * mm, id="body")
        self.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=self._decorate)])

    def _decorate(self, canvas: Any, _doc: Any) -> None:
        canvas.saveState()
        report = self.report

        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, A4[1] - 15 * mm, A4[0] - 18 * mm, 15 * mm * 0 + A4[1] - 15 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, A4[1] - 13 * mm, "CRUCIBLE - compliance you can prove")
        canvas.drawRightString(
            A4[0] - 18 * mm,
            A4[1] - 13 * mm,
            f"{report.device.get('hostname') or report.device_id} - {report.report_id}",
        )

        canvas.line(18 * mm, 16 * mm, A4[0] - 18 * mm, 16 * mm)
        # The footer is the tamper-evidence surface. It is on every page so that
        # a page removed from a printed report is detectable.
        verification = report.verification_hash or report.merkle_root[:16]
        canvas.setFont("Courier", 6.8)
        canvas.drawString(18 * mm, 12 * mm, f"verify: {verification}")
        canvas.drawCentredString(
            A4[0] / 2, 12 * mm, "generated offline - no configuration data left this host"
        )
        canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"page {canvas.getPageNumber()}")
        canvas.restoreState()


def _kv_table(rows: list[tuple[str, str]], width: float) -> Table:
    table = Table(rows, colWidths=[42 * mm, width - 42 * mm])
    table.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 8),
                ("FONT", (1, 0), (1, -1), "Helvetica", 8),
                ("TEXTCOLOR", (0, 0), (-1, -1), INK),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, RULE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return table


def render_pdf(report: AuditReport, path: str | Path) -> Path:
    """Render the per-device audit report."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    style = _styles()
    width = A4[0] - 36 * mm
    story: list[Any] = []
    device = report.device

    # -- title -------------------------------------------------------------
    story.append(Paragraph("Network security compliance audit", style["title"]))
    story.append(
        Paragraph(
            f"{device.get('hostname') or report.device_id} &mdash; "
            f"{device.get('vendor', 'unknown')} {device.get('os') or ''}",
            style["muted"],
        )
    )
    story.append(Spacer(1, 8))

    # -- 1. identity -------------------------------------------------------
    story.append(Paragraph("1. Device identity", style["h2"]))
    missing = "<i>not present in the supplied files</i>"
    story.append(
        _kv_table(
            [
                ("Hostname", str(device.get("hostname") or missing)),
                ("Vendor / OS", f"{device.get('vendor', 'unknown')} {device.get('os') or ''}"),
                ("OS version", str(device.get("version") or missing)),
                ("Model", str(device.get("model") or missing)),
                ("Serial number", str(device.get("serial") or missing)),
                ("Report generated", report.generated_at),
                ("Rule set digest", report.rule_set_digest),
            ],
            width,
        )
    )

    # -- 2. posture --------------------------------------------------------
    counts = report.evaluation.counts()
    severities = report.evaluation.severity_counts()
    story.append(Paragraph("2. Posture summary", style["h2"]))

    summary = Table(
        [
            ["Score", "Projected", "Failed", "Unknown", "Passed"],
            [
                f"{report.score}%",
                f"{report.projected_score()}%",
                str(counts["fail"]),
                str(counts["unknown"]),
                str(counts["pass"]),
            ],
        ],
        colWidths=[width / 5] * 5,
    )
    summary.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, 0), "Helvetica", 7.5),
                ("FONT", (0, 1), (-1, 1), "Helvetica-Bold", 15),
                ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
                ("TEXTCOLOR", (0, 1), (-1, 1), INK),
                ("TEXTCOLOR", (2, 1), (2, 1), SEVERITY_COLOURS["critical"]),
                ("TEXTCOLOR", (3, 1), (3, 1), MUTED),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOX", (0, 0), (-1, -1), 0.25, RULE),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, RULE),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(summary)
    story.append(Spacer(1, 5))
    story.append(
        Paragraph(
            f"Failures by severity &mdash; critical {severities['critical']}, "
            f"high {severities['high']}, medium {severities['medium']}, low {severities['low']}. "
            f"Frameworks evaluated: {', '.join(report.frameworks)}.",
            style["body"],
        )
    )

    # -- 3. coverage -------------------------------------------------------
    coverage = report.coverage
    total, parsed = coverage["total_lines"], coverage["parsed_lines"]
    percent = round(100.0 * parsed / total, 1) if total else 0.0
    story.append(Paragraph("3. Coverage", style["h2"]))
    story.append(
        Paragraph(
            f"<b>Parsed {parsed:,} of {total:,} lines ({percent}%). "
            f"{coverage['unparsed_lines']:,} lines uninterpreted</b> &mdash; listed verbatim in "
            "Appendix C.",
            style["body"],
        )
    )
    story.append(Spacer(1, 3))
    if report.adapter_packs:
        story.append(
            Paragraph(
                "<b>No built-in parser exists for this vendor.</b> It was read by the signed "
                f"adapter pack <b>{', '.join(report.adapter_packs)}</b>. Facts learned that way "
                "are marked tier 2 (model-proposed) or tier 3 (administrator-confirmed) in the "
                "evidence below, and the pack id is committed to the ledger with them.",
                style["body"],
            )
        )
    elif not report.parser_applied:
        story.append(
            Paragraph(
                "<b>No deterministic parser was applied to this device.</b> The vendor could not "
                "be identified with sufficient confidence, so every control below is reported "
                "UNKNOWN rather than passing by default.",
                style["body"],
            )
        )
        story.append(Spacer(1, 3))
    story.append(
        Paragraph(
            "Every uninterpreted line is a control that could not be evaluated &mdash; not one "
            "that quietly passed. This figure is published rather than hidden.",
            style["muted"],
        )
    )

    # -- 4. findings -------------------------------------------------------
    story.append(Paragraph("4. Findings", style["h2"]))
    if not report.findings:
        story.append(
            Paragraph(
                "No findings. Every applicable control passed on parsed facts.", style["body"]
            )
        )

    for finding in report.findings:
        block: list[Any] = []
        colour = SEVERITY_COLOURS.get(finding.severity.value, INK)
        state_colour = STATE_COLOURS[finding.state]
        block.append(
            Paragraph(
                f'<font color="{colour.hexval()}"><b>{finding.severity.value.upper()}</b></font> '
                f'&nbsp;<font color="{state_colour.hexval()}">[{finding.state.value.upper()}]'
                f"</font>&nbsp; <b>{finding.rule_id}</b> &mdash; {finding.title}",
                style["h3"],
            )
        )
        block.append(Paragraph(finding.rationale, style["body"]))
        block.append(Paragraph(f"Frameworks: {', '.join(finding.frameworks)}", style["muted"]))

        if finding.evidence:
            lines = "\n".join(
                f"{item.cite()}  (tier {item.tier})\n    {item.raw.strip()}"
                for item in finding.evidence
            )
            block.append(Spacer(1, 3))
            block.append(Paragraph("Evidence", style["muted"]))
            block.append(Preformatted(lines, style["mono"]))

        if finding.missing_paths:
            label = (
                "Could not evaluate &mdash; these facts were never parsed:"
                if finding.verdict is Verdict.UNKNOWN
                else "Failed because the configuration never sets:"
            )
            block.append(Spacer(1, 3))
            block.append(Paragraph(label, style["muted"]))
            block.append(Preformatted("\n".join(finding.missing_paths), style["mono"]))

        if finding.remediation:
            block.append(Spacer(1, 3))
            block.append(Paragraph(f"Remediation ({finding.remediation_target})", style["muted"]))
            block.append(Preformatted("\n".join(finding.remediation), style["mono"]))

        block.append(Spacer(1, 6))
        story.append(KeepTogether(block))

    # -- 5. remediation plan ----------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("5. Remediation plan", style["h2"]))
    if not report.plan.steps:
        story.append(Paragraph("Nothing to apply.", style["body"]))
    else:
        story.append(
            Paragraph(
                f"{report.plan.command_count} commands across {len(report.plan.phases())} phases, "
                f"rendered for <b>{report.plan.target}</b>.",
                style["body"],
            )
        )
        story.append(
            Paragraph(
                "<b>Ordered so that applying it top to bottom cannot lock you out.</b> The safe "
                "path is established before the weak services it replaces are disabled, and "
                "management access is narrowed last.",
                style["body"],
            )
        )
        for phase, steps in report.plan.phases():
            story.append(Paragraph(f"Phase {phase} &mdash; {steps[0].phase_name}", style["h3"]))
            commands_block: list[str] = []
            for step in steps:
                commands_block.append(f"! {step.rule_id} ({step.severity}) - {step.title}")
                commands_block.extend(step.commands)
                commands_block.append("!")
            story.append(Preformatted("\n".join(commands_block), style["mono"]))

    if report.plan.unsupported:
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(
                f"No remediation is available for {device.get('vendor')} for "
                f"{', '.join(report.plan.unsupported)}. Printing another platform's syntax would "
                "be worse than printing nothing.",
                style["muted"],
            )
        )

    # -- appendices --------------------------------------------------------
    story.append(Paragraph("Appendix A &mdash; Reproducibility", style["h2"]))
    story.append(
        _kv_table(
            [
                ("Rule set digest", report.rule_set_digest),
                ("IR schema version", report.ir_schema_version),
                ("Tool version", report.tool_version),
                ("Merkle root", report.merkle_root),
                ("Ledger entry", str(report.ledger_seq) if report.ledger_seq else "not committed"),
                ("Verification hash", report.verification_hash or "-"),
            ],
            width,
        )
    )

    story.append(Paragraph("Appendix C &mdash; Uninterpreted lines", style["h2"]))
    sample = coverage.get("unparsed_sample") or []
    if not sample:
        story.append(Paragraph("Every line of every supplied file was interpreted.", style["body"]))
    else:
        story.append(
            Paragraph(
                "Verbatim, so a reader can check for themselves that nothing important was "
                "skipped.",
                style["body"],
            )
        )
        story.append(
            Preformatted(
                "\n".join(f"{e['file']}:{e['line']}: {e['raw']}" for e in sample), style["mono"]
            )
        )

    _Doc(str(target), report).build(story)
    return target


class _FleetDoc(BaseDocTemplate):
    """Same page furniture as a device report, without a device to name."""

    def __init__(self, path: str, **kwargs: Any) -> None:
        super().__init__(path, pagesize=A4, **kwargs)
        frame = Frame(18 * mm, 20 * mm, A4[0] - 36 * mm, A4[1] - 40 * mm, id="body")
        self.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=self._decorate)])

    def _decorate(self, canvas: Any, _doc: Any) -> None:
        canvas.saveState()
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, A4[1] - 15 * mm, A4[0] - 18 * mm, A4[1] - 15 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, A4[1] - 13 * mm, "CRUCIBLE - compliance you can prove")
        canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 13 * mm, "fleet report")
        canvas.line(18 * mm, 16 * mm, A4[0] - 18 * mm, 16 * mm)
        canvas.setFont("Courier", 6.8)
        canvas.drawString(18 * mm, 12 * mm, "cross-device findings")
        canvas.drawCentredString(
            A4[0] / 2, 12 * mm, "generated offline - no configuration data left this host"
        )
        canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"page {canvas.getPageNumber()}")
        canvas.restoreState()


def render_fleet_pdf(fleet: FleetReport, path: str | Path) -> Path:
    """The fleet report as a document, ranked fixes first."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    style = _styles()
    width = A4[0] - 36 * mm
    story: list[Any] = []
    counts = fleet.counts()
    graph = fleet.graph.to_dict()["counts"]

    story.append(Paragraph("Fleet report", style["title"]))
    story.append(
        Paragraph(
            f"{graph['devices']} devices &middot; {graph['interfaces']} interfaces &middot; "
            f"{graph['segments']} segments",
            style["muted"],
        )
    )
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"<b>{fleet.headline()}</b>", style["body"]))
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            "Every finding here is invisible to a per-device checklist: each device on these "
            "paths passes its own audit. Adjacency is inferred from addressing, and any finding "
            "resting on an inferred link is marked.",
            style["muted"],
        )
    )

    # -- ranked fixes ---------------------------------------------------------
    story.append(Paragraph("1. Fixes, in the order that matters", style["h2"]))
    story.append(
        Paragraph(
            "Ranked by attack paths severed, not by severity count. "
            "That is the difference between a list of findings and a plan.",
            style["body"],
        )
    )
    rows: list[list[Any]] = [["#", "Fix", "Paths", "Rule"]]
    for index, fix in enumerate(fleet.fixes, start=1):
        rows.append(
            [
                str(index),
                Paragraph(
                    f"{fix.action}<br/><font size=7 color='#5F6368'>"
                    f"{', '.join(fix.devices)}</font>",
                    style["body"],
                ),
                str(fix.paths_severed),
                fix.rule_id or "-",
            ]
        )
    table = Table(rows, colWidths=[8 * mm, width - 48 * mm, 14 * mm, 26 * mm])
    table.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
                ("FONT", (0, 1), (-1, -1), "Helvetica", 8),
                ("TEXTCOLOR", (0, 0), (-1, -1), INK),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, 0), 0.5, INK),
                ("LINEBELOW", (0, 1), (-1, -2), 0.25, RULE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(table)

    # -- findings --------------------------------------------------------------
    story.append(Paragraph("2. Cross-device findings", style["h2"]))
    story.append(
        Paragraph(
            f"Critical {counts['critical']} &middot; high {counts['high']} &middot; "
            f"medium {counts['medium']} &middot; low {counts['low']}",
            style["muted"],
        )
    )
    for correlation in fleet.correlations:
        block: list[Any] = [
            Paragraph(
                f"<font color='{SEVERITY_COLOURS.get(correlation.severity, MUTED)}'>"
                f"<b>{correlation.severity.upper()}</b></font> &nbsp; "
                f"<font face='Courier' size=8>{correlation.id}</font> &nbsp; "
                f"{correlation.title}",
                style["h3"],
            ),
            Paragraph(correlation.summary, style["body"]),
        ]
        if correlation.paths:
            # Summarised on purpose: a full hop list is fixed-width text that
            # cannot wrap, and it would run off the page. Every hop is in
            # fleet.md and fleet.json.
            lines = []
            for route in correlation.paths[:6]:
                marker = " (inferred)" if route.inferred else ""
                hops = max(len(route.hops) // 2, 1)
                plural = "hop" if hops == 1 else "hops"
                lines.append(f"{route.source}  =>  {route.target}   {hops} {plural}{marker}")
            if len(correlation.paths) > 6:
                lines.append(f"... {len(correlation.paths) - 6} more paths")
            block.append(Preformatted("\n".join(lines), style["mono"]))
        if correlation.remediation:
            block.append(
                Paragraph("<b>Fix:</b> " + "<br/>".join(correlation.remediation), style["body"])
            )
        story.append(KeepTogether(block))
        story.append(Spacer(1, 4))

    _FleetDoc(str(target)).build(story)
    return target
