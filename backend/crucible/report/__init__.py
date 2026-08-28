"""Reporting - deliverable 4.

One report object, three renderings: JSON for pipelines, Markdown for terminals
and diffs, PDF for the artefact an auditor signs. All three read the same
assembled report, so they cannot disagree about what was found.
"""

from crucible.report.build import AuditReport, build_report
from crucible.report.remediation import RemediationPlan, RemediationStep, build_plan
from crucible.report.text import render_markdown

__all__ = [
    "AuditReport",
    "RemediationPlan",
    "RemediationStep",
    "build_plan",
    "build_report",
    "render_markdown",
    "render_pdf",
]


def render_pdf(report: AuditReport, path: str) -> str:
    """Render a PDF.

    Imported lazily so that the deterministic pipeline - parse, evaluate,
    verdict - can run and be tested without ReportLab present. The verdict path
    should not depend on a rendering library.
    """
    from crucible.report.pdf import render_pdf as _render

    return str(_render(report, path))
