"""Entry points - CLI and HTTP.

Both drive the same :func:`crucible.api.runner.run_audit`, so the terminal and
the dashboard cannot disagree about what an audit found.
"""

from crucible.api.runner import AuditJob, AuditResult, run_audit

__all__ = ["AuditJob", "AuditResult", "run_audit"]
