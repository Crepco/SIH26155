"""Ordering remediation so that applying it cannot lock the operator out.

The reason administrators ignore compliance reports is not laziness. It is that
applying three hundred untested CLI changes to a live core switch is more
frightening than the findings themselves. A report that hands over commands in
severity order is asking someone to disable Telnet on a device they are
currently connected to over Telnet.

So the printed order is not severity order. It is dependency order:

===== ================================================================
Phase What it does
===== ================================================================
0     Establish the safe path first - enable SSH, AAA, logging, NTP.
1     General hardening that cannot cut the session.
2     Disable the weak services the safe path replaced.
3     Narrow who can reach the management plane. Highest lockout risk,
      so it goes last, when everything else is already in place.
===== ================================================================

Individually safe fixes can be jointly unsafe, which is why this operates over
the whole finding set rather than per finding.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from crucible.common.types import Finding, Verdict

__all__ = ["RemediationPlan", "RemediationStep", "build_plan"]

PHASE_NAMES = {
    0: "Establish the safe path",
    1: "Harden",
    2: "Disable weak services",
    3: "Restrict management access",
}

#: Substrings that place a fix in a phase. Checked against the generated
#: commands, so the classification follows what will actually be typed rather
#: than what the rule is nominally about.
_PHASE_MARKERS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (
        3,
        (
            "access-class",
            "access-list",
            "trusthost",
            "ip access-group",
            "firewall filter",
            "connection-limit",
        ),
    ),
    (
        2,
        (
            "no ip telnet",
            "transport input ssh",
            "admin-telnet disable",
            "telnet disabled=yes",
            "delete service telnet",
            "delete system services telnet",
            "no ip http server",
            "www disabled=yes",
            "no snmp-server community",
            "snmp community remove",
            "no username",
        ),
    ),
    (
        0,
        (
            "ip ssh",
            "set service ssh",
            "protocol-version",
            "aaa new-model",
            "aaa authentication",
            "tacacs",
            "radius",
            "logging host",
            "logging trap",
            "syslogd",
            "ntp ",
            "snmp-server user",
            "snmp-server group",
            "security-level",
        ),
    ),
)


@dataclass(slots=True)
class RemediationStep:
    """One finding's fix, placed in the ordered plan."""

    rule_id: str
    title: str
    severity: str
    phase: int
    commands: list[str]
    target: str

    @property
    def phase_name(self) -> str:
        return PHASE_NAMES[self.phase]


@dataclass(slots=True)
class RemediationPlan:
    """The whole ordered fix sequence for one device."""

    steps: list[RemediationStep]
    target: str | None
    #: Findings that failed but for which we have no commands for this vendor.
    #: Named explicitly rather than dropped: a gap the report admits to is a
    #: gap someone can close, and printing another platform's syntax would be
    #: worse than printing nothing.
    unsupported: list[str]

    @property
    def command_count(self) -> int:
        return sum(len(step.commands) for step in self.steps)

    def phases(self) -> list[tuple[int, list[RemediationStep]]]:
        grouped: dict[int, list[RemediationStep]] = {}
        for step in self.steps:
            grouped.setdefault(step.phase, []).append(step)
        return sorted(grouped.items())

    def flat_commands(self) -> list[str]:
        return [command for step in self.steps for command in step.commands]


def _phase_for(commands: Iterable[str]) -> int:
    blob = "\n".join(commands).lower()
    for phase, markers in _PHASE_MARKERS:
        if any(marker in blob for marker in markers):
            return phase
    return 1


def build_plan(findings: list[Finding]) -> RemediationPlan:
    """Order the fixes for a device so the sequence is safe to paste.

    Within a phase, severity decides. Across phases, safety does - a critical
    finding in phase 3 is still applied after a medium one in phase 0, because
    the medium one is what keeps the operator connected.
    """
    steps: list[RemediationStep] = []
    unsupported: list[str] = []
    target: str | None = None

    for finding in findings:
        if finding.verdict is not Verdict.FAIL:
            continue
        if not finding.remediation:
            unsupported.append(finding.rule_id)
            continue
        target = target or finding.remediation_target
        steps.append(
            RemediationStep(
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity.value,
                phase=_phase_for(finding.remediation),
                commands=list(finding.remediation),
                target=finding.remediation_target or "unknown",
            )
        )

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    steps.sort(key=lambda s: (s.phase, severity_rank.get(s.severity, 9), s.rule_id))
    return RemediationPlan(steps=steps, target=target, unsupported=unsupported)
