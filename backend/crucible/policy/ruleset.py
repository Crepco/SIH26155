"""Loading compliance rules from YAML.

Rules are data, never code. This module turns files into :class:`Rule` objects
and refuses, loudly, to produce a partial rule set: a rule that does not load is
a control that is silently not being checked, which is the same failure as a
silent PASS wearing different clothes.

Assertions are compiled here, at load time, so a typo in a rule stops the run
immediately rather than failing on device 147 of 200.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from crucible.common.errors import RuleError
from crucible.common.types import Severity
from crucible.policy.expr import Expression, compile_expression

__all__ = ["Rule", "RuleSet", "load_rules"]

_REQUIRED = ("id", "title", "frameworks", "severity", "assert", "rationale", "remediation")

#: Vendor to remediation key, in preference order. A vendor with no entry gets
#: no remediation block and the report says so rather than printing commands
#: from a platform the operator does not run.
REMEDIATION_TARGETS: dict[str, tuple[str, ...]] = {
    "cisco": ("cisco_ios",),
    "arista": ("arista_eos", "cisco_ios"),
    "juniper": ("juniper", "junos"),
    "fortinet": ("fortios",),
    "mikrotik": ("routeros",),
    "paloalto": ("panos",),
    "vyos": ("vyos",),
}


@dataclass(slots=True)
class Rule:
    """One compliance control, compiled and ready to evaluate."""

    id: str
    title: str
    frameworks: list[str]
    severity: Severity
    assertion: Expression
    rationale: str
    remediation: dict[str, list[str]]
    applies_to: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    verify: dict[str, Any] | None = None
    source_file: str = ""

    def applies(self, vendor: str, role: str | None = None) -> bool:
        """Whether this rule is in scope for a device.

        A rule that is out of scope reports ``not_applicable`` - never a pass.
        The distinction matters on a fleet report, where "40 devices passed"
        should not be inflated by controls that never ran.
        """
        vendors = self.applies_to.get("vendor")
        if vendors and vendor not in vendors:
            return False
        roles = self.applies_to.get("role")
        if roles and role is not None and role not in roles:
            return False
        return True

    def remediation_for(self, vendor: str) -> tuple[str | None, list[str]]:
        for key in REMEDIATION_TARGETS.get(vendor, ()):
            if key in self.remediation:
                return key, list(self.remediation[key])
        return None, []

    @property
    def verifiable(self) -> bool:
        """Eligible for a live demonstration against a twin.

        Both conditions are required: the rule must name a probe, and the
        severity must be worth booting a container for.
        """
        return self.verify is not None and self.severity.verifiable


@dataclass(slots=True)
class RuleSet:
    """An ordered, de-duplicated set of rules plus where they came from."""

    rules: list[Rule] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterable[Rule]:  # type: ignore[override]
        return iter(self.rules)

    def for_framework(self, framework: str) -> "RuleSet":
        """Filter by framework identifier, without re-parsing anything.

        This is the IR paying for itself: selecting NIST does not run a
        different rule set against a different parse, it regroups the same
        findings by a different set of identifiers.
        """
        needle = framework.lower()
        matched = [
            rule
            for rule in self.rules
            if any(identifier.lower().startswith(needle) for identifier in rule.frameworks)
        ]
        return RuleSet(rules=matched, sources=list(self.sources))

    def frameworks(self) -> list[str]:
        seen: set[str] = set()
        for rule in self.rules:
            for identifier in rule.frameworks:
                seen.add(identifier.split(":")[0])
        return sorted(seen)

    @property
    def version_digest(self) -> str:
        """A stable digest of the rule set, recorded in every report.

        A report from September has to be explicable in March, when the rules
        have moved on. Recording which rule set produced it is the difference
        between an audit trail and a screenshot.
        """
        from crucible.common.canonical import canonical_bytes, sha256_hex

        material = [
            {"id": rule.id, "assert": rule.assertion.source, "severity": rule.severity.value}
            for rule in sorted(self.rules, key=lambda r: r.id)
        ]
        return sha256_hex(canonical_bytes(material))[:16]


def _parse_rule(raw: Any, source: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{source}: expected a mapping, found {type(raw).__name__}")

    missing = [key for key in _REQUIRED if key not in raw]
    if missing:
        raise RuleError(f"{source}: rule {raw.get('id', '<no id>')} is missing {', '.join(missing)}")

    remediation = raw["remediation"]
    if not isinstance(remediation, dict) or not remediation:
        raise RuleError(f"{source}: rule {raw['id']} has no remediation")
    for target, commands in remediation.items():
        if not isinstance(commands, list) or not all(isinstance(c, str) for c in commands):
            raise RuleError(f"{source}: rule {raw['id']} remediation.{target} must be a list of strings")

    try:
        assertion = compile_expression(str(raw["assert"]))
    except RuleError as exc:
        raise RuleError(f"{source}: rule {raw['id']} assertion is invalid: {exc}") from exc

    return Rule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        frameworks=[str(f) for f in raw["frameworks"]],
        severity=Severity.parse(str(raw["severity"])),
        assertion=assertion,
        rationale=" ".join(str(raw["rationale"]).split()),
        remediation={k: list(v) for k, v in remediation.items()},
        applies_to=dict(raw.get("applies_to") or {}),
        references=[str(r) for r in raw.get("references") or []],
        verify=dict(raw["verify"]) if raw.get("verify") else None,
        source_file=source,
    )


def load_rules(*paths: str | Path) -> RuleSet:
    """Load every rule file under the given paths.

    Duplicate identifiers are a hard error. Rule identifiers appear in issued
    reports and in the hash-chained ledger, so two rules sharing one is a
    corrupted audit trail rather than a style problem.
    """
    files: list[Path] = []
    for target in paths:
        path = Path(target)
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*.yaml") if not p.name.startswith("_")))
            files.extend(sorted(p for p in path.rglob("*.yml") if not p.name.startswith("_")))
        elif path.is_file():
            files.append(path)
        else:
            raise RuleError(f"no such rule path: {path}")

    ruleset = RuleSet()
    seen: dict[str, str] = {}

    for file in files:
        # Skip the annotated template: it is documentation shaped like a rule.
        if "_template" in file.parts:
            continue
        try:
            documents = yaml.safe_load(file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RuleError(f"{file}: malformed YAML: {exc}") from exc
        if documents is None:
            continue
        if not isinstance(documents, list):
            raise RuleError(f"{file}: expected a list of rules")

        for raw in documents:
            rule = _parse_rule(raw, str(file))
            if rule.id in seen:
                raise RuleError(
                    f"duplicate rule id {rule.id}: {seen[rule.id]} and {file}. "
                    "Identifiers appear in issued reports and may never be reused."
                )
            seen[rule.id] = str(file)
            ruleset.rules.append(rule)
        ruleset.sources.append(str(file))

    if not ruleset.rules:
        raise RuleError(f"no rules found under {', '.join(str(p) for p in paths)}")

    ruleset.rules.sort(key=lambda r: (r.severity.rank, r.id))
    return ruleset
