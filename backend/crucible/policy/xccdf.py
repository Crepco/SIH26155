"""Importing DISA STIGs from XCCDF, without pretending they are machine-checkable.

STIGs ship as machine-readable XCCDF XML, so one importer yields hundreds of
real controls instead of hand-typed ones. But a STIG control is written for a
human reviewer: its check is prose ("in the presence of the reviewer, the SA
should enter..."), not an expression over parsed facts. Importing all of it and
calling every control "evaluated" would be exactly the silent-pass failure this
project exists to prevent.

So an import produces two things:

* **Rules** for the controls an explicit *binding* connects to an IR assertion.
  These are evaluated like any other rule, and carry the STIG id, the Vuln id
  and the CCIs as framework identifiers.
* **A catalogue** listing every control in the benchmark, bound or not, with
  the reason. Unbound controls are reported as requiring manual review; they
  are never evaluated and never counted as passes.

A binding is written once per benchmark, by hand, and reviewed. That is the
honest cost of turning prose into an assertion, and it is much smaller than
writing the controls themselves.

XCCDF 1.1 and 1.2 are both read. Document type declarations are refused: a
benchmark is a file from outside, and entity expansion is not a risk worth
taking for a convenience.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from crucible.common.errors import RuleError

__all__ = ["Benchmark", "Binding", "Control", "ImportResult", "import_benchmark", "load_benchmark"]

#: DISA category to our severity. CAT I is "directly and immediately results in
#: loss of confidentiality, availability or integrity", which is what our
#: critical means; CAT III is advisory.
_SEVERITY = {"high": "critical", "medium": "medium", "low": "low", "unknown": "info"}

_DISCUSSION = re.compile(r"<VulnDiscussion>(.*?)</VulnDiscussion>", re.DOTALL)
_TAGS = re.compile(r"<[^>]+>")
_ID_SAFE = re.compile(r"[^A-Z0-9._-]")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find(node: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in node if _local(c.tag) == name), None)


def _findall(node: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in node if _local(c.tag) == name]


def _text(node: ET.Element | None) -> str:
    if node is None:
        return ""
    return " ".join("".join(node.itertext()).split())


@dataclass(frozen=True, slots=True)
class Control:
    """One STIG control, as written."""

    vuln_id: str
    rule_id: str
    stig_id: str
    severity: str
    title: str
    discussion: str
    fix_text: str
    check_text: str
    ccis: tuple[str, ...] = ()
    srg: str = ""

    @property
    def crucible_id(self) -> str:
        base = _ID_SAFE.sub("-", (self.stig_id or self.vuln_id).upper())
        return f"STIG-{base}"[:64]

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "rule_id": self.rule_id,
            "stig_id": self.stig_id,
            "severity": self.severity,
            "title": self.title,
            "ccis": list(self.ccis),
            "srg": self.srg,
        }


@dataclass(slots=True)
class Benchmark:
    id: str
    title: str
    version: str
    release: str
    controls: list[Control] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for control in self.controls:
            counts[control.severity] = counts.get(control.severity, 0) + 1
        return counts


@dataclass(frozen=True, slots=True)
class Binding:
    """The human decision that turns one prose check into an assertion."""

    assertion: str
    stig_id: str = ""
    vuln_id: str = ""
    remediation_from: str = ""
    remediation: dict[str, list[str]] = field(default_factory=dict)
    frameworks: tuple[str, ...] = ()
    applies_to: dict[str, Any] = field(default_factory=dict)
    severity: str = ""

    def matches(self, control: Control) -> bool:
        if self.stig_id and self.stig_id.upper() == control.stig_id.upper():
            return True
        return bool(self.vuln_id) and self.vuln_id.upper() == control.vuln_id.upper()


@dataclass(slots=True)
class ImportResult:
    benchmark: Benchmark
    rules: list[dict[str, Any]] = field(default_factory=list)
    catalogue: list[dict[str, Any]] = field(default_factory=list)

    @property
    def machine_checkable(self) -> int:
        return len(self.rules)

    @property
    def manual(self) -> int:
        return len(self.catalogue) - len(self.rules)

    def summary(self) -> str:
        return (
            f"{self.benchmark.title} {self.benchmark.version}: "
            f"{len(self.catalogue)} controls, {self.machine_checkable} machine-checkable, "
            f"{self.manual} require manual review"
        )

    def rules_yaml(self) -> str:
        header = (
            f"# Imported from {self.benchmark.title} (version {self.benchmark.version},"
            f" {self.benchmark.release}).\n"
            "# Generated by `crucible stig-import`. Do not edit: change the bindings and\n"
            "# re-import, or the next import will silently drop the edit.\n"
            "#\n"
            f"# {self.manual} further controls in this benchmark have no binding to an IR\n"
            "# assertion and are listed in the catalogue beside this file. They are NOT\n"
            "# evaluated, and they are never counted as passes.\n"
        )
        return header + yaml.safe_dump(self.rules, sort_keys=False, allow_unicode=True, width=100)

    def catalogue_json(self) -> str:
        return json.dumps(
            {
                "benchmark": {
                    "id": self.benchmark.id,
                    "title": self.benchmark.title,
                    "version": self.benchmark.version,
                    "release": self.benchmark.release,
                },
                "counts": {
                    "controls": len(self.catalogue),
                    "machine_checkable": self.machine_checkable,
                    "manual": self.manual,
                    "by_severity": self.benchmark.by_severity(),
                },
                "controls": self.catalogue,
            },
            indent=2,
        )


def _refuse_dtd(text: str) -> None:
    head = text[:4096].lower()
    if "<!doctype" in head or "<!entity" in text.lower():
        raise RuleError("the benchmark contains a document type declaration; refused")


def load_benchmark(source: str | Path) -> Benchmark:
    """Read a benchmark from an XCCDF file, or from the zip DISA publishes."""
    path = Path(source)
    if path.suffix.lower() == ".zip":
        text = _from_zip(path)
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
    return parse_benchmark(text)


def _from_zip(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        names = [
            n
            for n in archive.namelist()
            if n.lower().endswith(".xml") and "xccdf" in n.lower() and not n.startswith("/")
        ]
        if not names:
            raise RuleError(f"{path.name} contains no XCCDF file")
        member = archive.getinfo(sorted(names, key=len)[0])
        if member.file_size > 64 * 1024 * 1024:
            raise RuleError(f"{member.filename} is implausibly large for a benchmark")
        with archive.open(member) as handle:
            return handle.read().decode("utf-8", errors="replace")


def parse_benchmark(text: str) -> Benchmark:
    _refuse_dtd(text)
    try:
        root = ET.fromstring(text)  # noqa: S314 - DTDs refused above; expat resolves no entities
    except ET.ParseError as exc:
        raise RuleError(f"benchmark is not well-formed XML: {exc}") from exc
    if _local(root.tag) != "Benchmark":
        raise RuleError(f"expected an XCCDF Benchmark, found <{_local(root.tag)}>")

    release = ""
    for plain in _findall(root, "plain-text"):
        if plain.get("id") == "release-info":
            release = _text(plain)

    benchmark = Benchmark(
        id=root.get("id", "benchmark"),
        title=_text(_find(root, "title")) or root.get("id", "benchmark"),
        version=_text(_find(root, "version")),
        release=release,
    )

    for group in root.iter():
        if _local(group.tag) != "Group":
            continue
        for rule in _findall(group, "Rule"):
            benchmark.controls.append(_control(group, rule))
    return benchmark


def _control(group: ET.Element, rule: ET.Element) -> Control:
    description = _text(_find(rule, "description"))
    discussion = _DISCUSSION.search(description)
    check = _find(rule, "check")
    ccis = tuple(
        _text(ident)
        for ident in _findall(rule, "ident")
        if "cci" in (ident.get("system") or "").lower()
    )
    return Control(
        vuln_id=group.get("id", ""),
        rule_id=rule.get("id", ""),
        stig_id=_text(_find(rule, "version")),
        severity=_SEVERITY.get(rule.get("severity", "unknown"), "info"),
        title=_text(_find(rule, "title")),
        discussion=_TAGS.sub("", discussion.group(1)).strip() if discussion else description,
        fix_text=_text(_find(rule, "fixtext")),
        check_text=_text(_find(check, "check-content")) if check is not None else "",
        ccis=ccis,
        srg=_text(_find(group, "title")),
    )


def load_bindings(source: str | Path) -> list[Binding]:
    path = Path(source)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: malformed bindings: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("bindings"), list):
        raise RuleError(f"{path}: expected a mapping with a 'bindings' list")
    bindings = []
    for entry in raw["bindings"]:
        if not isinstance(entry, dict) or "assert" not in entry:
            raise RuleError(f"{path}: every binding needs an 'assert'")
        if not entry.get("stig_id") and not entry.get("vuln_id"):
            raise RuleError(f"{path}: every binding needs a stig_id or a vuln_id")
        bindings.append(
            Binding(
                assertion=str(entry["assert"]),
                stig_id=str(entry.get("stig_id", "")),
                vuln_id=str(entry.get("vuln_id", "")),
                remediation_from=str(entry.get("remediation_from", "")),
                remediation={k: list(v) for k, v in (entry.get("remediation") or {}).items()},
                frameworks=tuple(entry.get("frameworks") or ()),
                applies_to=dict(entry.get("applies_to") or {}),
                severity=str(entry.get("severity", "")),
            )
        )
    return bindings


def import_benchmark(
    benchmark: Benchmark,
    bindings: Sequence[Binding] = (),
    *,
    reference_rules: Iterable[Any] = (),
) -> ImportResult:
    """Turn a benchmark plus its bindings into rules and a catalogue.

    ``reference_rules`` are already-loaded rules whose remediation a binding may
    reuse with ``remediation_from``: the same fix, written once.
    """
    known = {getattr(rule, "id", ""): rule for rule in reference_rules}
    result = ImportResult(benchmark=benchmark)

    for control in benchmark.controls:
        binding = next((b for b in bindings if b.matches(control)), None)
        entry = control.to_dict()
        entry["bound"] = binding is not None
        if binding is None:
            entry["status"] = "manual review - no binding to an IR assertion"
            result.catalogue.append(entry)
            continue

        remediation: dict[str, list[str]] = dict(binding.remediation)
        if binding.remediation_from:
            source_rule = known.get(binding.remediation_from)
            if source_rule is None:
                raise RuleError(
                    f"{control.crucible_id}: remediation_from names "
                    f"{binding.remediation_from}, which is not in the loaded rule set"
                )
            remediation = {k: list(v) for k, v in source_rule.remediation.items()}
        if not remediation:
            # The STIG's own fix text, as a manual instruction. It is not a
            # vendor CLI, so no vendor will match it and the report will say
            # the fix is not automated for this platform - which is true.
            remediation = {"manual": [control.fix_text or "See the benchmark fix text."]}

        frameworks = [
            f"STIG:{control.stig_id or control.vuln_id}",
            f"STIG-VULN:{control.vuln_id}",
            *[f"CCI:{cci}" for cci in control.ccis],
            *binding.frameworks,
        ]
        rule: dict[str, Any] = {
            "id": control.crucible_id,
            "title": control.title,
            "frameworks": frameworks,
            "severity": binding.severity or control.severity,
            "assert": binding.assertion,
            "rationale": control.discussion or control.title,
            "remediation": remediation,
        }
        if binding.applies_to:
            rule["applies_to"] = binding.applies_to
        rule["references"] = [f"{benchmark.title} {control.vuln_id} ({control.rule_id})"]
        result.rules.append(rule)
        entry["status"] = "evaluated"
        entry["crucible_id"] = control.crucible_id
        result.catalogue.append(entry)

    return result
