"""Ground-truth label files.

One file per configuration, in the format frozen in ``corpus/labels/README.md``.
A label is written from the configuration and the control text, never from the
tool's output: a label produced by running the auditor first measures agreement
with ourselves and is worth nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from crucible.common.errors import CrucibleError

__all__ = ["Label", "LabelError", "load_labels"]

_VERDICTS = {"pass", "fail", "unknown", "not_applicable"}


class LabelError(CrucibleError):
    """A label file is malformed. Never silently skipped: a label that does not
    load is a measurement quietly not taken."""


@dataclass(frozen=True, slots=True)
class LabelledFact:
    path: str
    value: Any
    line: int | None = None
    file: str | None = None


@dataclass(slots=True)
class Label:
    config_id: str
    labelled_by: str
    labelled_on: str
    facts: list[LabelledFact] = field(default_factory=list)
    verdicts: dict[str, str] = field(default_factory=dict)
    notes: str = ""
    source: str = ""

    @property
    def human_reviewed(self) -> bool:
        """Whether a person has signed off on this label.

        Printed with every number: a figure measured against unreviewed labels
        is provisional, and saying so is the difference between a measurement
        and a claim.
        """
        lowered = self.labelled_by.lower()
        return "ai-assisted" not in lowered and "unreviewed" not in lowered


def load_labels(path: str | Path) -> list[Label]:
    """Load one label file, or every label file in a directory."""
    target = Path(path)
    files = (
        sorted(p for p in target.rglob("*.yaml") if not p.name.startswith("_"))
        if target.is_dir()
        else [target]
    )
    labels = []
    for file in files:
        try:
            raw = yaml.safe_load(file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise LabelError(f"{file}: malformed YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise LabelError(f"{file}: expected a mapping")
        labels.append(_parse(raw, str(file)))
    if not labels:
        raise LabelError(f"no label files under {target}")
    return labels


def _parse(raw: dict[str, Any], source: str) -> Label:
    for required in ("config_id", "labelled_by", "expected_verdicts"):
        if required not in raw:
            raise LabelError(f"{source}: missing {required}")

    facts = []
    for path, body in (raw.get("ir_facts") or {}).items():
        if not isinstance(body, dict) or "value" not in body:
            raise LabelError(f"{source}: fact {path} needs a value")
        line = body.get("line")
        if line is not None and not isinstance(line, int):
            raise LabelError(f"{source}: fact {path} has a non-numeric line")
        facts.append(
            LabelledFact(path=str(path), value=body["value"], line=line, file=body.get("file"))
        )

    verdicts = {}
    for rule_id, verdict in (raw.get("expected_verdicts") or {}).items():
        text = str(verdict).strip().lower()
        if text not in _VERDICTS:
            raise LabelError(f"{source}: {rule_id} has verdict {verdict!r}")
        verdicts[str(rule_id)] = text

    return Label(
        config_id=str(raw["config_id"]),
        labelled_by=str(raw["labelled_by"]),
        labelled_on=str(raw.get("labelled_on", "")),
        facts=facts,
        verdicts=verdicts,
        notes=str(raw.get("notes", "")).strip(),
        source=source,
    )
