"""The fixed transform library an adapter pack may name.

There is deliberately no expression language. A pack is data, and a pack that
could compute could also lie in a way a reviewer cannot see. Every transform is
here, small enough to read in one sitting, and a pack naming anything else is
refused at load time.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from crucible.common.errors import CrucibleError

__all__ = [
    "DEFAULT_COMMUNITIES",
    "TRANSFORMS",
    "TransformError",
    "TransformResult",
    "apply_transform",
    "to_bool",
]

#: Community strings every scanner tries first. Shared by every vendor, so it
#: belongs to the transform, not to a pack.
DEFAULT_COMMUNITIES = frozenset(
    {"public", "private", "community", "admin", "default", "cisco", "manager", "snmp", "secret"}
)

_TRUE = frozenset({"yes", "true", "enable", "enabled", "on", "1", "y"})
_FALSE = frozenset({"no", "false", "disable", "disabled", "off", "0", "n"})

TRANSFORMS = frozenset(
    {
        "identity",
        "invert_yes_no",
        "to_int",
        "to_bool",
        "minutes_from_seconds",
        "collect",
        "collect_redacted",
        "presence",
        "negated_presence",
        "lookup",
    }
)


class TransformError(CrucibleError):
    """A value did not fit the transform. The line stays uninterpreted."""


@dataclass(frozen=True, slots=True)
class TransformResult:
    value: Any
    #: The literal on the line that must not reach evidence, if any.
    secret: str | None = None


def to_bool(raw: str) -> bool:
    word = raw.strip().strip('"').lower()
    if word in _TRUE:
        return True
    if word in _FALSE:
        return False
    raise TransformError(f"not a boolean: {raw!r}")


def apply_transform(
    name: str, raw: str | None, values: Mapping[str, Any] | None = None
) -> TransformResult:
    """Turn the captured text into the IR value.

    ``raw`` is the ``value`` group from the match, or ``None`` when the pattern
    has no such group (presence transforms).
    """
    if name == "presence":
        return TransformResult(True)
    if name == "negated_presence":
        return TransformResult(False)
    if raw is None:
        raise TransformError(f"transform {name} needs a captured value")

    text = raw.strip().strip('"')
    if name == "identity":
        return TransformResult(text)
    if name == "to_bool":
        return TransformResult(to_bool(text))
    if name == "invert_yes_no":
        return TransformResult(not to_bool(text))
    if name == "to_int":
        try:
            return TransformResult(int(text))
        except ValueError as exc:
            raise TransformError(f"not an integer: {raw!r}") from exc
    if name == "minutes_from_seconds":
        try:
            seconds = int(text)
        except ValueError as exc:
            raise TransformError(f"not a number of seconds: {raw!r}") from exc
        # Round up: a 90-second timeout is not "one minute" for a control that
        # asks for ten or fewer, and rounding down would flatter the device.
        return TransformResult(-(-seconds // 60))
    if name == "collect":
        return TransformResult(text)
    if name == "collect_redacted":
        # The IR never stores a community string, only whether it is one of the
        # well-known defaults. Same contract as the Tier-0 parsers.
        marker = "default" if text.lower() in DEFAULT_COMMUNITIES else "custom"
        return TransformResult(marker, secret=text)
    if name == "lookup":
        if not values:
            raise TransformError("lookup needs a values table")
        key = text.lower()
        for candidate, mapped in values.items():
            if str(candidate).lower() == key:
                return TransformResult(mapped)
        raise TransformError(f"{raw!r} is not in the lookup table")
    raise TransformError(f"unknown transform {name!r}")
