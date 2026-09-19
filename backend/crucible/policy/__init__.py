"""The compliance engine - rules as data, verdicts as arithmetic.

This package reads the IR and nothing else. It never sees a configuration line,
never calls a model, and is the only place in the system permitted to decide
whether a device passes a control.

Specification: docs/04-rule-format.md
"""

from crucible.policy.engine import DeviceEvaluation, evaluate_device
from crucible.policy.expr import UNKNOWN, Expression, compile_expression
from crucible.policy.ruleset import Rule, RuleSet, load_rules

__all__ = [
    "UNKNOWN",
    "DeviceEvaluation",
    "Expression",
    "Rule",
    "RuleSet",
    "compile_expression",
    "evaluate_device",
    "load_rules",
]
