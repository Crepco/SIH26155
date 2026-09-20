"""Measuring the tool against hand-labelled ground truth.

Most projects in this category cannot answer *how accurate is it?*. This one
can, because the answer is computed by a script anyone can re-run rather than
asserted in a slide.

What is measured (docs/16):

* **precision** - of the failures reported, the fraction a labeller agrees are
  real;
* **recall** - of the failures a labeller found, the fraction reported;
* **fact accuracy** - of the IR facts a labeller recorded, the fraction read
  with the same value, from the same line;
* **UNKNOWN rate** - controls we refused to decide. A high rate is not a
  failure. Hiding it would be.

Specification: docs/16-validation-plan.md
"""

from crucible.validation.labels import Label, load_labels
from crucible.validation.measure import DeviceScore, ValidationReport, validate

__all__ = ["DeviceScore", "Label", "ValidationReport", "load_labels", "validate"]
