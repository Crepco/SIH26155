## What this changes

<!-- One paragraph. What is different after this merges. -->

## Track and phase

Track: <!-- A / B / C / D / E / F -->
Phase: <!-- 0-5 -->
Closes: <!-- #issue -->

## Invariants

Tick what applies, and say why for anything unticked that should have been ticked.

- [ ] **1 — The AI never decides pass or fail.** No code path lets model output become a verdict.
- [ ] **2 — Every finding carries line-level evidence.** File, line number, raw text.
- [ ] **3 — Fail closed.** Nothing unparsed became a PASS. Unknowns are reported as UNKNOWN.
- [ ] **4 — Coverage is published.** `parsed + unparsed == total` still holds on every fixture.
- [ ] **5 — Three finding states.** DEMONSTRATED / ASSERTED / UNKNOWN, never collapsed to two.
- [ ] **Air-gap.** No outbound call, no cloud SDK, no external asset, not behind a flag.

## Contract changes

- [ ] This PR does not touch the IR schema or the rule format.
- [ ] It does, and it includes a version bump, a migration note, a docs update, and a green
      multi-vendor consistency run.

## Checks

- [ ] `make check` is clean.
- [ ] Tests added, or the reason none were is stated below.
- [ ] Docs in `docs/` updated if behaviour described there changed.
- [ ] No CIS Benchmark text reproduced in rules, reports or docs.
- [ ] No real device configuration data committed.

## Notes for the reviewer

<!-- What to look at first. What you are unsure about. -->
