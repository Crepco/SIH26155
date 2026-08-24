# Contributing

Six people, three and a half weeks, one shared IR. This document exists so that nobody has to
ask how to name a branch at 2 a.m.

## The one rule that governs the whole build

**The baseline ships first, end to end, before any differentiator is started.** A working
pipeline across three vendors with one framework beats a half-finished feature list every time.
Every differentiator is additive and independently droppable — if a phase slips we drop the last
item, never the foundation.

## Track ownership

Ownership is exclusive: one person is accountable per track. The two integration points — the
**IR schema** and the **rule format** — are frozen jointly and treated as contracts after that.

| Track | Owns | Critical dependency |
|-------|------|---------------------|
| **A — Parsing & Normalisation** | Tier-0 parsers, fingerprinting, the IR schema, coverage accounting | Freezes the IR schema by 27 Aug. Everything blocks on this. |
| **B — Compliance Engine** | YAML rule format, evaluator, CIS rule authoring, XCCDF importer, severity model | Needs the frozen IR schema, nothing else. |
| **C — AI & Training Loop** | Tier-1/2/3 cascade, embeddings, local model integration, adapter pack format, confidence scoring | Needs Tier-0 to exist so it knows what falls through. |
| **D — Frontend & Dashboard** | Upload flow, training GUI, fleet posture view, findings drill-down | Needs API contracts by 31 Aug; can mock until then. |
| **E — Reporting & Ledger** | PDF generation, remediation renderer, hash-chained ledger, signing, drift snapshots | Needs IR + rule results; the remediation renderer is shared with Crucible. |
| **F — Crucible & Infrastructure** | containerlab harness, VyOS renderer, probe library, regression suite, deployment, air-gap packaging | Starts on infra and air-gap immediately; Crucible proper begins Phase 4. |

## Branches

    main                     always green, always demoable
    track/<letter>/<topic>   e.g. track/a/cisco-ios-parser
    fix/<topic>              e.g. fix/serial-extraction-arista
    docs/<topic>             e.g. docs/adapter-pack-spec

Never commit directly to `main` once Phase 1 opens. Open a PR, get one review from a different
track, merge with a squash.

## Commit messages

Conventional Commits, lower case, imperative, no trailing period.

    <type>(<optional scope>): <what changed>

Types in use: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`, `ci`, `schema`,
`rules`, `corpus`.

    feat(parser): extract serial from show version for arista eos
    rules(cis): add session timeout control CIS-NET-1.2.4
    schema: bump IR to v1.1.0 for snmp v3 user list

## Hard rules that a review will reject

1. **No outbound network calls.** Any HTTP client reaching a host outside the deployment is a
   blocking review comment. The system must run with the cable unplugged.
2. **No cloud LLM SDKs.** Not OpenAI, not Anthropic, not Gemini. Not behind a flag.
3. **The model never returns a verdict.** Model output is a candidate mapping with a confidence
   score. If a code path lets model output become a pass/fail, it is wrong by construction.
4. **No silent passes.** Anything that could not be parsed is UNKNOWN, surfaced in the report and
   counted against coverage. Never PASS by omission.
5. **Every finding carries evidence.** File, line number, raw text. A finding without a citation
   does not ship.
6. **CIS Benchmark text is never reproduced.** Cite the control identifier from rule metadata.
   STIG and NIST text may be quoted.
7. **Rules are data.** If adding a compliance control requires editing Python, the rule format is
   wrong — fix the format, not the rule.

## Definition of done for a task

- The change is covered by a test, or the task explicitly says why not.
- Coverage accounting still adds up: parsed + unparsed equals total lines.
- Docs updated in the same PR if a spec in `docs/` changed behaviour.
- `make check` is clean.

## Local setup

Setup instructions land with Phase 1. Track F owns the offline bundle; if a dependency cannot be
vendored into that bundle, it cannot be a dependency.
