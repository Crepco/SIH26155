# Architecture decision records

One file per decision. Never edited after acceptance — superseded by a new record instead. The
point is that a decision made once in August is not re-litigated every week in September.

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-vendor-neutral-ir.md) | A vendor-neutral IR sits between parsing and everything else | Accepted |
| [0002](0002-rules-as-data.md) | Compliance rules are data, never code | Accepted |
| [0003](0003-local-models-only.md) | All inference is local; no cloud model, ever | Accepted |
| [0004](0004-ai-proposes-engine-disposes.md) | The model proposes parsers; the deterministic engine issues verdicts | Accepted |
| [0005](0005-single-emulation-target.md) | VyOS is the only emulation target | Superseded by [0008](0008-alpine-twin.md) |
| [0006](0006-no-permissioned-blockchain.md) | Hash-chained ledger instead of a permissioned blockchain | Accepted |
| [0007](0007-plain-html-console.md) | The console and training GUI are plain HTML; the Next.js scaffold is retired | Accepted |
| [0008](0008-alpine-twin.md) | The Crucible twin is a purpose-built Alpine container, not VyOS | Accepted |

## Format

Context, decision, consequences. Short enough that everyone actually reads it.
