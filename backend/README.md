# Backend

FastAPI service. Everything from an uploaded file to a signed PDF.

**Status: Phase 1 complete.** `ingest`, `fingerprint`, `parsers`, `ir`, `policy`, `report`, `ledger` and
`api` are implemented and covered by 101 tests (`python tests/run_tests.py`). `training`, `graph` and
`sandbox` are specified only; they are Phases 2 to 4. To run it, see the setup section of the
[top-level README](../README.md#setup-five-minutes-no-internet-needed-after-install).

## Package layout

    crucible/
      common/       shared types, canonical serialisation, redaction, errors
      ingest/       upload, archives, bundles, file classification            [1]
      fingerprint/  vendor, model, OS version, serial from show output        [1]
      parsers/      Tier 0 deterministic parsers, one module per vendor       [2]
      ir/           schema loading, validation, coverage accounting           [3]
      training/     Tiers 1-3: structural inference, mapping proposal,
                    confidence scoring, adapter pack export and import        [2]
      policy/       rule loading, expression evaluator, XCCDF importer        [4]
      graph/        fleet graph construction and cross-device correlation     [5]
      report/       PDF generation, remediation rendering, what-if projection [6]
      ledger/       Merkle trees, hash chaining, Ed25519 signing              [6]
      sandbox/      Crucible: VyOS renderer, containerlab harness, probes     [7]
      api/          HTTP surface, job submission, streaming progress

Numbers map to the pipeline stages in [docs/02-architecture.md](../docs/02-architecture.md).

## The dependency rule

    ingest -> fingerprint -> parsers -> ir
                                        |
              +--------------+----------+----------+
              v              v          v          v
           policy         graph      report     sandbox

Nothing to the right of `ir` may import anything to the left of it. `policy`, `graph`, `report`
and `sandbox` read the IR and never touch raw configuration text or vendor-specific structures.
A violation of this rule is what turns a clean architecture into a pile of special cases, so it
is enforced by an import-linter check in CI rather than by good intentions.

## Module ownership

| Package | Track |
|---------|-------|
| `ingest`, `fingerprint`, `parsers`, `ir` | A |
| `policy` | B |
| `graph` | B |
| `training` | C |
| `report`, `ledger` | E |
| `sandbox` | F |
| `api`, `common` | Shared; changes need a second reviewer |

## Testing

| Directory | Contents |
|-----------|----------|
| `tests/unit/` | Per-module. Fast, no containers, no model |
| `tests/integration/` | Full pipeline against real corpus files. Runs egress-blocked |
| `tests/fixtures/` | Small, checked-in configuration excerpts. Real device data lives in `corpus/`, not here |

Two invariants are asserted on every fixture in every run, because they are the two that fail
silently: `parsed_lines + unparsed_lines == total_lines`, and no finding exists without
provenance.
