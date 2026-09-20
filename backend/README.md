# Backend

FastAPI service. Everything from an uploaded file to a signed PDF.

**Status: Phases 1 to 5 complete.** Every package here is implemented and covered by 224 tests
(`python tests/run_tests.py`, no pytest required) — `ingest`, `fingerprint`, `parsers`, `ir`,
`policy`, `report`, `ledger`, `api`, `training`, `graph`, `sandbox` and `validation`. The one
package that needs anything beyond the seven runtime dependencies is `sandbox`, which boots a
container twin and so needs a Docker daemon; without one, findings stay `ASSERTED`.

To run it, see the setup section of the
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
      report/       PDF generation, remediation rendering, what-if projection,
                    drift between two audits of one device                    [6]
      ledger/       Merkle trees, hash chaining, Ed25519 signing              [6]
      sandbox/      Crucible: twin spec, Docker harness, stdlib probes        [7]
      validation/   labelled ground truth, precision and recall
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

`python tests/run_tests.py` runs everything with no test framework installed, which is what the
offline bundle relies on. `pytest` works too, and takes markers: `pytest -m "not sandbox"` skips
the tests that need a Docker daemon. A bare module name runs one file's tests:
`python tests/run_tests.py training`.

| Path | Contents |
|------|----------|
| `tests/test_*.py` | One file per area, named for what it protects rather than for a layer |
| `tests/fixtures/` | Small, checked-in configuration excerpts, six devices across six vendors |
| `tests/fixtures/xccdf/` | Real DISA benchmark excerpts, for the importer |

Real device data lives in `corpus/`, not here, and the labels behind the accuracy numbers are in
`corpus/labels/`.

Two invariants are asserted on every fixture in every run, because they are the two that fail
silently: `parsed_lines + unparsed_lines == total_lines`, and no finding exists without
provenance.
