# Tests

    unit/          per-module, fast, no containers and no model
    integration/   full pipeline against real corpus files, egress-blocked
    fixtures/      small checked-in configuration excerpts

Real device configurations live in [`corpus/`](../../corpus/), not here. Fixtures are the small
excerpts a unit test needs inline.

## The two invariants asserted on every run

These are the two that fail silently, so they are checked everywhere rather than in one test:

1. `parsed_lines + unparsed_lines == total_lines`, for every device, always.
2. No finding exists without provenance — file, line and raw text.

## The tests that decide whether the architecture works

| Test | What it proves |
|------|----------------|
| Multi-vendor consistency | The same control produces identical verdicts across four vendors. This is the IR earning its place |
| Fail-closed | A file with deliberately unparseable content produces UNKNOWN, never PASS |
| Unseen vendor | A held-out vendor is trained through the API and the mappings survive pack export and import |
| Egress-blocked pipeline | A full audit completes with no route to anything but loopback |
| Canonicalisation stability | The same findings serialise to the same bytes, so the ledger hashes are reproducible |
| Lockout safety | Generated remediation never disables the connected transport before the replacement is up |

## Markers

    pytest -m "not sandbox and not model"     what CI runs by default
    pytest -m sandbox                          requires Docker and containerlab
    pytest -m model                            requires a local Ollama instance
    pytest -m integration                      full pipeline over the corpus
