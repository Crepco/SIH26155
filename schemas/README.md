# Schemas

Machine-readable contracts. When this directory and a document in `docs/` disagree, the schema
wins and the document is the bug.

| Directory | Contract | Spec | Owner |
|-----------|----------|------|-------|
| [`ir/`](ir/) | The normalised security baseline model — the intermediate representation | [docs/03](../docs/03-ir-schema.md) | Track A |
| [`rule/`](rule/) | A compliance control expressed as data | [docs/04](../docs/04-rule-format.md) | Track B |
| [`adapter/`](adapter/) | A signed, portable Vendor Adapter Pack | [docs/06](../docs/06-adapter-packs.md) | Track C |

## Versioning

Each contract is directory-versioned (`v1.0.0/`) and every instance document carries its own
`schema_version`. Patch changes are editorial. Minor changes are additive and optional. Major
changes remove, retype or rename — and land with a migration note.

Once frozen, a version directory is never edited in place. Ship `v1.1.0` instead.

## Freeze status

| Contract | Version | Status | Freeze date |
|----------|---------|--------|-------------|
| IR | v1.0.0 | draft | 27 Aug 2026 |
| Rule | v1.0.0 | draft | 27 Aug 2026 |
| Adapter pack | v1.0.0 | draft | Phase 2 |

## Validation

Every schema is validated in CI, and every fixture in `corpus/` and every file in `rules/` is
validated against its schema on every push. A rule that does not validate does not load; a
malformed adapter pack is refused at import rather than warned about.
