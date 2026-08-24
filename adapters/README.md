# Vendor Adapter Packs

Signed, portable units of learned vendor knowledge. Specification:
[docs/06-adapter-packs.md](../docs/06-adapter-packs.md).

## What lives here

| Path | Contents |
|------|----------|
| `_template/` | The annotated starting point, and the example used in documentation |
| `builtin/` | Packs the team authored and signed for vendors that do not warrant a Tier-0 parser |
| `imported/` | Packs received from another deployment. Never edited; re-export instead |

Packs produced by a running deployment are written to its data directory, not to this repository.
What is committed here is only what ships with the product.

## Trust

Import verifies an Ed25519 signature against a locally held trust store, entirely offline. An
unsigned or signature-invalid pack is refused rather than warned about, because a pack decides
how a line of a critical-infrastructure configuration is interpreted.

Public keys of trusted publishers live in `trust/` and are managed as deliberately as any other
credential. Adding a key is an administrative action with an audit record, never a side effect of
importing a file.

## Privacy rule for exported packs

A pack carries knowledge of a vendor grammar and never fragments of a customer configuration.
Export strips sample text and keeps only counts, and refuses to emit a pack whose match
expressions contain literal addresses, hostnames or credentials. Assume every exported pack will
be published to two hundred organisations, because that is the intended workflow.
