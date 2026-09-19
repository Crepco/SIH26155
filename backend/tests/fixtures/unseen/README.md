# Unseen-vendor fixtures

Configurations from vendors this build has **no Tier-0 parser and no fingerprint signatures for**.
They exist to exercise Tiers 1 to 3: structural inference, Tier-2 proposals and the training loop
that turns an administrator's confirmations into a signed adapter pack.

| Directory | Vendor | Grammar | Provenance |
|-----------|--------|---------|------------|
| `huawei-vrp-agg-01/` | Huawei VRP 5.x | `#`-separated marker blocks | Representative configuration written for these tests from the public VRP command reference. Not a dump of a real device. |

Nothing in `crucible/training/vocabulary.py` may be derived from these files. The vocabulary
is built from the vendors the build already parses, and a test enforces that it contains no
VRP or RouterOS syntax, so the transfer to an unseen vendor is real.
