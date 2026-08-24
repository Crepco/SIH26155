# crucible.parsers — Tier 0 deterministic parsers

**Track A. Phase 1 (Cisco IOS, Junos, FortiOS), Phase 2 (Arista, PAN-OS, RouterOS).**

One module per vendor. A Tier-0 parser has exactly two obligations and no others:

1. Write facts into the IR **with provenance** — file, line number, raw text, tier 0.
2. Account for **every line** it consumed, so that coverage adds up.

It may not guess. It may not skip. A line it does not understand falls through to Tier 1, which
is a normal and expected outcome, not an error.

## Planned modules

| Module | Vendor | Approach |
|--------|--------|----------|
| `cisco_ios` | Cisco IOS / IOS-XE | ciscoconfparse2 over the hierarchical config |
| `arista_eos` | Arista EOS | Shares the IOS-style handler with an EOS dialect table |
| `junos` | Juniper Junos | lxml over the XML representation, not the CLI text |
| `panos` | Palo Alto PAN-OS | lxml over the XML export |
| `fortios` | Fortinet FortiOS | Custom `config` / `edit` / `set` / `next` / `end` block parser |
| `routeros` | MikroTik RouterOS | Custom flat path-prefixed command parser |
| `show_output` | Any | TextFSM + ntc-templates for `show version` and friends; this is where serial numbers come from |

## Why show output is a first-class input

Serial numbers and hardware details are explicitly required in the report and are usually **not
present in the running configuration at all**. They live in `show version`. Ingestion therefore
accepts a bundle or a tech-support archive, and this package parses both halves. Teams that treat
a config file as the only input will fail a stated deliverable.

## Adding a vendor

Prefer not to. The training loop exists so that a new vendor is an adapter pack rather than a
module — that is the claim the whole submission rests on. A Tier-0 parser is justified only when a
vendor is in the six-vendor submission scope or its grammar is genuinely beyond what a pack can
express.
