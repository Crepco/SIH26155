# Corpus manifest

Every file in `raw/` is recorded here: what it is, where it came from, and whether it is
labelled. Phase 0 target: **60+ configurations across 8+ vendors, 20 labelled.**

## Progress

| Vendor | OS | Collected | Labelled | Source |
|--------|-----|-----------|----------|--------|
| Cisco | IOS / IOS-XE | 0 | 0 | DevNet sandbox, ntc-templates fixtures |
| Juniper | Junos | 0 | 0 | vSRX / vMX trial, public dumps |
| Fortinet | FortiOS | 0 | 0 | FortiGate VM evaluation |
| Arista | EOS | 0 | 0 | containerlab cEOS |
| Palo Alto | PAN-OS | 0 | 0 | Public XML exports |
| MikroTik | RouterOS | 0 | 0 | CHR in a VM |
| VyOS | VyOS | 0 | 0 | containerlab |
| SONiC | SONiC | 0 | 0 | containerlab |
| FRR | FRRouting | 0 | 0 | containerlab |
| Nokia | SR Linux | 0 | 0 | containerlab |
| **Total** | | **0 / 60** | **0 / 20** | |

## Record format

One row per file, added when the file is added:

| id | file | vendor | os | version | lines | has_show_output | labelled | source | licence | date |
|----|------|--------|----|---------|-------|-----------------|----------|--------|---------|------|
| — | — | — | — | — | — | — | — | — | — | — |

## Held-out vendor

**MikroTik RouterOS is held out of the build entirely.** It is not used to develop or tune any
Tier-0 parser, and no MikroTik file is used while building the training loop.

It exists in this corpus for exactly one purpose: the Phase 2 definition of done, where it is fed
in cold, trained live through the GUI in under three minutes, exported as an adapter pack, and
imported into a second instance. That is the single most convincing evidence that the AI claim is
real rather than marketing, and it is only convincing if the hold-out is genuine.

Anyone who uses a MikroTik config for development has spent the demo.
