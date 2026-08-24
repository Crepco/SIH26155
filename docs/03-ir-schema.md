# 03 — IR schema: the normalised security baseline model

**Status: draft, freezes 27 August 2026. Owner: Track A.**

This is the single most consequential artefact in the project. Every other track reads from it.
It is versioned from commit one and changes to it are treated as breaking API changes with a
migration, not as edits.

## Design rules

1. **Vendor-neutral vocabulary.** No field is named after any vendor's CLI. Cisco's
   `exec-timeout`, Fortinet's `admintimeout` and Juniper's `idle-timeout` all become
   `mgmt.idle_timeout_min`.
2. **Security posture only.** The IR is not a configuration model. It does not attempt to
   represent everything a device can do — only the properties a security benchmark can assert on.
   Routing policy detail that no control examines does not belong here.
3. **Every fact is evidenced.** A value in the IR carries provenance: which file, which line, and
   which tier of the cascade produced it. A fact without provenance cannot appear in a finding.
4. **Absence is not falsehood.** A field that was never observed is `null`, and `null` is not
   `false`. Rules must distinguish "Telnet is disabled" from "we never found out".
5. **Additive evolution.** New fields are optional. Removing or retyping a field is a major
   version bump.

## Shape

    {
      "device": { "vendor":"cisco", "os":"IOS", "version":"15.2", "serial":"FDO1234ABCD" },
      "mgmt": {
        "telnet_enabled": false,
        "ssh": { "enabled": true, "version": 2, "ciphers": ["aes256-ctr"] },
        "idle_timeout_min": 10
      },
      "aaa":        { "enabled": true, "local_users": [ {"name":"admin","hash":"scrypt"} ] },
      "snmp":       { "version": 3, "communities": [] },
      "logging":    { "servers": ["10.0.0.5"], "level": "informational" },
      "ntp":        { "servers": ["10.0.0.1"], "authenticated": true },
      "interfaces": [ { "name":"Gi0/1", "acl_in":"BLOCK_MGMT", "shutdown": false } ]
    }

The machine-readable definition lives in [`schemas/ir/`](../schemas/ir/) and is the authority.
This document explains intent; the JSON Schema decides.

## Top-level sections

| Section | Holds | Consumed by |
|---------|-------|-------------|
| `device` | Vendor, model, OS, version, serial, hostname, fingerprint confidence | Reporting, twin rendering |
| `mgmt` | Management plane: telnet, ssh, http/https, console, idle timeout, banners | Most CIS/STIG controls, most probes |
| `aaa` | Authentication, authorisation, accounting; local users; password policy; credential hashes | Credential-reuse correlation |
| `snmp` | Version, communities, v3 users, ACL restrictions, trap targets | Default-community probe |
| `logging` | Syslog servers, severity level, buffered logging, timestamps | Fleet log-correlation checks |
| `ntp` | Servers, authentication, source interface | NTP drift correlation |
| `interfaces` | Name, description, addressing, applied ACLs, shutdown state, zone membership | Fleet graph, ACL analysis |
| `acls` | Named lists, ordered entries, action, match criteria, hit position | Shadowed-ACE detection |
| `routing` | Protocols in use, neighbour authentication, redistribution | Regression checks in Crucible |
| `services` | Discovery protocols, unused daemons, source routing, proxy ARP | Hardening controls |
| `crypto` | TLS versions, certificate metadata, IKE/IPsec proposals | Weak-crypto controls |
| `coverage` | Total lines, parsed lines, unparsed line list, per-tier attribution | Invariants 3 and 4 |
| `provenance` | Per-fact file, line, tier, adapter pack id, confidence | Invariant 2 |

## Provenance and coverage

Provenance is not optional decoration; it is the mechanism that makes invariants 2, 3 and 4
enforceable. Every scalar written into the IR is accompanied by a record of where it came from.

    coverage:
      total_lines:    13102
      parsed_lines:   12847
      unparsed_lines: 255
      by_tier: { tier0: 12310, tier1: 402, tier2: 121, tier3: 14 }

    provenance:
      "mgmt.idle_timeout_min":
        file: "core-sw-01/running-config.txt"
        line: 4412
        raw:  " exec-timeout 10 0"
        tier: 0
        confidence: 1.0

`parsed_lines + unparsed_lines` must equal `total_lines` for every device, always. A test asserts
this on every fixture in the corpus. Coverage accounting is built into the first parser, not
retrofitted — retrofitting it later is painful and the number stops being trustworthy.

## Versioning

Directory-versioned: `schemas/ir/v1.0.0/`. The IR document carries its own `schema_version`.

- **Patch** — documentation, description text, examples.
- **Minor** — new optional field, new enum member, relaxed constraint.
- **Major** — removed field, retyped field, tightened constraint, renamed path.

Any change lands with: the schema edit, a migration note, an update to this document, and a
green run of the multi-vendor consistency test in [16](16-validation-plan.md).

## Open questions before freeze

- Do ACL entries need normalised protocol/port ranges, or is raw match text plus an ordinal
  enough for shadow detection? *(Track A + Track B, decide by 27 Aug.)*
- Does `interfaces[].zone` generalise across Fortinet zones, Palo Alto zones and Cisco zone-based
  firewall, or does it need a vendor-tagged escape hatch? *(Track A.)*
- Where do cloud security groups sit — as `interfaces` with synthetic names, or their own
  section? Out of submission scope, but the schema should not preclude it.
