# 06 — Vendor Adapter Packs

**Owner: Track C. Format frozen and implemented.** Packs are built, signed, exported,
imported and gated by a trust store; `crucible pack` and `crucible trust` manage them.

The training loop does not merely persist a mapping to a local database. It emits a **signed,
portable Vendor Adapter Pack** — a self-contained YAML file describing one vendor grammar and its
field mappings into the IR. Export it from one deployment, import it into another, and that
instance speaks the new vendor too.

It is the network defence equivalent of a Sigma rule or a Suricata feed.

## The operational story

NCIIPC audits two hundred organisations. One of them buys a new vendor. That organisation trains
the parser once, publishes the adapter pack, and all two hundred can audit the new hardware the
next morning — with no code written and no software update shipped.

That is the answer to NTRO requirement 5 in a single sentence, and it is a stronger claim than
supporting forty vendors out of the box, because it does not expire when a vendor ships firmware.

## Shape

    schema_version: "1.0.0"
    pack:
      id: mikrotik-routeros-7
      vendor: mikrotik
      os: RouterOS
      os_versions: ">=7.0"
      created: 2026-09-11
      author: "audit team, org-042"

    grammar:
      kind: flat_path_prefixed
      comment_prefix: "#"
      path_token: "/"

    fingerprint:
      - match: "/system identity set name="
        confidence: 0.9

    mappings:
      - ir_path: mgmt.telnet_enabled
        match: "/ip service set telnet disabled=(?P<value>yes|no)"
        transform: invert_yes_no
        tier_learned: 3
        confirmed_by: "admin@org-042"
        samples: 4

      - ir_path: mgmt.ssh.enabled
        match: "/ip service set ssh disabled=(?P<value>yes|no)"
        transform: invert_yes_no
        tier_learned: 2
        confidence: 0.88
        samples: 2

    signature:
      algorithm: ed25519
      key_id: "org-042-audit"
      value: "base64..."

## What a pack may and may not contain

| Allowed | Forbidden |
|---------|-----------|
| Grammar description | Executable code of any kind |
| Match expressions over configuration text | Shell commands, file paths, network addresses to contact |
| Named transforms from a fixed library | Arbitrary transform expressions |
| IR paths that exist in the declared IR version | IR paths invented by the pack |
| Provenance and sample counts | Configuration content from the organisation that trained it |

That last row matters more than it looks. A pack is shared between organisations, so it must
carry *knowledge of a vendor grammar* and never *fragments of a customer configuration*. Export
strips sample text and keeps only counts; the exporter refuses to emit a pack whose match
expressions contain literal addresses, hostnames or credentials.

## Signing, and why it is not decoration

An adapter pack is executable knowledge: it decides how a line of a critical-infrastructure
configuration is interpreted. A malicious pack could map `telnet disabled=no` to
`telnet_enabled: false` and produce a clean audit on a wide-open device.

Therefore:

- Packs are signed with Ed25519 at export.
- Import verifies the signature against a locally held trust store, offline.
- An unsigned or signature-invalid pack is **refused**, not warned about.
- The pack id and key id are recorded in the provenance of every fact the pack produced, so a
  report can be traced to the exact knowledge that produced it, and a compromised pack can be
  audited backwards through issued reports.

## Import and precedence

When several sources can interpret the same line, precedence is: built-in Tier 0 parser, then
signed adapter packs in trust order, then Tier 1 inference, then a Tier 2 proposal. A pack never
overrides a built-in parser; it extends coverage rather than redefining it.

## Proving it works

The Phase 2 definition of done is exactly this: hold MikroTik out of the build entirely, feed it
in cold, train it live in under three minutes, export the pack, import it into a second instance,
and audit the same file there. Two instances, one lesson, no code.
