# ADR 0001 — A vendor-neutral IR sits between parsing and everything else

**Status:** Accepted · 25 Aug 2026 · Track A

## Context

The problem statement names roughly forty vendors and says the list is illustrative. There is no
shared tokeniser, no shared hierarchy and no shared vocabulary between them: Cisco calls it
`exec-timeout`, Fortinet calls it `admintimeout`, Juniper calls it `idle-timeout`.

The obvious approach is a rule per vendor per control. That is forty times three hundred
combinations, it is unmaintainable by six people, and it breaks whenever any vendor ships a
firmware update.

## Decision

Introduce a vendor-neutral intermediate representation — the normalised security baseline model.
Parsers write into it. Rules, reports, remediation, fleet analysis and the verification sandbox
read only from it. No component downstream of normalisation may see vendor-specific text.

## Consequences

**Good.**

- Adding a vendor never touches the rules engine. Adding a benchmark never touches a parser. That
  is exactly NTRO requirement 5, satisfied structurally rather than claimed.
- One parse, four frameworks. The same IR is scored against CIS, NIST, STIG and ISO with no
  re-parsing.
- Crucible becomes affordable: because everything already routes through the IR, adding one render
  target (VyOS) makes every audited device from every vendor bootable as a twin. Without the IR
  this feature would be impossible rather than merely expensive.
- Cross-device correlation becomes possible at all, because forty devices from six vendors are
  finally comparable.

**Bad, and accepted.**

- The IR is a single point of failure for the whole project. If it churns mid-build, every track
  breaks. Mitigated by freezing it on 27 Aug and versioning it from commit one — this is the top
  risk in the register.
- Anything the IR cannot express is invisible to the rest of the system. This forces discipline
  about what the IR must cover, and it is why UNKNOWN exists as a first-class finding state.
- Normalisation loses vendor nuance. Accepted: the IR models security posture, not device
  behaviour.
