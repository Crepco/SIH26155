# ADR 0005 — VyOS is the only emulation target

**Status:** Accepted · 25 Aug 2026 · Track F

## Context

Crucible needs to boot a replica of an audited device in order to demonstrate a finding and
validate a fix. The instinct is to emulate each vendor faithfully: cEOS for Arista, CSR for Cisco,
a VM for FortiOS, and so on. That is a licensing problem, a disk-space problem, a boot-time
problem and a maintenance problem, and it would consume the entire remaining schedule.

## Decision

One emulation target: **VyOS in containerlab**. Every audited device, from every vendor, is
rendered from the IR into a VyOS configuration and booted as a container. Everything routes
through the IR to reach it.

We are not rebuilding GNS3.

## Consequences

**Good.**

- The new capability is a single renderer — IR to VyOS — added to renderers we are already
  building for the remediation deliverable. The rest of Crucible is orchestration.
- Twins boot in seconds and tear down cleanly, so verification is fast enough to run across the
  whole corpus as a parser self-test.
- No vendor licensing or image redistribution problem in the offline bundle.

**Bad, and accepted.**

- A VyOS twin is not a real Palo Alto, and a judge will say so. The answer is that we are not
  verifying feature parity; we are verifying **security properties**. If the IR says the
  management plane is reachable from the untrusted zone with no ACL, that property reproduces
  faithfully regardless of which platform enforces it.
- Properties that VyOS cannot model cannot be demonstrated. Those findings stay ASSERTED and the
  report says so explicitly. We never fake a proof.
- Vendor-specific bugs and quirks are out of reach. That is a different product, and honestly
  stating the boundary is stronger than blurring it.
