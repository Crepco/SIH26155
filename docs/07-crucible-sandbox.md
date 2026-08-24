# 07 — Crucible: the verification sandbox

**Owner: Track F. Begins Phase 4, after the IR is trustworthy.**

This is the single element that makes the submission structurally different from every other
team, and it is why the project is called Crucible — a proving ground.

## The gap in the category

Nipper, Tufin and FireMon tell you what is wrong. Batfish tells you what is reachable. **Nobody
proves the finding is real, or proves the fix is safe, before you touch production.** Every
compliance tool ever built ends its sentence at *this line violates CIS-NET-1.2.4*. That is an
assertion.

And the reason administrators ignore compliance reports is not laziness. It is that applying
three hundred untested CLI changes to a live core switch is more frightening than the findings
themselves. The report lands, gets filed, and nothing changes. That failure mode is the actual
reason misconfigurations survive for years in production networks.

## What Crucible does

It boots a **disposable virtual replica** of the audited device, demonstrates the vulnerability
against it, applies our generated remediation, and then proves both that the finding is closed
and that legitimate traffic still flows.

Findings are promoted from *asserted* to *demonstrated*. Remediation is promoted from *suggested*
to *validated*.

## Why it is almost free, architecturally

Two things we are already building reduce this to a rendering problem:

1. A vendor-neutral IR — the normalised security baseline model.
2. A renderer that goes IR to vendor-specific CLI, because the remediation deliverable demands it.

We already render IR to Cisco IOS, IR to FortiOS, IR to Junos. We add **one more render target:
IR to VyOS**, which boots as a container. That is the entire new capability. Because the IR is
the pivot, any audited device from any vendor becomes something we can boot, probe and test. A
Palo Alto configuration we cannot emulate becomes a VyOS container that behaves equivalently on
the security properties we care about. No other team has an IR, so no other team can do this.

## The four phases of a verification run

    [ normalised IR ]
        |
        +--> render -> vendor CLI remediation        (already built)
        |
        +--> render -> VyOS config                   (the one new renderer)
                    |
                    v
            containerlab: boot the twin
            isolated bridge, no egress, ephemeral
                    |
      PHASE 1  DEMONSTRATE THE FINDING
               telnet 23                     -> banner returned    -> CONFIRMED
               ssh weak kex offered          -> accepted           -> CONFIRMED
               snmpwalk default community    -> responds           -> CONFIRMED
               nmap from untrusted segment   -> mgmt plane open    -> CONFIRMED
                    |
      PHASE 2  APPLY GENERATED REMEDIATION
               the exact CLI printed in our PDF, in the exact order
                    |
      PHASE 3  RE-TEST
               every probe above             -> refused            -> CLOSED
                    |
      PHASE 4  REGRESSION / BLAST RADIUS
               BGP session still up?         [ok]
               users VLAN -> internet?       [ok]
               syslog still reaching?        [ok]
               management still reachable?   [ok]  no lockout

Phase 4 matters most operationally and no compliance product performs it. It is the difference
between a report an administrator files and a report an administrator acts on.

## The three claims it unlocks

- **"This finding is not a guess — here is the capture of us exploiting it."** Every finding
  carries a reproducible proof artefact: the probe command, the response, a packet capture.
  Stacked on line-cited evidence and the hash-chained ledger, the audit record forms a complete
  chain from raw config line, to parsed fact, to rule violation, to live demonstration, to signed
  report.
- **"This fix works — we ran it."** Remediation is validated before it is printed.
- **"This fix will not break your network — we checked."** Regression tests pass on the twin
  before the CLI ever reaches a human.

## It also measures our own false-positive rate

If the twin cannot reproduce a finding, that is a signal our parser mapped something incorrectly.
The sandbox doubles as an automated self-test for the entire parsing cascade. Run across the whole
corpus it generates a measured precision figure — the accuracy metric most hackathon projects
never have, and it produces itself.

## Scope discipline

- **One emulation target only.** VyOS in containerlab. Everything routes through the IR to reach
  it. We are not rebuilding GNS3.
- **Six to eight probe types, maximum.** Telnet reachable, weak SSH KEX or cipher accepted,
  default SNMP community, HTTP management plane exposed, ACL bypass from an untrusted segment, no
  session timeout, unauthenticated NTP. All testable with nmap, ssh, snmpwalk and curl.
- **Verify only HIGH and CRITICAL findings.** Verifying 312 findings is pointless. Verifying the
  nine that could actually get you owned is the product.
- **Findings that cannot be emulated stay ASSERTED.** Never fake a proof. Password hashing
  algorithm, for example, is a static property with no runtime probe — that is fine, and we say
  so in the report.
- **Twins are ephemeral and network-isolated.** Bridge network, no egress, torn down after every
  run. We state this explicitly in the architecture document, because an NTRO evaluator will
  absolutely think about the risk of booting a replica of a sensitive device.

## Anticipated challenges

| Question | Answer |
|----------|--------|
| "A VyOS twin is not a real Palo Alto." | Correct, and it does not need to be. We are not verifying feature parity; we are verifying **security properties**. If the IR says the management plane is reachable from the untrusted zone with no ACL, that property reproduces faithfully regardless of which platform enforces it. Where a property cannot be modelled, the finding stays ASSERTED and the report says so. |
| "Is this not just penetration testing?" | No. A pentest targets a live production device. This targets a disposable twin, so it is safe to run continuously, in CI, before a configuration is ever pushed. |
| "Why not simply trust the parser?" | Because in a compliance tool, trust is the thing that fails silently. This is the only mechanism that catches a parser mapping the wrong field — and it catches it automatically, across the whole corpus. |
| "What is the failure mode?" | Twin boot failure, or an unsupported property. Both degrade to ASSERTED. Never to a false DEMONSTRATED, and never to a false pass. |

## Definition of done

    crucible verify --finding CIS-NET-1.2.1

confirms a finding live, in under fifteen seconds, offline.
