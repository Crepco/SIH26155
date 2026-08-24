# crucible.sandbox — the Crucible verification sandbox

**Track F. Phase 4, after the IR is trustworthy.**

Boots a disposable twin of an audited device, demonstrates the finding, applies the generated
remediation, re-tests, and checks blast radius. Full specification:
[docs/07-crucible-sandbox.md](../../../docs/07-crucible-sandbox.md).

## Planned components

| Component | Responsibility |
|-----------|----------------|
| `render_vyos` | IR to VyOS configuration. The one new render target the whole sandbox pivots on |
| `harness` | containerlab topology generation, boot, configure, tear down |
| `probes` | Six to eight probe types, maximum. Their output *is* the proof artefact |
| `regression` | Phase 4 blast-radius checks: BGP up, VLAN reachable, syslog flowing, no lockout |
| `capture` | tcpdump to pcap, digested and attached to the finding |

## Probe library, and its ceiling

Telnet reachable · weak SSH KEX or cipher accepted · default SNMP community · HTTP management
plane exposed · ACL bypass from an untrusted segment · no session timeout · unauthenticated NTP.

All testable with nmap, ssh, snmpwalk and curl. The list does not grow without a decision: eight
probes that work beat twenty that sometimes do.

## Hard constraints

- Twins run on an **isolated bridge with no egress** and are **torn down after every run**. An
  NTRO evaluator will think about the risk of booting a replica of a sensitive device, and the
  answer has to already be in the design.
- Only **HIGH and CRITICAL** findings are verified. Verifying 312 findings is pointless;
  verifying the nine that could get you owned is the product.
- Twin boot failure or an unsupported property degrades to **ASSERTED**. Never to a false
  DEMONSTRATED, and never to a false pass.
- A finding with no probe stays ASSERTED and the report says so. We never fake a proof.

## The self-test property

If the twin cannot reproduce a finding, that is a signal the parser mapped something incorrectly.
Run across the whole corpus, this package generates a measured precision figure for the entire
parsing cascade — the accuracy metric most projects never have, and it produces itself.
