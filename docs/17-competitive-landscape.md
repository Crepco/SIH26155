# 17 — Knowing the landscape

Vague references to *expensive vendor-locked tools* read as a student guessing at a market.
Naming the incumbents precisely, and stating exactly how we differ, reads as domain awareness —
and protects us if a well-informed judge raises one of them.

| Existing tool | What it does | Where we differ |
|---------------|--------------|-----------------|
| **Titania Nipper** | The actual commercial product in this exact category: multi-vendor configuration auditing with remediation | Open; learns vendors instead of hard-coding them; air-gapped; reasons across devices; proves findings |
| **Batfish** (open source) | Multi-vendor config parsing plus reachability and ACL analysis. Genuinely strong | Batfish does reachability but not compliance, cannot learn unseen vendors, and needs hand-written parsers. We can call it for hard reachability mathematics |
| **Tufin / AlgoSec / FireMon** | Enterprise firewall policy management and change automation | Vendor-locked, costly, and none verify their own recommendations against a live replica |
| **RANCID / Oxidized** | Configuration backup and versioning only | No compliance evaluation at all — complementary, not competing |
| **Nessus / OpenVAS** | Network vulnerability scanning against live hosts | Scans running services, not configuration intent. Requires reachability to production; we work from files, offline |
| **Ansible / NAPALM validate** | Configuration state assertion in a pipeline | Requires you to have written the expected state per vendor. That is the work we are eliminating |

## The honest summary

Nipper and Tufin tell you what is wrong. Batfish tells you what is reachable. **Nobody proves the
finding is real, or proves the fix is safe, before you touch production.** Every compliance tool
ever built ends its sentence at *this line violates CIS-NET-1.2.4*. That is an assertion, and it
is where we start rather than where we stop.

## Where we are genuinely weaker, and should say so

An evaluator who knows this market will trust us more for naming these than for claiming they do
not exist.

- **Vendor breadth.** Nipper supports far more devices at Tier 0 than six. Our answer is that the
  training loop makes breadth a data problem rather than a release-cycle problem — but on day one,
  their list is longer.
- **Reachability mathematics.** Batfish is years ahead on formal reachability analysis. We do not
  reimplement it; we call it where it helps.
- **Production maturity.** These are shipped products with support contracts. We are three weeks
  old. What we have is an architecture that can be extended without our involvement.

## Licensing caution worth stating in the architecture document

**CIS Benchmarks are copyrighted and licence-restricted.** Reproducing their text inside generated
reports has real licensing implications. DISA STIGs and NIST SP 800-53 are US government
publications and are far safer to quote.

We cite CIS control *identifiers* deterministically from our own rule metadata, and quote full
control text only from STIG and NIST sources. Evaluators at NTRO will notice that we thought about
this — and a team that has not will be visibly unprepared if asked.
