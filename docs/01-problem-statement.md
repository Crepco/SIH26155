# 01 — The problem, explained in full

Problem Statement **SIH26155** · National Technical Research Organisation ·
Software · Blockchain & Cybersecurity · Idea submission closes **20 September 2026**.

## 1.1 What the problem statement says

Modern enterprise and government networks are heterogeneous by necessity. A single organisation
runs firewalls from Palo Alto, Fortinet, Cisco and Check Point; switches and routers from Cisco,
Arista, Juniper, HPE Aruba and MikroTik; cloud-native security groups in AWS and Azure; and
increasingly white-box hardware running SONiC or Cumulus. The statement names roughly forty
vendors and then says explicitly that the list is *illustrative* — the tool must handle
configurations from vendors it has never seen.

Every one of those devices carries a configuration file, and every one of them is supposed to
comply with CIS Benchmarks, NIST SP 800-53, DISA STIGs and ISO/IEC 27001. Today an auditor either
works through a three-hundred-item checklist by hand, or buys an expensive vendor-locked
enterprise suite that only understands its own ecosystem.

NTRO wants the third option: a vendor-agnostic compliance engine that does **not** depend on a
hard-coded library of commands, because such a library becomes obsolete the moment a vendor ships
a firmware update. The engine should use pattern recognition and NLP to read a raw configuration,
map it onto a standardised internal schema, and evaluate that schema against whichever framework
the auditor selects. When it meets a structure it does not recognise, an administrator must be
able to **teach it through a GUI, with no backend code redeployment**.

## The five deliverables NTRO evaluates against

| Required component | What it means concretely |
|--------------------|--------------------------|
| 1. Unified Ingestion Engine | Single or bulk upload of configuration files from any device, through one dashboard. |
| 2. AI-Powered Training Module | A low-code GUI where an admin maps unrecognised command lines to security categories, and the engine learns. |
| 3. Multi-Framework Compliance Engine | Evaluate one parsed configuration against CIS, NIST, STIG or ISO without re-parsing. |
| 4. Actionable Intelligence & PDF Reporting | One PDF per device: device identity including serial and hardware, pass/fail with severity, and device-specific step-by-step remediation CLI. |
| 5. Vendor-Agnostic Scalability | Modular architecture supporting new vendors, standards and OS versions with no manual code changes. |

Submission artefacts are equally explicit: a source code link, a README with setup instructions, a
two-page architecture document, a two-minute demo video, and a five-slide technical presentation.
Every artefact should visibly map back to those five components — evaluators are almost certainly
scoring against that exact list.

## 1.2 Who is asking, and why it changes the design

NTRO is India's technical intelligence agency. NCIIPC — whose contact address appears in the
problem statement's own dataset field — sits under it and protects critical information
infrastructure: power grids, banking, telecommunications, transport and government networks.

That single fact drives half of our design decisions. A network device configuration is a
complete blueprint of an organisation's defences: every ACL, every trust relationship, every
management interface, every credential hash. For an NCIIPC-protected network, uploading that file
to a commercial LLM API hosted in another jurisdiction is not a policy preference to be weighed —
it is a hard disqualifier.

> **Design consequence.** The system must run fully air-gapped: a local quantised model, local
> embeddings, zero outbound network calls. This is not an enhancement bolted on at the end. It is
> the operating environment, and building for it from day one is the clearest signal we can give
> that we understood the customer and not merely the spec.

## 1.3 Why the problem is genuinely hard

### Syntactic diversity

One security intention — disable Telnet, enforce SSH, set a ten-minute idle timeout — on four
platforms. Same meaning, four incompatible grammars, four vocabularies.

    CISCO IOS                        block-structured, "!" separators
      no ip telnet server
      ip ssh version 2
      line vty 0 4
       transport input ssh
       exec-timeout 10 0

    JUNIPER JUNOS                    curly-brace hierarchy
      system {
          services { ssh { protocol-version v2; } }
          login    { idle-timeout 10; }
      }

    FORTINET FORTIOS                 config / edit / set / next / end
      config system global
          set admintimeout 10
          set admin-telnet disable
      end

    MIKROTIK ROUTEROS                flat, path-prefixed commands
      /ip service set telnet disabled=yes
      /ip service set ssh port=22

Palo Alto PAN-OS is XML. SONiC is a JSON document. AWS is an API response. There is no shared
tokeniser, no shared hierarchy, no shared vocabulary: Cisco calls it `exec-timeout`, Fortinet
calls it `admintimeout`, Juniper calls it `idle-timeout`. A regex written for one is worthless on
the others.

### Scale and drift

- A production firewall configuration routinely runs to **forty thousand lines or more**. It does
  not fit in a language model's context window, and even if it did, attention over forty thousand
  lines of near-identical ACL entries is unreliable.
- Vendors change syntax between firmware versions. A parser hard-coded in September is wrong by
  March.
- Serial numbers and hardware details — which the statement explicitly requires in the report —
  are usually **not present in the running configuration at all**. They live in `show version`
  output. Ingestion must accept a bundle of files or a tech-support archive, not a single config
  file. Many teams will miss this and fail a stated deliverable.

## 1.4 What most teams will build, and why it fails

The predictable submission: an upload box, the whole configuration pasted into a prompt saying
"check this against CIS benchmarks and list the violations", the reply rendered as a table, a PDF
export. It demos acceptably for four minutes and collapses under the first serious question.

| Failure | Why it is fatal for an audit tool |
|---------|-----------------------------------|
| Non-deterministic | Run it twice, get two different answers. An audit that is not reproducible is not an audit. |
| Hallucinated findings | Cites control IDs that do not exist; flags lines not in the file. In compliance, a confident wrong answer is worse than no answer. |
| Context limits | Real configurations do not fit. The model silently sees a fraction of the device. |
| Silent false passes | Anything the parser misses quietly reports PASS. An auditor signs off on a device that was never hardened. |
| Undeployable | Sends critical-infrastructure configurations to a third-party API. NTRO cannot use it at any price. |

Each of those five is an opening. Our architecture is designed so that none of them can occur —
not mitigated, but structurally impossible. See [02 — Architecture](02-architecture.md).
