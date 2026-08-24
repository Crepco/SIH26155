# Security Policy

This project ingests network device configurations. A configuration file is a complete blueprint
of an organisation's defences: every ACL, every trust relationship, every management interface,
every credential hash. Treat the data as more sensitive than the code.

## Threat model in one paragraph

The intended deployment is an air-gapped, on-premises installation inside a
critical-infrastructure operator, auditing devices whose compromise would be nationally
significant. The adversary we design against is one who obtains a copy of the audit system, its
database, its reports, or its adapter packs — and one who can submit a crafted configuration file
as input.

## Non-negotiable properties

| Property | Rule |
|----------|------|
| **No egress** | No code path may contact a host outside the deployment. No telemetry, no update checks, no model downloads at runtime, no font CDNs in the frontend. |
| **No cloud inference** | Model inference is local only. A cloud LLM SDK in the dependency tree is a defect regardless of whether it is called. |
| **Configs never leave the deployment** | Uploaded configurations, parse artefacts and reports stay on the host. Export is an explicit, audited, user action. |
| **Adapter packs are signed** | A Vendor Adapter Pack is executable knowledge. Unsigned or signature-invalid packs are refused at import, not warned about. |
| **Reports are tamper-evident** | Findings are hash-chained, Merkle-rooted and signed. The verification hash is printed in the PDF. |
| **Twins are isolated and ephemeral** | Crucible containers run on an isolated bridge with no egress and are torn down after every run. A twin never reaches a production network. |
| **Secrets are redacted in output** | Credential hashes, SNMP community strings and pre-shared keys are matched, redacted and never printed into a report or a log. |

## Input handling

Configuration files are untrusted input. Parsers must survive:

- Files up to and beyond 40,000 lines without unbounded memory growth.
- Malformed, truncated and mixed-encoding input.
- Archive uploads containing path traversal entries, symlinks, and zip bombs.
- XML input (Junos, PAN-OS, XCCDF) — external entity resolution must be disabled. Use a hardened
  parser configuration; never the library default.

A parser that raises on hostile input is acceptable. A parser that returns PASS on input it did
not understand is a critical defect.

## Reporting a vulnerability

During the hackathon, report privately to a team member rather than opening a public issue.
Include the input that triggered it — reduced to the smallest reproducing case, with any real
device data removed.

## Out of scope

Findings that require an attacker to already have administrative access to the host running the
auditor. If they own the host, they own the audit.
