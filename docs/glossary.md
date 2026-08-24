# Glossary

Defined once here, used consistently everywhere else.

**Adapter pack** — A signed, portable YAML file describing one vendor's grammar and its field
mappings into the IR. Produced by the training loop, exportable between deployments. The network
defence equivalent of a Sigma rule or a Suricata feed. See [06](06-adapter-packs.md).

**ASSERTED** — A finding state. The rule matched against parsed facts, but the property is not
runtime-testable or the twin could not model it. Honest, and clearly weaker than DEMONSTRATED.

**Attack path** — A chain across two or more devices that reaches a sensitive asset, where no
single device on the chain necessarily fails its own benchmark.

**Blast radius** — Phase 4 of a verification run: what a remediation breaks. BGP session still
up, users VLAN still reaching the internet, syslog still flowing, management still reachable.

**Coverage** — Parsed lines divided by total lines, per device, published in every report.
The number we volunteer and commercial tools hide.

**Crucible** — The verification sandbox, and the project's name. A disposable digital twin that
demonstrates the finding, applies the fix, re-tests, and checks for collateral damage.

**DEMONSTRATED** — A finding state. The vulnerability was reproduced live against a twin and the
proof artefact — probe command, response, packet capture — is attached to the finding.

**Digital twin** — An ephemeral, network-isolated container rendered from the IR that reproduces
the audited device's *security properties*, not its feature set.

**Fingerprinting** — Determining vendor, model, OS version and serial number from an uploaded
bundle. Serial usually lives in `show version` output, not in the running configuration.

**IR — intermediate representation** — The vendor-neutral normalised security baseline model.
Parsers write into it; rules, reports, remediation, graph analysis and Crucible read only from it.
Think LLVM IR for network security posture. See [03](03-ir-schema.md).

**Probe** — A single runtime test executed against a twin: telnet reachability, weak SSH KEX,
default SNMP community, exposed HTTP management, ACL bypass, session timeout, NTP authentication.

**Render target** — A backend that turns IR into a concrete artefact. Cisco IOS CLI, Junos CLI,
FortiOS CLI are remediation render targets; VyOS is the twin render target.

**Rule** — One compliance control expressed as data: an identifier, framework mappings, a
severity, an assertion over the IR, a rationale, and per-vendor remediation. Never Python.

**Shadowed ACE** — A permissive access-control entry earlier in a list that prevents a later
restrictive entry from ever firing. The restrictive rule exists, so a checklist passes; it never
fires, so the network is open.

**Tier 0 / 1 / 2 / 3** — The four stages of the parsing cascade: deterministic parser, structural
inference, local-model mapping proposal, human confirmation via the training GUI.

**UNKNOWN** — A finding state. The engine could not interpret the relevant configuration, so it
refuses to claim either pass or fail. Never silently a PASS.

**XCCDF** — The machine-readable XML format DISA publishes STIGs in. One importer yields hundreds
of real controls instead of forty hand-typed ones.
