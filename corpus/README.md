# Configuration corpus

Sixty-plus real configuration files across eight-plus vendors, and twenty of them hand-labelled.
Built in Phase 0, before there is any code to be distracted by.

> **Do not demo on synthetic toy configs. Evaluators can tell.**

## Layout

    corpus/
      raw/       real configurations, GITIGNORED - pulled locally, never pushed
      labels/    hand-labelled ground truth, checked in
      MANIFEST.md   what we have, where it came from, licence

`raw/` is gitignored on purpose. A configuration file is a blueprint of a network defence; even
from a lab device, the habit of not committing them is the habit worth having. Each engineer
populates `raw/` locally from the sources below.

## Where the configs come from

| Source | Vendors | Notes |
|--------|---------|-------|
| containerlab | Arista cEOS, Nokia SR Linux, FRR, SONiC, VyOS | All on one laptop. See [`labs/`](../labs/) |
| VMs | MikroTik CHR, pfSense | Free, and both have genuinely different grammars |
| Cisco DevNet always-on sandboxes | Cisco IOS, IOS-XE, NX-OS | Real devices, publicly available |
| ntc-templates test fixtures | Many | Show-command output, which is where serial numbers live |
| Public config dumps on GitHub | Many | Check the licence before committing anything derived |

## Ground truth

Twenty configurations, hand-labelled by the team. There is no substitute and no shortcut: without
this we can never state an accuracy number, and a project that cannot answer *how accurate is it*
loses to one that can.

A label file records, per configuration: the expected IR facts for each control in scope, the
expected verdict, and the line that justifies it. Precision and recall in
[docs/16](../docs/16-validation-plan.md) are computed against these files.

## Rules for adding to the corpus

1. **Never commit real customer data.** If provenance is uncertain, it does not go in.
2. **Redact before sharing.** Addresses, hostnames, community strings and credential material are
   replaced consistently — consistently, because the fleet-graph correlations depend on identical
   values staying identical.
3. **Record the source** in `MANIFEST.md`, including licence and date.
4. **Prefer files with quirks.** A perfectly clean config teaches the parser nothing. Vendor
   version drift, mixed indentation, truncated output and stray banners are the point.
5. **Bundle the show output** with the config where possible. Serial and hardware are required by
   the report and are not in the running configuration.
