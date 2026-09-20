# DISA STIGs

STIGs ship as machine-readable XCCDF XML, so one importer yields hundreds of real controls
instead of hand-typed ones. `crucible stig-import` reads XCCDF 1.1 and 1.2, from the XML or
straight from the zip DISA publishes.

```bash
crucible stig-import U_Cisco_IOS-XE_Router_NDM_V3Rx_STIG.zip \
  --bindings rules/stig/bindings/cisco-ios-xe-ndm.yaml \
  --out rules/stig/cisco-ios-xe-ndm.yaml
```

## Why an import is not the same as coverage

A STIG control is written for a human reviewer. Its check text is prose — *"in the presence of
the reviewer, the SA should enter the following command"* — not an expression over parsed facts.
Importing 300 controls and reporting them as evaluated would be the silent-pass failure this
project exists to prevent, wearing a compliance badge.

So an import produces two artefacts:

| Artefact | Contents |
|----------|----------|
| `<name>.yaml` | Rules for the controls a **binding** connects to an IR assertion. Evaluated like any other rule, carrying the STIG id, the Vuln id and the CCIs as framework identifiers. |
| `<name>.catalogue.json` | Every control in the benchmark, with its status: `evaluated` or `manual review - no binding to an IR assertion`. |

The count is reported both ways, every time:

```
BIND DNS STIG 4: 51 controls, 2 machine-checkable, 49 require manual review
```

## Writing a binding

Copy [`bindings/_template.yaml`](bindings/_template.yaml). Bind a control only after reading both
the control text and the IR field. A binding that approximates a control is worse than no binding,
because the report will claim a verdict the standard does not support.

## What is here today

No network-device binding set ships yet. The Cisco and Juniper NDM STIGs are distributed by DISA
as zips from `dl.dod.cyber.mil`, which the build environment could not reach; rather than guess at
control identifiers, the importer is shipped with its format verified against two **real** DISA
benchmarks (BIND 9 v4r1.16 and Mozilla Firefox v5r1, in `backend/tests/fixtures/xccdf/`), and the
binding file is left for whoever has the network STIG in hand.

That is a half-day of reading per benchmark, and it is the honest half-day.

## Framework identifiers

An imported rule carries `STIG:<stig id>`, `STIG-VULN:<vuln id>` and one `CCI:<cci>` per
identifier in the benchmark. `crucible audit --framework STIG` selects them, and the report groups
by the family name `DISA-STIG`.
