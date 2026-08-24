# Frontend

Next.js dashboard, training GUI and fleet graph view.

**Status: Phase 0. Structure only — implementation begins Phase 1, against mocked API contracts
frozen by 31 Aug.**

## Why this matters more than it looks

The training GUI is the artefact judges will physically touch. Requirement 2 in the problem
statement is a low-code GUI where an administrator maps unrecognised command lines to security
categories, with no backend redeployment. If that screen feels unfinished, the strongest backend
in the room does not rescue it.

## Screens

| Screen | Purpose | Phase |
|--------|---------|-------|
| Upload | Single file, bulk, folder, archive, tech-support bundle. Progress per device | 1 |
| Fleet posture | Compliance score across the fleet, by vendor, by severity, by framework | 1 |
| Device detail | Findings with line-cited evidence, the raw line in context, remediation CLI | 1 |
| **Training GUI** | Unrecognised lines grouped by similarity, proposed mapping with confidence, live preview of the extraction against the operator own file, confirm or correct | 2 |
| Adapter packs | Export, import, signature status, provenance of learned mappings | 2 |
| Fleet graph | Attack paths, ranked remediation, the one fix that severs the most paths | 3 |
| Reports | Generated PDFs, ledger status, verification hash | 3 |

## Design constraints

- **No CDN.** Fonts, icons and every asset are bundled. The build output must contain no reference
  to an external host — this is checked, not trusted. See [docs/11](../docs/11-air-gap.md).
- **Three finding states, three visual treatments.** DEMONSTRATED, ASSERTED and UNKNOWN are never
  collapsed into pass and fail. Grey is not green.
- **Coverage is always on screen**, never behind a tab. It is the number that makes the rest
  credible.
- **Projector legibility.** The fleet graph is a pitch centrepiece and will be seen from eight
  metres away on a badly calibrated projector.
- **Evidence is one click from any finding.** File, line number, raw text, in context.

## Stack

Next.js + React + Tailwind + shadcn/ui. Cytoscape.js or react-force-graph for the fleet view.
Streamlit is the documented fallback if frontend bandwidth collapses — a plain interface that
works beats a beautiful one that is half-built on demo day.
