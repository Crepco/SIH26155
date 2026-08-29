# Documentation index

Everything the team needs to build Crucible, and everything an evaluator needs to understand it.
Read in this order if you are new to the project.

## Start here

| Doc | What it answers |
|-----|-----------------|
| [01 — Problem statement](01-problem-statement.md) | What NTRO asked for, who will use it, and why the problem is genuinely hard. |
| [02 — Architecture](02-architecture.md) | The IR pivot, the six stages, and the five invariants. |
| [Glossary](glossary.md) | Every term of art used in this repository, defined once. |

## Contracts — frozen, changed only by team decision

| Doc | What it defines |
|-----|-----------------|
| [03 — IR schema](03-ir-schema.md) | The vendor-neutral normalised security baseline model. The single most consequential artefact in the project. |
| [04 — Rule format](04-rule-format.md) | How a compliance control is expressed as data, and the assertion language it may use. |
| [06 — Adapter packs](06-adapter-packs.md) | The portable, signed unit of learned vendor knowledge. |

## Subsystem specifications

| Doc | Subsystem | Track |
|-----|-----------|-------|
| [05 — Parsing cascade](05-parsing-cascade.md) | Tiers 0 to 3, coverage accounting, confidence scoring | A, C |
| [07 — Crucible sandbox](07-crucible-sandbox.md) | Digital twins, probes, the four-phase verification run | F |
| [08 — Fleet graph](08-fleet-graph.md) | Cross-device correlation and attack-path ranking | B |
| [09 — Ledger and signing](09-ledger-and-signing.md) | Hash chaining, Merkle roots, report signatures | E |
| [10 — Reporting](10-reporting.md) | Per-device PDF, remediation rendering, coverage disclosure | E |
| [11 — Air-gap constraints](11-air-gap.md) | What "offline" means operationally, and how it is enforced | F |

## Project management

| Doc | Contents |
|-----|----------|
| [12 — Execution plan](12-execution-plan.md) | Scope decision, phases, dates, definitions of done. |
| [13 — Technology stack](13-tech-stack.md) | Every dependency and the constraint that justifies it. |
| [14 — Risk register](14-risk-register.md) | What can kill this project and what we do about it. |
| [15 — Demo script](15-demo-script.md) | The rehearsed sequence for the finals, beat by beat. Describes the finished system. |
| [18 — Internal round runbook](18-internal-round-runbook.md) | How to set up, run and present **the build as it exists today** — with what must not be claimed. |
| [16 — Validation plan](16-validation-plan.md) | How we produce a real accuracy number instead of a claim. |
| [17 — Competitive landscape](17-competitive-landscape.md) | Nipper, Batfish, Tufin, AlgoSec, FireMon, RANCID — and where we differ. |

## Decision records

Architecture decisions that would otherwise be re-litigated every week live in
[adr/](adr/). One file per decision, never edited after acceptance — superseded instead.

## Submission artefacts

The problem statement requires five artefacts. Each is generated from the documents above.

| Artefact | Source |
|----------|--------|
| Source code link | This repository |
| README with setup instructions | [../README.md](../README.md) |
| Two-page architecture document | Distilled from [02](02-architecture.md) — lead with the IR pivot and the five invariants |
| Two-minute demo video | Scripted from [15](15-demo-script.md) |
| Five-slide technical presentation | Problem, architecture, differentiators, measured results, deployment path |
