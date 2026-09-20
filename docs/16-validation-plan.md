# 16 — Validation plan

How we produce a real number instead of a claim. Most hackathon projects cannot answer *how
accurate is it?* — this one can, because the ground truth is built in Phase 0 before there is any
code to be distracted by.

> ## Results, 21 September 2026
>
> Run it yourself: `crucible validate --labels corpus/labels/fixtures --devices tests/fixtures/devices`
>
> | | Planned | Actual |
> |---|---|---|
> | Labelled configurations | 20 | **6** |
> | Precision | — | **1.00** (37 true, 0 false positives) |
> | Recall | — | **0.90** (0 missed as PASS, 4 missed as UNKNOWN) |
> | Fact accuracy | — | **1.00** (53/53) |
> | Verdict agreement | — | 0.95 |
> | Citation agreement | — | 0.77 (another line may justify the same fact) |
> | Mean coverage | — | 98.1% |
> | UNKNOWN rate | — | 0.23 |
>
> **Two limits, stated before anyone asks.** The corpus is six shipped fixtures, not twenty real
> configurations — `corpus/raw` is empty, and `make corpus` prints that count rather than a
> claim. And **the labels were written with AI assistance and have not been reviewed by a
> person**, so every figure above is provisional. The tool prints that caveat itself on every
> run, which is the only way a caveat survives contact with a slide deck.
>
> Measuring was worth more than the number. It found four real bugs that inspection had not: an
> assertion stricter than its own rule title, Arista eAPI assumed to be plaintext when it
> defaults to HTTPS, and NTP and Junos services that needed a closed-world reading. Precision
> reached 1.00 by fixing those, not by adjusting the labels.
>
> Sections 1, 2, 3 and 7 are done. Section 4 runs on demand rather than across a corpus.
> Sections 5 and 6 are not done: nobody outside the team has read a generated PDF cold.

## 1. Multi-vendor consistency

Run the same control — *disable Telnet, enforce SSHv2* — across four vendors and confirm identical
pass/fail semantics.

This is the test that proves the IR is doing its job. If the same security intention produces
different verdicts on Cisco and Junos, the normalisation is wrong and every downstream claim is
built on sand.

**Pass criterion:** identical verdict and identical cited-evidence structure across all four, for
every control that applies to all four.

## 2. Unseen-vendor generalisation

Hold one vendor out of the build entirely. Feed it in live. Train it through the GUI. Export the
pack, import it into a second instance, audit the same file again.

This is the single most convincing proof that the AI claim is real rather than marketing, and it
is the Phase 2 definition of done for exactly that reason.

**Pass criterion:** under three minutes from cold file to clean audit, with the trained mappings
surviving export and import.

## 3. Ground-truth accuracy

Precision and recall against the 20 hand-labelled configurations. Quote the number, whatever it
is.

| Metric | Definition here |
|--------|-----------------|
| Precision | Of the findings we reported, the fraction that a human labeller agrees are real |
| Recall | Of the violations a human labeller found, the fraction we reported |
| Coverage | Parsed lines over total lines, per device |
| UNKNOWN rate | Findings we honestly refused to decide |

A high UNKNOWN rate is not a failure. Hiding it would be.

## 4. Sandbox cross-check

Every finding the twin fails to reproduce is a parser bug. Run Crucible across the whole corpus
and track the reproduction rate as a quality metric over time.

This is the property that makes the sandbox pay for itself twice: it proves findings for the
customer, and it audits our own parser for us — automatically, across the whole corpus, without
anyone writing a test.

## 5. Framework fidelity

Validate a sample of rule interpretations against the published control text, and cite control
identifiers in the report so the mapping is demonstrably grounded in the real standard rather
than in our idea of it.

## 6. Cold-read usability

Hand a generated PDF to someone unfamiliar with the project. If they cannot act on the
remediation without narration, the report has failed its actual purpose — regardless of how
correct it is.

Run this with a person who was not in the room when it was built. Twice.

## 7. Air-gap verification

The full audit pipeline runs in CI with no route to anything but loopback. If a code path tries
to resolve or connect, the job fails. This runs from Phase 1, not from September.

## What we will report

One table, in the deck and in the architecture document:

    devices audited          N
    vendors covered          N (6 Tier-0, N via adapter packs)
    controls evaluated       N (CIS hand-authored + STIG imported)
    mean coverage            NN.N%
    precision / recall       N.NN / N.NN   against 20 labelled configs
    findings demonstrated    N of N high/critical, live against twins
    mean verify time         N.N s per finding, offline

Every one of those numbers is produced by a script that can be re-run in front of a judge. None
of them is an estimate.
