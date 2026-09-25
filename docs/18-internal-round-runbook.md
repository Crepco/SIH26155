# 18 — Internal round runbook

**For the build as it exists today.** Every command here has been run and every claim is
something the code actually does.

> [15 — Demo script](15-demo-script.md) is the *finals* script, for a longer slot. Everything it
> shows — live vendor training, the fleet attack-path graph, `crucible verify` against a booted
> twin — is now built. This document is the five-minute version, and the twin beat here is
> optional because it is the one thing that needs a Docker daemon on the presenting machine.

---

## Part 1 — Setup

One-time, on the machine you will actually present from. Not a borrowed laptop.

```bash
git clone https://github.com/Crepco/SIH26155.git
cd SIH26155

python --version          # must be 3.11 or newer
pip install -r backend/requirements.txt
```

That is the whole install. Seven packages, no build step, no database, and no Docker unless you
intend to show the twin.

### Verify the machine is ready

```bash
cd backend
python tests/run_tests.py
```

Expect `227 passed`. If anything fails, stop and fix it — do not present a red suite.

---

## Part 2 — Pre-flight, the morning of

Run this once, then **delete the output** so the demo starts clean:

```bash
cd backend
python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports
python -m crucible.api.cli verify ../reports/ledger.jsonl
rm -rf ../reports          # Windows: rmdir /s /q ..\reports
```

Checklist:

- [ ] `227 passed` from the test suite.
- [ ] The audit prints six devices and exits with code `1`.
- [ ] `verify` prints **INTACT**.
- [ ] `../reports` deleted, so nothing is stale on stage.
- [ ] Two terminals open, font size at least 16pt, in the `backend` directory.
- [ ] Browser open at a blank tab, zoom 110–125%.
- [ ] `reports/ledger.jsonl` will be opened in your editor during beat 4 — know where it is.
- [ ] Wi-Fi toggle reachable in one click from the taskbar.
- [ ] Recorded fallback video open in a third window.

---

## Part 3 — The demo, five minutes

Two terminals: **T1** for the console server, **T2** for commands.

### Beat 0 · 0:00–0:30 · The stakes

One slide, no demo yet.

> "Most networks are not breached through zero-days. They are breached through a device somebody
> configured wrong four years ago and nobody has read since. An auditor's job is to find those,
> across forty vendors that all speak different languages. Today that is a person with a
> three-hundred-item checklist."

### Beat 1 · 0:30–1:15 · Pull the plug first

Do this **before** anything else. It reframes everything that follows.

**Turn off Wi-Fi, visibly.** Say what you are doing. Then, in **T1**:

```bash
cd backend
python -m uvicorn crucible.api.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Click **Audit the sample fleet**.

> "That is six real configurations from six vendors — Cisco, Arista, Fortinet, Juniper,
> MikroTik, Palo Alto. Parsed, scored, and signed in about a second, with the network off. There is no cloud
> model in this system and no outbound call in any code path. That is not a preference. The
> customer is NCIIPC — a device config is a blueprint of a national network's defences, and
> sending it to an API in another country disqualifies the tool before anyone reads the features."

### Beat 2 · 1:15–2:30 · The evidence gutter — your strongest moment

Click **core-sw-01** in the fleet rail, then expand **CIS-NET-1.1.1 (Telnet)**.

Point at the excerpt on screen.

> "Every other team here will show you an AI that says 'this device looks insecure.' Here is what
> we show instead: line 102 of the running config, in its own vty block, with the offending line
> marked. You can open the file and check.
>
> The model in this system never decides pass or fail — in fact this build has no model in the
> verdict path at all. Rules are YAML, evaluated against parsed facts. Run it twice, get the same
> answer twice. An audit that is not reproducible is not an audit."

Now scroll up to **COVERAGE** and point at it.

> "163 of 164 lines read. One line we could not interpret, and it is listed at the bottom of this
> page, verbatim. No commercial tool volunteers that number. Every uninterpreted line is a control
> we did *not* evaluate — not one that quietly passed."

Then click the **UNKNOWN** filter chip.

> "This is the part I would most like you to remember. Two states force a tool to lie: everything
> it failed to understand becomes a pass. We have three. Grey is not green."

### Beat 3 · 2:30–3:15 · A report you can act on

Scroll to **REMEDIATION**.

> "Three phases, and the order is the point. Phase 0 turns SSH on. Phase 2 turns Telnet off.
> Phase 3 narrows who can reach the management plane, last, when there is already a safe path in.
>
> The reason administrators ignore compliance reports is not laziness. It is that pasting three
> hundred untested commands into a live core switch is scarier than the findings. If your fix
> disconnects the operator, they will never run your tool again."

Open `reports/cisco-ios-core-01.pdf`. Show page 1 (identity + serial), then the footer.

> "Serial number FDO1234ABCD. That is not in the running config — it is in `show version`, so we
> ingest bundles, not single files. Every page carries a verification hash."

### Beat 4 · 3:15–4:15 · Break it on purpose

This is the *Blockchain & Cybersecurity* half, and it is a live proof rather than a slide.

In **T2**:

```bash
python -m crucible.api.cli verify ../reports/ledger.jsonl
```

> "Six entries, chain intact, signature verified."

Now **open `reports/ledger.jsonl` in your editor, on screen**, and change one character in the
second entry — flip a digit in `merkle_root`. Save. Do it by hand where they can see it; running
a script here is far less convincing.

```bash
python -m crucible.api.cli verify ../reports/ledger.jsonl
```

> "Signature fails on the entry I edited, and the next entry's link to it breaks. Each entry
> commits to the hash of the one before, so you cannot quietly revise a past audit — you would
> have to forge the issuing key.
>
> We did not bolt a blockchain onto this. There is one writer and no peers, so a consensus
> protocol would add operational weight and no integrity. Merkle chaining plus signing is the
> honest engineering answer, and being able to say why is worth more than a chain nobody can run."

Restore the file:

```bash
git checkout -- . 2>/dev/null; rm -rf ../reports
python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports
```

### Beat 5 · 4:15–5:00 · What is built, and what is not

Put this on a slide. Say it plainly.

> "What you just saw is real and runs offline: ingestion, six vendor parsers, the vendor-neutral
> IR, the rule engine, line-cited reports, the signed ledger — and the three things we said last
> time were only specified. It learns a vendor it has never seen, from an administrator, and
> ships that as a signed pack. It correlates a fleet into attack paths. And it boots a disposable
> twin to prove a finding before you touch production. 227 tests, including one that fails the
> build if any asset on that page tries to reach the internet.
>
> Two things are honestly open. Our accuracy numbers — precision 1.00, recall 0.90 — come from
> six configurations we labelled ourselves, and **nobody outside this team has reviewed those
> labels**. And the corpus is six fixtures, not the sixty real configurations we want. Both are
> measurement problems, not engineering ones, and the tool prints that caveat itself rather than
> waiting for us to remember.
>
> We would rather hand you the limits of our own numbers than have you find them."

---

## Part 4 — Things you must not say

Getting caught overclaiming is worse than any missing feature.

The list has changed shape. Tiers 1–3, the fleet graph and Crucible are all built now, so those
claims are safe to make. What replaced them is subtler, and easier to say by accident.

| Do not say | Because | Say instead |
|---|---|---|
| "It learns new vendors automatically" | An administrator confirms every mapping. That gate is the design, not a limitation — an unattended parser-writer is exactly what an auditor could not trust. | "An administrator teaches it a vendor in minutes, without us shipping code." |
| "Precision is 100%" | True of the number, misleading about its weight. Six configurations, and **the labels have not been reviewed by a person**. | "1.00 precision on six hand-labelled configs — our own labels, not yet reviewed. It is a starting point, not a benchmark." |
| "We tested it on sixty real configurations" | `corpus/raw` is empty. Every number comes from the six shipped fixtures. | "Six fixtures today. Scaling the corpus is the open work, and `make corpus` prints the real count." |
| "We support forty vendors" | Six Tier-0 parsers. The answer to the other thirty-four is the training loop, which is a better answer — use it. | "Six properly, and a way to add the seventh without code." |
| "300+ STIG controls" | The importer is real and works on real DISA benchmarks, but the repository ships 13 hand-authored CIS rules. | "13 controls across four frameworks, plus an importer that ingests a DISA benchmark." |
| "Every finding is proven on a twin" | Only HIGH and CRITICAL findings get a twin, only where Docker is present, and only some are demonstrated. | "Findings we can prove are marked DEMONSTRATED; the rest stay ASSERTED, and the report says which." |

The framing that works for all of these: **give the number, then give its limit, unprompted.** An
evaluator who finds the limit themselves stops believing the number. One who is handed it starts
believing the rest.

---

## Part 5 — Questions you will get

**"Where is the AI? This looks like regexes."**
> "Correct on the audit you just watched, and that is the architecture rather than a gap. The AI
> writes *parsers*, never verdicts — it proposes a field mapping for a line no deterministic
> parser claimed, and that mapping is applied deterministically. Six vendors are handled at tier
> 0, so on those the model layer has nothing to do. Show me a vendor we do not parse and you will
> see it work. ADR 0004."
>
> Then open the TRAIN view, or run `propose --hold-out mikrotik`. Held out that way it recovers
> **9 of 9 fields** with the local Qwen2.5-Coder-7B, and 7 of 9 with the deterministic proposer
> and no model at all. Both numbers are worth giving: the second is what a customer without a
> GPU gets, and it still works.
>
> If asked why the model is off by default: "because an audit has to give the same answer twice.
> A model that gets picked up merely because it happens to be running would make two machines
> disagree about the same configuration. You turn it on deliberately."

**"Why is so much UNKNOWN? That looks like it failed."**
> "It is the feature. Those are controls where the configuration genuinely does not say. Every
> other tool reports those as passes. Turn it around: would you rather a report that says 91%
> compliant, or one that says 'I read 99% of this file and here are the four things I could not
> determine'?"

**"Only 13 rules?"**
> "Hand-authored, each mapped to four frameworks, each with per-vendor remediation and evidence,
> and each checked against labelled ground truth. The scaling answer is the XCCDF importer, which
> is built: point it at a DISA benchmark and those controls load into the same engine. We spent
> the time on the format and the evidence, not the count — a hundred controls nobody validated
> would be a worse artefact, not a better one."

**"How do I know the AI didn't invent a finding?"**
> Re-open the evidence gutter. "File, line number, raw text — and there is no model in the verdict
> path at all. A proposal can only ever change how a line is *read*; the verdict comes from the
> rule. Where Docker is available we go further and prove it on a twin, which is what
> DEMONSTRATED means on that report."

**"What if the config is 40,000 lines?"**
> "Coverage accounting is per line and the parsers are single-pass. Context limits never bite us
> because the model only ever sees individual unresolved lines, never the file. A sixty-device
> fleet audits in seconds, and one unreadable device does not take the other fifty-nine with it."

**"Is this just a wrapper around ciscoconfparse / Batfish?"**
> "No dependency on either, and none in the tree — the parsers and the graph are ours. Batfish
> solves harder reachability maths than we do, and for deep L3 analysis we would call it rather
> than reimplement it. Nipper is the commercial product in this exact category; docs/17 says
> precisely where we differ and where we are weaker."

**"Why not just use ChatGPT?"**
> "Because the customer cannot. And because a compliance verdict has to be identical on two runs."

---

## Part 6 — If it breaks

- **Server will not start** — port 8000 in use. `--port 8010` and reload the tab.
- **Console is blank** — hard refresh (Ctrl+Shift+R). If still blank, drop to the CLI: the audit
  command prints the same findings with the same citations. Nothing is lost but polish.
- **Anything else** — go to the recorded video and say *"this is why we record it."* That is a
  perfectly good line. Do not debug on stage.

The CLI is the durable fallback for the entire demo. It needs no browser, no server and no port:

```bash
python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports --all
```

---

## The one line to leave them with

> "Every team here can tell you what is wrong with a firewall. We can show you the line, prove we
> read the whole file, order the fix so it will not lock you out, and sign the report so it cannot
> be quietly edited afterwards — with the internet off."
