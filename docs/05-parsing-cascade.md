# 05 — The parsing cascade

**Owner: Track A (Tier 0) and Track C (Tiers 1 to 3).**

This is where the "AI" in the problem statement actually lives — and where most teams will put a
prompt instead. The cascade exists so that the model is invoked on a tiny fraction of a file,
never returns a verdict, and never sees enough text to hit a context limit.

## The four tiers

    raw configuration bundle
            |
    Tier 0  known vendor -> deterministic parser
            ciscoconfparse2, TextFSM + ntc-templates, lxml for Junos and PAN-OS XML,
            custom block and flat-command parsers for FortiOS and RouterOS
            | lines that no Tier-0 handler claimed fall through
            v
    Tier 1  structural inference -> generic configuration tree
            detect brace / indent / flat-command grammar, build a tree with no
            semantics attached. Deterministic. No model involved.
            | nodes whose MEANING is still unknown fall through
            v
    Tier 2  lexical retrieval, or a local model, PROPOSES A MAPPING
            "set admintimeout 10"  ->  mgmt.idle_timeout_min   (confidence 0.86)
            output is a candidate extraction rule, never a pass or a fail
            | proposals below the confidence threshold fall through
            v
    Tier 3  interactive training GUI -> administrator confirms or corrects
            persisted as a signed Vendor Adapter Pack (YAML)
            on the next run this line is handled at Tier 0

The direction of travel matters: every line that Tier 3 resolves becomes a Tier 0 line forever
after. The system gets cheaper and more deterministic the more it is used.

## Tier 0 — deterministic parsers

Six vendors are in scope for the submission: Cisco IOS, Juniper Junos, Fortinet FortiOS, Arista
EOS, Palo Alto PAN-OS, MikroTik RouterOS. The other thirty-four named vendors are handled by the
training loop, which is the point of the exercise rather than a gap in it.

A Tier-0 parser has exactly two obligations: write facts into the IR with provenance, and account
for every line it consumed. It may not guess, and it may not skip.

## Tier 1 — structural inference

Before any model runs, we try to understand the *shape* of an unknown file. Three grammars cover
almost everything in this domain:

| Grammar | Signature | Examples |
|---------|-----------|----------|
| Brace-delimited hierarchy | balanced `{` `}`, statements ending `;` | Junos, some Nokia |
| Indentation or marker blocks | leading whitespace depth, `!` or `end` separators | Cisco IOS, Arista EOS, FortiOS |
| Flat path-prefixed commands | every line begins with a path token such as `/ip` | MikroTik RouterOS |

XML and JSON are detected before this stage and parsed structurally, never as text.

Tier 1 produces a tree with no meaning attached. That is deliberate: a tree with known structure
and unknown semantics is a far better prompt for Tier 2 than raw text, and it costs no inference.

## Tier 2 — the model proposes, never decides

The model receives a small, structured task: here is a node from an unknown configuration, here
are the IR fields that similar nodes mapped to on other vendors, propose a field mapping and an
extraction expression, with a confidence score.

What comes back is a **candidate extraction rule**. It is then applied deterministically to the
raw text, and the resulting value is what enters the IR — with provenance recording tier 2 and
the confidence. The verdict still comes from the policy engine operating on that parsed fact.

Embeddings do the transfer learning: a command learned on Vendor A produces a nearby vector for a
structurally similar command on Vendor B, so the model is given real precedent rather than being
asked to invent a mapping from nothing.

Three properties fall out of this design and each answers an obvious challenge:

- **Context limits never bite.** The model sees individual unresolved nodes, never a 40,000-line
  file.
- **A 7B quantised model on a laptop is viable.** It runs on the small residue that survived Tiers
  0 and 1.
- **Non-determinism cannot reach the verdict.** Even if the model proposes something different on
  a second run, the proposal is a parser, the parser is applied deterministically, and low
  confidence goes to a human rather than into a report.

## Tier 3 — the training GUI

The deliverable NTRO named explicitly. Unrecognised lines are surfaced verbatim, grouped by
similarity so an administrator maps a family at a time rather than a line at a time. The admin
picks a target field, sees the proposed extraction applied live against their own file, and
confirms.

The result is persisted as a Vendor Adapter Pack — signed, portable, importable elsewhere. See
[06](06-adapter-packs.md).

## Coverage accounting

Built into the first parser, never retrofitted.

    parsed_lines + unparsed_lines == total_lines        for every device, always

A test asserts this over every fixture in the corpus. Per-tier attribution is recorded so the
report can state not only how much was understood but by which mechanism — a Tier 2 or Tier 3
fact is honestly weaker evidence than a Tier 0 fact, and the report says so.

## Confidence thresholds

| Confidence | Behaviour |
|------------|-----------|
| High | Mapping applied, recorded as tier 2, flagged for review in the coverage appendix |
| Medium | Mapping applied but the affected findings are capped at ASSERTED and listed for confirmation |
| Low | Not applied. The line is surfaced in the training GUI and counted as unparsed |

Thresholds are configuration, not constants in code, and the values chosen are printed in the
report so an auditor can see the posture the tool was run with.
