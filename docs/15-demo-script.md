# 15 — Demo script

Internal rounds are won on clarity and one memorable moment, not on feature count. Rehearse this
exact sequence, with a recorded fallback. Live demos die.

## The run of show

| Time | Beat | What happens |
|------|------|--------------|
| 0:00–0:20 | The stakes | One slide. *Misconfiguration, not zero-days, is how most networks fall.* |
| 0:20–0:50 | Bulk ingest | Drag in 12 configs from 6 vendors at once. Fleet compliance score populates. Establishes scale immediately |
| 0:50–1:30 | Drill into one device | Show a finding with line-cited evidence and the vendor-specific fix. Say: *no hallucinated findings — every finding points at a line number* |
| **1:30–3:00** | **The moment** | **Kill the internet, visibly.** Feed in an unseen vendor. It flags unknown blocks honestly. Train four lines in the GUI. Re-run — clean audit. Export the adapter pack, import into a second instance, audit again. Still offline |
| 3:00–3:45 | Prove it | `crucible verify` — twin boots, telnet connects, banner appears on screen. FINDING CONFIRMED. Apply fix. Connection refused. FINDING CLOSED. Regression: no lockout |
| 3:45–4:15 | The network view | Fleet graph. *These three devices are individually compliant. Together they expose the core. Here is the one fix that severs 47 paths* |
| 4:15–4:35 | The artefact | Open the generated PDF. Signed, hash-verified, with the before/after projection and the coverage figure |

## The one line to say on stage

> Every team here can tell you what is wrong with this firewall. We are the only ones who can
> prove it, fix it, and prove the fix did not break anything — with the internet unplugged.

## Narration notes

- **Do not explain the architecture during the demo.** The architecture slide comes before or
  after. During the demo, narrate consequences: what an attacker gets, what an administrator does.
- **Say the coverage number out loud.** *We understood 98.1 per cent of this file and here are the
  255 lines we did not.* No competing demo will volunteer a weakness, and volunteering it is
  exactly what makes the rest credible.
- **When the plug comes out, stop talking for two seconds.** Let the room notice.
- **Never say the model decided something.** The model proposed a mapping; the engine decided.
  That distinction is the whole submission and it must be in the vocabulary of everyone on the
  team, not just the presenter.

## Preconditions checked before walking on

- Containers pre-booted and warm. A cold VyOS boot on stage is thirty seconds of silence.
- The unseen vendor file is one nobody has run through the tool before, and it is on the machine
  already, not on a USB stick.
- The second instance for the adapter-pack import is already running and visible.
- Airplane mode toggle is on the taskbar, not buried in a settings dialogue.
- Recorded fallback video is open in a second window, one alt-tab away.
- Demo machine, not a borrowed one. Rehearsed twice on that exact machine.

## The failure plan

If the twin does not boot, say so, and go straight to the recorded run. *This is why we record
it* is a perfectly good line, and it is far better than eight seconds of clicking. The fleet graph
and the PDF are both stateless and always work; if anything else fails, move to them.
