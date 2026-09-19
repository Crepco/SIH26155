# Demo video: two-minute script

**Target length: 1:50.** The limit is 2:00, and the extra ten seconds cover pauses. The voice-over is about
240 words, a calm pace.

Everything shown here exists and runs today. Do **not** show or imply live vendor training, the fleet
graph or a Crucible twin (see [docs/18](../18-internal-round-runbook.md) Part 4). The closing card
names them as next phases, and that is all.

---

## Before you record (10 minutes)

1. **Fresh reports** so the tamper beat is clean. From `backend/`:
   ```bash
   python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports
   python -m crucible.api.cli verify ../reports/ledger.jsonl        # must say INTACT
   ```
2. **Start the server** in a terminal you won't show:
   `python -m uvicorn crucible.api.main:app --host 127.0.0.1 --port 8000`
3. **Browser** at <http://127.0.0.1:8000>, zoom 125%, bookmarks bar hidden, no other tabs. Do **not**
   click *Audit the sample fleet* yet.
4. **Second tab** at <http://127.0.0.1:8000/reports/cisco-ios-core-01.pdf>. It only exists after the
   sample audit, so open it just after beat 2 while off-camera, or pause the recording.
5. **Terminal** in `backend/`, font 18pt or more, cleared, with only the two `verify` commands ready in history.
6. **Editor** with `reports/ledger.jsonl` open, word wrap on, and the cursor on line 2 near `"merkle_root"`.
7. **Wi-Fi off** before recording. The taskbar icon must be visible in the frame.
8. Notifications off (Windows Focus / Do Not Disturb). 1920×1080.

**Recording:** OBS (Display Capture, 1080p30), or Win+Alt+R with Xbox Game Bar for the active
window. Record the voice-over separately if the room is noisy, and cut to it. Record each beat as its
own clip; they are easier to trim than one take.

---

## The script

| Time | Screen | Voice-over |
|------|--------|-----------|
| **0:00–0:12** | Title card: **CRUCIBLE · Compliance you can prove** · SIH26155 · NTRO. | "Most networks aren't breached through zero-days. They're breached through a device someone configured wrong years ago, and nobody has read that config since. Crucible reads it for them." |
| **0:12–0:30** | Zoom on the taskbar: **Wi-Fi off**. Cut to the console, click **Audit the sample fleet**. The fleet list fills with five devices and their scores. | "The network is off. That's five real configurations from Cisco, Arista, Fortinet, Juniper and MikroTik, parsed, scored and signed in about a second. There's no cloud model and no outbound call, because a config is a blueprint of a network's defences and it never leaves the machine." |
| **0:30–0:52** | Click **core-sw-01**. Expand **CIS-NET-1.1.1 Telnet**. Hold on the evidence gutter with **line 102** marked. | "Every finding points at a line. Here's Telnet enabled on the management lines: line 102 of the running config, shown in place. The verdict comes from rules written as data, evaluated against parsed facts. No model decides pass or fail, so the same file gives the same answer every time." |
| **0:52–1:08** | Scroll up to **COVERAGE: 163 of 164 lines**. Show **NOT INTERPRETED** with the one line. Click the **UNKNOWN** chip. | "It also tells you what it didn't understand: 163 of 164 lines, and the one it couldn't read is listed. Anything it can't determine is UNKNOWN, never a quiet pass. Grey is not green." |
| **1:08–1:22** | Scroll to **REMEDIATION** and hover the phases. Switch to the PDF tab: page 1 identity with **serial FDO1234ABCD**, then zoom on the footer hash. | "The fixes are vendor CLI, ordered so they can't lock you out: SSH on first, Telnet off after. The PDF carries the serial number from `show version`, and every page has a verification hash." |
| **1:22–1:44** | Terminal: `verify` → **INTACT**. Editor: change one digit in line 2's `merkle_root` and save. Terminal: `verify` → **TAMPERED, entry 2: signature does not verify, entry 3: chain broken**. | "Every report is Merkle-rooted, hash-chained and signed. Now I change one character in a past audit. The signature fails and the chain breaks, so you can't quietly rewrite an audit without the issuing key." |
| **1:44–1:55** | Closing card with two columns. **Built today:** ingestion · 5 vendor parsers · vendor-neutral IR · CIS/NIST/STIG rules · signed PDF + ledger · 101 tests. **Next:** AI training module · fleet attack paths · Crucible twin. Repo URL. | "That's the foundation, working offline today. Next, the engine learns new vendors from an administrator, and proves findings on a disposable twin. Crucible: compliance you can prove." |

**Word count:** about 240. If you run long, cut the second sentence of the 0:30 beat first.

---

## After recording

- Trim to **under 2:00** and check the final export length.
- Upload it (YouTube *unlisted* or Google Drive with *anyone with the link can view*). Open the link in a
  private window to confirm it plays when logged out.
- Put the link in the README: replace `VIDEO_LINK` near the top.
- Restore the ledger: `rm -rf ../reports` and re-run the `audit` command, or just leave it,
  since `reports/` is ignored by git.

## If something goes wrong on a take

- **The console shows an empty fleet.** Hard refresh (Ctrl+Shift+R) and click the button again.
- **The PDF tab 404s.** The sample audit hasn't run in this server session yet. Click *Audit the sample fleet* first.
- **`verify` says no public key.** You're pointing at a ledger the CLI didn't write. Use `../reports/ledger.jsonl`
  from the pre-flight step, not the server's temp directory.
