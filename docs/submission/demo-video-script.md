# Demo video: two-minute script

**Target length: 1:52.** The limit is 2:00, and the remaining seconds cover pauses. The voice-over
is about 255 words, a calm pace.

Everything in this script exists and runs. The honesty rules in
[docs/18](../18-internal-round-runbook.md) Part 4 still apply: show what the build does, and say
the numbers the tool prints.

Two minutes cannot hold everything, so this cuts hard. The two beats that earn their seconds are
**teaching an unseen vendor** (the thing NTRO actually asked for) and **Crucible** (proving a
finding rather than asserting it). Reporting and remediation get one shot between them.

---

## Before you record (15 minutes)

1. **Fresh reports** so the tamper beat is clean. From `backend/`:
   ```bash
   python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports
   python -m crucible.api.cli verify ../reports/ledger.jsonl        # must say INTACT
   ```
2. **The local model**, for the TRAIN beat:
   ```bash
   ollama list                    # must show qwen2.5-coder:7b-instruct-q4_K_M
   export CRUCIBLE_OLLAMA=1       # PowerShell: $env:CRUCIBLE_OLLAMA = "1"
   ```
   The model is opt-in, so without that variable the console uses the deterministic proposer and
   the beat loses its point. Make one throwaway proposal off-camera first: the first call after a
   cold start loads 4.7 GB and reads as a hang.
3. **The twin image**, for the Crucible beat. Check the daemon answers *before* you start:
   ```bash
   docker image inspect crucible-twin:1 >/dev/null && echo ok
   ```
   If it prints nothing, build it: `docker build -t crucible-twin:1 labs/crucible/twin`.
   If Docker is unavailable, see *If the sandbox will not run* below — do not fake the beat.
4. **Dry-run the Crucible command once** off-camera. The first run pulls nothing but does warm
   the image, and a twelve-second boot on camera reads as a hang:
   ```bash
   python -m crucible.api.cli verify --device tests/fixtures/devices/cisco-ios-core-01 \
     --finding CIS-NET-1.1.1
   ```
5. **Start the server** in a terminal you won't show:
   `python -m uvicorn crucible.api.main:app --host 127.0.0.1 --port 8000`
6. **Browser** at <http://127.0.0.1:8000>, zoom 125%, bookmarks bar hidden, no other tabs. Do
   **not** click *Audit the sample fleet* yet.
7. **Terminal** in `backend/`, font 18pt or more, cleared.
8. **Editor** with `reports/ledger.jsonl` open, word wrap on, cursor on line 2 near `"merkle_root"`.
9. **Wi-Fi off** before recording. The taskbar icon must be visible in the frame.
10. Notifications off (Windows Focus / Do Not Disturb). 1920×1080.

**Recording:** OBS (Display Capture, 1080p30), or Win+Alt+R with Xbox Game Bar. Record the
voice-over separately if the room is noisy. Record each beat as its own clip; they are far easier
to trim than one take.

---

## The script

| Time | Screen | Voice-over |
|------|--------|-----------|
| **0:00–0:10** | Title card: **CRUCIBLE · Compliance you can prove** · SIH26155 · NTRO. | "Most networks aren't breached through zero-days. They're breached through a device someone configured wrong years ago, that nobody has read since." |
| **0:10–0:26** | Zoom the taskbar: **Wi-Fi off**. Cut to the console, click **Audit the sample fleet**. Six devices and their scores fill in. | "The network is off. Six real configurations — Cisco, Arista, Fortinet, Juniper, MikroTik, Palo Alto — parsed, scored and signed in about a second. No cloud model, no outbound call: a config is a blueprint of a network's defences, and it never leaves the machine." |
| **0:26–0:48** | Click **core-sw-01**, expand **CIS-NET-1.1.1 Telnet**, hold on the evidence gutter at **line 102**. Scroll to **COVERAGE 163 of 164** and click the **UNKNOWN** chip. | "Every finding points at a line — Telnet on the management lines, line 102, shown in place. It also reports what it did *not* understand: 163 of 164 lines, and anything it can't determine is UNKNOWN, never a quiet pass. Grey is not green." |
| **0:48–1:10** | Switch to the **TRAIN** view. Show a family of unrecognised lines, its proposed mapping and the **preview** of what would be extracted. Accept one, then show the signed pack. | "NTRO asked for an engine an administrator can teach a new vendor without shipping code. These are the lines nobody recognised, grouped, each with a proposed mapping and a preview of exactly what it would read — from a seven-billion-parameter model running on this machine, on loopback, with the network still off. Hold a vendor out of the build entirely and it recovers nine fields out of nine. The administrator confirms, and it's signed into a portable adapter pack. The model only ever proposes how to *read* a line. It never decides pass or fail." |
| **1:10–1:30** | Terminal: the `verify --device … --finding CIS-NET-1.1.1` command. Let the twin boot, the probe connect, the fix apply and the re-test fail. Hold on **DEMONSTRATED**. | "And a finding shouldn't just be asserted. This boots a disposable twin of that switch, connects to Telnet to prove the port really is open, applies the fix, and tries again — including a check that the fix didn't lock the administrator out. Only now is it marked DEMONSTRATED." |
| **1:30–1:48** | Terminal: `verify` → **INTACT**. Editor: change one digit in line 2's `merkle_root`, save. Terminal: `verify` → **TAMPERED**. | "Every report is Merkle-rooted, hash-chained and Ed25519-signed. Change one character of a past audit, and the signature fails and the chain breaks. You cannot quietly rewrite history without the issuing key." |
| **1:48–1:58** | Closing card. **Built:** 6 vendors · learns new ones, 9/9 on a held-out vendor · CIS/NIST/STIG/ISO · XCCDF import · fleet attack paths · Crucible twin · signed ledger · 227 tests · offline bundle. **Measured:** precision 1.00, recall 0.90 on six labelled configs. Repo URL. | "Six vendors today, and a way to learn the seventh without us. A local model, on this machine, with the cable out. Crucible: compliance you can prove." |

**Word count:** about 255. If you run long, cut the last sentence of the 0:10 beat, then the
lock-out clause at 1:10.

---

## If the sandbox will not run

Do not stage it. Two honest options, in order of preference:

1. **Cut the beat and redistribute.** Give 1:10–1:30 to the fleet view instead: the attack-path
   graph and the one fix that severs the most paths. Change the closing line to "…and proves them
   on a disposable twin where Docker is available."
2. **Show the no-Docker path as designed behaviour.** Run the same command with the daemon
   stopped: it prints `no Docker daemon: findings stay ASSERTED`. Voice-over: "with no sandbox
   available, the finding stays ASSERTED — it never silently becomes a pass." That is a real
   guarantee, and showing it is worth more than pretending.

---

## After recording

- Trim to **under 2:00** and check the exported length.
- Upload it (YouTube *unlisted*, or Google Drive with *anyone with the link can view*). Open the
  link in a private window to confirm it plays when logged out.
- Put the link in the README: replace `VIDEO_LINK` near the top.
- Restore the ledger: re-run the `audit` command. `reports/` is git-ignored either way.

## If something goes wrong on a take

- **Empty fleet.** Hard refresh (Ctrl+Shift+R) and click the button again.
- **The TRAIN view is empty.** It only lists what no parser claimed. Add `--hold-out mikrotik` to a
  CLI `propose` run, or upload a config from a vendor with no Tier-0 parser.
- **The twin boot hangs.** Ctrl-C, check `docker ps -a` for a stuck container, `docker rm -f` it,
  and fall back to the no-Docker beat above rather than burning takes.
- **`verify` says no public key.** You're pointing at a ledger the CLI didn't write. Use
  `../reports/ledger.jsonl` from the pre-flight step, not the server's temp directory.
