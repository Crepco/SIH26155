/* ===========================================================================
   Crucible audit console.

   No framework, no build step, no dependency. That is a deliberate choice, not
   a shortcut: the deployment target is an air-gapped host, and a page that needs
   a bundler and three hundred packages to render is a page that cannot be shown
   to have no external asset in it. Everything here is readable in one sitting.

   The console never computes a verdict. It renders what the backend decided, so
   that the screen and the signed PDF can never disagree.
   =========================================================================== */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  devices: [],
  selected: 0,
  filter: "all",
  open: new Set(),
};

/* -- helpers -------------------------------------------------------------- */

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const pct = (parsed, total) => (total ? Math.round((parsed / total) * 1000) / 10 : 0);

/** Bar colour tracks the severity of the number, not a brand palette. */
function grade(value) {
  if (value >= 80) return "meter--pass";
  if (value >= 50) return "meter--warn";
  return "meter--fail";
}

function fail(message) {
  const box = $("error");
  box.textContent = message;
  box.classList.remove("hidden");
}

function clearError() {
  $("error").classList.add("hidden");
}

/* -- data ----------------------------------------------------------------- */

async function loadRules() {
  try {
    const r = await fetch("/rules");
    const data = await r.json();
    $("stat-rules").innerHTML = `rules <b>${data.count}</b> · ${esc(data.frameworks.join(" · "))}`;
  } catch {
    $("stat-rules").innerHTML = "rules <b>unavailable</b>";
  }
}

async function loadLedger() {
  try {
    const r = await fetch("/ledger");
    const data = await r.json();
    if (!data.entries) {
      $("stat-ledger").innerHTML = "ledger <b>empty</b>";
      return;
    }
    const verdict = data.verified === false ? "TAMPERED" : "intact";
    $("stat-ledger").innerHTML = `ledger <b>${data.entries}</b> · ${verdict}`;

    $("ledger-sheet").classList.remove("hidden");
    $("ledger-state").textContent =
      `${data.entries} entries · ${data.verified === false ? "TAMPERED" : "chain intact"}` +
      (data.signature_checked ? " · signature verified" : " · no key present");
    $("chain").innerHTML = data.log
      .map(
        (e) => `<li>
          <span class="chain__seq">${e.seq}</span>
          <span>${esc(e.timestamp)}</span>
          <span>${esc(e.device_id)}</span>
          <span class="seal__hash">${esc(e.verification_hash)}</span>
        </li>`
      )
      .join("");
  } catch {
    $("stat-ledger").innerHTML = "ledger <b>—</b>";
  }
}

async function audit(request) {
  clearError();
  $("working").classList.remove("hidden");
  document.querySelectorAll(".drop .btn").forEach((b) => (b.disabled = true));
  try {
    const response = await request();
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || `the audit could not run (HTTP ${response.status})`);
    }
    const job = await response.json();
    if (!job.reports || !job.reports.length) throw new Error("no readable configuration in that upload");
    showJob(job);
  } catch (e) {
    fail(e.message);
  } finally {
    $("working").classList.add("hidden");
    document.querySelectorAll(".drop .btn").forEach((b) => (b.disabled = false));
  }
}

/** Render an audit job. Used by the audit view and by the training view's re-audit. */
function showJob(job, select = 0) {
  state.devices = job.reports;
  state.selected = select;
  state.open.clear();
  $("drop").classList.add("hidden");
  $("sheet").classList.remove("hidden");
  renderFleet();
  renderDevice();
  loadLedger();
}

/* -- views ---------------------------------------------------------------- */

function switchView(name) {
  document.querySelectorAll("[data-view-panel]").forEach((panel) =>
    panel.classList.toggle("hidden", panel.dataset.viewPanel !== name));
  document.querySelectorAll("#views [data-view]").forEach((tab) =>
    tab.setAttribute("aria-current", tab.dataset.view === name ? "page" : "false"));
  window.scrollTo({ top: 0 });
  document.dispatchEvent(new CustomEvent("crucible:view", { detail: name }));
}

$("views").addEventListener("click", (e) => {
  const tab = e.target.closest("[data-view]");
  if (tab) switchView(tab.dataset.view);
});

/* Shared with the other views, which live in their own files. */
window.Crucible = { $, esc, pct, grade, showJob, switchView, loadLedger };

const auditSample = () => audit(() => fetch("/demo", { method: "POST" }));

const auditFiles = (files) =>
  audit(() => {
    const form = new FormData();
    for (const f of files) form.append("files", f, f.name);
    return fetch("/audit", { method: "POST", body: form });
  });

/* -- fleet rail ----------------------------------------------------------- */

function renderFleet() {
  $("fleet-count").textContent = state.devices.length;
  $("fleet").innerHTML = state.devices
    .map((r, i) => {
      const score = r.summary.score;
      const cov = pct(r.coverage.parsed_lines, r.coverage.total_lines);
      const name = r.device.hostname || r.device_id;
      return `<li>
        <button class="device" data-index="${i}" aria-current="${i === state.selected}">
          <span class="device__name">${esc(name)}</span>
          <span class="device__meta">${esc(r.device.vendor)} ${esc(r.device.os || "")} · ${cov}% read</span>
          <span class="device__score">
            <span class="meter ${grade(score)}"><span class="meter__fill" style="--pct:${score}%"></span></span>
            <span>${score}%</span>
          </span>
        </button>
      </li>`;
    })
    .join("");
}

/* -- device sheet --------------------------------------------------------- */

function renderDevice() {
  const r = state.devices[state.selected];
  if (!r) return;
  const d = r.device;

  $("d-name").textContent = d.hostname || r.device_id;

  const serial = d.serial
    ? `serial <b>${esc(d.serial)}</b>`
    : `serial <span title="Serial lives in show version output, not the running config">not supplied</span>`;
  $("d-ident").innerHTML =
    `<b>${esc(d.vendor)}</b> ${esc(d.os || "")} ${esc(d.version || "")} · ` +
    (d.model ? `<b>${esc(d.model)}</b> · ` : "") + serial +
    ` · read at ${esc((d.fingerprint_confidence_bp || 0) / 100)}% confidence`;

  renderCoverage(r);
  renderTally(r);
  renderFindings(r);
  renderPlan(r);
  renderUnparsed(r);
  renderSeal(r);
}

function renderCoverage(r) {
  const c = r.coverage;
  const value = pct(c.parsed_lines, c.total_lines);
  $("cov-pct").textContent = `${value}%`;
  $("cov-of").textContent = `${c.parsed_lines.toLocaleString()} of ${c.total_lines.toLocaleString()} lines read`;

  const bar = $("cov-bar");
  bar.style.setProperty("--pct", `${value}%`);
  bar.parentElement.className = `meter ${grade(value)}`;

  const tiers = c.by_tier || {};
  $("cov-tier").textContent = ["tier0", "tier1", "tier2", "tier3"]
    .filter((k) => tiers[k])
    .map((k) => `${k.replace("tier", "tier ")} · ${tiers[k]}`)
    .join("  ") || "tier 0 · 0";

  // The sentence that separates this tool from every other one in the category.
  $("cov-note").innerHTML = c.unparsed_lines
    ? `${c.unparsed_lines.toLocaleString()} line${c.unparsed_lines === 1 ? "" : "s"} could not be
       interpreted. <button class="linkish" id="jump-unparsed">Read them</button> — every one is a
       control that was not evaluated, not one that quietly passed.`
    : `Every supplied line was interpreted.`;

  const jump = $("jump-unparsed");
  if (jump) {
    jump.onclick = () => $("unparsed-section").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  if (r.adapter_packs && r.adapter_packs.length) {
    $("cov-note").innerHTML =
      `<b>No built-in parser for this vendor.</b> Read by the signed adapter pack
       <b>${esc(r.adapter_packs.join(", "))}</b>. Learned facts are marked tier 2 or 3 in the evidence.`;
  } else if (!r.parser_applied) {
    $("cov-note").innerHTML =
      `<b>No parser was applied.</b> The vendor could not be identified with enough confidence,
       so every control below is UNKNOWN rather than passing by default.`;
  }
}

function renderTally(r) {
  const s = r.summary;
  $("frameworks").textContent = s.frameworks.join(" · ");
  const cells = [
    ["score", `${s.score}%`, ""],
    ["after fixes", `${s.projected_score}%`, ""],
    ["failed", s.counts.fail, "fail"],
    ["unknown", s.counts.unknown, ""],
    ["passed", s.counts.pass, "pass"],
    ["critical", s.by_severity.critical, "fail"],
  ];
  $("tally").innerHTML = cells
    .map(
      ([k, n, mod]) => `<div class="tally__cell ${mod ? `tally__cell--${mod}` : ""}">
        <span class="tally__n">${esc(n)}</span><span class="tally__k">${esc(k.toUpperCase())}</span>
      </div>`
    )
    .join("");
}

function visible(findings) {
  switch (state.filter) {
    case "fail": return findings.filter((f) => f.verdict === "fail");
    case "unknown": return findings.filter((f) => f.verdict === "unknown");
    case "serious": return findings.filter((f) => ["critical", "high"].includes(f.severity));
    default: return findings;
  }
}

function renderFindings(r) {
  const rows = visible(r.findings);
  if (!rows.length) {
    $("register").innerHTML = `<p class="notice" style="padding:1rem 0">Nothing matches this filter.</p>`;
    return;
  }

  $("register").innerHTML = rows
    .map((f) => {
      const open = state.open.has(f.rule_id);
      return `<div class="finding">
        <button class="finding__row" data-rule="${esc(f.rule_id)}" aria-expanded="${open}">
          <span class="sev sev--${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span>
          <span class="finding__id">${esc(f.rule_id)}</span>
          <span class="finding__title">${esc(f.title)}</span>
          <span class="state state--${esc(f.state)}">${esc(f.state.toUpperCase())}</span>
        </button>
        ${open ? body(f) : ""}
      </div>`;
    })
    .join("");
}

function body(f) {
  const parts = [`<p class="finding__rationale">${esc(f.rationale)}</p>`];

  // The evidence gutter: the finding shown in the configuration it came from.
  for (const e of f.evidence) {
    const lines = (e.context && e.context.length
      ? e.context
      : [{ line: e.line, text: e.raw, cited: true }]
    )
      .map(
        (l) => `<div class="excerpt__line ${l.cited ? "excerpt__line--cited" : ""}">
          <span class="excerpt__no">${l.line}</span><span class="excerpt__text">${esc(l.text)}</span>
        </div>`
      )
      .join("");
    parts.push(`<div class="excerpt">
      <div class="excerpt__file"><span>${esc(e.file)}</span><span>${esc(e.ir_path)} · tier ${e.tier}${
        e.adapter_pack ? ` · pack ${esc(e.adapter_pack)}` : ""}</span></div>
      <div class="excerpt__lines">${lines}</div>
    </div>`);
  }

  if (f.missing_paths && f.missing_paths.length) {
    const label = f.verdict === "unknown"
      ? "Could not be evaluated — these facts were never parsed:"
      : "Failed because the configuration never sets:";
    parts.push(`<div class="absent">${label}
      ${f.missing_paths.map((p) => `<code>${esc(p)}</code>`).join(", ")}</div>`);
  }

  parts.push(`<p class="meta">${esc(f.frameworks.join(" · "))}</p>`);

  if (f.remediation && f.remediation.length) {
    parts.push(`<div>
      <p class="meta" style="margin:0 0 .3rem">Fix — ${esc(f.remediation_target)}</p>
      <pre class="cli">${f.remediation.map(esc).join("\n")}</pre>
    </div>`);
  }

  return `<div class="finding__body">${parts.join("")}</div>`;
}

function renderPlan(r) {
  const plan = r.remediation;
  if (!plan.phases.length) {
    $("plan-count").textContent = "";
    $("plan").innerHTML = `<p class="notice">Nothing to apply.</p>`;
    return;
  }
  $("plan-count").textContent =
    `${plan.command_count} commands · ${plan.phases.length} phases · ${plan.target}`;

  $("plan").innerHTML = plan.phases
    .map(
      (p) => `<div class="phase">
        <div class="phase__head"><span class="phase__n">${p.phase}</span><span>${esc(p.name.toUpperCase())}</span></div>
        <pre class="cli">${p.steps
          .map(
            (s) =>
              `<span class="cmt">! ${esc(s.rule_id)} (${esc(s.severity)}) — ${esc(s.title)}</span>\n` +
              s.commands.map(esc).join("\n")
          )
          .join("\n\n")}</pre>
      </div>`
    )
    .join("");
}

function renderUnparsed(r) {
  const sample = r.coverage.unparsed_sample || [];
  const section = $("unparsed-section");
  if (!sample.length) {
    section.classList.add("hidden");
    return;
  }
  section.classList.remove("hidden");
  $("unparsed-count").textContent = `${r.coverage.unparsed_lines} lines`;
  $("unparsed").innerHTML = sample
    .map(
      (e) => `<div class="excerpt__line">
        <span class="excerpt__no">${e.line}</span><span class="excerpt__text">${esc(e.raw)}</span>
      </div>`
    )
    .join("");
}

function renderSeal(r) {
  $("s-report").textContent = r.report_id;
  $("s-merkle").textContent = (r.integrity.merkle_root || "—").slice(0, 24);
  $("s-seq").textContent = r.integrity.ledger_seq ?? "not committed";
  $("s-verify").textContent = r.integrity.verification_hash || "—";
  $("s-rules").textContent = r.rule_set_digest;
  $("s-ir").textContent = r.ir_schema_version;
}

/* -- events --------------------------------------------------------------- */

$("fleet").addEventListener("click", (e) => {
  const button = e.target.closest("[data-index]");
  if (!button) return;
  state.selected = Number(button.dataset.index);
  state.open.clear();
  renderFleet();
  renderDevice();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

$("register").addEventListener("click", (e) => {
  const row = e.target.closest("[data-rule]");
  if (!row) return;
  const id = row.dataset.rule;
  state.open.has(id) ? state.open.delete(id) : state.open.add(id);
  renderFindings(state.devices[state.selected]);
});

$("filters").addEventListener("click", (e) => {
  const chip = e.target.closest("[data-filter]");
  if (!chip) return;
  state.filter = chip.dataset.filter;
  document.querySelectorAll("#filters .chip").forEach((c) =>
    c.setAttribute("aria-pressed", String(c === chip)));
  renderFindings(state.devices[state.selected]);
});

$("run-sample").addEventListener("click", auditSample);
$("choose").addEventListener("click", () => $("file-input").click());
$("add-more").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", (e) => {
  if (e.target.files.length) auditFiles(e.target.files);
  e.target.value = "";
});

const drop = $("drop");
["dragenter", "dragover"].forEach((type) =>
  drop.addEventListener(type, (e) => {
    e.preventDefault();
    drop.classList.add("is-over");
  }));
["dragleave", "drop"].forEach((type) =>
  drop.addEventListener(type, (e) => {
    e.preventDefault();
    drop.classList.remove("is-over");
  }));
drop.addEventListener("drop", (e) => {
  if (e.dataTransfer.files.length) auditFiles(e.dataTransfer.files);
});

loadRules();
loadLedger();
