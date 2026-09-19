/* ===========================================================================
   Training view - Tiers 2 and 3.

   An administrator teaches the engine a vendor it cannot read. Every decision
   made here produces a candidate *parser* (an adapter-pack mapping); none of it
   produces a verdict. After signing, the file is re-audited through the normal
   pipeline and the policy engine decides, exactly as for any other device.

   Same rules as the audit console: no framework, no dependency, no asset from
   anywhere but this deployment.
   =========================================================================== */

"use strict";

(() => {
  const { $, esc, grade, showJob, switchView } = window.Crucible;

  const t = {
    session: null, // summary from the API
    fields: [],
    transforms: [],
    acceptAbove: 0.85,
    open: new Set(),
    drafts: new Map(), // family key -> mapping being edited
    previews: new Map(), // family key -> preview hits
    pendingPack: null, // a pack file waiting on an explicit trust decision
  };

  /* -- plumbing ------------------------------------------------------------ */

  function fail(message) {
    const box = $("t-error");
    box.textContent = message;
    box.classList.remove("hidden");
  }

  function clear() {
    $("t-error").classList.add("hidden");
  }

  async function call(url, options = {}) {
    const response = await fetch(url, options);
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(body.detail || `request failed (HTTP ${response.status})`);
      error.status = response.status;
      throw error;
    }
    return body;
  }

  const post = (url, payload) =>
    call(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload ?? {}),
    });

  function busy(on) {
    $("t-working").classList.toggle("hidden", !on);
    document.querySelectorAll("#t-start .btn").forEach((b) => (b.disabled = on));
  }

  /* -- starting a session ---------------------------------------------------- */

  async function start(request) {
    clear();
    busy(true);
    try {
      t.session = await request();
      t.open.clear();
      t.drafts.clear();
      t.previews.clear();
      const vendor = t.session.vendor !== "unknown" ? t.session.vendor : "";
      $("t-vendor").value = vendor;
      $("t-pack-id").value = vendor ? `${vendor}-learned` : "";
      $("t-result").classList.add("hidden");
      render();
      $("t-session").classList.remove("hidden");
      $("t-session").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      fail(e.message);
    } finally {
      busy(false);
    }
  }

  const startSample = (name) => start(() => post(`/train/sample/${name}`));

  const startFiles = (files) =>
    start(() => {
      const form = new FormData();
      for (const f of files) form.append("files", f, f.name);
      return call("/train", { method: "POST", body: form });
    });

  /* -- rendering --------------------------------------------------------------- */

  function render() {
    const s = t.session;
    if (!s) return;
    const grammar = Object.values(s.grammar)[0] || {};
    const c = s.coverage;
    $("t-device").textContent = s.device_id;
    $("t-ident").innerHTML =
      `grammar <b>${esc(grammar.grammar || "unknown")}</b> (tier 1, ${esc(
        Math.round((grammar.confidence_bp || 0) / 100))}%) · ` +
      `<b>${c.parsed}</b> of ${c.total} lines read before training · ` +
      `vendor <b>${esc(s.vendor)}</b>` +
      (s.hold_out.length ? ` · built-in parser held out: <b>${esc(s.hold_out.join(", "))}</b>` : "") +
      ` · proposer <b>${esc(s.proposer)}</b>`;

    const confirmed = new Set(s.confirmed.map((m) => m.match));
    $("t-confirmed").textContent =
      `${s.confirmed.length} mapping${s.confirmed.length === 1 ? "" : "s"} ready · ` +
      `${s.confirmed.filter((m) => m.tier_learned === 3).length} confirmed by you`;

    $("t-families").innerHTML = s.families.length
      ? s.families.map((f) => family(f, confirmed)).join("")
      : `<p class="notice" style="padding:1rem 0">Nothing is left uninterpreted.</p>`;
  }

  function draftFor(f) {
    if (!t.drafts.has(f.key)) {
      const p = f.proposal;
      t.drafts.set(
        f.key,
        p
          ? { ...p.mapping }
          : {
              ir_path: "",
              match: "^" + f.samples[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+") + "$",
              transform: "presence",
              tier_learned: 3,
            }
      );
    }
    return t.drafts.get(f.key);
  }

  function family(f, confirmed) {
    const p = f.proposal;
    const draft = draftFor(f);
    const done = confirmed.has(draft.match) || (p && confirmed.has(p.mapping.match));
    const state = done
      ? `<span class="state state--pass">READY</span>`
      : `<span class="state state--unknown">OPEN</span>`;
    const confidence = p ? Math.round(p.confidence * 100) : 0;
    const proposal = p
      ? `<span class="proposal">
          <span class="proposal__path">${esc(p.ir_path)}</span>
          <span class="meter ${grade(confidence)}"><span class="meter__fill" style="--pct:${confidence}%"></span></span>
          <span class="proposal__conf">${(p.confidence).toFixed(2)}</span>
        </span>`
      : `<span class="proposal proposal--none">no proposal</span>`;
    const open = t.open.has(f.key);
    return `<div class="finding family">
      <button class="finding__row family__row" data-family="${esc(f.key)}" aria-expanded="${open}">
        <span class="family__line">${f.lines[0]}${f.count > 1 ? `<small>×${f.count}</small>` : ""}</span>
        <span class="family__text">${esc(f.samples[0])}${
          f.context.length ? `<small>in ${esc(f.context[f.context.length - 1])}</small>` : ""}</span>
        ${proposal}
        ${state}
      </button>
      ${open ? editor(f, draft) : ""}
    </div>`;
  }

  function options(values, selected) {
    return values
      .map((v) => `<option value="${esc(v)}" ${v === selected ? "selected" : ""}>${esc(v)}</option>`)
      .join("");
  }

  function editor(f, draft) {
    const p = f.proposal;
    const fieldOptions =
      `<option value="">choose a field…</option>` +
      t.fields
        .map((x) => `<option value="${esc(x.path)}" ${x.path === draft.ir_path ? "selected" : ""}
          title="${esc(x.description)}">${esc(x.path)}</option>`)
        .join("");
    const values = draft.values
      ? Object.entries(draft.values).map(([k, v]) => `${k}=${v}`).join(" ")
      : "";
    const hits = t.previews.get(f.key);
    const preview = hits
      ? `<div class="excerpt"><div class="excerpt__file"><span>preview · exactly what an audit will do</span>
           <span>${hits.filter((h) => h.applies).length} line(s) would be read</span></div>
           <div class="excerpt__lines">${
             hits.length
               ? hits
                   .map(
                     (h) => `<div class="excerpt__line ${h.applies ? "excerpt__line--cited" : ""}">
                  <span class="excerpt__no">${h.line}</span>
                  <span class="excerpt__text">${esc(h.text)}  →  ${
                    h.error ? `<i>${esc(h.error)}</i>` : `<b>${esc(JSON.stringify(h.value))}</b>`
                  }${h.applies ? "" : " <i>(already read by another tier)</i>"}</span>
                </div>`
                   )
                   .join("")
               : `<div class="excerpt__line"><span class="excerpt__no">—</span><span class="excerpt__text">matches nothing in this file</span></div>`
           }</div></div>`
      : "";
    return `<div class="finding__body editor" data-editor="${esc(f.key)}">
      ${p ? `<p class="meta">Tier 2 (${esc(p.source)}): ${esc(p.rationale)}${
        p.alternatives.length ? ` · also considered ${p.alternatives.map((a) => esc(a.ir_path)).join(", ")}` : ""
      }</p>` : `<p class="meta">No field in the vocabulary resembles this line. Map it by hand, or leave it uninterpreted.</p>`}
      <div class="form form--mapping">
        <label>IR field <select data-k="ir_path">${fieldOptions}</select></label>
        <label>transform <select data-k="transform">${options(t.transforms, draft.transform)}</select></label>
        <label class="wide">match <input data-k="match" value="${esc(draft.match)}" spellcheck="false"></label>
        <label>only inside <input data-k="within" value="${esc(draft.within || "")}" placeholder="block header pattern" spellcheck="false"></label>
        <label>lookup values <input data-k="values" value="${esc(values)}" placeholder="v2c=2 v3=3" spellcheck="false"></label>
      </div>
      <div class="actions actions--left">
        <button class="btn btn--ghost" data-act="preview">Preview on this file</button>
        <button class="btn" data-act="confirm">Confirm mapping</button>
      </div>
      ${preview}
    </div>`;
  }

  /* -- editing ------------------------------------------------------------------ */

  function readEditor(key) {
    const box = document.querySelector(`[data-editor="${CSS.escape(key)}"]`);
    const draft = { ...t.drafts.get(key) };
    box.querySelectorAll("[data-k]").forEach((input) => {
      const k = input.dataset.k;
      const v = input.value.trim();
      if (k === "values") {
        draft.values = v
          ? Object.fromEntries(
              v.split(/\s+/).map((pair) => {
                const [name, raw] = pair.split("=");
                const value = raw === "true" ? true : raw === "false" ? false : /^\d+$/.test(raw) ? Number(raw) : raw;
                return [name, value];
              })
            )
          : undefined;
      } else if (k === "within") {
        draft.within = v || undefined;
      } else {
        draft[k] = v;
      }
    });
    t.drafts.set(key, draft);
    return draft;
  }

  function payload(draft) {
    const out = {
      ir_path: draft.ir_path,
      match: draft.match,
      transform: draft.transform,
      tier_learned: 3,
    };
    if (draft.within) out.within = draft.within;
    if (draft.values) out.values = draft.values;
    return out;
  }

  async function preview(key) {
    clear();
    const draft = readEditor(key);
    if (!draft.ir_path) return fail("Choose the IR field this line sets.");
    try {
      const body = await post(`/train/${t.session.session}/preview`, { mapping: payload(draft) });
      t.previews.set(key, body.hits);
      render();
    } catch (e) {
      fail(e.message);
    }
  }

  async function confirm(key) {
    clear();
    const draft = readEditor(key);
    if (!draft.ir_path) return fail("Choose the IR field this line sets.");
    try {
      t.session = await post(`/train/${t.session.session}/confirm`, {
        mapping: payload(draft),
        confirmed_by: $("t-author").value.trim() || "administrator",
      });
      t.open.delete(key);
      render();
    } catch (e) {
      fail(e.message);
    }
  }

  async function acceptAll() {
    clear();
    try {
      t.session = await post(`/train/${t.session.session}/accept`, { threshold: t.acceptAbove });
      render();
    } catch (e) {
      fail(e.message);
    }
  }

  /* -- the pack --------------------------------------------------------------------- */

  async function sign() {
    clear();
    const button = $("t-sign");
    button.disabled = true;
    try {
      const body = await post(`/train/${t.session.session}/pack`, {
        pack_id: $("t-pack-id").value,
        vendor: $("t-vendor").value,
        os: $("t-os").value,
        author: $("t-author").value,
      });
      const before = body.coverage_before;
      const after = body.coverage_after;
      const box = $("t-result");
      box.innerHTML = `
        <p><b>Signed and installed ${esc(body.pack.id)}</b> · ${body.pack.mappings} mappings ·
           publisher <span class="seal__hash">${esc(body.pack.key_id)}</span> ·
           digest <span class="seal__hash">${esc(body.pack.digest)}</span></p>
        <p>Lines read: <b>${before.parsed}</b> of ${before.total} → <b>${after.parsed}</b> of ${after.total}.
           The rules now decide on what the pack reads, through the ordinary pipeline.</p>
        <div class="actions actions--left">
          <button class="btn" id="t-open-audit">Open the re-audit</button>
          <a class="btn btn--ghost" href="/packs/${encodeURIComponent(body.pack.id)}/export"
             download="${esc(body.pack.id)}.yaml">Export the pack</a>
        </div>`;
      box.classList.remove("hidden");
      $("t-open-audit").onclick = () => {
        showJob(body.audit);
        switchView("audit");
      };
      loadPacks();
    } catch (e) {
      fail(e.message);
    } finally {
      button.disabled = false;
    }
  }

  /* -- installed packs and trust ---------------------------------------------------- */

  async function loadPacks() {
    try {
      const body = await call("/packs");
      $("t-publisher").textContent = `this deployment publishes as ${body.publisher}`;
      $("t-packs").innerHTML = body.packs.length
        ? `<table class="packs"><thead><tr><th>pack</th><th>vendor</th><th>mappings</th><th>signed by</th><th>digest</th><th></th></tr></thead><tbody>${
            body.packs
              .map(
                (p) => `<tr>
              <td><b>${esc(p.id)}</b></td>
              <td>${esc(p.vendor)} ${esc(p.os || "")}</td>
              <td>${p.mappings} <small>(${p.tier3} confirmed)</small></td>
              <td class="seal__hash">${esc(p.key_id)}${p.own ? " <small>(here)</small>" : ""}</td>
              <td class="seal__hash">${esc(p.digest)}</td>
              <td><a class="linkish" href="/packs/${encodeURIComponent(p.id)}/export" download="${esc(p.id)}.yaml">export</a>
                  · <button class="linkish" data-remove="${esc(p.id)}">remove</button></td>
            </tr>`
              )
              .join("")
          }</tbody></table>`
        : `<p class="notice">No packs installed. Train one above, or import one.</p>`;
    } catch (e) {
      $("t-packs").innerHTML = `<p class="notice">Packs unavailable: ${esc(e.message)}</p>`;
    }
  }

  async function importPack(file) {
    const box = $("t-import-result");
    const form = new FormData();
    form.append("file", file, file.name);
    try {
      const body = await call("/packs/import", { method: "POST", body: form });
      box.innerHTML = `<p><b>Imported ${esc(body.imported)}</b> from publisher
        <span class="seal__hash">${esc(body.key_id)}</span>. Audits now use it.</p>`;
      t.pendingPack = null;
      loadPacks();
    } catch (e) {
      if (e.status === 403) {
        t.pendingPack = file;
        box.innerHTML = `<p><b>Refused.</b> ${esc(e.message)}</p>
          <p>If you know this publisher, load their public key to trust them, and the import
             will be retried. This is the only way a publisher becomes trusted.</p>
          <div class="actions actions--left">
            <button class="btn btn--ghost" id="t-trust">Trust a publisher key…</button>
          </div>`;
        $("t-trust").onclick = () => $("t-key-file").click();
      } else {
        box.innerHTML = `<p><b>Refused.</b> ${esc(e.message)}</p>`;
      }
    }
    box.classList.remove("hidden");
  }

  async function trustKey(file) {
    const form = new FormData();
    form.append("file", file, file.name);
    try {
      const body = await call("/trust", { method: "POST", body: form });
      $("t-import-result").innerHTML = `<p>Now trusting publisher <span class="seal__hash">${esc(
        body.trusted)}</span>.</p>`;
      if (t.pendingPack) await importPack(t.pendingPack);
    } catch (e) {
      fail(e.message);
    }
  }

  /* -- events -------------------------------------------------------------------------- */

  $("t-sample-vrp").addEventListener("click", () => startSample("huawei-vrp"));
  $("t-sample-mikrotik").addEventListener("click", () => startSample("mikrotik-held-out"));
  $("t-choose").addEventListener("click", () => $("t-file").click());
  $("t-file").addEventListener("change", (e) => {
    if (e.target.files.length) startFiles(e.target.files);
    e.target.value = "";
  });
  $("t-accept").addEventListener("click", acceptAll);
  $("t-sign").addEventListener("click", sign);
  $("t-import").addEventListener("click", () => $("t-pack-file").click());
  $("t-pack-file").addEventListener("change", (e) => {
    if (e.target.files.length) importPack(e.target.files[0]);
    e.target.value = "";
  });
  $("t-key-file").addEventListener("change", (e) => {
    if (e.target.files.length) trustKey(e.target.files[0]);
    e.target.value = "";
  });
  $("t-packs").addEventListener("click", async (e) => {
    const button = e.target.closest("[data-remove]");
    if (!button) return;
    await call(`/packs/${encodeURIComponent(button.dataset.remove)}`, { method: "DELETE" });
    loadPacks();
  });

  $("t-families").addEventListener("click", (e) => {
    const row = e.target.closest("[data-family]");
    if (row) {
      const key = row.dataset.family;
      t.open.has(key) ? t.open.delete(key) : t.open.add(key);
      render();
      return;
    }
    const act = e.target.closest("[data-act]");
    if (!act) return;
    const key = act.closest("[data-editor]").dataset.editor;
    if (act.dataset.act === "preview") preview(key);
    if (act.dataset.act === "confirm") confirm(key);
  });

  document.addEventListener("crucible:view", (e) => {
    if (e.detail === "train") loadPacks();
  });

  call("/train/fields")
    .then((body) => {
      t.fields = body.fields;
      t.transforms = body.transforms;
      t.acceptAbove = body.accept_above;
      $("t-accept").textContent = `ACCEPT ALL ≥ ${body.accept_above.toFixed(2)}`;
    })
    .catch(() => {});
})();
