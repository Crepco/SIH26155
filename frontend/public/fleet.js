/* ===========================================================================
   Fleet view - what no single device's audit can see.

   Draws the fleet as devices over the segments they share, and lights up the
   attack paths of whichever cross-device finding you select. The SVG is built
   by hand for the same reason the rest of this page is: a graph library would
   be the only third-party code in the deployment, and the layout here is two
   rows and some lines.

   Like every other view, it renders what the backend decided and computes no
   verdict of its own.
   =========================================================================== */

"use strict";

(() => {
  const { $, esc } = window.Crucible;

  const f = { report: null, selected: null };

  const SEV = ["critical", "high", "medium", "low"];

  /* -- layout ------------------------------------------------------------- */

  const W = 1000;
  const DEVICE_Y = 52;
  const SEGMENT_Y = 300;
  const DEVICE_W = 132;
  const DEVICE_H = 52;

  function layout(graph) {
    const devices = graph.nodes.filter((n) => n.kind === "device");
    const segments = graph.nodes.filter((n) => n.kind === "segment");
    const place = (items, y, width) =>
      items.map((node, i) => ({
        node,
        x: ((i + 0.5) * (W - 40)) / items.length + 20 - width / 2,
        y,
        w: width,
      }));
    return {
      devices: place(devices, DEVICE_Y, DEVICE_W),
      segments: place(segments, SEGMENT_Y, 116),
      interfaces: graph.nodes.filter((n) => n.kind === "interface"),
      edges: graph.edges,
    };
  }

  /** Which segments an attack path runs through, and which devices it touches. */
  function pathParts(correlation) {
    const segments = new Set();
    const devices = new Set();
    for (const path of correlation.paths || []) {
      for (const hop of path.hops) {
        if (hop.includes("/")) segments.add(hop);
        else devices.add(hop.split(":")[0]);
      }
    }
    for (const device of correlation.devices || []) devices.add(device);
    return { segments, devices };
  }

  function graphSvg(report) {
    const model = layout(report.graph);
    const active = f.selected ? pathParts(f.selected) : null;
    const boxes = new Map();
    const parts = [];

    for (const { node, x, y, w } of model.devices) {
      boxes.set(node.id, { x: x + w / 2, y: y + DEVICE_H });
      const lit = active && active.devices.has(node.attrs_device || node.device_id);
      const score = node.score ?? "";
      parts.push(`<g class="fg-device ${lit ? "is-lit" : ""}">
        <rect x="${x}" y="${y}" width="${w}" height="${DEVICE_H}" rx="2"/>
        <text class="fg-name" x="${x + 8}" y="${y + 18}">${esc(node.label)}</text>
        <text class="fg-meta" x="${x + 8}" y="${y + 32}">${esc(node.vendor || "")} ${esc(
          node.os || ""
        )}</text>
        <text class="fg-meta" x="${x + 8}" y="${y + 45}">${
          node.mgmt_acl ? "mgmt ACL" : "no mgmt ACL"
        }${score !== "" ? ` · ${score}%` : ""}</text>
      </g>`);
    }

    for (const { node, x, y, w } of model.segments) {
      boxes.set(node.id, { x: x + w / 2, y });
      const lit = active && active.segments.has(node.label);
      parts.push(`<g class="fg-segment ${lit ? "is-lit" : ""}">
        <rect x="${x}" y="${y}" width="${w}" height="26" rx="13"/>
        <text x="${x + w / 2}" y="${y + 17}" text-anchor="middle">${esc(node.label)}</text>
      </g>`);
    }

    // interface -> segment membership, drawn from the owning device
    const owner = new Map();
    for (const edge of model.edges) {
      if (edge.kind === "HAS_INTERFACE") owner.set(edge.dst, edge.src);
    }
    for (const edge of model.edges) {
      if (edge.kind !== "MEMBER_OF") continue;
      const device = boxes.get(owner.get(edge.src));
      const segment = boxes.get(edge.dst);
      if (!device || !segment) continue;
      const iface = model.interfaces.find((n) => n.id === edge.src);
      const untrusted = iface && iface.trust === "untrusted";
      const lit =
        active &&
        active.segments.has(report.graph.nodes.find((n) => n.id === edge.dst)?.label) &&
        active.devices.has(iface?.device);
      parts.push(
        `<line class="fg-link ${untrusted ? "is-untrusted" : ""} ${lit ? "is-lit" : ""}"
           x1="${device.x}" y1="${device.y}" x2="${segment.x}" y2="${segment.y}"/>`
      );
    }

    // shared credentials are a fleet-level relationship, drawn between devices
    for (const edge of model.edges) {
      if (edge.kind !== "SHARES_CREDENTIAL") continue;
      const device = boxes.get(edge.src);
      if (!device) continue;
      parts.push(
        `<circle class="fg-cred" cx="${device.x}" cy="${DEVICE_Y - 8}" r="4"><title>shared credential</title></circle>`
      );
    }

    return `<svg class="fg" viewBox="0 0 ${W} 360" role="img"
      aria-label="Fleet topology: devices over the segments they share">${parts.join("")}</svg>`;
  }

  /* -- rendering ------------------------------------------------------------ */

  function render() {
    const report = f.report;
    if (!report) {
      $("f-empty").classList.remove("hidden");
      $("f-body").classList.add("hidden");
      return;
    }
    $("f-empty").classList.add("hidden");
    $("f-body").classList.remove("hidden");

    $("f-headline").textContent = report.headline;
    const counts = report.counts;
    $("f-counts").innerHTML = SEV.map(
      (s) => `<span class="tally__cell ${s === "critical" ? "tally__cell--fail" : ""}">
        <span class="tally__n">${counts[s] || 0}</span><span class="tally__k">${s.toUpperCase()}</span>
      </span>`
    ).join("") +
      `<span class="tally__cell"><span class="tally__n">${report.paths}</span>
       <span class="tally__k">ATTACK PATHS</span></span>`;

    $("f-graph").innerHTML = graphSvg(report);

    $("f-fixes").innerHTML = `<table class="packs"><thead><tr>
        <th>#</th><th>fix</th><th>paths severed</th><th>devices</th><th>rule</th></tr></thead><tbody>${
      report.fixes
        .map(
          (fix, i) => `<tr>
        <td>${i + 1}</td>
        <td><b>${esc(fix.action)}</b></td>
        <td>${fix.paths_severed}</td>
        <td>${esc(fix.devices.join(", "))}</td>
        <td>${esc(fix.rule_id || "—")}</td>
      </tr>`
        )
        .join("")
    }</tbody></table>`;

    $("f-findings").innerHTML = report.correlations
      .map((c) => {
        const open = f.selected && f.selected.id === c.id;
        return `<div class="finding">
        <button class="finding__row" data-correlation="${esc(c.id)}" aria-expanded="${open}">
          <span class="sev sev--${esc(c.severity)}">${esc(c.severity.toUpperCase())}</span>
          <span class="finding__id">${esc(c.id)}</span>
          <span class="finding__title">${esc(c.title)}</span>
          <span class="state state--${c.confidence === "inferred" ? "unknown" : "asserted"}">${esc(
            c.confidence.toUpperCase()
          )}</span>
        </button>
        ${open ? correlationBody(c) : ""}
      </div>`;
      })
      .join("");
  }

  function correlationBody(c) {
    const paths = (c.paths || [])
      .map(
        (p) =>
          `<div class="excerpt__line"><span class="excerpt__text">${esc(p.hops.join("  →  "))}${
            p.inferred ? "   (inferred adjacency)" : ""
          }</span></div>`
      )
      .join("");
    return `<div class="finding__body">
      <p class="finding__rationale">${esc(c.summary)}</p>
      ${paths ? `<div class="excerpt"><div class="excerpt__file"><span>attack paths</span>
        <span>${c.paths.length}</span></div><div class="excerpt__lines">${paths}</div></div>` : ""}
      ${
        c.evidence && c.evidence.length
          ? `<div class="absent">Evidence: ${c.evidence
              .map((e) => `<code>${esc(e.device)}</code> ${esc(e.detail)}`)
              .join(" · ")}</div>`
          : ""
      }
      ${
        c.remediation && c.remediation.length
          ? `<p class="meta" style="margin:.5rem 0 .2rem">Fix</p><ul class="plain">${c.remediation
              .map((r) => `<li>${esc(r)}</li>`)
              .join("")}</ul>`
          : ""
      }
    </div>`;
  }

  /* -- events ---------------------------------------------------------------- */

  $("f-findings").addEventListener("click", (e) => {
    const row = e.target.closest("[data-correlation]");
    if (!row) return;
    const id = row.dataset.correlation;
    f.selected = f.selected && f.selected.id === id
      ? null
      : f.report.correlations.find((c) => c.id === id);
    render();
  });

  document.addEventListener("crucible:job", (e) => {
    f.report = e.detail && e.detail.fleet ? e.detail.fleet : null;
    f.selected = null;
    render();
  });

  render();
})();
