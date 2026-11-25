// PhishLens frontend. Plain JS, no build step.
// SECURITY: all text coming from the server (which may originate from an uploaded page)
// is inserted with textContent via h(), never innerHTML.
"use strict";

const state = { user: null, csrf: null, perms: new Set() };

// ------------------------------------------------------------------ helpers
function h(tag, attrs = {}, ...children) {
  if (tag === "table" && !(attrs && attrs["data-bare"])) {
    return h("div", { class: "table-wrap" }, h("table", { ...attrs, "data-bare": true }, ...children));
  }
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (sel) => document.querySelector(sel);
const can = (p) => state.perms.has(p);
const pct = (x) => (x === null || x === undefined ? "—" : `${Math.round(x * 100)}%`);
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString() : "");

function toast(msg, isErr = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add("hidden"), 4000);
}

class ApiError extends Error {
  constructor(status, body) {
    super(body?.error?.message || `Request failed (${status})`);
    this.status = status;
    this.code = body?.error?.code;
  }
}

async function api(path, { method = "GET", json, form, raw } = {}) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET" && state.csrf) opts.headers["X-CSRF-Token"] = state.csrf;
  if (json !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(json); }
  if (form) opts.body = form;
  const res = await fetch(path, opts);
  if (raw && res.ok) return res;
  let body = null;
  try { body = await res.json(); } catch { /* empty */ }
  if (!res.ok) {
    // Session expired mid-use -> back to login. (Not for the auth endpoints themselves, or we'd loop.)
    if (res.status === 401 && state.user && !path.startsWith("/api/auth/")) { resetSession(); route(); }
    throw new ApiError(res.status, body);
  }
  return body;
}

async function download(path, fallbackName) {
  try {
    const res = await api(path, { raw: true });
    const blob = await res.blob();
    const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") || "")?.[1] || fallbackName;
    const a = h("a", { href: URL.createObjectURL(blob), download: name });
    document.body.append(a); a.click(); a.remove();
  } catch (e) { toast(e.message, true); }
}

function resetSession() {
  state.user = null; state.csrf = null; state.perms = new Set();
}

function setSession(data) {
  state.user = { username: data.username, role: data.role };
  state.csrf = data.csrf_token;
  state.perms = new Set(data.permissions);
}

// Each navigation gets a token; an async view that finishes after the user has already moved on
// must not overwrite the newer screen (found by the E2E suite: quick filter changes showed stale rows).
let navToken = 0;
let renderToken = 0;

function render(...nodes) {
  if (renderToken !== navToken) return;
  const v = $("#view");
  v.replaceChildren(...nodes);
  v.focus();
}

function paintChrome() {
  const signedIn = !!state.user;
  $("#nav").classList.toggle("hidden", !signedIn);
  $("#who").classList.toggle("hidden", !signedIn);
  if (!signedIn) return;
  $("#who-name").textContent = state.user.username;
  $("#who-role").textContent = state.user.role;
  for (const a of document.querySelectorAll("#nav a")) {
    a.classList.toggle("hidden", !can(a.dataset.perm)); // cosmetic only; server enforces
    a.classList.toggle("active", location.hash.startsWith(a.getAttribute("href")));
  }
}

// ------------------------------------------------------------------ views
function loginView() {
  const err = h("p", { class: "error", role: "alert" });
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      const btn = form.querySelector("button"); btn.disabled = true;
      try {
        const data = await api("/api/auth/login", { method: "POST", json: {
          username: form.username.value, password: form.password.value } });
        setSession(data);
        const target = "#/dashboard";
        if (location.hash === target) route(); else location.hash = target;
      } catch (ex) { err.textContent = ex.message; } finally { btn.disabled = false; }
    },
  },
    h("label", { for: "username" }, "Username"),
    h("input", { id: "username", name: "username", type: "text", autocomplete: "username", required: true, maxlength: 64 }),
    h("label", { for: "password" }, "Password"),
    h("input", { id: "password", name: "password", type: "password", autocomplete: "current-password", required: true }),
    err,
    h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Sign in")),
  );
  $("#page-title").textContent = "PhishLens — Sign in";
  document.title = "Sign in · PhishLens";
  render(h("section", { class: "card narrow" }, h("h2", {}, "Sign in"), form));
}

function analyzeView() {
  const err = h("p", { class: "error", role: "alert" });
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const fd = new FormData(form);
      if (!fd.get("label")) fd.delete("label");
      const btn = form.querySelector("button"); btn.disabled = true; btn.textContent = "Analyzing…";
      try {
        const res = await api("/api/samples", { method: "POST", form: fd });
        if (res.duplicate) toast("Same page was uploaded before; ran a fresh analysis on the stored copy.");
        location.hash = `#/result/${res.analysis.id}`;
      } catch (ex) { err.textContent = ex.message; } finally { btn.disabled = false; btn.textContent = "Analyze page"; }
    },
  },
    h("label", { for: "file" }, "Saved page ", h("span", { class: "hint" }, "(.html / .htm, max 2 MB — parsed only, never opened or run)")),
    h("input", { id: "file", name: "file", type: "file", accept: ".html,.htm,text/html", required: true }),
    h("label", { for: "source_url" }, "Original URL ", h("span", { class: "hint" }, "(optional, used for URL features, never visited)")),
    h("input", { id: "source_url", name: "source_url", type: "url", maxlength: 2048, placeholder: "http://example.test/login" }),
    h("label", { for: "label" }, "Ground-truth label ", h("span", { class: "hint" }, "(optional, for evaluation)")),
    h("select", { id: "label", name: "label" },
      h("option", { value: "" }, "Unlabeled"), h("option", { value: "benign" }, "Benign"), h("option", { value: "phishing" }, "Phishing")),
    err,
    h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Analyze page")),
  );
  render(h("section", { class: "card" }, h("h2", {}, "Analyze a saved page"), form));
}

function meter(score, thresholds) {
  const fill = h("div", { class: "fill" }); fill.style.width = `${Math.round(score * 100)}%`;
  const t1 = h("div", { class: "tick", title: "suspicious threshold" }); t1.style.left = `${thresholds.suspicious * 100}%`;
  const t2 = h("div", { class: "tick", title: "phishing threshold" }); t2.style.left = `${thresholds.phishing * 100}%`;
  return [
    h("div", { class: "meter-label" }, h("span", {}, `Risk score ${pct(score)}`),
      h("span", {}, `suspicious ≥ ${pct(thresholds.suspicious)} · phishing ≥ ${pct(thresholds.phishing)}`)),
    h("div", { class: "meter" }, fill, t1, t2),
  ];
}

function contributionBars(top) {
  const max = Math.max(...top.map((t) => Math.abs(t.contribution)), 0.0001);
  return top.map((t) => {
    const span = h("span", { class: t.contribution > 0 ? "pos" : "neg" });
    span.style.width = `${(Math.abs(t.contribution) / max) * 50}%`;
    return h("div", { class: "bar" },
      h("code", {}, `${t.feature} = ${t.value}`),
      h("div", { class: "track", title: t.direction }, span),
      h("span", { class: "muted" }, (t.contribution > 0 ? "+" : "") + t.contribution.toFixed(2)));
  });
}

async function resultView(id) {
  let r;
  try { r = await api(`/api/analyses/${encodeURIComponent(id)}`); } catch (e) { return render(h("section", { class: "card" }, e.message)); }

  if (r.restricted_view) {
    return render(
      h("div", { class: `verdict ${r.decision}` }, h("div", { class: "big" }, r.decision),
        h("div", {}, h("div", {}, r.recommended_action), h("div", { class: "meta" }, `Score ${pct(r.score)} · ${fmtTime(r.created_at)}`))),
      h("section", { class: "card" }, h("h2", {}, "Why"),
        r.reasons.length ? r.reasons.map((x) => h("div", { class: "rule" }, h("div", { class: "name" }, x.name), h("div", {}, x.reason)))
          : h("p", { class: "muted" }, "No warning rules fired.")),
    );
  }

  const fired = r.rules.fired;
  const verdict = h("div", { class: `verdict ${r.decision}` },
    h("div", { class: "big" }, r.decision),
    h("div", {},
      h("div", {}, h("b", {}, r.recommended_action)),
      h("div", { class: "meta" }, `${r.filename} · ${r.source_url || "no URL declared"} · ${fmtTime(r.created_at)}`),
      h("div", { class: "meta" }, `Severity `, h("span", { class: `pill ${r.severity}` }, r.severity),
        ` · confidence ${pct(r.confidence)} · ${r.mode === "rules_only" ? "rules only (no model loaded)" : "rules + ML"} · ${r.latency_ms} ms`)),
  );

  const rulesCard = h("section", { class: "card" },
    h("h2", {}, `Rules fired (${fired.length})`, h("span", { class: "hint" }, `  rule score ${pct(r.rules.score)}`)),
    fired.length ? fired.map((f) => h("div", { class: `rule ${f.severity}` },
      h("div", {}, h("span", { class: "name" }, `${f.id} · ${f.name}`), " ", h("span", { class: `pill ${f.severity}` }, f.severity),
        h("span", { class: "hint" }, `  weight ${f.weight}`)),
      h("div", {}, f.reason),
      f.evidence.length ? h("div", {}, f.evidence.map((e) => h("span", { class: "evidence" }, e))) : null,
    )) : h("p", { class: "muted" }, "No rule fired. Nothing in the page matched a known phishing indicator."),
  );

  const mlCard = h("section", { class: "card" }, h("h2", {}, "Model explanation"),
    r.ml ? [
      h("p", {}, `Model ${r.ml.model_version} says `, h("b", {}, pct(r.ml.probability)), " phishing probability. ",
        h("span", { class: "hint" }, "Red bars push towards phishing, green towards benign.")),
      ...contributionBars(r.ml.top_features),
    ] : h("p", { class: "muted" }, "No model loaded — decision is based on rules only."));

  const fb = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api(`/api/analyses/${r.id}/feedback`, { method: "POST", json: { verdict: fb.verdict.value, comment: fb.comment.value || null } });
        toast("Feedback saved."); resultView(id);
      } catch (ex) { toast(ex.message, true); }
    },
  },
    h("label", { for: "verdict" }, "Is this decision right?"),
    h("select", { id: "verdict", name: "verdict" }, h("option", { value: "correct" }, "Correct"),
      h("option", { value: "false_positive" }, "False positive (it's actually safe)"),
      h("option", { value: "false_negative" }, "False negative (it's actually phishing)")),
    h("label", { for: "comment" }, "Comment ", h("span", { class: "hint" }, "(optional, max 500)")),
    h("textarea", { id: "comment", name: "comment", maxlength: 500, rows: 2 }),
    h("div", { class: "row" }, h("button", { type: "submit" }, "Submit feedback")),
  );

  const actions = h("div", { class: "row" },
    can("export:run") && h("button", { onclick: () => download(`/api/analyses/${r.id}/export?format=json`, "report.json") }, "Export JSON"),
    can("export:run") && h("button", { onclick: () => download(`/api/analyses/${r.id}/export?format=csv`, "report.csv") }, "Export CSV"),
    can("analysis:run") && h("button", {
      onclick: async () => {
        try { const n = await api(`/api/samples/${r.sample_id}/analyze`, { method: "POST" }); location.hash = `#/result/${n.id}`; }
        catch (ex) { toast(ex.message, true); }
      },
    }, "Re-analyze with current config"),
    h("button", { onclick: () => window.print() }, "Print / save as PDF"),
    h("a", { href: `#/history?sample=${r.sample_id}` }, "All runs of this page"),
  );

  const details = h("section", { class: "card" }, h("h2", {}, "Reproducibility"),
    h("dl", { class: "kv" },
      h("dt", {}, "Analysis ID"), h("dd", { class: "mono" }, r.id),
      h("dt", {}, "Config version"), h("dd", {}, `v${r.config_version}`),
      h("dt", {}, "Versions"), h("dd", { class: "mono" }, `${r.versions.features} · ${r.versions.rules} · ${r.versions.model || "no model"}`),
      h("dt", {}, "Thresholds"), h("dd", {}, `phishing ${r.thresholds.phishing} · suspicious ${r.thresholds.suspicious} · ml weight ${r.thresholds.ml_weight}`),
      h("dt", {}, "Disabled rules"), h("dd", {}, r.rules.disabled.join(", ") || "none"),
      h("dt", {}, "Ground truth"), h("dd", {}, r.label || "unlabeled"),
    ),
    h("details", {}, h("summary", {}, "All extracted features"),
      h("table", {}, h("tbody", {}, Object.entries(r.features).map(([k, v]) => h("tr", {}, h("td", { class: "mono" }, k), h("td", {}, String(v))))))),
  );

  const fbList = (r.feedback || []).map((f) => h("li", {}, `${f.username}: ${f.verdict.replace("_", " ")}`,
    f.comment ? ` — ${f.comment}` : "", h("span", { class: "hint" }, `  ${fmtTime(f.created_at)}`)));

  render(verdict, h("section", { class: "card" }, ...meter(r.score, r.thresholds), actions),
    h("div", { class: "grid2" }, rulesCard, mlCard), details,
    can("feedback:write") ? h("section", { class: "card" }, h("h2", {}, "Analyst feedback"), fbList.length ? h("ul", {}, fbList) : null, fb) : null);
}

async function historyView(params) {
  const decision = params.get("decision") || "";
  const q = params.get("q") || "";
  const sample = params.get("sample") || "";
  const qs = new URLSearchParams({ limit: "100" });
  if (decision) qs.set("decision", decision);
  if (q) qs.set("q", q);
  if (sample) qs.set("sample_id", sample);
  let data;
  try { data = await api(`/api/analyses?${qs}`); } catch (e) { return render(h("section", { class: "card" }, e.message)); }

  const filters = h("form", {
    class: "row",
    onsubmit: (e) => {
      e.preventDefault();
      const p = new URLSearchParams();
      if (filters.decision.value) p.set("decision", filters.decision.value);
      if (filters.q && filters.q.value) p.set("q", filters.q.value);
      location.hash = `#/history?${p}`;
    },
  },
    h("select", { name: "decision", "aria-label": "Decision filter" },
      ["", "phishing", "suspicious", "benign"].map((d) => h("option", { value: d, selected: d === decision }, d || "All decisions"))),
    state.user.role !== "viewer" && h("input", { name: "q", type: "text", placeholder: "Search file or URL", value: q, "aria-label": "Search" }),
    h("button", { type: "submit" }, "Filter"),
    can("export:run") && h("button", { type: "button", onclick: () => download("/api/analyses/export/history.csv", "history.csv") }, "Export history CSV"),
  );

  const c = data.counts || {};
  const stats = h("div", { class: "stats" },
    ["phishing", "suspicious", "benign"].map((d) => h("div", { class: "stat" }, h("b", {}, c[d] || 0), h("span", { class: `pill ${d}` }, d))));

  const picked = new Set();
  const compareBtn = h("button", { type: "button", disabled: true,
    onclick: () => { const [x, y] = [...picked]; location.hash = `#/compare?a=${x}&b=${y}`; } }, "Compare selected (0/2)");
  const pick = (id, box) => {
    if (box.checked) { if (picked.size >= 2) { box.checked = false; return toast("Select only two."); } picked.add(id); }
    else picked.delete(id);
    compareBtn.textContent = `Compare selected (${picked.size}/2)`; compareBtn.disabled = picked.size !== 2;
  };
  const rows = data.items.map((a) => h("tr", { class: "clickable", tabindex: 0,
    onclick: (e) => { if (e.target.tagName !== "INPUT") location.hash = `#/result/${a.id}`; },
    onkeydown: (e) => { if (e.key === "Enter" && e.target.tagName !== "INPUT") location.hash = `#/result/${a.id}`; } },
    h("td", {}, h("input", { type: "checkbox", "aria-label": "Select for comparison", onchange: (e) => pick(a.id, e.target) })),
    h("td", {}, fmtTime(a.created_at)),
    h("td", {}, a.filename || "—", a.source_url ? h("div", { class: "mono muted" }, a.source_url) : null),
    h("td", {}, h("span", { class: `pill ${a.decision}` }, a.decision)),
    h("td", {}, pct(a.score)),
    h("td", {}, a.severity ? h("span", { class: `pill ${a.severity}` }, a.severity) : "—"),
    h("td", {}, a.config_version ? `v${a.config_version}` : "—"),
    h("td", {}, a.label || "—"),
  ));
  render(h("section", { class: "card" }, h("h2", {}, sample ? "Runs of one page" : "Analysis history"), stats, filters,
    h("div", { class: "row" }, compareBtn),
    h("table", {}, h("thead", {}, h("tr", {}, [h("span", { class: "sr-only" }, "Select"), "When", "Page", "Decision", "Score", "Severity", "Config", "Label"].map((x) => h("th", { scope: "col" }, x)))),
      h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: 8, class: "muted" }, "No analyses yet."))))));
}

function datasetView() {
  const out = h("div");
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault(); out.replaceChildren();
      const fd = new FormData(form);
      fd.set("analyze", form.analyze.checked ? "true" : "false");
      const btn = form.querySelector("button"); btn.disabled = true; btn.textContent = "Importing…";
      try {
        const r = await api("/api/samples/import", { method: "POST", form: fd });
        out.append(h("dl", { class: "kv" }, Object.entries(r).map(([k, v]) => [h("dt", {}, k), h("dd", {}, String(v))])));
        toast("Import finished.");
      } catch (ex) { out.append(h("p", { class: "error" }, ex.message)); }
      finally { btn.disabled = false; btn.textContent = "Import"; }
    },
  },
    h("p", {}, "Upload a .zip with .html pages and an optional ", h("code", {}, "labels.csv"), " (columns: filename,label,source_url). ",
      "Use only safe or instructor-approved archived samples."),
    h("label", { for: "zip" }, "Dataset archive"),
    h("input", { id: "zip", name: "file", type: "file", accept: ".zip", required: true }),
    h("label", {}, h("input", { type: "checkbox", name: "analyze" }), " Analyze every page after import"),
    h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Import")),
  );
  render(h("section", { class: "card" }, h("h2", {}, "Import labeled dataset"), form, out));
}

// ---------------------------------------------------------------- dashboard
async function dashboardView() {
  let d;
  try { d = await api("/api/dashboard"); } catch (e) { return render(h("section", { class: "card" }, e.message)); }
  const dec = d.by_decision || {};
  const sev = d.by_severity || {};
  const total = d.totals.analyses || 0;
  const bar = (label, n, cls) => {
    const fill = h("span", { class: `fill ${cls}` }); fill.style.width = `${total ? (n / total) * 100 : 0}%`;
    return h("div", { class: "hbar" }, h("span", { class: "hbar-label" }, label), h("span", { class: "hbar-track" }, fill), h("b", {}, n));
  };
  const status = h("section", { class: "card" }, h("h2", {}, "System status"),
    h("div", { class: "stats" },
      h("div", { class: "stat" }, h("b", {}, total), "analyses"),
      h("div", { class: "stat" }, h("b", {}, d.totals.last_24h), "last 24 h"),
      h("div", { class: "stat" }, h("b", {}, d.totals.samples), `pages (${d.totals.labeled_samples} labeled)`),
      h("div", { class: "stat" }, h("b", {}, d.latency ? `${d.latency.mean_ms} ms` : "—"), d.latency ? `avg latency · p95 ${d.latency.p95_ms} ms` : "latency"),
      h("div", { class: "stat" }, h("b", {}, d.status.model === "loaded" ? "Hybrid" : "Rules only"),
        d.status.model_version ? `model ${d.status.model_version}` : `model ${d.status.model}`),
      h("div", { class: "stat" }, h("b", {}, `v${d.status.config_version}`), "config")));
  const decisions = h("section", { class: "card" }, h("h2", {}, "Decisions"),
    bar("Phishing", dec.phishing || 0, "phishing"), bar("Suspicious", dec.suspicious || 0, "suspicious"), bar("Benign", dec.benign || 0, "benign"),
    h("h3", {}, "Severity (last 500)"),
    h("div", { class: "row" }, ["high", "medium", "low", "none"].map((k) => h("span", { class: `pill ${k}` }, `${k}: ${sev[k] || 0}`))));
  const rules = h("section", { class: "card" }, h("h2", {}, "Most frequent indicators"),
    d.top_rules.length ? h("table", {}, h("tbody", {}, d.top_rules.map((r) => h("tr", {}, h("td", { class: "mono" }, r.id), h("td", {}, r.name), h("td", {}, r.count)))))
      : h("p", { class: "muted" }, "No rules have fired yet."));
  const risky = h("section", { class: "card" }, h("h2", {}, "Recent phishing detections"),
    d.recent_high_risk.length ? h("table", {}, h("tbody", {}, d.recent_high_risk.map((r) => h("tr", {
      class: "clickable", tabindex: 0, onclick: () => (location.hash = `#/result/${r.id}`),
      onkeydown: (e) => { if (e.key === "Enter") location.hash = `#/result/${r.id}`; } },
      h("td", {}, fmtTime(r.created_at)), h("td", {}, r.filename || "—"), h("td", {}, pct(r.score)),
      h("td", {}, r.top_reason || "")))))
      : h("p", { class: "muted" }, "No phishing detections yet."));
  const fb = d.feedback ? h("section", { class: "card" }, h("h2", {}, "Analyst feedback"),
    h("div", { class: "stats" }, ["correct", "false_positive", "false_negative"].map((k) =>
      h("div", { class: "stat" }, h("b", {}, d.feedback[k] || 0), k.replace("_", " "))))) : null;
  render(status, h("div", { class: "grid2" }, decisions, rules), risky, fb);
}

// ---------------------------------------------------------------- compare
async function compareView(params) {
  const a = params.get("a"), b = params.get("b");
  if (!a || !b) return render(h("section", { class: "card" }, "Pick two analyses in History, then press Compare."));
  let ra, rb;
  try { [ra, rb] = await Promise.all([api(`/api/analyses/${encodeURIComponent(a)}`), api(`/api/analyses/${encodeURIComponent(b)}`)]); }
  catch (e) { return render(h("section", { class: "card" }, e.message)); }
  const col = (r) => h("div", {},
    h("div", { class: `verdict ${r.decision}` }, h("div", { class: "big" }, r.decision),
      h("div", {}, h("div", {}, r.filename || ""), h("div", { class: "meta" }, `score ${pct(r.score)} · config v${r.config_version} · ${fmtTime(r.created_at)}`))),
    ...(r.rules ? r.rules.fired.map((f) => h("div", { class: `rule ${f.severity}` }, h("div", { class: "name" }, `${f.id} · ${f.name}`),
      f.evidence.length ? h("div", {}, f.evidence.map((e) => h("span", { class: "evidence" }, e))) : null))
      : (r.reasons || []).map((x) => h("div", { class: "rule" }, x.name))),
    r.rules && !r.rules.fired.length ? h("p", { class: "muted" }, "No rules fired.") : null,
    h("a", { href: `#/result/${r.id}` }, "Open full result"));
  const diffRows = [];
  if (ra.features && rb.features) {
    for (const k of Object.keys(ra.features)) {
      if (ra.features[k] !== rb.features[k]) diffRows.push(h("tr", {}, h("td", { class: "mono" }, k), h("td", {}, String(ra.features[k])), h("td", {}, String(rb.features[k]))));
    }
  }
  render(h("section", { class: "card" }, h("h2", {}, "Compare two analyses"), h("div", { class: "grid2" }, col(ra), col(rb))),
    diffRows.length ? h("section", { class: "card" }, h("h2", {}, `Features that differ (${diffRows.length})`),
      h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Feature"), h("th", {}, "Left"), h("th", {}, "Right"))), h("tbody", {}, diffRows))) : null);
}

// ---------------------------------------------------------------- account
function accountView() {
  const err = h("p", { class: "error", role: "alert" });
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      if (form.new_password.value !== form.repeat.value) { err.textContent = "New passwords do not match."; return; }
      try {
        await api("/api/auth/password", { method: "POST", json: { current_password: form.current_password.value, new_password: form.new_password.value } });
        form.reset(); toast("Password changed. Other sessions were signed out.");
      } catch (ex) { err.textContent = ex.message; }
    },
  },
    h("label", { for: "cp" }, "Current password"), h("input", { id: "cp", name: "current_password", type: "password", autocomplete: "current-password", required: true }),
    h("label", { for: "np" }, "New password ", h("span", { class: "hint" }, "(10+ characters, mix letters with numbers or symbols)")),
    h("input", { id: "np", name: "new_password", type: "password", autocomplete: "new-password", required: true, minlength: 10 }),
    h("label", { for: "rp" }, "Repeat new password"), h("input", { id: "rp", name: "repeat", type: "password", autocomplete: "new-password", required: true }),
    err, h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Change password")));
  render(h("section", { class: "card narrow" }, h("h2", {}, `Account · ${state.user.username}`), form));
}

// ---------------------------------------------------------------- admin
async function adminView(tab = "config") {
  const tabs = h("div", { class: "tabs" }, [["config", "Config"], ["users", "Users"], ["audit", "Audit log"], ["model", "Model"]]
    .map(([k, label]) => h("button", { class: k === tab ? "active" : "", onclick: () => (location.hash = `#/admin/${k}`) }, label)));
  const body = h("div");
  render(h("section", { class: "card" }, h("h2", {}, "Administration"), tabs, body));
  try {
    if (tab === "config") await adminConfig(body);
    else if (tab === "users") await adminUsers(body);
    else if (tab === "audit") await adminAudit(body);
    else await adminModel(body);
  } catch (e) { body.replaceChildren(h("p", { class: "error" }, e.message)); }
}

async function adminConfig(body) {
  const { version, config, rules } = await api("/api/admin/config");
  const hist = await api("/api/admin/config/history");
  const num = (name, val, step) => h("input", { id: `cfg-${name}`, name, type: "number", min: 0, max: 1, step, value: val, required: true });
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      const disabled = [...form.querySelectorAll("input[name=rule]:not(:checked)")].map((i) => i.value);
      const payload = {
        phishing_threshold: parseFloat(form.phishing_threshold.value), suspicious_threshold: parseFloat(form.suspicious_threshold.value),
        ml_weight: parseFloat(form.ml_weight.value), disabled_rules: disabled, reason: form.reason.value, confirm: false,
      };
      if (!window.confirm(`Save config v${version + 1}? New analyses will use these settings.`)) return;
      payload.confirm = true;
      try { const r = await api("/api/admin/config", { method: "PUT", json: payload }); toast(`Saved config v${r.version}.`); adminView("config"); }
      catch (ex) { toast(ex.message, true); }
    },
  },
    h("p", { class: "muted" }, `Current version: v${version}`),
    h("div", { class: "grid2" },
      h("div", {}, h("label", { for: "cfg-phishing_threshold" }, "Phishing threshold"), num("phishing_threshold", config.phishing_threshold, 0.01)),
      h("div", {}, h("label", { for: "cfg-suspicious_threshold" }, "Suspicious threshold"), num("suspicious_threshold", config.suspicious_threshold, 0.01))),
    h("label", { for: "cfg-ml_weight" }, "ML weight ", h("span", { class: "hint" }, "(0 = rules only, 1 = model only)")), num("ml_weight", config.ml_weight, 0.05),
    h("h3", {}, "Enabled rules"),
    rules.map((r) => h("label", { class: "hint" }, h("input", { type: "checkbox", name: "rule", value: r.id, checked: !config.disabled_rules.includes(r.id) }),
      ` ${r.id} ${r.name} (w=${r.weight}, ${r.severity})`)),
    h("label", { for: "cfg-reason" }, "Reason for change"), h("input", { id: "cfg-reason", name: "reason", type: "text", minlength: 3, maxlength: 200, required: true }),
    h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Save new version")),
  );
  body.replaceChildren(form, h("h3", {}, "History"),
    h("table", {}, h("thead", {}, h("tr", {}, ["Version", "When", "By", "Reason", "Settings"].map((x) => h("th", {}, x)))),
      h("tbody", {}, hist.items.map((c) => h("tr", {}, h("td", {}, `v${c.version}`), h("td", {}, fmtTime(c.created_at)),
        h("td", {}, c.changed_by || "system"), h("td", {}, c.reason || ""), h("td", { class: "mono" }, JSON.stringify(c.config_json)))))));
}

async function adminUsers(body) {
  const { items } = await api("/api/admin/users");
  const form = h("form", {
    class: "row",
    onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api("/api/admin/users", { method: "POST", json: { username: form.username.value, password: form.password.value, role: form.role.value } });
        toast("User created."); adminView("users");
      } catch (ex) { toast(ex.message, true); }
    },
  },
    h("input", { name: "username", type: "text", placeholder: "username", required: true, pattern: "[a-z0-9_.\\-]{3,32}" }),
    h("input", { name: "password", type: "password", placeholder: "password (10+ chars)", required: true, autocomplete: "new-password" }),
    h("select", { name: "role" }, ["analyst", "viewer", "admin"].map((r) => h("option", { value: r }, r))),
    h("button", { class: "primary", type: "submit" }, "Add user"));
  const toggle = async (u) => {
    if (!window.confirm(`${u.disabled ? "Enable" : "Disable"} ${u.username}?`)) return;
    try { await api(`/api/admin/users/${u.id}`, { method: "PATCH", json: { disabled: !u.disabled, confirm: true } }); adminView("users"); }
    catch (ex) { toast(ex.message, true); }
  };
  body.replaceChildren(form, h("table", {},
    h("thead", {}, h("tr", {}, ["User", "Role", "Status", "Created", ""].map((x) => h("th", {}, x)))),
    h("tbody", {}, items.map((u) => h("tr", {}, h("td", {}, u.username), h("td", {}, u.role),
      h("td", {}, u.disabled ? "disabled" : "active"), h("td", {}, fmtTime(u.created_at)),
      h("td", {}, u.username !== state.user.username && h("button", { class: u.disabled ? "" : "danger", onclick: () => toggle(u) }, u.disabled ? "Enable" : "Disable")))))));
}

async function adminAudit(body) {
  const { items } = await api("/api/admin/audit?limit=200");
  const verifyOut = h("span", { class: "hint" });
  body.replaceChildren(
    h("div", { class: "row" },
      h("button", { onclick: async () => {
        const v = await api("/api/admin/audit/verify");
        verifyOut.textContent = v.valid ? `Chain intact (${v.events_checked} events checked).` : `CHAIN BROKEN at event #${v.broken_at_seq}!`;
      } }, "Verify hash chain"), verifyOut),
    h("table", {}, h("thead", {}, h("tr", {}, ["#", "When", "Actor", "Action", "Outcome", "Target", "Details"].map((x) => h("th", {}, x)))),
      h("tbody", {}, items.map((ev) => h("tr", {}, h("td", {}, ev.seq), h("td", {}, fmtTime(ev.ts)),
        h("td", {}, `${ev.actor || "anonymous"}${ev.role ? ` (${ev.role})` : ""}`), h("td", { class: "mono" }, ev.action),
        h("td", {}, h("span", { class: `pill ${ev.outcome === "success" ? "benign" : ev.outcome === "denied" ? "phishing" : "suspicious"}` }, ev.outcome)),
        h("td", { class: "mono" }, ev.target || ""), h("td", { class: "mono" }, JSON.stringify(ev.details)))))));
}

async function adminModel(body) {
  const m = await api("/api/admin/model");
  body.replaceChildren(
    h("dl", { class: "kv" }, Object.entries(m).filter(([k]) => k !== "test_metrics").map(([k, v]) => [h("dt", {}, k), h("dd", { class: "mono" }, String(v))])),
    m.test_metrics ? [h("h3", {}, "Held-out test metrics (from training)"),
      h("dl", { class: "kv" }, Object.entries(m.test_metrics).map(([k, v]) => [h("dt", {}, k), h("dd", { class: "mono" }, typeof v === "object" ? JSON.stringify(v) : String(v))]))] : null,
    h("div", { class: "row" }, can("config:write") && h("button", { onclick: async () => {
      if (!window.confirm("Reload the model from disk? New analyses will use whatever model file is there now.")) return;
      try { const r = await api("/api/admin/model/reload", { method: "POST", json: { confirm: true } }); toast(`Model status: ${r.status}`); adminView("model"); }
      catch (ex) { toast(ex.message, true); }
    } }, "Reload model from disk")),
    can("config:write") && retentionCard());
}

function retentionCard() {
  const out = h("span", { class: "hint", role: "status" });
  const form = h("form", {
    class: "row",
    onsubmit: async (e) => {
      e.preventDefault();
      const days = parseInt(form.days.value, 10);
      if (!window.confirm(`Delete stored raw pages older than ${days} day(s)? Results and reports are kept, but those pages can no longer be re-analysed.`)) return;
      try {
        const r = await api("/api/admin/samples/purge", { method: "POST", json: { older_than_days: days, confirm: true } });
        out.textContent = `Deleted ${r.purged} stored page(s).`;
      } catch (ex) { toast(ex.message, true); }
    },
  },
    h("label", { for: "ret-days" }, "Delete stored pages older than"),
    h("input", { id: "ret-days", name: "days", type: "number", min: 0, max: 3650, value: 30, required: true }),
    h("span", {}, "days"),
    h("button", { class: "danger", type: "submit" }, "Purge"), out);
  return [h("h3", {}, "Data retention"),
    h("p", { class: "muted" }, "Raw pages are only needed to re-analyse; decisions, reasons and short evidence stay in history. ",
      "Set PHISHLENS_RETENTION_DAYS to purge automatically at startup."), form];
}

// ------------------------------------------------------------------ router
async function route() {
  const token = ++navToken;
  if (!state.user) {
    try { setSession(await api("/api/auth/me")); } catch { resetSession(); }
  }
  if (token !== navToken) return;  // a newer navigation started while we were checking the session
  renderToken = token;
  paintChrome();
  if (!state.user) return loginView();

  const [path, query] = (location.hash.slice(1) || "/").split("?");
  const titles = { analyze: "Analyze a page", result: "Analysis result", dataset: "Import dataset", admin: "Administration",
    history: "Analysis history", dashboard: "Dashboard", compare: "Compare analyses", account: "Account" };
  const section = path.split("/").filter(Boolean)[0] || "dashboard";
  $("#page-title").textContent = `PhishLens — ${titles[section] || "Dashboard"}`;
  document.title = `${titles[section] || "Dashboard"} · PhishLens`;
  const params = new URLSearchParams(query || "");
  const parts = path.split("/").filter(Boolean);
  switch (parts[0]) {
    case "analyze": return can("sample:write") ? analyzeView() : historyView(params);
    case "result": return resultView(parts[1]);
    case "dataset": return datasetView();
    case "admin": return adminView(parts[1]);
    case "history": return historyView(params);
    case "dashboard": return dashboardView();
    case "compare": return compareView(params);
    case "account": return accountView();
    default: location.hash = "#/dashboard";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("#logout").addEventListener("click", async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch { /* ignore */ }
    resetSession(); location.hash = ""; route();
  });
  window.addEventListener("hashchange", () => { paintChrome(); route(); });
  route();
});
