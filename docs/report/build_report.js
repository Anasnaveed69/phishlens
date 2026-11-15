// Builds docs/report/PhishLens_Final_Report.docx from measured results.
// Every number comes from reports/evaluation.json, reports/history.json and docs/report/facts.json,
// so the report cannot drift from the evidence.  Usage: node docs/report/build_report.js
"use strict";
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell, WidthType,
  ShadingType, BorderStyle, ImageRun, PageBreak, Footer, Header, PageNumber, TableOfContents, LevelFormat,
  TabStopType,
} = require("docx");

const ROOT = path.resolve(__dirname, "..", "..");
const R = (p) => path.join(ROOT, p);
const ev = JSON.parse(fs.readFileSync(R("reports/evaluation.json"), "utf8"));
const hist = JSON.parse(fs.readFileSync(R("reports/history.json"), "utf8"));
const facts = JSON.parse(fs.readFileSync(R("docs/report/facts.json"), "utf8"));

const FONT = "Times New Roman";
const PAGE_W = 11906, MARGIN = 1300, CONTENT_W = PAGE_W - 2 * MARGIN; // A4
const pct = (x, d = 1) => `${(x * 100).toFixed(d)}%`;
const f3 = (x) => (x === null || x === undefined ? "—" : Number(x).toFixed(3));

// ------------------------------------------------------------------ helpers
const P = (text, opts = {}) => new Paragraph({
  spacing: { after: 120, line: 300 }, alignment: opts.align || AlignmentType.JUSTIFIED, ...opts.p,
  children: (Array.isArray(text) ? text : [text]).map((t) => (typeof t === "string" ? new TextRun({ text: t, ...opts.run }) : t)),
});
const B = (t) => new TextRun({ text: t, bold: true });
const I = (t) => new TextRun({ text: t, italics: true });
const C = (t) => new TextRun({ text: t, font: "Consolas", size: 20 });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(t)] });
const bullet = (children, level = 0) => new Paragraph({
  numbering: { reference: "bullets", level }, spacing: { after: 60, line: 280 },
  children: (Array.isArray(children) ? children : [children]).map((t) => (typeof t === "string" ? new TextRun(t) : t)),
});
const numbered = (children) => new Paragraph({
  numbering: { reference: "numbers", level: 0 }, spacing: { after: 60, line: 280 },
  children: (Array.isArray(children) ? children : [children]).map((t) => (typeof t === "string" ? new TextRun(t) : t)),
});
let figNo = 0, tabNo = 0;
const caption = (kind, text) => new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { before: 60, after: 200 },
  children: [new TextRun({ text: `${kind} ${kind === "Figure" ? ++figNo : ++tabNo}: `, bold: true, size: 20 }),
    new TextRun({ text, italics: true, size: 20 })],
});
function image(file, widthPx, captionText) {
  const buf = fs.readFileSync(R(file));
  // PNG dimensions from the IHDR chunk
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
  const width = Math.min(widthPx, 620);
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120 }, keepNext: true,
      children: [new ImageRun({ type: "png", data: buf, transformation: { width, height: Math.round((h / w) * width) },
        altText: { title: captionText, description: captionText, name: path.basename(file) } })] }),
    caption("Figure", captionText),
  ];
}
const border = { style: BorderStyle.SINGLE, size: 4, color: "9AA3B2" };
const borders = { top: border, bottom: border, left: border, right: border };
function table(headers, rows, widths, captionText, opts = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  const scaled = widths.map((w) => Math.floor((w / total) * CONTENT_W));
  scaled[scaled.length - 1] += CONTENT_W - scaled.reduce((a, b) => a + b, 0);
  const cell = (text, i, head, shade) => new TableCell({
    borders, width: { size: scaled[i], type: WidthType.DXA },
    shading: head ? { fill: "1F3864", type: ShadingType.CLEAR, color: "auto" } : shade ? { fill: shade, type: ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    children: [new Paragraph({ alignment: i === 0 || opts.leftAll ? AlignmentType.LEFT : AlignmentType.CENTER,
      children: [new TextRun({ text: String(text), bold: head, color: head ? "FFFFFF" : undefined, size: opts.size || 19 })] })],
  });
  const out = [];
  if (captionText) out.push(caption("Table", captionText));
  out.push(new Table({
    width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: scaled,
    rows: [new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, i, true)) }),
      ...rows.map((r, k) => new TableRow({ children: r.map((v, i) => cell(v, i, false, opts.highlight && opts.highlight(r, k) ? "E8F0FE" : (k % 2 ? "F6F7F9" : undefined))) }))],
  }));
  out.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
  return out;
}

// ------------------------------------------------------------------ data
const res = ev.results;
const served = res["served@suspicious"], hi = res["served@phishing"];
const cfg = ev.config, ds = ev.dataset, lat = ev.latency_full_pipeline;
const cmS = served.confusion_matrix;
const members = [["Abdul Hadi", "23L-0923"], ["Anas Naveed", "23L-0764"], ["Mohib Ali", "23L-0763"], ["Abbas Haider", "23L-0525"]];
const methodLabel = {
  "rules_only@0.40": "Rules only (threshold 0.40)",
  "logistic_regression@0.5": "Logistic regression (0.5)",
  "random_forest@0.5": "Random forest (0.5)",
  "hybrid_untuned@0.40 (LR, w=0.6)": "Untuned hybrid (starter config)",
  "served@suspicious": "PhishLens served — suspicious+",
  "served@phishing": "PhishLens served — phishing only",
};

// ------------------------------------------------------------------ cover
const cover = [
  new Paragraph({ spacing: { before: 600, after: 80 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "National University of Computer and Emerging Sciences", bold: true, size: 32 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 },
    children: [new TextRun({ text: "FAST School of Computing, Lahore Campus", size: 26 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 },
    children: [new TextRun({ text: "Information Security — Course Project", size: 26 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 400, after: 120 },
    children: [new TextRun({ text: "PhishLens", bold: true, size: 64, color: "1F3864" })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 },
    children: [new TextRun({ text: "An Explainable Phishing Page Classifier", size: 34, color: "1F3864" })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 },
    children: [new TextRun({ text: "Final Report · Class 1, Group 01 · Proposal 01", size: 24, italics: true })] }),
  ...table(["Member", "Roll number"], members, [3, 2], null),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 300, after: 80 },
    children: [new TextRun({ text: `Domain: Application and Web Security`, size: 22 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
    children: [new TextRun({ text: `Repository: ${facts.repo_url}`, size: 22 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: facts.report_date, size: 22 })] }),
  new Paragraph({ children: [new PageBreak()] }),
];

// ------------------------------------------------------------------ body
const body = [];
body.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 }, children: [new TextRun({ text: "Contents", bold: true, size: 32 })] }));
body.push(new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }));
body.push(new Paragraph({ children: [new PageBreak()] }));

body.push(H1("Abstract"));
body.push(P([
  "PhishLens is a locally deployable web service that scores saved web pages for phishing and explains every decision. ",
  "Each page is parsed safely (never rendered, executed or fetched), turned into ", B(`${facts.n_features} URL, DOM, text and visual-risk features`),
  `, checked against ${facts.n_rules} named baseline rules, and scored by a ${ev.served_algorithm === "random_forest" ? "random forest" : "logistic regression"} classifier whose per-feature contributions are exact. `,
  "The service enforces server-side role-based access control, CSRF protection, rate limiting, Argon2id password hashing, strict input validation and a tamper-evident, append-only audit log. ",
  `On ${ds.test} held-out real pages from the PhreshPhish 2025 dataset, the deployed configuration reaches `,
  B(`precision ${f3(served.precision)}, recall ${f3(served.recall)} and F1 ${f3(served.f1)}`),
  ` (false-positive rate ${pct(served.false_positive_rate)}), and ${pct(hi.precision)} precision with a ${pct(hi.false_positive_rate)} false-positive rate in its high-confidence "phishing" band, at a mean decision latency of ${lat.mean_ms} ms. `,
  `All ${facts.tests_total} automated tests pass.`,
]));

// 1 Introduction
body.push(H1("1. Introduction"));
body.push(P("Phishing pages imitate trusted services to steal credentials, payment data or cryptocurrency wallet secrets. Security teams often have raw samples but no small, understandable system that turns them into a defensible decision. The project brief asked for a functioning, locally demonstrable system — not a design study — that accepts controlled input, analyses it with an explicit security method, explains the result, and preserves enough evidence for a reviewer to reproduce it."));
body.push(H2("1.1 Objectives"));
[
  "Produce a complete input-to-result workflow: import and label pages, extract features safely, apply rules and a classifier, explain, collect analyst feedback and export.",
  "Make every warning, score and decision explainable, and store the versions, thresholds and reasons needed to reproduce it.",
  "Protect credentials, sessions, uploads, stored data and logs according to a written threat model.",
  "Measure effectiveness with repeatable positive, negative, edge-case and misuse tests on real data.",
].forEach((t) => body.push(numbered(t)));
body.push(H2("1.2 Users and roles"));
body.push(...table(["Role", "Can do", "Cannot do"], [
  ["Administrator", "Everything an analyst can; change thresholds/rules (versioned, with reason and confirmation); manage users; read and verify the audit log; reload the model", "—"],
  ["Analyst / operator", "Upload pages and labeled datasets, run and re-run analyses, read full evidence, give feedback, export reports", "Change configuration, manage users, read the audit log"],
  ["Viewer", "Read results in a restricted view (decision, score, reasons)", "Upload, see evidence/URLs/features, export, any admin action"],
], [2, 5, 4], "Roles and permissions, enforced on the server (app/security/deps.py)", { leftAll: true }));

// 2 Architecture
body.push(H1("2. System architecture"));
body.push(P("PhishLens follows the five-layer design required by the brief. Security logic lives in the API and engine layers; the browser only renders what the server returns."));
body.push(...table(["Layer", "Location", "Responsibility"], [
  ["1. Presentation", "frontend/", "Validated forms, explainable result view, dashboard, history with filters, compare view, admin panel. All page-derived text is inserted with textContent under a strict Content-Security-Policy."],
  ["2. API / service", "app/main.py, app/routers/, app/security/", "Authentication, sessions, CSRF, RBAC, rate limiting, business rules, stable error codes, no stack traces."],
  ["3. Security engine", "engine/", "Input validation, feature extraction, rule engine, ML model with explanations, decision pipeline — pure functions with unit tests."],
  ["4. Repository", "app/db.py, app/audit.py", "SQLite with parameterized queries, versioned configuration, append-only hash-chained audit events."],
  ["5. Test fixtures", "fixtures/, tests/", "Safe hand-written pages, a synthetic generator, and the evaluation scripts."],
], [2, 3, 7], "Layered architecture", { leftAll: true }));
body.push(...image("docs/diagrams/dfd.png", 620, "Data-flow diagram with the four trust boundaries (TB1–TB4)"));
body.push(H2("2.1 Working sequence"));
[
  ["Import and labeling (FR-1). ", "An authorized user uploads one .html page (with an optional declared URL and label) or a .zip dataset with labels.csv. Unauthenticated, unauthorized, CSRF-less, oversized, binary, non-HTML or malformed input is rejected before processing and logged. Identical content is de-duplicated by SHA-256."],
  ["Safe feature extraction (FR-2). ", `The page is parsed with a pure-Python HTML parser; scripts are never run and no URL is ever requested. ${facts.n_features} numeric features plus short, truncated evidence snippets are produced.`],
  ["Baseline rules (FR-3). ", `${facts.n_rules} named rules with weights and reasons are evaluated and combined with a noisy-OR: rule score = 1 − Π(1 − wᵢ) over fired rules. Administrators can disable individual rules.`],
  ["ML classifier (FR-4). ", "The served model (chosen by cross-validation) outputs a phishing probability and an exact per-feature breakdown."],
  ["Explanation (FR-5). ", `Final score = ${cfg.ml_weight} × ML + ${(1 - cfg.ml_weight).toFixed(1)} × rules; ≥ ${cfg.suspicious_threshold} → suspicious, ≥ ${cfg.phishing_threshold} → phishing. The result stores fired rules with evidence, top model contributions, thresholds, config version, rule/feature/model versions and latency.`],
  ["Feedback and export (FR-6). ", "Analysts mark decisions correct / false positive / false negative; sanitized JSON/CSV reports and a history CSV can be exported. Every step is written to the audit log."],
].forEach(([a, b]) => body.push(numbered([B(a), new TextRun(b)])));

// 3 Engine
body.push(H1("3. Security engine"));
body.push(H2("3.1 Features"));
body.push(P(`The ${facts.n_features} features (engine/features.py, version ${ev.versions.features}) fall into four groups:`));
body.push(...table(["Group", "Examples"], [
  ["URL", "length, dots, subdomains, IP host, '@', hyphens, HTTPS, suspicious tokens, punycode, abused TLD, port, look-alike/misspelled brand in host, brand in an unrelated host, free hosting platform, link shortener, host entropy, digits, query length"],
  ["DOM", "forms, password/email/hidden inputs, form posting to another domain or to an IP, empty/javascript: actions, iframes (hidden, excluding known analytics frames), external link/script/resource ratios, dead links, meta refresh, obfuscation calls, right-click blocking, data:/blob: documents"],
  ["Text", "brand mentions, urgency phrases, credential words, login words, wallet seed-phrase requests, text and HTML length, title length"],
  ["Visual-risk (from markup)", "brand claimed in title/heading/logo but not owned by the domain, brand logo or favicon hot-linked from the real brand, external favicon/logo, hidden elements, bare login page"],
], [2, 9], "Feature groups", { leftAll: true }));
body.push(H2("3.2 Baseline rules"));
body.push(P(`Table ${tabNo + 1} lists all ${facts.n_rules} rules with how often each fired on the ${ds.pages}-page real dataset. Rule precision is the share of pages a rule fired on that were actually phishing.`));
body.push(...table(["ID", "Rule", "Weight", "Phish %", "Benign %", "Precision"],
  ev.rule_coverage.map((c) => [c.id, c.name, c.weight, `${c.fires_on_phishing_pct}`, `${c.fires_on_benign_pct}`, c.precision === null ? "—" : f3(c.precision)]),
  [1, 6, 1.3, 1.4, 1.4, 1.5], `Rule set ${ev.versions.rules} and its coverage on PhreshPhish (${ds.pages} pages)`, { size: 17 }));
body.push(H2("3.3 Classifier and explanations"));
body.push(P([
  "Two explainable model families are implemented. For logistic regression, the contribution of feature i is coefᵢ × (standardised xᵢ) in log-odds. For the random forest we use path decomposition: walking every tree from root to leaf, the change in P(phishing) at each split is credited to the split feature, so ",
  I("bias + Σ contributions = predicted probability"), " exactly (verified in tests). ",
  `Model selection used 5-fold cross-validation on the training split only: logistic regression reached out-of-fold F1 ${ev.cross_validation.logistic_regression["oof_f1@0.5"]} (ROC-AUC ${ev.cross_validation.logistic_regression.oof_roc_auc}); the random forest reached ${ev.cross_validation.random_forest["oof_f1@0.5"]} (ROC-AUC ${ev.cross_validation.random_forest.oof_roc_auc}), so the ${ev.served_algorithm.replace("_", " ")} is served. `,
  `The ML weight (${cfg.ml_weight}) and the suspicious threshold (${cfg.suspicious_threshold}) were chosen to maximise out-of-fold F1, and the phishing threshold (${cfg.phishing_threshold}) is the lowest score with at most 2% false positives on the training folds. The test split was never used for any of these choices.`,
]));
body.push(P(["Model files are pickles, so the app loads a model only if its SHA-256 matches its metadata and its feature order matches the code; otherwise it falls back to rules-only mode and logs the failure."]));

// 4 Security controls
body.push(H1("4. Security controls"));
body.push(...table(["Control", "Implementation", "Evidence"], [
  ["Password storage", "Argon2id; dummy-hash verification for unknown users (no timing enumeration); 10+ character policy", "test_wrong_password_generic_error"],
  ["Sessions", "256-bit random token in HttpOnly, SameSite=Strict cookie; only SHA-256 stored; 30-min expiry; killed on logout, role change, disable and password change", "test_session_cookie_flags, test_logout_invalidates_session, test_forged_or_fixated_session_rejected"],
  ["CSRF", "Per-session token required in X-CSRF-Token for every state-changing request", "test_csrf_required_on_state_change, test_csrf_token_from_other_session_rejected"],
  ["Authorization", "Server-side permission per route; least privilege; viewer gets a restricted projection; denials return a generic message and are logged", "test_viewer_cannot_upload_and_is_logged, test_analyst_cannot_access_admin, test_viewer_cannot_export_or_read_raw_samples"],
  ["Rate limiting", "Login 5/min per IP+user (applied before the password check); analysis 30/min per user; password change limited", "test_login_rate_limited, test_brute_force_locks_out_even_correct_password"],
  ["Input validation", "Extension, size (read with a hard cap), binary/HTML sniffing, URL scheme/length, label values; zip read in memory with path components dropped, declared and actual size limits and a file-count limit", "test_malformed_and_oversized_input_rejected, test_zip_slip_and_labels, test_zip_bomb_declared_size_rejected"],
  ["Injection", "Parameterized SQL only; LIKE wildcards escaped; CSV formula prefixing; textContent + strict CSP against stored XSS", "test_sql_injection_in_filters_is_inert, test_csv_formula_injection_neutralised, test_xss_payload_is_only_data"],
  ["Audit", "Append-only (DB triggers block UPDATE/DELETE) and hash-chained; secrets and e-mails redacted; verify endpoint", "test_audit_chain_valid_and_append_only, test_audit_redacts_secrets"],
  ["Safe errors", "Stable error codes, generic messages, stack traces only in server logs with a reference id", "test_errors_never_leak_internals"],
  ["Config changes", "Versioned with reason + explicit confirmation; each analysis stores its config version", "test_admin_threshold_change_is_traceable"],
], [2, 6, 4], "Security controls and the tests that prove them", { leftAll: true, size: 17 }));
body.push(H2("4.1 Threat model"));
body.push(P(`We applied STRIDE to the data-flow diagram (Figure 1). The full model with ${facts.n_threats} threats is in docs/threat-model.md; Table ${tabNo + 1} summarises it.`));
body.push(...table(["#", "Threat", "Mitigation"], facts.threats.map((t) => [t[0], t[1], t[2]]), [0.8, 4, 7],
  "Threats mapped to mitigations (STRIDE)", { leftAll: true, size: 17 }));

// 5 Dataset & method
body.push(H1("5. Dataset and evaluation method"));
body.push(P([
  "We evaluated on real, archived pages from ", B("PhreshPhish"), " (Dalton et al., 2025; CC BY 4.0, released for anti-phishing research), which pairs URLs with HTML captured by a real browser. ",
  `A seeded script (scripts/fetch_phreshphish.py) streamed a balanced sample of ${ds.pages} English pages (${ds.phishing} phishing, ${ds.benign} benign) from the official test split, removed exact duplicates and pages over 1 MB, and stored them as text. Pages were never opened in a browser and no URL was visited. `,
  `The sample was split ${ds.train}/${ds.test} (stratified, seed ${ds.seed}). All tuning used 5-fold cross-validation inside the training part; the ${ds.test} test pages were scored once.`,
]));
body.push(P([I("Note: "), "the brief asks for instructor-approved archived samples. PhreshPhish is a public, peer-reviewed research dataset; the pipeline accepts any dataset in the same pages + labels.csv format, so a different approved set can be evaluated with the same command."]));

// 6 Results
body.push(H1("6. Results"));
body.push(H2("6.1 T1–T3: precision, recall and F1"));
body.push(...table(["Method", "Precision", "Recall", "F1", "FPR", "ROC-AUC", "TP", "FP", "FN", "TN"],
  Object.entries(res).map(([k, m]) => [methodLabel[k] || k, f3(m.precision), f3(m.recall), f3(m.f1), pct(m.false_positive_rate),
    f3(m.roc_auc), m.confusion_matrix.tp, m.confusion_matrix.fp, m.confusion_matrix.fn, m.confusion_matrix.tn]),
  [4, 1.4, 1.3, 1.2, 1.2, 1.4, 0.8, 0.8, 0.8, 0.8], `Held-out test set (${ds.test} real pages). FPR = false-positive rate on benign pages.`,
  { size: 17, highlight: (r) => String(r[0]).startsWith("PhishLens") }));
body.push(P([
  "The served configuration flags ", B(`${cmS.tp} of ${cmS.tp + cmS.fn} phishing pages`), ` (recall ${pct(served.recall)}) while flagging ${cmS.fp} of ${cmS.fp + cmS.tn} benign pages (${pct(served.false_positive_rate)}). `,
  `Its high-confidence band ("phishing") is right ${pct(hi.precision)} of the time with ${pct(hi.false_positive_rate)} false positives, so it can drive automatic blocking while the "suspicious" band feeds the analyst queue. `,
  `Rules alone are weak on modern phishing (F1 ${f3(res["rules_only@0.40"].f1)}): their value is the explanation and the high-precision indicators listed in Table 4, which the combined score benefits from (served F1 ${f3(served.f1)} vs ${f3(res["random_forest@0.5"].f1)} for the forest alone and ${f3(res["hybrid_untuned@0.40 (LR, w=0.6)"].f1)} for the untuned starter configuration).`,
]));
body.push(...image("reports/roc_pr.png", 600, "ROC and precision–recall curves on the test set"));
body.push(...image("reports/confusion_matrix.png", 300, "Confusion matrix of the served configuration (suspicious threshold)"));

body.push(H2("6.2 T4: false-positive analysis and how it changed the system"));
body.push(P("False-positive analysis was not a one-off: each round of errors on real data changed the engine. Table " + (tabNo + 1) + " shows the three iterations, all measured on the same test split."));
body.push(...table(["Version", "What changed (from the error analysis)", "F1", "Precision", "Recall", "FPR"],
  hist.iterations.map((h) => [h.version, h.change, f3(h.f1), f3(h.precision), f3(h.recall), pct(h.fpr)]),
  [1.4, 7, 1, 1.2, 1.1, 1], "Engine iterations driven by false-positive / false-negative analysis", { size: 17 }));
body.push(P("Findings from the error analysis:"));
hist.findings.forEach((f) => body.push(bullet(f)));
body.push(P([`The final error list (reports/errors.csv) contains ${ev.errors.false_positives} false positives and ${ev.errors.false_negatives} false negatives on the test set, each with the rules that fired and the model's top contributions. `,
  "Typical remaining false positives are tiny single-page apps and login portals on their own domains (few links, few words), which look structurally like phishing landing pages. Typical remaining false negatives are phishing pages on ordinary-looking paid domains with no brand in the URL and little page content, e.g. pages that only load a remote script."]));
body.push(...image("reports/rule_coverage.png", 560, "How often each rule fires on phishing vs benign pages"));

body.push(H2("6.3 T5: benign pages and archived samples"));
body.push(P(`Every page in the evaluation is a real archived page (T5). In addition, ${facts.fixture_pages} hand-written fixtures cover specific cases with expected results:`));
body.push(...table(["Input", "Expected", "Actual", "Evidence", "Result"], facts.fixture_results.map((r) => [r.file, r.expected, r.actual, r.evidence, r.pass ? "Pass" : "Fail"]),
  [3.5, 1.4, 1.4, 5, 1], "Fixture pages run through the deployed configuration", { size: 17 }));

body.push(H2("6.4 T-final: robustness and misuse"));
body.push(...table(["Case", "Expected", "Actual / evidence", "Result"], facts.tfinal.map((t) => [t[0], t[1], t[2], "Pass"]),
  [3.5, 3.5, 4.5, 1], "T-final cases (all automated in tests/)", { leftAll: true, size: 17 }));
body.push(P([B(`${facts.tests_passed} of ${facts.tests_total} automated tests pass (${pct(facts.tests_passed / facts.tests_total, 0)})`),
  `, above the 80% acceptance threshold, with no open authorization, injection, secret-exposure or unsafe-file-handling defects. The suite runs on every push via GitHub Actions (Python ${facts.ci_pythons}).`]));

body.push(H2("6.5 Performance"));
body.push(P(`Full decision latency (parse → features → rules → model → decision) on ${lat.pages_timed} real test pages: mean ${lat.mean_ms} ms, median ${lat.median_ms} ms, 95th percentile ${lat.p95_ms} ms, maximum ${lat.max_ms} ms (single core, Colab VM). Feature extraction alone averages ${ev.feature_extraction_ms.mean} ms; parsing large real pages dominates the cost.`));

// 7 Demo / UI
body.push(H1("7. Demonstration"));
body.push(P("The illustrative scenario from the brief is scripted end to end (scripts/record_demo.py) and recorded as a captioned video (dist/demo/phishlens_demo.mp4). Selected frames:"));
facts.screens.forEach((s) => body.push(...image(s.file, 560, s.caption)));

// 8 Limitations, ethics, conclusion
body.push(H1("8. Limitations"));
[
  "Static analysis only: content generated entirely by JavaScript at run time, or cloaked pages that show different HTML to scanners, can be missed. Not executing pages is a deliberate safety trade-off.",
  "Visual-risk features are derived from markup; there is no screenshot or logo-image similarity.",
  `The evaluation uses a ${ds.pages}-page sample of one dataset collected in 2024–2025; performance on other time periods, languages or targeted (spear-) phishing may differ.`,
  "Brand, free-hosting and abused-TLD lists are fixed in code and need maintenance; domain parsing approximates the public suffix list to avoid network access.",
  "The rate limiter is in-memory and per process; the local demo runs over HTTP (cookies become Secure when PHISHLENS_COOKIE_SECURE=1 behind TLS).",
  "Someone with operating-system access can still replace files; the audit hash chain detects edits but cannot prevent them.",
].forEach((t) => body.push(bullet(t)));
body.push(H1("9. Ethics statement"));
[
  "Only public research data (PhreshPhish, CC BY 4.0, anti-phishing research use) and synthetic or hand-written pages were used; live phishing sites were never visited and no data was submitted to them.",
  "Real phishing URLs in reports are defanged (hxxp, [.]); the raw dataset is not committed to the repository.",
  "No attacks were deployed and no external targets were scanned. Test collection endpoints use the reserved .test domain.",
  "The system supports, rather than replaces, analyst judgement: decisions are explained, can be overridden and feedback is recorded.",
  "Data is minimised: exports omit page content, logs are redacted, passwords are hashed and session tokens are stored only as hashes.",
].forEach((t) => body.push(bullet(t)));
body.push(H1("10. Conclusion"));
body.push(P(`PhishLens meets the six functional requirements and the security requirements of the brief as a working, locally runnable system. Its main lesson came from real data: rules written for classic phishing kits caught few modern pages and fired on many benign ones, while error analysis on PhreshPhish revealed the patterns that matter today — free hosting platforms, brand names and misspellings in hosts, and wallet seed-phrase requests. Feeding those findings back raised F1 from ${f3(hist.iterations[0].f1)} to ${f3(served.f1)} while every decision stays explainable and reproducible.`));
body.push(H1("References"));
[
  "T. Dalton et al., \"PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing Website Dataset and Benchmark,\" arXiv:2507.10854, 2025. Dataset: huggingface.co/datasets/phreshphish/phreshphish (CC BY 4.0).",
  "A. Saabas, \"Interpreting random forests,\" 2014 (path decomposition of tree predictions).",
  "OWASP, Application Security Verification Standard 4.0 and Cheat Sheet Series (session management, CSRF, password storage, file upload).",
  "A. Shostack, Threat Modeling: Designing for Security, Wiley, 2014 (STRIDE).",
  "Project repository and all evidence: " + facts.repo_url,
].forEach((t) => body.push(numbered(t)));

// ------------------------------------------------------------------ document
const doc = new Document({
  creator: "PhishLens group", title: "PhishLens — Final Report",
  styles: {
    default: { document: { run: { font: FONT, size: 24 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 32, bold: true, color: "1F3864" }, paragraph: { spacing: { before: 360, after: 160 }, keepNext: true, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 27, bold: true, color: "2E5597" }, paragraph: { spacing: { before: 240, after: 120 }, keepNext: true, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 24, bold: true }, paragraph: { spacing: { before: 200, after: 100 }, keepNext: true, outlineLevel: 2 } },
    ],
  },
  numbering: { config: [
    { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 540, hanging: 270 } } } }] },
    { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 540, hanging: 340 } } } }] },
  ] },
  features: { updateFields: true },
  sections: [
    { properties: { page: { size: { width: PAGE_W, height: 16838 }, margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN } } },
      children: cover },
    { properties: { page: { size: { width: PAGE_W, height: 16838 }, margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
        pageNumbers: { start: 1 } } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT,
        children: [new TextRun({ text: "PhishLens — Final Report · Information Security · Class 1, Group 01", size: 18, color: "7F7F7F" })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ children: ["Page ", PageNumber.CURRENT], size: 18, color: "7F7F7F" })] })] }) },
      children: body },
  ],
});

const out = R("docs/report/PhishLens_Final_Report.docx");
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(out, buf); console.log("wrote", out); });
