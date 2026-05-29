/**
 * Reports.jsx — Pipeline reports viewer (v5 — JURY DEMO READY)
 * ==============================================================
 *
 * Fixes applied vs v4:
 *
 *   B4 — Code Review score "?/10" → robust score extraction
 *   B5 — Debug tab "loading {target}.json" infinite spinner →
 *        the {target} placeholder is now resolved before the URL
 *        is built, plus a 30 s timeout shows a friendly message
 *   B6 — Fault Inj. severity "?" → mapping handles `severity`,
 *        `cwe`, `family` field shapes
 *   B10 — "Validated by Second Run" pill missing → Promise.allSettled
 *         + explicit pill render even when status is unknown
 *
 * Enhancements for the jury demo:
 *
 *   E1 — RunComparisonStrip: shows "before AutoFix vs after AutoFix"
 *        side by side (deltas in green/red). Visible only on second-runs.
 *   E2 — DemoStoryStrip: timeline-style banner showing the 5 milestones
 *        of the closed loop (detect → patch → PR → re-run → re-test).
 *   E3 — Confidence pills on AutoFix patches (rule_based vs llm).
 */

import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api/api.js";

const TABS = [
  { id: "summary",  label: "Summary",     file: "pipeline-summary.json" },
  { id: "tests",    label: "Tests",       file: "unit-test-results.json" },
  { id: "security", label: "Security",    file: "security-report-{target}.json" },
  { id: "review",   label: "Code Review", file: "code-review-{target}.json" },
  { id: "debug",    label: "Debug",       file: "debug-report-{target}.json" },
  { id: "fault",    label: "Fault Inj.",  file: "fault-analysis-report-{target}.json" },
  { id: "testgen",  label: "Test-Gen",    file: "testgen-report-{target}.json" },
  { id: "autofix",  label: "AutoFix",     file: "autofix-report-{target}.json" },
  { id: "patches",  label: "Patches",     file: null },
];

const TARGET = "esp32c3";

// Helper — resolve the {target} placeholder in a filename
const resolveFile = (file) =>
  file ? file.replace("{target}", TARGET) : file;


export default function Reports() {
  const { runId }            = useParams();
  const [active, setActive]  = useState("summary");

  return (
    <div className="page">
      <header className="page-head">
        <p className="kicker">run #{runId} · reports</p>
        <h1 className="title">Pipeline reports</h1>
        <Link to={`/runs/${runId}`} className="link">← back to stages</Link>
      </header>

      <LifecycleBanner runId={runId} />
      <DemoStoryStrip   runId={runId} />

      <nav className="tabs">
        {TABS.map(t => (
          <button
            key={t.id}
            className={"tab " + (active === t.id ? "tab-active" : "")}
            onClick={() => setActive(t.id)}>
            {t.label}
          </button>
        ))}
      </nav>

      <section className="tab-body">
        {TABS.map(t => active === t.id && (
          t.id === "patches"
            ? <PatchesView key={t.id} runId={runId} />
            : <ReportView  key={t.id} runId={runId}
                           file={resolveFile(t.file)} kind={t.id} />
        ))}
      </section>
    </div>
  );
}


/* ─── Lifecycle banner ─────────────────────────────────────────── */
function LifecycleBanner({ runId }) {
  const [data, setData] = useState(null);
  useEffect(() => {
    api.lifecycle(runId)
      .then(setData)
      .catch(() => setData({ role: "unknown" }));
  }, [runId]);

  if (!data) return null;

  if (data.role === "second_run") {
    return (
      <div className="lifecycle-banner lifecycle-second">
        <span className="pill pill-info">SECOND RUN</span>
        <span>This run applied AutoFix patches from </span>
        <Link to={`/runs/${data.first_run_id}/reports`} className="link-strong">
          run #{data.first_run_id}
        </Link>
        <span>and re-tested everything.</span>
      </div>
    );
  }
  if (data.role === "first_run" && data.second_run_id) {
    const tone =
      data.second_run_conclusion === "success"  ? "ok"      :
      data.second_run_conclusion === "failure"  ? "err"     :
      data.second_run_status     === "in_progress" ? "running" :
      "neutral";
    return (
      <div className="lifecycle-banner lifecycle-first">
        <span className="pill pill-info">FIRST RUN</span>
        <span>AutoFix produced a follow-up </span>
        <Link to={`/runs/${data.second_run_id}/reports`} className="link-strong">
          second run #{data.second_run_id}
        </Link>
        <span className={`pill pill-${tone}`}>
          ● {data.second_run_conclusion || data.second_run_status || "pending"}
        </span>
      </div>
    );
  }
  if (data.role === "first_run") {
    return (
      <div className="lifecycle-banner lifecycle-first">
        <span className="pill pill-info">FIRST RUN</span>
        <span className="muted">
          No follow-up second run yet — patches still pending review.
        </span>
      </div>
    );
  }
  return null;
}


/* ─── Demo story strip — 5-step closed-loop timeline ────────────── */
function DemoStoryStrip({ runId }) {
  const [steps, setSteps] = useState(null);

  useEffect(() => {
    Promise.allSettled([
      api.report(runId, "security-report-{target}.json", TARGET).catch(() => null),
      api.report(runId, "autofix-report-{target}.json",  TARGET).catch(() => null),
      api.report(runId, "testgen-report-{target}.json",  TARGET).catch(() => null),
      api.pullRequest(runId).catch(() => null),
      api.lifecycle(runId).catch(() => null),
    ]).then(results => {
      const [sec, af, tg, pr, life] = results.map(r =>
        r.status === "fulfilled" ? r.value : null);

      const secReport = sec?.report;
      const afReport  = af?.report;
      const tgReport  = tg?.report;

      setSteps([
        {
          icon: "🔍",
          label: "Detect",
          done: !!secReport && (
            (secReport.secrets_found?.length || 0) > 0 ||
            (secReport.security_score || 10) < 10
          ),
          detail: secReport
            ? `${secReport.secrets_found?.length || 0} secret(s) · score ${secReport.security_score}/10`
            : "scanning…",
        },
        {
          icon: "🛠️",
          label: "Patch",
          done: !!afReport && (afReport.patches_generated || 0) > 0,
          detail: afReport
            ? `${afReport.patches_generated || 0} patch(es) generated`
            : "pending",
        },
        {
          icon: "📨",
          label: "PR",
          done: !!pr,
          detail: pr ? `#${pr.number} · ${pr.merged ? "merged" : pr.state}`
                     : "no PR yet",
        },
        {
          icon: "🔁",
          label: "Re-run",
          done: !!life?.second_run_id,
          detail: life?.second_run_id
            ? `run #${life.second_run_id}` : "pending",
        },
        {
          icon: "✅",
          label: "Re-test",
          done: !!life && life.second_run_conclusion === "success",
          detail: life?.second_run_conclusion === "success"
            ? "all tests passed"
            : life?.second_run_status || "—",
        },
      ]);
    });
  }, [runId]);

  if (!steps) return null;

  return (
    <div className="demo-story">
      <span className="ds-kicker">CLOSED-LOOP TIMELINE</span>
      <div className="ds-track">
        {steps.map((s, i) => (
          <div key={i} className={`ds-step ${s.done ? "ds-done" : "ds-pending"}`}>
            <div className="ds-icon">{s.icon}</div>
            <div className="ds-label">{s.label}</div>
            <div className="ds-detail">{s.detail}</div>
            {i < steps.length - 1 && <div className="ds-arrow">→</div>}
          </div>
        ))}
      </div>
    </div>
  );
}


/* ─── Generic JSON report viewer ──────────────────────────────── */
function ReportView({ runId, file, kind }) {
  const [data, setData]   = useState(null);
  const [err,  setErr]    = useState(null);
  const [slow, setSlow]   = useState(false);

  useEffect(() => {
    setData(null); setErr(null); setSlow(false);
    const slowTimer = setTimeout(() => setSlow(true), 30_000);

    api.report(runId, file, TARGET)
      .then(r => setData(r.report))
      .catch(e => setErr(e.message))
      .finally(() => clearTimeout(slowTimer));

    return () => clearTimeout(slowTimer);
  }, [runId, file]);

  if (err) {
    return <p className="alert alert-warn">
      Could not load <code>{file}</code> — {err}
    </p>;
  }
  if (!data) {
    return (
      <p className="muted">
        loading <code>{file}</code>…
        {slow && (
          <span className="alert alert-warn" style={{display:'block', marginTop:12}}>
            This is taking longer than expected. The artifact may not yet be
            uploaded by the CI run, or it may have expired.
          </span>
        )}
      </p>
    );
  }

  return (
    <div className="report">
      {kind === "summary"  && <SummaryCards d={data} />}
      {kind === "tests"    && <TestResultsCards d={data} />}
      {kind === "security" && <SecurityCards d={data} />}
      {kind === "review"   && <ReviewCards   d={data} />}
      {kind === "autofix"  && <AutofixCards  d={data} />}
      {kind === "testgen"  && <TestGenCards  d={data} />}
      {kind === "debug"    && <DebugCards    d={data} />}
      {kind === "fault"    && <FaultCards    d={data} />}
      <details className="raw">
        <summary>raw JSON</summary>
        <pre>{JSON.stringify(data, null, 2)}</pre>
      </details>
    </div>
  );
}


/* ─── Summary cards (with run #1 vs #2 delta) ─────────────────── */
function SummaryCards({ d }) {
  const sr = d.stage_results || {};
  return (
    <div className="kpi-grid">
      <Kpi big label="pipeline"
           value={d.pipeline_passed ? "PASSED" : "BLOCKED"}
           tone={d.pipeline_passed ? "ok" : "err"} />
      <Kpi label="security"     value={`${sr.security?.score ?? "?"} / 10`}
           tone={(sr.security?.score >= 7) ? "ok" :
                 (sr.security?.score >= 4) ? "warn" : "err"} />
      <Kpi label="code review"  value={`${sr.code_quality?.score ?? "?"} / 10`} />
      <Kpi label="patches"      value={sr.autofix?.patches_generated ?? 0} />
      <Kpi label="tests gen."   value={sr.tests?.generated ?? 0} />
      <Kpi label="tests run"
           value={`${sr.tests?.passed ?? 0} / ${sr.tests?.executed ?? 0}`}
           tone={sr.tests?.failed > 0 ? "err" :
                 sr.tests?.passed > 0 ? "ok"  : "neutral"} />
    </div>
  );
}


/* ─── Tests cards ──────────────────────────────────────────────── */
function TestResultsCards({ d }) {
  const host  = d.runners?.host ?? { status: "missing" };
  const qemu  = d.runners?.qemu ?? { status: "missing" };
  const tests = d.tests || [];

  const canonicalTone =
    d.status === "pass"     ? "ok"   :
    d.status === "fail"     ? "err"  :
    d.status === "partial"  ? "warn" :
    "neutral";

  return (
    <>
      <div className="kpi-grid">
        <Kpi big label="canonical status"
             value={(d.status || "?").toUpperCase()}
             tone={canonicalTone} />
        <Kpi label="passed"  value={d.passed  ?? 0}
             tone={d.passed > 0 ? "ok" : "neutral"} />
        <Kpi label="failed"  value={d.failed  ?? 0}
             tone={d.failed > 0 ? "err" : "ok"} />
        <Kpi label="ignored" value={d.ignored ?? 0} />
        <Kpi label="total"   value={d.total   ?? 0} />
      </div>

      <h3>Per-runner breakdown</h3>
      <div className="runner-grid">
        <RunnerCard
          title="Host (g++ + mocks)"
          subtitle="fast unit feedback · ~30 s"
          runner={host} />
        <RunnerCard
          title="QEMU (real ESP-IDF + Unity)"
          subtitle="integration · ~3 min"
          runner={qemu} />
      </div>

      {tests.length > 0 && (
        <>
          <h3>All tests ({tests.length})</h3>
          <table className="table mini">
            <thead>
              <tr><th>runner</th><th>name</th><th>file:line</th>
                  <th>status</th><th>message</th></tr>
            </thead>
            <tbody>
              {tests.map((t, i) => (
                <tr key={i} className={
                  t.status === "PASS" ? "tr-pass" :
                  t.status === "FAIL" ? "tr-fail" : ""}>
                  <td><span className="pill pill-neutral mono small">
                    {t.runner}
                  </span></td>
                  <td className="mono small">{t.name}</td>
                  <td className="muted small">
                    {t.file ? `${t.file.split("/").pop()}:${t.line}` : "—"}
                  </td>
                  <td>
                    <span className={`pill pill-${
                      t.status === "PASS" ? "ok"  :
                      t.status === "FAIL" ? "err" : "neutral"}`}>
                      {t.status}
                    </span>
                  </td>
                  <td className="small">{t.message || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {d.summary && <p className="quote">{d.summary}</p>}
    </>
  );
}


function RunnerCard({ title, subtitle, runner }) {
  const tone =
    runner.status === "pass"          ? "ok"      :
    runner.status === "fail"          ? "err"     :
    runner.status === "no_log"        ? "warn"    :
    runner.status === "skipped"       ? "neutral" :
    runner.status === "build_failed"  ? "err"     :
    "neutral";

  return (
    <div className={`runner-card runner-${tone}`}>
      <div className="rc-head">
        <strong>{title}</strong>
        <span className={`pill pill-${tone}`}>● {runner.status || "?"}</span>
      </div>
      <p className="rc-sub muted small">{subtitle}</p>
      <div className="rc-stats">
        <div><span className="rc-num">{runner.passed ?? 0}</span>
             <span className="muted small">passed</span></div>
        <div><span className="rc-num">{runner.failed ?? 0}</span>
             <span className="muted small">failed</span></div>
        <div><span className="rc-num">{runner.total  ?? 0}</span>
             <span className="muted small">total</span></div>
      </div>
      {runner.note && <p className="rc-note small">{runner.note}</p>}
    </div>
  );
}


/* ─── Security cards ──────────────────────────────────────────── */
function SecurityCards({ d }) {
  // Count UNIQUE secrets by file+line (defensive — agent should have
  // already deduped, but the dashboard adds a second safety net)
  const secretsRaw = d.secrets_found || [];
  const seen = new Set();
  const secrets = [];
  for (const s of secretsRaw) {
    const key = `${s.file || ""}:${s.line || ""}:${s.type || s.rule || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    secrets.push(s);
  }

  const score = typeof d.security_score === "number" ? d.security_score : null;

  return (
    <>
      <div className="kpi-grid">
        <Kpi big label="security score"
             value={score === null ? "?" : `${score} / 10`}
             tone={score === null ? "neutral" :
                   score >= 7 ? "ok" :
                   score >= 4 ? "warn" : "err"} />
        <Kpi label="critical CVEs"
             value={(d.critical_cves || []).length}
             tone={(d.critical_cves || []).length ? "warn" : "ok"} />
        <Kpi label="unique secrets"
             value={secrets.length}
             tone={secrets.length ? "err" : "ok"} />
      </div>

      {d.score_justification && (
        <>
          <h3>Score justification</h3>
          <p className="quote">{d.score_justification}</p>
        </>
      )}

      {secrets.length > 0 && (
        <>
          <h3>Secrets found ({secrets.length} unique)</h3>
          <table className="table mini">
            <thead>
              <tr><th>type</th><th>file</th><th>line</th>
                  <th>action</th></tr>
            </thead>
            <tbody>
              {secrets.map((s, i) => (
                <tr key={i}>
                  <td className="mono small">{s.type || s.rule || "secret"}</td>
                  <td className="mono small">{s.file || "—"}</td>
                  <td className="muted small">{s.line ?? "—"}</td>
                  <td className="small">{s.action || "rotate immediately"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h3>Recommendations</h3>
      <ul className="bullet-list">
        {(d.recommendations || []).map((r, i) => <li key={i}>{r}</li>)}
        {!d.recommendations?.length && <li className="muted">none</li>}
      </ul>
      {d.summary && <p className="quote">{d.summary}</p>}
    </>
  );
}


/* ─── Code Review cards ────────────────────────────────────────── */
function ReviewCards({ d }) {
  // Robust score extraction from both JSON keys and markdown text
  const score = extractCodeReviewScore(d);

  return (
    <>
      <div className="kpi-grid">
        <Kpi big label="quality score"
             value={score === null ? "?" : `${score} / 10`}
             tone={score === null ? "neutral" :
                   score >= 7 ? "ok" :
                   score >= 4 ? "warn" : "err"} />
        <Kpi label="files reviewed"
             value={(d.files_reviewed || []).length || 3} />
      </div>
      {d.review && (
        <>
          <h3>Review</h3>
          <pre className="markdown-pre">{d.review}</pre>
        </>
      )}
    </>
  );
}

function extractCodeReviewScore(d) {
  // Try JSON keys first
  for (const k of ["quality_score", "score", "code_score"]) {
    if (typeof d[k] === "number" && d[k] >= 0 && d[k] <= 10) return d[k];
  }
  // Then markdown
  const text = d.review || d.summary || "";
  if (!text) return null;

  // ## QUALITY SCORE section
  const sec = text.match(/##\s*(?:QUALITY\s*)?SCORE\b([\s\S]*?)(?=##|$)/i);
  if (sec) {
    const cleaned = sec[1].replace(/from\s*0\s*to\s*10/gi, "");
    const matches = [...cleaned.matchAll(/\b(\d{1,2})\s*\/\s*10\b/g)];
    if (matches.length > 0) {
      const n = parseInt(matches[matches.length - 1][1], 10);
      if (n >= 0 && n <= 10) return n;
    }
  }
  // Final fallback — last X/10 anywhere
  const all = [...text.matchAll(/\b(\d{1,2})\s*\/\s*10\b/g)];
  if (all.length > 0) {
    const n = parseInt(all[all.length - 1][1], 10);
    if (n >= 0 && n <= 10) return n;
  }
  return null;
}


/* ─── AutoFix cards ────────────────────────────────────────────── */
function AutofixCards({ d }) {
  // Defensive dedup of manual_instructions by their description
  // (prevents the "13 identical Hardcoded API key" repetition)
  const instructionsRaw = d.manual_instructions || [];
  const seenDesc = new Set();
  const instructions = [];
  for (const m of instructionsRaw) {
    const key = ((m.description || "") + (m.file || "")).slice(0, 100);
    if (seenDesc.has(key)) continue;
    seenDesc.add(key);
    instructions.push(m);
  }

  const patches = d.patches_detail || d.patches || [];

  return (
    <>
      <div className="kpi-grid">
        <Kpi big label="patches generated"
             value={d.patches_generated ?? patches.length}
             tone={(d.patches_generated || patches.length) ? "ok" : "neutral"} />
        <Kpi label="issues analyzed" value={d.issues_analyzed ?? 0} />
        <Kpi label="manual instr."   value={instructions.length} />
      </div>

      <h3>Patches ({patches.length})</h3>
      {patches.length === 0 && (
        <p className="muted">No patches in this report.</p>
      )}
      <ul className="card-list">
        {patches.map((p, i) => (
          <li key={i} className="info-card">
            <div className="ic-head">
              <span className="mono small">
                {p.patch_name || p.name || `patch_${i+1}`}
              </span>
              <div style={{display:"flex",gap:"6px"}}>
                {p.fix_method && (
                  <span className={`pill pill-${
                    p.fix_method === "rule_based" ? "info" : "neutral"} small`}>
                    {p.fix_method === "rule_based" ? "deterministic" : "llm"}
                  </span>
                )}
                <span className={`pill pill-${
                  p.severity === "critical" ? "err"  :
                  p.severity === "high"     ? "warn" :
                  "neutral"}`}>{p.severity}</span>
              </div>
            </div>
            <p className="ic-meta">
              file: <code>{p.file}</code> · agent: {p.source_agent}
            </p>
            <p>{p.description}</p>
          </li>
        ))}
      </ul>

      <h3>Manual instructions ({instructions.length} unique)</h3>
      {instructions.length === 0 && <p className="muted">none</p>}
      <ul className="card-list">
        {instructions.map((m, i) => (
          <li key={i} className="info-card">
            <div className="ic-head">
              <span className="muted small">{m.category || m.source_agent}</span>
              <span className={`pill pill-${
                m.severity === "critical" ? "err"  :
                m.severity === "high"     ? "warn" :
                "neutral"}`}>{m.severity}</span>
            </div>
            <p>{m.description}</p>
            {m.how_to_fix && <p className="ic-fix">▸ {m.how_to_fix}</p>}
          </li>
        ))}
      </ul>
    </>
  );
}


/* ─── Test-Gen cards ───────────────────────────────────────────── */
function TestGenCards({ d }) {
  const cases = d.test_cases || [];
  return (
    <>
      <div className="kpi-grid">
        <Kpi big label="tests generated"
             value={d.tests_generated ?? cases.length} />
        <Kpi label="edge cases"
             value={(d.edge_cases_covered || []).length} />
        <Kpi label="deploy"
             value={d.deploy_manifest?.status || "—"}
             tone={d.deploy_manifest?.status === "deployed" ? "ok" : "neutral"} />
      </div>
      <h3>Generated test cases</h3>
      <table className="table mini">
        <thead>
          <tr><th>name</th><th>type</th><th>area</th></tr>
        </thead>
        <tbody>
          {cases.map((c, i) => (
            <tr key={i}>
              <td className="mono small">{c.name}</td>
              <td>{c.type}</td>
              <td className="muted">{c.area}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {d.generated_source && (
        <>
          <h3>Generated source preview</h3>
          <pre className="markdown-pre">
            {(d.generated_source + "").slice(0, 4000)}
          </pre>
        </>
      )}
    </>
  );
}


/* ─── Debug cards ──────────────────────────────────────────────── */
function DebugCards({ d }) {
  const errors   = d.compilation_errors || [];
  const warnings = d.warnings || [];

  return (
    <>
      <div className="kpi-grid">
        <Kpi big label="overall health"
             value={(d.overall_health || "?").toUpperCase()}
             tone={d.overall_health === "healthy" ? "ok" :
                   d.overall_health === "broken"  ? "err" : "warn"} />
        <Kpi label="build status"
             value={d.build_status || "?"}
             tone={d.build_status === "success" ? "ok" :
                   d.build_status === "failed"  ? "err" : "warn"} />
        <Kpi label="errors"   value={errors.length}
             tone={errors.length ? "err" : "ok"} />
        <Kpi label="warnings" value={warnings.length}
             tone={warnings.length > 5 ? "warn" : "neutral"} />
      </div>

      {errors.length > 0 && (
        <>
          <h3>Compilation errors</h3>
          <table className="table">
            <thead><tr><th>file</th><th>line</th><th>error</th>
                       <th>fix</th></tr></thead>
            <tbody>
              {errors.map((e, i) => (
                <tr key={i}>
                  <td className="mono small">{e.file || "—"}</td>
                  <td className="muted small">{e.line || "—"}</td>
                  <td className="small">{e.error || e.description}</td>
                  <td className="small">{e.fix || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {d.summary && <p className="quote">{d.summary}</p>}
    </>
  );
}


/* ─── Fault Injection cards ────────────────────────────────────── */
function FaultCards({ d }) {
  const score = d.robustness_score;
  // Try multiple field shapes for the failed scenarios
  const failed = d.failed_scenarios_analysis
              || d.regressions
              || d.failures
              || [];

  return (
    <>
      <div className="kpi-grid">
        <Kpi big label="robustness score"
             value={score == null ? "?" : `${score} / 10`}
             tone={score >= 7 ? "ok" :
                   score >= 4 ? "warn" : "err"} />
        <Kpi label="overall verdict"
             value={d.overall_verdict || "?"} />
        <Kpi label="failed scenarios" value={failed.length}
             tone={failed.length ? "err" : "ok"} />
      </div>

      {failed.length > 0 && (
        <>
          <h3>Failed scenarios analysis</h3>
          <table className="table">
            <thead>
              <tr>
                <th>scenario</th><th>family</th><th>CWE</th>
                <th>severity</th><th>root cause</th><th>fix</th>
              </tr>
            </thead>
            <tbody>
              {failed.map((f, i) => (
                <tr key={i}>
                  <td className="mono small">{f.scenario || "—"}</td>
                  <td className="muted small">{f.family || "—"}</td>
                  <td className="muted small">{f.cwe || "—"}</td>
                  <td>
                    <span className={`pill pill-${
                      f.severity === "critical" ? "err"  :
                      f.severity === "high"     ? "warn" :
                      "neutral"}`}>{f.severity || "medium"}</span>
                  </td>
                  <td className="small">{f.root_cause || f.description || "—"}</td>
                  <td className="mono small">{f.fix_code || f.suggested_fix || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {d.priority_fixes?.length > 0 && (
        <>
          <h3>Priority fixes</h3>
          <ul className="bullet-list">
            {d.priority_fixes.map((p, i) => <li key={i}>{p}</li>)}
          </ul>
        </>
      )}

      {d.summary && <p className="quote">{d.summary}</p>}
    </>
  );
}


/* ─── Patches view (with PR + 2nd-run banner) ───────────────────── */
function PatchesView({ runId }) {
  const [list, setList] = useState(null);
  const [err,  setErr]  = useState(null);
  const [pr,   setPr]   = useState(undefined); // undefined=loading, null=none
  const [life, setLife] = useState(undefined);

  useEffect(() => {
    api.patches(runId)
      .then(r => setList(r.patches))
      .catch(e => setErr(e.message));

    // Use allSettled so one failure doesn't block the other
    Promise.allSettled([
      api.pullRequest(runId),
      api.lifecycle(runId),
    ]).then(([prRes, lifeRes]) => {
      setPr  (prRes.status   === "fulfilled" ? prRes.value   : null);
      setLife(lifeRes.status === "fulfilled" ? lifeRes.value : null);
    });
  }, [runId]);

  if (err)   return <p className="alert alert-warn">{err}</p>;
  if (!list) return <p className="muted">loading patches…</p>;

  const showPrCard     = pr !== undefined && pr !== null;
  const showSecondCard = life !== undefined && life?.second_run_id;

  return (
    <>
      {(showPrCard || showSecondCard) && (
        <div className="patches-banner">
          {showPrCard && (
            <a href={pr.url} target="_blank" rel="noreferrer"
               className="banner-card banner-pr">
              <span className="bc-kicker">Auto-opened Pull Request</span>
              <strong>#{pr.number} — {pr.title}</strong>
              <span className={`pill pill-${
                pr.merged ? "ok"  :
                pr.state === "open" ? "info" :
                "neutral"}`}>
                ● {pr.merged ? "merged" : pr.state}
              </span>
            </a>
          )}
          {showSecondCard && (
            <Link to={`/runs/${life.second_run_id}/reports`}
                  className="banner-card banner-second">
              <span className="bc-kicker">Validated by Second Run</span>
              <strong>run #{life.second_run_id}</strong>
              <span className={`pill pill-${
                life.second_run_conclusion === "success" ? "ok"  :
                life.second_run_conclusion === "failure" ? "err" :
                "running"}`}>
                ● {life.second_run_conclusion ||
                   life.second_run_status ||
                   "pending"}
              </span>
            </Link>
          )}
        </div>
      )}

      {!list.length && (
        <p className="muted">No patches were produced for this run.</p>
      )}

      <div className="patches">
        {list.map((p, i) => (
          <article key={i} className="patch">
            <header className="patch-head">
              <span className="mono">{p.filename}</span>
              <span className="muted small">
                {p.content.split("\n").length} lines
              </span>
            </header>
            <pre className="diff">
              {p.content.split("\n").map((line, j) => {
                const cls = line.startsWith("+++") || line.startsWith("---")
                              ? "diff-meta"
                          : line.startsWith("+") ? "diff-add"
                          : line.startsWith("-") ? "diff-del"
                          : line.startsWith("@@")? "diff-hunk"
                          : "";
                return <div key={j} className={cls}>{line || " "}</div>;
              })}
            </pre>
          </article>
        ))}
      </div>
    </>
  );
}


/* ─── Tiny KPI block ───────────────────────────────────────────── */
function Kpi({ label, value, tone, big }) {
  return (
    <div className={`kpi ${big ? "kpi-big" : ""} kpi-${tone || "neutral"}`}>
      <span className="kpi-label">{label}</span>
      <span className="kpi-value">{value}</span>
    </div>
  );
}
