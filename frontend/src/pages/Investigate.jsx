import { useEffect, useRef, useState } from "react";
import { api, downloadText } from "../api.js";
import { go } from "../router.js";
import { ErrorNotice, Markdown, PageHead, PriorityStamp } from "../components/Common.jsx";

const EXAMPLES = [
  "Investigate CVE-2023-34362 and recommend detections and mitigations",
  "Investigate CVE-2021-44228 exploitation on our Java web servers",
  "We found a new .aspx file in our file transfer server's web folder. What should we check?",
];

// The agent's six steps, shown while it runs (the request returns only when all are done).
const STEPS = [
  "Find CVE and ATT&CK IDs in the question",
  "Fetch live intel: NVD, CISA KEV, EPSS",
  "Search our documents for evidence",
  "Map to MITRE ATT&CK",
  "Write recommendations",
  "Write the report",
];

function useSeconds(running) {
  const [seconds, setSeconds] = useState(0);
  const timer = useRef(null);
  useEffect(() => {
    if (!running) return;
    setSeconds(0);
    timer.current = setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => clearInterval(timer.current);
  }, [running]);
  return seconds;
}

export function ReportView({ result, onDelete }) {
  const filename = `cyberintel-investigation-${result.id ?? "unsaved"}.md`;
  return (
    <>
      <div className="report-bar">
        <div>
          <PriorityStamp level={result.risk?.level} />
          <p className="muted" style={{ marginTop: "0.75rem" }}>
            {result.id ? `Saved to history as investigation ${result.id}.` : "Not saved: the history database is unavailable."}
          </p>
        </div>
        <div className="actions">
          <button className="btn quiet" onClick={() => downloadText(filename, result.report_markdown)}>Download report</button>
          {onDelete && <button className="btn danger" onClick={onDelete}>Delete</button>}
        </div>
      </div>
      <section className="sheet">
        <Markdown className="report">{result.report_markdown}</Markdown>
      </section>
    </>
  );
}

export default function Investigate({ param }) {
  const [query, setQuery] = useState(param || "");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const seconds = useSeconds(busy);

  useEffect(() => { if (param) setQuery(param); }, [param]);

  async function run(q = query) {
    if (q.trim().length < 5) return;
    setQuery(q);
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.investigate(q));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  // a rough guide to which step is running, based on typical timings
  const activeStep = Math.min(STEPS.length - 1, Math.floor(seconds / 4));

  return (
    <>
      <PageHead title="Investigate">
        The agent works through an investigation the way an analyst would, then writes a report. Facts come from live
        sources and your documents; the language model only chooses among checked options and writes the summary.
      </PageHead>

      <form className="query" onSubmit={(e) => { e.preventDefault(); run(); }}>
        <textarea value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Describe the vulnerability or incident" aria-label="What to investigate" />
        <div className="query-row">
          <button className="btn" disabled={busy}>{busy ? "Investigating…" : "Run investigation"}</button>
          {result?.id && <button type="button" className="btn quiet" onClick={() => go("history", String(result.id))}>Open in history</button>}
        </div>
        <div className="examples">
          Try:
          {EXAMPLES.map((ex) => <button type="button" key={ex} onClick={() => run(ex)}>{ex}</button>)}
        </div>
      </form>

      {busy && (
        <section className="sheet" aria-live="polite">
          <p><strong>Investigating</strong> ({seconds} s). This usually takes 15 to 60 seconds.</p>
          <ol className="steps">
            {STEPS.map((s, i) => <li key={s} className={i === activeStep ? "active" : ""}>{s}</li>)}
          </ol>
        </section>
      )}
      <ErrorNotice error={error} />
      {result && <ReportView result={result} />}
      {!result && !busy && !error && <p className="empty">Describe a vulnerability or an incident to start an investigation.</p>}
    </>
  );
}
