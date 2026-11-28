import { useState } from "react";
import { api } from "../api.js";
import { ErrorNotice, Loading, Markdown, PageHead } from "../components/Common.jsx";

const EXAMPLES = [
  "How do I detect Log4Shell exploitation?",
  "What is the CVSS score of CVE-2024-3400 and is it being exploited?",
  "How do ransomware operators stop victims from recovering backups?",
  "What web shell was dropped on MOVEit servers?",
];

// Turn citation markers like [2] into links "#src-2", which the Markdown renderer
// below swaps for buttons that jump to that source.
function linkCitations(text) {
  return (text || "").replace(/\[(\d+)\](?!\()/g, "[$1](#src-$1)");
}

function Grounding({ g }) {
  if (!g || Object.keys(g).length === 0) return null;
  const problems = [];
  if (g.invalid_citations?.length) problems.push(`cites sources that don't exist: ${g.invalid_citations.map((n) => `[${n}]`).join(" ")}`);
  if (g.unsupported_cve_ids?.length) problems.push(`mentions CVE IDs not found in any source: ${g.unsupported_cve_ids.join(", ")}`);
  return (
    <div className="grounding">
      {g.refused ? (
        <span><strong>Refused.</strong> The sources don't cover this question, so no answer was invented.</span>
      ) : g.grounded ? (
        <span><strong>Grounded.</strong> Every citation points to a real source: {g.cited_sources.map((n) => `[${n}]`).join(" ")}</span>
      ) : (
        <span className="warn"><strong>Check this answer.</strong> {problems.join("; ") || "it has no citations."}</span>
      )}
      {g.uncited_sentences > 0 && !g.refused && <span>{g.uncited_sentences} sentence(s) without a citation</span>}
    </div>
  );
}

export default function Ask() {
  const [question, setQuestion] = useState("");
  const [mode, setMode] = useState("auto");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [flash, setFlash] = useState(null);

  async function submit(q = question) {
    if (!q.trim()) return;
    setQuestion(q);
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.ask(q, mode));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  function showSource(n) {
    const el = document.getElementById(`src-${n}`);
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    setFlash(n);
    setTimeout(() => setFlash(null), 1600);
  }

  const citationLink = ({ href, children }) =>
    href?.startsWith("#src-") ? (
      <button type="button" className="cite" onClick={() => showSource(href.slice(5))} aria-label={`Show source ${children}`}>
        {children}
      </button>
    ) : (
      <a href={href} target="_blank" rel="noreferrer">{children}</a>
    );

  return (
    <>
      <PageHead title="Ask">
        Answers come only from indexed advisories and live NVD, CISA KEV and EPSS data. Each claim cites its source, and
        questions the sources can't answer are refused.
      </PageHead>

      <form className="query" onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <textarea
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="e.g. Which Log4j versions fix CVE-2021-44228?"
          aria-label="Your question"
        />
        <div className="query-row">
          <button className="btn" disabled={busy}>{busy ? "Answering…" : "Ask"}</button>
          <label className="inline">
            Search
            <select value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="auto">auto (best in evaluation)</option>
              <option value="dense">meaning only</option>
              <option value="keyword">keywords only</option>
              <option value="hybrid">meaning + keywords</option>
            </select>
          </label>
        </div>
        <div className="examples">
          Try:
          {EXAMPLES.map((ex) => (
            <button type="button" key={ex} onClick={() => submit(ex)}>{ex}</button>
          ))}
        </div>
      </form>

      {busy && <Loading>Searching sources and writing a cited answer…</Loading>}
      <ErrorNotice error={error} />

      {result && (
        <>
          <section className="sheet" aria-label="Answer">
            <Markdown className="answer" components={{ a: citationLink }}>{linkCitations(result.answer)}</Markdown>
            <Grounding g={result.grounding} />
            <p className="muted" style={{ marginTop: "0.5rem" }}>
              Answered by {result.answer_model || "no model (all were busy)"}. Search mode: {result.search_mode}.
            </p>
          </section>

          {result.sources?.length > 0 && (
            <>
              <h2 className="section-title">Sources</h2>
              <ol className="sources">
                {result.sources.map((s) => (
                  <li key={s.id} id={`src-${s.id}`} className={String(flash) === String(s.id) ? "flash" : ""}>
                    <span className="n">[{s.id}]</span>
                    <div>
                      <div className="src">{s.source}{s.page ? `, page ${s.page}` : ""}</div>
                      <div className="snippet">{s.snippet}</div>
                      <div className="scores">
                        {[
                          s.dense_score != null && `meaning match ${s.dense_score}`,
                          s.bm25_score != null && `keyword match ${s.bm25_score}`,
                          s.rerank_score != null && `rerank ${s.rerank_score}`,
                        ].filter(Boolean).join(", ")}
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            </>
          )}
        </>
      )}
    </>
  );
}
