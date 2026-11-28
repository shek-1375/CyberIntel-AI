import { useEffect, useState } from "react";
import { api, CVE_PATTERN } from "../api.js";
import { go } from "../router.js";
import { ErrorNotice, Loading, PageHead, PriorityStamp, levelClass, percent } from "../components/Common.jsx";

const EXAMPLES = ["CVE-2023-34362", "CVE-2024-3400", "CVE-2021-44228"];

function Facts({ card }) {
  const cvss = card.nvd?.cvss;
  const kev = card.kev;
  const epss = card.epss;
  return (
    <div className="facts">
      <div className={`fact ${levelClass(cvss?.severity)}`}>
        <h3>Severity (CVSS {cvss?.version || ""})</h3>
        <div className="big" style={{ "--c": cvss ? undefined : "var(--ink-soft)" }}>
          {cvss?.score ?? "—"} <span style={{ fontSize: "var(--t-md)", fontWeight: 600 }}>{cvss?.severity || "not scored"}</span>
        </div>
        <div className="sub mono">{cvss?.vector || "No CVSS vector published"}</div>
      </div>
      <div className={`fact ${kev ? "critical" : ""}`}>
        <h3>Exploited in the wild (CISA KEV)</h3>
        <div className="big">{kev ? "Yes" : "Not listed"}</div>
        <div className="sub">
          {kev
            ? `Added ${kev.date_added}. Ransomware use: ${kev.ransomware_use}. Federal deadline ${kev.due_date}.`
            : "CISA has not confirmed exploitation."}
        </div>
      </div>
      <div className={`fact ${epss?.probability >= 0.5 ? "high" : ""}`}>
        <h3>Chance of exploitation in 30 days (EPSS)</h3>
        <div className="big">{percent(epss?.probability)}</div>
        <div className="sub">{epss ? `Higher than ${percent(epss.percentile, 1)} of all CVEs` : "No EPSS score"}</div>
      </div>
    </div>
  );
}

function Techniques({ list }) {
  if (!list?.length) return <p className="muted">No ATT&CK techniques suggested.</p>;
  return (
    <div className="techniques">
      {list.map((t) => (
        <article className="technique" key={t.technique_id}>
          <header>
            <a className="tid" href={t.url} target="_blank" rel="noreferrer">{t.technique_id}</a>
            <h3>{t.name}</h3>
            <span className="muted">{t.tactics.join(", ")}</span>
            <span className={`basis ${t.basis}`} title={t.basis === "rule" ? "Suggested by a rule" : "Suggested by keyword match, so check it"}>
              {t.basis === "rule" ? "rule" : "keyword match"}
            </span>
          </header>
          <p className="muted" style={{ marginTop: "0.35rem" }}>Why: {t.reason}</p>
          {t.mitigations?.length > 0 && (
            <ul>
              {t.mitigations.map((m) => (
                <li key={m.mitigation_id}>
                  <strong>{m.mitigation_id} {m.name}</strong>
                  {m.how ? `: ${m.how}` : ""}
                </li>
              ))}
            </ul>
          )}
        </article>
      ))}
    </div>
  );
}

export default function CveLookup({ param }) {
  const [input, setInput] = useState(param || "");
  const [card, setCard] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!param) return;
    setInput(param);
    if (!CVE_PATTERN.test(param)) {
      setError(new Error("Use the format CVE-YYYY-NNNN, for example CVE-2021-44228."));
      return;
    }
    let cancelled = false;
    setBusy(true);
    setError(null);
    setCard(null);
    api.cve(param)
      .then((c) => !cancelled && setCard(c))
      .catch((e) => !cancelled && setError(e))
      .finally(() => !cancelled && setBusy(false));
    return () => { cancelled = true; };
  }, [param]);

  const lookUp = (id) => go("cve", id.trim().toUpperCase());

  return (
    <>
      <PageHead title="CVE lookup">
        Live facts from NVD, CISA KEV and FIRST EPSS, a patch priority worked out by fixed rules, and the MITRE ATT&CK
        techniques the vulnerability enables.
      </PageHead>

      <form className="query" onSubmit={(e) => { e.preventDefault(); if (input.trim()) lookUp(input); }}>
        <div className="query-row">
          <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="CVE-2023-34362" aria-label="CVE ID" />
          <button className="btn" disabled={busy}>{busy ? "Looking up…" : "Look up"}</button>
        </div>
        <div className="examples">
          Try:
          {EXAMPLES.map((ex) => <button type="button" key={ex} onClick={() => lookUp(ex)}>{ex}</button>)}
        </div>
      </form>

      {busy && <Loading>Fetching NVD, CISA KEV and EPSS. The first lookup also downloads MITRE ATT&CK, which can take a minute.</Loading>}
      <ErrorNotice error={error} />

      {card && (
        <article aria-label={card.cve_id}>
          <div className="cve-head">
            <div>
              <div className="cve-id">{card.cve_id}</div>
              <ul className="reasons">
                {card.priority.reasons.map((r) => <li key={r}>{r}</li>)}
              </ul>
            </div>
            <PriorityStamp level={card.priority.level} />
          </div>

          <Facts card={card} />

          <section className="sheet">
            <h2>What it is</h2>
            <p style={{ marginTop: "0.5rem", maxWidth: "75ch" }}>{card.nvd?.description || "NVD has no description for this CVE."}</p>
            {card.nvd?.cwes?.length > 0 && <p className="muted" style={{ marginTop: "0.5rem" }}>Weakness: {card.nvd.cwes.join(", ")}</p>}
            {card.kev && (
              <p style={{ marginTop: "0.75rem" }}><strong>CISA required action:</strong> {card.kev.required_action}</p>
            )}
            {card.nvd?.nvd_url && (
              <p style={{ marginTop: "0.75rem" }}>
                <a href={card.nvd.nvd_url} target="_blank" rel="noreferrer">Open in NVD</a>
              </p>
            )}
          </section>

          <h2 className="section-title">MITRE ATT&CK techniques</h2>
          <Techniques list={card.attack} />

          <p style={{ marginTop: "1.5rem" }}>
            <button className="btn quiet" onClick={() => go("investigate", `Investigate ${card.cve_id} and recommend detections and mitigations`)}>
              Investigate {card.cve_id}
            </button>
          </p>

          {card.errors?.length > 0 && (
            <div className="notice info" style={{ marginTop: "1rem" }}>
              {card.errors.map((e) => <p key={e}>{e}</p>)}
            </div>
          )}
        </article>
      )}

      {!card && !busy && !error && <p className="empty">Enter a CVE ID to see its live intelligence card.</p>}
    </>
  );
}
