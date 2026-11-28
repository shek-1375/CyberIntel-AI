import { useEffect, useState } from "react";
import { api } from "../api.js";
import { go } from "../router.js";
import { ErrorNotice, Loading, PageHead, PriorityStamp, formatDate } from "../components/Common.jsx";
import { ReportView } from "./Investigate.jsx";

function SavedInvestigation({ id }) {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setResult(null);
    setError(null);
    api.investigation(id).then(setResult).catch(setError);
  }, [id]);

  async function remove() {
    if (!window.confirm(`Delete investigation ${id}? This can't be undone.`)) return;
    try {
      await api.deleteInvestigation(id);
      go("history");
    } catch (e) {
      setError(e);
    }
  }

  return (
    <>
      <p style={{ marginBottom: "1rem" }}><a href="#/history">Back to history</a></p>
      <ErrorNotice error={error} />
      {!result && !error && <Loading>Loading investigation {id}…</Loading>}
      {result && (
        <>
          <PageHead title={result.query}>Investigated {formatDate(result.created_at)}</PageHead>
          <ReportView result={result} onDelete={remove} />
        </>
      )}
    </>
  );
}

function Investigations() {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => { api.investigations().then(setRows).catch(setError); }, []);

  if (error) return <ErrorNotice error={error} />;
  if (!rows) return <Loading>Loading saved investigations…</Loading>;
  if (rows.length === 0) {
    return <p className="empty">No investigations yet. <a href="#/investigate">Run your first investigation</a>.</p>;
  }
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Priority</th><th>Investigation</th><th>CVEs</th><th>When</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td><PriorityStamp level={r.risk_level} small /></td>
              <td><button className="link" onClick={() => go("history", String(r.id))}>{r.query}</button></td>
              <td>{r.cve_ids.join(", ") || "none"}</td>
              <td>{formatDate(r.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Questions() {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => { api.questions().then(setRows).catch(setError); }, []);

  if (error) return <ErrorNotice error={error} />;
  if (!rows) return <Loading>Loading questions…</Loading>;
  if (rows.length === 0) return <p className="empty">No questions yet. <a href="#/ask">Ask one</a>.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Question</th><th>Result</th><th>Model</th><th>When</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>{r.question}</td>
              <td>{r.refused ? "Refused (not in sources)" : r.grounded ? "Grounded" : <span className="known">Check answer</span>}</td>
              <td>{r.answer_model || "none"}</td>
              <td>{formatDate(r.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function History({ param }) {
  const [tab, setTab] = useState("investigations");
  if (param) return <SavedInvestigation id={param} />;

  return (
    <>
      <PageHead title="History">Every investigation and question is saved in the PostgreSQL database.</PageHead>
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "investigations"} onClick={() => setTab("investigations")}>Investigations</button>
        <button role="tab" aria-selected={tab === "questions"} onClick={() => setTab("questions")}>Questions</button>
      </div>
      {tab === "investigations" ? <Investigations /> : <Questions />}
    </>
  );
}
