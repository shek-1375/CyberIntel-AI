import { useEffect, useState } from "react";
import { api } from "./api.js";
import { useRoute } from "./router.js";
import Ask from "./pages/Ask.jsx";
import CveLookup from "./pages/CveLookup.jsx";
import Investigate from "./pages/Investigate.jsx";
import ExploitedNow from "./pages/ExploitedNow.jsx";
import History from "./pages/History.jsx";
import Evaluation from "./pages/Evaluation.jsx";

const PAGES = [
  { id: "ask", label: "Ask", Component: Ask },
  { id: "cve", label: "CVE lookup", Component: CveLookup },
  { id: "investigate", label: "Investigate", Component: Investigate },
  { id: "exploited", label: "Exploited now", Component: ExploitedNow },
  { id: "history", label: "History", Component: History },
  { id: "evaluation", label: "Evaluation", Component: Evaluation },
];

function Status() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(false);

  const check = () => {
    setError(false);
    api.health().then(setHealth).catch(() => {
      setHealth(null);
      setError(true);
    });
  };
  useEffect(check, []);

  if (error) {
    return (
      <div className="status">
        <div className="bad">API not reachable</div>
        <button onClick={check}>Check again</button>
      </div>
    );
  }
  if (!health) return <div className="status">Checking services…</div>;
  const ok = (v) => (v === "ok" ? "ok" : "down");
  return (
    <div className="status" aria-label="Service status">
      <div><span>API</span><span>ok</span></div>
      <div className={health.qdrant === "ok" ? "" : "bad"}><span>Search index</span><span>{health.qdrant === "ok" ? `${health.indexed_chunks} chunks` : "down"}</span></div>
      <div className={health.gemini_key_set ? "" : "bad"}><span>Gemini key</span><span>{health.gemini_key_set ? "set" : "missing"}</span></div>
      <div className={health.database === "ok" ? "" : "bad"}><span>History database</span><span>{ok(health.database)}</span></div>
      <button onClick={check}>Check again</button>
    </div>
  );
}

export default function App() {
  const { page, param } = useRoute();
  const current = PAGES.find((p) => p.id === page) || PAGES[0];
  const { Component } = current;

  return (
    <div className="app">
      <aside className="rail">
        <div className="wordmark">
          CyberIntel <span>AI</span>
        </div>
        <nav aria-label="Main">
          {PAGES.map((p) => (
            <a key={p.id} href={`#/${p.id}`} aria-current={p.id === current.id ? "page" : undefined}>
              {p.label}
            </a>
          ))}
        </nav>
        <Status />
      </aside>
      <main>
        <Component param={param} />
      </main>
    </div>
  );
}
