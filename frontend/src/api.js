// All calls go to "/api/...", which Vite forwards to the FastAPI backend (see vite.config.js).
const BASE = "/api";

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(BASE + path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
  } catch {
    throw new Error("Can't reach the API. Start the backend with: uvicorn app.main:app --reload");
  }
  const text = await res.text();
  let data = text;
  try {
    data = JSON.parse(text);
  } catch {
    /* plain text response (reports, evaluation) */
  }
  if (!res.ok) {
    const detail = data && data.detail;
    const message = typeof detail === "string" ? detail : Array.isArray(detail) ? detail.map((d) => d.msg).join("; ") : text;
    throw new Error(`${res.status}: ${message || res.statusText}`);
  }
  return data;
}

export const api = {
  health: () => request("/health"),
  ask: (question, mode) => request("/ask", { method: "POST", body: JSON.stringify({ question, mode }) }),
  cve: (id) => request(`/intel/cve/${encodeURIComponent(id.trim().toUpperCase())}`),
  kev: (search, limit = 50) => request(`/intel/kev?search=${encodeURIComponent(search)}&limit=${limit}`),
  investigate: (query) => request("/investigate", { method: "POST", body: JSON.stringify({ query }) }),
  investigations: () => request("/investigations"),
  investigation: (id) => request(`/investigations/${id}`),
  deleteInvestigation: (id) => request(`/investigations/${id}`, { method: "DELETE" }),
  questions: () => request("/questions"),
  evaluation: () => request("/evaluation/latest"),
};

export function downloadText(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}

export const CVE_PATTERN = /^CVE-\d{4}-\d{4,7}$/i;
