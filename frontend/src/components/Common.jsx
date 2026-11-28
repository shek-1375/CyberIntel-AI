import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const LEVELS = ["critical", "high", "medium", "low", "unknown"];

export function levelClass(level) {
  const l = String(level || "unknown").toLowerCase();
  return LEVELS.includes(l) ? l : "unknown";
}

/** The priority stamp: the one bold element of the design. */
export function PriorityStamp({ level, small = false }) {
  const l = levelClass(level);
  return (
    <span className={`stamp ${l}${small ? " small" : ""}`} title={`Patch priority: ${l}`}>
      {l}
    </span>
  );
}

export function Loading({ children }) {
  return (
    <p className="loading" role="status">
      {children}
    </p>
  );
}

export function ErrorNotice({ error }) {
  if (!error) return null;
  return (
    <p className="notice" role="alert">
      {error.message || String(error)}
    </p>
  );
}

export function PageHead({ title, children }) {
  return (
    <header className="page-head">
      <h1>{title}</h1>
      {children && <p>{children}</p>}
    </header>
  );
}

/** Renders Markdown, including tables (GitHub-flavoured Markdown). */
export function Markdown({ children, className, components }) {
  return (
    <div className={className}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {children || ""}
      </ReactMarkdown>
    </div>
  );
}

export function formatDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function percent(x, digits = 1) {
  return x == null ? "—" : `${(x * 100).toFixed(digits)}%`;
}
