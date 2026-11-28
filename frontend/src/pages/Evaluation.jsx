import { useEffect, useState } from "react";
import { api } from "../api.js";
import { ErrorNotice, Loading, Markdown, PageHead } from "../components/Common.jsx";

export default function Evaluation() {
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => { api.evaluation().then(setReport).catch(setError); }, []);

  return (
    <>
      <PageHead title="Evaluation">
        How well search finds the right evidence, measured on 18 labelled questions (Hit@1, Hit@4 and MRR). Run
        python -m scripts.evaluate in the backend to refresh it.
      </PageHead>
      <ErrorNotice error={error} />
      {!report && !error && <Loading>Loading the latest evaluation…</Loading>}
      {report && (
        <section className="sheet">
          <Markdown className="report">{report}</Markdown>
        </section>
      )}
    </>
  );
}
