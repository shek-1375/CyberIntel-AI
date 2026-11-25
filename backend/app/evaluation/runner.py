"""Runs the evaluation and writes a report.

Three experiments:

1. evaluate_retrieval   every search mode on every answerable question -> Hit@1, Hit@4, MRR
2. chunk_size_experiment  re-chunk the documents at several sizes into TEMPORARY Qdrant
                          collections, run hybrid + rerank on each, then delete them.
                          The main `cyber_docs` collection is never touched.
3. evaluate_answers     call /ask's answer() on every question (including ones the documents
                        can't answer) and run the grounding checks. Uses Gemini, so it is optional.
"""
import json
import time
from datetime import datetime
from pathlib import Path

from app.config import BACKEND_DIR, CHUNK_OVERLAP, CHUNK_SIZE, COLLECTION, DOCUMENTS_DIR, TOP_K
from app.evaluation.metrics import first_relevant_rank, summarise
from app.retrieval import retriever

EVAL_SET = BACKEND_DIR / "eval" / "eval_set.json"
RESULTS_DIR = BACKEND_DIR / "eval" / "results"

# (name shown in the report, search mode, use reranker?, fusion weights)
# Day 3 round 2: after the first run showed keyword search hurting ordinary questions,
# we added weighted fusion, dense + rerank, and the "auto" router, and measure them all.
CONFIGS = [
    ("dense", "dense", False, None),
    ("keyword", "keyword", False, None),
    ("hybrid", "hybrid", False, None),
    ("hybrid + rerank", "hybrid", True, None),
    ("dense + rerank", "dense", True, None),
    ("weighted 2:1", "hybrid", False, {"dense": 2.0, "keyword": 1.0}),
    ("weighted 2:1 + rerank", "hybrid", True, {"dense": 2.0, "keyword": 1.0}),
    ("auto", "auto", False, None),
    ("auto + rerank", "auto", True, None),
]

# the configs compared in the chunk size experiment
CHUNK_CONFIGS = [c for c in CONFIGS if c[0] in ("dense", "hybrid + rerank", "auto", "auto + rerank")]


def load_questions() -> list[dict]:
    return json.loads(EVAL_SET.read_text(encoding="utf-8"))["questions"]


def answerable(questions: list[dict]) -> list[dict]:
    return [q for q in questions if q.get("answerable", True)]


# ------------------------------------------------------------------ 1. retrieval
def evaluate_retrieval(collection: str = COLLECTION, configs=CONFIGS, k: int = TOP_K) -> dict:
    questions = answerable(load_questions())
    per_config, per_question = {}, {q["id"]: {"question": q["question"], "type": q["type"]} for q in questions}

    for name, mode, use_rerank, weights in configs:
        ranks = []
        for q in questions:
            res = retriever.search(
                q["question"], top_k=k, mode=mode, use_rerank=use_rerank, collection=collection, weights=weights
            )
            rank = first_relevant_rank(res["results"], q["source"], q["evidence"])
            ranks.append(rank)
            per_question[q["id"]][name] = rank
        summary = summarise(ranks, k)
        # break the score down by question type (exact_id, paraphrase, detection...)
        by_type = {}
        for qtype in sorted({q["type"] for q in questions}):
            type_ranks = [r for q, r in zip(questions, ranks) if q["type"] == qtype]
            by_type[qtype] = summarise(type_ranks, k)
        per_config[name] = {**summary, "by_type": by_type}

    return {"k": k, "collection": collection, "configs": per_config, "per_question": per_question}


# ------------------------------------------------------------------ 2. chunk sizes
def chunk_size_experiment(sizes: list[int], overlap: int = CHUNK_OVERLAP) -> dict:
    from app.ingestion.chunker import chunk_documents
    from app.ingestion.loader import load_directory

    docs = load_directory(DOCUMENTS_DIR)
    results = {}
    for size in sizes:
        collection = f"{COLLECTION}_eval_{size}"
        chunks = chunk_documents(docs, chunk_size=size, chunk_overlap=min(overlap, size // 4))
        retriever.index_chunks(chunks, collection=collection)
        try:
            ev = evaluate_retrieval(collection, configs=CHUNK_CONFIGS)
            results[size] = {"chunks": len(chunks), **{name: {m: v for m, v in r.items() if m != "by_type"} for name, r in ev["configs"].items()}}
        finally:
            retriever.delete_collection(collection)  # clean up the temporary collection
    return results


# ------------------------------------------------------------------ 3. answers
def evaluate_answers(pause_seconds: float = 2.0) -> dict:
    from app.rag.chain import answer

    rows = []
    for q in load_questions():
        res = answer(q["question"])
        g = res.get("grounding", {})
        failed = res.get("answer_model") is None  # every Gemini model was busy
        if q.get("answerable", True):
            correct = (not failed) and g.get("grounded", False) and not g.get("refused", False)
        else:
            correct = (not failed) and g.get("refused", False) and not g.get("unsupported_cve_ids")
        rows.append({
            "id": q["id"], "type": q["type"], "answerable": q.get("answerable", True),
            "model": res.get("answer_model"), "correct": correct, "llm_failed": failed,
            "refused": g.get("refused"), "cited": g.get("cited_sources"),
            "unsupported_cve_ids": g.get("unsupported_cve_ids"), "answer": res["answer"][:300],
        })
        time.sleep(pause_seconds)  # be gentle with the free-tier rate limit

    scored = [r for r in rows if not r["llm_failed"]]
    def rate(items):
        return round(sum(r["correct"] for r in items) / len(items), 3) if items else None
    return {
        "answered": len(scored),
        "llm_failures": len(rows) - len(scored),
        "answerable_correct_rate": rate([r for r in scored if r["answerable"]]),
        "unanswerable_refusal_rate": rate([r for r in scored if not r["answerable"]]),
        "hallucinated_cve_answers": sum(1 for r in scored if r["unsupported_cve_ids"]),
        "rows": rows,
    }


# ------------------------------------------------------------------ report
def _fmt(v):
    return "—" if v is None else f"{v:.2f}" if isinstance(v, float) else str(v)


def write_report(retrieval: dict, chunk_sizes: dict | None = None, answers: dict | None = None) -> Path:
    k = retrieval["k"]
    lines = [
        "# CyberIntel AI — Evaluation report",
        "",
        f"Run: {datetime.now():%Y-%m-%d %H:%M}  ·  questions: {len(retrieval['per_question'])}  ·  "
        f"chunk size {CHUNK_SIZE}, overlap {CHUNK_OVERLAP}  ·  top-k = {k}",
        "",
        "## 1. Retrieval quality by search mode",
        "",
        f"| Mode | Hit@1 | Hit@{k} | MRR |",
        "|---|---|---|---|",
    ]
    for name, r in retrieval["configs"].items():
        lines.append(f"| {name} | {_fmt(r['hit@1'])} | {_fmt(r[f'hit@{k}'])} | {_fmt(r['mrr'])} |")

    lines += ["", "### MRR by question type", ""]
    names = list(retrieval["configs"])
    types = list(next(iter(retrieval["configs"].values()))["by_type"])
    lines += ["| Type | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for t in types:
        lines.append(f"| {t} | " + " | ".join(_fmt(retrieval["configs"][n]["by_type"][t]["mrr"]) for n in names) + " |")

    lines += ["", "### Rank of the first correct chunk, per question (— = not in top " + str(k) + ")", ""]
    lines += ["| ID | Type | Question | " + " | ".join(names) + " |", "|---|---|---|" + "---|" * len(names)]
    for qid, row in retrieval["per_question"].items():
        lines.append(f"| {qid} | {row['type']} | {row['question'][:60]} | " + " | ".join(_fmt(row.get(n)) for n in names) + " |")

    if chunk_sizes:
        cnames = [c[0] for c in CHUNK_CONFIGS]
        lines += ["", "## 2. Chunk size experiment (MRR, and Hit@1 in brackets)", "",
                  "| Chunk size | Chunks | " + " | ".join(cnames) + " |", "|---|---|" + "---|" * len(cnames)]
        for size, r in chunk_sizes.items():
            cells = [f"{_fmt(r[n]['mrr'])} ({_fmt(r[n]['hit@1'])})" for n in cnames]
            lines.append(f"| {size} | {r['chunks']} | " + " | ".join(cells) + " |")

    if answers:
        lines += [
            "", "## 3. Answer grounding", "",
            f"- Answers generated: {answers['answered']} (LLM failures: {answers['llm_failures']})",
            f"- Answerable questions answered with valid citations: {_fmt(answers['answerable_correct_rate'])}",
            f"- Unanswerable questions correctly refused: {_fmt(answers['unanswerable_refusal_rate'])}",
            f"- Answers containing a CVE ID not found in the sources: {answers['hallucinated_cve_answers']}",
            "", "| ID | Answerable | Correct | Refused | Cited | Model |", "|---|---|---|---|---|---|",
        ]
        for r in answers["rows"]:
            lines.append(f"| {r['id']} | {r['answerable']} | {'✅' if r['correct'] else '❌'} | {r['refused']} | {r['cited']} | {r['model']} |")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines) + "\n"
    path = RESULTS_DIR / f"eval-{datetime.now():%Y%m%d-%H%M}.md"
    path.write_text(text, encoding="utf-8")
    (RESULTS_DIR / "latest.md").write_text(text, encoding="utf-8")
    return path
