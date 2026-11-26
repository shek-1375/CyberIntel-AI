"""CyberIntel AI - API.

Run from backend/:  uvicorn app.main:app --reload
Try it at:          http://localhost:8000/docs
"""
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.config import DOCUMENTS_DIR, GOOGLE_API_KEY, RERANK, SEARCH_MODE, TOP_K
from app.ingestion.chunker import chunk_documents
from app.ingestion.loader import load_directory
from app.rag.chain import answer
from app.intel.routes import router as intel_router
from app.retrieval import retriever

app = FastAPI(title="CyberIntel AI", version="0.4.0 (Day 4: live threat intelligence)")

app.include_router(intel_router)

Mode = Literal["dense", "keyword", "hybrid", "auto"]


class Question(BaseModel):
    question: str
    mode: Mode = SEARCH_MODE
    rerank: bool = RERANK


class CompareRequest(BaseModel):
    question: str


@app.get("/health")
def health():
    try:
        chunks = retriever.count()
        qdrant = "ok"
    except Exception as e:
        chunks, qdrant = 0, f"error: {e}"
    return {"api": "ok", "qdrant": qdrant, "indexed_chunks": chunks, "gemini_key_set": bool(GOOGLE_API_KEY)}


@app.post("/ingest")
def ingest():
    """Load every file in data/documents, chunk, embed and store in Qdrant."""
    docs = load_directory(DOCUMENTS_DIR)
    if not docs:
        raise HTTPException(400, f"No .md/.txt/.pdf files in {DOCUMENTS_DIR}")
    chunks = chunk_documents(docs)
    stored = retriever.index_chunks(chunks)
    return {"files": sorted({d.metadata["source"] for d in docs}), "chunks_stored": stored}


@app.post("/search")
def search(q: Question):
    """Retrieval only (no answer). Choose mode: dense, keyword, hybrid or auto, and rerank on/off."""
    res = retriever.search(q.question, top_k=TOP_K, mode=q.mode, use_rerank=q.rerank)
    for r in res["results"]:
        r["text"] = r["text"][:300]
    return res


@app.post("/compare")
def compare(q: CompareRequest):
    """Run the same question through every search mode side by side.

    Shows which source file and chunk each mode puts at the top. Great for
    seeing (and explaining in interviews) why hybrid + rerank is better.
    """
    def top(mode, use_rerank=False):
        res = retriever.search(q.question, top_k=TOP_K, mode=mode, use_rerank=use_rerank)
        return res, [f"{r['chunk_id']}  |  {r['text'][:80]!r}" for r in res["results"]]

    _, dense = top("dense")
    _, keyword = top("keyword")
    _, hybrid = top("hybrid")
    reranked_res, reranked = top("hybrid", use_rerank=True)
    _, auto = top("auto")
    return {
        "question": q.question,
        "dense": dense,
        "keyword": keyword,
        "hybrid": hybrid,
        "hybrid + rerank": reranked,
        "auto (hybrid if the question has a CVE/ATT&CK ID, else dense)": auto,
        "rerank_worked": reranked_res["reranked"],
        "rerank_model": reranked_res["rerank_model"],
    }


@app.post("/ask")
def ask(q: Question):
    return answer(q.question, mode=q.mode, use_rerank=q.rerank)


class EvaluateRequest(BaseModel):
    include_answers: bool = False


@app.post("/evaluate")
def evaluate(req: EvaluateRequest):
    """Score every search mode on the evaluation set (eval/eval_set.json).

    Returns Hit@1, Hit@4 and MRR per mode and writes eval/results/latest.md.
    include_answers=true also generates answers with Gemini and checks grounding
    (slower: about a minute). For the chunk size experiment use the script:
    python -m scripts.evaluate --chunk-sizes 400,800,1200
    """
    from app.evaluation.runner import evaluate_answers, evaluate_retrieval, write_report

    retrieval = evaluate_retrieval()
    answers = evaluate_answers() if req.include_answers else None
    report = write_report(retrieval, None, answers)
    summary = {name: {m: v for m, v in r.items() if m != "by_type"} for name, r in retrieval["configs"].items()}
    out = {"retrieval": summary, "report_file": str(report)}
    if answers:
        out["answers"] = {k: v for k, v in answers.items() if k != "rows"}
    return out
