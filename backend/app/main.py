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
from app.retrieval import retriever

app = FastAPI(title="CyberIntel AI", version="0.2.1 (Day 2: hybrid search + reranking)")

Mode = Literal["dense", "keyword", "hybrid"]


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
    """Retrieval only (no answer). Choose mode: dense, keyword or hybrid, and rerank on/off."""
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
    return {
        "question": q.question,
        "dense": dense,
        "keyword": keyword,
        "hybrid": hybrid,
        "hybrid + rerank": reranked,
        "rerank_worked": reranked_res["reranked"],
        "rerank_model": reranked_res["rerank_model"],
    }


@app.post("/ask")
def ask(q: Question):
    return answer(q.question, mode=q.mode, use_rerank=q.rerank)
