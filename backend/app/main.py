"""CyberIntel AI - prototype API.

Run from backend/:  uvicorn app.main:app --reload
Try it at:          http://localhost:8000/docs
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.config import DOCUMENTS_DIR, GOOGLE_API_KEY
from app.ingestion.chunker import chunk_documents
from app.ingestion.loader import load_directory
from app.rag.chain import answer
from app.retrieval import retriever

app = FastAPI(title="CyberIntel AI (prototype)")


class Question(BaseModel):
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
    """Retrieval only (no LLM) - useful to see what evidence the model will get."""
    return retriever.search(q.question)


@app.post("/ask")
def ask(q: Question):
    return answer(q.question)
