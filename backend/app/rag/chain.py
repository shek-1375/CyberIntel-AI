"""Step 5 of RAG: retrieve evidence, then ask Gemini to answer ONLY from it.

The numbered passages let the model cite [1], [2]... and let the analyst
check every claim. If the evidence doesn't cover the question, the model
must say so instead of guessing.
"""
from app.config import RERANK, SEARCH_MODE, TOP_K
from app.llm import call_llm
from app.retrieval.retriever import search

PROMPT = """You are CyberIntel AI, an assistant for security analysts.
Answer the question using ONLY the numbered evidence below.
- Cite every fact with the passage number, like [1] or [2].
- Never invent CVE IDs, versions, scores or indicators.
- If the evidence doesn't contain the answer, say "The indexed sources don't cover this."

Evidence:
{context}

Question: {question}
Answer:"""


def answer(question: str, mode: str = SEARCH_MODE, use_rerank: bool = RERANK) -> dict:
    retrieval = search(question, top_k=TOP_K, mode=mode, use_rerank=use_rerank)
    passages = retrieval["results"]
    if not passages:
        return {"answer": "No documents indexed yet. Call POST /ingest first.", "sources": []}

    context = "\n\n".join(f"[{i}] ({p['source']})\n{p['text']}" for i, p in enumerate(passages, 1))
    model_used = None
    try:
        message, model_used = call_llm(PROMPT.format(context=context, question=question))
        reply = message.content
        if isinstance(reply, list):  # some Gemini versions return a list of content parts
            reply = "".join(part.get("text", "") if isinstance(part, dict) else str(part) for part in reply)
    except Exception as e:
        # every model failed (e.g. all busy): tell the user instead of crashing with a 500
        reply = f"Gemini could not answer right now ({type(e).__name__}). Please try again in a minute."

    return {
        "answer": reply,
        "answer_model": model_used,
        "search_mode": retrieval["mode"],
        "reranked": retrieval["reranked"],
        "rerank_model": retrieval["rerank_model"],
        "sources": [
            {
                "id": i,
                "source": p["source"],
                "page": p.get("page"),
                "dense_score": p.get("dense_score"),
                "bm25_score": p.get("bm25_score"),
                "rrf_score": p.get("rrf_score"),
                "rerank_score": p.get("rerank_score"),
                "snippet": p["text"][:200],
            }
            for i, p in enumerate(passages, 1)
        ],
    }
