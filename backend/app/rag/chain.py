"""Step 5 of RAG: retrieve evidence, then ask Gemini to answer ONLY from it.

The numbered passages let the model cite [1], [2]... and let the analyst
check every claim. If the evidence doesn't cover the question, the model
must say so instead of guessing.

Day 3: every answer is checked by grounding.py (plain code, no AI) for invalid
citations and CVE IDs that don't appear in the sources.

Day 4: if the question names a CVE, live facts from NVD, CISA KEV and EPSS are
added as an extra numbered passage, so Gemini can cite the real CVSS score and
exploitation status, even for CVEs that aren't in our documents.
"""
import logging

from app.config import LIVE_INTEL, RERANK, SEARCH_MODE, TOP_K
from app.llm import call_llm
from app.rag.grounding import CVE_RE, check_grounding
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

log = logging.getLogger(__name__)
MAX_LIVE_CVES = 3


def live_intel_passages(question: str) -> list[dict]:
    """One extra evidence passage per CVE named in the question (live NVD + KEV + EPSS)."""
    from app.intel.service import card_as_text, cve_intel

    passages = []
    for cve_id in list(dict.fromkeys(c.upper() for c in CVE_RE.findall(question)))[:MAX_LIVE_CVES]:
        try:
            card = cve_intel(cve_id, include_attack=False)
            if card.get("nvd") or card.get("kev"):
                passages.append({"source": f"live intel: NVD + CISA KEV + EPSS ({cve_id})", "text": card_as_text(card)})
        except Exception as e:  # live intel is a bonus; never let it break the answer
            log.warning("Live intel for %s failed: %s", cve_id, e)
    return passages


def answer(question: str, mode: str = SEARCH_MODE, use_rerank: bool = RERANK, live_intel: bool = LIVE_INTEL) -> dict:
    retrieval = search(question, top_k=TOP_K, mode=mode, use_rerank=use_rerank)
    passages = retrieval["results"] + (live_intel_passages(question) if live_intel else [])
    if not passages:
        return {"answer": "No documents indexed yet. Call POST /ingest first.", "answer_model": None, "sources": [], "grounding": {}}

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
        "grounding": check_grounding(reply, [p["text"] for p in passages]) if model_used else {},
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
