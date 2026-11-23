"""Step 5 of RAG: retrieve evidence, then ask Gemini to answer ONLY from it.

The numbered passages let the model cite [1], [2]... and let the analyst
check every claim. If the evidence doesn't cover the question, the model
must say so instead of guessing.
"""
from functools import lru_cache

from langchain_google_genai import ChatGoogleGenerativeAI

from app.config import CHAT_MODEL, GOOGLE_API_KEY
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


@lru_cache
def get_llm() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(model=CHAT_MODEL, google_api_key=GOOGLE_API_KEY, temperature=0.1)


def answer(question: str) -> dict:
    passages = search(question)
    if not passages:
        return {"answer": "No documents indexed yet. Call POST /ingest first.", "sources": []}

    context = "\n\n".join(f"[{i}] ({p['source']})\n{p['text']}" for i, p in enumerate(passages, 1))
    reply = get_llm().invoke(PROMPT.format(context=context, question=question)).content
    if isinstance(reply, list):  # some Gemini versions return a list of content parts
        reply = "".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in reply)

    return {
        "answer": reply,
        "sources": [
            {"id": i, "source": p["source"], "page": p.get("page"), "score": p["score"], "snippet": p["text"][:200]}
            for i, p in enumerate(passages, 1)
        ],
    }
