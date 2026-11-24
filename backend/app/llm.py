"""Gemini chat models with automatic fallback.

Problem we hit: "503 UNAVAILABLE - This model is currently experiencing high
demand". When the main model is busy, we try the next model in the list
instead of failing. The response tells you which model actually answered.

Answers:   CHAT_MODEL  -> FALLBACK_MODELS ...
Reranking: RERANK_MODEL -> FALLBACK_MODELS ...  (a "lite" model is enough for scoring)
"""
import logging
from functools import lru_cache

from langchain_google_genai import ChatGoogleGenerativeAI

from app.config import CHAT_MODEL, FALLBACK_MODELS, GOOGLE_API_KEY, RERANK_MODEL

log = logging.getLogger(__name__)


@lru_cache
def get_llm(model: str = CHAT_MODEL) -> ChatGoogleGenerativeAI:
    if not GOOGLE_API_KEY:
        raise RuntimeError("GOOGLE_API_KEY missing - add it to backend/.env")
    # max_retries=1: if a model is busy, move on to the next one quickly
    return ChatGoogleGenerativeAI(model=model, google_api_key=GOOGLE_API_KEY, temperature=0.1, max_retries=1)


def _model_chain(first: str) -> list[str]:
    chain = [first] + [m for m in FALLBACK_MODELS if m != first]
    return list(dict.fromkeys(chain))  # remove duplicates, keep order


def call_llm(prompt: str, schema=None, purpose: str = "answer"):
    """Call Gemini, trying each model in turn. Returns (result, model_used).

    schema: an optional Pydantic class; if given, Gemini must reply in that exact structure.
    """
    first = RERANK_MODEL if purpose == "rerank" else CHAT_MODEL
    last_error = None
    for model in _model_chain(first):
        try:
            llm = get_llm(model)
            runnable = llm.with_structured_output(schema) if schema else llm
            return runnable.invoke(prompt), model
        except Exception as e:
            log.warning("Model %s failed (%s), trying next model", model, str(e)[:120])
            last_error = e
    raise last_error
