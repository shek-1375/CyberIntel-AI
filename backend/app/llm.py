"""Gemini chat models with automatic fallback.

Problem we hit: "503 UNAVAILABLE - This model is currently experiencing high
demand". When the main model is busy, we try the next model in the list
instead of failing. The response tells you which model actually answered.

Answers:   CHAT_MODEL  -> FALLBACK_MODELS ...
Reranking: RERANK_MODEL -> FALLBACK_MODELS ...  (a "lite" model is enough for scoring)

Day 5: the first agent run spent 268 seconds on one summary, because the busy
main model was retried for every call. Two fixes:
  * TIMEOUT: a call that takes longer than LLM_TIMEOUT seconds is abandoned.
  * CIRCUIT BREAKER: a model that just failed with 503 (busy), 429 (rate limit)
    or a timeout is skipped for COOLDOWN_SECONDS, so the next calls go straight
    to a model that works. If every model is cooling down, they're tried anyway.
"""
import logging
import time
from functools import lru_cache

from langchain_google_genai import ChatGoogleGenerativeAI

from app.config import CHAT_MODEL, FALLBACK_MODELS, GOOGLE_API_KEY, LLM_TIMEOUT, RERANK_MODEL

log = logging.getLogger(__name__)

COOLDOWN_SECONDS = 120
_busy_until: dict[str, float] = {}  # model name -> time until which we skip it


@lru_cache
def get_llm(model: str = CHAT_MODEL) -> ChatGoogleGenerativeAI:
    if not GOOGLE_API_KEY:
        raise RuntimeError("GOOGLE_API_KEY missing - add it to backend/.env")
    # max_retries=1 and a timeout: if a model is busy or slow, move on to the next one quickly
    return ChatGoogleGenerativeAI(
        model=model, google_api_key=GOOGLE_API_KEY, temperature=0.1, max_retries=1, timeout=LLM_TIMEOUT
    )


def _is_temporary(error: Exception) -> bool:
    """Busy, rate-limited or timed out: worth skipping this model for a while."""
    text = str(error).lower()
    return any(k in text for k in ("503", "unavailable", "429", "resource_exhausted", "timeout", "timed out", "deadline"))


def _model_chain(first: str) -> list[str]:
    chain = [first] + [m for m in FALLBACK_MODELS if m != first]
    return list(dict.fromkeys(chain))  # remove duplicates, keep order


def call_llm(prompt: str, schema=None, purpose: str = "answer"):
    """Call Gemini, trying each model in turn. Returns (result, model_used).

    schema: an optional Pydantic class; if given, Gemini must reply in that exact structure.
    """
    first = RERANK_MODEL if purpose == "rerank" else CHAT_MODEL
    now = time.monotonic()
    chain = _model_chain(first)
    ready = [m for m in chain if _busy_until.get(m, 0) <= now]
    cooling = [m for m in chain if m not in ready]  # last resort only
    last_error = None
    for model in ready + cooling:
        try:
            llm = get_llm(model)
            runnable = llm.with_structured_output(schema) if schema else llm
            result = runnable.invoke(prompt)
            _busy_until.pop(model, None)
            return result, model
        except Exception as e:
            if _is_temporary(e):
                _busy_until[model] = time.monotonic() + COOLDOWN_SECONDS
            log.warning("Model %s failed (%s), trying next model", model, str(e)[:120])
            last_error = e
    raise last_error
