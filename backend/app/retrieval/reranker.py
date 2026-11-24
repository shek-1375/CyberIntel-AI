"""Reranking: a second, more careful look at the candidates.

Search (dense or BM25) looks at the question and each chunk SEPARATELY, so it
is fast but rough. A reranker reads the question and a chunk TOGETHER and
judges "does this chunk actually answer this question?". That's slower, so we
only rerank the top ~10 candidates, then keep the best few.

Two rerankers are available (RERANKER in .env):

  cross-encoder (default)
      A small model trained specifically for reranking (ms-marco-MiniLM-L-6-v2,
      trained on Bing search queries). Runs LOCALLY on your CPU via FastEmbed:
      free, no API key, never "503 busy". Downloaded once (~80 MB) on first use.
      Its scores are raw relevance numbers: higher = more relevant, and they can
      be negative. Only their ORDER matters.

  gemini
      Asks a Gemini model to score each passage 0-10. Works, but depends on the
      API being available (we hit repeated 503 "high demand" errors).

If the chosen reranker fails, we try the other one, and if both fail we keep
the hybrid order instead of crashing.
"""
import logging
from functools import lru_cache

from pydantic import BaseModel, Field

from app.config import CROSS_ENCODER_MODEL, RERANKER
from app.llm import call_llm

log = logging.getLogger(__name__)


# ------------------------------------------------------------- cross-encoder
@lru_cache
def _cross_encoder():
    from fastembed.rerank.cross_encoder import TextCrossEncoder

    log.info("Loading cross-encoder %s (downloads once on first use)...", CROSS_ENCODER_MODEL)
    return TextCrossEncoder(model_name=CROSS_ENCODER_MODEL)


def _rerank_cross_encoder(question: str, candidates: list[dict]) -> str:
    scores = list(_cross_encoder().rerank(question, [c["text"] for c in candidates]))
    for c, s in zip(candidates, scores):
        c["rerank_score"] = round(float(s), 3)
    return f"cross-encoder ({CROSS_ENCODER_MODEL})"


# ------------------------------------------------------------- gemini
class Score(BaseModel):
    passage: int = Field(description="The passage number shown in square brackets")
    score: int = Field(description="0 = irrelevant, 10 = directly answers the question")


class Scores(BaseModel):
    scores: list[Score]


PROMPT = """You are ranking evidence for a security analyst.
For each passage, score from 0 to 10 how directly it answers the question.
A passage that only mentions the same topic, but doesn't answer the question, scores low.
Give a score for every passage.

Question: {question}

Passages:
{passages}
"""


def _rerank_gemini(question: str, candidates: list[dict]) -> str:
    passages = "\n\n".join(f"[{i}] {c['text'][:700]}" for i, c in enumerate(candidates))
    result, model = call_llm(PROMPT.format(question=question, passages=passages), schema=Scores, purpose="rerank")
    by_index = {s.passage: s.score for s in result.scores}
    for i, c in enumerate(candidates):
        c["rerank_score"] = by_index.get(i, 0)
    return f"gemini ({model})"


# ------------------------------------------------------------- entry point
def rerank(question: str, candidates: list[dict]) -> tuple[list[dict], str | None]:
    """Returns (re-ordered candidates, reranker used). Reranker is None if all failed."""
    if len(candidates) < 2:
        return candidates, None

    order = [_rerank_cross_encoder, _rerank_gemini]
    if RERANKER == "gemini":
        order.reverse()

    for method in order:
        try:
            used = method(question, candidates)
            return sorted(candidates, key=lambda c: c["rerank_score"], reverse=True), used
        except Exception as e:
            log.warning("Reranker %s failed: %s", method.__name__, str(e)[:150])
    return candidates, None
