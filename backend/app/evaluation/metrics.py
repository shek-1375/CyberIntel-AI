"""Retrieval metrics (pure Python, unit-tested).

For each question we know which document and which evidence phrase hold the
answer. We look at the ranked list the search returned and find the rank of
the FIRST chunk that is relevant (right document + contains the phrase).

  Hit@1   Was the very first result relevant?         (1 or 0 per question)
  Hit@k   Was ANY of the top k results relevant?      (1 or 0 per question)
          k = TOP_K = 4, because those 4 chunks are what Gemini sees.
  MRR     Mean Reciprocal Rank: 1/rank of the first relevant result,
          averaged over questions. Rank 1 -> 1.0, rank 2 -> 0.5, rank 4 -> 0.25,
          not found -> 0. It rewards putting the answer HIGH, not just somewhere.

Every metric is averaged over all questions and reported from 0 to 1
(0.83 means 83% of questions).
"""
import re


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().lower()


def is_relevant(chunk: dict, source: str, evidence: str) -> bool:
    return chunk.get("source") == source and _normalise(evidence) in _normalise(chunk.get("text", ""))


def first_relevant_rank(results: list[dict], source: str, evidence: str) -> int | None:
    """1-based rank of the first relevant chunk, or None if none are relevant."""
    for rank, chunk in enumerate(results, start=1):
        if is_relevant(chunk, source, evidence):
            return rank
    return None


def summarise(ranks: list[int | None], k: int) -> dict:
    """Turn a list of first-relevant ranks (one per question) into Hit@1, Hit@k and MRR."""
    n = len(ranks)
    if n == 0:
        return {"questions": 0, "hit@1": 0.0, f"hit@{k}": 0.0, "mrr": 0.0}
    hit1 = sum(1 for r in ranks if r == 1) / n
    hitk = sum(1 for r in ranks if r is not None and r <= k) / n
    mrr = sum(1 / r for r in ranks if r is not None and r <= k) / n
    return {"questions": n, "hit@1": round(hit1, 3), f"hit@{k}": round(hitk, 3), "mrr": round(mrr, 3)}
