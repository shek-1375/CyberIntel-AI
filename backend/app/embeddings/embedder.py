"""Step 3 of RAG: turn text into vectors (embeddings).

Texts with similar meaning get vectors that point in similar directions,
so "Java logging RCE" can match a chunk about Log4Shell without sharing words.

Day 4: the free tier allows 100 embedding requests per minute, and every chunk
counts as one. Ingesting 100 KEV entries sent far more than that at once and got
"429 RESOURCE_EXHAUSTED". So chunks are now sent in batches, and when Google says
429 we wait for the time it asks for (plus a little) and retry, instead of failing.
"""
import logging
import re
import time
from functools import lru_cache

from langchain_google_genai import GoogleGenerativeAIEmbeddings

from app.config import EMBEDDING_MODEL, GOOGLE_API_KEY

log = logging.getLogger(__name__)

BATCH_SIZE = 50        # chunks per request batch (half the free-tier per-minute limit)
MAX_RETRIES = 6        # how many times to wait and retry one batch
DEFAULT_WAIT = 30.0    # seconds to wait if Google doesn't say how long


@lru_cache
def get_embedder() -> GoogleGenerativeAIEmbeddings:
    if not GOOGLE_API_KEY:
        raise RuntimeError("GOOGLE_API_KEY missing - add it to backend/.env")
    return GoogleGenerativeAIEmbeddings(model=EMBEDDING_MODEL, google_api_key=GOOGLE_API_KEY)


def is_rate_limit(error: Exception) -> bool:
    text = str(error)
    return "429" in text or "RESOURCE_EXHAUSTED" in text


def retry_delay(error: Exception, default: float = DEFAULT_WAIT) -> float:
    """Google's 429 message says e.g. 'Please retry in 4.62s'. Use that (plus a margin) if present."""
    m = re.search(r"retry in ([\d.]+)\s*s", str(error), re.IGNORECASE)
    return float(m.group(1)) + 2.0 if m else default


def embed_texts(texts: list[str], batch_size: int = BATCH_SIZE) -> list[list[float]]:
    vectors: list[list[float]] = []
    batches = [texts[i: i + batch_size] for i in range(0, len(texts), batch_size)]
    for n, batch in enumerate(batches, start=1):
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                vectors.extend(get_embedder().embed_documents(batch))
                break
            except Exception as e:
                if not is_rate_limit(e) or attempt == MAX_RETRIES:
                    raise
                wait = retry_delay(e)
                log.warning("Embedding rate limit on batch %d/%d, waiting %.0f s (attempt %d)", n, len(batches), wait, attempt)
                time.sleep(wait)
        if len(batches) > 1:
            log.info("Embedded batch %d/%d (%d chunks)", n, len(batches), len(batch))
    return vectors


@lru_cache(maxsize=1024)
def _embed_query_cached(text: str) -> tuple[float, ...]:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return tuple(get_embedder().embed_query(text))
        except Exception as e:
            if not is_rate_limit(e) or attempt == MAX_RETRIES:
                raise
            time.sleep(retry_delay(e))


def embed_query(text: str) -> list[float]:
    """Embed a question. Cached, so asking the same question again (e.g. during
    evaluation, where every question runs in several search modes) costs no API call."""
    return list(_embed_query_cached(text))
