"""Step 3 of RAG: turn text into vectors (embeddings).

Texts with similar meaning get vectors that point in similar directions,
so "Java logging RCE" can match a chunk about Log4Shell without sharing words.
"""
from functools import lru_cache

from langchain_google_genai import GoogleGenerativeAIEmbeddings

from app.config import EMBEDDING_MODEL, GOOGLE_API_KEY


@lru_cache
def get_embedder() -> GoogleGenerativeAIEmbeddings:
    if not GOOGLE_API_KEY:
        raise RuntimeError("GOOGLE_API_KEY missing - add it to backend/.env")
    return GoogleGenerativeAIEmbeddings(model=EMBEDDING_MODEL, google_api_key=GOOGLE_API_KEY)


def embed_texts(texts: list[str]) -> list[list[float]]:
    return get_embedder().embed_documents(texts)


@lru_cache(maxsize=1024)
def _embed_query_cached(text: str) -> tuple[float, ...]:
    return tuple(get_embedder().embed_query(text))


def embed_query(text: str) -> list[float]:
    """Embed a question. Cached, so asking the same question again (e.g. during
    evaluation, where every question runs in several search modes) costs no API call."""
    return list(_embed_query_cached(text))
