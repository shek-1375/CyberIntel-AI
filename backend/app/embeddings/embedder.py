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


def embed_query(text: str) -> list[float]:
    return get_embedder().embed_query(text)
