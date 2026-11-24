"""Step 4 of RAG: store chunks in Qdrant and search them.

Day 1: dense (vector) search only.
Day 2: three search modes plus an optional reranking step:

    question ─┬─► dense search (Qdrant, meaning)  ─┐
              └─► keyword search (BM25, exact words)┴─► RRF fusion ─► rerank (Gemini) ─► top-k

    mode="dense"    vectors only (Day 1 behaviour)
    mode="keyword"  BM25 only
    mode="hybrid"   both, merged with Reciprocal Rank Fusion
"""
import uuid
from functools import lru_cache

from langchain_core.documents import Document
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from app.config import CANDIDATES, COLLECTION, QDRANT_URL, RRF_K, TOP_K
from app.embeddings.embedder import embed_query, embed_texts
from app.retrieval.bm25 import BM25
from app.retrieval.fusion import reciprocal_rank_fusion
from app.retrieval.reranker import rerank

_bm25_index: BM25 | None = None  # built lazily from Qdrant, rebuilt after each ingest


@lru_cache
def get_client() -> QdrantClient:
    return QdrantClient(url=QDRANT_URL)


# ------------------------------------------------------------------ storing
def index_chunks(chunks: list[Document]) -> int:
    global _bm25_index
    client = get_client()
    vectors = embed_texts([c.page_content for c in chunks])

    # Fresh collection each time keeps things simple (no duplicates).
    if client.collection_exists(COLLECTION):
        client.delete_collection(COLLECTION)
    client.create_collection(
        COLLECTION, vectors_config=VectorParams(size=len(vectors[0]), distance=Distance.COSINE)
    )

    points = []
    for c, v in zip(chunks, vectors):
        # chunk_id lets us recognise the same chunk in the dense and keyword result lists
        chunk_id = f"{c.metadata['source']}#{c.metadata['chunk_index']}"
        points.append(
            PointStruct(id=str(uuid.uuid4()), vector=v, payload={"text": c.page_content, "chunk_id": chunk_id, **c.metadata})
        )
    client.upsert(COLLECTION, points=points, wait=True)
    _bm25_index = None  # documents changed, so the keyword index must be rebuilt
    return len(points)


def count() -> int:
    client = get_client()
    if not client.collection_exists(COLLECTION):
        return 0
    return client.count(COLLECTION).count


def _all_payloads() -> list[dict]:
    """Read every stored chunk from Qdrant (used to build the BM25 index)."""
    client, out, offset = get_client(), [], None
    while True:
        points, offset = client.scroll(COLLECTION, limit=256, offset=offset, with_payload=True, with_vectors=False)
        out.extend(p.payload for p in points)
        if offset is None:
            return out


# ------------------------------------------------------------------ searching
def dense_search(question: str, limit: int) -> list[dict]:
    hits = get_client().query_points(COLLECTION, query=embed_query(question), limit=limit, with_payload=True).points
    return [{**h.payload, "dense_score": round(h.score, 3)} for h in hits]


def keyword_search(question: str, limit: int) -> list[dict]:
    global _bm25_index
    if _bm25_index is None:
        _bm25_index = BM25(_all_payloads())
    return _bm25_index.search(question, limit)


def search(question: str, top_k: int = TOP_K, mode: str = "hybrid", use_rerank: bool = False) -> dict:
    if count() == 0:
        return {"mode": mode, "reranked": False, "rerank_model": None, "results": []}

    if mode == "dense":
        candidates = dense_search(question, CANDIDATES)
    elif mode == "keyword":
        candidates = keyword_search(question, CANDIDATES)
    else:  # hybrid
        candidates = reciprocal_rank_fusion(
            {"dense": dense_search(question, CANDIDATES), "keyword": keyword_search(question, CANDIDATES)},
            k=RRF_K,
        )

    rerank_model = None
    if use_rerank:
        candidates, rerank_model = rerank(question, candidates[:CANDIDATES])

    return {
        "mode": mode,
        "reranked": rerank_model is not None,
        "rerank_model": rerank_model,
        "results": candidates[:top_k],
    }
