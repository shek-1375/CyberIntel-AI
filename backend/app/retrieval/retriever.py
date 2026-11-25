"""Step 4 of RAG: store chunks in Qdrant and search them.

Day 1: dense (vector) search only.
Day 2: three search modes plus an optional reranking step:

    question ─┬─► dense search (Qdrant, meaning)  ─┐
              └─► keyword search (BM25, exact words)┴─► RRF fusion ─► rerank ─► top-k

    mode="dense"    vectors only (Day 1 behaviour)
    mode="keyword"  BM25 only
    mode="hybrid"   both, merged with Reciprocal Rank Fusion
    mode="auto"     Day 3: hybrid if the question contains a CVE / ATT&CK ID, otherwise dense.
                    The evaluation showed keyword search is the best retriever for exact IDs
                    but drags down ordinary questions, so we only use it when it helps.

Day 3: every function takes an optional `collection`, so the evaluation script
can build temporary collections (e.g. with a different chunk size) and test them
without touching the main `cyber_docs` collection.
"""
import uuid
from functools import lru_cache

from langchain_core.documents import Document
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from app.config import CANDIDATES, COLLECTION, DENSE_WEIGHT, KEYWORD_WEIGHT, QDRANT_URL, RRF_K, TOP_K
from app.embeddings.embedder import embed_query, embed_texts
from app.retrieval.bm25 import BM25
from app.retrieval.fusion import reciprocal_rank_fusion
from app.retrieval.reranker import rerank
from app.text_utils import has_security_id

_bm25_indexes: dict[str, BM25] = {}  # one keyword index per collection, built lazily


@lru_cache
def get_client() -> QdrantClient:
    return QdrantClient(url=QDRANT_URL)


# ------------------------------------------------------------------ storing
def index_chunks(chunks: list[Document], collection: str = COLLECTION) -> int:
    client = get_client()
    vectors = embed_texts([c.page_content for c in chunks])

    # Fresh collection each time keeps things simple (no duplicates).
    if client.collection_exists(collection):
        client.delete_collection(collection)
    client.create_collection(
        collection, vectors_config=VectorParams(size=len(vectors[0]), distance=Distance.COSINE)
    )

    points = []
    for c, v in zip(chunks, vectors):
        # chunk_id lets us recognise the same chunk in the dense and keyword result lists
        chunk_id = f"{c.metadata['source']}#{c.metadata['chunk_index']}"
        points.append(
            PointStruct(id=str(uuid.uuid4()), vector=v, payload={"text": c.page_content, "chunk_id": chunk_id, **c.metadata})
        )
    client.upsert(collection, points=points, wait=True)
    _bm25_indexes.pop(collection, None)  # documents changed, so the keyword index must be rebuilt
    return len(points)


def delete_collection(collection: str) -> None:
    client = get_client()
    if client.collection_exists(collection):
        client.delete_collection(collection)
    _bm25_indexes.pop(collection, None)


def count(collection: str = COLLECTION) -> int:
    client = get_client()
    if not client.collection_exists(collection):
        return 0
    return client.count(collection).count


def _all_payloads(collection: str) -> list[dict]:
    """Read every stored chunk from Qdrant (used to build the BM25 index)."""
    client, out, offset = get_client(), [], None
    while True:
        points, offset = client.scroll(collection, limit=256, offset=offset, with_payload=True, with_vectors=False)
        out.extend(p.payload for p in points)
        if offset is None:
            return out


# ------------------------------------------------------------------ searching
def dense_search(question: str, limit: int, collection: str = COLLECTION) -> list[dict]:
    hits = get_client().query_points(collection, query=embed_query(question), limit=limit, with_payload=True).points
    return [{**h.payload, "dense_score": round(h.score, 3)} for h in hits]


def keyword_search(question: str, limit: int, collection: str = COLLECTION) -> list[dict]:
    if collection not in _bm25_indexes:
        _bm25_indexes[collection] = BM25(_all_payloads(collection))
    return _bm25_indexes[collection].search(question, limit)


def search(
    question: str,
    top_k: int = TOP_K,
    mode: str = "hybrid",
    use_rerank: bool = False,
    collection: str = COLLECTION,
    weights: dict[str, float] | None = None,
) -> dict:
    if count(collection) == 0:
        return {"mode": mode, "reranked": False, "rerank_model": None, "results": []}

    requested_mode = mode
    if mode == "auto":
        mode = "hybrid" if has_security_id(question) else "dense"

    if mode == "dense":
        candidates = dense_search(question, CANDIDATES, collection)
    elif mode == "keyword":
        candidates = keyword_search(question, CANDIDATES, collection)
    else:  # hybrid
        candidates = reciprocal_rank_fusion(
            {
                "dense": dense_search(question, CANDIDATES, collection),
                "keyword": keyword_search(question, CANDIDATES, collection),
            },
            k=RRF_K,
            weights=weights or {"dense": DENSE_WEIGHT, "keyword": KEYWORD_WEIGHT},
        )

    rerank_model = None
    if use_rerank:
        # copies, so reranking one search never changes another search's results
        candidates, rerank_model = rerank(question, [dict(c) for c in candidates[:CANDIDATES]])

    return {
        "mode": requested_mode if requested_mode == mode else f"{requested_mode} -> {mode}",
        "reranked": rerank_model is not None,
        "rerank_model": rerank_model,
        "results": candidates[:top_k],
    }
