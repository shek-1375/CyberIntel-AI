"""Step 4 of RAG: store vectors in Qdrant and search them.

Each chunk becomes a Qdrant "point": id + vector + payload (text and metadata).
Search embeds the question and returns the nearest chunks by cosine similarity.
"""
import uuid
from functools import lru_cache

from langchain_core.documents import Document
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from app.config import COLLECTION, QDRANT_URL, TOP_K
from app.embeddings.embedder import embed_query, embed_texts


@lru_cache
def get_client() -> QdrantClient:
    return QdrantClient(url=QDRANT_URL)


def index_chunks(chunks: list[Document]) -> int:
    client = get_client()
    vectors = embed_texts([c.page_content for c in chunks])

    # Fresh collection each time keeps the prototype simple (no duplicates).
    if client.collection_exists(COLLECTION):
        client.delete_collection(COLLECTION)
    client.create_collection(
        COLLECTION, vectors_config=VectorParams(size=len(vectors[0]), distance=Distance.COSINE)
    )

    points = [
        PointStruct(id=str(uuid.uuid4()), vector=v, payload={"text": c.page_content, **c.metadata})
        for c, v in zip(chunks, vectors)
    ]
    client.upsert(COLLECTION, points=points, wait=True)
    return len(points)


def search(question: str, top_k: int = TOP_K) -> list[dict]:
    hits = get_client().query_points(
        COLLECTION, query=embed_query(question), limit=top_k, with_payload=True
    ).points
    return [{**h.payload, "score": round(h.score, 3)} for h in hits]


def count() -> int:
    client = get_client()
    if not client.collection_exists(COLLECTION):
        return 0
    return client.count(COLLECTION).count
