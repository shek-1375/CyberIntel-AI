"""Step 2 of RAG: split documents into small chunks.

Small chunks give focused embeddings, so search returns the exact paragraph
that answers a question. Overlap keeps sentences on a boundary findable.
The splitter tries paragraph breaks first, then lines, then sentences.
"""
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from app.config import CHUNK_OVERLAP, CHUNK_SIZE


def chunk_documents(docs: list[Document]) -> list[Document]:
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    chunks = splitter.split_documents(docs)  # metadata is copied onto every chunk
    for i, c in enumerate(chunks):
        c.metadata["chunk_index"] = i
    return chunks
