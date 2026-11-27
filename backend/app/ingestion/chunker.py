"""Step 2 of RAG: split documents into small chunks.

Small chunks give focused embeddings, so search returns the exact paragraph
that answers a question. Overlap keeps sentences on a boundary findable.
The splitter tries paragraph breaks first, then lines, then sentences.

Day 2 addition: CONTEXTUAL CHUNK HEADERS.
A chunk like "## Detection - search logs for ${jndi:ldap ..." never says
"Log4Shell", because the title ended up in a different chunk. Search and the
reranker then can't tell it belongs to the Log4Shell advisory. So we put the
document title at the top of every chunk:

    [Advisory Summary: Log4Shell (CVE-2021-44228) ...]
    ## Detection
    - Search web, proxy and application logs ...

Day 5 addition: STRUCTURE-AWARE SPLITTING.
The splitter now tries Markdown headings ("\n## ", "\n### ") before blank
lines. A heading starts a new section, so cutting there keeps each section,
and each CISA KEV entry (one "## CVE-..." heading each), in one piece.
Before this, a size-based cut could leave the end of one CVE and the start of
the next in the same chunk, and the answer could mix their details up.
"""
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from app.config import CHUNK_OVERLAP, CHUNK_SIZE


def add_context_header(text: str, title: str | None) -> str:
    if not title or text.lstrip().startswith("# " + title):
        return text  # no title, or this chunk already starts with the title itself
    return f"[{title}]\n{text}"


def chunk_documents(docs: list[Document], chunk_size: int | None = None, chunk_overlap: int | None = None) -> list[Document]:
    """chunk_size / chunk_overlap default to the .env settings; the evaluation
    script passes other values to compare chunk sizes."""
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size or CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP if chunk_overlap is None else chunk_overlap,
        separators=["\n## ", "\n### ", "\n\n", "\n", ". ", " ", ""],
    )
    chunks = splitter.split_documents(docs)  # metadata is copied onto every chunk
    for i, c in enumerate(chunks):
        c.metadata["chunk_index"] = i
        c.page_content = add_context_header(c.page_content, c.metadata.get("title"))
    return chunks
