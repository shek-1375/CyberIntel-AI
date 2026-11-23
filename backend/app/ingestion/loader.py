"""Step 1 of RAG: load files into text + metadata.

The metadata (file name, page) is what later lets us cite sources.
"""
from pathlib import Path

from langchain_core.documents import Document
from pypdf import PdfReader

SUPPORTED = {".pdf", ".txt", ".md"}


def load_file(path: Path) -> list[Document]:
    if path.suffix.lower() == ".pdf":
        reader = PdfReader(str(path))
        return [
            Document(page_content=text, metadata={"source": path.name, "page": i})
            for i, page in enumerate(reader.pages, start=1)
            if (text := (page.extract_text() or "").strip())
        ]
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [Document(page_content=text, metadata={"source": path.name})]


def load_directory(directory: Path) -> list[Document]:
    docs = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in SUPPORTED:
            docs.extend(load_file(path))
    return docs
