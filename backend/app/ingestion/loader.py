"""Step 1 of RAG: load files into text + metadata.

The metadata (file name, page, title) is what later lets us cite sources.
The title is also stamped onto every chunk (see chunker.py), so a chunk never
"forgets" which document it came from.
"""
from pathlib import Path

from langchain_core.documents import Document
from pypdf import PdfReader

SUPPORTED = {".pdf", ".txt", ".md"}


def document_title(text: str, path: Path) -> str:
    """The first Markdown heading ("# ...") if there is one, otherwise a tidy file name."""
    for line in text.splitlines()[:10]:
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem.replace("-", " ").replace("_", " ").title()


def load_file(path: Path) -> list[Document]:
    if path.suffix.lower() == ".pdf":
        reader = PdfReader(str(path))
        pages = [(i, (p.extract_text() or "").strip()) for i, p in enumerate(reader.pages, start=1)]
        title = document_title(pages[0][1] if pages else "", path)
        return [
            Document(page_content=text, metadata={"source": path.name, "page": i, "title": title})
            for i, text in pages
            if text
        ]
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [Document(page_content=text, metadata={"source": path.name, "title": document_title(text, path)})]


def load_directory(directory: Path) -> list[Document]:
    docs = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in SUPPORTED:
            docs.extend(load_file(path))
    return docs
