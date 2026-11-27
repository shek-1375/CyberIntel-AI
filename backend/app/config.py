"""All settings in one place, read from backend/.env."""
import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_DIR / ".env", override=True)

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
CHAT_MODEL = os.getenv("GEMINI_CHAT_MODEL", "gemini-3.8-flash")
RERANK_MODEL = os.getenv("GEMINI_RERANK_MODEL", "gemini-3.5-flash-lite")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "30"))     # seconds before giving up on one Gemini call
# Tried in order when a model is busy (503) or unavailable
FALLBACK_MODELS = [
    m.strip() for m in os.getenv("GEMINI_FALLBACK_MODELS", "gemini-3.5-flash-lite,gemini-3.1-flash-lite").split(",") if m.strip()
]
EMBEDDING_MODEL = os.getenv("GEMINI_EMBEDDING_MODEL", "models/gemini-embedding-001")

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION = os.getenv("QDRANT_COLLECTION", "cyber_docs")

CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "800"))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "100"))
TOP_K = int(os.getenv("TOP_K", "4"))

# --- Day 2: hybrid search + reranking ---
SEARCH_MODE = os.getenv("SEARCH_MODE", "hybrid")      # dense | keyword | hybrid | auto
CANDIDATES = int(os.getenv("CANDIDATES", "10"))       # how many each retriever fetches before fusion
RRF_K = int(os.getenv("RRF_K", "60"))                 # Reciprocal Rank Fusion constant
DENSE_WEIGHT = float(os.getenv("DENSE_WEIGHT", "1.0"))     # RRF weight for dense results
KEYWORD_WEIGHT = float(os.getenv("KEYWORD_WEIGHT", "1.0")) # RRF weight for keyword results
RERANK = os.getenv("RERANK", "true").lower() == "true"  # re-order the candidates before answering
RERANKER = os.getenv("RERANKER", "cross-encoder")       # cross-encoder (local, free) | gemini
CROSS_ENCODER_MODEL = os.getenv("CROSS_ENCODER_MODEL", "Xenova/ms-marco-MiniLM-L-6-v2")

DOCUMENTS_DIR = BACKEND_DIR / "data" / "documents"

# --- Day 4: live threat intelligence ---
NVD_API_KEY = os.getenv("NVD_API_KEY", "")            # optional: raises NVD limit from 5 to 50 requests / 30 s
LIVE_INTEL = os.getenv("LIVE_INTEL", "true").lower() == "true"  # add live NVD/KEV/EPSS facts to /ask for CVE questions
INTEL_CACHE_DIR = BACKEND_DIR / "data" / "intel"      # downloaded feeds are cached here (not committed to Git)
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "30"))
