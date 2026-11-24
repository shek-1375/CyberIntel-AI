# CyberIntel AI

A RAG (Retrieval-Augmented Generation) assistant for security analysts: ask questions about security advisories and get answers grounded in your documents, with citations.

```
documents ─► load ─► chunk ─► embed (Gemini) ─► Qdrant

question ─┬─► dense search  (Qdrant, meaning)  ─┐
          └─► keyword search (BM25, exact words)┴─► RRF fusion ─► rerank (Gemini) ─► answer + [1][2] citations
```

## Progress

- **Day 1:** ingestion, chunking, Gemini embeddings, Qdrant vector search, cited answers
- **Day 2:** hybrid search (BM25 + vectors with Reciprocal Rank Fusion), Gemini reranking, `/compare` endpoint, unit tests. See [docs/day2-hybrid-search.md](docs/day2-hybrid-search.md)

## Project layout

```
CyberIntel-AI/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI: /health /ingest /search /compare /ask
│   │   ├── config.py              # settings from .env
│   │   ├── llm.py                 # shared Gemini chat model
│   │   ├── text_utils.py          # tokenizer that keeps CVE IDs whole
│   │   ├── ingestion/loader.py    # 1. read .md/.txt/.pdf
│   │   ├── ingestion/chunker.py   # 2. split into chunks
│   │   ├── embeddings/embedder.py # 3. Gemini embeddings
│   │   ├── retrieval/
│   │   │   ├── retriever.py       # 4. store in Qdrant + dense/keyword/hybrid search
│   │   │   ├── bm25.py            #    keyword search (BM25, from scratch)
│   │   │   ├── fusion.py          #    Reciprocal Rank Fusion
│   │   │   └── reranker.py        #    Gemini reranking
│   │   └── rag/chain.py           # 5. grounded answer with citations
│   ├── tests/test_retrieval.py    # unit tests (no API key needed)
│   ├── data/documents/            # sample advisories (add your own here)
│   ├── .env.example
│   └── requirements.txt
├── docs/day2-hybrid-search.md
├── docker-compose.yml             # Qdrant
└── README.md
```

## Setup (Windows)

```bash
# 1. Start Qdrant (Docker Desktop must be running), from the project root
docker compose up -d

# 2. Python environment
cd backend
python -m venv venv
source venv/Scripts/activate      # PowerShell: .\venv\Scripts\activate
pip install -r requirements.txt

# 3. API key: copy .env.example to .env and add your Gemini key

# 4. Run
uvicorn app.main:app --reload     # open http://localhost:8000/docs
```

## Try it

1. `POST /ingest` indexes everything in `data/documents`
2. `POST /compare` with `{"question": "How do I detect Log4Shell?"}` shows dense vs keyword vs hybrid vs hybrid+rerank
3. `POST /ask` with `{"question": "Which Log4j versions fix CVE-2021-44228?"}`

`/search` and `/ask` accept `"mode": "dense" | "keyword" | "hybrid"` and `"rerank": true | false`.

## Tests

```bash
cd backend
python -m pytest -v
```

## Roadmap

1. ~~RAG prototype~~
2. ~~Hybrid search + reranking~~
3. Retrieval evaluation (hit rate, MRR) and grounding checks
4. CVE data from NVD / CISA KEV, MITRE ATT&CK mapping
5. LangGraph investigation agent
6. React dashboard, PostgreSQL
7. Tests, Docker, deployment
