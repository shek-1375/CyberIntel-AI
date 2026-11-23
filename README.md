# CyberIntel AI — Prototype

A small RAG prototype: ask questions about security advisories and get answers grounded in your documents, with citations.

```
documents ─► load ─► chunk ─► embed (Gemini) ─► Qdrant
question  ─► embed ─► search Qdrant (top 4) ─► Gemini answers from evidence ─► answer + [1][2] citations
```

## Project layout

```
CyberIntel-AI/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI: /health /ingest /search /ask
│   │   ├── config.py              # settings from .env
│   │   ├── ingestion/loader.py    # 1. read .md/.txt/.pdf
│   │   ├── ingestion/chunker.py   # 2. split into chunks
│   │   ├── embeddings/embedder.py # 3. Gemini embeddings
│   │   ├── retrieval/retriever.py # 4. store + search in Qdrant
│   │   └── rag/chain.py           # 5. grounded answer with citations
│   ├── data/documents/            # sample advisories (add your own here)
│   ├── .env.example
│   └── requirements.txt
├── docker-compose.yml             # Qdrant
└── README.md
```

## Setup (Windows PowerShell)

```powershell
# 1. Start Qdrant (needs Docker Desktop running), from the project root
docker compose up -d
# dashboard: http://localhost:6333/dashboard

# 2. Python environment
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt

# 3. API key
copy .env.example .env
# edit .env and paste your key from https://aistudio.google.com/apikey

# 4. Run the API
uvicorn app.main:app --reload
```

On WSL/Linux/macOS use `source venv/bin/activate` and `cp` instead of `copy`.

## Try it

Open http://localhost:8000/docs and run, in order:

1. `GET /health` — checks Qdrant and that your key is set
2. `POST /ingest` — indexes everything in `data/documents`
3. `POST /search` — `{"question": "How do I detect Log4Shell?"}` shows the retrieved chunks and similarity scores
4. `POST /ask` — same body, returns a cited answer

Good test questions:
- "Which Log4j versions fix CVE-2021-44228?"
- "What web shell was used in the MOVEit attacks?"
- "How do ransomware operators stop victims recovering from backups?"
- "What is the capital of France?" → should say the sources don't cover it (grounding check)

To add your own data, drop PDFs or markdown files into `backend/data/documents` and call `/ingest` again.

## Milestone 1 checklist

- [ ] Virtual environment working
- [ ] Dependencies installed
- [ ] Gemini API key configured
- [ ] Qdrant running locally
- [ ] FastAPI backend running and `/ask` returns cited answers

## Next steps (later phases)

1. Hybrid search (BM25 + vectors) so exact IDs like `CVE-2023-34362` match reliably
2. Reranking + a small retrieval evaluation set
3. CVE lookups from NVD and CISA KEV
4. MITRE ATT&CK mapping
5. LangGraph investigation agent
6. React dashboard, PostgreSQL, Docker deployment
