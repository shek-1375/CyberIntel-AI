# CyberIntel AI

A RAG (Retrieval-Augmented Generation) assistant for security analysts: ask questions about security advisories and get answers grounded in your documents, with citations.

```
documents ─► load ─► chunk ─► embed (Gemini) ─► Qdrant

question ─┬─► dense search  (Qdrant, meaning)  ─┐
          └─► keyword search (BM25, exact words)┴─► RRF fusion ─► rerank (Gemini) ─► answer + [1][2] citations
```

## Progress

- **Day 1:** ingestion, chunking, Gemini embeddings, Qdrant vector search, cited answers
- **Day 2:** hybrid search (BM25 + vectors with Reciprocal Rank Fusion), stemming, contextual chunk headers, local cross-encoder reranking, model fallback, `/compare`. See [docs/day2-hybrid-search.md](docs/day2-hybrid-search.md)
- **Day 3:** evaluation set (21 questions), Hit@1 / Hit@4 / MRR for every search mode, chunk size experiment, automatic grounding checks on every answer. See [docs/day3-evaluation.md](docs/day3-evaluation.md) and the latest results in [backend/eval/results/latest.md](backend/eval/results/latest.md)
- **Day 4:** live threat intelligence from NVD, CISA KEV, FIRST EPSS and MITRE ATT&CK; rule-based patch priority; CVE → ATT&CK mapping with reasons; live CVE facts cited in answers. See [docs/day4-threat-intel.md](docs/day4-threat-intel.md)
- **Day 5:** LangGraph investigation agent (entities → live CVE intel → document evidence → validated ATT&CK mapping → recommendations → report), structure-aware chunking. See [docs/day5-agent.md](docs/day5-agent.md)

## Project layout

```
CyberIntel-AI/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI: /health /ingest /search /compare /ask /evaluate
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
│   │   ├── rag/chain.py           # 5. grounded answer with citations
│   │   ├── rag/grounding.py       #    checks answers for invalid citations / invented CVE IDs
│   │   ├── evaluation/            #    metrics (Hit@k, MRR) and the evaluation runner
│   │   ├── intel/                 # live threat intel: nvd, kev, epss, attack, risk, routes
│   │   └── agent/                 # LangGraph investigation agent: state, nodes, graph, report
│   ├── eval/eval_set.json         # 21 labelled evaluation questions
│   ├── eval/results/              # evaluation reports
│   ├── scripts/evaluate.py        # python -m scripts.evaluate
│   ├── tests/                     # unit tests (no API key needed)
│   ├── data/documents/            # sample advisories (add your own here)
│   ├── .env.example
│   └── requirements.txt
├── docs/                          # day-by-day write-ups
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
4. `GET /intel/cve/CVE-2023-34362` for a live intel card (NVD, KEV, EPSS, priority, ATT&CK)
5. `POST /investigate/report` with `{"query": "Investigate CVE-2023-34362 and recommend detections and mitigations"}` for a full investigation report

`/search` and `/ask` accept `"mode": "dense" | "keyword" | "hybrid"` and `"rerank": true | false`.

## Evaluate

```bash
cd backend
python -m scripts.evaluate --chunk-sizes 400,800,1200 --answers
```
Writes `eval/results/latest.md` with Hit@1, Hit@4 and MRR per search mode, a chunk size comparison and answer grounding results.

## Tests

```bash
cd backend
python -m pytest -v
```

## Roadmap

1. ~~RAG prototype~~
2. ~~Hybrid search + reranking~~
3. ~~Retrieval evaluation (hit rate, MRR) and grounding checks~~
4. ~~CVE data from NVD / CISA KEV, MITRE ATT&CK mapping~~
5. ~~LangGraph investigation agent~~
6. React dashboard, PostgreSQL
7. Tests, Docker, deployment
