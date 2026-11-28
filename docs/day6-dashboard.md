# Day 6: React dashboard and PostgreSQL history

## PostgreSQL history

| Table | Stores |
|---|---|
| `investigations` | every agent run: question, risk level, CVE IDs, summary, the Markdown report and the full JSON result |
| `question_logs` | every `/ask` question: answer, whether it was grounded or refused, which model answered, sources |

- PostgreSQL 16 runs as a second service in `docker-compose.yml` (user/password/db `cyberintel`, port 5433 on your computer (5432 inside the container, so it never clashes with a locally installed PostgreSQL), volume `postgres_data`, health check with `pg_isready`).
- `backend/app/db.py` uses **SQLAlchemy 2.0** (typed `Mapped[...]` models) with the **psycopg 3** driver. Tables are created at startup.
- **Graceful degradation:** if PostgreSQL is down, `/ask` and `/investigate` still work; the response says the result wasn't saved, `/health` reports the database status and the history endpoints return 503 with an explanation.
- The same code runs on **SQLite in memory** for the unit tests, so they need no database server.

New endpoints: `GET /investigations`, `GET /investigations/{id}`, `GET /investigations/{id}/report.md` (download), `DELETE /investigations/{id}`, `GET /questions`, `GET /evaluation/latest`. `/health` now includes `database`. CORS allows the dashboard's origin (`FRONTEND_ORIGINS`).

## The dashboard (`frontend/`)

React 19 + Vite, plain JavaScript, two libraries (`react-markdown` + `remark-gfm` to render reports and tables).

| Page | What it does |
|---|---|
| **Ask** | Question → cited answer. Citation markers like [2] are buttons that jump to and highlight the source. Shows whether the answer is grounded, refused, or needs checking, and which model answered |
| **CVE lookup** | Live card: CVSS, CISA KEV, EPSS, the priority stamp with its reasons, NVD description, CISA required action, ATT&CK techniques (rule vs keyword match) with mitigations, and a button to investigate |
| **Investigate** | Runs the LangGraph agent, shows the steps and elapsed time while waiting, renders the report, download button, link to history |
| **Exploited now** | The CISA KEV list, newest first, filter as you type (300 ms debounce); CVE IDs open the CVE card |
| **History** | Saved investigations (open, download, delete) and question history with grounded/refused status |
| **Evaluation** | The latest evaluation report |

- **Routing** without a library: the URL hash (`#/cve/CVE-2023-34362`), so pages can be bookmarked and Back works.
- **API calls** go to `/api/...`; Vite's dev server proxies them to FastAPI on port 8000.
- A status panel in the side rail shows the API, search index, Gemini key and history database.

### Design decisions

- **Subject-led, not template-led:** a triage desk for analysts. Cool paper background and navy ink; the only strong colours are the CVSS severity colours, so colour always means risk.
- **Public Sans** (the US government's design-system typeface; NVD and CISA are government sources) for the interface, **Source Serif 4** for reading answers and reports.
- **One bold element:** the rotated, double-bordered **priority stamp** (critical / high / medium / low), like a triage stamp, with a single short "stamp" animation. Everything else is quiet: thin borders, no shadows, left-aligned.
- Accessibility: visible keyboard focus, reduced-motion respected, responsive down to phone width (the side rail becomes a top bar).
- Deliberately avoided the default "dark hacker theme with neon green".

## How to run

```bash
# project root
docker compose up -d                 # Qdrant + PostgreSQL
# backend (terminal 1)
cd backend && source venv/Scripts/activate
pip install -r requirements.txt      # adds sqlalchemy + psycopg
uvicorn app.main:app --reload
# frontend (terminal 2)
cd frontend
npm install                          # first time only
npm run dev                          # http://localhost:5173
```

## Interview answer

> "I added a React dashboard so analysts don't need Swagger: cited answers where each citation jumps to its
> source, a live CVE card with a rule-based priority, the investigation agent with downloadable reports, and the CISA
> KEV feed. Investigations and questions are saved in PostgreSQL through SQLAlchemy, and the app degrades gracefully
> when the database is down. The same database code runs on in-memory SQLite in the tests."
