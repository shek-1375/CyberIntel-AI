# Day 3: Evaluation and grounding checks

## Why

On Day 2 every improvement was judged **by eye**: run `/compare` on one question and
see whether the right chunk moved up. That doesn't tell you whether a change helps
*overall*, or quietly makes other questions worse. Day 3 turns "looks better" into numbers.

## The evaluation set (`backend/eval/eval_set.json`)

21 questions:

| Type | Count | Example | Tests |
|---|---|---|---|
| exact_id | 3 | `What is CVE-2023-35708?` | Finding an exact identifier |
| factual | 6 | `Who was behind the MOVEit Transfer attacks?` | Plain fact lookup |
| detection | 3 | `How do I detect Log4Shell exploitation?` | The Day 2 problem |
| mitigation | 4 | `What should we do if we can't patch MOVEit immediately?` | Remediation advice |
| paraphrase | 3 | `How do attackers steal domain password hashes?` | Different words from the document |
| unanswerable | 3 | `What is the CVSS score of CVE-2024-3400?` | Must refuse, not invent |

Each answerable question records **which document** holds the answer and a short
**evidence phrase** copied from it. A retrieved chunk counts as correct if it comes from
that document and contains the phrase. Using a phrase (not a chunk number) means the set
still works when chunk size changes. A unit test checks every phrase still exists in its
document, so editing a document can't silently break the evaluation.

## The metrics (`app/evaluation/metrics.py`)

For each question, find the rank of the **first correct chunk** in the results:

| Metric | Meaning | Example |
|---|---|---|
| **Hit@1** | Was the first result correct? | 0.67 = right chunk first for 67% of questions |
| **Hit@4** | Was a correct chunk anywhere in the top 4? (Gemini sees 4 chunks) | 0.94 = Gemini had the evidence 94% of the time |
| **MRR** | Mean Reciprocal Rank: 1/rank, averaged. Rank 1 = 1.0, rank 2 = 0.5, rank 4 = 0.25, missing = 0 | Rewards putting the answer high, not just somewhere |

Hit@4 says whether the answer *can* be right; Hit@1 and MRR say how cleanly search found it.

## Grounding checks (`app/rag/grounding.py`)

The prompt *asks* Gemini to cite and not invent CVE IDs. These checks *verify* it, in
plain code, on every `/ask` answer (see the new `grounding` field):

| Check | Catches |
|---|---|
| `invalid_citations` | Citing `[7]` when only 4 sources were given |
| `unsupported_cve_ids` | A CVE ID in the answer that is in none of the sources: a hallucination |
| `uncited_sentences` | Factual-looking sentences with no citation |
| `refused` | The model said the sources don't cover the question |
| `grounded` | No invalid citations, no unsupported CVE IDs, and the answer cites something or properly refuses |

## How to run it

From `backend/` with `(venv)` active, Qdrant running, after `/ingest`:

```bash
python -m scripts.evaluate                                  # every search mode
python -m scripts.evaluate --chunk-sizes 800,1000,1200      # + chunk size experiment
python -m scripts.evaluate --chunk-sizes 800,1000,1200 --answers  # + answer grounding (Gemini)
```

Or `POST /evaluate` in `/docs`. The report is saved to `backend/eval/results/latest.md`.

The chunk size experiment builds **temporary** Qdrant collections (`cyber_docs_eval_400` etc.),
evaluates them and deletes them, so your main collection is never touched.

## Round 1 results: the numbers disagreed with our assumption

| Mode | Hit@1 | Hit@4 | MRR |
|---|---|---|---|
| dense | 0.72 | 1.00 | 0.83 |
| keyword | 0.56 | 0.78 | 0.64 |
| hybrid | 0.61 | 0.94 | 0.74 |
| hybrid + rerank | 0.67 | 1.00 | 0.80 |

Dense was best overall. Broken down by question type, keyword search was the **best**
retriever for exact IDs (MRR 0.75 vs dense 0.44) but the **worst** for factual questions
(0.37 vs 0.87). Where keyword found nothing useful (q16, q18), its wrong guesses still
earned fusion points and pushed dense's correct chunk from rank 1 down to rank 3 or 4.

Chunk size: MRR rose with size (400: 0.68, 800: 0.80, 1200: 0.86), but with only three
documents a 1200-character chunk set has 12 chunks, so the top 4 is a third of the whole
corpus. Bigger chunks also send more text to the LLM and give less precise citations.
Retrieval scores alone can't settle chunk size on a corpus this small.

## Round 2: fixes suggested by the data

| Option | Idea |
|---|---|
| `dense + rerank` | Skip keyword search; let the cross-encoder polish dense results |
| `weighted 2:1` | Weighted RRF: a dense rank counts twice as much as a keyword rank |
| `auto` | **Route by question:** hybrid if the question contains a CVE or ATT&CK ID (where keyword helps), otherwise dense (where keyword hurts) |

All are measured together by `python -m scripts.evaluate`. Set the winner as
`SEARCH_MODE` in `.env`.

## Interview answer

> "I built a labelled evaluation set of 21 security questions, including exact-ID,
> paraphrase and unanswerable ones, and measured Hit@1, Hit@4 and MRR for every search
> mode. The first run surprised me: plain vector search beat hybrid search overall. The
> per-type breakdown showed why: keyword search was best for exact CVE IDs but hurt
> ordinary questions. So I added query routing (hybrid only when the question contains a
> security ID) and weighted fusion, and measured them against the baseline. I also
> added automatic grounding checks that flag invalid citations and CVE IDs that don't
> appear in the sources, and I test that the system refuses questions its documents
> can't answer."
