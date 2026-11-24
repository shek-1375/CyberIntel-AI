# Day 2: Hybrid search and reranking

## The problem we saw on Day 1

Searching **"How do I detect Log4Shell?"** with vector (dense) search returned the
**Mitigation** chunk (score 0.772) slightly above the **Detection** chunk (0.768).
Both chunks are about Log4Shell, so their embeddings are close. Vector search found
the right *topic* but not the most precise *section*.

Vector search has a second weakness: **exact identifiers**. To an embedding model,
`CVE-2023-35708` and `CVE-2023-34362` look almost the same. An analyst searching for
one exact CVE needs the chunk that contains *that* ID.

## The fix: three new pieces

```
question ─┬─► dense search  (Qdrant: similar MEANING) ─┐
          └─► keyword search (BM25: same exact WORDS) ─┴─► RRF fusion ─► rerank (Gemini) ─► top 4 ─► answer
```

| Piece | File | What it does | Analogy |
|---|---|---|---|
| **BM25 keyword search** | `retrieval/bm25.py` | Scores chunks by exact shared words; rare words (like a CVE ID) count much more than common ones | Ctrl+F, but smart about which words matter |
| **Reciprocal Rank Fusion** | `retrieval/fusion.py` | Merges the dense and keyword lists using only ranks: `1 / (60 + rank)` per list | Two judges each rank the contestants; whoever ranks well with both wins |
| **Reranker** | `retrieval/reranker.py` | Gemini reads the question and each candidate *together* and scores 0–10 | A specialist re-checking the shortlist |

### Why not just add the scores?
Dense scores are about 0–1; BM25 scores can be 0, 3.7, 12.4... Adding them lets BM25
dominate. RRF ignores the raw numbers and uses positions, so neither retriever dominates.

### Why rerank only ~10 candidates?
Search compares the question with each chunk **separately**: fast enough for millions of
chunks, but rough. A reranker reads the question and a chunk **together**: much more
accurate, but slow and costly. So we search widely and cheaply, then rerank a short list.
This "retrieve, then rerank" pattern is standard in production search.

### What if Gemini is busy?
The reranker catches the error and keeps the hybrid order. The answer step also catches
errors and returns a friendly message instead of a 500.

## New and changed endpoints

| Endpoint | New on Day 2 |
|---|---|
| `POST /search` | Body accepts `"mode": "dense" \| "keyword" \| "hybrid"` and `"rerank": true/false` |
| `POST /ask` | Same options; response shows `search_mode`, `reranked` and every score per source |
| `POST /compare` | Runs one question through dense, keyword, hybrid and hybrid + rerank side by side |

## Experiments to run

1. `/compare` with `{"question": "How do I detect Log4Shell?"}`
   Watch whether the Detection chunk moves to the top with hybrid + rerank.
2. `/compare` with `{"question": "CVE-2023-35708"}`
   Keyword and hybrid should find the MOVEit chunk that names this exact CVE.
3. `/compare` with `{"question": "attackers stealing files from a file transfer server"}`
   No exact keywords here, so dense search should do the heavy lifting.

## What the first test showed, and the fixes

The first `/compare` run for "How do I detect Log4Shell?" did **not** put the Detection chunk first:

| Problem found | Cause | Fix |
|---|---|---|
| Keyword search returned only the title chunk | BM25 matches exact words, and "detect" is not the same word as "Detection" | **Stemming** in `text_utils.py`: detect / detection / detecting / detected all become `detect`. Security IDs like `CVE-2021-44228` are never stemmed |
| `hybrid + rerank` was identical to `hybrid` | Gemini returned **503 high demand**, so the reranker fell back silently | **Model fallback** in `llm.py`: try a "lite" model first for reranking, then other models. `/compare` now shows `rerank_worked` and `rerank_model`, so a silent fallback is visible |

After stemming, keyword search found the **Detection** sections of both advisories.

### Second test: every Gemini model was busy

With stemming, hybrid ranked Mitigation and Detection almost equally (RRF scores 0.03202 vs 0.03200),
which is exactly the kind of tie a reranker should break. But the reranker still failed: **every**
Gemini model in the fallback chain returned 503. The fix was to stop depending on an API for
reranking and use a **local cross-encoder** (`ms-marco-MiniLM-L-6-v2`, run with FastEmbed from
the Qdrant team). It is a small model trained specifically to score (question, passage) pairs, runs on
the CPU, costs nothing and never returns "busy". Gemini reranking remains as a fallback option
(`RERANKER=gemini`).

| | Bi-encoder (embeddings) | Cross-encoder (reranker) |
|---|---|---|
| Input | Question and chunk encoded **separately** | Question and chunk read **together** |
| Speed | Fast: chunk vectors are pre-computed | Slow: must run once per (question, chunk) pair |
| Accuracy | Good at topic | Better at "does this answer the question?" |
| Used for | Searching all chunks | Re-ordering the top ~10 |

### Third test: the local reranker exposed a chunking problem

The cross-encoder ran, but it ranked the **title** chunk first and dropped the Log4Shell
**Detection** chunk. The Detection chunk never contains the word "Log4Shell": the title
ended up in a different chunk, so a small reranker couldn't tell what it was about
(the larger Gemini model could guess from context).

Fix: **contextual chunk headers**. `loader.py` records each document's title and
`chunker.py` stamps it on top of every chunk:

```
[Advisory Summary: Log4Shell (CVE-2021-44228) — Apache Log4j 2 Remote Code Execution]
## Detection
- Search web, proxy and application logs for ${jndi:ldap ...
```

This helps dense search, BM25 and the reranker at once. With headers, BM25 alone
already ranks the Log4Shell Detection chunk first and the MOVEit Detection chunk second.

## Interview answer

> "Pure vector search ranked a mitigation section above the detection section for a
> detection question, and it's unreliable for exact IDs like CVE numbers. I added BM25
> keyword search, merged both lists with Reciprocal Rank Fusion so neither score scale
> dominates, and added a reranking stage that reads the question and passage together.
> My first test showed no improvement, so I investigated: BM25 had no stemming, so
> 'detect' didn't match 'Detection', and the reranker was silently falling back because
> the model returned 503. I added stemming that never alters CVE IDs, and when every
> hosted model was overloaded I switched reranking to a local cross-encoder, so ranking
> quality no longer depends on API availability. The small cross-encoder then revealed that
> chunks had lost their document context, so I added contextual chunk headers."
