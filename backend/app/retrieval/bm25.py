"""Keyword search with BM25, written from scratch so you can explain every line.

Vector search finds text with similar MEANING. It is weak at exact strings:
"CVE-2023-35708" and "CVE-2023-34362" look almost identical to an embedding
model. BM25 scores documents by the exact words they share with the query.

BM25 score of a document for a query = sum over each query word w of

    IDF(w) * ( tf * (k1 + 1) ) / ( tf + k1 * (1 - b + b * doc_len / avg_len) )

  tf      how many times w appears in this document (more = better, with diminishing returns)
  IDF(w)  how rare w is across all documents (rare words like a CVE ID count a lot,
          common words like "attack" count little)
  doc_len / avg_len   long documents are penalised a little, so they don't win just by being long
  k1=1.5, b=0.75      standard tuning constants
"""
import math
from collections import Counter

from app.text_utils import tokenize


class BM25:
    def __init__(self, documents: list[dict], k1: float = 1.5, b: float = 0.75):
        """documents: list of chunk payloads, each with a "text" field."""
        self.documents = documents
        self.k1, self.b = k1, b
        self.term_freqs = [Counter(tokenize(d["text"])) for d in documents]
        self.doc_lens = [sum(tf.values()) for tf in self.term_freqs]
        self.avg_len = (sum(self.doc_lens) / len(self.doc_lens)) if documents else 0.0

        # document frequency: in how many documents does each word appear?
        df = Counter()
        for tf in self.term_freqs:
            df.update(tf.keys())
        n = len(documents)
        self.idf = {w: math.log(1 + (n - f + 0.5) / (f + 0.5)) for w, f in df.items()}

    def score(self, query_tokens: list[str], i: int) -> float:
        tf, dl = self.term_freqs[i], self.doc_lens[i]
        s = 0.0
        for w in query_tokens:
            if w not in tf:
                continue
            f = tf[w]
            s += self.idf[w] * (f * (self.k1 + 1)) / (f + self.k1 * (1 - self.b + self.b * dl / self.avg_len))
        return s

    def search(self, query: str, limit: int) -> list[dict]:
        q = tokenize(query)
        scored = [(self.score(q, i), i) for i in range(len(self.documents))]
        scored = [x for x in scored if x[0] > 0]
        scored.sort(reverse=True)
        return [{**self.documents[i], "bm25_score": round(s, 3)} for s, i in scored[:limit]]
