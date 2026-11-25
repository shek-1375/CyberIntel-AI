"""Reciprocal Rank Fusion (RRF): merge the dense and keyword result lists.

Problem: dense scores are cosine similarities (about 0 to 1) and BM25 scores
are unbounded (0, 3.7, 12.4 ...). You can't just add them.

Solution: ignore the raw scores and use only each result's RANK (1st, 2nd, ...):

    rrf_score(chunk) = sum over each list:  1 / (k + rank)

With k = 60, being 1st gives 1/61, being 10th gives 1/70. A chunk that appears
near the top of BOTH lists beats one that is first in only one list.

Day 3: optional WEIGHTS. weights={"dense": 2, "keyword": 1} makes a dense rank
count twice as much as a keyword rank: weighted RRF.
"""


def reciprocal_rank_fusion(
    ranked_lists: dict[str, list[dict]], k: int = 60, weights: dict[str, float] | None = None
) -> list[dict]:
    fused: dict[str, dict] = {}
    for list_name, results in ranked_lists.items():
        weight = (weights or {}).get(list_name, 1.0)
        for rank, item in enumerate(results, start=1):
            entry = fused.setdefault(item["chunk_id"], {**item, "rrf_score": 0.0, "ranks": {}})
            entry.update({key: val for key, val in item.items() if key.endswith("_score")})
            entry["rrf_score"] += weight / (k + rank)
            entry["ranks"][list_name] = rank
    results = sorted(fused.values(), key=lambda d: d["rrf_score"], reverse=True)
    for r in results:
        r["rrf_score"] = round(r["rrf_score"], 4)
    return results
