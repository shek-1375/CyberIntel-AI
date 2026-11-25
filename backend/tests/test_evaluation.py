"""Unit tests for Day 3: retrieval metrics, grounding checks and the evaluation set.

Run from backend/:   python -m pytest -v
"""
import json
import re
from pathlib import Path

from app.evaluation.metrics import first_relevant_rank, is_relevant, summarise
from app.rag.grounding import check_grounding

BACKEND = Path(__file__).resolve().parents[1]


# ---------------- metrics
RESULTS = [
    {"source": "a.md", "text": "Mitigation: upgrade the library"},
    {"source": "b.md", "text": "Detection: search   web logs for jndi"},  # extra spaces on purpose
    {"source": "a.md", "text": "Detection: search web logs for jndi"},
]


def test_relevance_needs_right_source_and_phrase():
    assert is_relevant(RESULTS[2], "a.md", "search web logs")
    assert not is_relevant(RESULTS[1], "a.md", "search web logs")   # right phrase, wrong document
    assert not is_relevant(RESULTS[0], "a.md", "search web logs")   # right document, wrong phrase


def test_relevance_ignores_case_and_extra_spaces():
    assert is_relevant(RESULTS[1], "b.md", "SEARCH WEB LOGS")


def test_first_relevant_rank():
    assert first_relevant_rank(RESULTS, "a.md", "search web logs") == 3
    assert first_relevant_rank(RESULTS, "c.md", "anything") is None


def test_summarise_hit_and_mrr():
    # 4 questions: answer found at rank 1, rank 2, rank 4, and not found
    s = summarise([1, 2, 4, None], k=4)
    assert s["hit@1"] == 0.25          # only 1 of 4 first
    assert s["hit@4"] == 0.75          # 3 of 4 somewhere in the top 4
    assert s["mrr"] == round((1 + 0.5 + 0.25 + 0) / 4, 3)


# ---------------- grounding
SOURCES = ["Log4Shell is CVE-2021-44228 and affects 2.0-beta9 to 2.14.1.", "Upgrade to 2.17.1 or later."]


def test_grounded_answer_passes():
    g = check_grounding("Log4Shell is CVE-2021-44228 [1]. Upgrade to 2.17.1 [2].", SOURCES)
    assert g["grounded"] and g["cited_sources"] == [1, 2] and not g["unsupported_cve_ids"]


def test_hallucinated_cve_is_caught():
    g = check_grounding("This is related to CVE-2099-12345 [1].", SOURCES)
    assert g["unsupported_cve_ids"] == ["CVE-2099-12345"] and not g["grounded"]


def test_invalid_citation_is_caught():
    g = check_grounding("Upgrade to 2.17.1 [7].", SOURCES)
    assert g["invalid_citations"] == [7] and not g["grounded"]


def test_refusal_counts_as_grounded():
    g = check_grounding("The indexed sources don't cover this.", SOURCES)
    assert g["refused"] and g["grounded"]


def test_answer_without_citations_is_not_grounded():
    assert not check_grounding("You should upgrade Log4j to the latest version.", SOURCES)["grounded"]


# ---------------- the evaluation set itself
def test_every_evidence_phrase_exists_in_its_document():
    """If someone edits a document, this test tells them which questions broke."""
    norm = lambda s: re.sub(r"\s+", " ", s).lower()
    questions = json.loads((BACKEND / "eval" / "eval_set.json").read_text(encoding="utf-8"))["questions"]
    for q in questions:
        if q.get("answerable", True):
            doc = (BACKEND / "data" / "documents" / q["source"]).read_text(encoding="utf-8")
            assert norm(q["evidence"]) in norm(doc), f"{q['id']}: evidence phrase not found in {q['source']}"


# ---------------- Day 3 round 2: weighted fusion and the auto router
def test_weighted_rrf_lets_dense_win_a_tie():
    from app.retrieval.fusion import reciprocal_rank_fusion
    lists = {"dense": [{"chunk_id": "d"}, {"chunk_id": "k"}], "keyword": [{"chunk_id": "k"}, {"chunk_id": "d"}]}
    assert reciprocal_rank_fusion(lists)[0]["rrf_score"] == reciprocal_rank_fusion(lists)[1]["rrf_score"]  # equal: a tie
    weighted = reciprocal_rank_fusion(lists, weights={"dense": 2.0, "keyword": 1.0})
    assert weighted[0]["chunk_id"] == "d"  # dense's favourite wins


def test_has_security_id():
    from app.text_utils import has_security_id
    assert has_security_id("What is CVE-2023-35708?")
    assert has_security_id("Which ATT&CK technique is T1490?")
    assert has_security_id("is t1059.001 used here")
    assert not has_security_id("How do I detect Log4Shell?")
    assert not has_security_id("Upgrade to 2.17.1")  # a version number is not an ID
