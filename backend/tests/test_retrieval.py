"""Unit tests for the parts of retrieval that need no API key or Qdrant.

Run from backend/:   python -m pytest -v
"""
from app.retrieval.bm25 import BM25
from app.retrieval.fusion import reciprocal_rank_fusion
from app.text_utils import tokenize


# ---------------- tokenizer
def test_tokenizer_keeps_security_ids_whole():
    tokens = tokenize("Is CVE-2021-44228 in log4j-core exploited via T1190.?")
    assert "cve-2021-44228" in tokens
    assert "log4j-core" in tokens
    assert "t1190" in tokens


def test_tokenizer_drops_stopwords():
    assert tokenize("What is the fix for this") == ["fix"]


# ---------------- BM25
DOCS = [
    {"chunk_id": "a", "text": "MOVEit Transfer SQL injection CVE-2023-34362 exploited by CL0P"},
    {"chunk_id": "b", "text": "Follow-on SQL injection bugs CVE-2023-35036 and CVE-2023-35708 were fixed later"},
    {"chunk_id": "c", "text": "Log4Shell CVE-2021-44228 is a JNDI lookup remote code execution in Log4j"},
]


def test_bm25_finds_exact_cve_id():
    results = BM25(DOCS).search("CVE-2023-35708", limit=3)
    assert results[0]["chunk_id"] == "b"
    assert len(results) == 1  # no other document contains that exact ID


def test_bm25_rare_words_matter_more_than_common_ones():
    # "sql" and "injection" appear in 2 docs; "jndi" only in 1 -> doc c wins for a JNDI question
    results = BM25(DOCS).search("JNDI injection", limit=3)
    assert results[0]["chunk_id"] == "c"


def test_bm25_no_match_returns_empty():
    assert BM25(DOCS).search("kubernetes", limit=3) == []


# ---------------- Reciprocal Rank Fusion
def test_rrf_rewards_chunks_found_by_both_retrievers():
    dense = [{"chunk_id": "x"}, {"chunk_id": "y"}, {"chunk_id": "z"}]
    keyword = [{"chunk_id": "z"}, {"chunk_id": "y"}]
    fused = reciprocal_rank_fusion({"dense": dense, "keyword": keyword})
    ids = [r["chunk_id"] for r in fused]
    assert ids[-1] == "x"            # only in one list
    assert set(ids[:2]) == {"y", "z"}  # in both lists
    y = next(r for r in fused if r["chunk_id"] == "y")
    assert y["ranks"] == {"dense": 2, "keyword": 2}


def test_rrf_keeps_scores_from_both_lists():
    fused = reciprocal_rank_fusion({
        "dense": [{"chunk_id": "x", "dense_score": 0.8}],
        "keyword": [{"chunk_id": "x", "bm25_score": 4.2}],
    })
    assert fused[0]["dense_score"] == 0.8 and fused[0]["bm25_score"] == 4.2


# ---------------- stemming (Day 2 fix: "detect" must match "Detection")
def test_stemming_matches_word_forms():
    from app.text_utils import stem
    assert stem("detection") == stem("detect") == stem("detecting") == stem("detected") == "detect"
    assert stem("vulnerabilities") == stem("vulnerability")
    assert stem("processes") == "process" and stem("process") == "process"


def test_stemming_never_touches_security_ids():
    assert tokenize("CVE-2021-44228 log4j-core T1059.001") == ["cve-2021-44228", "log4j-core", "t1059.001"]


def test_bm25_detect_question_finds_detection_section():
    docs = [
        {"chunk_id": "mitigation", "text": "Mitigation: upgrade log4j-core and remove the JndiLookup class"},
        {"chunk_id": "detection", "text": "Detection: search web logs for jndi:ldap strings and alert on Java processes"},
    ]
    assert BM25(docs).search("How do I detect it?", limit=2)[0]["chunk_id"] == "detection"


# ---------------- contextual chunk headers (Day 2 fix: chunks must remember their document)
def test_context_header_is_added_once():
    from app.ingestion.chunker import add_context_header
    title = "Advisory Summary: Log4Shell (CVE-2021-44228)"
    assert add_context_header("## Detection\n- search logs", title) == f"[{title}]\n## Detection\n- search logs"
    first_chunk = f"# {title}\n\nOverview..."
    assert add_context_header(first_chunk, title) == first_chunk  # already has the title


def test_document_title_from_markdown_heading():
    from pathlib import Path
    from app.ingestion.loader import document_title
    assert document_title("_note_\n# Log4Shell Advisory\ntext", Path("x.md")) == "Log4Shell Advisory"
    assert document_title("no heading here", Path("ransomware-playbook.pdf")) == "Ransomware Playbook"
