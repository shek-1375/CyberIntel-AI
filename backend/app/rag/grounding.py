"""Grounding checks: automatic tests that an answer sticks to its evidence.

The prompt TELLS Gemini to cite sources and never invent CVE IDs. These checks
VERIFY it after the answer is written, in plain code (no AI involved):

  invalid_citations    cited numbers that don't exist, e.g. [7] when only 4 sources were given
  unsupported_cve_ids  CVE IDs in the answer that appear in none of the sources (hallucination!)
  uncited_sentences    factual-looking sentences with no [n] citation
  refused              the model said the sources don't cover the question
  grounded             True when there are no invalid citations, no unsupported CVE IDs,
                       and the answer either cites something or properly refuses
"""
import re

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CITATION_RE = re.compile(r"\[(\d+)\]")
REFUSAL_PHRASES = ("don't cover this", "do not cover this", "not covered", "doesn't contain", "does not contain")


def check_grounding(answer: str, sources: list[str]) -> dict:
    """answer: the generated text. sources: the passage texts, in the order they were numbered."""
    answer = answer or ""
    cited = sorted({int(n) for n in CITATION_RE.findall(answer)})
    invalid = [n for n in cited if not 1 <= n <= len(sources)]

    evidence_cves = {c.upper() for s in sources for c in CVE_RE.findall(s)}
    unsupported = sorted({c.upper() for c in CVE_RE.findall(answer)} - evidence_cves)

    refused = any(p in answer.lower() for p in REFUSAL_PHRASES)

    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", answer) if len(s.strip()) > 30]
    uncited = [s for s in sentences if not CITATION_RE.search(s) and not any(p in s.lower() for p in REFUSAL_PHRASES)]

    return {
        "cited_sources": [n for n in cited if n not in invalid],
        "invalid_citations": invalid,
        "unsupported_cve_ids": unsupported,
        "uncited_sentences": len(uncited),
        "refused": refused,
        "grounded": not invalid and not unsupported and (bool(cited) or refused),
    }
