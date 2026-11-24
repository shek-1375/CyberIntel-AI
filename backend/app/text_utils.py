"""Small text helpers used by keyword search.

1. The tokenizer splits text into lowercase words, but keeps security IDs
   whole: "CVE-2021-44228", "T1059.001" and "log4j-core" stay one token each.
   A normal tokenizer would break "CVE-2021-44228" into "cve", "2021", "44228",
   and then every CVE from 2021 would look like a match.

2. Stemming cuts plain words down to a common root, so a question that says
   "detect" also matches a chunk that says "Detection" or "detected".
   BM25 only matches identical tokens, so without this "detect" != "detection".
"""
import re

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._\-]*")

# Very common words that carry no meaning for search.
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "does", "for", "from",
    "how", "i", "in", "is", "it", "of", "on", "or", "should", "that", "the", "this",
    "to", "was", "we", "what", "when", "which", "with", "you",
}

# (suffix, replacement), tried in this order; the first that fits wins.
SUFFIX_RULES = [
    ("ations", ""), ("ation", ""),      # exploitation -> exploit
    ("ions", ""), ("ion", ""),          # detection -> detect
    ("ings", ""), ("ing", ""),          # detecting -> detect
    ("ies", "y"),                       # vulnerabilities -> vulnerability
    ("sses", "ss"), ("ches", "ch"), ("shes", "sh"), ("xes", "x"),  # processes -> process
    ("ed", ""),                         # detected -> detect
    ("s", ""),                          # attackers -> attacker
]


def stem(word: str) -> str:
    """A small, explainable stemmer for plain English words.

    Security IDs (anything with a digit, dot or hyphen) are never stemmed.
    The remaining root must keep at least 4 letters, so short words stay intact.
    """
    if not word.isalpha() or len(word) <= 4 or word.endswith("ss"):
        return word
    for suffix, replacement in SUFFIX_RULES:
        if word.endswith(suffix):
            root = word[: -len(suffix)] + replacement
            if len(root) >= 4:
                return root
    return word


def tokenize(text: str) -> list[str]:
    tokens = []
    for tok in TOKEN_RE.findall(text.lower()):
        tok = tok.rstrip("._-")  # "T1190." -> "t1190"
        if tok and tok not in STOPWORDS:
            tokens.append(stem(tok))
    return tokens
