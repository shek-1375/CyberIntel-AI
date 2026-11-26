"""MITRE ATT&CK: the standard catalogue of attacker behaviour.

ATT&CK describes WHAT attackers do, organised as:
  Tactic      the goal          e.g. Initial Access, Execution, Credential Access
  Technique   how they do it    e.g. T1190 Exploit Public-Facing Application
  Mitigation  how to defend     e.g. M1051 Update Software

MITRE publishes ATT&CK as one big STIX 2.1 JSON file (tens of MB). We download it
once (cached for 7 days) and turn it into a small searchable index.

Mapping a CVE to ATT&CK (suggest_for_cve) is done with transparent rules plus
keyword search, and every suggestion says WHY it was made. Only techniques that
really exist in ATT&CK can be returned, so IDs are never invented.
"""
import re
from functools import lru_cache

from app.intel.http import cached_json
from app.retrieval.bm25 import BM25

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def _ext_id(obj: dict) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def _clean(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")       # remove "(Citation: Some Report 2021)"
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)        # [link text](url) -> link text
    return re.sub(r"\s+", " ", text).strip()


def _active(o: dict) -> bool:
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def parse_bundle(bundle: dict) -> dict:
    """STIX bundle -> {"techniques": {...}, "mitigations": {...}}."""
    objects = bundle.get("objects", [])
    tactic_names = {o.get("x_mitre_shortname"): o.get("name") for o in objects if o.get("type") == "x-mitre-tactic"}
    techniques, mitigations, stix_to_tid, stix_to_mid = {}, {}, {}, {}

    for o in objects:
        if not _active(o):
            continue
        if o.get("type") == "attack-pattern":
            tid, url = _ext_id(o)
            if not tid:
                continue
            stix_to_tid[o["id"]] = tid
            techniques[tid] = {
                "technique_id": tid,
                "name": o.get("name"),
                "tactics": [tactic_names.get(p["phase_name"], p["phase_name"]) for p in o.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"],
                "platforms": o.get("x_mitre_platforms", []),
                "description": _clean(o.get("description", "")),
                "detection": _clean(o.get("x_mitre_detection", "")),
                "url": url,
                "mitigations": [],
            }
        elif o.get("type") == "course-of-action":
            mid, url = _ext_id(o)
            if mid and mid.startswith("M"):
                stix_to_mid[o["id"]] = mid
                mitigations[mid] = {"mitigation_id": mid, "name": o.get("name"), "url": url}

    for o in objects:  # second pass: link mitigations to techniques
        if o.get("type") == "relationship" and o.get("relationship_type") == "mitigates" and _active(o):
            mid, tid = stix_to_mid.get(o.get("source_ref")), stix_to_tid.get(o.get("target_ref"))
            if mid and tid in techniques:
                techniques[tid]["mitigations"].append({**mitigations[mid], "how": _clean(o.get("description", ""))[:400]})

    return {"techniques": techniques, "mitigations": mitigations}


class AttackKB:
    def __init__(self, parsed: dict):
        self.techniques = parsed["techniques"]
        self._search = BM25([
            {"chunk_id": tid, "text": f"{t['name']} {t['name']} {' '.join(t['tactics'])} {t['description'][:1500]}"}
            for tid, t in self.techniques.items()
        ])

    def get(self, technique_id: str) -> dict | None:
        return self.techniques.get(technique_id.upper())

    def search(self, text: str, limit: int = 10) -> list[dict]:
        return [{**self.techniques[r["chunk_id"]], "match_score": r["bm25_score"]} for r in self._search.search(text, limit)]


@lru_cache(maxsize=1)
def get_kb() -> AttackKB:
    """Downloads ATT&CK on first use (tens of MB, can take a minute), then reuses the cached file."""
    return AttackKB(parse_bundle(cached_json(ATTACK_URL, "enterprise-attack.json", max_age_hours=24 * 7)))


# ----------------------------------------------------------------- CVE -> ATT&CK
# (CWE weakness types, technique, why). CWE = Common Weakness Enumeration.
CWE_RULES = [
    ({"CWE-78", "CWE-77", "CWE-94", "CWE-95", "CWE-917", "CWE-502"}, "T1059",
     "command/code injection or unsafe deserialization usually lets attackers run commands"),
    ({"CWE-434"}, "T1505.003", "unrestricted file upload is a common way to plant a web shell"),
    ({"CWE-269", "CWE-250", "CWE-266"}, "T1068", "improper privilege management can be used to escalate privileges"),
]


def suggest_for_cve(cve: dict, kb: AttackKB, keyword_limit: int = 3) -> list[dict]:
    """Suggest ATT&CK techniques for a parsed NVD CVE. Every suggestion includes its reason."""
    vector = ((cve.get("cvss") or {}).get("vector") or "").upper()
    cwes = set(cve.get("cwes") or [])
    desc = cve.get("description") or ""
    picks: list[tuple[str, str, str]] = []  # (technique_id, reason, basis)

    user_interaction = any(f"UI:{x}" in vector for x in ("R", "A", "P"))
    if "AV:N" in vector and not user_interaction:
        picks.append(("T1190", "exploitable over the network without user interaction (CVSS AV:N)", "rule"))
    if user_interaction:
        picks.append(("T1203", "exploitation needs a user to open or click something (CVSS UI)", "rule"))
    if "AV:L" in vector and "privilege" in desc.lower():
        picks.append(("T1068", "local vulnerability described as privilege escalation", "rule"))
    if re.search(r"web ?shell", desc, re.IGNORECASE):
        picks.append(("T1505.003", "description mentions a web shell", "rule"))
    for rule_cwes, tid, why in CWE_RULES:
        hit = cwes & rule_cwes
        if hit:
            picks.append((tid, f"{', '.join(sorted(hit))}: {why}", "rule"))
    for t in kb.search(desc, limit=keyword_limit + 5):
        picks.append((t["technique_id"], "keyword match with the CVE description", "keyword"))

    out, seen, keyword_count = [], set(), 0
    for tid, reason, basis in picks:
        tech = kb.get(tid)
        if not tech or tid in seen:  # only techniques that really exist in ATT&CK
            continue
        if basis == "keyword":
            if keyword_count >= keyword_limit:
                continue
            keyword_count += 1
        seen.add(tid)
        out.append({"technique_id": tid, "name": tech["name"], "tactics": tech["tactics"], "basis": basis,
                    "reason": reason, "url": tech["url"], "mitigations": tech["mitigations"][:4]})
    return out
