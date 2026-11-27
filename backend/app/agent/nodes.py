"""The six steps (nodes) of an investigation.

Design rule: FACTS COME FROM TOOLS, LANGUAGE COMES FROM THE LLM.
  * CVE facts (CVSS, KEV, EPSS)   -> live intel (app/intel)
  * narrative evidence            -> our RAG documents (app/retrieval)
  * ATT&CK techniques             -> candidates built by code; Gemini only CHOOSES
                                     among them, and every choice is validated
  * patch priority                -> rules (app/intel/risk.py), never the LLM
  * the report tables             -> rendered by code (app/agent/report.py)
Gemini writes: the technique selection + rationale, the recommendations
(each must cite a basis), and the executive summary.

Every node catches its own errors, records them in state["errors"], and lets
the investigation continue, so one failing source never kills the report.

TOOLS: nodes call outside services through the TOOLS dictionary, so the unit
tests can swap in fakes (no Qdrant, internet or Gemini needed). This pattern
is called dependency injection.
"""
import json
import re
import time
from typing import Literal

from pydantic import BaseModel, Field

from app.agent.state import InvestigationState

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
MAX_CVES = 5
EVIDENCE_K = 6

TOOLS: dict = {}


def tool(name: str):
    """Return the real implementation unless a test has put a fake in TOOLS."""
    if name not in TOOLS:
        if name == "cve_intel":
            from app.intel.service import cve_intel as fn
        elif name == "search":
            from app.retrieval.retriever import search as fn
        elif name == "attack_kb":
            from app.intel.attack import get_kb as fn
        elif name == "call_llm":
            from app.llm import call_llm as fn
        else:
            raise KeyError(name)
        TOOLS[name] = fn
    return TOOLS[name]


def _step(node: str, started: float, **details) -> list[dict]:
    return [{"node": node, "ms": round((time.perf_counter() - started) * 1000), **details}]


# ======================================================================= 1
def extract_entities(state: InvestigationState) -> dict:
    """Find CVE and ATT&CK IDs in the question with regular expressions (no AI needed)."""
    t = time.perf_counter()
    q = state["query"]
    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(q)))[:MAX_CVES]
    techniques = list(dict.fromkeys(m.upper() for m in TECHNIQUE_RE.findall(q)))
    return {"cve_ids": cves, "technique_ids": techniques,
            "steps": _step("extract_entities", t, cves=cves, techniques=techniques)}


def route_after_entities(state: InvestigationState) -> Literal["enrich_cves", "retrieve_evidence"]:
    """Conditional edge: only call the live CVE sources when the question names a CVE."""
    return "enrich_cves" if state.get("cve_ids") else "retrieve_evidence"


# ======================================================================= 2
def enrich_cves(state: InvestigationState) -> dict:
    """Live intel card per CVE: NVD + CISA KEV + EPSS + priority + ATT&CK suggestions."""
    t = time.perf_counter()
    cards, errors = [], []
    for cve_id in state["cve_ids"]:
        try:
            card = tool("cve_intel")(cve_id)
            cards.append(card)
            errors += [f"{cve_id}: {e}" for e in card.get("errors", [])]
        except Exception as e:
            errors.append(f"{cve_id}: live intel failed: {e}")
    return {"cve_cards": cards, "errors": errors,
            "steps": _step("enrich_cves", t, cards=len(cards))}


# ======================================================================= 3
def retrieve_evidence(state: InvestigationState) -> dict:
    """Search our documents. The query is expanded with each CVE's NVD description,
    so reports that discuss a vulnerability without quoting its ID are still found."""
    t = time.perf_counter()
    extra = " ".join(((c.get("nvd") or {}).get("description") or "")[:300] for c in state.get("cve_cards", []))
    query = f"{state['query']} {extra}".strip()
    try:
        results = tool("search")(query, top_k=EVIDENCE_K)["results"]
    except Exception as e:
        return {"evidence": [], "errors": [f"Document search failed (is Qdrant running?): {e}"],
                "steps": _step("retrieve_evidence", t, passages=0)}
    evidence = [{"ref": f"E{i}", "source": r.get("source"), "text": r.get("text", "")}
                for i, r in enumerate(results, start=1)]
    return {"evidence": evidence, "steps": _step("retrieve_evidence", t, passages=len(evidence))}


# ======================================================================= 4
class TechniqueChoice(BaseModel):
    technique_id: str = Field(description="Must be one of the candidate IDs")
    confidence: Literal["high", "medium", "low"]
    rationale: str = Field(description="One sentence citing CVE facts or evidence refs like E2")


class AttackSelection(BaseModel):
    techniques: list[TechniqueChoice] = Field(description="The 3-6 best-supported techniques, best first")


MAP_PROMPT = """You map a security incident or vulnerability to MITRE ATT&CK for a SOC analyst.
Choose ONLY from the candidate techniques listed (never invent IDs). Pick the 3 to 6 that the
question, the CVE facts and the evidence actually support. Use "high" confidence only when the
evidence explicitly describes the behaviour; "low" when it is only plausible.

Question: {query}

CVE facts:
{cves}

Evidence from our documents:
{evidence}

Candidate techniques (id | name | tactics | why it is a candidate):
{candidates}
"""


def build_candidates(state: InvestigationState, kb) -> list[dict]:
    """Collect candidate techniques from four places, each labelled with where it came from."""
    found: dict[str, dict] = {}

    def add(tid: str, why: str):
        tech = kb.get(tid)
        if tech and tid not in found:  # only real ATT&CK techniques
            found[tid] = {"technique_id": tid, "name": tech["name"], "tactics": tech["tactics"], "why": why}

    for tid in state.get("technique_ids", []):
        add(tid, "named in the question")
    for ev in state.get("evidence", []):  # e.g. the MOVEit advisory lists T1505.003
        for tid in TECHNIQUE_RE.findall(ev["text"]):
            add(tid.upper(), f"mentioned in evidence {ev['ref']} ({ev['source']})")
    for card in state.get("cve_cards", []):
        for s in card.get("attack", []):
            add(s["technique_id"], f"{card['cve_id']}: {s['reason']}")
    search_text = state["query"] + " " + " ".join(ev["text"][:400] for ev in state.get("evidence", [])[:3])
    for tech in kb.search(search_text, limit=6):
        add(tech["technique_id"], "keyword match with the question and evidence")
    return list(found.values())[:20]


def map_attack(state: InvestigationState) -> dict:
    t = time.perf_counter()
    try:
        kb = tool("attack_kb")()
    except Exception as e:
        return {"attack_candidates": [], "attack_mapping": [], "errors": [f"ATT&CK data unavailable: {e}"],
                "steps": _step("map_attack", t, candidates=0, selected=0)}

    candidates = build_candidates(state, kb)
    if not candidates:
        return {"attack_candidates": [], "attack_mapping": [], "steps": _step("map_attack", t, candidates=0, selected=0)}
    by_id = {c["technique_id"]: c for c in candidates}
    errors = []
    try:
        selection, model = tool("call_llm")(
            MAP_PROMPT.format(
                query=state["query"],
                cves=cve_facts_text(state) or "None",
                evidence=evidence_text(state, 500) or "None",
                candidates="\n".join(f"- {c['technique_id']} | {c['name']} | {', '.join(c['tactics'])} | {c['why']}"
                                     for c in candidates),
            ),
            schema=AttackSelection,
        )
        valid = [c for c in selection.techniques if c.technique_id.upper() in by_id]  # VALIDATION
        dropped = len(selection.techniques) - len(valid)
        if dropped:
            errors.append(f"Discarded {dropped} technique(s) the model chose that were not candidates.")
        choices = [(c.technique_id.upper(), c.confidence, c.rationale) for c in valid]
        method = f"selected by {model} from {len(candidates)} candidates"
    except Exception as e:
        errors.append(f"LLM technique selection failed, using rule-based candidates only: {str(e)[:120]}")
        choices = [(c["technique_id"], "medium", c["why"]) for c in candidates if "keyword" not in c["why"]][:5]
        method = "rule-based fallback (no LLM)"

    mapping = []
    for tid, confidence, rationale in choices:
        tech = kb.get(tid)
        mapping.append({
            "technique_id": tid, "name": tech["name"], "tactics": tech["tactics"], "url": tech.get("url"),
            "confidence": confidence, "rationale": rationale, "candidate_reason": by_id[tid]["why"],
            "mitigations": [{k: m.get(k) for k in ("mitigation_id", "name")} for m in tech.get("mitigations", [])[:4]],
        })
    return {"attack_candidates": candidates, "attack_mapping": mapping, "errors": errors,
            "steps": _step("map_attack", t, candidates=len(candidates), selected=len(mapping), method=method)}


# ======================================================================= 5
class Recommendation(BaseModel):
    action: str = Field(description="A specific, actionable step")
    category: Literal["patch", "mitigate", "detect", "hunt", "harden", "respond"]
    priority: Literal["immediate", "short-term", "long-term"]
    basis: list[str] = Field(description="References that justify it: CVE IDs, 'KEV', mitigation IDs (Mxxxx), technique IDs (Txxxx) or evidence refs (E1, E2...)")


class RecommendationPlan(BaseModel):
    recommendations: list[Recommendation]


REC_PROMPT = """You are writing remediation guidance for a security team.
Use ONLY the facts below. Every recommendation must cite at least one basis reference from the
allowed list. Cover, where relevant: patching, compensating controls, detection ideas and
threat hunting. Return 5 to 8 recommendations, most urgent first.

Question: {query}
Overall risk: {risk}

CVE facts:
{cves}

ATT&CK techniques and their official mitigations:
{attack}

Evidence:
{evidence}

Allowed basis references: {allowed}
"""

PRIORITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def overall_risk(cards: list[dict]) -> dict:
    """The worst CVE priority decides the overall risk (computed by rules, not the LLM)."""
    if not cards:
        return {"level": "unknown", "driver": None, "reasons": ["No CVE named; assessment based on document evidence only."]}
    worst = max(cards, key=lambda c: PRIORITY_ORDER.get(c["priority"]["level"], 0))
    return {"level": worst["priority"]["level"], "driver": worst["cve_id"], "reasons": worst["priority"]["reasons"]}


def allowed_basis(state: InvestigationState) -> set[str]:
    refs = {"KEV"} | {c["cve_id"] for c in state.get("cve_cards", [])}
    refs |= {e["ref"] for e in state.get("evidence", [])}
    for m in state.get("attack_mapping", []):
        refs.add(m["technique_id"])
        refs |= {x["mitigation_id"] for x in m["mitigations"]}
    return refs


def recommend(state: InvestigationState) -> dict:
    t = time.perf_counter()
    risk = overall_risk(state.get("cve_cards", []))
    allowed = allowed_basis(state)
    attack_text = "\n".join(
        f"- {m['technique_id']} {m['name']}: " + "; ".join(f"{x['mitigation_id']} {x['name']}" for x in m["mitigations"])
        for m in state.get("attack_mapping", [])
    )
    errors, recs = [], []
    try:
        plan, _ = tool("call_llm")(
            REC_PROMPT.format(query=state["query"], risk=json.dumps(risk), cves=cve_facts_text(state) or "None",
                              attack=attack_text or "None", evidence=evidence_text(state, 400) or "None",
                              allowed=", ".join(sorted(allowed))),
            schema=RecommendationPlan,
        )
        for r in plan.recommendations:
            basis = [b for b in r.basis if b.upper() in {a.upper() for a in allowed}]  # VALIDATION
            if basis:
                recs.append({**r.model_dump(), "basis": basis})
        if len(recs) < len(plan.recommendations):
            errors.append(f"Dropped {len(plan.recommendations) - len(recs)} recommendation(s) with no valid basis.")
    except Exception as e:
        errors.append(f"LLM recommendations failed, using rule-based ones: {str(e)[:120]}")

    if not recs:  # deterministic fallback, straight from KEV and ATT&CK
        for c in state.get("cve_cards", []):
            if c.get("kev"):
                recs.append({"action": c["kev"]["required_action"], "category": "patch", "priority": "immediate", "basis": [c["cve_id"], "KEV"]})
        for m in state.get("attack_mapping", []):
            for x in m["mitigations"][:2]:
                recs.append({"action": x["name"], "category": "mitigate", "priority": "short-term", "basis": [x["mitigation_id"], m["technique_id"]]})
    return {"risk": risk, "recommendations": recs, "errors": errors,
            "steps": _step("recommend", t, recommendations=len(recs))}


# ======================================================================= 6
SUMMARY_PROMPT = """Write a 4-6 sentence executive summary of this security investigation for a manager.
Use only the facts in the JSON. Do not add numbers, versions, names or IDs that are not in it.
State the overall risk level and the two or three most urgent actions.

{facts}
"""


def write_report(state: InvestigationState) -> dict:
    from app.agent.report import render_markdown

    t = time.perf_counter()
    facts = {
        "question": state["query"],
        "overall_risk": state.get("risk"),
        "cves": [{"cve_id": c["cve_id"], "cvss": ((c.get("nvd") or {}).get("cvss") or {}).get("score"),
                  "in_kev": bool(c.get("kev")), "epss": (c.get("epss") or {}).get("probability"),
                  "priority": c["priority"]["level"]} for c in state.get("cve_cards", [])],
        "attack_techniques": [f"{m['technique_id']} {m['name']}" for m in state.get("attack_mapping", [])],
        "top_recommendations": [r["action"] for r in state.get("recommendations", [])[:4]],
    }
    errors = []
    try:
        message, _ = tool("call_llm")(SUMMARY_PROMPT.format(facts=json.dumps(facts, indent=1)))
        summary = message.content if hasattr(message, "content") else str(message)
        if isinstance(summary, list):
            summary = "".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in summary)
    except Exception as e:
        summary = "Executive summary unavailable (the language model could not be reached). See the findings below."
        errors.append(f"Summary generation failed: {str(e)[:120]}")

    report = render_markdown({**state, "summary": summary, "errors": state.get("errors", []) + errors})
    return {"summary": summary, "report_markdown": report, "errors": errors, "steps": _step("write_report", t)}


# ======================================================================= helpers
def cve_facts_text(state: InvestigationState) -> str:
    lines = []
    for c in state.get("cve_cards", []):
        n, k, e = c.get("nvd") or {}, c.get("kev"), c.get("epss")
        cvss = n.get("cvss") or {}
        parts = [
            f"- {c['cve_id']}: {(n.get('description') or 'no NVD record')[:350]}",
            f"CVSS {cvss.get('score')} {cvss.get('severity')}",
            f"CWE {', '.join(n.get('cwes') or []) or 'n/a'}",
            f"KEV: yes, required action: {k['required_action']}" if k else "KEV: no",
            f"EPSS {e['probability']:.1%}" if e else "EPSS n/a",
            f"priority {c['priority']['level']}",
        ]
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def evidence_text(state: InvestigationState, max_chars: int) -> str:
    return "\n".join(f"[{e['ref']}] ({e['source']}) {e['text'][:max_chars]}" for e in state.get("evidence", []))
