"""Day 5 unit tests for the investigation agent.

All outside services are replaced with fakes through nodes.TOOLS, so these
tests need no Qdrant, internet or Gemini.   Run from backend/:  python -m pytest -v
"""
import pytest

from app.agent import nodes
from app.agent.report import render_markdown
from app.intel.attack import AttackKB, parse_bundle


# ---------------------------------------------------------------- fakes
def _tech(stix_id, tid, name, tactic):
    return {"type": "attack-pattern", "id": stix_id, "name": name, "description": f"{name} description.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
            "external_references": [{"source_name": "mitre-attack", "external_id": tid, "url": f"https://attack.mitre.org/{tid}"}]}


KB = AttackKB(parse_bundle({"objects": [
    {"type": "x-mitre-tactic", "x_mitre_shortname": "initial-access", "name": "Initial Access"},
    {"type": "x-mitre-tactic", "x_mitre_shortname": "persistence", "name": "Persistence"},
    _tech("a1", "T1190", "Exploit Public-Facing Application", "initial-access"),
    _tech("a2", "T1505.003", "Web Shell", "persistence"),
    _tech("a3", "T1059", "Command and Scripting Interpreter", "execution"),
    {"type": "course-of-action", "id": "m1", "name": "Update Software",
     "external_references": [{"source_name": "mitre-attack", "external_id": "M1051"}]},
    {"type": "relationship", "relationship_type": "mitigates", "source_ref": "m1", "target_ref": "a1", "description": "Patch."},
]}))

CARD = {
    "cve_id": "CVE-2023-34362", "errors": [],
    "nvd": {"description": "SQL injection in MOVEit Transfer.", "cvss": {"score": 9.8, "severity": "CRITICAL"},
            "cwes": ["CWE-89"], "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34362"},
    "kev": {"date_added": "2023-06-02", "ransomware_use": "Known", "required_action": "Apply updates per vendor instructions."},
    "epss": {"probability": 0.81, "percentile": 0.997},
    "priority": {"level": "critical", "reasons": ["in CISA KEV", "CVSS 9.8"]},
    "attack": [{"technique_id": "T1190", "reason": "exploitable over the network (CVSS AV:N)"}],
}

EVIDENCE = [{"source": "moveit-transfer-advisory.md",
             "text": "Deployment of a web shell, LEMURLOOT. ATT&CK mapping: T1190, T1505.003 Server Software Component: Web Shell"}]


class Msg:
    def __init__(self, content):
        self.content = content


def fake_llm(prompt, schema=None, purpose="answer"):
    if schema is nodes.AttackSelection:
        return schema(techniques=[
            {"technique_id": "T1505.003", "confidence": "high", "rationale": "E1 describes the LEMURLOOT web shell."},
            {"technique_id": "T1190", "confidence": "high", "rationale": "Network-exploitable SQL injection."},
            {"technique_id": "T9999", "confidence": "low", "rationale": "Invented by the model."},  # must be dropped
        ]), "fake-model"
    if schema is nodes.RecommendationPlan:
        return schema(recommendations=[
            {"action": "Patch MOVEit Transfer now", "category": "patch", "priority": "immediate", "basis": ["CVE-2023-34362", "KEV"]},
            {"action": "Hunt for human2.aspx", "category": "hunt", "priority": "immediate", "basis": ["E1", "T1505.003"]},
            {"action": "Something unsupported", "category": "harden", "priority": "long-term", "basis": ["M9999"]},  # dropped
        ]), "fake-model"
    return Msg("Critical MOVEit exposure; patch immediately and hunt for web shells."), "fake-model"


def failing_llm(*args, **kwargs):
    raise RuntimeError("503 UNAVAILABLE")


@pytest.fixture(autouse=True)
def fake_tools():
    nodes.TOOLS.clear()
    nodes.TOOLS.update({
        "cve_intel": lambda cve_id: CARD,
        "search": lambda query, top_k=6: {"results": EVIDENCE},
        "attack_kb": lambda: KB,
        "call_llm": fake_llm,
    })
    yield
    nodes.TOOLS.clear()


def run_all(query: str) -> dict:
    """Run the nodes in graph order without LangGraph, merging state the same way it does."""
    state = {"query": query, "steps": [], "errors": []}

    def apply(update):
        for k, v in update.items():
            state[k] = state[k] + v if k in ("steps", "errors") else v

    apply(nodes.extract_entities(state))
    if nodes.route_after_entities(state) == "enrich_cves":
        apply(nodes.enrich_cves(state))
    for node in (nodes.retrieve_evidence, nodes.map_attack, nodes.recommend, nodes.write_report):
        apply(node(state))
    return state


# ---------------------------------------------------------------- tests
def test_extract_entities_and_routing():
    s = nodes.extract_entities({"query": "Investigate cve-2023-34362 and T1505.003 activity"})
    assert s["cve_ids"] == ["CVE-2023-34362"] and s["technique_ids"] == ["T1505.003"]
    assert nodes.route_after_entities(s) == "enrich_cves"
    assert nodes.route_after_entities({"cve_ids": []}) == "retrieve_evidence"


def test_candidates_include_technique_mentioned_in_documents():
    state = {"query": "Investigate MOVEit", "evidence": [{"ref": "E1", **EVIDENCE[0]}], "cve_cards": [CARD]}
    whys = {c["technique_id"]: c["why"] for c in nodes.build_candidates(state, KB)}
    assert "T1505.003" in whys and "evidence E1" in whys["T1505.003"]   # found from our advisory
    assert "T1190" in whys


def test_full_investigation_validates_llm_output():
    s = run_all("Investigate CVE-2023-34362 and recommend detections")
    ids = [m["technique_id"] for m in s["attack_mapping"]]
    assert ids == ["T1505.003", "T1190"]                              # invented T9999 discarded
    assert any("not candidates" in e for e in s["errors"])
    assert [r["action"] for r in s["recommendations"]] == ["Patch MOVEit Transfer now", "Hunt for human2.aspx"]
    assert s["risk"]["level"] == "critical" and s["risk"]["driver"] == "CVE-2023-34362"
    assert [st["node"] for st in s["steps"]] == ["extract_entities", "enrich_cves", "retrieve_evidence",
                                                  "map_attack", "recommend", "write_report"]
    report = s["report_markdown"]
    assert "**Overall risk:** CRITICAL" in report and "| [CVE-2023-34362]" in report and "9.8" in report
    assert "T1505.003" in report and "Hunt for human2.aspx" in report


def test_question_without_cve_skips_live_intel():
    s = run_all("How do attackers deploy web shells on file transfer servers?")
    assert "enrich_cves" not in [st["node"] for st in s["steps"]]
    assert s["risk"]["level"] == "unknown"


def test_agent_still_produces_report_when_llm_is_down():
    nodes.TOOLS["call_llm"] = failing_llm
    s = run_all("Investigate CVE-2023-34362")
    assert s["attack_mapping"]                                         # rule-based fallback mapping
    assert all("keyword" not in m["candidate_reason"] for m in s["attack_mapping"])
    assert s["recommendations"][0]["basis"] == ["CVE-2023-34362", "KEV"]  # fallback from KEV
    assert "Executive summary unavailable" in s["report_markdown"]
    assert len(s["errors"]) >= 3


def test_report_renders_with_missing_data():
    md = render_markdown({"query": "anything", "steps": [], "errors": ["Document search failed"]})
    assert "# CyberIntel AI — Investigation Report" in md and "Document search failed" in md


def test_langgraph_graph_runs_end_to_end():
    pytest.importorskip("langgraph")
    from app.agent.graph import build_graph

    final = build_graph().invoke({"query": "Investigate CVE-2023-34362", "steps": [], "errors": []})
    assert [m["technique_id"] for m in final["attack_mapping"]] == ["T1505.003", "T1190"]
    assert final["report_markdown"].startswith("# CyberIntel AI")


# ---------------------------------------------------------------- Day 5 fix: circuit breaker
def test_busy_model_is_skipped_on_the_next_call(monkeypatch):
    from tests.test_intel import stub_gemini_library_if_missing
    stub_gemini_library_if_missing()
    from app import llm

    calls = []

    class FakeModel:
        def __init__(self, name):
            self.name = name

        def with_structured_output(self, schema):
            return self

        def invoke(self, prompt):
            calls.append(self.name)
            if self.name == "main":
                raise RuntimeError("503 UNAVAILABLE high demand")
            return f"answer from {self.name}"

    monkeypatch.setattr(llm, "get_llm", lambda model: FakeModel(model))
    monkeypatch.setattr(llm, "_model_chain", lambda first: ["main", "lite"])
    llm._busy_until.clear()

    assert llm.call_llm("q1") == ("answer from lite", "lite")
    assert calls == ["main", "lite"]                  # first call: main fails, falls back
    calls.clear()
    assert llm.call_llm("q2") == ("answer from lite", "lite")
    assert calls == ["lite"]                          # second call: busy main skipped entirely
    llm._busy_until.clear()
