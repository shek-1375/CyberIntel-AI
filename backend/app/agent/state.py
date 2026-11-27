"""The shared state that flows through the investigation graph.

LangGraph passes one dictionary (the "state") from node to node. Each node
reads what it needs and returns ONLY the fields it changed; LangGraph merges
them in. Fields marked Annotated[list, operator.add] are APPENDED to instead
of replaced, which gives us an audit trail (`steps`) and an error log
(`errors`) built up by every node.
"""
import operator
from typing import Annotated, Any, TypedDict


class InvestigationState(TypedDict, total=False):
    # input
    query: str
    # 1. extract_entities
    cve_ids: list[str]
    technique_ids: list[str]
    # 2. enrich_cves  (live intel cards from app/intel/service.py)
    cve_cards: list[dict[str, Any]]
    # 3. retrieve_evidence  (chunks from our documents, labelled E1, E2, ...)
    evidence: list[dict[str, Any]]
    # 4. map_attack
    attack_candidates: list[dict[str, Any]]
    attack_mapping: list[dict[str, Any]]
    # 5. recommend
    risk: dict[str, Any]
    recommendations: list[dict[str, Any]]
    # 6. write_report
    summary: str
    report_markdown: str
    # audit trail, appended to by every node
    steps: Annotated[list[dict[str, Any]], operator.add]
    errors: Annotated[list[str], operator.add]
