"""API endpoints for live threat intelligence (all under /intel in /docs)."""
import re

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.config import DOCUMENTS_DIR

router = APIRouter(prefix="/intel", tags=["threat intelligence"])

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


@router.get("/cve/{cve_id}")
def cve_card(cve_id: str):
    """Everything about one CVE: NVD details, CISA KEV status, EPSS probability,
    patch priority and suggested MITRE ATT&CK techniques with mitigations.
    The first call downloads ATT&CK (tens of MB) and can take a minute."""
    from app.intel.service import cve_intel

    if not CVE_ID.match(cve_id):
        raise HTTPException(400, "Use the format CVE-YYYY-NNNN, e.g. CVE-2021-44228")
    return cve_intel(cve_id)


@router.get("/kev")
def kev_list(search: str = Query("", description="Filter by vendor, product, CVE or words"), limit: int = Query(20, le=200)):
    """CISA Known Exploited Vulnerabilities, newest first."""
    from app.intel import kev

    return kev.search(search, limit) if search else kev.recent(limit)


@router.get("/attack/search")
def attack_search(q: str = Query(..., min_length=2, description="e.g. 'credential dumping' or 'web shell'"), limit: int = Query(5, le=20)):
    """Search MITRE ATT&CK techniques by keywords."""
    from app.intel.attack import get_kb

    return [
        {k: t[k] for k in ("technique_id", "name", "tactics", "url", "match_score")} | {"description": t["description"][:300]}
        for t in get_kb().search(q, limit)
    ]


@router.get("/attack/{technique_id}")
def attack_technique(technique_id: str):
    """One ATT&CK technique with its tactics, description, detection notes and mitigations."""
    from app.intel.attack import get_kb

    if not TECHNIQUE_ID.match(technique_id):
        raise HTTPException(400, "Use the format T1234 or T1234.001")
    tech = get_kb().get(technique_id)
    if not tech:
        raise HTTPException(404, f"{technique_id} is not an active ATT&CK technique")
    return tech


class IngestKevRequest(BaseModel):
    limit: int = Field(100, ge=10, le=1500, description="How many of the newest KEV entries to index")


@router.post("/kev/ingest")
def ingest_kev(req: IngestKevRequest):
    """Save the newest KEV entries as a document (data/documents/cisa-kev-recent.md)
    and re-index everything, so /ask can answer questions about recent exploited CVEs."""
    from app.ingestion.chunker import chunk_documents
    from app.ingestion.loader import load_directory
    from app.intel import kev
    from app.retrieval import retriever

    entries = kev.recent(req.limit)
    (DOCUMENTS_DIR / "cisa-kev-recent.md").write_text(kev.as_markdown(entries), encoding="utf-8")
    docs = load_directory(DOCUMENTS_DIR)
    stored = retriever.index_chunks(chunk_documents(docs))
    return {"kev_entries_written": len(entries), "newest": entries[0]["date_added"] if entries else None,
            "files": sorted({d.metadata["source"] for d in docs}), "chunks_stored": stored}
