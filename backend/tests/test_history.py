"""Day 6 tests: saving and listing history, and the history API endpoints.

They use an in-memory SQLite database instead of PostgreSQL, so no database
server is needed (SQLAlchemy lets the same code run on both).
Run from backend/:  python -m pytest -v
"""
import pytest

pytest.importorskip("sqlalchemy")

from app import db  # noqa: E402

RESULT = {
    "query": "Investigate CVE-2023-34362",
    "risk": {"level": "critical", "driver": "CVE-2023-34362"},
    "summary": "Critical MOVEit exposure.",
    "cves": [{"cve_id": "CVE-2023-34362"}],
    "attack_mapping": [{"technique_id": "T1505.003"}],
    "report_markdown": "# CyberIntel AI — Investigation Report\n",
}


@pytest.fixture(autouse=True)
def fresh_database():
    db.use_database("sqlite://")
    db.Base.metadata.drop_all(db.engine)
    db.create_tables()
    yield


def test_save_list_get_delete_investigation():
    new_id = db.save_investigation(RESULT)
    rows = db.list_investigations()
    assert rows[0]["id"] == new_id and rows[0]["risk_level"] == "critical"
    assert rows[0]["cve_ids"] == ["CVE-2023-34362"]

    full = db.get_investigation(new_id)
    assert full["attack_mapping"][0]["technique_id"] == "T1505.003"   # the whole agent result is kept
    assert full["report_markdown"].startswith("# CyberIntel AI")

    assert db.delete_investigation(new_id) is True
    assert db.get_investigation(new_id) is None
    assert db.delete_investigation(new_id) is False


def test_newest_first_and_limit():
    for i in range(3):
        db.save_investigation({**RESULT, "query": f"query {i}"})
    rows = db.list_investigations(limit=2)
    assert [r["query"] for r in rows] == ["query 2", "query 1"]


def test_log_question_records_grounding():
    db.log_question("What is CVE-2024-3400?", {
        "answer": "CVSS 10.0 [1]", "answer_model": "gemini-3.5-flash-lite",
        "grounding": {"grounded": True, "refused": False}, "sources": [{"source": "live intel"}],
    })
    q = db.list_questions()[0]
    assert q["grounded"] is True and q["refused"] is False and q["answer_model"] == "gemini-3.5-flash-lite"


def test_database_status_ok():
    assert db.database_status() == "ok"


def test_api_saves_investigation_and_lists_it(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    import app.agent.graph as graph
    from app.main import app

    monkeypatch.setattr(graph, "run_investigation", lambda query: {**RESULT, "query": query})
    client = TestClient(app)

    saved = client.post("/investigate", json={"query": "Investigate CVE-2023-34362"}).json()
    assert saved["saved"] is True and saved["id"]

    listed = client.get("/investigations").json()
    assert listed[0]["id"] == saved["id"]

    report = client.get(f"/investigations/{saved['id']}/report.md")
    assert report.status_code == 200 and "Investigation Report" in report.text
    assert client.get("/investigations/99999").status_code == 404
