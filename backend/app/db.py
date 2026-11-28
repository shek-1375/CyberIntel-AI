"""PostgreSQL storage for investigation history and question logs.

Why a normal (relational) database as well as Qdrant? They store different things:
  Qdrant      document chunks as vectors, searched by meaning
  PostgreSQL  records we want to keep and list: every investigation and its report,
              every question asked and whether its answer was grounded

We use SQLAlchemy, Python's standard database toolkit. Classes below become
tables; create_tables() creates them on startup if they don't exist yet.

If the database is down, the app keeps working: saving is skipped and the API
response says so, the same graceful degradation we use for Gemini and NVD.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import DATABASE_URL

log = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    query: Mapped[str] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(String(20), default="unknown")
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    report_markdown: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JSON, default=dict)  # the full agent output


class QuestionLog(Base):
    __tablename__ = "question_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    question: Mapped[str] = mapped_column(Text)
    answer: Mapped[str] = mapped_column(Text)
    grounded: Mapped[bool] = mapped_column(Boolean, default=False)
    refused: Mapped[bool] = mapped_column(Boolean, default=False)
    answer_model: Mapped[str | None] = mapped_column(String(80), nullable=True)
    sources: Mapped[list] = mapped_column(JSON, default=list)


# ------------------------------------------------------------------ connection
def make_engine(url: str):
    if url.startswith("sqlite"):  # used by the unit tests: an in-memory database
        return create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    return create_engine(url, pool_pre_ping=True)


engine = make_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def use_database(url: str) -> None:
    """Point the app at a different database (the tests use an in-memory SQLite one)."""
    global engine
    engine = make_engine(url)
    SessionLocal.configure(bind=engine)


def create_tables() -> bool:
    try:
        Base.metadata.create_all(engine)
        return True
    except Exception as e:
        log.warning("Database unavailable, history will not be saved: %s", str(e).splitlines()[0])
        return False


def database_status() -> str:
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return "ok"
    except Exception as e:
        return f"error: {str(e).splitlines()[0][:120]}"


# ------------------------------------------------------------------ investigations
def save_investigation(result: dict) -> int:
    with SessionLocal() as s:
        row = Investigation(
            query=result["query"],
            risk_level=(result.get("risk") or {}).get("level", "unknown"),
            cve_ids=[c["cve_id"] for c in result.get("cves", [])],
            summary=result.get("summary") or "",
            report_markdown=result.get("report_markdown") or "",
            result=result,
        )
        s.add(row)
        s.commit()
        return row.id


def list_investigations(limit: int = 50) -> list[dict]:
    with SessionLocal() as s:
        rows = s.scalars(select(Investigation).order_by(Investigation.id.desc()).limit(limit)).all()
        return [
            {"id": r.id, "created_at": r.created_at.isoformat(), "query": r.query,
             "risk_level": r.risk_level, "cve_ids": r.cve_ids, "summary": r.summary[:300]}
            for r in rows
        ]


def get_investigation(investigation_id: int) -> dict | None:
    with SessionLocal() as s:
        r = s.get(Investigation, investigation_id)
        if r is None:
            return None
        return {"id": r.id, "created_at": r.created_at.isoformat(), **r.result}


def delete_investigation(investigation_id: int) -> bool:
    with SessionLocal() as s:
        r = s.get(Investigation, investigation_id)
        if r is None:
            return False
        s.delete(r)
        s.commit()
        return True


# ------------------------------------------------------------------ questions
def log_question(question: str, result: dict) -> int:
    g = result.get("grounding") or {}
    with SessionLocal() as s:
        row = QuestionLog(
            question=question,
            answer=result.get("answer", ""),
            grounded=bool(g.get("grounded")),
            refused=bool(g.get("refused")),
            answer_model=result.get("answer_model"),
            sources=[src.get("source") for src in result.get("sources", [])],
        )
        s.add(row)
        s.commit()
        return row.id


def list_questions(limit: int = 50) -> list[dict]:
    with SessionLocal() as s:
        rows = s.scalars(select(QuestionLog).order_by(QuestionLog.id.desc()).limit(limit)).all()
        return [
            {"id": r.id, "created_at": r.created_at.isoformat(), "question": r.question, "answer": r.answer[:300],
             "grounded": r.grounded, "refused": r.refused, "answer_model": r.answer_model}
            for r in rows
        ]
