"""Run an investigation from the terminal and save the report.

Run from backend/ with (venv) active, Qdrant running and documents ingested:

    python -m scripts.investigate "Investigate CVE-2023-34362 and recommend detections and mitigations"

The Markdown report is printed and saved to backend/reports/.
"""
import logging
import sys
from datetime import datetime
from pathlib import Path

from app.agent.graph import run_investigation

logging.basicConfig(level=logging.WARNING)
REPORTS_DIR = Path(__file__).resolve().parents[1] / "reports"


def main() -> None:
    query = " ".join(sys.argv[1:]) or "Investigate CVE-2023-34362 and recommend detections and mitigations"
    print(f"Investigating: {query}\n(this makes several Gemini calls; 10-60 seconds)\n")
    result = run_investigation(query)

    print("Steps:")
    for s in result["steps"]:
        details = ", ".join(f"{k}={v}" for k, v in s.items() if k not in ("node", "ms"))
        print(f"  {s['node']:<18} {s['ms']:>6} ms   {details}")
    if result["errors"]:
        print("\nNotes:")
        for e in result["errors"]:
            print(f"  - {e}")

    REPORTS_DIR.mkdir(exist_ok=True)
    path = REPORTS_DIR / f"investigation-{datetime.now():%Y%m%d-%H%M%S}.md"
    path.write_text(result["report_markdown"], encoding="utf-8")
    print(f"\nRisk: {(result['risk'] or {}).get('level', 'unknown').upper()}")
    print(f"Report saved to {path}")


if __name__ == "__main__":
    main()
