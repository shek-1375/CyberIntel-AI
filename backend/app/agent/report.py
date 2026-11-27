"""Renders the investigation report as Markdown, using plain code.

Only the executive summary is written by the LLM. Every table below it is
filled directly from tool data, so scores, IDs and dates in the report are
exactly what NVD, CISA, FIRST and MITRE returned and can't be altered by the model.
"""
from datetime import datetime


def _cell(text) -> str:
    return str(text if text not in (None, "") else "—").replace("|", "/").replace("\n", " ")


def render_markdown(state: dict) -> str:
    risk = state.get("risk") or {"level": "unknown", "reasons": []}
    md = [
        "# CyberIntel AI — Investigation Report",
        "",
        f"**Question:** {state.get('query', '')}  ",
        f"**Generated:** {datetime.now():%Y-%m-%d %H:%M}  ",
        f"**Overall risk:** {risk['level'].upper()}" + (f" (driven by {risk['driver']})" if risk.get("driver") else ""),
        "",
        "## Executive summary",
        "",
        state.get("summary") or "—",
    ]

    cards = state.get("cve_cards") or []
    if cards:
        md += ["", "## Vulnerabilities (live data)", "",
               "| CVE | CVSS | Severity | CWE | CISA KEV | Ransomware | EPSS (30 days) | Priority |",
               "|---|---|---|---|---|---|---|---|"]
        for c in cards:
            n, k, e = c.get("nvd") or {}, c.get("kev"), c.get("epss")
            cvss = n.get("cvss") or {}
            kev_cell = f"Yes, {k['date_added']}" if k else "No"
            epss_cell = f"{e['probability']:.1%}" if e else "—"
            md.append(
                f"| [{c['cve_id']}]({n.get('nvd_url', '')}) | {_cell(cvss.get('score'))} | {_cell(cvss.get('severity'))} "
                f"| {_cell(', '.join(n.get('cwes') or []))} | {kev_cell} "
                f"| {_cell(k['ransomware_use'] if k else None)} | {epss_cell} "
                f"| **{c['priority']['level'].upper()}** |"
            )
        for c in cards:
            n = c.get("nvd") or {}
            md += ["", f"**{c['cve_id']}**: {n.get('description') or 'No NVD description available.'}"]
            if c.get("kev"):
                md.append(f"*CISA required action:* {c['kev']['required_action']}")

    mapping = state.get("attack_mapping") or []
    if mapping:
        md += ["", "## MITRE ATT&CK mapping", "",
               "| Technique | Name | Tactics | Confidence | Rationale |", "|---|---|---|---|---|"]
        for m in mapping:
            md.append(f"| [{m['technique_id']}]({m.get('url') or ''}) | {_cell(m['name'])} | {_cell(', '.join(m['tactics']))} "
                      f"| {m['confidence']} | {_cell(m['rationale'])} |")

    recs = state.get("recommendations") or []
    if recs:
        md += ["", "## Recommendations", ""]
        for i, r in enumerate(recs, start=1):
            md.append(f"{i}. **[{r['priority']} · {r['category']}]** {r['action']} *(basis: {', '.join(r['basis'])})*")

    evidence = state.get("evidence") or []
    if evidence:
        md += ["", "## Evidence used", ""]
        for e in evidence:
            snippet = " ".join(e["text"].split())[:200]
            md.append(f"- **{e['ref']}** `{e['source']}`: {snippet}…")

    steps = state.get("steps") or []
    if steps:
        md += ["", "## How this report was produced", "", "| Step | Time | Details |", "|---|---|---|"]
        for s in steps:
            details = ", ".join(f"{k}={v}" for k, v in s.items() if k not in ("node", "ms"))
            md.append(f"| {s['node']} | {s['ms']} ms | {_cell(details)} |")

    errors = state.get("errors") or []
    if errors:
        md += ["", "## Notes and limitations", ""] + [f"- {e}" for e in errors]
    return "\n".join(md) + "\n"
