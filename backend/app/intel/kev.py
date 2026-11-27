"""CISA KEV: the Known Exploited Vulnerabilities catalog.

CISA (the US Cybersecurity and Infrastructure Security Agency) lists CVEs that
are CONFIRMED to be exploited by real attackers. There are hundreds of
thousands of CVEs but only around a thousand are in KEV, so "is it in KEV?"
is the single most useful question when deciding what to patch first.

The whole catalog is one JSON file (about 1 MB). We download it once and
refresh it every 24 hours.
"""
from app.intel.http import cached_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_kev() -> list[dict]:
    return cached_json(KEV_URL, "kev.json", max_age_hours=24).get("vulnerabilities", [])


def parse_entry(v: dict) -> dict:
    return {
        "cve_id": v.get("cveID"),
        "vendor": v.get("vendorProject"),
        "product": v.get("product"),
        "name": v.get("vulnerabilityName"),
        "date_added": v.get("dateAdded"),
        "due_date": v.get("dueDate"),
        "ransomware_use": v.get("knownRansomwareCampaignUse"),  # "Known" or "Unknown"
        "description": v.get("shortDescription"),
        "required_action": v.get("requiredAction"),
    }


def lookup(cve_id: str, entries: list[dict] | None = None) -> dict | None:
    cve_id = cve_id.upper()
    for v in entries if entries is not None else load_kev():
        if v.get("cveID", "").upper() == cve_id:
            return parse_entry(v)
    return None


def recent(limit: int = 20, entries: list[dict] | None = None) -> list[dict]:
    rows = sorted(entries if entries is not None else load_kev(), key=lambda v: v.get("dateAdded", ""), reverse=True)
    return [parse_entry(v) for v in rows[:limit]]


def search(term: str, limit: int = 20, entries: list[dict] | None = None) -> list[dict]:
    term = term.lower()
    out = []
    for v in sorted(entries if entries is not None else load_kev(), key=lambda v: v.get("dateAdded", ""), reverse=True):
        text = " ".join(str(v.get(k, "")) for k in ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription"))
        if term in text.lower():
            out.append(parse_entry(v))
            if len(out) >= limit:
                break
    return out


def as_markdown(entries: list[dict]) -> str:
    """Render KEV entries as a document, so the RAG index can answer questions about them.

    Every line repeats its CVE ID, and long fields are shortened so every line fits
    well inside one chunk. Then, if a long entry has to be split, the split happens
    between lines, and each piece still says which CVE it is about, so details from
    two different vulnerabilities can't get mixed up.
    """
    def short(text, limit):
        text = " ".join((text or "").split())
        return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + " ..."

    lines = ["# CISA Known Exploited Vulnerabilities (most recent entries)", ""]
    for e in entries:
        cve = e["cve_id"]
        lines += [
            f"## {cve}: {e['vendor']} {e['product']}",
            f"{cve} summary: {short(e['name'], 150)}. {short(e['description'], 550)}",
            f"{cve} status: added to KEV on {e['date_added']}; federal due date {e['due_date']}; "
            f"known ransomware use: {e['ransomware_use']}.",
            f"{cve} required action: {short(e['required_action'], 400)}",
            "",
        ]
    return "\n".join(lines)
