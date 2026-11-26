"""NVD (National Vulnerability Database) CVE API 2.0.

The NVD is the US government's official database of CVEs. For each CVE it
gives the description, the CVSS severity score, the weakness type (CWE) and
the affected products. These are FACTS, so we fetch them instead of letting
the LLM remember them (it might remember wrong, or not know a new CVE at all).

    GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228

Rate limit: 5 requests / 30 s without a key, 50 with one (NVD_API_KEY in .env,
sent in the "apiKey" header). Results are cached for 24 hours.
"""
from app.config import NVD_API_KEY
from app.intel.http import cached_json

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _english(items: list[dict]) -> str:
    for d in items or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return (items or [{}])[0].get("value", "")


def _cvss(metrics: dict) -> dict | None:
    """Pick the newest CVSS version available, preferring NVD's own 'Primary' score."""
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if entries:
            m = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = m.get("cvssData", {})
            return {
                "version": version,
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or m.get("baseSeverity"),
                "vector": data.get("vectorString"),
            }
    return None


def parse_cve(cve: dict) -> dict:
    """Turn NVD's large, nested JSON into the fields an analyst needs."""
    cwes = sorted({
        d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })
    products = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    parts = m.get("criteria", "").split(":")  # cpe:2.3:a:apache:log4j:2.0:*...
                    if len(parts) > 4:
                        products.append(f"{parts[3]} {parts[4]}")
    return {
        "cve_id": cve.get("id"),
        "description": _english(cve.get("descriptions", [])),
        "published": (cve.get("published") or "")[:10],
        "last_modified": (cve.get("lastModified") or "")[:10],
        "status": cve.get("vulnStatus"),
        "cvss": _cvss(cve.get("metrics", {})),
        "cwes": cwes,
        "affected_products": sorted(set(products))[:15],
        # NVD lists the same URL once per source (e.g. NIST and the CNA), so remove duplicates
        "references": list(dict.fromkeys(r.get("url") for r in cve.get("references", []) if r.get("url")))[:8],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
    }


def get_cve(cve_id: str) -> dict | None:
    cve_id = cve_id.upper()
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else None
    data = cached_json(NVD_URL, f"nvd/{cve_id}.json", max_age_hours=24, params={"cveId": cve_id}, headers=headers)
    vulns = data.get("vulnerabilities", [])
    return parse_cve(vulns[0]["cve"]) if vulns else None
