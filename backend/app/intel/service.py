"""Combines all four sources into one "intel card" per CVE.

    NVD   -> what it is, how severe (CVSS), weakness type (CWE), affected products
    KEV   -> is it being exploited right now? what does CISA require?
    EPSS  -> how likely is exploitation in the next 30 days?
    ATT&CK-> which attacker techniques it enables, and the official mitigations
    risk  -> a patch priority computed from the above by plain rules

Each source is fetched separately, so if one is down the others still work and
the failure is listed under "errors".
"""
from app.intel import attack, epss, kev, nvd
from app.intel.risk import cve_priority


def cve_intel(cve_id: str, include_attack: bool = True) -> dict:
    cve_id = cve_id.upper()
    card: dict = {"cve_id": cve_id, "errors": []}

    try:
        card["nvd"] = nvd.get_cve(cve_id)
        if card["nvd"] is None:
            card["errors"].append("Not found in NVD (check the CVE ID).")
    except Exception as e:
        card["nvd"] = None
        card["errors"].append(f"NVD lookup failed: {e}")

    try:
        card["kev"] = kev.lookup(cve_id)
    except Exception as e:
        card["kev"] = None
        card["errors"].append(f"KEV lookup failed: {e}")

    try:
        card["epss"] = epss.get_epss([cve_id]).get(cve_id)
    except Exception as e:
        card["epss"] = None
        card["errors"].append(f"EPSS lookup failed: {e}")

    cvss_score = ((card["nvd"] or {}).get("cvss") or {}).get("score")
    card["priority"] = cve_priority(cvss_score, card["kev"] is not None, (card["epss"] or {}).get("probability"))

    card["attack"] = []
    if include_attack and card["nvd"]:
        try:
            card["attack"] = attack.suggest_for_cve(card["nvd"], attack.get_kb())
        except Exception as e:
            card["errors"].append(f"ATT&CK mapping failed: {e}")
    return card


def card_as_text(card: dict) -> str:
    """A compact text version of the card, given to Gemini as an extra evidence passage."""
    n, k, e = card.get("nvd") or {}, card.get("kev"), card.get("epss")
    cvss = n.get("cvss") or {}
    lines = [f"Live threat intelligence for {card['cve_id']} (NVD, CISA KEV, FIRST EPSS):"]
    if n:
        lines.append(f"Description (NVD): {n.get('description')}")
        lines.append(f"CVSS {cvss.get('version')}: {cvss.get('score')} {cvss.get('severity')} ({cvss.get('vector')}). "
                     f"Weakness: {', '.join(n.get('cwes') or []) or 'not listed'}. Published {n.get('published')}.")
    else:
        lines.append("NVD: no record found.")
    if k:
        lines.append(f"CISA KEV: YES, added {k['date_added']}, ransomware use {k['ransomware_use']}. "
                     f"Required action: {k['required_action']}")
    else:
        lines.append("CISA KEV: not listed (no confirmed in-the-wild exploitation recorded by CISA).")
    if e:
        lines.append(f"EPSS: {e['probability']:.1%} probability of exploitation in the next 30 days "
                     f"(percentile {e['percentile']:.0%}).")
    lines.append(f"Patch priority: {card['priority']['level'].upper()}.")
    return "\n".join(lines)
