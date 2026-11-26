"""Patch priority, decided by plain code (no AI), so it is consistent and explainable.

Three signals:
  CVSS  how bad it would be                (0-10, from NVD)
  KEV   confirmed exploited in the wild    (yes/no, from CISA)
  EPSS  chance of exploitation in 30 days  (0-1, from FIRST)

Rules, checked top to bottom:
  critical  in KEV and CVSS >= 7                     (exploited now, and serious)
  high      in KEV, or CVSS >= 9, or EPSS >= 0.5
  medium    CVSS >= 7, or EPSS >= 0.1
  low       anything else with data
  unknown   no CVSS and no EPSS available
"""


def cve_priority(cvss: float | None, in_kev: bool, epss: float | None) -> dict:
    reasons = []
    if in_kev:
        reasons.append("in CISA KEV: confirmed exploited in the wild")
    if cvss is not None:
        reasons.append(f"CVSS {cvss}")
    if epss is not None:
        reasons.append(f"EPSS {epss:.1%} chance of exploitation in the next 30 days")

    c, e = cvss or 0, epss or 0
    if in_kev and c >= 7:
        level = "critical"
    elif in_kev or c >= 9 or e >= 0.5:
        level = "high"
    elif c >= 7 or e >= 0.1:
        level = "medium"
    elif cvss is None and epss is None:
        level = "unknown"
    else:
        level = "low"
    return {"level": level, "reasons": reasons}
