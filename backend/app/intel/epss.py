"""EPSS: Exploit Prediction Scoring System (from FIRST.org).

CVSS says how BAD a vulnerability would be if exploited. EPSS estimates how
LIKELY it is to be exploited in the next 30 days (a probability from 0 to 1),
using data about real attack activity. Together:

    CVSS 9.8, EPSS 0.01  -> severe, but attackers aren't really using it
    CVSS 7.5, EPSS 0.95  -> less severe on paper, but being exploited a lot

    GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2023-34362
"""
from functools import lru_cache

from app.intel.http import get_json

EPSS_URL = "https://api.first.org/data/v1/epss"


def parse_epss(data: dict) -> dict[str, dict]:
    return {
        row["cve"].upper(): {"probability": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date")}
        for row in data.get("data", [])
    }


@lru_cache(maxsize=512)
def _fetch(ids: tuple[str, ...]) -> dict[str, dict]:
    return parse_epss(get_json(EPSS_URL, params={"cve": ",".join(ids)}))


def get_epss(cve_ids: list[str]) -> dict[str, dict]:
    ids = tuple(sorted({c.upper() for c in cve_ids}))
    return _fetch(ids) if ids else {}
