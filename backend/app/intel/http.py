"""Downloading threat-intel feeds, with a simple file cache.

Why cache? The KEV catalog and MITRE ATT&CK change at most daily, the ATT&CK
file is tens of MB, and NVD allows only 5 requests per 30 seconds without a key.
So each feed is downloaded once, saved under backend/data/intel/, and reused
until it is older than max_age_hours. If the internet is down, a stale copy is
used rather than failing.
"""
import json
import time
from pathlib import Path

from app.config import HTTP_TIMEOUT, INTEL_CACHE_DIR

USER_AGENT = "CyberIntel-AI/0.4 (educational project)"


def get_json(url: str, params: dict | None = None, headers: dict | None = None):
    import httpx

    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        r = client.get(url, params=params, headers={"User-Agent": USER_AGENT, **(headers or {})})
        r.raise_for_status()
        return r.json()


def cached_json(url: str, filename: str, max_age_hours: float, params: dict | None = None, headers: dict | None = None):
    path: Path = INTEL_CACHE_DIR / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600:
        return json.loads(path.read_text(encoding="utf-8"))
    try:
        data = get_json(url, params=params, headers=headers)
    except Exception:
        if path.exists():  # offline or rate-limited: a stale copy is better than nothing
            return json.loads(path.read_text(encoding="utf-8"))
        raise
    path.write_text(json.dumps(data), encoding="utf-8")
    return data
