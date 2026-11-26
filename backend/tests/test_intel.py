"""Day 4 unit tests: threat-intel parsing, risk scoring and CVE -> ATT&CK suggestions.

Uses small hand-made samples shaped like the real NVD / KEV / EPSS / ATT&CK data,
so no internet connection is needed.   Run from backend/:  python -m pytest -v
"""
from app.intel import attack, kev, nvd
from app.intel.epss import parse_epss
from app.intel.risk import cve_priority

# ---------------- samples shaped like the real feeds
NVD_SAMPLE = {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:09.143",
    "lastModified": "2025-02-04T15:15:13.773",
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "es", "value": "..."}, {"lang": "en", "value": "Apache Log4j2 JNDI features allow remote code execution."}],
    "metrics": {
        "cvssMetricV31": [
            {"source": "other", "type": "Secondary", "cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL", "vectorString": "X"}},
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
        ],
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 9.3}, "baseSeverity": "HIGH"}],
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-917"}, {"lang": "en", "value": "NVD-CWE-Other"}]}],
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
    ]}]}],
    "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"},
                   {"url": "https://logging.apache.org/log4j/2.x/security.html"}],  # duplicate on purpose
}

KEV_SAMPLE = [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Apache Log4j2 RCE",
     "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known",
     "shortDescription": "Log4j2 JNDI injection.", "requiredAction": "Apply updates per vendor instructions."},
    {"cveID": "CVE-2023-34362", "vendorProject": "Progress", "product": "MOVEit Transfer", "vulnerabilityName": "MOVEit SQL Injection",
     "dateAdded": "2023-06-02", "dueDate": "2023-06-23", "knownRansomwareCampaignUse": "Known",
     "shortDescription": "SQL injection.", "requiredAction": "Apply updates per vendor instructions."},
]

STIX_SAMPLE = {"objects": [
    {"type": "x-mitre-tactic", "x_mitre_shortname": "initial-access", "name": "Initial Access"},
    {"type": "x-mitre-tactic", "x_mitre_shortname": "execution", "name": "Execution"},
    {"type": "attack-pattern", "id": "ap--1", "name": "Exploit Public-Facing Application",
     "description": "Adversaries may exploit a weakness in an Internet-facing computer (Citation: Report 2020).",
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1190", "url": "https://attack.mitre.org/techniques/T1190"}]},
    {"type": "attack-pattern", "id": "ap--2", "name": "Command and Scripting Interpreter",
     "description": "Adversaries may abuse command and script interpreters to execute commands.",
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]},
    {"type": "attack-pattern", "id": "ap--old", "name": "Old technique", "revoked": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
    {"type": "course-of-action", "id": "coa--1", "name": "Update Software",
     "external_references": [{"source_name": "mitre-attack", "external_id": "M1051"}]},
    {"type": "relationship", "relationship_type": "mitigates", "source_ref": "coa--1", "target_ref": "ap--1",
     "description": "Patch internet-facing systems."},
]}


# ---------------- NVD
def test_nvd_parse_prefers_primary_newest_cvss():
    c = nvd.parse_cve(NVD_SAMPLE)
    assert c["cvss"] == {"version": "3.1", "score": 10.0, "severity": "CRITICAL",
                         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
    assert c["description"].startswith("Apache Log4j2")       # English description chosen
    assert c["cwes"] == ["CWE-917"]                            # "NVD-CWE-Other" dropped
    assert c["affected_products"] == ["apache log4j"]          # non-vulnerable entries ignored
    assert c["published"] == "2021-12-10"
    assert c["references"] == ["https://logging.apache.org/log4j/2.x/security.html"]  # duplicates removed


# ---------------- KEV
def test_kev_lookup_and_recent():
    assert kev.lookup("cve-2021-44228", KEV_SAMPLE)["ransomware_use"] == "Known"
    assert kev.lookup("CVE-2000-0001", KEV_SAMPLE) is None
    assert kev.recent(1, KEV_SAMPLE)[0]["cve_id"] == "CVE-2023-34362"  # newest first
    assert kev.search("moveit", entries=KEV_SAMPLE)[0]["product"] == "MOVEit Transfer"


def test_kev_markdown_document():
    md = kev.as_markdown(kev.recent(2, KEV_SAMPLE))
    assert md.startswith("# CISA Known Exploited Vulnerabilities")
    assert "## CVE-2021-44228: Apache Log4j2" in md


# ---------------- EPSS
def test_epss_parse():
    data = {"data": [{"cve": "CVE-2021-44228", "epss": "0.944", "percentile": "0.999", "date": "2026-11-26"}]}
    assert parse_epss(data)["CVE-2021-44228"]["probability"] == 0.944


# ---------------- risk
def test_priority_rules():
    assert cve_priority(10.0, True, 0.94)["level"] == "critical"
    assert cve_priority(5.0, True, None)["level"] == "high"      # in KEV but low CVSS
    assert cve_priority(9.8, False, 0.01)["level"] == "high"     # very severe on paper
    assert cve_priority(7.5, False, 0.02)["level"] == "medium"
    assert cve_priority(4.3, False, 0.001)["level"] == "low"
    assert cve_priority(None, False, None)["level"] == "unknown"
    assert "in CISA KEV" in cve_priority(10.0, True, None)["reasons"][0]


# ---------------- ATT&CK
def test_stix_parse_and_mitigation_links():
    parsed = attack.parse_bundle(STIX_SAMPLE)
    t = parsed["techniques"]
    assert set(t) == {"T1190", "T1059"}                          # revoked technique skipped
    assert t["T1190"]["tactics"] == ["Initial Access"]           # short name -> full tactic name
    assert "Citation" not in t["T1190"]["description"]
    assert t["T1190"]["mitigations"][0]["mitigation_id"] == "M1051"


def test_cve_to_attack_suggestions_have_reasons_and_real_ids():
    kb = attack.AttackKB(attack.parse_bundle(STIX_SAMPLE))
    sugg = attack.suggest_for_cve(nvd.parse_cve(NVD_SAMPLE), kb)
    ids = [s["technique_id"] for s in sugg]
    assert ids[0] == "T1190"                                     # network-exploitable, no user interaction
    assert "T1059" in ids                                        # CWE-917 is an injection weakness
    assert all(s["reason"] for s in sugg)
    assert all(kb.get(i) for i in ids)                           # never an invented ID


def test_user_interaction_suggests_client_execution_only_if_known():
    kb = attack.AttackKB(attack.parse_bundle(STIX_SAMPLE))
    cve = {"description": "A crafted document", "cwes": [], "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}}
    ids = [s["technique_id"] for s in attack.suggest_for_cve(cve, kb)]
    assert "T1190" not in ids          # needs user interaction, so not "exploit public-facing app"
    assert "T1203" not in ids          # T1203 isn't in this small sample KB, so it can't be suggested


# ---------------- Day 4 fix: embedding rate limits
def test_rate_limit_detection_and_retry_delay():
    import sys, types
    sys.modules.setdefault("langchain_google_genai", types.SimpleNamespace(GoogleGenerativeAIEmbeddings=object))
    from app.embeddings.embedder import is_rate_limit, retry_delay
    err = Exception("429 RESOURCE_EXHAUSTED ... Please retry in 4.624848916s.")
    assert is_rate_limit(err)
    assert round(retry_delay(err), 1) == 6.6          # Google's delay + 2 s margin
    assert retry_delay(Exception("429 no hint")) == 30.0
    assert not is_rate_limit(Exception("400 API key not valid"))


def test_embed_texts_waits_and_retries_on_429(monkeypatch):
    import sys, types
    sys.modules.setdefault("langchain_google_genai", types.SimpleNamespace(GoogleGenerativeAIEmbeddings=object))
    from app.embeddings import embedder

    calls = {"n": 0}

    class FakeEmbedder:
        def embed_documents(self, batch):
            calls["n"] += 1
            if calls["n"] == 2:  # second request hits the rate limit once
                raise Exception("429 RESOURCE_EXHAUSTED Please retry in 0.1s")
            return [[float(len(t))] for t in batch]

    slept = []
    monkeypatch.setattr(embedder, "get_embedder", lambda: FakeEmbedder())
    monkeypatch.setattr(embedder.time, "sleep", lambda s: slept.append(s))
    out = embedder.embed_texts(["a", "bb", "ccc", "dddd", "eeeee"], batch_size=2)
    assert out == [[1.0], [2.0], [3.0], [4.0], [5.0]]   # all chunks embedded, in order
    assert len(slept) == 1                              # waited once, then retried
