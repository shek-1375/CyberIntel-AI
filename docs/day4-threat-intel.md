# Day 4: Live threat intelligence

## Why

Documents go out of date, and an LLM's memory is frozen at its training date. For facts
like "how severe is this CVE?" or "is it being exploited right now?", a security assistant
must use **live, authoritative sources**, not the model's memory.

## The four sources

| Source | Question it answers | How we get it | Cached |
|---|---|---|---|
| **NVD** (NIST) | What is this CVE? How severe (CVSS)? Which weakness (CWE)? Which products? | CVE API 2.0: `?cveId=CVE-...` | 24 h per CVE |
| **CISA KEV** | Is it confirmed exploited in the wild? What must be done, by when? | One JSON feed (~1,500 entries) | 24 h |
| **FIRST EPSS** | How likely is exploitation in the next 30 days? (0–1) | `api.first.org/data/v1/epss?cve=...` | in memory |
| **MITRE ATT&CK** | Which attacker techniques does it enable? Which mitigations apply? | Enterprise STIX bundle (tens of MB) | 7 days |

Downloads are cached in `backend/data/intel/` (not committed to Git). If a source is offline,
a stale cached copy is used; if there is none, the card lists the error and the other sources still work.

**CVSS vs EPSS vs KEV:** CVSS = how bad *if* exploited. EPSS = how *likely* to be exploited.
KEV = *confirmed* exploited. A CVSS 9.8 bug with EPSS 1% may matter less this week than a CVSS 7.5
bug that is in KEV.

## Patch priority (`app/intel/risk.py`)

Computed by plain rules, so it is consistent and explainable:

| Level | Rule |
|---|---|
| critical | in KEV **and** CVSS ≥ 7 |
| high | in KEV, or CVSS ≥ 9, or EPSS ≥ 0.5 |
| medium | CVSS ≥ 7, or EPSS ≥ 0.1 |
| low | anything else with data |
| unknown | no CVSS and no EPSS |

## CVE → ATT&CK mapping (`app/intel/attack.py`)

Each suggestion states **why** it was made, and only techniques that exist in ATT&CK can be
returned, so IDs are never invented:

| Rule | Suggests |
|---|---|
| CVSS vector `AV:N` and no user interaction | T1190 Exploit Public-Facing Application |
| CVSS needs user interaction (`UI:R` / `UI:A` / `UI:P`) | T1203 Exploitation for Client Execution |
| Local vector + "privilege" in the description | T1068 Exploitation for Privilege Escalation |
| CWE-78/77/94/95/917/502 (injection, deserialization) | T1059 Command and Scripting Interpreter |
| CWE-434 (file upload) or "web shell" in the description | T1505.003 Web Shell |
| Keyword search of the description against ATT&CK (BM25) | up to 3 more, labelled `keyword` |

On Day 5 the investigation agent will let the LLM choose among these candidates.

## Live intel in answers

If a question names a CVE (`LIVE_INTEL=true`), `/ask` adds a passage built from NVD + KEV + EPSS,
so Gemini can cite the real CVSS score and KEV status, even for CVEs not in our documents.
The evaluation question "What is the CVSS score of CVE-2024-3400?" was therefore no longer
unanswerable and was replaced.

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /intel/cve/{cve_id}` | Full intel card: NVD, KEV, EPSS, priority, ATT&CK suggestions + mitigations |
| `GET /intel/kev?search=moveit` | KEV entries (newest first, optional filter) |
| `GET /intel/attack/search?q=credential dumping` | ATT&CK techniques by keyword |
| `GET /intel/attack/T1190` | One technique with tactics, detection notes and mitigations |
| `POST /intel/kev/ingest` | Writes the newest KEV entries as a document and re-indexes, so RAG can answer "which Ivanti CVEs are being exploited?" |

## Interview answer

> "LLMs shouldn't be trusted for facts that change, like CVSS scores or whether a CVE is being
> exploited. I integrated NVD, CISA KEV, EPSS and MITRE ATT&CK as live sources with caching and
> graceful degradation, compute patch priority with transparent rules rather than the LLM, and
> map CVEs to ATT&CK using CVSS-vector and CWE rules plus keyword search, where every suggestion
> carries its reason and must be a real technique ID. When a question names a CVE, the live facts
> are added as a citable source in the RAG answer."
