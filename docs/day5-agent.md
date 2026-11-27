# Day 5: LangGraph investigation agent

## First: structure-aware chunking

Day 4 showed size-based chunking cutting CISA KEV entries in half: a chunk could hold the end
of one CVE and the start of the next, so an answer could attach one entry's "required action"
to another CVE. The splitter now tries Markdown headings (`\n## `, `\n### `) before blank lines,
so every section, and every `## CVE-...` KEV entry, stays in one piece. A unit test builds a
30-entry KEV document and checks no entry is split.

## What the agent does

`/ask` answers one question from retrieved passages. An **investigation** is a multi-step
process an analyst would follow. The agent is a **LangGraph state graph** of six nodes:

| Node | Does | Facts from |
|---|---|---|
| `extract_entities` | Finds CVE and ATT&CK IDs with regular expressions | Code |
| *conditional edge* | CVEs found → `enrich_cves`; otherwise skip to evidence | Code |
| `enrich_cves` | Live card per CVE: NVD, CISA KEV, EPSS, priority, ATT&CK suggestions | NVD, CISA, FIRST, MITRE |
| `retrieve_evidence` | RAG search, query expanded with each CVE's NVD description; passages labelled E1, E2... | Our documents |
| `map_attack` | Builds candidates (IDs in the question, IDs **mentioned in our documents**, live suggestions, keyword search); Gemini **chooses** 3–6 with structured output; choices not in the candidate list are discarded | Code + Gemini (choice only) |
| `recommend` | Overall risk = worst CVE priority (rules); Gemini writes 5–8 recommendations that must each cite a basis (CVE, KEV, Mxxxx, Txxxx, E#); items without a valid basis are dropped | Rules + Gemini |
| `write_report` | Gemini writes only the executive summary; every table is rendered by code from tool data | Code + Gemini (summary only) |

The state is a `TypedDict`; `steps` and `errors` are `Annotated[list, operator.add]`, so every
node appends to an audit trail instead of overwriting it.

## Safety and reliability

- **Facts from tools, language from the LLM.** CVSS, KEV, EPSS and priority never pass through the model.
- **Constrained choice.** The model picks techniques from a list built by code; invented IDs are discarded.
- **Every recommendation cites a basis** from an allowed list; unsupported ones are dropped.
- **Graceful degradation.** If Gemini is down, the agent uses the rule-based candidates and KEV/ATT&CK
  mitigations, and the report says the summary is unavailable. If Qdrant is down, the report still has the live intel.
- **Dependency injection.** Nodes call services through `nodes.TOOLS`, so the tests replace them with fakes
  and run with no Qdrant, internet or Gemini.

## Why this finds what the live intel missed

For MOVEit (CVE-2023-34362) the NVD description never mentions a web shell, so Day 4's card
suggested T1190 plus some noisy keyword matches. The agent also reads our MOVEit advisory, which
names LEMURLOOT and lists **T1505.003 Web Shell**, so that technique becomes a candidate
("mentioned in evidence E1") and Gemini can select it with high confidence.

## First real run (CVE-2023-34362, MOVEit)

| | Result |
|---|---|
| Time | ~16 s (after the fix below; the first run took ~5 minutes) |
| ATT&CK | **T1190**, **T1505.003 Web Shell** and **T1136 Create Account**, all supported by our MOVEit advisory. Day 4's noisy keyword matches (T1588.006, T1505.001) were rejected |
| Recommendations | 6, e.g. patch, alert on `human2.aspx` / `X-siLock-Comment`, file integrity monitoring on `wwwroot`, hunt for the "Health Check Service" account |

### Problems found and fixed

| Problem | Cause | Fix |
|---|---|---|
| The summary step took 268 s | The busy main model (503) was retried on every call, with no timeout | `LLM_TIMEOUT` (30 s) plus a **circuit breaker**: a model that just failed with 503/429/timeout is skipped for 2 minutes |
| Evaluation MRR dropped 0.88 → 0.85 | A controlled experiment (remove the KEV document, re-ingest, re-evaluate → back to 0.88) showed the cause was the extra KEV document competing in search, not the new chunking | Evaluate on a fixed corpus |
| A KEV chunk without a CVE ID (E6) was cited as a basis | Some KEV entries are longer than one chunk and were split mid-entry | Every KEV line now repeats its CVE ID, and long fields are shortened so splits happen between lines |
| Two tests failed only when run together | A test replaced the Gemini library with a fake that leaked into later tests | Fake the library only when it isn't installed |

## How to run

```bash
pip install -r requirements.txt          # adds langgraph
python -m scripts.investigate "Investigate CVE-2023-34362 and recommend detections and mitigations"
```
Or in `/docs`: `POST /investigate` (full JSON), `POST /investigate/report` (Markdown only),
`GET /agent/graph` (Mermaid diagram of the graph; paste into https://mermaid.live).

## Interview answer

> "I built the investigation workflow as a LangGraph state graph with six nodes and a conditional
> edge that only calls the live CVE sources when the question names a CVE. Facts like CVSS, KEV status
> and priority come from tools and rules; the LLM only chooses ATT&CK techniques from candidates built
> by code and writes the recommendations and summary, and both are validated: invented technique IDs
> and recommendations without a valid basis are discarded. Every node degrades gracefully, the state
> keeps an audit trail of steps and errors, and the nodes are unit-tested with injected fake tools."
