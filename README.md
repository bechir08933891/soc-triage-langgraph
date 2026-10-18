# SOC Triage Agent — LangGraph + A2A Edition

A live graphical demonstration of a multi-agent AI system applied to
cybersecurity alert triage.

Security alerts from Wazuh (an open-source SIEM) flow through a LangGraph
state machine of five specialised agents. The agents communicate over the
**A2A protocol** (Agent2Agent, Linux Foundation). The interface shows, in
real time, what every agent is doing, which tools it calls, and what it costs.

## The five agents

| Agent | Role | Uses an LLM? |
|------|------|--------------|
| `triage` | Classifies the attack and assigns a severity | No — fully deterministic |
| `hunter` | Enriches indicators and maps to MITRE ATT&CK | Yes (prose and one score only) |
| `forensics` | Rebuilds the attack timeline, detects lateral movement | Yes |
| `reporter` | Writes the structured incident report | Yes |
| `hitl` | Pauses the graph and waits for a human decision | No |

---

## Findings at a glance

Every number below is reproducible by running the named script on the full
738-record corpus.

| # | Finding | Reproduce with |
|---|---------|----------------|
| 1 | The dataset's True/False Positive labels are a function of `rule.level` alone — 738 of 738 records (100%) | `python verify.py` |
| 2 | 63% of records are active-response wrappers hiding the real alert at `data.parameters.alert` | `python inspect_nested.py` |
| 3 | No alert reaches Critical or High severity; only levels 3, 4, 5 and 8 are present | `python analyse.py` |
| 4 | Unwrapping the wrappers recovers 46 real source IPs and 466 real host names; coverage rises 96.5% to 99.6% | `python analyse.py` |
| 5 | First-party and third-party IP reputation agree on only 57.4%, and fail in opposite directions | `python compare_reputation.py` |
| 6 | Measured LLM cost is about 20x below the design estimate: 657 tokens and $0.00014 per enrichment | `python test_llm.py` |
| 7 | A2A costs 444 ms per agent call against 1.4 ms in-process — 318x more, and about 20% of a two-agent run | `python measure.py` |
| 8 | Reproducibility is partial by design: the rule scorer gives 1 distinct result in 500 runs, the LLM gives 3 in 16 | `python measure.py` |

---

## Architecture: what LangGraph does, and what A2A does

The two are not alternatives. They solve different problems, and the project
uses each for what it is good at.

```text
   +----------------------------------------------+
   |  LangGraph - the orchestrator                |
   |  - SOCState: one typed, shared memory        |
   |  - checkpoints, replay, human-in-the-loop    |
   |                                              |
   |  each node is an A2A CLIENT                  |
   +---+--------------+---------------------------+
       | A2A          | A2A
       v              v
   +--------+     +--------+
   | triage |     | hunter |   one process, port 9001
   |/triage |     |/hunter |   each with its own Agent Card
   +--------+     +--------+
```

**A2A** (Agent2Agent, hosted by the Linux Foundation) lets agents discover
each other and exchange work across vendor and organisational boundaries. It
works, by design, *without* shared internal memory.

**LangGraph** holds exactly what A2A deliberately omits: one typed state
object that every agent reads and writes, checkpointed after each step, with
a native `interrupt()` for human approval.

Agents are therefore addressed through published Agent Cards, never hardcoded
URLs, while the investigation itself lives in auditable shared state.

### The transport switch

`SOC_A2A_MODE` selects how nodes reach their agents:

| Value | Behaviour |
|-------|-----------|
| `true` | nodes call their agents over A2A (real interoperability) |
| `false` | nodes call the Python function directly (fast, no server needed) |

The graph, the state, the audit trail and the results are **identical** either
way. Only the transport changes. That is what makes the measurement in
finding 7 possible, and what keeps the demonstration runnable if a port is
unavailable.

---

## Installation

Requires Python 3.10 or newer.

```bash
# 1. Get the code
git clone https://github.com/YOUR-USERNAME/soc-triage-langgraph.git
cd soc-triage-langgraph

# 2. Create an isolated environment
py -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

# 3. Install the libraries
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Configuration

Copy `.env.example` to `.env` and fill in what you have. **Every key is
optional** — the system degrades to deterministic behaviour rather than
failing.

```text
OPENAI_API_KEY=sk-...          # for the hunter, forensics and reporter agents
SOC_LLM_MODEL=gpt-6-luna       # see the note on model deprecation below
ABUSEIPDB_API_KEY=...          # optional: external IP reputation
SOC_OFFLINE_MODE=false         # true = no outbound calls at all
SOC_A2A_MODE=true              # false = call agents in-process
```

`.env` is git-ignored and must never be committed.

> **On model choice.** `gpt-4o-mini`, named in the original design, was
> deprecated on 2026-10-14 and shuts down on 2027-01-14. `gpt-6-luna` is
> OpenAI's recommended replacement and is cheaper. The LLM layer detects and
> works around per-model parameter constraints at runtime — see
> *Design decisions*.

---

## Getting the dataset

The alert corpus is **not** stored in this repository. It is a 3 MB public
dataset, and anyone can fetch it with one command:

```bash
python download_data.py
```

This downloads the complete dataset — all 738 records, nothing sampled —
from Hugging Face into `data/wazuh_formatted_alerts.json`.

| | |
|---|---|
| **Source** | [`kholil-lil/wazuh-alerts`](https://huggingface.co/datasets/kholil-lil/wazuh-alerts) |
| **File** | `wazuh_formatted_alerts.json` (about 3 MB) |
| **Licence** | MIT |
| **Records** | 738 |

**If the download fails** (firewall, proxy, no internet), download the file
by hand from
<https://huggingface.co/datasets/kholil-lil/wazuh-alerts/blob/main/wazuh_formatted_alerts.json>
and place it in the `data/` folder under that exact name. Then re-run the
command above — it will detect the file and skip the download.

To force a fresh copy, edit `download_data.py` and set `force=True`.

---

## Running the agents

The A2A agents run as one small web server. Start it in its own window and
leave it running:

```bash
python run_agents.py
```

| Address | What it serves |
|---------|----------------|
| `http://127.0.0.1:9001/` | the list of hosted agents |
| `http://127.0.0.1:9001/triage/.well-known/agent-card.json` | the triage Agent Card |
| `http://127.0.0.1:9001/hunter/.well-known/agent-card.json` | the hunter Agent Card |

All agents share one process deliberately: four separate servers would use
roughly 600 MB, one process about 150 MB. Each still has its own card and
endpoint, so splitting them onto separate machines later requires no code
change — only different addresses in the cards.

If the port is already held by an older copy of the server, `run_agents.py`
prints the commands to find and release it.

---

## Scripts

Each script answers one question. Run them from the project root with the
environment active.

### Data and findings

| Command | What it answers |
|---------|-----------------|
| `python download_data.py` | Fetch the complete dataset |
| `python analyse.py` | What is in the data, and how does triage classify it? |
| `python inspect_classes.py` | Is the classifier over-matching? |
| `python verify.py` | Are the dataset's labels real ground truth? |
| `python inspect_nested.py` | What is hidden inside active-response records? |
| `python compare_reputation.py` | Does local reputation agree with AbuseIPDB? |

### Components and measurement

| Command | What it tests |
|---------|---------------|
| `python test_intel.py` | MITRE coverage and IP enrichment across the corpus |
| `python test_llm.py` | The LLM layer, with real token counts and cost |
| `python test_node.py` | One LangGraph node, local and over A2A |
| `python test_two_nodes.py` | Two agents collaborating in one graph |
| `python measure.py` | Transport overhead and reproducibility, isolated |

---

## Findings in detail

Measured across all 738 records unless stated otherwise.

**1. The True/False Positive labels are derived from the severity level.**
A single rule — *"level 3 or below means False Positive"* — reproduces the
published label on **738 of 738 records (100.0%)**. These labels therefore
carry no information beyond `rule.level` and cannot serve as ground truth for
a classifier. Reproduce with `python verify.py`.

**2. 63% of the dataset is active-response bookkeeping.** 466 records
describe the firewall blocking or unblocking a host. Each one wraps the alert
that triggered it at `data.parameters.alert`, including the **real host name
and attacker IP** that the outer record anonymises as `xxx`. Reproduce with
`python inspect_nested.py`.

**3. No alert reaches Critical or High severity.** The only Wazuh levels
present are 3, 4, 5 and 8. The escalation path and the human-in-the-loop gate
therefore never fire on this corpus. It is used for format fidelity and
distribution analysis; the live demonstration uses a curated scenario, and
this is stated explicitly rather than hidden.

**4. Unwrapping the active-response records recovers hidden evidence.**
Reading the nested alert at `data.parameters.alert` raises the number of
alerts carrying a real source IP from 645 to 691, and replaces the
anonymised host name `xxx` with the real one (`prod-server`) on 466 records.
Classification coverage rises from 96.5% to 99.6%, and no alert description
is classified inconsistently any more.

**5. First-party and third-party IP reputation fail in opposite directions.**

Across the 47 unique source addresses in the corpus, our local
frequency-based reputation and AbuseIPDB agreed on only 27 (57.4%). The 20
disagreements decompose exactly into three causes:

| Cause | n | Share |
|-------|---|-------|
| Benign internet-measurement projects | 7 | 35% |
| External blind spot: abuse we observed, never reported externally | 9 | 45% |
| Local blind spot: reported abuse we saw too rarely to score | 4 | 20% |

The research-scanner category is dominated by six addresses inside
`64.62.156.0/24`, registered in ARIN to The Shadowserver Foundation — a
self-described "altruistic, public benefit, nonprofit organization" that
scans the internet and reports findings free to network owners and national
CERTs. Each carried roughly 1,600 abuse reports and a 100% AbuseIPDB
confidence score. Acting on that score would consume analyst time on a
benign scan.

The operational consequence is asymmetric. The nine externally-unknown
addresses account for **533 of the 691 IP-bearing alerts (77.1%)**, while the
four addresses only external intelligence flagged account for 6 alerts
(0.9%). A Tier-1 system relying on crowd-sourced reputation alone would have
had no signal on three quarters of the attack traffic in this corpus.

Design response: both verdicts are retained separately with their provenance
in `per_source`; a verified allowlist corrects known research scanners with
the reason recorded in the audit trail; and no single source may drive
escalation alone.

Reproduce with `python compare_reputation.py`.

**6. Measured LLM cost is roughly twenty times below the design estimate.**
The original design budgeted about 3,500 tokens and $0.0075 per run.
Measured on real alerts, the hunter agent uses **657 tokens (463 in, 194
out) and about $0.00014** per enrichment. The difference is architectural
rather than incidental: the model receives about 460 tokens of *curated
facts* assembled by deterministic tools, not a raw alert dump. Reproduce with
`python test_llm.py`.

**7. A2A transport costs 444 ms per agent call on this machine.**

Measuring the transport requires isolating it from the language model, whose
latency (4–7 s, varying by more than a second between identical calls)
otherwise swamps it. The triage node calls no model, so timing it ten times
under each transport measures the protocol alone:

| Transport | Median | Mean | Stdev | n |
|-----------|--------|------|-------|---|
| in-process | **1.4 ms** | 1.6 ms | 0.6 ms | 10 |
| A2A | **445.1 ms** | 449.9 ms | 42.4 ms | 10 |

That is **443.7 ms of overhead per agent call, a factor of 318**. For the
current two-agent pipeline the transport accounts for roughly 887 ms, or
about **20% of a 4.5 s enriched run**. Adding the forensics and reporter
agents would raise it to roughly 1.8 s.

A single wall-clock comparison between the two modes is **confounded** and
must not be used: the measured A2A run completed in 4476 ms while the
in-process runs took 5955 ms and 6869 ms, so A2A appeared *faster* despite
carrying ~900 ms more transport. That is an artefact of LLM latency variance,
not a property of the protocol.

*Known optimisation.* The client currently re-fetches the Agent Card and
builds a fresh HTTP client on every call, so each agent invocation costs two
round trips plus connection setup. This is correct discovery behaviour but
wasteful for repeated calls to the same agent. Caching the resolved card for
the lifetime of a run is the obvious next step and would be expected to cut
the overhead substantially. It is deliberately left unoptimised here so that
the measured figure reflects the straightforward implementation.

Reproduce with `python measure.py` under each `SOC_A2A_MODE`.

**8. Reproducibility is partial by design, and the boundary is measurable.**

| Scorer | Runs | Distinct results | Spread |
|--------|------|------------------|--------|
| Deterministic rules | 500 | **1** (score 43) | none |
| Language model | 16 | **3** (43, 48, 55) | range 12, stdev 4.17 |

The model reproduced the rule-based score in **13 of 16 runs (81%)** and
deviated upward in 3 (19%), with a maximum deviation of **+12 points**. The
cause is recorded in the audit trail: the configured model rejects
`temperature=0`, so `temperature_pinned` is false and the model runs at its
default sampling temperature.

This is precisely why severity — the field that decides whether a human is
woken — is computed by rules, while the model's contribution is bounded to
prose and a single advisory score. The system does not claim end-to-end
reproducibility; it claims reproducibility for the decisions that require it,
and it can show where the boundary lies.

Reproduce with `python measure.py`.

---

## Design decisions

**Triage uses no AI.** Severity decisions must be reproducible: the same
alert must always produce the same result. The triage agent applies fixed
rules and records every signal that fired in `matched_signals`. Running one
alert 500 times yields exactly one distinct result. AI is used where it is
strong — reasoning and writing — in the hunter, forensics and reporter agents.

**The language model's output contract is two fields wide.** `HuntSynthesis`
contains a length-bounded hypothesis and an integer 0 to 100. The model never
chooses an attack type, a severity, a MITRE technique or an IP verdict: those
are produced by deterministic tools and handed to it as facts. The surface on
which a hallucination could land is therefore two bounded fields, and the
exact fact block sent to the model is printable for inspection.

**Every value is validated by a contract.** Pydantic models in
`core/models.py` and `core/contracts.py` define closed vocabularies. An
invented severity such as `"VERY BAD"` raises an error instead of entering the
system. Contracts are enforced at both ends of every network boundary: the
agent validates what arrives, and the client validates what returns.

**Structured output is enforced in two independent layers.** Layer 1 uses the
provider's `json_schema` mode. Layer 2, used when a model or provider does
not support it, places the schema in the prompt and validates the reply with
Pydantic locally. Layer 1 is a provider feature that varies by model; layer 2
is this system's own guarantee.

**Fallbacks cannot themselves fail.** `core/llm.py` guarantees that the only
exception escaping `structured_call` is `LLMUnavailable`, so a caller can
always fall back to deterministic synthesis. When that happens, the reason is
recorded in the audit trail and stated in the generated text — the system
never passes a rule-based summary off as model reasoning.

**Per-model API constraints are handled at runtime.** The configured model
rejected `temperature=0`, a parameter the previous generation accepted. The
LLM layer detects that specific rejection, rebuilds the client without the
parameter, retries, and records in the audit trail whether temperature was
pinned — so a reproducibility claim is never made when it does not hold. See
finding 8 for the measured consequence.

**The classifier reads curated fields only.** It searches rule descriptions
and Wazuh rule groups, never the raw `full_log`. Searching free text caused
the same alert description to be classified two different ways.

**The taxonomy was revised from data, not designed in advance.** Two
non-threat categories — `NormalActivity` and `Vulnerability` — were added
after the real corpus showed that successful logins and resolved CVEs were
being forced into attack families. A classifier with no way to say "nothing
is happening here" is obliged to be wrong.

**Threat intelligence is cached and degrades gracefully.** The corpus
contains 691 IP-bearing alerts but only 47 unique addresses, so caching
removes 93.2% of lookups. With no external key available, reputation is
derived from the corpus itself and labelled `LocalCorpus`, so the system
produces real verdicts offline without claiming external provenance.

**Distribution surfaced implicit dependencies.** Two became visible only once
agents ran in separate processes: the local reputation source needs an
address's frequency across the whole corpus, which a single-alert agent
cannot know, so `HuntRequest` passes it explicitly; and token accounting had
to be carried back in A2A artifact metadata, so cost metrics stay accurate
when the work happens elsewhere.

---

## Project structure

```text
soc-triage-langgraph/
|
+-- core/
|   +-- config.py         # every tunable setting, in one place
|   +-- models.py         # Alert - the input contract
|   +-- contracts.py      # what each agent must return
|   +-- state.py          # SOCState - the shared memory, with reducers
|   +-- preprocessor.py   # raw dataset -> validated Alerts
|   +-- llm.py            # the model client, schema enforcement, cost
|
+-- tools/
|   +-- severity.py       # deterministic triage logic
|   +-- mitre.py          # MITRE ATT&CK mapping, verified against attack.mitre.org
|   +-- threat_intel.py   # IP reputation: local corpus, AbuseIPDB, VirusTotal
|   +-- hunter.py         # evidence gathering plus LLM synthesis
|
+-- a2a_agents/
|   +-- triage_agent.py   # Agent Card plus executor
|   +-- hunter_agent.py   # Agent Card plus executor
|   +-- server.py         # hosts every agent on one port
|
+-- nodes/
|   +-- a2a_client.py     # generic A2A caller, reused by every node
|   +-- triage_node.py    # LangGraph node
|   +-- hunter_node.py    # LangGraph node
|
+-- data/                 # dataset and caches land here, not committed
+-- run_agents.py         # start the A2A server
+-- *.py                  # analysis, test and measurement scripts
```

---

## Status

### Foundation
- [x] Step 1 — Environment prepared
- [x] Step 2 — Project and dependencies installed
- [x] Step 3 — Connected to GitHub
- [x] Step 4 — The Alert contract (input validation)
- [x] Step 5 — Closed vocabularies and the Triage contract
- [x] Step 6 — All five agent contracts complete
- [x] Step 7 — The shared memory (SOCState) with reducers

### Triage agent (deterministic)
- [x] Step 8 — Deterministic triage logic
- [x] Step 9 — Real dataset loaded and measured
- [x] Step 9B — Classifier corrected from real evidence (96.5% to 99.6%)
- [x] Step 10 — Triage running as a real A2A agent
- [x] Step 11 — LangGraph node calling A2A, with transport switch

### Hunter agent (tools plus LLM)
- [x] Step 12 — MITRE ATT&CK mapping and threat intelligence with caching
- [x] Step 12B — Per-source verdicts kept separately for comparison
- [x] Step 12C — Research-scanner allowlist (Shadowserver, Censys, Expanse)
- [x] Step 12D — First-party against third-party reputation decomposed
- [x] Step 13 — LLM layer with two-level schema enforcement
- [x] Step 13B — Self-healing temperature handling, crash-proof fallback
- [x] Step 14 — Hunter as a second A2A agent, with metrics across the boundary
- [x] Step 14B — Transport overhead and reproducibility measured in isolation

### Remaining
- [ ] Step 15 — Forensics agent (timeline, lateral movement)
- [ ] Step 16 — Reporter agent (the incident report)
- [ ] Step 17 — The full graph: conditional edges, checkpoints, human-in-the-loop
- [ ] Step 18 — Streamlit demonstration interface (the five visual layers)
- [ ] Step 19 — Automated test suite
- [ ] Step 20 — Evaluation: does the LLM's score add signal over the rules?
- [ ] Step 21 — Optional: cache resolved Agent Cards, re-measure finding 7
- [ ] Step 22 — Optional: expose the whole system as one A2A agent

---

## Methodology note

The implementation sequence was revised seven times in response to
measurement: the classifier after the real corpus exposed over-matching, the
reputation layer after a merged score was found to hide its sources, the LLM
layer after a provider constraint and a crashable fallback were discovered
under test, and the latency claim after a single-run comparison proved
confounded by model variance. Each revision is a separate commit with the
script that produced the evidence, so the decision trail is reproducible
rather than reconstructed.

Two claims were explicitly withdrawn during development rather than
defended: that the published dataset labels constitute ground truth
(finding 1), and that a single wall-clock comparison can measure transport
overhead (finding 7).

---

## Author

Bejaoui Bechir
Doctoral demo project — 2026