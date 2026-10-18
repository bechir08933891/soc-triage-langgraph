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
| `hunter` | Enriches indicators and maps to MITRE ATT&CK | Yes |
| `forensics` | Rebuilds the attack timeline, detects lateral movement | Yes |
| `reporter` | Writes the structured incident report | Yes |
| `hitl` | Pauses the graph and waits for a human decision | No |

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
| **File** | `wazuh_formatted_alerts.json` (≈ 3 MB) |
| **Licence** | MIT |
| **Records** | 738 |

**If the download fails** (firewall, proxy, no internet), download the file
by hand from
<https://huggingface.co/datasets/kholil-lil/wazuh-alerts/blob/main/wazuh_formatted_alerts.json>
and place it in the `data/` folder under that exact name. Then re-run the
command above — it will detect the file and skip the download.

To force a fresh copy, edit `download_data.py` and set `force=True`.

---

## Analysis scripts

Each script answers one question about the data. Run them from the project
root with the environment active.

| Command | What it answers |
|---------|-----------------|
| `python download_data.py` | Fetch the complete dataset |
| `python analyse.py` | What is in the data, and how does triage classify it? |
| `python inspect_classes.py` | Is the classifier over-matching? |
| `python verify.py` | Are the dataset's labels real ground truth? |
| `python inspect_nested.py` | What is hidden inside active-response records? |

These scripts are the evidence behind the findings below. Every number
claimed here can be reproduced by running them.

---

## Findings about the public dataset

Measured across all 738 records.

**1. The True/False Positive labels are derived from the severity level.**
A single rule — *"level ≤ 3 means False Positive"* — reproduces the published
label on **738 of 738 records (100.0%)**. These labels therefore carry no
information beyond `rule.level` and cannot serve as ground truth for a
classifier. Reproduce with `python verify.py`.

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

Across the 47 unique source addresses in the corpus, our local frequency-based
reputation and AbuseIPDB agreed on only 27 (57.4%). The 20 disagreements
decompose exactly into three causes:

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

---

## Design decisions

**Triage uses no AI.** Severity decisions must be reproducible: the same
alert must always produce the same result. The triage agent applies fixed
rules and records every signal that fired in `matched_signals`. Running one
alert 500 times yields exactly one distinct result. AI is used where it is
strong — reasoning and writing — in the hunter, forensics and reporter agents.

**Every value is validated by a contract.** Pydantic models in `core/models.py`
and `core/contracts.py` define closed vocabularies. An invented severity such
as `"VERY BAD"` raises an error instead of entering the system.

**The classifier reads curated fields only.** It searches rule descriptions
and Wazuh rule groups, never the raw `full_log`. Searching free text caused
the same alert description to be classified two different ways.

**LangGraph orchestrates; A2A transports.** The agents communicate over A2A,
an open interoperability protocol. LangGraph holds the shared typed state,
the checkpoints and the human-in-the-loop interrupt — things A2A deliberately
does not do, since it works without shared internal memory.

---

## Project structure

```
soc-triage-langgraph/
├── core/
│   ├── models.py         # Alert — the input contract
│   ├── contracts.py      # What each agent must return
│   ├── state.py          # SOCState — the shared memory
│   └── preprocessor.py   # Raw dataset -> validated Alerts
├── tools/
│   └── severity.py       # Deterministic triage logic
├── data/                 # Dataset lands here (not committed)
└── *.py                  # Analysis scripts
```

---

## Status

- [x] Step 1 — Environment prepared
- [x] Step 2 — Project and dependencies installed
- [x] Step 3 — Connected to GitHub
- [x] Step 4 — The Alert contract (input validation)
- [x] Step 5 — Closed vocabularies and the Triage contract
- [x] Step 6 — All five agent contracts complete
- [x] Step 7 — The shared memory (SOCState) with reducers
- [x] Step 8 — Deterministic triage logic
- [x] Step 9 — Real dataset loaded and measured
- [x] Step 9B — Classifier corrected from real evidence
- [x] Step 10 — Triage running as a real A2A agent
- [x] Step 11 — LangGraph node calling A2A, with transport switch
- [ ] Step 12 — Hunter agent (threat intelligence + LLM)
- [ ] Step 13 — Forensics agent (timeline, lateral movement)
- [ ] Step 14 — Reporter agent
- [ ] Step 15 — The graph: edges, checkpoints, human-in-the-loop
- [ ] Step 16 — Streamlit demonstration interface
- [ ] Step 17 — Automated tests

---

## Author

Bejaoui Bechir
Doctoral demo project — 2026