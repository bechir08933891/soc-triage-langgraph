# SOC Triage Agent — LangGraph Edition

A live graphical demonstration of a multi-agent AI system applied to
cybersecurity alert triage.

Security alerts from Wazuh (an open-source SIEM) flow through a LangGraph
state machine of five specialised nodes. The interface shows, in real time,
what every agent is doing, which tools it calls, and what it costs.

## The five nodes

| Node | Role | Uses an LLM? |
|------|------|--------------|
| `triage` | Classifies the attack and assigns a severity | No — fully deterministic |
| `hunter` | Enriches indicators and maps to MITRE ATT&CK | Yes |
| `forensics` | Rebuilds the attack timeline, detects lateral movement | Yes |
| `reporter` | Writes the structured incident report | Yes |
| `hitl` | Pauses the graph and waits for a human decision | No |

## Status

🚧 Under construction — built step by step.

- [x] Step 1 — Environment prepared
- [x] Step 2 — Project and dependencies installed
- [x] Step 3 — Connected to GitHub
- [x] Step 4 — The Alert contract (input validation)
- [ ] Step 5 — The agent output contracts

## Installation

```bash
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Author

Doctoral project — 2026