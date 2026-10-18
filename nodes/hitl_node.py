"""
nodes/hitl_node.py
==================
The human gate. Agent 5 of 5 - and the only one that is a person.

    reads   : alert, escalation_signals, overridden_triage, triage_result,
              forensics_result, report
    writes  : human_decision, events

HOW `interrupt()` ACTUALLY WORKS, because it is surprising:

  FIRST RUN  - `interrupt(payload)` RAISES. The node never finishes, so
               NOTHING it would have returned is written to state. The
               payload travels out to the caller as `state["__interrupt__"]`
               and the graph stops, with its progress saved in a checkpoint.

  ON RESUME  - the node is re-executed FROM THE TOP, and this time
               `interrupt()` RETURNS the value carried by
               `Command(resume=...)`. The node then finishes normally.

So the node runs twice, and every line above `interrupt()` runs twice too.
That is fine here because those lines only build a dictionary. It would NOT
be fine if they sent an email, charged a card, or blocked a firewall rule.
Side effects belong strictly AFTER the interrupt.

FAIL-SAFE: an answer we do not recognise becomes `escalated`, never
`approved`. "I did not understand you" must not silently mean "go ahead".
"""

from __future__ import annotations

from langgraph.types import interrupt

from core.contracts import Decision, HumanDecision
from core.state import SOCState, make_event

NODE = "hitl"


async def hitl_node(state: SOCState) -> dict:
    """Pause, show a human why, and record what they chose."""
    alert = state["alert"]
    signals = state.get("escalation_signals") or []
    forensics = state.get("forensics_result")
    triage = state.get("triage_result")

    # Everything the human needs in order to decide, and nothing else. A
    # gate that shows 4,000 characters of Markdown is a gate people click
    # through without reading.
    payload = {
        "alert_id": alert.id,
        "host": alert.agent_name,
        "description": alert.rule_description,
        "escalation_signals": signals,
        "overridden_triage": bool(state.get("overridden_triage")),
        "triage": triage.headline() if triage else "no triage result",
        "attack_stage": forensics.attack_stage.value if forensics else "unknown",
        "affected_hosts": forensics.affected_hosts if forensics else [],
        "report_chars": len(state.get("report") or ""),
        # The options come FROM the enum, so the gate can never offer a
        # choice the contract would reject.
        "options": [d.value for d in Decision],
    }

    # Everything above this line runs twice. Everything below runs once.
    answer = interrupt(payload)

    # The answer can be a dictionary (an interface) or bare text (a terminal).
    if isinstance(answer, dict):
        raw = answer.get("decision", Decision.ESCALATED.value)
        decided_by = answer.get("decided_by", "analyst")
        note = answer.get("note", "")
    else:
        raw = str(answer)
        decided_by = "analyst"
        note = ""

    try:
        decision = Decision(raw)
    except ValueError:
        # FAIL SAFE, and say so in the record. An unreadable answer must
        # never resolve to "approved".
        decision = Decision.ESCALATED
        note = f"unrecognised answer {raw!r}; defaulted to escalated. {note}".strip()

    record = HumanDecision(decision=decision, decided_by=decided_by, note=note)

    # TWO events, written together on the resumed pass: the pause and the
    # answer. The audit trail should show that a human was asked, not only
    # what they said.
    events = [
        make_event(NODE, "interrupt",
                   f"Paused for a human on {alert.id}: "
                   f"{', '.join(signals) or 'no signals'}",
                   signals=signals,
                   overridden_triage=payload["overridden_triage"]),
        make_event(NODE, "resume", f"Human decided: {record.headline()}",
                   decision=decision.value, decided_by=decided_by, note=note),
    ]
    return {"human_decision": record, "events": events}