"""
run_graph.py
============
Run the whole system on one alert, live, in the terminal.

    python run_graph.py            -> the synthetic lateral-movement demo
    python run_graph.py demo       -> the same
    python run_graph.py <alert-id> -> any alert from the corpus

This is the demonstration script. It streams the audit trail as it happens,
stops at the human gate, shows WHY the alert was escalated, asks for a
decision, and resumes.
"""

from __future__ import annotations

import asyncio
import sys

from langgraph.types import Command

from core.config import describe
from core.preprocessor import load_alerts
from core.state import initial_state
from graph import build_graph
from tools import history, scenarios


# One character per event kind, so a long run stays readable.
KIND_MARK = {
    "node_start": ">", "node_end": "<", "tool_call": ".", "llm_call": "~",
    "a2a_call": "@", "a2a_task": " ", "interrupt": "!", "resume": "+",
    "error": "x",
}


def show(event: dict) -> None:
    """Print one audit-trail line."""
    mark = KIND_MARK.get(event["kind"], " ")
    print(f"  {mark} [{event['node']:<9}] {event['message'][:78]}")


def pick_alert(argument: str | None):
    """Find the alert to run, and make sure the datastore is ready."""
    alerts = load_alerts()
    history.build(alerts)
    scenarios.install()
    if argument == "demo" or argument is None:
        return scenarios.lateral_movement_incident()[2], alerts
    for alert in alerts:
        if alert.id == argument:
            return alert, alerts
    for alert in scenarios.all_demo_alerts():
        if alert.id == argument:
            return alert, alerts
    raise SystemExit(f"No alert with id {argument!r}. Try 'demo'.")


async def main() -> None:
    argument = sys.argv[1] if len(sys.argv) > 1 else None
    alert, _ = pick_alert(argument)
    graph = build_graph()
    # The thread_id is what ties a paused run to its resume. Two runs with
    # the same id share a history; two different ids are separate cases.
    config = {"configurable": {"thread_id": f"run-{alert.id}"}}

    print("=" * 74)
    print(f"  {alert.id}  |  {alert.rule_description[:46]}")
    print(f"  {describe()}")
    print("=" * 74)
    print("  > node start   < node end   . tool   ~ llm   @ a2a   ! pause")
    print()

    # `stream_mode="values"` yields the WHOLE state after each step. We
    # remember how many events we have already printed, so each line is
    # printed exactly once as the run progresses.
    seen = 0
    state: dict = {}
    async for chunk in graph.astream(initial_state(alert), config=config,
                                     stream_mode="values"):
        state = chunk
        for event in state.get("events", [])[seen:]:
            show(event)
        seen = len(state.get("events", []))

    # No interrupt means the routers sent the run straight to END.
    if "__interrupt__" not in state:
        print()
        print(f"  AUTO-CLOSED. No escalation signal. "
              f"Report: {len(state.get('report') or '')} characters.")
        return

    # `.value` is the payload the hitl node passed to interrupt().
    pause = state["__interrupt__"][0].value
    print()
    print("=" * 74)
    print("  PAUSED FOR A HUMAN")
    print("=" * 74)
    print(f"  alert        : {pause['alert_id']} on {pause['host']}")
    print(f"  description  : {pause['description']}")
    print(f"  triage said  : {pause['triage']}")
    print(f"  attack stage : {pause['attack_stage']}")
    print(f"  hosts        : {', '.join(pause['affected_hosts']) or 'none'}")
    print("  why escalated:")
    for signal in pause["escalation_signals"]:
        print(f"     - {signal}")
    if pause["overridden_triage"]:
        print("  NOTE: triage alone would have auto-closed this alert.")
    print()
    print(f"  options: {', '.join(pause['options'])}")
    answer = input("  your decision [approved]: ").strip() or "approved"
    note = input("  note (optional): ").strip()

    print()
    # The SAME graph, the SAME thread_id, and a Command instead of a state.
    # LangGraph loads the checkpoint and continues from the pause.
    seen_after = seen
    async for chunk in graph.astream(
            Command(resume={"decision": answer, "decided_by": "analyst",
                            "note": note}),
            config=config, stream_mode="values"):
        state = chunk
        for event in state.get("events", [])[seen_after:]:
            show(event)
        seen_after = len(state.get("events", []))

    decision = state.get("human_decision")
    print()
    print("=" * 74)
    print(f"  CLOSED: {decision.headline() if decision else 'no decision'}")
    print(f"  Report: {len(state.get('report') or '')} characters")
    print("=" * 74)


asyncio.run(main())