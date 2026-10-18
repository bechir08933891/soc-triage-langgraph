"""
nodes/triage_node.py
====================
The LangGraph node for triage. Agent 1 of 5.

A LangGraph node is a function that RECEIVES the whole state and RETURNS
only the keys it changed. This one:

    reads   : state["alert"]
    writes  : triage_result, events, (errors if it fails)

It is `async def` because A2A calls go over a network. LangGraph handles
async nodes natively — you call `graph.ainvoke()` instead of `graph.invoke()`.

The node does NOT contain triage logic. It chooses a transport, calls, and
records what happened. The logic lives in tools/severity.py or in the agent.
"""

from __future__ import annotations

# `time.perf_counter()` is a high-precision stopwatch. We use it to measure
# how long each node takes — a real number for your metrics sidebar.
import time

from core.config import A2A_MODE
from core.contracts import TriageResult
from core.state import SOCState, make_event
from nodes.a2a_client import A2ACallFailed, call_agent
from tools.severity import assign_severity

# The node's name, written once. The events, the UI card and the graph all
# use this, so a rename cannot leave them out of step.
NODE = "triage"


async def triage_node(state: SOCState) -> dict:
    """Classify the alert, over A2A or locally, and record the whole journey."""
    alert = state["alert"]

    # The first event turns the TRIAGE card yellow in your demo interface.
    # We record the transport in the event, so the log itself shows which
    # mode the run used. That is self-documenting evidence.
    events = [
        make_event(
            NODE, "node_start",
            f"Triaging {alert.id} (level {alert.rule_level})",
            transport="a2a" if A2A_MODE else "local",
        )
    ]
    started = time.perf_counter()

    try:
        if A2A_MODE:
            # --- Over the network --------------------------------------------
            events.append(make_event(
                NODE, "a2a_call", "Calling the triage agent over A2A",
                agent="triage",
            ))

            response = await call_agent("triage", alert.model_dump_json())

            # Turn every A2A observation into a log line. This is what proves
            # to a viewer that discovery, the task lifecycle and the artifact
            # really happened.
            for observation in response["observations"]:
                events.append(make_event(
                    NODE, "a2a_task",
                    f"{observation['stage']}: {observation['detail']}",
                    task_id=response["task_id"],
                ))

            # 🔑 The answer crossed a network, so it is untrusted. Our
            # contract from Step 5 validates it before it enters the state.
            result = TriageResult.model_validate_json(response["result_json"])

            events.append(make_event(
                NODE, "a2a_task", f"A2A task {response['final_state']}",
                task_id=response["task_id"],
                agent=response["agent_name"],
                version=response["agent_version"],
            ))

        else:
            # --- In this process ---------------------------------------------
            events.append(make_event(
                NODE, "tool_call", "Calling assign_severity() locally",
            ))
            result = assign_severity(alert)

    except (A2ACallFailed, ValueError) as error:
        # A failure must not crash the graph. We record it in `errors` (which
        # has a reducer, so nothing is lost) and return no result. Later nodes
        # can see that triage produced nothing and react accordingly.
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        events.append(make_event(
            NODE, "error", f"Triage failed: {error}", elapsed_ms=elapsed_ms,
        ))
        return {"triage_result": None, "events": events, "errors": [str(error)]}

    # Success. This event turns the card green and fills the log line.
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    events.append(make_event(
        NODE, "node_end", result.headline(),
        severity=result.severity.value,
        attack_type=result.attack_type.value,
        score=result.score,
        escalate=result.escalate_to_tier2,
        elapsed_ms=elapsed_ms,
    ))

    # Only the keys we changed. LangGraph merges them into the shared state,
    # appending to `events` because of its reducer.
    return {"triage_result": result, "events": events}