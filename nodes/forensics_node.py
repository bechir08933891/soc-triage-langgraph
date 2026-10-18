"""
nodes/forensics_node.py
=======================
The LangGraph node for forensic investigation. Agent 3 of 5.

    reads   : state["alert"]
    writes  : forensics_result, events, token_usage, (errors on failure)

Same shape as triage_node and hunter_node: choose a transport, call, record
what happened. Two things are specific to forensics.

  1. It reports the DATASTORE's condition as a visible event. The agent
     owns state, and state can be missing, so "where did these events come
     from?" must be answerable from the log.

  2. It reports the ACTOR SPLIT - how many events belong to this attacker
     and how many to others. That number is finding 14 made visible on
     every single run, rather than buried in a test.
"""

from __future__ import annotations

import time

from core.config import A2A_MODE
from core.contracts import ForensicsRequest, ForensicsResult
from core.state import SOCState, make_event, make_usage
from nodes.a2a_client import A2ACallFailed, call_agent
from tools import history
from tools.forensics import TIMELINE_WINDOW_MINUTES, narrate

NODE = "forensics"


async def forensics_node(state: SOCState) -> dict:
    """Investigate the alert, over A2A or locally, and record the journey."""
    alert = state["alert"]

    events = [
        make_event(
            NODE, "node_start",
            f"Investigating {alert.id} in a {TIMELINE_WINDOW_MINUTES} minute window",
            transport="a2a" if A2A_MODE else "local",
        )
    ]
    usage_records: list[dict] = []
    started = time.perf_counter()

    try:
        if A2A_MODE:
            # --- Over the network ------------------------------------------
            events.append(make_event(NODE, "a2a_call",
                                     "Calling the forensics agent over A2A",
                                     agent="forensics"))

            # `mode="json"` turns dates and Enums into plain JSON values,
            # which is required before the object can travel over the wire.
            request = ForensicsRequest(
                alert=alert.model_dump(mode="json"),
                window_minutes=TIMELINE_WINDOW_MINUTES)
            response = await call_agent("forensics", request.model_dump_json())

            for observation in response["observations"]:
                events.append(make_event(
                    NODE, "a2a_task",
                    f"{observation['stage']}: {observation['detail']}",
                    task_id=response["task_id"]))

            result = ForensicsResult.model_validate_json(response["result_json"])

            events.append(make_event(NODE, "a2a_task",
                                     f"A2A task {response['final_state']}",
                                     task_id=response["task_id"],
                                     agent=response["agent_name"]))

            # Everything the remote agent attached to its artifact. A2A
            # metadata is all strings, so numbers are converted back.
            remote = response.get("metadata") or {}
            if remote.get("history"):
                events.append(make_event(NODE, "tool_call",
                                         f"Datastore: {remote['history']}"))
            input_tokens = int(remote.get("input_tokens", 0) or 0)
            output_tokens = int(remote.get("output_tokens", 0) or 0)
            if input_tokens or output_tokens:
                events.append(make_event(
                    NODE, "llm_call",
                    f"Remote LLM {remote.get('llm_mode', '?')}: "
                    f"{input_tokens} in + {output_tokens} out",
                    cost_usd=remote.get("cost_usd"),
                    containment_priority=remote.get("containment_priority")))
                usage_records.append(make_usage(
                    NODE, input_tokens, output_tokens,
                    remote.get("llm_model", "remote")))
            # "skipped" and "fallback" mean OPPOSITE things: one was our own
            # deliberate choice, the other was a failure. They are logged
            # with different kinds so the interface can colour them apart.
            if remote.get("skipped_reason"):
                events.append(make_event(
                    NODE, "tool_call",
                    f"LLM skipped: {remote['skipped_reason'][:120]}"))
            if remote.get("fallback_reason"):
                events.append(make_event(
                    NODE, "error",
                    f"Remote LLM fallback: {remote['fallback_reason'][:120]}"))

        else:
            # --- In this process -------------------------------------------
            note = history.ensure_built()
            events.append(make_event(NODE, "tool_call", f"Datastore: {note}"))
            events.append(make_event(NODE, "tool_call",
                                     "Running narrate() locally"))
            result, meta = narrate(alert)

            usage = meta.get("usage")
            if usage:
                events.append(make_event(
                    NODE, "llm_call",
                    f"LLM {usage['mode']}: {usage['input_tokens']} in + "
                    f"{usage['output_tokens']} out",
                    model=usage["model"],
                    cost_usd=round(float(usage.get("cost_usd", 0.0)), 6),
                    containment_priority=meta.get("containment_priority")))
                usage_records.append(make_usage(NODE, usage["input_tokens"],
                                                usage["output_tokens"],
                                                usage["model"]))
            if meta.get("skipped_reason"):
                events.append(make_event(
                    NODE, "tool_call",
                    f"LLM skipped: {meta['skipped_reason']}"))
            if meta.get("fallback_reason"):
                events.append(make_event(
                    NODE, "error",
                    f"LLM fallback: {meta['fallback_reason'][:120]}"))

    except (A2ACallFailed, ValueError) as error:
        # A2ACallFailed = the network or the agent. ValueError = a contract
        # rejected the answer. Both mean "no result", and both are recorded
        # rather than raised, so one failing agent cannot kill the run.
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        events.append(make_event(NODE, "error",
                                 f"Investigation failed: {error}",
                                 elapsed_ms=elapsed_ms))
        return {"forensics_result": None, "events": events,
                "errors": [str(error)]}

    # THE ACTOR SPLIT, on every run. A viewer who sees "25 events" and is
    # not told how many belong to someone else will read the timeline as a
    # single incident - which is exactly the mistake finding 14 records.
    own = sum(1 for e in result.timeline if e.same_actor)
    events.append(make_event(
        NODE, "tool_call",
        f"Timeline: {len(result.timeline)} event(s), {own} belong to this "
        f"actor, {len(result.timeline) - own} to others",
        hosts=result.affected_hosts))

    # Name the pattern explicitly. These two are never both reported as the
    # headline, because confusing them is the original sin of this module.
    if result.lateral_movement:
        events.append(make_event(NODE, "tool_call",
                                 "LATERAL MOVEMENT detected",
                                 hosts=result.affected_hosts))
    elif result.horizontal_spread:
        events.append(make_event(NODE, "tool_call",
                                 "Horizontal spread (scanning or spraying)",
                                 hosts=result.affected_hosts))

    elapsed_ms = round((time.perf_counter() - started) * 1000)
    events.append(make_event(
        NODE, "node_end",
        f"Stage {result.attack_stage.value}, "
        f"{len(result.affected_hosts)} host(s) affected",
        attack_stage=result.attack_stage.value,
        lateral_movement=result.lateral_movement,
        horizontal_spread=result.horizontal_spread,
        elapsed_ms=elapsed_ms))

    update: dict = {"forensics_result": result, "events": events}
    # Only include token_usage if there is something to add. An empty list
    # would still trigger the reducer, harmlessly but pointlessly.
    if usage_records:
        update["token_usage"] = usage_records
    return update