"""
nodes/hunter_node.py
====================
The LangGraph node for threat hunting. Agent 2 of 5.

    reads   : state["alert"]
    writes  : hunt_result, events, token_usage, (errors on failure)

Same shape as triage_node: choose a transport, call, record what happened.
Two things are new.

  1. It must supply `local_hits` - the number of alerts in the whole corpus
     from this alert's IP address. The agent cannot know that by itself.

  2. In A2A mode it reads the TOKEN COUNTS back out of the A2A artifact
     metadata. Without that, the metrics sidebar would show zero cost
     whenever the work happened in another process, which would be a lie.
"""

from __future__ import annotations

import time

from core.config import A2A_MODE
from core.contracts import HuntRequest, HuntResult
from core.llm import cost_usd
from core.state import SOCState, make_event, make_usage
from nodes.a2a_client import A2ACallFailed, call_agent
from tools.hunter import hunt
from tools.threat_intel import count_local_hits

NODE = "hunter"


# Counting the corpus means reading 738 alerts from disk. We do it ONCE and
# remember the answer. `None` means "not computed yet" - which is different
# from an empty dictionary, meaning "computed, and there was nothing".
_hits_cache: dict[str, int] | None = None


def local_hits_for(alert) -> int:
    """How many alerts in the whole corpus came from this alert's IP."""
    global _hits_cache
    if _hits_cache is None:
        try:
            from core.preprocessor import load_alerts
            _hits_cache = count_local_hits(load_alerts())
        except Exception:
            # No corpus available (for example, somebody else is calling our
            # agent with their own alert). Degrade to zero rather than fail:
            # the local reputation source simply contributes nothing.
            _hits_cache = {}
    return _hits_cache.get(alert.src_ip or "", 0)


async def hunter_node(state: SOCState) -> dict:
    """Enrich the alert, over A2A or locally, and record the whole journey."""
    alert = state["alert"]
    hits = local_hits_for(alert)

    events = [
        make_event(
            NODE, "node_start",
            f"Hunting {alert.id} (local hits for its IP: {hits})",
            transport="a2a" if A2A_MODE else "local",
        )
    ]
    usage_records: list[dict] = []
    started = time.perf_counter()

    try:
        if A2A_MODE:
            # --- Over the network ------------------------------------------
            events.append(make_event(NODE, "a2a_call",
                                     "Calling the hunter agent over A2A",
                                     agent="hunter"))

            # `mode="json"` turns dates and Enums into plain JSON values,
            # which is required before the object can travel over the wire.
            request = HuntRequest(alert=alert.model_dump(mode="json"),
                                  local_hits=hits)
            response = await call_agent("hunter", request.model_dump_json())

            for observation in response["observations"]:
                events.append(make_event(
                    NODE, "a2a_task",
                    f"{observation['stage']}: {observation['detail']}",
                    task_id=response["task_id"]))

            result = HuntResult.model_validate_json(response["result_json"])

            events.append(make_event(NODE, "a2a_task",
                                     f"A2A task {response['final_state']}",
                                     task_id=response["task_id"],
                                     agent=response["agent_name"]))

            # Read the token counts the agent attached to its artifact, so
            # the metrics are real in A2A mode too, not only locally.
            # A2A metadata is all strings, so we convert back to numbers.
            remote = response.get("metadata") or {}
            input_tokens = int(remote.get("input_tokens", 0) or 0)
            output_tokens = int(remote.get("output_tokens", 0) or 0)
            if input_tokens or output_tokens:
                events.append(make_event(
                    NODE, "llm_call",
                    f"Remote LLM {remote.get('llm_mode', '?')}: "
                    f"{input_tokens} in + {output_tokens} out",
                    cost_usd=remote.get("cost_usd")))
                usage_records.append(make_usage(
                    NODE, input_tokens, output_tokens,
                    remote.get("llm_model", "remote")))
            if remote.get("fallback_reason"):
                events.append(make_event(
                    NODE, "error",
                    f"Remote LLM fallback: {remote['fallback_reason'][:120]}"))

        else:
            # --- In this process -------------------------------------------
            events.append(make_event(NODE, "tool_call", "Running hunt() locally"))
            result, meta = hunt(alert, local_hits=hits)

            usage = meta.get("usage")
            if usage:
                events.append(make_event(
                    NODE, "llm_call",
                    f"LLM {usage['mode']}: {usage['input_tokens']} in + "
                    f"{usage['output_tokens']} out",
                    model=usage["model"],
                    cost_usd=round(cost_usd(usage["model"],
                                            usage["input_tokens"],
                                            usage["output_tokens"]), 6)))
                usage_records.append(make_usage(NODE, usage["input_tokens"],
                                                usage["output_tokens"],
                                                usage["model"]))
            if meta.get("fallback_reason"):
                events.append(make_event(
                    NODE, "error",
                    f"LLM fallback: {meta['fallback_reason'][:120]}"))

    except (A2ACallFailed, ValueError) as error:
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        events.append(make_event(NODE, "error", f"Hunt failed: {error}",
                                 elapsed_ms=elapsed_ms))
        return {"hunt_result": None, "events": events, "errors": [str(error)]}

    # One log line per finding. THIS is what proves to a viewer that the
    # tools really ran: a verdict with its sources, a technique with its
    # tactic. A claim without a visible tool call is just a claim.
    for ioc in result.iocs:
        events.append(make_event(NODE, "tool_call",
                                 f"Enriched {ioc.headline()}",
                                 sources=ioc.sources))
    for technique in result.techniques:
        events.append(make_event(NODE, "tool_call",
                                 f"Mapped to MITRE {technique.headline()}",
                                 tactic=technique.tactic))

    elapsed_ms = round((time.perf_counter() - started) * 1000)
    events.append(make_event(
        NODE, "node_end",
        f"Threat score {result.threat_score}/100, "
        f"worst verdict {result.worst_verdict.value}",
        threat_score=result.threat_score,
        iocs=len(result.iocs),
        techniques=len(result.techniques),
        elapsed_ms=elapsed_ms))

    update: dict = {"hunt_result": result, "events": events}
    # Only include token_usage if there is something to add. An empty list
    # would still trigger the reducer — harmlessly, but pointlessly.
    if usage_records:
        update["token_usage"] = usage_records
    return update