"""
nodes/reporter_node.py
======================
The LangGraph node for report writing. Agent 4 of 5.

    reads   : alert, triage_result, hunt_result, forensics_result
    writes  : report, events, token_usage, (errors on failure)

It is the only node that reads other nodes' output, so it is the only one
that can be called with pieces missing - and it says which pieces, out
loud, in the log.

It also logs the sentence that justifies the architecture:
"Triage alone would have auto-closed this alert."
"""

from __future__ import annotations

import time

from core.config import A2A_MODE
from core.contracts import IncidentReport, ReportRequest
from core.state import SOCState, make_event, make_usage
from nodes.a2a_client import A2ACallFailed, call_agent
from tools.reporter import report

NODE = "reporter"


def _dump(model):
    """A finding as plain JSON, or None if the agent never answered.

    `mode="json"` turns dates and Enums into plain values, which is required
    before an object can travel over the wire. None must STAY None: an empty
    dictionary would mean "it answered, with nothing".
    """
    return model.model_dump(mode="json") if model is not None else None


async def reporter_node(state: SOCState) -> dict:
    """Write the report, over A2A or locally, and record the decision."""
    alert = state["alert"]
    triage = state.get("triage_result")
    hunt = state.get("hunt_result")
    forensics = state.get("forensics_result")

    missing = [name for name, value in (("triage", triage), ("hunt", hunt),
                                        ("forensics", forensics))
               if value is None]

    events = [
        make_event(
            NODE, "node_start",
            f"Writing the report for {alert.id}"
            + (f" (missing: {', '.join(missing)})" if missing else ""),
            transport="a2a" if A2A_MODE else "local",
            missing=missing,
        )
    ]
    usage_records: list[dict] = []
    started = time.perf_counter()

    try:
        if A2A_MODE:
            # --- Over the network ------------------------------------------
            events.append(make_event(NODE, "a2a_call",
                                     "Calling the reporter agent over A2A",
                                     agent="reporter"))
            request = ReportRequest(
                alert=alert.model_dump(mode="json"),
                triage_result=_dump(triage),
                hunt_result=_dump(hunt),
                forensics_result=_dump(forensics))
            response = await call_agent("reporter", request.model_dump_json())

            for observation in response["observations"]:
                events.append(make_event(
                    NODE, "a2a_task",
                    f"{observation['stage']}: {observation['detail']}",
                    task_id=response["task_id"]))

            document = IncidentReport.model_validate_json(response["result_json"])

            events.append(make_event(NODE, "a2a_task",
                                     f"A2A task {response['final_state']}",
                                     task_id=response["task_id"],
                                     agent=response["agent_name"]))

            # The decision comes back as METADATA, not parsed out of the
            # Markdown. A router must never read a document to find a flag.
            # A2A metadata is all strings, so they are converted back here.
            remote = response.get("metadata") or {}
            escalate = str(remote.get("escalate", "False")) == "True"
            overridden = str(remote.get("overridden_triage", "False")) == "True"
            signals = remote.get("signals", "none")

            input_tokens = int(remote.get("input_tokens", 0) or 0)
            output_tokens = int(remote.get("output_tokens", 0) or 0)
            if input_tokens or output_tokens:
                events.append(make_event(
                    NODE, "llm_call",
                    f"Remote LLM {remote.get('llm_mode', '?')}: "
                    f"{input_tokens} in + {output_tokens} out",
                    cost_usd=remote.get("cost_usd"),
                    summary_confidence=remote.get("summary_confidence")))
                usage_records.append(make_usage(
                    NODE, input_tokens, output_tokens,
                    remote.get("llm_model", "remote")))
            if remote.get("fallback_reason"):
                events.append(make_event(
                    NODE, "error",
                    f"Remote LLM fallback: {remote['fallback_reason'][:120]}"))

        else:
            # --- In this process -------------------------------------------
            events.append(make_event(NODE, "tool_call",
                                     "Running report() locally"))
            document, meta = report(alert, triage=triage, hunt=hunt,
                                    forensics=forensics)
            escalate = meta["escalate"]
            overridden = meta["overridden_triage"]
            signals = "; ".join(meta["signals"]) or "none"

            usage = meta.get("usage")
            if usage:
                events.append(make_event(
                    NODE, "llm_call",
                    f"LLM {usage['mode']}: {usage['input_tokens']} in + "
                    f"{usage['output_tokens']} out",
                    model=usage["model"],
                    cost_usd=round(float(usage.get("cost_usd", 0.0)), 6),
                    summary_confidence=meta.get("confidence")))
                usage_records.append(make_usage(NODE, usage["input_tokens"],
                                                usage["output_tokens"],
                                                usage["model"]))
            if meta.get("fallback_reason"):
                events.append(make_event(
                    NODE, "error",
                    f"LLM fallback: {meta['fallback_reason'][:120]}"))

    except (A2ACallFailed, ValueError) as error:
        # A2ACallFailed = the network or the agent. ValueError = a contract
        # rejected the answer. Both mean "no report", and both are recorded
        # rather than raised, so one failing agent cannot kill the run.
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        events.append(make_event(NODE, "error", f"Report failed: {error}",
                                 elapsed_ms=elapsed_ms))
        return {"report": None, "events": events, "errors": [str(error)]}

    events.append(make_event(NODE, "tool_call",
                             f"Escalation signals: {signals}"))
    # THE SENTENCE. When it appears, the multi-agent design just earned its
    # keep on this alert - and a viewer can watch it happen live.
    if overridden:
        events.append(make_event(
            NODE, "tool_call",
            "Triage alone would have auto-closed this alert"))

    elapsed_ms = round((time.perf_counter() - started) * 1000)
    events.append(make_event(
        NODE, "node_end",
        f"{'ESCALATE' if escalate else 'Auto-close'} - "
        f"report of {document.char_count} characters",
        escalate=escalate,
        overridden_triage=overridden,
        report_chars=document.char_count,
        elapsed_ms=elapsed_ms))

    update: dict = {"report": document.markdown, "events": events}
    # Only include token_usage if there is something to add. An empty list
    # would still trigger the reducer, harmlessly but pointlessly.
    if usage_records:
        update["token_usage"] = usage_records
    return update