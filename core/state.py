"""
core/state.py
=============
SOCState — the single shared box of information for the whole graph.

Everything an agent knows, it knows because it is in this box. Nothing is
hidden in global variables or private agent memory. That property is what
makes the run auditable.

Two kinds of field:

* REPLACED fields (`triage_result`, `report`, ...)
  The last writer wins. Each is written by exactly one agent, so there is
  never any ambiguity.

* ACCUMULATED fields (`events`, `token_usage`, `errors`)
  Marked with `operator.add`. An agent returning {"events": [e]} ADDS to the
  list instead of replacing it. This is how the audit trail builds itself.
"""

from __future__ import annotations

# `operator` holds Python's basic operations as functions.
# `operator.add` is the `+` sign in function form. For two lists,
# [1, 2] + [3] gives [1, 2, 3] — exactly the "keep everything" behaviour.
import operator

from datetime import datetime, timezone

# `Annotated` attaches extra information to a type.
#    Annotated[list[dict], operator.add]
# means "a list of dictionaries, AND here is the rule for combining two of
# them". LangGraph reads that attached rule. This is how a reducer is declared.
#
# `TypedDict` is a dictionary whose keys and value types are written down in
# advance. At runtime it is a normal dict, but your editor and LangGraph both
# know what belongs inside.
#
# `Literal` means "only these exact words are allowed" — a mini Enum.
from typing import Annotated, Any, Literal, Optional, TypedDict

# Our own contracts from the previous steps.
from core.contracts import ForensicsResult, HumanDecision, HuntResult, TriageResult
from core.models import Alert


# The five agent names, written down once and only once.
# The graph, the interface and the tests all import this, so renaming an agent
# can never leave one part of the project out of step with another.
# Round brackets make a tuple, which cannot be modified.
NODE_NAMES: tuple[str, ...] = ("triage", "hunter", "forensics", "reporter", "hitl")


# The kinds of event our agents may emit. Each drives something visible in
# the demonstration interface.
EventKind = Literal[
    "node_start",   # an agent started        -> its card turns yellow
    "node_end",     # an agent finished       -> its card turns green
    "tool_call",    # a tool was used         -> a log line + the tool counter
    "llm_call",     # the AI was called       -> the token counter moves

    # --- A2A events: these make the protocol VISIBLE in your demo ----------
    "a2a_call",     # we sent a request to an A2A agent
    "a2a_task",     # an A2A task changed state (working, completed, failed)

    "interrupt",    # the human gate opened   -> the approval panel appears
    "resume",       # the human answered      -> the graph continues
    "error",        # an agent failed         -> its card turns red
]


class SOCState(TypedDict, total=False):
    """The shared box of information that flows through the graph.

    `total=False` means no key is strictly required to be present. LangGraph
    needs that freedom, because an agent returns only the few keys it changed,
    not the whole box.
    """

    # --- THE INPUT -----------------------------------------------------------
    # The alert being investigated. Written once at the start, then read-only.
    alert: Alert

    # --- WHAT EACH AGENT PRODUCES (replaced, no reducer) ---------------------
    # `Optional[...]` with a value of None means "empty until that agent runs".
    # Seeing None here tells you immediately which agents have not run yet.
    triage_result: Optional[TriageResult]        # written by agent 1
    hunt_result: Optional[HuntResult]            # written by agent 2
    forensics_result: Optional[ForensicsResult]  # written by agent 3
    report: Optional[str]                        # written by agent 4
    human_decision: Optional[HumanDecision]      # written by agent 5

    # --- WHAT ACCUMULATES (with a reducer) -----------------------------------

    # The audit trail. Every agent ADDS its events here; none can erase them.
    # This single list feeds the live log, the flow chart, and the final proof
    # that the pipeline really did what it says it did.
    events: Annotated[list[dict], operator.add]

    # One record per AI call, so the cost counter is real, not estimated.
    token_usage: Annotated[list[dict], operator.add]

    # Problems that did not stop the pipeline. We collect them rather than
    # crashing: a threat database being down should not kill the whole run.
    errors: Annotated[list[str], operator.add]


# =============================================================================
# SMALL FACTORY FUNCTIONS
#
# These build the little dictionaries that go into the accumulated fields.
# One function per shape means every event in the project looks the same —
# which is what lets all five interface layers read the same stream.
# =============================================================================


def make_event(node: str, kind: EventKind, message: str, **data: Any) -> dict:
    """Build one audit event.

    `**data` collects any extra keyword arguments into a dictionary. So:
        make_event("triage", "a2a_task", "Completed", task_id="1b6a", state="OK")
    puts {"task_id": "1b6a", "state": "OK"} into the `data` field. That lets us
    attach details without ever changing this function.
    """
    return {
        # The exact moment, in UTC.
        # `.isoformat()` makes text like "2026-02-18T10:32:00.123+00:00".
        # `timespec="milliseconds"` keeps three digits after the second —
        # precise enough to order events, short enough to read on screen.
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),

        "node": node,        # which agent
        "kind": kind,        # what type of event
        "message": message,  # the human-readable line shown in the log
        "data": data,        # any extra structured details
    }


def make_usage(node: str, input_tokens: int, output_tokens: int, model: str) -> dict:
    """Build one token-accounting record for the metrics sidebar.

    Tokens are how AI usage is measured and billed. Input tokens are what we
    send; output tokens are what the model writes back.
    """
    return {
        "node": node,
        "model": model,
        # `int(...)` forces a whole number. Some APIs return these as text,
        # and text cannot be added up.
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "total_tokens": int(input_tokens) + int(output_tokens),
    }


def initial_state(alert: Alert) -> SOCState:
    """Build the starting state for one investigation.

    Important: the three accumulated fields MUST start as empty lists. If one
    started as None, the first `None + [event]` would crash the graph.
    """
    return {
        "alert": alert,
        "triage_result": None,
        "hunt_result": None,
        "forensics_result": None,
        "report": None,
        "human_decision": None,
        "events": [],
        "token_usage": [],
        "errors": [],
    }