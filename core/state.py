"""
core/state.py
=============
The shared memory of one run.

LangGraph hands this dictionary to every node, and each node returns ONLY
the keys it changed. LangGraph merges the result. How it merges depends on
the key:

  - a plain key is REPLACED       (the last writer wins)
  - an Annotated key is REDUCED   (the values are combined)

That difference is what makes the parallel step safe. `hunter` and
`forensics` run at the same time and both append to `events`. Without the
reducer, one would overwrite the other and half the audit trail would
vanish. `operator.add` on two lists concatenates them, so both survive.

Rule the whole project follows: `hunt_result` is only ever written by the
hunter, `forensics_result` only by forensics. Two nodes never write the
same plain key in the same step, because there would be no honest way to
choose a winner.
"""

from __future__ import annotations

import operator
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Optional, TypedDict

from core.contracts import ForensicsResult, HumanDecision, HuntResult, TriageResult
from core.models import Alert


# The five agents. The fifth is the human, who needs no web address.
NODE_NAMES: tuple[str, ...] = ("triage", "hunter", "forensics", "reporter", "hitl")

# Every kind of thing that can appear in the audit trail. A Literal means a
# typo like "tool_calls" is caught by the type checker rather than producing
# an event the interface silently refuses to colour.
EventKind = Literal[
    "node_start", "node_end", "tool_call", "llm_call",
    "a2a_call", "a2a_task", "interrupt", "resume", "error",
]


class SOCState(TypedDict, total=False):
    """One run's memory.

    `total=False` means every key is optional, so a node can return a
    dictionary with two keys in it and LangGraph merges just those two.
    """

    # The input. Never modified by anything.
    alert: Alert

    # One field per agent's finding. `Optional` because an agent may fail,
    # and None has to mean "no answer" rather than "an empty answer".
    triage_result: Optional[TriageResult]
    hunt_result: Optional[HuntResult]
    forensics_result: Optional[ForensicsResult]
    report: Optional[str]

    # THE ESCALATION DECISION, as data. The router branches on `escalate`,
    # which the reporter computed from every agent's signals. A router must
    # never have to read a Markdown document to find a flag.
    escalate: Optional[bool]
    escalation_signals: Optional[list[str]]
    overridden_triage: Optional[bool]

    # What the human chose at the gate.
    human_decision: Optional[HumanDecision]

    # THE THREE REDUCED KEYS. `Annotated[list[dict], operator.add]` tells
    # LangGraph: when two nodes both write this, ADD the lists together
    # instead of replacing one with the other.
    events: Annotated[list[dict], operator.add]
    token_usage: Annotated[list[dict], operator.add]
    errors: Annotated[list[str], operator.add]


def make_event(node: str, kind: EventKind, message: str, **data: Any) -> dict:
    """One line in the audit trail.

    `**data` collects any extra keyword arguments into a dictionary, so a
    caller can attach whatever that event needs - tokens, hosts, a task id -
    without this function knowing about any of them.
    """
    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "node": node,
        "kind": kind,
        "message": message,
        "data": data,
    }


def make_usage(node: str, input_tokens: int, output_tokens: int,
               model: str) -> dict:
    """One language-model call, counted. Added up for the cost display."""
    return {
        "node": node,
        "model": model,
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "total_tokens": int(input_tokens) + int(output_tokens),
    }


def initial_state(alert: Alert) -> SOCState:
    """A fresh run.

    Every key is set explicitly, even to None. A key that simply does not
    exist and a key that exists holding None behave differently in
    `state.get(...)` chains, and being explicit removes the question.
    """
    return {
        "alert": alert,
        "triage_result": None,
        "hunt_result": None,
        "forensics_result": None,
        "report": None,
        "escalate": None,
        "escalation_signals": [],
        "overridden_triage": None,
        "human_decision": None,
        "events": [],
        "token_usage": [],
        "errors": [],
    }