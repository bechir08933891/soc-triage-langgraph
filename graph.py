"""
graph.py
========
The orchestration graph. This is where the five agents become a system.

    START -> triage -> +-> hunter ----+-> reporter -> escalate? -+-> hitl -> END
                       +-> forensics -+                          +--------> END

FOUR DESIGN DECISIONS, each with a reason:

1. HUNTER AND FORENSICS RUN IN PARALLEL.
   They answer different questions - "is this indicator known bad?" and
   "what else happened around it?" - and neither needs the other's answer.
   Running them in one step halves the waiting, and over A2A it means two
   network calls overlap instead of queueing.

2. THE JOIN DOES NOT BLOCK WHEN A BRANCH IS SKIPPED.
   `reporter` has incoming edges from both, but when `route_after_triage`
   sends work only to forensics, the reporter still runs. This is the
   classic graph mistake, and it is tested for in Part 5 of test_graph.py.

3. THE ROUTERS BRANCH ON DATA, NEVER ON PROSE.
   `route_after_report` reads `state["escalate"]`, a boolean the reporter
   computed. A router that searched the Markdown report for the word
   "ESCALATE" would break the first time the wording changed.

4. THE CHECKPOINT SERIALISER IS STRICT.
   A checkpoint is a file. If an attacker can write to it, a permissive
   deserialiser becomes a way to run code. LangGraph's default is
   permissive-with-a-warning and will be blocked in a future version, so
   this file builds the serialiser in STRICT mode and names exactly the
   types our state can contain.
"""

from __future__ import annotations

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph

from core.contracts import (
    AttackStage,
    AttackType,
    Decision,
    ForensicsResult,
    HumanDecision,
    HuntResult,
    IncidentReport,
    IOCEnrichment,
    MitreTechnique,
    Severity,
    SimilarAlert,
    TimelineEvent,
    TriageResult,
    Verdict,
)
from core.models import Alert
from core.state import SOCState
from nodes.forensics_node import forensics_node
from nodes.hitl_node import hitl_node
from nodes.hunter_node import hunter_node
from nodes.reporter_node import reporter_node
from nodes.triage_node import triage_node


# Every type that can appear inside SOCState and therefore inside a
# checkpoint. If you add a field to a contract, nothing changes here; if you
# add a NEW class to the state, add it here or the strict serialiser will
# refuse to read it back.
CHECKPOINT_TYPES = [
    Alert,
    AttackStage,
    AttackType,
    Decision,
    ForensicsResult,
    HumanDecision,
    HuntResult,
    IncidentReport,
    IOCEnrichment,
    MitreTechnique,
    Severity,
    SimilarAlert,
    TimelineEvent,
    TriageResult,
    Verdict,
]


def make_serializer() -> JsonPlusSerializer:
    """A checkpoint serialiser that trusts ONLY our own contracts.

    `allowed_msgpack_modules=None` means strict: only LangGraph's built-in
    safe types. `.with_msgpack_allowlist(...)` then adds ours, by class, so
    a typo in a module name is an import error here instead of a silent
    failure to restore a run.
    """
    return JsonPlusSerializer(
        allowed_msgpack_modules=None
    ).with_msgpack_allowlist(CHECKPOINT_TYPES)


def make_checkpointer() -> InMemorySaver:
    """Where paused runs are stored.

    In memory, so the graph can be interrupted and resumed inside one
    process - enough for the demonstration. Swapping in a database saver is
    a one-line change and needs nothing else in this file to move.
    """
    return InMemorySaver(serde=make_serializer())


# =============================================================================
# THE ROUTERS - plain functions, so they can be tested without a graph
# =============================================================================


def route_after_triage(state: SOCState) -> list[str]:
    """Which agents to run next.

    Returning a LIST is how LangGraph is told to run several nodes in the
    same step. With no source address there is nothing for the hunter to
    look up, so it is skipped - an honest saving, not a guess about
    severity. Forensics always runs: an alert with no IP still has
    neighbours in time.
    """
    alert = state["alert"]
    if alert.src_ip:
        return ["hunter", "forensics"]
    return ["forensics"]


def route_after_report(state: SOCState) -> str:
    """Pause for a human, or finish.

    Reads `escalate`, which the reporter computed from the UNION of every
    agent's signals. Per finding 15 this must never be the triage severity
    alone: triage auto-closed all five alerts of a confirmed intrusion.
    """
    return "hitl" if state.get("escalate") else END


# =============================================================================
# THE GRAPH
# =============================================================================


def build_graph(checkpointer=None):
    """Assemble and compile the graph.

    `checkpointer` is a parameter so a test can supply its own, but the
    default is a real one: without a checkpointer, `interrupt()` has nowhere
    to save progress and cannot resume at all.
    """
    builder = StateGraph(SOCState)

    # One node per agent. The name is what appears in the audit trail and
    # in the drawn diagram, so it matches the node module's NODE constant.
    builder.add_node("triage", triage_node)
    builder.add_node("hunter", hunter_node)
    builder.add_node("forensics", forensics_node)
    builder.add_node("reporter", reporter_node)
    builder.add_node("hitl", hitl_node)

    builder.add_edge(START, "triage")

    # The fan-out. The third argument lists every node the router is allowed
    # to name - LangGraph needs it to draw the diagram and to validate that
    # the router cannot return a node that does not exist.
    builder.add_conditional_edges("triage", route_after_triage,
                                  ["hunter", "forensics"])

    # The join. Two plain edges into one node: the reporter runs once, after
    # whichever of the two branches actually ran.
    builder.add_edge("hunter", "reporter")
    builder.add_edge("forensics", "reporter")

    # The gate. A dictionary maps the router's return value to a node, and
    # END is a legal destination like any other.
    builder.add_conditional_edges("reporter", route_after_report,
                                  {"hitl": "hitl", END: END})
    builder.add_edge("hitl", END)

    return builder.compile(checkpointer=checkpointer or make_checkpointer())