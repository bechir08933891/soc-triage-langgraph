"""Finding 18: routing, the human gate, and the checkpoint allowlist."""
from __future__ import annotations

import asyncio

import pytest
from langgraph.graph import END
from langgraph.types import Command

from core.contracts import Decision
from core.models import Alert
from core.state import initial_state
from graph import (CHECKPOINT_TYPES, build_graph, make_serializer,
                   route_after_report, route_after_triage)


def run(coroutine):
    """Streamlit and pytest are both synchronous; the graph is not.

    asyncio.run is safe here because neither runner holds an event loop.
    """
    return asyncio.run(coroutine)


@pytest.fixture(scope="module")
def graph():
    return build_graph()


def quiet(alert_id="Q-1", src_ip="203.0.113.9"):
    """An alert nothing should escalate: 'Log file rotated.' maps to
    AttackStage.NotApplicable, so no agent raises a signal."""
    return Alert(id=alert_id, timestamp="2030-03-01T00:00:00+00:00",
                 rule_id="1", rule_level=3,
                 rule_description="Log file rotated.",
                 agent_name="quiet-host", src_ip=src_ip, raw={})


# --- The routers, with no graph at all --------------------------------------

def test_an_alert_with_an_address_reaches_both_agents():
    assert route_after_triage({"alert": quiet()}) == ["hunter", "forensics"]


def test_an_alert_without_an_address_skips_the_hunter():
    """Nothing to look up. An honest saving, not a guess about severity."""
    assert route_after_triage({"alert": quiet(src_ip=None)}) == ["forensics"]


@pytest.mark.parametrize("escalate,destination", [(True, "hitl"), (False, END)])
def test_the_gate_routes_on_state_not_on_prose(escalate, destination):
    """A router that searched the Markdown for 'ESCALATE' would break the
    first time the wording changed."""
    assert route_after_report({"escalate": escalate}) == destination


# --- Finding 18: the checkpoint is an untrusted file ------------------------

def test_the_serializer_is_strict():
    serde = make_serializer()
    assert serde._allowed_msgpack_modules is not True


def test_every_state_type_is_allow_listed():
    """A type missing from this list cannot be read back, so a paused run
    would silently fail to resume."""
    names = {cls.__name__ for cls in CHECKPOINT_TYPES}
    assert {"Alert", "TriageResult", "HuntResult", "ForensicsResult",
            "HumanDecision", "TimelineEvent", "IncidentReport"} <= names


def test_a_paused_run_resumes_without_warnings(graph, built_history):
    """pytest.ini promotes UserWarning to an error, so an unlisted type
    deserialised from a checkpoint fails this test."""
    from tools import scenarios
    alert = scenarios.lateral_movement_incident()[2]
    config = {"configurable": {"thread_id": "test-resume"}}

    first = run(graph.ainvoke(initial_state(alert), config=config))
    assert first["escalate"] is True
    assert "__interrupt__" in first
    # The node never finished, so it wrote nothing.
    assert first["human_decision"] is None

    pause = first["__interrupt__"][0].value
    assert pause["escalation_signals"]
    assert pause["overridden_triage"] is True

    final = run(graph.ainvoke(
        Command(resume={"decision": "approved", "decided_by": "b.karim",
                        "note": "contained db-01"}),
        config=config))
    assert final["human_decision"].decision is Decision.APPROVED
    assert final["human_decision"].note == "contained db-01"


# --- The behaviours that fail silently when they are wrong ------------------

def test_a_quiet_alert_never_pauses(graph, built_history):
    """A gate that always appears is not a gate."""
    config = {"configurable": {"thread_id": "test-quiet"}}
    state = run(graph.ainvoke(initial_state(quiet()), config=config))
    assert state["escalate"] is False
    assert "__interrupt__" not in state
    assert state["human_decision"] is None
    assert state["report"]


def test_a_skipped_branch_does_not_block_the_join(graph, built_history):
    """THE CLASSIC GOTCHA. The reporter has incoming edges from both hunter
    and forensics; if a skipped branch blocked it, the graph would stop."""
    config = {"configurable": {"thread_id": "test-noip"}}
    state = run(graph.ainvoke(initial_state(quiet("N-1", None)), config=config))
    ran = {event["node"] for event in state["events"]}
    assert "hunter" not in ran
    assert "reporter" in ran
    assert state["hunt_result"] is None
    assert state["report"]


def test_an_unreadable_answer_fails_safe(graph, built_history):
    """'I did not understand you' must never silently mean 'go ahead'."""
    from tools import scenarios
    alert = scenarios.lateral_movement_incident()[4]
    config = {"configurable": {"thread_id": "test-nonsense"}}
    run(graph.ainvoke(initial_state(alert), config=config))
    state = run(graph.ainvoke(Command(resume="maybe later"), config=config))
    assert state["human_decision"].decision is Decision.ESCALATED
    assert "unrecognised" in state["human_decision"].note


def test_hunter_and_forensics_share_a_step(graph, built_history):
    """The parallel fan-out, read out of the checkpoint rather than asserted."""
    from tools import scenarios
    config = {"configurable": {"thread_id": "test-parallel"}}
    run(graph.ainvoke(initial_state(scenarios.lateral_movement_incident()[2]),
                      config=config))

    async def steps():
        return [snapshot.next async for snapshot
                in graph.aget_state_history(config)]

    assert any(len(step) == 2 for step in run(steps()))