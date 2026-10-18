"""
test_graph.py
=============
Everything the graph claims, checked.

  Part 1  the shape, as Mermaid (paste it into the README)
  Part 2  the routers, called directly with no graph at all
  Part 3  an escalating alert pauses, then resumes with the human's answer
  Part 4  a quiet alert must NOT pause
  Part 5  skipping the hunter must NOT block the reporter   <- the gotcha
  Part 6  a nonsense human answer must fail SAFE
  Part 7  the checkpoint trail, including the parallel step

Run it with warnings as errors to prove the strict checkpoint allowlist is
complete:
    python -W error::UserWarning test_graph.py
"""

import asyncio

from langgraph.types import Command

from core.config import describe
from core.models import Alert
from core.preprocessor import load_alerts
from core.state import initial_state
from graph import build_graph, route_after_report, route_after_triage
from tools import history, scenarios


def quiet_alert(alert_id: str, src_ip: str | None) -> Alert:
    """An alert that nothing should escalate. `Log file rotated.` maps to
    AttackStage.NotApplicable, so no agent raises a signal."""
    return Alert(id=alert_id, timestamp="2030-03-01T00:00:00+00:00",
                 rule_id="1", rule_level=3,
                 rule_description="Log file rotated.",
                 agent_name="quiet-host", src_ip=src_ip, raw={})


async def main() -> None:
    alerts = load_alerts()
    history.build(alerts)
    scenarios.install()
    graph = build_graph()
    print(f"CONFIG: {describe()}")

    print()
    print("=" * 74)
    print("PART 1 - THE GRAPH SHAPE")
    print("=" * 74)
    # Mermaid is plain text, so it needs no extra package - unlike the ASCII
    # drawing, which wants `grandalf` installed.
    print(graph.get_graph().draw_mermaid())

    print("=" * 74)
    print("PART 2 - THE ROUTERS, CALLED DIRECTLY")
    print("=" * 74)
    # A router is a plain function of state. Testing it needs no graph, no
    # server and no network - which is exactly why routing logic lives in
    # functions rather than inside the nodes.
    with_ip = quiet_alert("R-1", "203.0.113.9")
    without = quiet_alert("R-2", None)
    print(f"  src_ip present -> {route_after_triage({'alert': with_ip})}")
    print(f"  src_ip absent  -> {route_after_triage({'alert': without})}")
    print(f"  escalate True  -> {route_after_report({'escalate': True})}")
    print(f"  escalate False -> {route_after_report({'escalate': False})}")

    print()
    print("=" * 74)
    print("PART 3 - AN ESCALATING ALERT: PAUSE, THEN RESUME")
    print("=" * 74)
    focus = scenarios.lateral_movement_incident()[2]
    config = {"configurable": {"thread_id": "test-escalate"}}
    first = await graph.ainvoke(initial_state(focus), config=config)
    paused = "__interrupt__" in first
    print(f"  escalate       : {first['escalate']}")
    print(f"  interrupted    : {paused}   (must be True)")
    # Must be None: the hitl node never finished, so it wrote nothing.
    print(f"  human_decision : {first['human_decision']}   (must be None)")
    if paused:
        pause = first["__interrupt__"][0].value
        print(f"  signals shown  : {pause['escalation_signals']}")
        print(f"  overridden     : {pause['overridden_triage']}")

    final = await graph.ainvoke(
        Command(resume={"decision": "approved", "decided_by": "b.karim",
                        "note": "contained db-01"}),
        config=config)
    print(f"  after resume   : {final['human_decision'].headline()}")
    print(f"  note kept      : {final['human_decision'].note!r}")

    print()
    print("=" * 74)
    print("PART 4 - A QUIET ALERT MUST NOT PAUSE")
    print("=" * 74)
    config2 = {"configurable": {"thread_id": "test-quiet"}}
    result = await graph.ainvoke(initial_state(quiet_alert("Q-1", "203.0.113.9")),
                                 config=config2)
    print(f"  escalate       : {result['escalate']}   (must be False)")
    print(f"  interrupted    : {'__interrupt__' in result}   (must be False)")
    print(f"  human_decision : {result['human_decision']}   (must be None)")
    print(f"  report written : {len(result['report'] or '')} characters")

    print()
    print("=" * 74)
    print("PART 5 - NO SOURCE IP: SKIP THE HUNTER, STILL REPORT")
    print("=" * 74)
    # THE CLASSIC GOTCHA. The reporter has incoming edges from BOTH hunter
    # and forensics. If a skipped branch blocked the join, the reporter
    # would never run and the graph would silently stop.
    config3 = {"configurable": {"thread_id": "test-noip"}}
    result = await graph.ainvoke(initial_state(quiet_alert("N-1", None)),
                                 config=config3)
    ran = sorted({event["node"] for event in result["events"]})
    print(f"  nodes that ran : {ran}")
    print(f"  hunter skipped : {'hunter' not in ran}   (must be True)")
    print(f"  reporter ran   : {'reporter' in ran}   (must be True)")
    print(f"  hunt_result    : {result['hunt_result']}   (must be None)")

    print()
    print("=" * 74)
    print("PART 6 - A NONSENSE HUMAN ANSWER MUST FAIL SAFE")
    print("=" * 74)
    config4 = {"configurable": {"thread_id": "test-nonsense"}}
    await graph.ainvoke(initial_state(focus), config=config4)
    result = await graph.ainvoke(Command(resume="maybe later"), config=config4)
    decision = result["human_decision"]
    print(f"  decision       : {decision.decision.value}   (must be escalated)")
    print(f"  note explains  : {decision.note[:60]}")

    print()
    print("=" * 74)
    print("PART 7 - THE CHECKPOINT TRAIL")
    print("=" * 74)
    # History comes back newest-first, so it is reversed to read forwards.
    snapshots = []
    async for snapshot in graph.aget_state_history(config):
        snapshots.append(snapshot.next or ("END",))
    for index, step in enumerate(reversed(snapshots), start=1):
        print(f"  {index:>2}  next -> {step}")
    print(f"  snapshots      : {len(snapshots)}")
    # A step with TWO node names in it is the parallel fan-out, visible in
    # the checkpoint rather than merely asserted in a comment.
    parallel = any(len(step) == 2 for step in snapshots)
    print(f"  a parallel step: {parallel}   (hunter and forensics together)")


asyncio.run(main())