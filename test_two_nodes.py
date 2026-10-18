"""
test_two_nodes.py
=================
Two agents collaborating in one graph: triage, then hunter.

The hunter reads nothing from triage directly — it reads the ALERT from the
shared state. But both results end up in the same state, which is what the
reporter agent will later consume.
"""

import asyncio
import time

from langgraph.graph import END, START, StateGraph

from core.config import describe
from core.preprocessor import load_alerts
from core.state import SOCState, initial_state
from nodes.hunter_node import hunter_node
from nodes.triage_node import triage_node

print("CONFIG:", describe())

builder = StateGraph(SOCState)
builder.add_node("triage", triage_node)
builder.add_node("hunter", hunter_node)
builder.add_edge(START, "triage")
builder.add_edge("triage", "hunter")   # the pipeline takes shape
builder.add_edge("hunter", END)
graph = builder.compile()


async def main() -> None:
    alerts = load_alerts()
    # Pick a brute-force alert that has a source IP, so the hunter has
    # something real to enrich.
    alert = next(a for a in alerts if a.src_ip and "non-existent" in a.rule_description)
    print()
    print("=" * 74)
    print(f"ALERT {alert.id}  |  {alert.rule_description[:44]}")
    print("=" * 74)

    started = time.perf_counter()
    final = await graph.ainvoke(initial_state(alert))
    elapsed = time.perf_counter() - started

    print("LIVE LOG - the two agents collaborating:")
    for event in final["events"]:
        print(f"  [{event['node']:<8}][{event['kind']:<10}] {event['message'][:60]}")

    triage = final["triage_result"]
    hunt_result = final["hunt_result"]
    print()
    print("STATE AFTER BOTH AGENTS:")
    print(f"  triage_result : {triage.headline() if triage else 'None'}")
    if hunt_result:
        print(f"  hunt_result   : score {hunt_result.threat_score}/100, "
              f"{len(hunt_result.iocs)} IOC, {len(hunt_result.techniques)} technique(s)")
        print(f"  hypothesis    : {hunt_result.hypothesis[:140]}...")
    tokens = sum(u["total_tokens"] for u in final["token_usage"])
    print(f"  token_usage   : {len(final['token_usage'])} record(s), {tokens} tokens")
    print(f"  errors        : {final['errors'] or 'none'}")
    print(f"TOTAL TIME      : {elapsed*1000:.0f} ms")


asyncio.run(main())