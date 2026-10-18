"""
test_node.py
============
Runs the triage node inside a real one-node LangGraph graph.

Try it both ways:
    set SOC_A2A_MODE=true    -> needs `python run_agents.py` in another window
    set SOC_A2A_MODE=false   -> works alone
"""

import asyncio
import time

from langgraph.graph import END, START, StateGraph

from core.config import describe
from core.preprocessor import load_alerts
from core.state import SOCState, initial_state
from nodes.triage_node import triage_node

print("CONFIG:", describe())
print()

# A real graph, with one real node.
builder = StateGraph(SOCState)
builder.add_node("triage", triage_node)
builder.add_edge(START, "triage")
builder.add_edge("triage", END)
graph = builder.compile()


async def main() -> None:
    alerts = load_alerts(limit=2)
    for alert in alerts:
        print("=" * 70)
        print(f"ALERT {alert.id}  level {alert.rule_level}  {alert.rule_description[:38]}")
        print("=" * 70)

        started = time.perf_counter()
        # `ainvoke` is the async version of `invoke`. Our node is async, so
        # the whole graph must be run this way.
        final = await graph.ainvoke(initial_state(alert))
        elapsed = time.perf_counter() - started

        print("LIVE LOG (what the demo interface will show):")
        for event in final["events"]:
            print(f"  [{event['kind']:<12}] {event['message']}")

        result = final["triage_result"]
        if result:
            print(f"\nRESULT IN STATE: {result.headline()}")
            print(f"  escalate: {result.escalate_to_tier2}")
        else:
            print(f"\nNO RESULT. errors: {final['errors']}")
        print(f"TOTAL TIME: {elapsed*1000:.0f} ms")
        print()


asyncio.run(main())