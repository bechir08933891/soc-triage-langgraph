"""
test_pipeline.py
================
Runs all four agents in sequence over ONE alert, in whichever transport the
environment selects.

The point is not that it passes - it is that the two transports produce the
SAME results. That is what makes "the agents speak A2A" a measurable claim
rather than a decoration.

Run it twice:
    set SOC_A2A_MODE=1   (needs run_agents.py in another window)
    set SOC_A2A_MODE=0   (no server needed)
"""

import asyncio
import os

from core.preprocessor import load_alerts
from tools import history, scenarios


async def run_one(alert, label):
    # Imported INSIDE the function, AFTER the environment variable is read,
    # so the nodes see the transport we chose for this run. Importing at the
    # top of the file would freeze A2A_MODE before the test could set it.
    from core.config import describe
    from core.state import initial_state
    from nodes.forensics_node import forensics_node
    from nodes.hunter_node import hunter_node
    from nodes.reporter_node import reporter_node
    from nodes.triage_node import triage_node

    print("=" * 74)
    print(f"  {label}   ({describe()})")
    print("=" * 74)

    state = initial_state(alert)
    # Sequential by hand. Step 18 replaces this loop with the real LangGraph
    # graph, which can run hunter and forensics in parallel.
    for node in (triage_node, hunter_node, forensics_node, reporter_node):
        update = await node(state)
        state.update(update)
        for event in update.get("events", []):
            print(f"  [{event['node']:<9}] {event['kind']:<11} "
                  f"{event['message'][:72]}")
        print()

    triage = state.get("triage_result")
    hunt = state.get("hunt_result")
    forensics = state.get("forensics_result")
    document = state.get("report")

    print("  RESULTS")
    print(f"    triage    : {triage.headline() if triage else 'FAILED'}")
    if hunt:
        print(f"    hunter    : score {hunt.threat_score}/100, "
              f"{len(hunt.iocs)} ioc(s), worst {hunt.worst_verdict.value}")
    else:
        print("    hunter    : FAILED")
    if forensics:
        own = sum(1 for e in forensics.timeline if e.same_actor)
        print(f"    forensics : {forensics.attack_stage.value}, "
              f"{len(forensics.timeline)} events ({own} this actor), "
              f"lateral={forensics.lateral_movement} "
              f"spread={forensics.horizontal_spread}")
    else:
        print("    forensics : FAILED")
    print("    report    : "
          + (f"{len(document)} characters" if document else "FAILED"))
    tokens = sum(u["total_tokens"] for u in state.get("token_usage", []))
    print(f"    tokens    : {tokens}")
    print(f"    errors    : {state.get('errors') or 'none'}")
    print()
    return state


async def main():
    alerts = load_alerts()
    history.build(alerts)
    scenarios.install()
    # The synthetic lateral-movement incident. The real corpus has no
    # lateral movement at all - that is finding 10 - so this is the only
    # alert within reach that exercises every branch.
    alert = scenarios.lateral_movement_incident()[2]
    mode = os.getenv("SOC_A2A_MODE", "1")
    label = "RUN - in process" if mode in ("0", "false", "no", "off") \
        else "RUN - over A2A"
    state = await run_one(alert, label)

    print("=" * 74)
    print("  THE REPORT")
    print("=" * 74)
    print(state.get("report") or "(no report)")


asyncio.run(main())