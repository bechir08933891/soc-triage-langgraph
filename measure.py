"""
measure.py
==========
Two measurements the single-run tests cannot give you.

PART A - TRANSPORT OVERHEAD
    Times the TRIAGE node, which uses no language model at all. With the LLM
    out of the picture, what remains is the pure cost of the transport.
    Run this script twice, once per SOC_A2A_MODE, and compare the medians.

PART B - REPRODUCIBILITY
    Runs the same alert through the deterministic scorer and through the LLM
    several times, and reports the spread of each. A claim of
    reproducibility needs a number, not an assertion.
"""

import asyncio
import statistics as stats
import time

from langgraph.graph import END, START, StateGraph

from core.config import A2A_MODE, describe
from core.llm import llm_available, temperature_is_pinned
from core.preprocessor import load_alerts
from core.state import SOCState, initial_state
from nodes.hunter_node import local_hits_for
from nodes.triage_node import triage_node
from tools.hunter import hunt
from tools.severity import assign_severity

RUNS_TRANSPORT = 10
RUNS_LLM = 8          # about $0.001 in total

print("=" * 72)
print("MEASUREMENT")
print("=" * 72)
print(f"  {describe()}")
print(f"  LLM available     : {llm_available()}")
print(f"  temperature pinned: {temperature_is_pinned()}")

alerts = load_alerts()
alert = next(a for a in alerts if a.src_ip and "non-existent" in a.rule_description)
hits = local_hits_for(alert)
print(f"  alert             : {alert.id} (IP seen {hits} times)")

# A one-node graph. Triage is deterministic, so whatever time this takes
# beyond a millisecond IS the transport.
builder = StateGraph(SOCState)
builder.add_node("triage", triage_node)
builder.add_edge(START, "triage")
builder.add_edge("triage", END)
graph = builder.compile()


async def part_a() -> None:
    print()
    print("=" * 72)
    print(f"PART A - TRANSPORT OVERHEAD  ({RUNS_TRANSPORT} runs, no LLM involved)")
    print("=" * 72)

    # One warm-up run first. The very first call pays for connection setup
    # and imports, which would distort the median.
    await graph.ainvoke(initial_state(alert))

    timings = []
    for _ in range(RUNS_TRANSPORT):
        started = time.perf_counter()
        await graph.ainvoke(initial_state(alert))
        timings.append((time.perf_counter() - started) * 1000)

    label = "A2A" if A2A_MODE else "in-process"
    print(f"  transport : {label}")
    # The MEDIAN, not the mean: one slow outlier drags a mean around, while
    # the median shows the typical case.
    print(f"  median    : {stats.median(timings):7.1f} ms")
    print(f"  mean      : {stats.mean(timings):7.1f} ms")
    print(f"  min / max : {min(timings):7.1f} / {max(timings):.1f} ms")
    if len(timings) > 1:
        print(f"  stdev     : {stats.stdev(timings):7.1f} ms")
    print()
    print("  Run again with the other SOC_A2A_MODE and compare the medians.")


def part_b() -> None:
    print()
    print("=" * 72)
    print(f"PART B - REPRODUCIBILITY  (same alert, {RUNS_LLM} runs)")
    print("=" * 72)

    # A SET keeps only unique values, so its length is the number of
    # distinct answers. For a deterministic function that must be 1.
    rule_scores = [assign_severity(alert).score for _ in range(500)]
    distinct = len(set(rule_scores))
    print(f"  Deterministic scorer, 500 runs")
    print(f"    distinct results : {distinct}")
    print(f"    score            : {rule_scores[0]}")

    if not llm_available():
        print()
        print("  LLM not available, so the LLM half is skipped.")
        return

    print()
    print(f"  LLM threat score, {RUNS_LLM} runs")
    scores, used = [], 0
    for index in range(RUNS_LLM):
        result, meta = hunt(alert, local_hits=hits)
        scores.append(result.threat_score)
        used += 1 if meta["llm_used"] else 0
        print(f"    run {index + 1}: {result.threat_score}", end="")
        if not meta["llm_used"]:
            print("  (fallback)", end="")
        print()

    print()
    print(f"    LLM really used  : {used}/{RUNS_LLM}")
    print(f"    distinct results : {len(set(scores))}")
    print(f"    mean             : {stats.mean(scores):.1f}")
    print(f"    min / max        : {min(scores)} / {max(scores)}  "
          f"(range {max(scores) - min(scores)})")
    if len(scores) > 1:
        # Standard deviation: the typical distance from the mean. A larger
        # number means the model's answers are more scattered.
        print(f"    stdev            : {stats.stdev(scores):.2f}")
    print()
    if temperature_is_pinned():
        print("    temperature was pinned to 0.")
    else:
        print("    temperature could NOT be pinned: this model rejects a")
        print("    non-default value, so the spread above is expected.")


asyncio.run(part_a())
part_b()