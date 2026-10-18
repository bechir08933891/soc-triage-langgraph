"""
test_gate.py
============
The escalation gate, measured three ways on the whole corpus.

WHY THREE POLICIES AND NOT ONE: the first gate escalated 76.8% of alerts,
which is worse than useless. The obvious fix - stop escalating on reputation
alone - cuts the volume, but a quieter gate is worthless if it is also
BLIND. So this test measures both halves of the trade-off:

  VOLUME    on the real corpus, where there are no labels
  DETECTION on the labelled synthetic incidents, where the answer is known

A policy is only defensible if it reduces volume AND still catches
DEMO-LM-* (a confirmed intrusion) while still refusing DEMO-GA-* and
DEMO-PS-* (spraying, which is not).

WHY OFFLINE MODE IS REQUIRED, and why it does not weaken the measurement:
OFFLINE_MODE blocks new network calls and the language model. It does NOT
block the threat-intelligence FILE CACHE, so every reputation verdict used
here is the real one. And the model cannot affect this measurement at all:
the decision is computed before any model is contacted, verified identical
across a working model and two injected failures (test_reporter.py Part 2).
"""

import sys
import time
from collections import Counter

from core.config import OFFLINE_MODE
from core.preprocessor import load_alerts
from tools import history, scenarios
from tools.forensics import investigate
from tools.hunter import hunt
from tools.reporter import POLICY_DEFAULT, recommend_escalation
from tools.severity import assign_severity
from tools.threat_intel import count_local_hits


POLICIES = ("any", "corroborate", "triggering")


# A guard, not a warning. Running this by accident with the model enabled
# would cost real money for numbers that do not need it.
if not OFFLINE_MODE:
    print("REFUSING TO RUN.")
    print()
    print("  This test runs ALL THREE agents over every alert in the corpus,")
    print("  three times, once per policy. Without offline mode that means")
    print("  thousands of language-model calls and reputation lookups -")
    print("  minutes of waiting and real money, for numbers that need neither.")
    print()
    print("  Offline mode still reads the threat-intelligence CACHE, so the")
    print("  verdicts are the real ones. It only blocks new network calls and")
    print("  the language model, neither of which affects the decision.")
    print()
    print("  Run it like this:")
    print("      set SOC_OFFLINE_MODE=1")
    print("      python test_gate.py")
    print("      set SOC_OFFLINE_MODE=0")
    sys.exit(1)


alerts = load_alerts()
history.build(alerts)
scenarios.install()
# Counted ONCE for the whole corpus. The hunter cannot work this out from a
# single alert, which is why the caller supplies it.
local_hits = count_local_hits(alerts)

print("=" * 74)
print("THE ESCALATION GATE - THREE POLICIES, MEASURED")
print("=" * 74)
print(f"  alerts        : {len(alerts)}")
print(f"  default policy: {POLICY_DEFAULT}")
print()
print("  any          every signal escalates, reputation included")
print("  corroborate  reputation escalates only alongside another signal")
print("  triggering   reputation never escalates, only informs")
print()

started = time.perf_counter()
# Gather the three findings ONCE per alert, then apply each policy to them.
# Re-running the agents per policy would triple the work for identical input,
# and would also let the policies be compared on different data by accident.
gathered = []
for alert in alerts:
    triage = assign_severity(alert)
    hunt_result, _ = hunt(alert, local_hits=local_hits.get(alert.src_ip or "", 0))
    forensics, _ = investigate(alert)
    gathered.append((alert, triage, hunt_result, forensics))

demo = []
for alert in scenarios.all_demo_alerts():
    triage = assign_severity(alert)
    hunt_result, _ = hunt(alert, local_hits=0)
    forensics, _ = investigate(alert)
    demo.append((alert, triage, hunt_result, forensics))
print(f"  gathered in {time.perf_counter() - started:.1f}s")

print()
print("  VOLUME ON THE REAL CORPUS")
print(f"    {'policy':<14}{'escalated':>12}{'share':>9}{'suppressed':>13}")
total = len(alerts)
for policy in POLICIES:
    escalated = suppressed = 0
    for _, triage, hunt_result, forensics in gathered:
        decision = recommend_escalation(triage, hunt_result, forensics,
                                        policy=policy)
        escalated += bool(decision["escalate"])
        suppressed += bool(decision["suppressed"])
    mark = " <- default" if policy == POLICY_DEFAULT else ""
    print(f"    {policy:<14}{escalated:>12}{escalated/total:>8.1%}"
          f"{suppressed:>13}{mark}")

print()
print("  DETECTION ON THE LABELLED INCIDENTS")
print("    A policy that cuts volume by going blind is worthless. DEMO-LM-*")
print("    is a confirmed intrusion and MUST escalate under every policy.")
print(f"    {'policy':<14}{'LM caught':>11}{'GA caught':>11}{'PS caught':>11}")
for policy in POLICIES:
    caught = Counter()
    for alert, triage, hunt_result, forensics in demo:
        decision = recommend_escalation(triage, hunt_result, forensics,
                                        policy=policy)
        # "DEMO-LM-03" -> "LM"
        family = alert.id.split("-")[1]
        if decision["escalate"]:
            caught[family] += 1
    print(f"    {policy:<14}{caught['LM']:>8}/5{caught['GA']:>10}/3"
          f"{caught['PS']:>10}/3")
print()
print("    GA (generic account sprayed) and PS (spraying, no success) are")
print("    NOT intrusions. Catching them would be a false positive.")

print()
print("  UNDER THE DEFAULT POLICY, WHO RAISED THE SIGNAL")
by_agent = Counter()
signal_text = Counter()
suppressed_why = Counter()
overridden = 0
for _, triage, hunt_result, forensics in gathered:
    decision = recommend_escalation(triage, hunt_result, forensics)
    if decision["overridden_triage"]:
        overridden += 1
    if decision["suppressed"]:
        suppressed_why[decision["suppressed"]] += 1
    for signal in decision["signals"]:
        by_agent[signal.split(":")[0]] += 1
        signal_text[signal] += 1
for agent, count in by_agent.most_common():
    print(f"    {agent:<28}{count:>5}")
print()
print(f"    triage would have CLOSED : {overridden}/{total} "
      f"({overridden/total:.1%})")
print()
print("    THE SIGNALS THEMSELVES")
for text, count in signal_text.most_common(10):
    print(f"      {count:>5}x  {text}")
print()
print("    WHY THE REST WERE CLOSED")
for reason, count in suppressed_why.most_common():
    print(f"      {count:>5}x  {reason}")