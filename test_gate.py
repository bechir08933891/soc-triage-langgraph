"""
test_gate.py
============
The complete escalation gate: all three agents, every alert in the corpus.

WHY OFFLINE MODE IS REQUIRED, and why it does not weaken the measurement:

  OFFLINE_MODE blocks new network calls and the language model. It does NOT
  block the threat-intelligence FILE CACHE, so every reputation verdict used
  here is the real one fetched earlier - including the malicious verdicts.

  And the language model cannot affect this measurement at all: the
  escalation decision is computed by `recommend_escalation` before any model
  is contacted, and was verified identical across a working model, an
  LLMUnavailable and an injected KeyError (test_reporter.py, Part 2).

  So offline mode costs nothing and saves 738 model calls.

The number this test exists to produce is "triage would have CLOSED". Those
are alerts a single-agent system auto-closes and this one escalates.
"""

import sys
import time
from collections import Counter

from core.config import OFFLINE_MODE
from core.preprocessor import load_alerts
from tools import history
from tools.forensics import investigate
from tools.hunter import hunt
from tools.reporter import recommend_escalation
from tools.severity import assign_severity
from tools.threat_intel import count_local_hits


# A guard, not a warning. Running this by accident with the model enabled
# would cost real money for numbers that do not need it.
if not OFFLINE_MODE:
    print("REFUSING TO RUN.")
    print()
    print("  This test runs ALL THREE agents over every alert in the corpus.")
    print("  Without offline mode that means hundreds of language-model calls")
    print("  and hundreds of reputation lookups - minutes of waiting and real")
    print("  money, for numbers that do not need either.")
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
# Counted ONCE for the whole corpus. The hunter cannot work this out from a
# single alert, which is why the caller supplies it.
local_hits = count_local_hits(alerts)

print("=" * 74)
print("THE COMPLETE ESCALATION GATE - ALL THREE AGENTS, ALL ALERTS")
print("=" * 74)
print(f"  alerts        : {len(alerts)}")
print("  offline mode  : on (cache yes, network no, language model no)")
print()

started = time.perf_counter()
triage_only = combined = overridden = suppressed = 0
signal_by_agent = Counter()
signal_text = Counter()
winners = Counter()

for alert in alerts:
    triage = assign_severity(alert)
    hunt_result, _ = hunt(alert, local_hits=local_hits.get(alert.src_ip or "", 0))
    forensics, _ = investigate(alert)
    decision = recommend_escalation(triage, hunt_result, forensics)

    if triage.escalate_to_tier2:
        triage_only += 1
    if decision["escalate"]:
        combined += 1
    if decision["overridden_triage"]:
        overridden += 1
        # Which agent rescued this alert from being auto-closed?
        # `signal.split(":")[0]` takes the agent name off the front of
        # "forensics: lateral movement".
        for signal in decision["signals"]:
            winners[signal.split(":")[0]] += 1
    if decision["suppressed"]:
        suppressed += 1
    for signal in decision["signals"]:
        signal_by_agent[signal.split(":")[0]] += 1
        signal_text[signal] += 1

elapsed = time.perf_counter() - started
total = len(alerts)

print(f"  measured in {elapsed:.1f}s")
print()
print("  THE GATE")
print(f"    triage alone escalates    : {triage_only:>4}/{total} "
      f"({triage_only/total:.1%})")
print(f"    all three agents escalate : {combined:>4}/{total} "
      f"({combined/total:.1%})")
print(f"    triage would have CLOSED  : {overridden:>4}/{total} "
      f"({overridden/total:.1%})")
print(f"    explicitly suppressed     : {suppressed:>4}/{total} "
      f"({suppressed/total:.1%})")

print()
print("  WHICH AGENT RAISED THE SIGNAL")
for agent, count in signal_by_agent.most_common():
    print(f"    {agent:<12}{count:>5}")

print()
print("  WHICH AGENT RESCUED AN ALERT TRIAGE WOULD HAVE CLOSED")
# This is the table that answers "was the second agent worth building?"
# per agent, rather than for the architecture as a whole.
for agent, count in winners.most_common():
    print(f"    {agent:<12}{count:>5}")

print()
print("  THE SIGNALS THEMSELVES")
for text, count in signal_text.most_common(12):
    print(f"    {count:>5}x  {text}")