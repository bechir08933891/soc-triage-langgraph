"""
test_forensics.py
=================
Builds the history database and measures the forensics detector across the
whole corpus.

The number that matters is the lateral-movement rate. If it is close to
100%, the detector is broken: it would be claiming every scanned network is
breached.
"""

from collections import Counter

from core.preprocessor import load_alerts
from tools import history
from tools.forensics import investigate

print("=" * 74)
print("PART 1 - HOST NAME RECOVERY")
print("=" * 74)
alerts = load_alerts()
hosts = Counter(a.agent_name for a in alerts)
print(f"  alerts         : {len(alerts)}")
print(f"  distinct hosts : {len(hosts)}")
for host, count in hosts.most_common(10):
    print(f"    {host:<26}{count:>5}")

real = sum(count for host, count in hosts.items()
           if host not in ("xxx", "unknown-host"))
print()
print(f"  with a real host name : {real}/{len(alerts)} = {real/len(alerts):.1%}")

print()
print("=" * 74)
print("PART 2 - BUILDING THE HISTORY DATABASE")
print("=" * 74)
written = history.build(alerts)
print(f"  rows written : {written}")
print(f"  row count    : {history.row_count()}")

print()
print("=" * 74)
print("PART 3 - MULTI-HOST PATTERNS ACROSS THE CORPUS")
print("=" * 74)
lateral, spread, neither = [], [], []
stages = Counter()
for alert in alerts:
    result, meta = investigate(alert)
    stages[result.attack_stage.value] += 1
    if result.lateral_movement:
        lateral.append((alert, result, meta))
    elif result.horizontal_spread:
        spread.append((alert, result, meta))
    else:
        neither.append(alert)

total = len(alerts)
print(f"  lateral movement  : {len(lateral):>4}  ({len(lateral)/total:.1%})")
print(f"  horizontal spread : {len(spread):>4}  ({len(spread)/total:.1%})")
print(f"  neither           : {len(neither):>4}  ({len(neither)/total:.1%})")
print()
print("  ATTACK STAGES")
for stage, count in stages.most_common():
    print(f"    {stage:<26}{count:>5}")

print()
print("=" * 74)
print("PART 4 - THE LATERAL MOVEMENT CASES (if any)")
print("=" * 74)
if not lateral:
    print("  None found. On this corpus that may be correct — see finding 3:")
    print("  no alert reaches High severity, and most traffic is scanning.")
else:
    # A set of the users involved, so we do not print the same one 50 times.
    seen = set()
    for alert, result, meta in lateral:
        if alert.user in seen:
            continue
        seen.add(alert.user)
        print(f"  user={alert.user}  successes={meta['successes']}")
        print(f"    {meta['lateral_signals'][0]}")
        print(f"    hosts: {', '.join(result.affected_hosts)}")
        print()

print("=" * 74)
print("PART 5 - ONE FULL TIMELINE")
print("=" * 74)
sample = (lateral or spread or [(alerts[0], *investigate(alerts[0]))])[0]
alert, result, meta = sample
print(f"  focus alert : {alert.id}  {alert.rule_description[:40]}")
print(f"  stage       : {result.attack_stage.value}  ({meta['stage_reason']})")
print(f"  lateral     : {result.lateral_movement}")
print(f"  spread      : {result.horizontal_spread}")
print(f"  hosts       : {', '.join(result.affected_hosts) or 'none'}")
print()
print("  TIMELINE (>> marks the alert under investigation)")
for event in result.timeline[:12]:
    print(f"    {event.headline()[:88]}")
print()
print("  ANALYSIS")
print(f"    {result.analysis}")