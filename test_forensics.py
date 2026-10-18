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

print()
print("=" * 74)
print("PART 6 - THE DETECTOR ON LABELLED SYNTHETIC INCIDENTS")
print("=" * 74)
# Imported here so the earlier parts measure the real corpus only.
from tools import scenarios

added = scenarios.install()
print(f"  synthetic rows added : {added}")
print(f"  database now holds   : {history.row_count()}")
print()
print("  EXPECTED: DEMO-LM-* lateral. DEMO-GA-* and DEMO-PS-* spread only.")
print()
for demo in scenarios.all_demo_alerts():
    result, meta = investigate(demo)
    if result.lateral_movement:
        verdict = "LATERAL"
    elif result.horizontal_spread:
        verdict = "spread"
    else:
        verdict = "neither"
    # The id tells us the right answer, so we can grade ourselves.
    wanted = "LATERAL" if "-LM-" in demo.id else "spread"
    mark = "ok " if verdict == wanted else "BAD"
    print(f"  {mark} {demo.id:<12} {verdict:<8} "
          f"successes={meta['successes']}  stage={result.attack_stage.value}")
    reason = meta["lateral_signals"] or meta["spread_signals"]
    if reason:
        print(f"        {reason[0]}")

print()
print("  Every line must start with 'ok'. A 'BAD' on DEMO-GA or DEMO-PS")
print("  means the detector has become too loose again.")

print()
print("=" * 74)
print("PART 7 - WHICH DESCRIPTIONS HAVE NO STAGE KEYWORD")
print("=" * 74)
# We extend STAGE_BY_KEYWORD from evidence, not from guessing. This lists
# exactly what is still unmatched so the list can grow honestly.
from core.contracts import AttackStage

unmatched = Counter()
for alert in alerts:
    result, meta = investigate(alert)
    if result.attack_stage == AttackStage.UNDETERMINED:
        unmatched[alert.rule_description] += 1

# Printing BOTH layers side by side: the triage attack type and the
# forensics stage. Where they disagree, one of the two keyword lists is
# incomplete, and the disagreement is the thing worth looking at.
from tools.severity import assign_severity

print(f"  distinct unmatched descriptions : {len(unmatched)}")
print(f"  {'count':>6}  {'triage says':<18}  description")
for description, count in unmatched.most_common(25):
    example = next(a for a in alerts if a.rule_description == description)
    attack_type = assign_severity(example).attack_type.value
    print(f"  {count:>5}x  {attack_type:<18}  {description[:48]}")
