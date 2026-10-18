"""
test_forensics.py
=================
Everything the forensics layer claims, measured on the real corpus in one
pass, plus the labelled synthetic incidents that prove the detector fires on
the right pattern.

Written as a SINGLE loop over the alerts. The earlier version called
investigate() three separate times for three separate statistics - about
2,200 database queries of pure waste. Collect once, report many times.

The numbers that matter:
  Part 3 - lateral movement must be LOW. Near 100% means broken.
  Part 6 - how much of a time window belongs to a different attacker.
  Part 7 - every line must say 'ok'.
"""

from collections import Counter

from core.contracts import AttackStage
from core.preprocessor import load_alerts
from tools import history, scenarios
from tools.forensics import investigate
from tools.severity import assign_severity


print("=" * 74)
print("PART 1 - HOST NAME RECOVERY")
print("=" * 74)
alerts = load_alerts()
hosts = Counter(a.agent_name for a in alerts)
print(f"  alerts         : {len(alerts)}")
print(f"  distinct hosts : {len(hosts)}")
for host, count in hosts.most_common(10):
    print(f"    {host:<26}{count:>5}")
# "xxx" is the dataset's anonymised placeholder; "unknown-host" is our own
# honest admission. Neither counts as a recovered name.
real = sum(c for h, c in hosts.items() if h not in ("xxx", "unknown-host"))
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
print("PART 3 - ONE PASS OVER THE WHOLE CORPUS")
print("=" * 74)
lateral, spread, neither = [], [], []
stages = Counter()
unmatched = Counter()
findings = []
total_events = same_actor_events = 0
foreign_share = []

for alert in alerts:
    result, meta = investigate(alert)
    findings.append((alert, result, meta))
    stages[result.attack_stage.value] += 1

    if result.attack_stage is AttackStage.UNDETERMINED:
        unmatched[alert.rule_description] += 1

    if result.lateral_movement:
        lateral.append((alert, result, meta))
    elif result.horizontal_spread:
        spread.append((alert, result, meta))
    else:
        neither.append(alert)

    # Actor accounting, for Part 6.
    mine = sum(1 for e in result.timeline if e.same_actor)
    total_events += len(result.timeline)
    same_actor_events += mine
    if result.timeline:
        foreign_share.append(1 - mine / len(result.timeline))

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
    print("  None found. On this corpus that is expected - see finding 10:")
    print("  85.8% of alerts come from a single host, so there is nowhere")
    print("  to move to.")
else:
    # One line per distinct account, so one busy user does not fill the page.
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
# Prefer a lateral case, then a spread case, then whatever came first.
alert, result, meta = (lateral or spread or findings)[0]
print(f"  focus alert : {alert.id}  {alert.rule_description[:40]}")
print(f"  stage       : {result.attack_stage.value}  ({meta['stage_reason']})")
print(f"  lateral     : {result.lateral_movement}")
print(f"  spread      : {result.horizontal_spread}")
print(f"  hosts       : {', '.join(result.affected_hosts) or 'none'}")
print()
print("  TIMELINE   >> = the alert under investigation")
print("             ~  = a DIFFERENT actor, here by coincidence of timing")
for event in result.timeline[:12]:
    print(f"    {event.headline()[:88]}")
print()
print("  ANALYSIS")
print(f"    {result.analysis}")


print()
print("=" * 74)
print("PART 6 - HOW MUCH OF A TIME WINDOW IS THE WRONG ACTOR?")
print("=" * 74)
# This is the size of finding 14, measured. Before the actor partition,
# every one of these foreign events was handed to the language model as
# part of the same story - and the model dutifully wove them in.
foreign = total_events - same_actor_events
print(f"  timeline events built     : {total_events}")
print(f"  belong to THIS actor      : {same_actor_events} "
      f"({same_actor_events/total_events:.1%})")
print(f"  belong to ANOTHER actor   : {foreign} ({foreign/total_events:.1%})")
print(f"  mean events per window    : {total_events/total:.1f}")
mostly = sum(1 for s in foreign_share if s > 0.5)
orphans = sum(1 for s in foreign_share if s >= 0.999)
print(f"  windows >50% foreign      : {mostly}/{len(foreign_share)} "
      f"({mostly/len(foreign_share):.1%})")
# MUST be 0. Anything else means an alert was marked a stranger in its own
# timeline - which happened, for alerts with no IP and a generic account.
print(f"  windows with NO own event : {orphans}   (must be 0)")


print()
print("=" * 74)
print("PART 7 - THE DETECTOR ON LABELLED SYNTHETIC INCIDENTS")
print("=" * 74)
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
    # The id carries the right answer, so the test can grade itself.
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
print("PART 8 - WHICH DESCRIPTIONS HAVE NO STAGE KEYWORD")
print("=" * 74)
# Both layers side by side: the triage attack type and the forensics stage.
# Where they disagree, one of the two keyword lists is incomplete, and the
# disagreement is the thing worth reading.
print(f"  distinct unmatched descriptions : {len(unmatched)}")
print(f"  {'count':>6}  {'triage says':<18}  description")
for description, count in unmatched.most_common(25):
    example = next(a for a in alerts if a.rule_description == description)
    attack_type = assign_severity(example).attack_type.value
    print(f"  {count:>5}x  {attack_type:<18}  {description[:48]}")