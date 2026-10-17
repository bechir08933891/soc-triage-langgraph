"""
analyse.py
==========
Runs the triage agent across the WHOLE real dataset and reports what happened.
This is the moment the project stops being theoretical.
"""

# `Counter` counts how many times each value appears. Very handy for stats.
from collections import Counter

from core.preprocessor import DATASET_FILE, load_alerts, load_raw_records
from tools.severity import assign_severity

print("=" * 70)
print("PART 1 - WHAT IS IN THE FILE")
print("=" * 70)
size_mb = DATASET_FILE.stat().st_size / 1_000_000
print(f"File      : {DATASET_FILE.name} ({size_mb:.2f} MB)")
raw = load_raw_records()
print(f"Records   : {len(raw)}")
first = raw[0]
print(f"Keys      : {sorted(first.keys())}")
print(f"Has label : {'_label' in first}  ->  {first.get('_label')}")

print()
print("=" * 70)
print("PART 2 - LOADING INTO VALIDATED ALERTS")
print("=" * 70)
alerts = load_alerts()
print(f"Valid alerts    : {len(alerts)} / {len(raw)}")
# `sum(1 for x in list if condition)` counts how many items match.
print(f"With source IP  : {sum(1 for a in alerts if a.src_ip)}")
print(f"With a username : {sum(1 for a in alerts if a.user)}")
print(f"With full_log   : {sum(1 for a in alerts if a.full_log)}")
levels = Counter(a.rule_level for a in alerts)
print("Wazuh levels    :", dict(sorted(levels.items())))

print()
print("=" * 70)
print("PART 3 - YOUR TRIAGE AGENT ON REAL DATA")
print("=" * 70)
results = [assign_severity(a) for a in alerts]
types = Counter(r.attack_type.value for r in results)
sevs = Counter(r.severity.value for r in results)

print(f"{'ATTACK TYPE':<24}{'COUNT':>8}{'SHARE':>9}")
print("-" * 41)
for name, count in types.most_common():
    print(f"{name:<24}{count:>8}{count/len(results):>8.1%}")

print()
print(f"{'SEVERITY':<24}{'COUNT':>8}{'SHARE':>9}")
print("-" * 41)
for name in ("Critical", "High", "Medium", "Low", "Info"):
    count = sevs.get(name, 0)
    print(f"{name:<24}{count:>8}{count/len(results):>8.1%}")

unknown = types.get("Unknown", 0)
coverage = 1 - unknown / len(results)
escalated = sum(1 for r in results if r.escalate_to_tier2)
print()
print(f"KEYWORD COVERAGE : {coverage:.1%}   ({unknown} alerts came back Unknown)")
print(f"ESCALATED        : {escalated} / {len(results)}  ({escalated/len(results):.1%})")
print(f"AUTO-CLOSED      : {len(results)-escalated} / {len(results)}  "
      f"({1-escalated/len(results):.1%})")

# This block is the most useful part of the whole script: it tells us exactly
# which real descriptions our keyword table does not recognise yet.
if unknown:
    print()
    print("--- The descriptions we could NOT classify (top 10) ---")
    # `zip(a, b)` walks two lists side by side, pairing their items.
    misses = Counter(
        a.rule_description
        for a, r in zip(alerts, results)
        if r.attack_type.value == "Unknown"
    )
    for text, count in misses.most_common(10):
        print(f"  {count:>5}x  {text[:60]}")