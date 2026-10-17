"""
inspect_nested.py
=================
Active-response records wrap the alert that triggered them, at
    data -> parameters -> alert

This script digs that out and reports what is really in there: the levels,
the descriptions, and the source IPs of the actual attacks.
"""

from collections import Counter

from core.preprocessor import load_alerts

alerts = load_alerts()

nested_levels = Counter()
nested_descriptions = Counter()
found = 0
missing = 0
example = None

for alert in alerts:
    data = alert.raw.get("data")
    if not isinstance(data, dict):
        continue

    parameters = data.get("parameters")
    if not isinstance(parameters, dict):
        continue

    inner = parameters.get("alert")
    if not isinstance(inner, dict):
        missing += 1
        continue

    found += 1
    inner_rule = inner.get("rule", {})
    nested_levels[inner_rule.get("level")] += 1
    nested_descriptions[inner_rule.get("description")] += 1
    if example is None:
        example = inner

print("=" * 70)
print("THE ALERTS HIDDEN INSIDE ACTIVE-RESPONSE RECORDS")
print("=" * 70)
print(f"Records carrying a nested alert : {found}")
print(f"Records without one             : {missing}")

print()
print("NESTED ALERT LEVELS  (this decides whether escalation is possible)")
print("-" * 50)
for level, count in sorted(nested_levels.items(), key=lambda x: (x[0] is None, x[0])):
    print(f"  level {str(level):>4} : {count:>5}")

print()
print("NESTED ALERT DESCRIPTIONS (top 15)")
print("-" * 50)
for description, count in nested_descriptions.most_common(15):
    print(f"  {count:>5}x  {str(description)[:58]}")

if example:
    print()
    print("=" * 70)
    print("ONE COMPLETE NESTED ALERT")
    print("=" * 70)
    print("keys      :", sorted(example.keys()))
    print("rule      :", example.get("rule"))
    print("agent     :", example.get("agent"))
    print("data      :", example.get("data"))
    print("full_log  :", str(example.get("full_log"))[:160])