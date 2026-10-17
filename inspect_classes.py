"""
inspect_classes.py
==================
Checks WHAT our classifier is actually matching, before we change anything.

Rule of this project: measure first, then fix. Changing keywords without
looking at what they currently catch is guessing with extra steps.
"""

from collections import Counter, defaultdict

from core.preprocessor import load_alerts
from tools.severity import assign_severity

alerts = load_alerts()
results = [assign_severity(a) for a in alerts]

print("=" * 78)
print("A - THE GROUND-TRUTH LABELS THAT CAME WITH THE DATASET")
print("=" * 78)
# `.raw` still holds everything, including the `_label` we kept in Step 9.
labels = Counter(a.raw.get("_label", "(none)") for a in alerts)
for name, count in labels.most_common():
    print(f"  {name:<20} {count:>5}  ({count/len(alerts):.1%})")

print()
print("=" * 78)
print("B - THE 20 MOST COMMON ALERTS, AND HOW WE CLASSIFIED THEM")
print("=" * 78)
# A dictionary where each key starts with an empty Counter automatically.
by_description = defaultdict(Counter)
levels = {}
for alert, result in zip(alerts, results):
    by_description[alert.rule_description][result.attack_type.value] += 1
    levels[alert.rule_description] = alert.rule_level

# Sort descriptions by how often they appear, biggest first.
ranked = sorted(by_description.items(), key=lambda item: -sum(item[1].values()))

print(f"{'N':>5}  {'LVL':>3}  {'OUR CLASS':<22} DESCRIPTION")
print("-" * 78)
for description, classes in ranked[:20]:
    total = sum(classes.values())
    # `most_common(1)[0][0]` = the single most frequent class for this text.
    main = classes.most_common(1)[0][0]
    print(f"{total:>5}  {levels[description]:>3}  {main:<22} {description[:44]}")

print()
print("=" * 78)
print("C - FOR EACH CLASS, WHAT IS ACTUALLY IN IT?")
print("=" * 78)
per_class = defaultdict(Counter)
for alert, result in zip(alerts, results):
    per_class[result.attack_type.value][alert.rule_description] += 1

for class_name, descriptions in sorted(
    per_class.items(), key=lambda item: -sum(item[1].values())
):
    total = sum(descriptions.values())
    print(f"\n{class_name}  ({total} alerts, {len(descriptions)} distinct descriptions)")
    for description, count in descriptions.most_common(5):
        print(f"      {count:>5}x  {description[:62]}")