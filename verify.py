"""
verify.py
=========
Two checks before we change any code:

  A) Is the dataset's True/False Positive label just the Wazuh level
     in disguise? If yes, it cannot be used as ground truth.
  B) What is really inside an "Active Response" alert? That tells us
     whether our classifier is reading real evidence or getting lucky.
"""

from collections import Counter, defaultdict

from core.preprocessor import load_alerts

alerts = load_alerts()

print("=" * 70)
print("A - IS THE LABEL JUST THE WAZUH LEVEL IN DISGUISE?")
print("=" * 70)

# defaultdict(Counter) builds a small table: for each level, count each label.
table = defaultdict(Counter)
for alert in alerts:
    table[alert.rule_level][alert.raw.get("_label", "(none)")] += 1

print(f"{'LEVEL':>6}{'True Positive':>16}{'False Positive':>16}")
print("-" * 38)
for level in sorted(table):
    row = table[level]
    print(f"{level:>6}{row.get('True Positive', 0):>16}{row.get('False Positive', 0):>16}")


def one_line_rule(level: int) -> str:
    """The dumbest possible classifier. If this scores ~100%, the labels
    carry no information beyond the severity level."""
    return "False Positive" if level <= 3 else "True Positive"


agree = sum(1 for a in alerts if one_line_rule(a.rule_level) == a.raw.get("_label"))
print()
print("A single rule 'level <= 3 means False Positive' agrees with the")
print(f"dataset label on {agree} / {len(alerts)} alerts = {agree/len(alerts):.1%}")

print()
print("=" * 70)
print("B - WHAT IS REALLY INSIDE AN 'ACTIVE RESPONSE' ALERT?")
print("=" * 70)
shown = 0
for alert in alerts:
    if "Active Response" in alert.rule_description and shown < 2:
        print(f"\n--- example {shown + 1} ---")
        print("description :", alert.rule_description)
        print("level       :", alert.rule_level)
        print("full_log    :", (alert.full_log or "(none)")[:200])
        print("raw keys    :", sorted(alert.raw.keys()))
        data = alert.raw.get("data")
        if isinstance(data, dict):
            print("data keys   :", sorted(data.keys()))
            # Active-response records often carry the ORIGINAL alert inside.
            inner = data.get("alert")
            if isinstance(inner, dict):
                inner_rule = inner.get("rule", {})
                print("NESTED rule :", inner_rule.get("description"),
                      "| level", inner_rule.get("level"))
        shown += 1

if shown == 0:
    print("(no active-response alerts found)")