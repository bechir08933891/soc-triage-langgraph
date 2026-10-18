"""
test_reporter.py
================
Tests the reporter's two guarantees:

  1. THE DECISION IS MODEL-INDEPENDENT. It must be identical across a
     working model, an LLMUnavailable, and an unexpected crash.
  2. PARTIAL INPUT STILL PRODUCES A REPORT, and names what is missing.

Plus the measurement that justifies the whole architecture: how many alerts
the combined gate escalates that triage alone would have closed.
"""

from core.llm import LLMUnavailable
from core.preprocessor import load_alerts
from tools import history, reporter, scenarios
from tools.forensics import investigate
from tools.severity import assign_severity

alerts = load_alerts()
history.build(alerts)
scenarios.install()

focus = scenarios.lateral_movement_incident()[2]
triage = assign_severity(focus)
forensics, _ = investigate(focus)

print("=" * 74)
print("PART 1 - PARTIAL INPUT")
print("=" * 74)
print("  A missing agent must be NAMED, not guessed, and a report must")
print("  still be produced.")
print()
for label, kwargs in (
        ("triage + forensics", dict(triage=triage, forensics=forensics)),
        ("triage only", dict(triage=triage)),
        ("forensics only", dict(forensics=forensics)),
        ("nothing at all", dict()),
):
    document, meta = reporter.report(focus, **kwargs)
    print(f"  {label:<20} escalate={str(meta['escalate']):<6} "
          f"missing={meta['missing']}  chars={document.char_count}")

print()
print("=" * 74)
print("PART 2 - THE DECISION IS MODEL-INDEPENDENT")
print("=" * 74)
# Save the real functions so Part 4 can use them again.
saved_call = reporter.structured_call
saved_available = reporter.llm_available


def working(schema, system, user):
    """A stub model that answers correctly."""
    return (schema(summary="The agents disagree on this alert, and the "
                           "escalation comes from the forensics context "
                           "rather than from the rule severity.",
                   confidence=77),
            {"input_tokens": 700, "output_tokens": 150, "total_tokens": 850,
             "cost_usd": 0.00014, "model": "stub", "mode": "json_schema"})


def unavailable(*args, **kwargs):
    """The documented failure."""
    raise LLMUnavailable("provider returned 503")


def unexpected(*args, **kwargs):
    """The undocumented one - a bug inside the LLM layer."""
    raise KeyError("choices")


reporter.llm_available = lambda: True
decisions = {}
for label, behaviour in (("model works", working),
                         ("LLMUnavailable", unavailable),
                         ("KeyError", unexpected)):
    reporter.structured_call = behaviour
    document, meta = reporter.report(focus, triage=triage,
                                     forensics=forensics)
    decisions[label] = (meta["escalate"], tuple(meta["signals"]))
    print(f"  {label:<16} escalate={str(meta['escalate']):<6} "
          f"llm_used={str(meta['llm_used']):<6} "
          f"signals={len(meta['signals'])}")

# `len(set(...)) == 1` means every run produced the same decision. A set
# removes duplicates, so one element left means they were all the same.
identical = len(set(decisions.values())) == 1
print()
print(f"  all three decisions identical : {identical}   (must be True)")

# Put the real functions back, so nothing after this point is affected.
reporter.structured_call = saved_call
reporter.llm_available = saved_available

print()
print("=" * 74)
print("PART 3 - THE ESCALATION GATE ACROSS THE CORPUS")
print("=" * 74)
print("  The hunter is left out here on purpose: it needs network lookups")
print("  for 738 alerts. This measures what triage + forensics alone add.")
print()
triage_only = combined = overridden = suppressed = 0
for alert in alerts:
    t = assign_severity(alert)
    f, _ = investigate(alert)
    decision = reporter.recommend_escalation(t, None, f)
    if t.escalate_to_tier2:
        triage_only += 1
    if decision["escalate"]:
        combined += 1
    if decision["overridden_triage"]:
        overridden += 1
    if decision["suppressed"]:
        suppressed += 1

total = len(alerts)
print(f"  triage alone escalates       : {triage_only:>4}/{total} "
      f"({triage_only/total:.1%})")
print(f"  triage + forensics escalates : {combined:>4}/{total} "
      f"({combined/total:.1%})")
print(f"  triage would have CLOSED     : {overridden:>4}/{total} "
      f"({overridden/total:.1%})")
print(f"  explicitly suppressed        : {suppressed:>4}/{total} "
      f"({suppressed/total:.1%})")
print()
print("  The third line is finding 15 at corpus scale: alerts the system")
print("  escalates that a single-agent design would have auto-closed.")

print()
print("=" * 74)
print("PART 4 - THE DISAGREEMENT SENTENCE MUST BE IN THE DOCUMENT")
print("=" * 74)
document, meta = reporter.report(focus, triage=triage, forensics=forensics)
for needle in ("THE AGENTS DISAGREE",
               "Triage alone would have auto-closed",
               "No verdict in this report was produced by a language model"):
    found = needle in document.markdown
    print(f"  {'ok ' if found else 'BAD'} \"{needle[:52]}\"")