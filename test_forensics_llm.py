"""
test_forensics_llm.py
=====================
Tests the language layer on all five paths, and only ONE of them needs the
API key. The other four are forced, so a broken provider can never hide a
broken fallback.
"""

from core.models import Alert
from core.llm import LLMUnavailable, llm_available
from core.preprocessor import load_alerts
from tools import forensics, history, scenarios

alerts = load_alerts()
history.build(alerts)
scenarios.install()

# The synthetic lateral-movement incident: the richest facts we have.
focus = scenarios.lateral_movement_incident()[2]

print("=" * 74)
print("PART 1 - THE EXACT FACTS THE MODEL WILL BE GIVEN")
print("=" * 74)
result, meta = forensics.investigate(focus)
meta.setdefault("successes", meta.get("successes", 0))
print(forensics.facts_for_prompt(focus, result, meta))

print()
print("=" * 74)
print("PART 2 - PATH 3: A REAL CALL (needs the API key)")
print("=" * 74)
if not llm_available():
    print("  Skipped: no API key, or offline mode is on.")
else:
    result, meta = forensics.narrate(focus)
    usage = meta["usage"] or {}
    print(f"  llm_used  : {meta['llm_used']}")
    print(f"  priority  : {meta['containment_priority']}/100")
    print(f"  tokens    : {usage.get('total_tokens')}")
    print(f"  cost      : ${usage.get('cost_usd', 0):.6f}")
    print()
    print("  DETERMINISTIC (machine-checked, always present)")
    print(f"    {meta['deterministic_analysis']}")
    print()
    print("  NARRATIVE (the model's only contribution)")
    narrative = result.analysis.split("NARRATIVE:", 1)
    print(f"    {narrative[1].strip() if len(narrative) > 1 else '(none)'}")
    print()
    # The headline cost number: a narrative on every alert that needs one.
    needs = sum(1 for a in alerts
                if forensics.investigate(a)[0].attack_stage
                is not forensics.AttackStage.NOT_APPLICABLE)
    per = usage.get("cost_usd", 0)
    print(f"  alerts needing a narrative : {needs}/{len(alerts)}")
    print(f"  projected corpus cost      : ${per * needs:.4f}")
    print(f"  saved by skipping the rest : ${per * (len(alerts)-needs):.4f}")

print()
print("=" * 74)
print("PART 3 - PATH 1: NotApplicable must NOT call the model")
print("=" * 74)
# A booby trap: if narrate() contacts the model here, this raises and the
# test fails loudly. Silence is the proof.
saved_call = forensics.structured_call
saved_available = forensics.llm_available
forensics.llm_available = lambda: True


def must_not_run(*args, **kwargs):
    raise AssertionError("the model was called for a NotApplicable alert")


forensics.structured_call = must_not_run

housekeeping = Alert(id="TEST-NA", timestamp="2030-06-01T00:00:00+00:00",
                     rule_id="1", rule_level=3,
                     rule_description="Log file rotated.",
                     agent_name="h1", raw={})
result, meta = forensics.narrate(housekeeping)
print(f"  stage          : {result.attack_stage.value}")
print(f"  llm_used       : {meta['llm_used']}")
print(f"  skipped_reason : {meta['skipped_reason']}")
print("  ok - the model was never contacted")

print()
print("=" * 74)
print("PART 4 - PATHS 4 AND 5: failures must not break anything")
print("=" * 74)


def raise_unavailable(*args, **kwargs):
    raise LLMUnavailable("provider returned 503")


def raise_unexpected(*args, **kwargs):
    raise KeyError("choices")


for label, broken in (("LLMUnavailable", raise_unavailable),
                      ("KeyError", raise_unexpected)):
    forensics.structured_call = broken
    result, meta = forensics.narrate(focus)
    usable = len(result.analysis) > 80 and result.attack_stage is not None
    print(f"  {label:<16} llm_used={meta['llm_used']}  "
          f"result_usable={usable}")
    print(f"                   reason: {meta['fallback_reason'][:60]}")

# Put the real functions back, so nothing after this point is affected.
forensics.structured_call = saved_call
forensics.llm_available = saved_available

print()
print("=" * 74)
print("PART 5 - THE SCHEMA IS THE REAL CONSTRAINT")
print("=" * 74)
from pydantic import ValidationError

for label, kwargs in (
        ("one-word narrative", {"narrative": "bad", "containment_priority": 50}),
        ("priority 400", {"narrative": "x" * 100, "containment_priority": 400}),
        ("negative priority", {"narrative": "x" * 100,
                               "containment_priority": -5}),
):
    try:
        forensics.ForensicsNarrative(**kwargs)
        print(f"  BAD {label:<22} was ACCEPTED")
    except ValidationError:
        print(f"  ok  {label:<22} rejected by the schema")