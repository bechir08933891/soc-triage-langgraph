"""
test_reporter.py
================
The reporter's three guarantees:

  1. THE DECISION IS MODEL-INDEPENDENT. Identical across a working model,
     an LLMUnavailable, and an unexpected crash.
  2. PARTIAL INPUT STILL PRODUCES A REPORT, and names what is missing.
  3. REPUTATION ESCALATES ONLY WITH IMPACT (finding 19) - including the
     branch the real corpus cannot exercise.

Part 5 exists because of a gap the corpus measurement exposed: 561 alerts
carry a malicious source address and NOT ONE has a recorded successful
authentication. The combination that makes reputation triggering again is
therefore never reached by the data, exactly as lateral movement is never
reached (finding 10). It is tested here by construction instead, with the
answers known in advance.
"""

from core.contracts import (
    AttackStage,
    AttackType,
    ForensicsResult,
    HuntResult,
    IOCEnrichment,
    Severity,
    TriageResult,
    Verdict,
)
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
# Save the real functions so later parts use them again.
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

# Put the real functions back.
reporter.structured_call = saved_call
reporter.llm_available = saved_available

print()
print("=" * 74)
print("PART 3 - TRIAGE + FORENSICS ACROSS THE CORPUS")
print("=" * 74)
print("  The hunter is excluded here, so this is NOT the full gate -")
print("  test_gate.py measures all three agents and all three policies.")
print("  This part isolates what context alone adds to rules alone.")
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

print()
print("=" * 74)
print("PART 5 - REPUTATION VS IMPACT (the branch the corpus cannot reach)")
print("=" * 74)
print("  561 corpus alerts carry a malicious source. NONE of them has a")
print("  recorded successful authentication, so the combination that makes")
print("  reputation triggering again is never exercised by the data.")
print("  These four cases exercise it by construction.")
print()

malicious = HuntResult(
    iocs=[IOCEnrichment(indicator="45.55.159.241",
                        verdict=Verdict.MALICIOUS, abuse_confidence=90)],
    hypothesis="a known-bad address, as AbuseIPDB reports it",
    threat_score=43)
clean = HuntResult(
    iocs=[IOCEnrichment(indicator="10.0.0.1", verdict=Verdict.CLEAN)],
    hypothesis="an ordinary internal address",
    threat_score=10)
low_triage = TriageResult(
    attack_type=AttackType.BRUTE_FORCE, severity=Severity.LOW, score=43,
    confidence=0.65, rationale="a low-severity brute-force attempt",
    escalate_to_tier2=False)


def context(successes: int) -> ForensicsResult:
    """Forensics that found no multi-host pattern, only N successes."""
    return ForensicsResult(attack_stage=AttackStage.INITIAL_ACCESS,
                           actor_successes=successes)


cases = [
    ("malicious source, 0 successes", malicious, context(0), False),
    ("malicious source, 1 success", malicious, context(1), True),
    ("malicious source, 6 successes", malicious, context(6), True),
    ("CLEAN source, 6 successes", clean, context(6), False),
]
for label, hunt_result, forensic, wanted in cases:
    decision = reporter.recommend_escalation(low_triage, hunt_result, forensic)
    reason = (decision["signals"][0] if decision["signals"]
              else decision["suppressed"])
    mark = "ok " if decision["escalate"] == wanted else "BAD"
    print(f"  {mark} {label:<32} escalate={str(decision['escalate']):<6} "
          f"{reason[:40]}")

print()
print("  Line 1 is the internet. Line 2 and 3 are intrusions. Line 4 is an")
print("  administrator doing their job - successes without a bad source are")
print("  not an incident either. Every line must say 'ok'.")