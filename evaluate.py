"""
evaluate.py
===========
Does the language model's threat score add signal over the deterministic
one, and would it ever change a decision?

The hunter has TWO scorers over IDENTICAL evidence:

    deterministic_synthesis()   rules: triage score + a reputation bonus
    the language model          the same facts, asked for a number

That is an unusually clean comparison. Both see the same fact block; one is
a pure function and the other is not.

RUNNING IT COSTS MONEY, so the script defaults to a DRY RUN:

    python evaluate.py        -> the plan only
    python evaluate.py run    -> actually ask the model

It samples rather than running all 738 alerts, because the sample is
STRATIFIED over evidence profiles and Part 1 shows how few of those exist.

WHY PART 0 IS LONGER THAN IT LOOKS (finding 22): the first version of the
faithfulness check was validated on five cases written by the same person
who wrote the check, none of which contained a negation. It then counted
"no indication of malicious activity" as a claim that something was
malicious, and reported an inflated violation count as a result. The cases
it got wrong are now in the self-test, taken verbatim from real model prose.
"""

from __future__ import annotations

import random
import re
import statistics
import sys
import time
from collections import Counter, defaultdict

from core.config import LLM_MODEL, OFFLINE_MODE
from core.llm import cost_usd, llm_available, structured_call
from core.preprocessor import load_alerts
from tools.hunter import (SYSTEM_PROMPT, HuntSynthesis, deterministic_synthesis,
                          facts_for_prompt, gather_evidence)
from tools.reporter import THREAT_SCORE_ESCALATE
from tools.threat_intel import count_local_hits


SAMPLE_SIZE = 60
# A fixed seed, so re-running samples the SAME alerts. A comparison whose
# population changes between runs cannot be reproduced.
SEED = 20261019


def profile(evidence: dict) -> tuple:
    """The evidence a scorer actually sees, reduced to a comparable key.

    Two alerts with the same profile present the scorer with the same
    situation. If the model is adding judgement, alerts within one profile
    should still score alike - that is what Part 5 checks.
    """
    triage = evidence["triage"]
    worst = "none"
    for ioc in evidence["iocs"]:
        worst = ioc.verdict.value
        break
    return (triage.attack_type.value, triage.severity.value, worst,
            len(evidence["techniques"]) > 0)


# Words that turn a mention of "malicious" into its opposite. The first
# version of this check had none of these and counted "no indication of
# malicious activity" as a claim that something was malicious.
NEGATORS = ("no ", "not ", "non-", "without ", "nothing ", "lacks ",
            "absent", "free of", "unlikely", "cannot confirm", "rather than",
            "no evidence", "no indication", "no sign", "does not", "isn't",
            "is not", "none of")


def _is_negated(text: str, position: int) -> bool:
    """Was this occurrence of a word negated by something just before it?

    Looks back 70 characters, which covers "the available facts provide no
    indication of malicious activity" and stops well short of running into
    a previous sentence's unrelated negation. A full stop inside the window
    resets it, because a negation before a sentence boundary does not negate
    a claim after it.
    """
    window = text[max(0, position - 70):position]
    window = window.rsplit(". ", 1)[-1]
    return any(word in window for word in NEGATORS)


def unsupported_claims(hypothesis: str, evidence: dict,
                       prompt: str = "") -> list[str]:
    """Claims in the prose that the fact block does not license.

    Three checks, each tied to a rule in the hunter's system prompt:
      - "Never claim an IP is malicious unless a verdict says so"
      - "Use ONLY the facts provided. Invent nothing."
      - the hunter has no timeline at all, so it cannot see movement

    `prompt` is the full fact block the model was given. Addresses are
    checked against ALL of it, not just the indicator list, because the
    block also contains a RAW LOG section - an address quoted from there is
    being read, not invented.
    """
    problems = []
    text = hypothesis.lower()

    verdicts = {i.verdict.value for i in evidence["iocs"]}
    if "malicious" not in verdicts:
        for match in re.finditer(r"malicious", text):
            if not _is_negated(text, match.start()):
                problems.append("says 'malicious' with no malicious verdict")
                break

    known = {i.indicator for i in evidence["iocs"]}
    haystack = prompt or ""
    for found in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", hypothesis):
        if found not in known and found not in haystack:
            problems.append(f"names an address not in the prompt: {found}")

    for match in re.finditer(r"lateral", text):
        if not _is_negated(text, match.start()):
            problems.append("claims lateral movement (the hunter has no timeline)")
            break

    return problems


def self_test() -> bool:
    """Prove the faithfulness check can FAIL, and that it does not OVERfire.

    A check that never fires is indistinguishable from a check that passes.
    A check that always fires is worse: it reports violations that are not
    there, which is what the first version of this one did.
    """
    from core.contracts import IOCEnrichment, Verdict
    clean = {"iocs": [IOCEnrichment(indicator="45.55.159.241",
                                    verdict=Verdict.CLEAN)]}
    bad = {"iocs": [IOCEnrichment(indicator="45.55.159.241",
                                  verdict=Verdict.MALICIOUS,
                                  abuse_confidence=90)]}
    cases = [
        ("faithful on a clean verdict",
         "The source 45.55.159.241 is rated clean; no sign of compromise.",
         clean, False),
        ("says malicious when the verdict is clean",
         "This is clearly malicious traffic from 45.55.159.241.",
         clean, True),
        ("says malicious when the verdict IS malicious",
         "The source 45.55.159.241 is rated malicious by AbuseIPDB.",
         bad, False),
        ("invents an address",
         "Traffic came from 8.8.8.8 and 45.55.159.241.", bad, True),
        ("claims lateral movement it cannot see",
         "The actor shows lateral movement across hosts.", bad, True),
        # THE CASES THE FIRST VERSION OF THIS CHECK GOT WRONG. Every one of
        # them is real model prose, and every one was counted as a
        # violation when it is the opposite of a violation.
        ("says there is NO indication of malicious activity",
         "The available facts provide no indication of malicious activity.",
         clean, False),
        ("says the source is NOT rated malicious",
         "The probe returned 404; the source is not rated malicious.",
         clean, False),
        ("says there is no evidence of malicious intent",
         "A single GET request to /, with no evidence of malicious intent.",
         clean, False),
        ("quotes an address from the RAW LOG section",
         "An SSH attempt using an invalid user from 47.236.196.112.",
         clean, False),
    ]
    # The prompt a real call would have carried, including a RAW LOG line.
    prompt = ("INDICATOR REPUTATION\n  45.55.159.241: verdict=clean\n"
              "\nRAW LOG\n  sshd: Invalid user from 47.236.196.112")
    ok = True
    for label, text, evidence, should_fire in cases:
        fired = bool(unsupported_claims(text, evidence, prompt))
        mark = "ok " if fired == should_fire else "BAD"
        if fired != should_fire:
            ok = False
        print(f"  {mark} {label}")
    return ok


alerts = load_alerts()
local_hits = count_local_hits(alerts)

print("=" * 74)
print("DOES THE LANGUAGE MODEL'S SCORE ADD SIGNAL OVER THE RULES?")
print("=" * 74)

print()
print("PART 0 - THE FAITHFULNESS CHECK MUST BE ABLE TO FAIL")
print("-" * 74)
if not self_test():
    print()
    print("  The detector is broken. Part 6 would be meaningless. Stopping.")
    sys.exit(1)

print()
print("PART 1 - HOW MUCH VARIETY IS THERE TO SCORE?")
print("-" * 74)
# Gathering evidence is cheap: reputation comes from the file cache, MITRE
# mapping is a dictionary lookup, triage is pure rules. No model involved.
evidence_by_id = {}
profiles = defaultdict(list)
for alert in alerts:
    evidence = gather_evidence(alert,
                               local_hits=local_hits.get(alert.src_ip or "", 0))
    evidence_by_id[alert.id] = evidence
    profiles[profile(evidence)].append(alert)
print(f"  alerts                     : {len(alerts)}")
print(f"  distinct evidence profiles : {len(profiles)}")
print("  (attack type, severity, worst verdict, has technique)")
print()
for key, group in sorted(profiles.items(), key=lambda kv: -len(kv[1]))[:8]:
    print(f"    {len(group):>5}  {key[0]:<20}{key[1]:<9}{key[2]:<12}"
          f"{'tech' if key[3] else '-'}")

print()
print("PART 2 - THE SAMPLE")
print("-" * 74)
random.seed(SEED)
sample = []
for key, group in profiles.items():
    # Proportional to the profile's share, but never zero: a rare profile
    # is exactly where a scorer is most likely to differ.
    take = max(1, round(SAMPLE_SIZE * len(group) / len(alerts)))
    sample.extend(random.sample(group, min(take, len(group))))
print(f"  stratified sample          : {len(sample)} alerts")
print(f"  at least one per profile   : yes ({len(profiles)} profiles)")
estimate = cost_usd(LLM_MODEL, 650 * len(sample), 130 * len(sample))
print(f"  model                      : {LLM_MODEL}")
print(f"  estimated cost             : ${estimate:.4f}")
print(f"  estimated time             : ~{len(sample) * 2 // 60 + 1} minute(s)")

# THE GUARD. Everything above this line is free. Everything below costs.
if len(sys.argv) < 2 or sys.argv[1] != "run":
    print()
    print("  This is a DRY RUN. Nothing was sent to the model.")
    print("  To run it for real:")
    print("      python evaluate.py run")
    sys.exit(0)

if OFFLINE_MODE or not llm_available():
    print()
    print("  CANNOT RUN: the model is unavailable.")
    print("  Needs OPENAI_API_KEY set and SOC_OFFLINE_MODE off.")
    sys.exit(1)

print()
print("PART 3 - RULES VERSUS THE MODEL")
print("-" * 74)
rows = []
failures = 0
started = time.perf_counter()
for index, alert in enumerate(sample, start=1):
    evidence = evidence_by_id[alert.id]
    # The SAME evidence object goes to both scorers. That is what makes
    # this a comparison of scorers rather than of inputs.
    rule_score = deterministic_synthesis(alert, evidence).threat_score
    try:
        prompt = facts_for_prompt(alert, evidence)
        answer, usage = structured_call(HuntSynthesis, SYSTEM_PROMPT, prompt)
        rows.append({"alert": alert, "evidence": evidence, "prompt": prompt,
                     "rule": rule_score, "llm": answer.threat_score,
                     "hypothesis": answer.hypothesis, "usage": usage})
    except Exception as error:
        # A failure is recorded, not fatal. An evaluation that dies at
        # alert 41 of 60 has measured nothing.
        failures += 1
        print(f"    {alert.id}: {type(error).__name__}")
    if index % 10 == 0:
        print(f"    {index}/{len(sample)}…")
elapsed = time.perf_counter() - started

if not rows:
    print("  No answers. Stopping.")
    sys.exit(1)

spent = sum(float(r["usage"].get("cost_usd", 0.0)) for r in rows)
tokens = sum(int(r["usage"].get("total_tokens", 0)) for r in rows)
print(f"  scored        : {len(rows)}/{len(sample)}  ({failures} failure(s))")
print(f"  elapsed       : {elapsed:.0f}s")
print(f"  tokens        : {tokens:,}")
print(f"  actual cost   : ${spent:.4f}")

deltas = [r["llm"] - r["rule"] for r in rows]
exact = sum(1 for d in deltas if d == 0)
print()
print(f"  exact agreement        : {exact}/{len(rows)} ({exact/len(rows):.1%})")
print(f"  mean absolute deviation: {statistics.mean(abs(d) for d in deltas):.1f} points")
print(f"  mean signed deviation  : {statistics.mean(deltas):+.1f} points")
print(f"  model scored higher    : {sum(1 for d in deltas if d > 0)}")
print(f"  model scored lower     : {sum(1 for d in deltas if d < 0)}")
print(f"  largest disagreement   : {max(abs(d) for d in deltas)} points")

print()
print("PART 4 - WOULD THE MODEL EVER CHANGE A DECISION?")
print("-" * 74)
# THE QUESTION THIS WHOLE FILE EXISTS FOR. Read it together with Part 5: a
# crossing is only judgement if identical evidence crosses consistently.
print(f"  A score of >= {THREAT_SCORE_ESCALATE} would have crossed the gate.")
print("  (The gate no longer uses this signal - see finding 21.)")
print()
rule_max = max(r["rule"] for r in rows)
llm_max = max(r["llm"] for r in rows)
rule_over = sum(1 for r in rows if r["rule"] >= THREAT_SCORE_ESCALATE)
llm_over = sum(1 for r in rows if r["llm"] >= THREAT_SCORE_ESCALATE)
flips = [r for r in rows
         if (r["rule"] >= THREAT_SCORE_ESCALATE) != (r["llm"] >= THREAT_SCORE_ESCALATE)]
print(f"  highest score, rules   : {rule_max}/100")
print(f"  highest score, model   : {llm_max}/100")
print(f"  rules cross the gate   : {rule_over}/{len(rows)}")
print(f"  model crosses the gate : {llm_over}/{len(rows)}")
print(f"  DECISIONS CHANGED      : {len(flips)}/{len(rows)}")
for row in flips[:8]:
    print(f"    {row['alert'].id}  rules {row['rule']} -> model {row['llm']}"
          f"  | {row['alert'].rule_description[:40]}")

print()
print("PART 5 - SAME EVIDENCE, SAME SCORE?")
print("-" * 74)
# Finding 8 measured this on one alert, 16 times. This measures it across
# the corpus: alerts sharing a profile present the scorer with the same
# situation, so a spread of scores within one profile is variance, not
# judgement - and any gate crossing inside such a group is variance too.
by_profile = defaultdict(list)
for row in rows:
    by_profile[profile(row["evidence"])].append(row["llm"])
spread = [(key, scores) for key, scores in by_profile.items() if len(scores) > 1]
if not spread:
    print("  No profile has more than one sampled alert.")
else:
    inconsistent = 0
    for key, scores in sorted(spread, key=lambda kv: -len(kv[1]))[:6]:
        distinct = sorted(set(scores))
        if len(distinct) > 1:
            inconsistent += 1
        crosses = any(v >= THREAT_SCORE_ESCALATE for v in distinct)
        flag = "  <- crosses the gate on SOME of them" if crosses else ""
        print(f"    {len(scores):>3} alerts  {key[0]:<18}{key[1]:<8}"
              f"scores {distinct}{flag}")
    print()
    print(f"  profiles where identical evidence produced different scores: "
          f"{inconsistent}/{len(spread)}")

print()
print("PART 6 - DOES THE MODEL CLAIM THINGS THE EVIDENCE DOES NOT SUPPORT?")
print("-" * 74)
problems = Counter()
offenders = []
for row in rows:
    found = unsupported_claims(row["hypothesis"], row["evidence"],
                               row.get("prompt", ""))
    for item in found:
        problems[item.split(":")[0]] += 1
    if found:
        offenders.append((row["alert"].id, found[0], row["hypothesis"][:200]))
print(f"  hypotheses checked     : {len(rows)}")
print(f"  with an unsupported claim: {len(offenders)}")
for kind, count in problems.most_common():
    print(f"    {count:>4}x  {kind}")
for alert_id, problem, text in offenders[:5]:
    print()
    print(f"    {alert_id}: {problem}")
    print(f"      {text}…")