"""
tools/reporter.py
=================
Assemble the findings of the other agents into one incident report, and
decide escalation.

TWO RULES THIS FILE EXISTS TO ENFORCE, both learned by measuring a mistake.

RULE 1 (finding 15) - THE DECISION IS A UNION, NOT A VOTE.

    triage, seeing one alert    : NormalActivity / Info -> auto-close
    forensics, seeing the window: LateralMovement       -> escalate

  Averaging them loses the intrusion. Letting triage decide loses it too:
  triage auto-closed all five alerts of a confirmed incident. So the
  decision is the union of the signals, and when the agents disagree the
  report SAYS SO - the quiet agent is usually right about the single alert
  and wrong about the set.

RULE 2 (finding 19) - REPUTATION IS NOT IMPACT.

  The first version of this gate escalated 567 of 738 alerts (76.8%),
  because 561 of them carried a source address the corpus had seen more
  than fifty times. That verdict is correct and useless on its own: a
  known-malicious host knocking on a door is the internet. So signals are
  split by what they can do ALONE:

    TRIGGERING     escalates by itself
    CORROBORATING  reaches the report, but does not open a ticket

  Reputation is corroborating. It regains triggering force only together
  with a recorded successful authentication by that actor, which is the
  difference between an attempt and an intrusion.

The language model writes the executive summary and nothing else. It is
structurally unable to change the decision: `recommend_escalation` runs
before the model is contacted, and `ReportSummary` has no field for a
verdict. Verified identical across a working model, an injected
LLMUnavailable, and an injected KeyError.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from core.contracts import (
    AttackStage,
    AttackType,
    ForensicsResult,
    HuntResult,
    IncidentReport,
    TriageResult,
    Verdict,
)
from core.llm import LLMUnavailable, llm_available, structured_call
from core.models import Alert


# =============================================================================
# THE POLICY - every threshold and every choice in one place
# =============================================================================

# A hunter threat score at or above this escalates on its own.
THREAT_SCORE_ESCALATE = 70

# Which policy the system actually uses. The alternatives are kept callable
# so test_gate.py can measure all three on the real corpus rather than
# asserting that this one is best.
#
#   "any"          every signal escalates, reputation included -> 76.8%
#   "corroborate"  reputation escalates only alongside another signal
#   "triggering"   reputation never escalates, only informs
POLICY_DEFAULT = "corroborate"

# Kill-chain stages that mean the attacker is already INSIDE. Reconnaissance
# and initial access are deliberately NOT here: the internet knocks on doors
# all day, and escalating every knock is how an analyst learns to ignore the
# queue - which is the whole failure finding 19 records.
LATE_STAGES = {
    AttackStage.LATERAL_MOVEMENT,
    AttackStage.PRIVILEGE_ESCALATION,
    AttackStage.PERSISTENCE,
    AttackStage.EXFILTRATION,
    AttackStage.EXECUTION,
}

# Triage families that are not attacks at all.
NON_THREAT_TYPES = {AttackType.NORMAL_ACTIVITY, AttackType.VULNERABILITY}


# =============================================================================
# STEP 1 - THE DECISION (no model involved, ever)
# =============================================================================


def recommend_escalation(triage: TriageResult | None,
                         hunt: HuntResult | None,
                         forensics: ForensicsResult | None,
                         policy: str = POLICY_DEFAULT) -> dict:
    """Decide escalation, and record exactly which signals caused it.

    Signals are collected into two lists:

      TRIGGERING     each one is sufficient on its own
      CORROBORATING  supporting evidence; not sufficient alone

    `overridden_triage` is the number that matters most. It is True when the
    system escalates something triage would have closed - which is the
    entire justification for having more than one agent.
    """
    triggering: list[str] = []
    corroborating: list[str] = []

    # --- TRIGGERING: evidence of severity, progression, or success --------
    if triage and triage.escalate_to_tier2:
        triggering.append(f"triage: {triage.severity.value} severity")
    if hunt and hunt.threat_score >= THREAT_SCORE_ESCALATE:
        triggering.append(f"hunter: threat score {hunt.threat_score}/100")
    if forensics and forensics.lateral_movement:
        triggering.append("forensics: lateral movement")
    if forensics and forensics.attack_stage in LATE_STAGES:
        triggering.append(f"forensics: stage {forensics.attack_stage.value}")

    # --- REPUTATION: triggering only WITH impact --------------------------
    malicious = bool(hunt and hunt.worst_verdict is Verdict.MALICIOUS)
    successes = forensics.actor_successes if forensics else 0

    if malicious and successes > 0:
        # A known-bad source that actually authenticated. This is an
        # incident, and it is the one combination that makes reputation
        # sufficient on its own.
        triggering.append(
            f"hunter+forensics: a malicious source with {successes} "
            f"successful authentication(s)")
    elif malicious:
        # A known-bad source that knocked and got nowhere. True, reported,
        # and not a reason to wake anybody.
        corroborating.append("hunter: a malicious indicator")

    # --- APPLY THE POLICY -------------------------------------------------
    if policy == "any":
        # The original gate. Kept so the 76.8% figure stays reproducible.
        signals = triggering + corroborating
    elif policy == "triggering":
        signals = triggering
    elif policy == "corroborate":
        # Corroborating signals are reported WITH the others when something
        # triggered, and ignored when nothing did.
        signals = (triggering + corroborating) if triggering else []
    else:
        raise ValueError(f"unknown policy {policy!r}")

    # If nothing fired, say WHY it was safe to close, rather than closing in
    # silence. Three different reasons, and they are not interchangeable.
    suppressed = None
    if not signals and forensics and \
            forensics.attack_stage is AttackStage.NOT_APPLICABLE:
        suppressed = "forensics: not attack activity"
    elif not signals and triage and triage.attack_type in NON_THREAT_TYPES:
        suppressed = f"triage: {triage.attack_type.value}"
    elif not signals and corroborating:
        suppressed = "reputation alone, with no evidence of impact"
    elif not signals:
        # A fourth branch so `suppressed` is never None when nothing fired.
        # "Closed, and here is why" must hold for EVERY closed alert, even
        # when the reason is simply that no agent found anything.
        suppressed = "no triggering signal from any agent"

    escalate = bool(signals)
    triage_alone = bool(triage and triage.escalate_to_tier2)
    return {
        "escalate": escalate,
        "signals": signals,
        "triggering": triggering,
        "corroborating": corroborating,
        "suppressed": suppressed,
        "policy": policy,
        "triage_alone_would_escalate": triage_alone,
        "overridden_triage": escalate and not triage_alone,
    }


def agreement_rows(triage, hunt, forensics) -> list[tuple[str, str, str]]:
    """One row per agent that answered: what it found, what it would do.

    An agent that did not answer gets NO row. An empty row would read as
    "it looked and found nothing", which is a different statement from
    "it never ran".

    The hunter's column says "corroborating" rather than "escalate" when it
    found a malicious indicator without a success, because that is precisely
    what the gate does with it.
    """
    rows = []
    if triage:
        rows.append(("triage (rules, one alert)",
                     f"{triage.attack_type.value} / {triage.severity.value}",
                     "escalate" if triage.escalate_to_tier2 else "auto-close"))
    if hunt:
        if hunt.threat_score >= THREAT_SCORE_ESCALATE:
            verdict = "escalate"
        elif hunt.worst_verdict is Verdict.MALICIOUS:
            verdict = "corroborating"
        else:
            verdict = "no signal"
        rows.append(("hunter (intel + MITRE)",
                     f"{hunt.worst_verdict.value}, score {hunt.threat_score}/100",
                     verdict))
    if forensics:
        pattern = ("lateral movement" if forensics.lateral_movement
                   else "horizontal spread" if forensics.horizontal_spread
                   else "no multi-host pattern")
        rows.append(("forensics (context, window)",
                     f"{forensics.attack_stage.value}, {pattern}",
                     "escalate" if forensics.lateral_movement
                     or forensics.attack_stage in LATE_STAGES else "no signal"))
    return rows


def conflict_note(rows, decision) -> str:
    """The sentence that makes this a multi-agent report and not a summary."""
    verdicts = {row[2] for row in rows}
    quiet_words = {"auto-close", "no signal", "corroborating"}
    # `&` on two sets is the intersection: the values present in both.
    if "escalate" in verdicts and quiet_words & verdicts:
        who = [r[0].split(" (")[0] for r in rows if r[2] == "escalate"]
        quiet = [r[0].split(" (")[0] for r in rows if r[2] in quiet_words]
        return (f"THE AGENTS DISAGREE. {', '.join(who)} escalate(s); "
                f"{', '.join(quiet)} would not. The disagreement is reported "
                f"rather than averaged, because the quiet agents are not "
                f"wrong: each alert judged alone may be ordinary, while the "
                f"set of them is not. The decision is the union of the "
                f"signals, never one agent's vote.")
    if decision["escalate"]:
        return "All agents that produced a signal agree on escalation."
    if decision["corroborating"]:
        return ("No agent produced a triggering signal. Reputation evidence "
                "is present but shows no impact, so it is recorded here and "
                "not escalated - a known-malicious source that achieved "
                "nothing is the threat landscape, not an incident.")
    return "No agent produced an escalation signal. Auto-closing at Tier 1."


# =============================================================================
# STEP 2 - THE SUMMARY (the model's only contribution)
# =============================================================================


def deterministic_summary(alert, triage, hunt, forensics, decision) -> str:
    """The summary used when there is no model. Plain, but complete.

    Note what it does NOT do: it never apologises for the model being
    absent, and it never says less than the model would about the decision.
    A fallback that is visibly worse teaches a reader to distrust it.
    """
    parts = [f"Alert {alert.id} on {alert.agent_name} "
             f"({alert.rule_description})."]
    if triage:
        parts.append(f"Rules classify it as {triage.attack_type.value} at "
                     f"{triage.severity.value} severity.")
    if hunt and hunt.iocs:
        parts.append(f"Threat intelligence returned "
                     f"{hunt.worst_verdict.value} for "
                     f"{len(hunt.iocs)} indicator(s).")
    if forensics:
        own = sum(1 for e in forensics.timeline if e.same_actor)
        parts.append(f"Context: {forensics.attack_stage.value}, "
                     f"{own} of {len(forensics.timeline)} nearby events "
                     f"attributable to this actor, "
                     f"{forensics.actor_successes} successful "
                     f"authentication(s).")
    parts.append("ESCALATE to Tier 2." if decision["escalate"]
                 else "Auto-closing at Tier 1.")
    return " ".join(parts)


# The third and fourth rules are the point of this prompt. A model asked to
# summarise conflicting findings will smooth them into one confident story,
# destroying exactly the signal finding 15 identified - and a model shown a
# "malicious" verdict will reach for alarm whatever the decision says.
SUMMARY_SYSTEM_PROMPT = (
    "You are a SOC shift lead writing the executive summary of an incident "
    "report. You are given VERIFIED FINDINGS from three deterministic "
    "agents and the escalation decision that was already made.\n\n"
    "Rules you must follow:\n"
    "- Use ONLY the findings provided. Invent nothing.\n"
    "- Do NOT change or argue with the escalation decision. State it.\n"
    "- If the agents disagree, SAY SO in one sentence. Do not smooth it "
    "over: the disagreement is information a reader needs.\n"
    "- A malicious source address with no successful authentication is NOT "
    "an incident. If the decision is to auto-close, do not write as though "
    "it should not have been.\n"
    "- 2 to 4 sentences. Plain language, for someone deciding what to do "
    "next.\n"
    "- confidence is 0-100: how well the findings support the decision."
)


class ReportSummary(BaseModel):
    """The model returns prose and a confidence. It cannot return a decision.

    There is no `escalate` field here, and that absence is the safety
    mechanism. A prompt saying "do not change the decision" can be ignored;
    a schema with no field for it cannot.
    """
    summary: str = Field(min_length=60, max_length=900)
    confidence: int = Field(ge=0, le=100)


def facts_for_prompt(alert, triage, hunt, forensics, decision, rows) -> str:
    """Printable, like every other fact block in this project.

    Whatever the model saw, you can see too. That is how the attribution
    bug in the forensics prompt was found - by reading the input, not by
    doubting the output.
    """
    lines = [
        "ALERT",
        f"  id          : {alert.id}",
        f"  host        : {alert.agent_name}",
        f"  description : {alert.rule_description}",
        f"  wazuh level : {alert.rule_level}/15",
        f"  source ip   : {alert.src_ip or 'none'}",
        f"  account     : {alert.user or 'none'}",
        "",
        "WHAT EACH AGENT CONCLUDED",
    ]
    for name, finding, verdict in rows:
        lines.append(f"  {name:<28} {finding}  ->  {verdict}")
    lines += ["", "DECISION (already made, do not change it)",
              f"  escalate : {decision['escalate']}",
              f"  policy   : {decision['policy']}"]
    for signal in decision["triggering"]:
        lines.append(f"  TRIGGERING    : {signal}")
    for signal in decision["corroborating"]:
        lines.append(f"  corroborating : {signal}")
    if decision["suppressed"]:
        lines.append(f"  suppressed by : {decision['suppressed']}")
    if decision["overridden_triage"]:
        lines.append("  NOTE     : triage alone would have auto-closed this")
    if forensics:
        lines += ["", "FORENSIC ANALYSIS", f"  {forensics.analysis}"]
    if hunt:
        lines += ["", "HUNTER HYPOTHESIS", f"  {hunt.hypothesis}"]
    return "\n".join(lines)


# =============================================================================
# STEP 3 - THE DOCUMENT
# =============================================================================


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    """Build a Markdown table. Returns LINES, so callers can keep appending."""
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return out


def build_markdown(alert, triage, hunt, forensics, decision, rows,
                   summary: str, summary_source: str) -> str:
    """Assemble the document. Deterministic: same findings, same document."""
    verdict_word = "ESCALATE TO TIER 2" if decision["escalate"] \
        else "AUTO-CLOSE AT TIER 1"
    # Two trailing spaces in Markdown mean "line break here".
    lines = [
        f"# Incident Report — {alert.id}",
        "",
        f"**Decision:** {verdict_word}  ",
        f"**Generated:** {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC  ",
        f"**Host:** {alert.agent_name}  ",
        "",
        "## Executive summary",
        "",
        summary,
        "",
        # Who wrote the prose is stated ON the prose. A reader should never
        # have to wonder which sentences a model produced.
        f"*Summary written by: {summary_source}.*",
        "",
        "## Escalation decision",
        "",
        f"Policy: `{decision['policy']}`",
        "",
    ]
    if decision["triggering"]:
        lines.append("**Triggering signals** — each sufficient on its own:")
        for signal in decision["triggering"]:
            lines.append(f"- {signal}")
        lines.append("")
    if decision["corroborating"]:
        lines.append("**Corroborating evidence** — reported, not sufficient "
                     "to escalate alone:")
        for signal in decision["corroborating"]:
            lines.append(f"- {signal}")
        lines.append("")
    if not decision["signals"]:
        lines.append("- no triggering signal from any agent")
        if decision["suppressed"]:
            lines.append(f"- suppressed by {decision['suppressed']}")
        lines.append("")
    if decision["overridden_triage"]:
        lines += ["> **Triage alone would have auto-closed this alert.** The "
                  "decision comes from the union of all agents' signals, not "
                  "from the triage severity.", ""]

    lines += ["## The alert", ""]
    lines += _table(["field", "value"], [
        ["id", alert.id],
        ["timestamp", f"{alert.timestamp:%Y-%m-%d %H:%M:%S} UTC"],
        ["rule", f"{alert.rule_id} (level {alert.rule_level}/15)"],
        ["description", alert.rule_description],
        ["host", alert.agent_name],
        ["source IP", alert.src_ip or "none"],
        ["account", alert.user or "none"],
    ])

    lines += ["", "## What each agent concluded", ""]
    lines += _table(["agent", "finding", "would it escalate?"],
                    [[n, f, v] for n, f, v in rows])
    lines += ["", conflict_note(rows, decision), ""]

    if triage:
        lines += ["## Triage (deterministic rules)", "",
                  f"- {triage.headline()}",
                  f"- {triage.rationale}",
                  f"- matched signals: `{'`, `'.join(triage.matched_signals) or 'none'}`",
                  ""]

    if hunt:
        lines += ["## Threat intelligence and MITRE ATT&CK", ""]
        if hunt.iocs:
            lines += _table(["indicator", "verdict", "abuse", "sources"],
                            [[i.indicator, i.verdict.value,
                              f"{i.abuse_confidence}%", ", ".join(i.sources)]
                             for i in hunt.iocs])
            lines.append("")
        if hunt.techniques:
            lines += _table(["technique", "name", "tactic"],
                            [[t.technique_id, t.name, t.tactic]
                             for t in hunt.techniques])
            lines.append("")
        lines += [f"**Hypothesis.** {hunt.hypothesis}", "",
                  f"**Threat score.** {hunt.threat_score}/100", ""]

    if forensics:
        own = sum(1 for e in forensics.timeline if e.same_actor)
        lines += ["## Forensic reconstruction", "",
                  f"- attack stage: **{forensics.attack_stage.value}**",
                  f"- lateral movement: **{forensics.lateral_movement}**",
                  f"- horizontal spread: **{forensics.horizontal_spread}**",
                  f"- successful authentications by this actor: "
                  f"**{forensics.actor_successes}**",
                  f"- hosts involved: {', '.join(forensics.affected_hosts) or 'none'}",
                  f"- timeline: {len(forensics.timeline)} event(s), "
                  f"{own} attributable to this actor, "
                  f"{len(forensics.timeline) - own} to others",
                  "", f"{forensics.analysis}", "",
                  "### Timeline", "",
                  "`>>` the alert under investigation · "
                  "`~` a different actor, present by coincidence of timing",
                  "", "```"]
        for event in forensics.timeline:
            lines.append(event.headline()[:100])
        lines += ["```", ""]

    # THE PROVENANCE TABLE. Without it a reader cannot tell a measured
    # claim from a written one, and the whole audit trail is decoration.
    lines += ["## Provenance", "",
              "| claim | produced by |",
              "|---|---|",
              "| attack type, severity, escalation signals | deterministic rules |",
              "| indicator verdicts, MITRE techniques | tools and external sources |",
              "| timeline, actor split, attack stage, successes | database queries and rules |",
              "| the prose in this report | " + summary_source + " |",
              "",
              "No verdict in this report was produced by a language model.",
              ""]
    return "\n".join(lines)


def report(alert: Alert,
           triage: TriageResult | None = None,
           hunt: HuntResult | None = None,
           forensics: ForensicsResult | None = None,
           policy: str = POLICY_DEFAULT
           ) -> tuple[IncidentReport, dict]:
    """Decide, then write. In that order, always.

    The order IS the safety property. `recommend_escalation` runs on the
    findings alone, before the model exists in this function's world, so no
    model failure and no model output can move the decision. Verified: the
    decision is identical across a successful call, an LLMUnavailable, and
    an injected KeyError.
    """
    decision = recommend_escalation(triage, hunt, forensics, policy=policy)
    rows = agreement_rows(triage, hunt, forensics)

    meta: dict = {"llm_used": False, "usage": None, "fallback_reason": None,
                  "skipped_reason": None, "confidence": None,
                  "escalate": decision["escalate"],
                  "signals": decision["signals"],
                  "triggering": decision["triggering"],
                  "corroborating": decision["corroborating"],
                  "policy": decision["policy"],
                  "suppressed": decision["suppressed"],
                  "overridden_triage": decision["overridden_triage"],
                  "missing": [name for name, value in
                              (("triage", triage), ("hunt", hunt),
                               ("forensics", forensics)) if value is None]}

    summary = deterministic_summary(alert, triage, hunt, forensics, decision)
    source = "deterministic template"

    if not llm_available():
        meta["fallback_reason"] = "No API key, or offline mode is on."
    else:
        try:
            written, usage = structured_call(
                ReportSummary, SUMMARY_SYSTEM_PROMPT,
                facts_for_prompt(alert, triage, hunt, forensics,
                                 decision, rows))
            summary = written.summary
            source = f"language model ({usage.get('model', '?')})"
            meta["llm_used"] = True
            meta["usage"] = usage
            meta["confidence"] = written.confidence
        except LLMUnavailable as error:
            meta["fallback_reason"] = str(error)[:300]
        except Exception as error:
            # The same net as every other model call in this project. The
            # "only LLMUnavailable escapes" promise failed once in Step 13
            # and killed a running script.
            meta["fallback_reason"] = (
                f"Unexpected {type(error).__name__}: {str(error)[:250]}")

    markdown = build_markdown(alert, triage, hunt, forensics, decision,
                              rows, summary, source)
    title = (f"{'ESCALATED' if decision['escalate'] else 'Auto-closed'}: "
             f"{alert.rule_description[:60]} on {alert.agent_name}")
    return IncidentReport(alert_id=alert.id, title=title,
                          markdown=markdown), meta