"""
tools/forensics.py
==================
Rebuild the story around an alert, decide what the multi-host pattern
actually means, and write it up for a human.

THREE LESSONS ARE BUILT INTO THIS FILE, each from a mistake that was made
and measured:

1. SCANNING IS NOT MOVEMENT.

       one SOURCE   -> many hosts                  = HORIZONTAL SPREAD
       one IDENTITY -> many hosts, WITH a
                       successful authentication   = LATERAL MOVEMENT

   The first version used "same user on two or more hosts" and flagged 100%
   of the corpus, because `root` and `admin` exist on every machine and
   scanners touch every machine. Three guards fix it: generic accounts are
   excluded, a recorded SUCCESS is required, and every query is bounded to a
   time window ("ever" is almost always true and says nothing).

2. A TIME WINDOW IS NOT AN INCIDENT.
   The timeline query is time-scoped; an incident is actor-scoped. Given one
   merged list, the language model wrote a perfectly faithful narrative that
   attributed a different attacker's failures to this one. The evidence is
   now partitioned into THIS ACTOR and OTHER ACTORS before generation.

3. DO NOT TRUST `full_log`.
   Step 9 removed it from the triage classifier because raw machine text
   caused inconsistent classification. This file searched it anyway, and it
   had already produced the corpus's only (wrong) `Execution` verdict.
   Stage inference now reads the same curated fields as triage.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from core.contracts import AttackStage, ForensicsResult, TimelineEvent
# The LLM layer from Step 13. `structured_call` promises that ONLY
# LLMUnavailable ever escapes it - but `narrate` still catches bare
# Exception, because that promise was broken once and killed a script.
from core.llm import LLMUnavailable, llm_available, structured_call
from core.models import Alert
from tools import history


# =============================================================================
# THE POLICY - every threshold in one place
# =============================================================================

TIMELINE_WINDOW_MINUTES = 60   # how far either side of the alert we look
TIMELINE_MAX_EVENTS = 25       # how many events a human can actually read
MIN_HOSTS = 2                  # "multi-host" starts at two


# Accounts that exist on many machines by design. Seeing one on several
# hosts is normal operation, not an intruder travelling.
GENERIC_ACCOUNTS = {
    "root", "admin", "administrator", "nobody", "system", "daemon",
    "guest", "test", "user", "ubuntu", "ec2-user", "postgres", "mysql",
    "oracle", "www-data", "postmaster", "support", "", "-",
}


# Which kill-chain stage a description suggests. ORDER MATTERS - first match
# wins - and the NON-ATTACK family comes first, for the same reason it comes
# first in tools/severity.py: asking "is this even an attack?" before
# "which attack?" stops normal operations being dressed up as intrusions.
STAGE_BY_KEYWORD: list[tuple[tuple[str, ...], AttackStage]] = [
    (("log file rotated", "session closed", "was solved", "was fixed",
      "log rotation", "logout"), AttackStage.NOT_APPLICABLE),
    (("exfiltration", "large outbound"), AttackStage.EXFILTRATION),
    (("crontab", "rootkit", "scheduled task", "backdoor"), AttackStage.PERSISTENCE),
    (("sudo to root", "privilege escalation", "setuid"),
     AttackStage.PRIVILEGE_ESCALATION),
    (("powershell", "command executed", "encoded command"), AttackStage.EXECUTION),
    (("authentication success", "session opened", "accepted password"),
     AttackStage.INITIAL_ACCESS),
    (("non-existent user", "brute force", "invalid user", "400 error",
      "authentication failure", "multiple authentication", "failed password",
      "scan", "sqlinjection", "sql injection", "xss"),
     AttackStage.INITIAL_ACCESS),
]


# =============================================================================
# SMALL HELPERS
# =============================================================================


def _parse(iso: str) -> datetime:
    """Turn a stored timestamp string back into a datetime."""
    return datetime.fromisoformat(iso)


def _same_actor(alert: Alert, src_ip: str | None,
                username: str | None) -> bool:
    """Is this event part of the SAME story as the focus alert?

    Two ways to be the same actor:
      - the same source address, or
      - the same account, but ONLY if that account is a real identity.

    A shared account is excluded for exactly the reason it is excluded from
    lateral-movement detection: two different attackers both guessing `root`
    are two attackers, not one. Everything else in the window is a
    coincidence of timing and must never be attributed here.
    """
    if alert.src_ip and src_ip == alert.src_ip:
        return True
    user = (alert.user or "").strip().lower()
    if user and user not in GENERIC_ACCOUNTS:
        return (username or "").strip().lower() == user
    return False


# =============================================================================
# STEP 1 - WHAT ELSE WAS HAPPENING?
# =============================================================================


def timeline_reconstruct(alert: Alert,
                         window_minutes: int = TIMELINE_WINDOW_MINUTES,
                         limit: int = TIMELINE_MAX_EVENTS) -> list[TimelineEvent]:
    """Every alert around this one, in time order, each marked by actor."""
    rows = history.alerts_near(alert.timestamp.isoformat(),
                               window_minutes=window_minutes, limit=limit)

    events = [TimelineEvent(
        timestamp=_parse(row["timestamp"]),
        alert_id=row["id"],
        host=row["agent_name"] or "unknown-host",
        description=row["rule_description"] or "(no description)",
        src_ip=row["src_ip"],
        username=row["username"],
        is_focus=(row["id"] == alert.id),
        # `row["id"] == alert.id or ...` is not redundant. An alert with NO
        # source IP and a generic account fails the actor test against its
        # OWN row, and was being labelled a stranger in its own timeline.
        # The alert under investigation IS the actor, by definition.
        same_actor=(row["id"] == alert.id
                    or _same_actor(alert, row["src_ip"], row["username"])),
    ) for row in rows]

    # If the alert is not in the database at all (a live alert, or a limit
    # that cut it), put it back. A timeline missing the event it is about
    # would be absurd.
    if all(not e.is_focus for e in events):
        events.append(TimelineEvent(
            timestamp=alert.timestamp, alert_id=alert.id,
            host=alert.agent_name, description=alert.rule_description,
            src_ip=alert.src_ip, username=alert.user,
            is_focus=True, same_actor=True))
        events.sort(key=lambda e: e.timestamp)

    return events


# =============================================================================
# STEP 2 - SPREAD, MOVEMENT, OR NEITHER?
# =============================================================================


def movement_check(alert: Alert,
                   window_minutes: int = TIMELINE_WINDOW_MINUTES) -> dict:
    """Decide whether this is lateral movement, horizontal spread, or neither."""
    when = alert.timestamp.isoformat()
    by_user = (history.hosts_for_user(alert.user, when, window_minutes)
               if alert.user else [])
    by_ip = (history.hosts_for_ip(alert.src_ip, when, window_minutes)
             if alert.src_ip else [])

    user_hosts = [r["agent_name"] for r in by_user]
    ip_hosts = [r["agent_name"] for r in by_ip]
    # `r["successes"] or 0` guards against SQL returning NULL.
    successes = sum(int(r["successes"] or 0) for r in by_user)

    account_is_generic = (alert.user or "").strip().lower() in GENERIC_ACCOUNTS

    lateral_signals: list[str] = []
    spread_signals: list[str] = []

    # One address, many hosts -> scanning. Never lateral movement: an IP is
    # not an identity, and an attacker scanning from one box has not moved.
    if len(ip_hosts) >= MIN_HOSTS:
        spread_signals.append(
            f"src_ip:{alert.src_ip} touched {len(ip_hosts)} hosts "
            f"in {window_minutes}min")

    if len(user_hosts) >= MIN_HOSTS:
        if account_is_generic:
            spread_signals.append(
                f"generic account '{alert.user}' seen on {len(user_hosts)} "
                f"hosts (shared account, not an identity)")
        elif successes == 0:
            # Tried several hosts and got into none: password spraying.
            spread_signals.append(
                f"user:{alert.user} attempted {len(user_hosts)} hosts with "
                f"no success recorded")
        else:
            # A real identity, several hosts, and it WORKED somewhere.
            # This is the only case that deserves the name.
            lateral_signals.append(
                f"user:{alert.user} on {len(user_hosts)} hosts with "
                f"{successes} successful authentication(s)")

    # `set(a) | set(b)` is the union: everything in either list, no repeats.
    affected = sorted(set(user_hosts) | set(ip_hosts))

    return {
        "lateral_movement": bool(lateral_signals),
        "horizontal_spread": bool(spread_signals),
        "lateral_signals": lateral_signals,
        "spread_signals": spread_signals,
        "affected_hosts": affected,
        "user_hosts": by_user,
        "ip_hosts": by_ip,
        "successes": successes,
        "account_is_generic": account_is_generic,
    }


# =============================================================================
# STEP 3 - WHERE IN THE KILL CHAIN?
# =============================================================================


def infer_attack_stage(alert: Alert, movement: dict) -> tuple[AttackStage, str]:
    """Which stage this looks like, and the evidence for it."""
    # Confirmed lateral movement overrides any keyword: it IS the stage.
    if movement["lateral_movement"]:
        return (AttackStage.LATERAL_MOVEMENT,
                "an identity authenticated successfully on multiple hosts")

    # `full_log` is deliberately NOT searched - see lesson 3 at the top of
    # this file. Only curated fields: the rule description, the triggering
    # alert's description, and Wazuh's own rule groups.
    haystack = " ".join(filter(None, [
        alert.rule_description.lower(),
        str(alert.raw.get("_trigger_description") or "").lower(),
        " ".join(str(g).lower()
                 for g in (alert.raw.get("_trigger_groups") or [])),
    ]))
    for keywords, stage in STAGE_BY_KEYWORD:
        for keyword in keywords:
            if keyword in haystack:
                return stage, f"keyword:{keyword}"

    return AttackStage.UNDETERMINED, "no stage keyword matched"


# =============================================================================
# STEP 4 - THE DETERMINISTIC INVESTIGATION
# =============================================================================


def investigate(alert: Alert,
                window_minutes: int = TIMELINE_WINDOW_MINUTES
                ) -> tuple[ForensicsResult, dict]:
    """The complete forensic pass. No language model involved.

    Returns (the result, information about how it was reached). The second
    value is the audit trail: every number the interface shows can be traced
    back to a query that produced it.
    """
    timeline = timeline_reconstruct(alert, window_minutes=window_minutes)
    movement = movement_check(alert, window_minutes=window_minutes)
    stage, stage_reason = infer_attack_stage(alert, movement)

    hosts_in_timeline = sorted({e.host for e in timeline
                                if e.host != "unknown-host"})
    affected = sorted(set(movement["affected_hosts"]) | set(hosts_in_timeline))

    # The analysis text names WHICH pattern was found and why. An analyst
    # reading "lateral movement: yes" with no reason cannot act on it.
    parts = [
        f"Reconstructed {len(timeline)} event(s) within {window_minutes} "
        f"minutes of {alert.id}, spanning {len(hosts_in_timeline)} "
        f"identifiable host(s)."
    ]
    if movement["lateral_movement"]:
        parts.append("LATERAL MOVEMENT: "
                     + "; ".join(movement["lateral_signals"]) + ".")
    elif movement["horizontal_spread"]:
        parts.append("Horizontal spread (scanning or spraying, not lateral "
                     "movement): " + "; ".join(movement["spread_signals"]) + ".")
    else:
        parts.append("No multi-host pattern in this window.")

    # Saying out loud how much of the window belongs to someone else. A
    # reviewer who sees "8 events" and is not told that 3 of them are a
    # different attacker will read the timeline as a single incident.
    others = sum(1 for e in timeline if not e.same_actor)
    if others:
        parts.append(f"{others} of the {len(timeline)} events in this window "
                     f"involve a different source or account and are not "
                     f"attributed to this actor.")

    parts.append(f"Attack stage {stage.value} from {stage_reason}.")

    result = ForensicsResult(
        timeline=timeline,
        affected_hosts=affected,
        lateral_movement=movement["lateral_movement"],
        horizontal_spread=movement["horizontal_spread"],
        attack_stage=stage,
        analysis=" ".join(parts),
    )
    meta = {
        "window_minutes": window_minutes,
        "timeline_events": len(timeline),
        "lateral_signals": movement["lateral_signals"],
        "spread_signals": movement["spread_signals"],
        "successes": movement["successes"],
        "account_is_generic": movement["account_is_generic"],
        "stage_reason": stage_reason,
        "user_hosts": movement["user_hosts"],
        "ip_hosts": movement["ip_hosts"],
    }
    return result, meta


# =============================================================================
# STEP 5 - THE LANGUAGE LAYER: prose over verified facts, nothing more
# =============================================================================

# Every line here exists to stop the model doing something we do not want.
# The second and third rules are the important ones: the deterministic layer
# has already decided what happened, and the model must not overrule it with
# a more exciting story.
NARRATIVE_SYSTEM_PROMPT = (
    "You are a SOC incident responder. You are given VERIFIED FACTS about "
    "one alert and the events around it, already reconstructed by "
    "deterministic tools. Your only job is to write the incident narrative "
    "and a containment priority.\n\n"
    "Rules you must follow:\n"
    "- Use ONLY the facts provided. Invent nothing.\n"
    "- If the facts say lateral movement is false, do NOT describe movement "
    "between hosts. Scanning is not movement.\n"
    "- Events listed under OTHER ACTORS belong to different sources or "
    "accounts. Never attribute them to this actor or fold them into this "
    "story.\n"
    "- Say plainly when the evidence is thin, and set a low priority.\n"
    "- The narrative must be 3 to 5 sentences, for a human analyst.\n"
    "- containment_priority is 0-100: how urgently a human should act."
)


class ForensicsNarrative(BaseModel):
    """The ONLY two things the model is allowed to produce.

    Deliberately tiny. The model cannot return a stage, a host list or a
    lateral-movement verdict, because code has already decided those.
    `min_length` rejects a one-word answer and `ge/le` make a priority of
    400 impossible rather than merely discouraged.
    """
    narrative: str = Field(min_length=60, max_length=1500)
    containment_priority: int = Field(ge=0, le=100)


def facts_for_prompt(alert: Alert, result: ForensicsResult,
                     meta: dict) -> str:
    """Build the fact block the model is given.

    Printable on purpose: whatever the model saw, you can see too. In a
    defense, showing the exact input beside the exact output is the
    difference between a demonstration and a magic trick - and it is how
    the attribution bug in this very function was found.
    """
    lines = [
        "ALERT",
        f"  id          : {alert.id}",
        f"  time        : {alert.timestamp.isoformat()}",
        f"  description : {alert.rule_description}",
        f"  wazuh level : {alert.rule_level}/15",
        f"  host        : {alert.agent_name}",
        f"  source ip   : {alert.src_ip or 'none'}",
        f"  account     : {alert.user or 'none'}",
        "",
        "MULTI-HOST ANALYSIS",
        f"  lateral movement  : {result.lateral_movement}",
        f"  horizontal spread : {result.horizontal_spread}",
        f"  successful auths  : {meta['successes']}",
        f"  generic account   : {meta['account_is_generic']}",
        f"  affected hosts    : {', '.join(result.affected_hosts) or 'none'}",
        f"  attack stage      : {result.attack_stage.value} "
        f"({meta['stage_reason']})",
        "",
    ]

    # TWO blocks, not one list. The model cannot reason about an attribution
    # boundary it was never shown, so the boundary is drawn for it, in the
    # data, under a heading that says what each group means.
    mine = [e for e in result.timeline if e.same_actor]
    theirs = [e for e in result.timeline if not e.same_actor]

    def block(title: str, events: list) -> None:
        """Append one labelled group of events to the fact block."""
        lines.append(title)
        if not events:
            lines.append("  (none)")
        for event in events:
            marker = ">>" if event.is_focus else "  "
            lines.append(f"  {marker} {event.timestamp.strftime('%H:%M:%S')} "
                         f"[{event.host}] {event.description[:58]}")
        lines.append("")

    block(f"THIS ACTOR - {len(mine)} event(s) in a "
          f"{meta['window_minutes']} minute window", mine)
    block(f"OTHER ACTORS - {len(theirs)} event(s) in the same window "
          f"(different source or account - DO NOT attribute to this actor)",
          theirs)
    return "\n".join(lines)


def narrate(alert: Alert,
            window_minutes: int = TIMELINE_WINDOW_MINUTES
            ) -> tuple[ForensicsResult, dict]:
    """The full forensic pass, WITH a written narrative when possible.

    Five paths, all of which return a usable result:
      1. stage is NotApplicable -> skip the model, save the money
      2. no API key / offline   -> deterministic text only
      3. the model answers      -> narrative appended to the analysis
      4. the model is down      -> deterministic text, reason recorded
      5. something unexpected   -> deterministic text, reason recorded

    `narrate` NEVER raises because of the model. The deterministic result
    exists before the model is contacted, so the worst case is plainer
    language, not a failed investigation.
    """
    result, meta = investigate(alert, window_minutes=window_minutes)

    # Set every audit key up front so later code never has to guess whether
    # a key exists, whichever path we take.
    meta.update({"llm_used": False, "usage": None, "fallback_reason": None,
                 "skipped_reason": None, "containment_priority": None,
                 "deterministic_analysis": result.analysis})

    # PATH 1 - a log rotation does not need a story written about it.
    if result.attack_stage is AttackStage.NOT_APPLICABLE:
        meta["skipped_reason"] = (
            "stage is NotApplicable - no attack to narrate")
        return result, meta

    # PATH 2 - no key, or SOC_OFFLINE_MODE is on.
    if not llm_available():
        meta["fallback_reason"] = "No API key, or offline mode is on."
        return result, meta

    try:
        # PATH 3 - the happy one.
        narrative, usage = structured_call(
            ForensicsNarrative, NARRATIVE_SYSTEM_PROMPT,
            facts_for_prompt(alert, result, meta))
        meta["llm_used"] = True
        meta["usage"] = usage
        meta["containment_priority"] = narrative.containment_priority
        # `model_copy(update=...)` makes a NEW result with one field changed.
        # The deterministic sentence is KEPT in front of the narrative, so a
        # reviewer always sees machine-checked facts first and prose second -
        # never prose alone.
        result = result.model_copy(update={
            "analysis": f"{result.analysis} NARRATIVE: {narrative.narrative}"})
    except LLMUnavailable as error:
        # PATH 4 - the documented failure.
        meta["fallback_reason"] = str(error)[:300]
    except Exception as error:
        # PATH 5 - the undocumented one. This net is here because the
        # "only LLMUnavailable escapes" promise failed once in Step 13 and
        # killed a running script.
        meta["fallback_reason"] = (
            f"Unexpected {type(error).__name__}: {str(error)[:250]}")

    return result, meta