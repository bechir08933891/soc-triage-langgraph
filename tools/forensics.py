"""
tools/forensics.py
==================
Rebuild the story around an alert, and work out what the multi-host pattern
actually means.

THE CENTRAL DISTINCTION, and the thing this file exists to get right:

    one SOURCE  -> many hosts                  = HORIZONTAL SPREAD
                                                 (scanning, password spraying)

    one IDENTITY -> many hosts, WITH a
                    successful authentication  = LATERAL MOVEMENT
                                                 (the attacker is inside)

An earlier version of this file used the rule "same user on two or more
hosts". Tested on the corpus it flagged 100% of alerts, because `root` and
`admin` exist on every machine and scanners touch every machine. Conflating
the two makes every scanned network look breached.

Three guards fix it:
  1. generic accounts are excluded - a shared account is not an identity
  2. a recorded SUCCESS is required - attempts alone are spraying
  3. everything is TIME-WINDOWED - "ever" is almost always true
"""

from __future__ import annotations

from datetime import datetime

from core.contracts import AttackStage, ForensicsResult, TimelineEvent
from core.models import Alert
from tools import history


TIMELINE_WINDOW_MINUTES = 60
TIMELINE_MAX_EVENTS = 25
MIN_HOSTS = 2


# Accounts that exist on many machines by design. Seeing one on several
# hosts is normal operation, not an intruder moving between them.
GENERIC_ACCOUNTS = {
    "root", "admin", "administrator", "nobody", "system", "daemon",
    "guest", "test", "user", "ubuntu", "ec2-user", "postgres", "mysql",
    "oracle", "www-data", "postmaster", "support", "", "-",
}


# Which kill-chain stage a description suggests. Order matters: the later
# stages are checked first, because an alert mentioning both a login and
# exfiltration is better described by the exfiltration.
STAGE_BY_KEYWORD: list[tuple[tuple[str, ...], AttackStage]] = [
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


def _parse(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


def timeline_reconstruct(alert: Alert,
                         window_minutes: int = TIMELINE_WINDOW_MINUTES,
                         limit: int = TIMELINE_MAX_EVENTS) -> list[TimelineEvent]:
    """Every alert around this one, in time order, with this one marked."""
    rows = history.alerts_near(alert.timestamp.isoformat(),
                               window_minutes=window_minutes, limit=limit)

    events = [TimelineEvent(
        timestamp=_parse(row["timestamp"]),
        alert_id=row["id"],
        host=row["agent_name"] or "unknown-host",
        description=row["rule_description"] or "(no description)",
        is_focus=(row["id"] == alert.id),
    ) for row in rows]

    # If the limit cut our own alert out of its own timeline, put it back.
    # A timeline missing the event it is about would be absurd.
    if all(not e.is_focus for e in events):
        events.append(TimelineEvent(
            timestamp=alert.timestamp, alert_id=alert.id,
            host=alert.agent_name, description=alert.rule_description,
            is_focus=True))
        events.sort(key=lambda e: e.timestamp)

    return events


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
            # This is the one case that deserves the name.
            lateral_signals.append(
                f"user:{alert.user} on {len(user_hosts)} hosts with "
                f"{successes} successful authentication(s)")

    # `set(a) | set(b)` is the union: everything in either list, no duplicates.
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


def infer_attack_stage(alert: Alert, movement: dict) -> tuple[AttackStage, str]:
    """Which kill-chain stage this looks like, and the evidence for it."""
    # Confirmed lateral movement overrides any keyword: it IS the stage.
    if movement["lateral_movement"]:
        return (AttackStage.LATERAL_MOVEMENT,
                "an identity authenticated successfully on multiple hosts")

    haystack = " ".join(filter(None, [
        alert.rule_description.lower(),
        (alert.full_log or "").lower(),
        str(alert.raw.get("_trigger_description") or "").lower(),
    ]))
    for keywords, stage in STAGE_BY_KEYWORD:
        for keyword in keywords:
            if keyword in haystack:
                return stage, f"keyword:{keyword}"

    return AttackStage.UNDETERMINED, "no stage keyword matched"


def investigate(alert: Alert,
                window_minutes: int = TIMELINE_WINDOW_MINUTES
                ) -> tuple[ForensicsResult, dict]:
    """The complete forensic pass. No language model involved.

    Returns (the result, information about how it was reached).
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