"""
tools/severity.py
=================
The triage logic: turn one Alert into one TriageResult. No AI, by design.

This version was CORRECTED using evidence from the real dataset. Three
changes, each driven by something the data showed us:

  1. We no longer search `full_log`.
     It is free text, and it caused the same description to be classified
     two different ways depending on which words happened to appear.
     We search the description and Wazuh's own curated rule GROUPS instead.
     Groups like ["syslog", "sshd", "authentication_failed"] are written by
     the rule author, not by chance.

  2. Precise phrases instead of bare words.
     "root" used to match "PAM: Login session opened for root", which is
     normal activity, not privilege escalation. Now we require
     "successful sudo to root".

  3. Two honest non-threat categories.
     A successful login and a fixed CVE are not attacks. Forcing them into
     an attack family would make the system confidently wrong.
"""

from __future__ import annotations

from core.contracts import AttackType, Severity, TriageResult
from core.models import Alert


# =============================================================================
# THE POLICY - every threshold in one place, at the top
# =============================================================================

LEVEL_CRITICAL = 12   # 12-15 -> Critical
LEVEL_HIGH = 10       # 10-11 -> High
LEVEL_MEDIUM = 7      # 7-9   -> Medium
LEVEL_LOW = 4         # 4-6   -> Low
#                       0-3   -> Info


# ORDER MATTERS: the first match wins.
#
# The two non-threat families come FIRST on purpose. "sshd: authentication
# success" contains the word "authentication", which would otherwise be
# caught by the brute-force family. Checking "is this normal?" before
# "is this an attack?" prevents that mistake.
ATTACK_KEYWORDS: list[tuple[AttackType, tuple[str, ...]]] = [
    (AttackType.NORMAL_ACTIVITY, (
        "authentication success", "login session opened", "login session closed",
        "session opened", "session closed", "log file rotated", "logon success",
        "connection reset", "database update",
    )),
    (AttackType.VULNERABILITY, (
        "cve-", "vulnerability", "was solved", "package upgrade",
    )),
    (AttackType.BRUTE_FORCE, (
        "brute force", "authentication failure", "failed login", "login failed",
        "non-existent user", "multiple failed", "missed the password",
        "invalid user",
        # These two are Wazuh GROUP names, not description words. Groups are
        # curated by the rule author, so they are a very reliable signal.
        "authentication_failed", "authentication_failures",
    )),
    (AttackType.MALWARE, (
        "malware", "virus detected", "trojan", "ransomware", "quarantine",
        "malicious file",
    )),
    (AttackType.PERSISTENCE, (
        # A changed crontab is how an attacker survives a reboot.
        "crontab", "scheduled task", "rootkit", "hidden process",
        "backdoor", "rootcheck",
    )),
    (AttackType.PRIVILEGE_ESCALATION, (
        # Full phrases only. A bare "root" or "sudo" matched normal logins.
        "successful sudo to root", "sudo to root", "privilege escalation",
        "setuid", "added to group root", "su to root",
    )),
    (AttackType.DATA_EXFILTRATION, (
        "exfiltration", "large outbound", "upload to external",
    )),
    (AttackType.WEB_ATTACK, (
        "sql injection", "shellshock", "wp-login", "web server 400",
        "web server 500", "web server 403", "xss",
        "web_scan", "accesslog",   # Wazuh group names
    )),
    (AttackType.RECONNAISSANCE, (
        "port scan", "nmap", "enumeration", "probe",
    )),
    (AttackType.POLICY_VIOLATION, (
        "integrity checksum", "configuration changed", "policy violation",
    )),
]


SEVERITY_BY_BAND: list[tuple[int, Severity]] = [
    (LEVEL_CRITICAL, Severity.CRITICAL),
    (LEVEL_HIGH, Severity.HIGH),
    (LEVEL_MEDIUM, Severity.MEDIUM),
    (LEVEL_LOW, Severity.LOW),
]


# Events that are not attacks. They are always forced down to Info.
# A set (curly braces) is the fastest way to ask "is it one of these?".
NON_THREATS = {AttackType.NORMAL_ACTIVITY, AttackType.VULNERABILITY}


# =============================================================================
# STEP 1 - WHAT KIND OF ATTACK?
# =============================================================================


def _classification_text(alert: Alert) -> str:
    """Build the text we search, from TRUSTED fields only.

    Four sources, all curated by Wazuh or recovered deliberately by us:
      1. the rule description
      2. the Wazuh rule groups
      3. the description of the alert that triggered an active response
      4. that trigger alert's groups

    `full_log` is deliberately NOT here. It is raw machine output and it was
    the cause of inconsistent classification.
    """
    pieces = [alert.rule_description.lower()]

    rule_block = alert.raw.get("rule")
    if isinstance(rule_block, dict):
        pieces.append(" ".join(str(g).lower() for g in rule_block.get("groups", [])))

    trigger = alert.raw.get("_trigger_description")
    if trigger:
        pieces.append(str(trigger).lower())

    pieces.append(" ".join(str(g).lower() for g in alert.raw.get("_trigger_groups", [])))

    return " ".join(piece for piece in pieces if piece)


def classify_attack_type(alert: Alert) -> tuple[AttackType, list[str]]:
    """Find the attack family. Returns the answer AND the clue that proved it."""
    haystack = _classification_text(alert)
    for attack_type, keywords in ATTACK_KEYWORDS:
        for keyword in keywords:
            if keyword in haystack:
                return attack_type, [f"keyword:{keyword}"]
    # Honest "I don't know" beats a confident wrong answer.
    return AttackType.UNKNOWN, []


# =============================================================================
# STEP 2 - HOW SERIOUS?
# =============================================================================


def base_severity(rule_level: int) -> Severity:
    """Turn the Wazuh level (0-15) into one of our five severity words."""
    for threshold, severity in SEVERITY_BY_BAND:
        if rule_level >= threshold:
            return severity
    return Severity.INFO


# =============================================================================
# STEP 3 - PUT IT ALL TOGETHER
# =============================================================================


def assign_severity(alert: Alert) -> TriageResult:
    """The complete triage decision. One Alert in, one TriageResult out.

    A pure function: no network, no clock, no hidden state. Same input,
    same output, forever.
    """
    signals: list[str] = []

    attack_type, type_signals = classify_attack_type(alert)
    signals.extend(type_signals)

    # If this alert came from an active-response record, say so explicitly.
    # Before this line, the behaviour happened by accident. Now it is
    # deliberate AND written into the audit trail.
    if alert.raw.get("_trigger_description"):
        signals.append(f"active_response:{alert.raw.get('_response_command', 'unknown')}")
        signals.append(f"trigger_rule:{alert.raw.get('_trigger_rule_id', '?')}")

    severity = base_severity(alert.rule_level)
    signals.append(f"wazuh_level:{alert.rule_level}")
    score = round(alert.rule_level / 15 * 100)

    if attack_type in NON_THREATS:
        # Not an attack. Force it to the bottom and skip the threat
        # adjustments entirely - an external IP on a successful login is
        # just a person working from home.
        severity = Severity.INFO
        score = min(score, 10)
        signals.append("non_threat_event")
    else:
        if alert.src_ip and not alert.is_private_src:
            score = min(100, score + 10)
            signals.append("external_source_ip")
        elif alert.is_private_src:
            signals.append("internal_source_ip")

        if alert.user in {"root", "admin", "administrator"}:
            score = min(100, score + 5)
            signals.append(f"privileged_account:{alert.user}")

    if attack_type is AttackType.UNKNOWN:
        confidence = 0.40
    elif attack_type in NON_THREATS:
        confidence = 0.90
    elif alert.rule_level >= LEVEL_HIGH:
        confidence = 0.95
    elif alert.rule_level >= LEVEL_MEDIUM:
        confidence = 0.80
    else:
        confidence = 0.65

    escalate = severity in (Severity.CRITICAL, Severity.HIGH)

    rationale = (
        f"Wazuh rule {alert.rule_id} fired at level {alert.rule_level}/15 on "
        f"{alert.agent_name}, mapped to {severity.value} severity. "
        f"Classified as {attack_type.value} from {len(signals)} matched signal(s). "
        f"{'Escalating to Tier 2.' if escalate else 'Auto-closing at Tier 1.'}"
    )

    return TriageResult(
        attack_type=attack_type,
        severity=severity,
        score=score,
        confidence=confidence,
        rationale=rationale,
        escalate_to_tier2=escalate,
        matched_signals=signals,
    )