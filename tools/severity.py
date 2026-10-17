"""
tools/severity.py
=================
The triage logic: turn one Alert into one TriageResult.

NO artificial intelligence is used here, and that is deliberate.

A severity decision must be REPRODUCIBLE. If the same alert can produce
"High" today and "Medium" tomorrow, the whole audit trail is worthless, and
a jury can destroy the project with one question. Fixed rules give the same
answer forever, and every clue that fired is written down in the result.

How the decision is made:
    1. WHAT kind of attack?  -> match keywords in the alert text
    2. HOW serious?          -> read the Wazuh level (0-15)
    3. Adjust the score      -> external IP? privileged account?
    4. Escalate or not?      -> Critical and High go to a human
"""

from __future__ import annotations

from core.contracts import AttackType, Severity, TriageResult
from core.models import Alert


# =============================================================================
# THE POLICY — all the thresholds live here, at the top, in one place
#
# Why at the top: during your defense someone will ask "where does the
# High threshold come from?". You scroll to line 30 and point. If these
# numbers were scattered through the code you could not answer cleanly.
# =============================================================================

# Wazuh grades alerts 0-15. These are the boundaries between severity bands.
LEVEL_CRITICAL = 12   # 12, 13, 14, 15  -> Critical
LEVEL_HIGH = 10       # 10, 11          -> High
LEVEL_MEDIUM = 7      # 7, 8, 9         -> Medium
LEVEL_LOW = 4         # 4, 5, 6         -> Low
#                       0, 1, 2, 3      -> Info


# The keyword table: which words mean which kind of attack.
#
# This is a LIST OF PAIRS. Each pair is (attack type, the words that signal it).
# Order matters — the first match wins — so the most specific families come
# first and the vaguest come last.
#
# Why a table instead of a long chain of if-statements: you can add a new
# attack family by adding one line, with no logic to rewrite. A jury can read
# the whole classification policy in twenty seconds.
ATTACK_KEYWORDS: list[tuple[AttackType, tuple[str, ...]]] = [
    (AttackType.BRUTE_FORCE, (
        "brute force", "authentication failure", "failed login",
        "non-existent user", "multiple failed", "missed the password",
        "login failed", "invalid user",
    )),
    (AttackType.MALWARE, (
        "malware", "virus", "trojan", "ransomware", "quarantine",
        "malicious file", "antivirus",
    )),
    (AttackType.PRIVILEGE_ESCALATION, (
        "sudo", "privilege", "root", "administrator", "setuid", "elevation",
    )),
    (AttackType.DATA_EXFILTRATION, (
        "exfiltration", "large outbound", "data transfer", "upload to external",
    )),
    (AttackType.WEB_ATTACK, (
        "sql injection", "xss", "web server", "400 error", "404",
        "wp-login", "shellshock", "web attack",
    )),
    (AttackType.PERSISTENCE, (
        "rootkit", "hidden process", "scheduled task", "cron",
        "backdoor", "rootcheck", "persistence",
    )),
    (AttackType.RECONNAISSANCE, (
        "scan", "port scan", "probe", "enumeration", "nmap",
    )),
    (AttackType.POLICY_VIOLATION, (
        "policy", "integrity checksum", "file rotated", "configuration changed",
    )),
]


# The severity bands, highest first. We walk this list and take the first
# band the alert reaches.
SEVERITY_BY_BAND: list[tuple[int, Severity]] = [
    (LEVEL_CRITICAL, Severity.CRITICAL),
    (LEVEL_HIGH, Severity.HIGH),
    (LEVEL_MEDIUM, Severity.MEDIUM),
    (LEVEL_LOW, Severity.LOW),
]


# =============================================================================
# STEP 1 — WHAT KIND OF ATTACK?
# =============================================================================


def classify_attack_type(alert: Alert) -> tuple[AttackType, list[str]]:
    """Find the attack family by searching the alert's text for keywords.

    Returns TWO things: the attack type, AND the list of clues that proved it.
    Returning the evidence alongside the answer is what makes the decision
    auditable instead of merely asserted.
    """
    # Build one big block of lowercase text to search in.
    # We search three places, because the useful word may be in any of them:
    #   1. the rule description  ("sshd: brute force trying to get access")
    #   2. the raw log line      (the real evidence from the machine)
    #   3. the Wazuh rule groups (["syslog", "sshd", "authentication_failures"])
    #
    # `.lower()` makes everything lowercase so "Brute Force" matches "brute force".
    # `filter(None, [...])` drops any empty pieces.
    # `" ".join(...)` glues what is left into one string.
    rule_block = alert.raw.get("rule", {})
    groups_text = ""
    if isinstance(rule_block, dict):
        groups_text = " ".join(str(g).lower() for g in rule_block.get("groups", []))

    haystack = " ".join(filter(None, [
        alert.rule_description.lower(),
        (alert.full_log or "").lower(),
        groups_text,
    ]))

    # Walk the table in order and return on the first keyword that appears.
    for attack_type, keywords in ATTACK_KEYWORDS:
        for keyword in keywords:
            if keyword in haystack:
                return attack_type, [f"keyword:{keyword}"]

    # Nothing matched. We say UNKNOWN honestly instead of guessing.
    # An honest "I don't know" is far better than a confident wrong answer,
    # especially in security.
    return AttackType.UNKNOWN, []


# =============================================================================
# STEP 2 — HOW SERIOUS?
# =============================================================================


def base_severity(rule_level: int) -> Severity:
    """Turn the Wazuh level (0-15) into one of our five severity words."""
    # The list is ordered highest first, so the first band we reach is correct.
    for threshold, severity in SEVERITY_BY_BAND:
        if rule_level >= threshold:
            return severity
    # Below every threshold, so levels 0-3.
    return Severity.INFO


# =============================================================================
# STEP 3 — PUT IT ALL TOGETHER
# =============================================================================


def assign_severity(alert: Alert) -> TriageResult:
    """The complete triage decision. One Alert in, one TriageResult out.

    This is the function the triage agent will call. It is a PURE function:
    it reads nothing outside its input, changes nothing, touches no network
    and no clock. Same input, same output, forever. That is what makes it
    testable and what makes the result reproducible.
    """
    # We collect every clue here as we go. This list becomes the proof.
    signals: list[str] = []

    # --- What kind of attack? ------------------------------------------------
    attack_type, type_signals = classify_attack_type(alert)
    # `.extend()` adds all items of one list into another.
    signals.extend(type_signals)

    # --- How serious? --------------------------------------------------------
    severity = base_severity(alert.rule_level)
    signals.append(f"wazuh_level:{alert.rule_level}")

    # Turn the 0-15 level into a 0-100 score, then adjust it with context.
    # `round()` gives a whole number, which our contract requires.
    score = round(alert.rule_level / 15 * 100)

    # --- Context adjustment 1: where did it come from? -----------------------
    # An attack from the public internet is more worrying than one from the
    # office network. `is_private_src` is the helper we built in Step 4.
    if alert.src_ip and not alert.is_private_src:
        # `min(100, ...)` stops the score going above 100, which our contract
        # would refuse.
        score = min(100, score + 10)
        signals.append("external_source_ip")
    elif alert.is_private_src:
        signals.append("internal_source_ip")

    # --- Context adjustment 2: which account? --------------------------------
    # An attack on a powerful account matters more.
    # Curly braces make a SET, which is the fastest way to ask "is it one of these?"
    if alert.user in {"root", "admin", "administrator"}:
        score = min(100, score + 5)
        signals.append(f"privileged_account:{alert.user}")

    # --- How confident are we? -----------------------------------------------
    # Honest confidence, not decoration. If we could not even identify the
    # attack type, we say so with a low number.
    if attack_type is AttackType.UNKNOWN:
        confidence = 0.40
    elif alert.rule_level >= LEVEL_HIGH:
        confidence = 0.95
    elif alert.rule_level >= LEVEL_MEDIUM:
        confidence = 0.80
    else:
        confidence = 0.65

    # --- The decision that drives the whole graph ----------------------------
    # This single True/False later decides whether the pipeline STOPS and waits
    # for a human, or closes by itself. It is the most important line here.
    escalate = severity in (Severity.CRITICAL, Severity.HIGH)

    # --- Write the explanation for the human reader --------------------------
    rationale = (
        f"Wazuh rule {alert.rule_id} fired at level {alert.rule_level}/15 on "
        f"{alert.agent_name}, mapped to {severity.value} severity. "
        f"Classified as {attack_type.value} from {len(signals)} matched signal(s). "
        f"{'Escalating to Tier 2.' if escalate else 'Auto-closing at Tier 1.'}"
    )

    # Build the contract object. If anything we computed were out of range,
    # Pydantic would refuse it right here — the quality gate from Step 5.
    return TriageResult(
        attack_type=attack_type,
        severity=severity,
        score=score,
        confidence=confidence,
        rationale=rationale,
        escalate_to_tier2=escalate,
        matched_signals=signals,
    )