"""
tools/mitre.py
==============
Map an alert to MITRE ATT&CK techniques.

MITRE ATT&CK is the worldwide reference catalogue of attacker methods.
Naming a technique turns "someone tried passwords" into "T1110, Brute Force,
Credential Access tactic" — precise, searchable, and understood by every
analyst in the world.

Every ID, name and tactic below was verified against attack.mitre.org.

One thing to note: MITRE has RENAMED tactic TA0005 from "Defense Evasion"
to "Stealth". Older papers and tutorials still use the old name. We use the
current one.
"""

from __future__ import annotations

from core.contracts import AttackType, MitreTechnique
from core.models import Alert

# A short alias, purely so the table below stays readable.
T = MitreTechnique


# =============================================================================
# THE BASE MAP — one broad technique per attack family
#
# A dictionary: give it an AttackType, get back the matching techniques.
# This is the "I know roughly what kind of attack this is" level.
# =============================================================================

BASE_MAP: dict[AttackType, list[MitreTechnique]] = {
    AttackType.BRUTE_FORCE: [
        T(technique_id="T1110", name="Brute Force", tactic="Credential Access"),
    ],
    AttackType.WEB_ATTACK: [
        T(technique_id="T1190", name="Exploit Public-Facing Application",
          tactic="Initial Access"),
    ],
    AttackType.RECONNAISSANCE: [
        T(technique_id="T1595", name="Active Scanning", tactic="Reconnaissance"),
    ],
    AttackType.MALWARE: [
        T(technique_id="T1204", name="User Execution", tactic="Execution"),
    ],
    AttackType.PERSISTENCE: [
        T(technique_id="T1053", name="Scheduled Task/Job", tactic="Persistence"),
    ],
    AttackType.PRIVILEGE_ESCALATION: [
        T(technique_id="T1548", name="Abuse Elevation Control Mechanism",
          tactic="Privilege Escalation"),
    ],
    AttackType.DATA_EXFILTRATION: [
        T(technique_id="T1041", name="Exfiltration Over C2 Channel",
          tactic="Exfiltration"),
    ],
    # Even normal activity has a technique. An attacker using a stolen but
    # valid password looks exactly like a legitimate login — that is T1078,
    # and it is why successful logins are still worth recording.
    AttackType.NORMAL_ACTIVITY: [
        T(technique_id="T1078", name="Valid Accounts", tactic="Stealth"),
    ],
}


# =============================================================================
# SUB-TECHNIQUES — the precise variant, when the text gives it away
#
# A sub-technique is a child of a technique: T1110.001 is one specific way
# of doing T1110. Naming it is much more useful to an analyst.
#
# This is a LIST OF PAIRS: (words to look for, the technique they prove).
# Unlike the severity table, we do NOT stop at the first match — an alert
# can legitimately show several techniques at once.
# =============================================================================

SUB_TECHNIQUES: list[tuple[tuple[str, ...], MitreTechnique]] = [
    (("non-existent user", "invalid user", "password guessing"),
     T(technique_id="T1110.001", name="Password Guessing",
       tactic="Credential Access")),

    (("password spraying", "multiple users"),
     T(technique_id="T1110.003", name="Password Spraying",
       tactic="Credential Access")),

    (("wp-login", "404", "wordlist", "directory"),
     T(technique_id="T1595.003", name="Wordlist Scanning",
       tactic="Reconnaissance")),

    (("vulnerability scan", "nessus", "openvas"),
     T(technique_id="T1595.002", name="Vulnerability Scanning",
       tactic="Reconnaissance")),

    (("crontab", "cron"),
     T(technique_id="T1053.003", name="Cron", tactic="Persistence")),

    (("sudo",),
     T(technique_id="T1548.003", name="Sudo and Sudo Caching",
       tactic="Privilege Escalation")),

    (("rootkit", "hidden process"),
     T(technique_id="T1014", name="Rootkit", tactic="Stealth")),
]


def _searchable_text(alert: Alert) -> str:
    """The text we look for keywords in.

    Here we DO include `full_log`, unlike in severity.py. The reason is the
    cost of a mistake. A wrong severity changes whether a human is woken up.
    A wrong extra technique only adds a line to a report, and an analyst can
    see for themselves whether it fits. Different risk, different rule.
    """
    pieces = [alert.rule_description.lower(), (alert.full_log or "").lower()]
    trigger = alert.raw.get("_trigger_description")
    if trigger:
        pieces.append(str(trigger).lower())
    return " ".join(piece for piece in pieces if piece)


def map_to_mitre(alert: Alert, attack_type: AttackType) -> list[MitreTechnique]:
    """Return every MITRE technique this alert shows.

    Two passes:
      1. the broad technique for the attack family
      2. any precise sub-technique the text reveals
    """
    # `list(...)` makes a COPY. Without it we would be adding items to the
    # BASE_MAP itself, which would grow forever and corrupt later calls.
    # This kind of bug is silent and very hard to find.
    techniques: list[MitreTechnique] = list(BASE_MAP.get(attack_type, []))

    haystack = _searchable_text(alert)

    for keywords, technique in SUB_TECHNIQUES:
        # `any(... for ...)` is True if at least one keyword is present.
        if any(keyword in haystack for keyword in keywords):
            # `all(...)` here means "none of the techniques we already have
            # has this same id" — in other words, do not add a duplicate.
            if all(t.technique_id != technique.technique_id for t in techniques):
                techniques.append(technique)

    return techniques