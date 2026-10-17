"""
core/contracts.py
=================
The OUTPUT contracts: what each of the five agents must give back.

`models.py` answers "what comes IN?" (the Alert).
`contracts.py` answers "what must each agent give BACK?".

The key idea here is the CLOSED VOCABULARY. An AI model writing free text
could answer "High", "HIGH", "very bad" or "pretty serious". A program cannot
work with that. So we write the allowed words ourselves, and anything else is
refused automatically.
"""

from __future__ import annotations

# `Enum` means "enumeration": a fixed list of allowed named choices.
# Think of it as a multiple-choice question where we write the options.
from enum import Enum

from pydantic import BaseModel, Field


# =============================================================================
# PART 1 — THE CLOSED VOCABULARIES
#
# Each class below is one multiple-choice question with a fixed answer list.
#
# `class Severity(str, Enum)` inherits from BOTH str and Enum. That double
# inheritance is deliberate and useful: the value behaves like a normal piece
# of text (so it can be saved to a file or printed), while still being a
# controlled choice (so a wrong value is impossible).
# =============================================================================


class Severity(str, Enum):
    """How serious is this alert? Exactly five answers are possible."""

    # On the left: the name we use in code (always written in CAPITALS).
    # On the right: the text that is really stored and displayed.
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AttackType(str, Enum):
    """What kind of attack is this? The triage agent must pick one."""

    BRUTE_FORCE = "BruteForce"                   # repeated password guessing
    MALWARE = "Malware"                          # a virus or malicious file
    PRIVILEGE_ESCALATION = "PrivilegeEscalation" # gaining admin rights
    DATA_EXFILTRATION = "DataExfiltration"       # stealing and sending out data
    RECONNAISSANCE = "Reconnaissance"            # scanning, looking around
    WEB_ATTACK = "WebAttack"                     # attacking a website
    PERSISTENCE = "Persistence"                  # staying in after being kicked out
    POLICY_VIOLATION = "PolicyViolation"         # breaking a company rule

    # Always provide an honest escape hatch. Without UNKNOWN, the agent would
    # be forced to guess a wrong category, which is worse than admitting doubt.
    UNKNOWN = "Unknown"


class AttackStage(str, Enum):
    """How far has the attacker already gone? Used later by the forensics agent.

    These names come from the classic kill-chain used in the security industry,
    so a real analyst will recognise them immediately.
    """

    INITIAL_ACCESS = "InitialAccess"             # they just got in
    EXECUTION = "Execution"                      # they ran something
    PERSISTENCE = "Persistence"                  # they installed a back door
    PRIVILEGE_ESCALATION = "PrivilegeEscalation" # they became administrator
    LATERAL_MOVEMENT = "LateralMovement"         # they moved to another machine
    EXFILTRATION = "Exfiltration"                # they are stealing data
    UNDETERMINED = "Undetermined"                # not enough evidence to say


class Verdict(str, Enum):
    """What does the threat database say about an IP address or a file?

    Lowercase here, because this is what the external APIs (AbuseIPDB,
    VirusTotal) actually return. We keep their wording so the mapping is
    obvious to anyone reading the audit trail.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    """The three buttons the human analyst can press in the demo interface."""

    APPROVED = "approved"    # yes, this is a real incident, escalate it
    REJECTED = "rejected"    # false alarm, close it
    ESCALATED = "escalated"  # too serious for Tier 2, send it higher


# =============================================================================
# PART 2 — THE TRIAGE AGENT'S OUTPUT
# =============================================================================


class TriageResult(BaseModel):
    """What the `triage` agent must produce. Agent number 1 of 5.

    Reminder about this agent: it uses NO artificial intelligence. It applies
    fixed rules. That is a deliberate design choice, because a severity score
    must be reproducible: the same alert must always give the same answer.
    A jury can re-run it and get an identical result. An AI could not promise that.
    """

    # The attack family. Because the type is `AttackType`, only the nine words
    # listed above can ever be stored here.
    attack_type: AttackType

    # How serious. Only the five Severity words are possible.
    severity: Severity

    # A numeric risk score from 0 to 100. Useful for sorting many alerts.
    # ge = "greater than or equal to", le = "less than or equal to".
    score: int = Field(ge=0, le=100, description="Risk score, 0 to 100")

    # How sure are we? A decimal between 0.0 (no idea) and 1.0 (certain).
    # 0.9 means ninety percent confident.
    confidence: float = Field(ge=0.0, le=1.0, description="From 0.0 to 1.0")

    # WHY did we decide this? Written in plain words, for the human reader.
    # `min_length=10` blocks lazy answers like "ok" or "bad". An audit trail
    # with no explanation has no value, so we refuse one at the contract level.
    rationale: str = Field(
        min_length=10,
        description="Human-readable explanation of the decision",
    )

    # Should this alert go to a Tier 2 analyst?
    # `bool` means True or False only. This single field later decides whether
    # the graph stops and waits for a human, or closes by itself.
    escalate_to_tier2: bool

    # Which clues led to the decision, e.g. ["rule:5710", "level>=10"].
    # `list[str]` means "a list of pieces of text".
    # `default_factory=list` means "if nothing is given, start with an empty list".
    # This is how we PROVE the decision instead of just asserting it.
    matched_signals: list[str] = Field(default_factory=list)

    def headline(self) -> str:
        """One short line for the live log of the demo interface."""
        # `.value` takes the stored text out of the Enum ("High", not Severity.HIGH).
        # `:.0%` formats 0.9 as "90%" — zero digits after the decimal point.
        return (
            f"{self.attack_type.value} / {self.severity.value} "
            f"(score {self.score}/100, confidence {self.confidence:.0%})"
        )