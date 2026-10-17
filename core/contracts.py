"""
core/contracts.py
=================
The OUTPUT contracts: what each of the five agents must give back.

`models.py` answers "what comes IN?" (the Alert).
`contracts.py` answers "what must each agent give BACK?".

The key idea is the CLOSED VOCABULARY. An AI model writing free text could
answer "High", "HIGH", "very bad" or "pretty serious". A program cannot work
with that. So we write the allowed words ourselves, and anything else is
refused automatically.

Layout of this file:
    PART 1 — the closed vocabularies (Enums)
    PART 2 — the triage agent's output
    PART 3 — the hunter agent's output
    PART 4 — the forensics agent's output
    PART 5 — the human decision and the final report
"""

from __future__ import annotations

# `datetime` for points in time, `timezone` to mark them as UTC.
from datetime import datetime, timezone

# `Enum` means "enumeration": a fixed list of allowed named choices.
# Think of it as a multiple-choice question where we write the options.
from enum import Enum

# `Optional[str]` means "either text, or nothing at all".
from typing import Optional

from pydantic import BaseModel, Field


# =============================================================================
# PART 1 — THE CLOSED VOCABULARIES
#
# Each class below is one multiple-choice question with a fixed answer list.
#
# `class Severity(str, Enum)` inherits from BOTH str and Enum. That double
# inheritance is deliberate: the value behaves like normal text (so it can be
# saved to a file or printed), while still being a controlled choice (so a
# wrong value is impossible).
# =============================================================================


class Severity(str, Enum):
    """How serious is this alert? Exactly five answers are possible."""

    # On the left: the name we use in code (always CAPITALS).
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
    VULNERABILITY = "Vulnerability"              # a CVE found or fixed. Not an attack.
    NORMAL_ACTIVITY = "NormalActivity"           # successful login, closed session. Normal.
    # Always provide an honest escape hatch. Without UNKNOWN, the agent would
    # be forced to guess a wrong category, which is worse than admitting doubt.
    UNKNOWN = "Unknown"


class AttackStage(str, Enum):
    """How far has the attacker already gone? Used by the forensics agent.

    These names come from the classic kill-chain used in the security industry,
    so a real analyst recognises them immediately.
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
    VirusTotal) actually return. We keep their wording so the mapping stays
    obvious to anyone reading the audit trail.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    """The three buttons the human analyst can press in the demo interface."""

    APPROVED = "approved"    # yes, real incident, escalate it
    REJECTED = "rejected"    # false alarm, close it
    ESCALATED = "escalated"  # too serious for Tier 2, send it higher


# =============================================================================
# PART 2 — THE TRIAGE AGENT'S OUTPUT  (agent 1 of 5)
# =============================================================================


class TriageResult(BaseModel):
    """What the `triage` agent must produce.

    Reminder: this agent uses NO artificial intelligence. It applies fixed
    rules. That is deliberate, because a severity score must be reproducible:
    the same alert must always give the same answer. A jury can re-run it and
    get an identical result. An AI could not promise that.
    """

    # Because the type is `AttackType`, only the nine words listed above can
    # ever be stored here.
    attack_type: AttackType

    # Only the five Severity words are possible.
    severity: Severity

    # A numeric risk score, useful for sorting many alerts.
    # ge = "greater than or equal to", le = "less than or equal to".
    score: int = Field(ge=0, le=100, description="Risk score, 0 to 100")

    # How sure are we? 0.0 = no idea, 1.0 = certain. 0.9 means 90% confident.
    confidence: float = Field(ge=0.0, le=1.0, description="From 0.0 to 1.0")

    # WHY did we decide this? `min_length=10` blocks lazy answers like "ok".
    # An audit trail with no explanation has no value, so we refuse one here.
    rationale: str = Field(min_length=10, description="Why we decided this")

    # Should a Tier 2 human see this? This single True/False later decides
    # whether the graph stops and waits for a person, or closes by itself.
    escalate_to_tier2: bool

    # The clues behind the decision, e.g. ["rule:5710", "level>=10"].
    # This is how we PROVE the decision instead of just asserting it.
    matched_signals: list[str] = Field(default_factory=list)

    def headline(self) -> str:
        """One short line for the live log of the demo interface."""
        # `.value` takes the text out of the Enum ("High", not Severity.HIGH).
        # `:.0%` formats 0.9 as "90%" — zero digits after the decimal point.
        return (
            f"{self.attack_type.value} / {self.severity.value} "
            f"(score {self.score}/100, confidence {self.confidence:.0%})"
        )


# =============================================================================
# PART 3 — THE HUNTER AGENT'S OUTPUT  (agent 2 of 5)
#
# The hunter returns several LISTS of things, so we build the small pieces
# first and assemble them at the end. This is called NESTING.
# =============================================================================


class IOCEnrichment(BaseModel):
    """One indicator (usually an IP address), checked against threat databases.

    IOC means "Indicator Of Compromise": a technical clue that something bad
    is happening. An IP address, a file fingerprint, a domain name.
    """

    # The thing we looked up, e.g. "185.220.101.42".
    indicator: str

    # What kind of thing it is. Default "ipv4" because that is our main case.
    ioc_type: str = "ipv4"

    # The judgement. Starts at UNKNOWN: if the lookup fails, we say "unknown"
    # rather than wrongly claiming the address is clean.
    verdict: Verdict = Verdict.UNKNOWN

    # AbuseIPDB returns a 0-100 confidence that an address is abusive.
    abuse_confidence: int = Field(default=0, ge=0, le=100)

    # Two-letter country code, when the database knows it.
    country: Optional[str] = None

    # Which databases answered, e.g. ["AbuseIPDB", "VirusTotal"].
    # Recording the source is what makes the finding verifiable.
    sources: list[str] = Field(default_factory=list)

    # A short human-readable explanation.
    detail: str = ""

    def headline(self) -> str:
        return f"{self.indicator} -> {self.verdict.value} ({self.abuse_confidence}% abuse)"


class MitreTechnique(BaseModel):
    """One attack technique from the MITRE ATT&CK catalogue.

    MITRE ATT&CK is the worldwide reference list of attacker methods. Naming
    a technique turns "someone tried passwords" into "T1110, Brute Force" —
    a precise, searchable, internationally understood label.
    """

    # `pattern=` checks the text against a regular expression (a text shape).
    # Reading `^T\d{4}(\.\d{3})?$` piece by piece:
    #   ^        the text must START here
    #   T        a literal letter T
    #   \d{4}    exactly four digits
    #   ( ... )? an optional group, the ? means "zero or one time"
    #   \.       a literal dot
    #   \d{3}    exactly three digits
    #   $        the text must END here
    # So "T1110" and "T1110.001" are accepted. "BRUTE-FORCE" is refused.
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")

    # The human name, e.g. "Brute Force".
    name: str

    # The attacker's goal, e.g. "CredentialAccess".
    tactic: str

    def headline(self) -> str:
        return f"{self.technique_id} ({self.name})"


class SimilarAlert(BaseModel):
    """A past alert that resembles the current one.

    Found by searching a vector database. The point is memory: if this exact
    situation happened last week and was a false alarm, that is worth knowing.
    """

    alert_id: str
    description: str

    # How different the two alerts are. SMALLER means MORE similar.
    # 0.0 would be identical. This is the normal convention for distances.
    distance: float = Field(ge=0.0, description="Lower = more similar")


class HuntResult(BaseModel):
    """What the `hunter` agent must produce. This is a NESTED model.

    `list[IOCEnrichment]` means "a list, and every item inside it must itself
    be a valid IOCEnrichment". Pydantic checks the box AND its contents.
    """

    iocs: list[IOCEnrichment] = Field(default_factory=list)
    techniques: list[MitreTechnique] = Field(default_factory=list)
    similar_alerts: list[SimilarAlert] = Field(default_factory=list)

    # The AI's conclusion, in plain words. This is the one field where the
    # model may write freely — but it must write at least a real sentence.
    hypothesis: str = Field(min_length=10, description="The agent's conclusion")

    threat_score: int = Field(default=0, ge=0, le=100)

    @property
    def worst_verdict(self) -> Verdict:
        """The most serious verdict among all the indicators checked.

        If one address out of five is malicious, the whole alert is serious.
        We look for the worst case first and stop as soon as we find it.
        """
        # A tuple in priority order: worst first.
        for level in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.CLEAN):
            for ioc in self.iocs:
                if ioc.verdict == level:
                    return level
        # No indicator matched any of the three, so we know nothing.
        return Verdict.UNKNOWN


# =============================================================================
# PART 4 — THE FORENSICS AGENT'S OUTPUT  (agent 3 of 5)
# =============================================================================


class TimelineEvent(BaseModel):
    """One moment in the reconstructed story of the attack."""

    timestamp: datetime
    alert_id: str
    host: str
    description: str

    # True only for the alert we are currently investigating. The interface
    # highlights it, so the viewer sees where "now" sits in the story.
    is_focus: bool = Field(default=False, description="The alert under triage")

    def headline(self) -> str:
        # A tiny conditional expression: VALUE_IF_TRUE if CONDITION else VALUE_IF_FALSE
        marker = ">>" if self.is_focus else "  "
        # `:%H:%M:%S` prints only hours, minutes and seconds from the date.
        return f"{marker} {self.timestamp:%H:%M:%S} [{self.host}] {self.description}"


class ForensicsResult(BaseModel):
    """What the `forensics` agent must produce."""

    # The attack story, in time order.
    timeline: list[TimelineEvent] = Field(default_factory=list)

    # Every machine that appears in that story.
    affected_hosts: list[str] = Field(default_factory=list)

    # Did the attacker move from one machine to another? This is the single
    # most important signal in the whole demonstration: one compromised
    # machine is an incident, two is a breach.
    lateral_movement: bool = False

    # How far along the kill-chain the attacker has reached.
    attack_stage: AttackStage = AttackStage.UNDETERMINED

    # The AI's reading of the timeline, in plain words.
    analysis: str = ""

    @property
    def event_count(self) -> int:
        """How many events are in the timeline. `len()` counts list items."""
        return len(self.timeline)


# =============================================================================
# PART 5 — THE HUMAN DECISION AND THE FINAL REPORT
# =============================================================================


class HumanDecision(BaseModel):
    """What the analyst answered at the human-in-the-loop gate.

    Why a whole model for one choice? Because "approved" alone is not an audit
    trail. A regulator asks THREE questions: what was decided, by whom, and
    when. All three live here.
    """

    decision: Decision
    decided_by: str = "analyst"

    # `default_factory` takes a FUNCTION, and calls it at the moment an object
    # is created. So each decision gets its own real timestamp.
    # `lambda: ...` is a short way of writing a tiny nameless function.
    # Writing `datetime.now(timezone.utc)` directly would freeze the time at
    # the moment Python first read this file — a classic and nasty bug.
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Optional free text, e.g. "Confirmed with the system owner."
    note: str = ""

    def headline(self) -> str:
        return f"{self.decision.value} by {self.decided_by} at {self.decided_at:%H:%M:%S} UTC"


class IncidentReport(BaseModel):
    """The final written report produced by the `reporter` agent."""

    alert_id: str
    title: str

    # The report itself, written in Markdown so it displays nicely.
    # `min_length=50` guarantees the AI actually wrote something. An empty
    # report that passes validation would be worse than a loud failure.
    markdown: str = Field(min_length=50)

    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def char_count(self) -> int:
        """Length of the report. Shown in the live log: 'Report (2847 chars)'."""
        return len(self.markdown)