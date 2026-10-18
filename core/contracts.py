"""
core/contracts.py
=================
The vocabulary of the whole system.

Every agent speaks through these models. That matters for three reasons:

  1. A CLOSED VOCABULARY. An Enum means "Critical" is the only way to say
     critical. No agent can invent "CRITICAL!!", "crit" or "sev1", so the
     interface and the report never have to guess what a value means.

  2. A VALIDATED BOUNDARY. `Field(ge=0, le=100)` is not a suggestion. A
     score of 400 raises an error at the moment it is created, next to the
     code that produced it, instead of appearing as a broken bar chart ten
     minutes later.

  3. A CONTRACT OVER THE WIRE. These models serialise to JSON, which is
     exactly what travels between the A2A agents. The same class that
     validates locally validates what arrives from the network.

Rule of thumb used throughout: the LLM is never allowed to produce a value
from one of these enums. Code decides the categories; the model only writes
prose. A schema is a far stronger constraint than a politely worded prompt.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# =============================================================================
# CLOSED VOCABULARIES - the only words the system is allowed to use
# =============================================================================


class Severity(str, Enum):
    """How serious. Derived from the Wazuh rule level, never from the LLM.

    Inheriting from `str` as well as `Enum` means Severity.HIGH behaves like
    the text "High" in JSON and in f-strings, while still being a real enum
    that cannot hold an unexpected value.
    """
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AttackType(str, Enum):
    """The attack family.

    VULNERABILITY and NORMAL_ACTIVITY were added from evidence in the real
    dataset: a successful login and a patched CVE are not attacks, and
    forcing them into an attack family made the system confidently wrong.
    """
    BRUTE_FORCE = "BruteForce"
    MALWARE = "Malware"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    DATA_EXFILTRATION = "DataExfiltration"
    RECONNAISSANCE = "Reconnaissance"
    WEB_ATTACK = "WebAttack"
    PERSISTENCE = "Persistence"
    POLICY_VIOLATION = "PolicyViolation"
    VULNERABILITY = "Vulnerability"
    NORMAL_ACTIVITY = "NormalActivity"
    UNKNOWN = "Unknown"


class AttackStage(str, Enum):
    """Where in the kill chain this sits.

    NOT_APPLICABLE and UNDETERMINED are deliberately different values:
      NOT_APPLICABLE -> "this is not attack activity"  (analyst: move on)
      UNDETERMINED   -> "I could not tell"             (analyst: dig in)
    Collapsing them into one label destroys the only signal an analyst
    needs from this field.
    """
    INITIAL_ACCESS = "InitialAccess"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    LATERAL_MOVEMENT = "LateralMovement"
    EXFILTRATION = "Exfiltration"
    NOT_APPLICABLE = "NotApplicable"
    UNDETERMINED = "Undetermined"


class Verdict(str, Enum):
    """What threat intelligence thinks of an indicator."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    """What the human analyst chose at the approval gate."""
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


# =============================================================================
# WHAT EACH AGENT PRODUCES
# =============================================================================


class TriageResult(BaseModel):
    """The triage agent's answer. Pure rules, no AI."""

    attack_type: AttackType
    severity: Severity
    # A number the interface can draw as a bar. Bounded, so it always can.
    score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    # `min_length=10` forbids an empty explanation. A decision with no stated
    # reason is not auditable, and this system is built to be audited.
    rationale: str = Field(min_length=10)
    escalate_to_tier2: bool
    # Every clue that led to the answer, e.g. "keyword:brute force".
    # `default_factory=list` gives each instance its OWN empty list; a plain
    # `= []` would share one list between every object ever created.
    matched_signals: list[str] = Field(default_factory=list)

    def headline(self) -> str:
        """One line for a log or a table row."""
        return (
            f"{self.attack_type.value} / {self.severity.value} "
            f"(score {self.score}/100, confidence {self.confidence:.0%})"
        )


class IOCEnrichment(BaseModel):
    """What we learned about one indicator (today, always an IP address)."""

    indicator: str
    ioc_type: str = "ipv4"
    verdict: Verdict = Verdict.UNKNOWN
    abuse_confidence: int = Field(default=0, ge=0, le=100)
    country: Optional[str] = None
    # Which services answered, e.g. ["AbuseIPDB", "LocalCorpus"].
    sources: list[str] = Field(default_factory=list)
    detail: str = ""
    # The raw answer from each service, kept so a reviewer can see exactly
    # what a source said rather than only our merged conclusion.
    per_source: dict[str, Any] = Field(default_factory=dict)

    def headline(self) -> str:
        return f"{self.indicator} -> {self.verdict.value} ({self.abuse_confidence}% abuse)"


class MitreTechnique(BaseModel):
    """One MITRE ATT&CK technique.

    The `pattern` is a regular expression that enforces the real ID shape:
    T followed by four digits, optionally .three digits for a sub-technique.
    "T1110" and "T1110.001" pass; "T111" and "brute force" do not. This is
    how a typo becomes an error here instead of a dead link in the report.
    """

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactic: str

    def headline(self) -> str:
        return f"{self.technique_id} ({self.name})"


class SimilarAlert(BaseModel):
    """A past alert that resembles this one. Lower distance = more similar."""

    alert_id: str
    description: str
    distance: float = Field(ge=0.0)


class HuntResult(BaseModel):
    """The hunter agent's answer: enrichment plus a written hypothesis."""

    iocs: list[IOCEnrichment] = Field(default_factory=list)
    techniques: list[MitreTechnique] = Field(default_factory=list)
    similar_alerts: list[SimilarAlert] = Field(default_factory=list)
    hypothesis: str = Field(min_length=10)
    threat_score: int = Field(default=0, ge=0, le=100)

    @property
    def worst_verdict(self) -> Verdict:
        """The most serious verdict among all indicators.

        A `@property` is computed on demand and read like a field:
        `result.worst_verdict`, with no brackets. It is not stored, so it can
        never disagree with the list it is derived from.

        Worst wins. If one source says clean and another says malicious, the
        alert is treated as malicious. Being wrong in the cautious direction
        costs an analyst a few minutes; being wrong the other way costs a
        missed intrusion.
        """
        for level in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.CLEAN):
            for ioc in self.iocs:
                if ioc.verdict == level:
                    return level
        return Verdict.UNKNOWN


class TimelineEvent(BaseModel):
    """One row in the reconstructed story around an alert."""

    timestamp: datetime
    alert_id: str
    host: str
    description: str
    # WHO was involved. These two fields exist so the timeline can be split
    # by ACTOR and not only by clock. A 60-minute window in a real SOC holds
    # several unrelated attackers, and merging them invents incidents that
    # never happened.
    src_ip: Optional[str] = None
    username: Optional[str] = None
    # True for the one alert being investigated.
    is_focus: bool = False
    # True when this event shares the focus alert's source address, or its
    # account when that account is a real identity rather than a shared one
    # like `root`. False means "in this window by coincidence".
    same_actor: bool = False

    def headline(self) -> str:
        """One printable line, with a marker that says how to read it."""
        if self.is_focus:
            marker = ">>"      # the alert under investigation
        elif self.same_actor:
            marker = "  "      # same attacker - part of this story
        else:
            marker = " ~"      # somebody else - here by coincidence
        return f"{marker} {self.timestamp:%H:%M:%S} [{self.host}] {self.description}"


class ForensicsResult(BaseModel):
    """The forensics agent's answer: the story, the hosts, and the pattern."""

    timeline: list[TimelineEvent] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    # ONE IDENTITY authenticating successfully on several hosts.
    lateral_movement: bool = False
    # Deliberately SEPARATE from lateral_movement. One source touching many
    # hosts is scanning or password spraying. Conflating the two makes every
    # scanned network look breached - the first version of this detector did
    # exactly that and flagged 100% of the corpus.
    horizontal_spread: bool = False
    attack_stage: AttackStage = AttackStage.UNDETERMINED
    # How many SUCCESSFUL authentications this actor achieved in the window.
    # Promoted out of the audit metadata into the contract because the
    # escalation gate needs it: reputation plus a success is an intrusion,
    # reputation plus nothing is the internet (finding 19).
    actor_successes: int = Field(default=0, ge=0)
    analysis: str = ""

    @property
    def event_count(self) -> int:
        return len(self.timeline)


class HumanDecision(BaseModel):
    """What the analyst decided at the approval gate, and when."""

    decision: Decision
    decided_by: str = "analyst"
    # `default_factory` runs the function at CREATION time. Writing
    # `= datetime.now(timezone.utc)` instead would freeze the timestamp at
    # the moment Python imported this file - every decision would carry the
    # same time.
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    note: str = ""

    def headline(self) -> str:
        return f"{self.decision.value} by {self.decided_by} at {self.decided_at:%H:%M:%S} UTC"


class IncidentReport(BaseModel):
    """The final document a human reads."""

    alert_id: str
    title: str
    # A real report cannot be 20 characters long. The floor makes an empty
    # or truncated generation fail loudly instead of shipping.
    markdown: str = Field(min_length=50)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def char_count(self) -> int:
        return len(self.markdown)


# =============================================================================
# WHAT TRAVELS BETWEEN AGENTS
# =============================================================================


class HuntRequest(BaseModel):
    """What a caller sends to the hunter agent over A2A.

    The alert alone is not enough: the local reputation needs to know how
    many times this address appears in the whole corpus, and an agent that
    only sees one alert cannot know that. So the caller supplies it.
    """

    alert: dict[str, Any]
    local_hits: int = Field(default=0, ge=0)


class ForensicsRequest(BaseModel):
    """What a caller sends to the forensics agent over A2A.

    `window_minutes` is bounded on purpose. A window of 0 would make the
    timeline meaningless, and a window of a year would pull in the entire
    corpus and time out. 5 minutes to 24 hours covers every sensible
    investigation, and a caller asking for something outside that range gets
    a validation error instead of a surprise.
    """

    alert: dict[str, Any]
    window_minutes: int = Field(default=60, ge=5, le=1440)


class ReportRequest(BaseModel):
    """What a caller sends to the reporter agent over A2A.

    Every finding is OPTIONAL. A report must still be produced when an
    agent failed or was skipped, because "the hunter did not answer" is
    information a human needs - and a report that silently omits a missing
    input looks exactly like a report where that input came back clean.
    """

    alert: dict[str, Any]
    triage_result: Optional[dict[str, Any]] = None
    hunt_result: Optional[dict[str, Any]] = None
    forensics_result: Optional[dict[str, Any]] = None