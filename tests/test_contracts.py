"""The closed vocabulary and the validation boundary."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.contracts import (AttackStage, AttackType, Decision, ForensicsRequest,
                            ForensicsResult, IncidentReport, MitreTechnique,
                            Severity, TimelineEvent, TriageResult, Verdict)


@pytest.mark.parametrize("enum_class", [Severity, AttackType, AttackStage,
                                        Verdict, Decision])
def test_vocabularies_are_closed(enum_class):
    with pytest.raises(ValueError):
        enum_class("something nobody agreed on")


def test_score_is_bounded():
    with pytest.raises(ValidationError):
        TriageResult(attack_type=AttackType.BRUTE_FORCE, severity=Severity.LOW,
                     score=400, confidence=0.5, rationale="x" * 20,
                     escalate_to_tier2=False)


def test_rationale_cannot_be_empty():
    with pytest.raises(ValidationError):
        TriageResult(attack_type=AttackType.BRUTE_FORCE, severity=Severity.LOW,
                     score=40, confidence=0.5, rationale="",
                     escalate_to_tier2=False)


@pytest.mark.parametrize("technique_id,valid", [
    ("T1110", True), ("T1110.001", True),
    ("T111", False), ("brute force", False), ("1110", False),
])
def test_mitre_id_shape(technique_id, valid):
    if valid:
        MitreTechnique(technique_id=technique_id, name="n", tactic="t")
    else:
        with pytest.raises(ValidationError):
            MitreTechnique(technique_id=technique_id, name="n", tactic="t")


def test_report_cannot_be_a_stub():
    with pytest.raises(ValidationError):
        IncidentReport(alert_id="a", title="t", markdown="too short")


@pytest.mark.parametrize("minutes,valid", [(5, True), (1440, True),
                                           (0, False), (4, False), (1441, False)])
def test_forensics_window_is_bounded(minutes, valid):
    if valid:
        ForensicsRequest(alert={}, window_minutes=minutes)
    else:
        with pytest.raises(ValidationError):
            ForensicsRequest(alert={}, window_minutes=minutes)


def test_the_model_has_nowhere_to_put_a_verdict():
    """Findings 15 and 21: the structural guarantee, not the prompt one.

    A prompt saying 'do not change the decision' can be ignored. A schema
    with no field for a decision cannot.
    """
    from tools.forensics import ForensicsNarrative
    from tools.reporter import ReportSummary

    for schema in (ForensicsNarrative, ReportSummary):
        fields = set(schema.model_fields)
        assert not fields & {"escalate", "verdict", "severity", "attack_stage",
                             "lateral_movement", "decision"}


def test_timeline_markers_distinguish_actors():
    """Finding 14: the reader must be able to see whose event it is."""
    from datetime import datetime, timezone
    when = datetime(2030, 1, 1, tzinfo=timezone.utc)
    focus = TimelineEvent(timestamp=when, alert_id="a", host="h",
                          description="d", is_focus=True, same_actor=True)
    mine = TimelineEvent(timestamp=when, alert_id="b", host="h",
                         description="d", same_actor=True)
    theirs = TimelineEvent(timestamp=when, alert_id="c", host="h",
                           description="d", same_actor=False)
    assert focus.headline().startswith(">>")
    assert theirs.headline().startswith(" ~")
    assert not mine.headline().startswith((">>", " ~"))


def test_forensics_carries_the_success_count():
    """Finding 19: the gate needs impact, not only reputation."""
    assert "actor_successes" in ForensicsResult.model_fields
    with pytest.raises(ValidationError):
        ForensicsResult(actor_successes=-1)