"""Findings 15, 17, 19 and 21: the escalation gate."""
from __future__ import annotations

import pytest

from core.contracts import (AttackStage, AttackType, ForensicsResult,
                            HuntResult, IOCEnrichment, Severity, TriageResult,
                            Verdict)
from core.llm import LLMUnavailable
from tools import reporter


@pytest.fixture
def quiet_triage():
    return TriageResult(attack_type=AttackType.BRUTE_FORCE,
                        severity=Severity.LOW, score=43, confidence=0.65,
                        rationale="a low-severity brute-force attempt",
                        escalate_to_tier2=False)


@pytest.fixture
def malicious_hunt():
    return HuntResult(
        iocs=[IOCEnrichment(indicator="45.55.159.241",
                            verdict=Verdict.MALICIOUS, abuse_confidence=90)],
        hypothesis="a known-bad address, as AbuseIPDB reports it",
        threat_score=43)


def context(successes=0, stage=AttackStage.INITIAL_ACCESS, lateral=False):
    return ForensicsResult(attack_stage=stage, actor_successes=successes,
                           lateral_movement=lateral)


# --- Finding 19: reputation is not impact -----------------------------------

def test_reputation_alone_does_not_escalate(quiet_triage, malicious_hunt):
    """561 of 738 corpus alerts carry a malicious source. A known-bad host
    knocking on a door is the internet, not an incident."""
    decision = reporter.recommend_escalation(quiet_triage, malicious_hunt,
                                             context(successes=0))
    assert decision["escalate"] is False
    assert decision["corroborating"]
    assert "reputation alone" in decision["suppressed"]


@pytest.mark.parametrize("successes", [1, 6])
def test_reputation_with_impact_escalates(quiet_triage, malicious_hunt,
                                          successes):
    """The branch the corpus cannot reach: no corpus alert has both a
    malicious source and a recorded success."""
    decision = reporter.recommend_escalation(quiet_triage, malicious_hunt,
                                             context(successes=successes))
    assert decision["escalate"] is True
    assert any("successful authentication" in s for s in decision["triggering"])


def test_successes_without_a_bad_source_are_an_administrator(quiet_triage):
    clean = HuntResult(iocs=[IOCEnrichment(indicator="10.0.0.1",
                                           verdict=Verdict.CLEAN)],
                       hypothesis="an ordinary internal address",
                       threat_score=10)
    decision = reporter.recommend_escalation(quiet_triage, clean,
                                             context(successes=6))
    assert decision["escalate"] is False


# --- Finding 21: no signal may depend on the language model -----------------

@pytest.mark.parametrize("score", [0, 43, 69, 70, 72, 100])
def test_the_model_score_cannot_move_the_decision(quiet_triage, score):
    """The hole this closes: `threat_score >= 70` was a triggering signal,
    and the model scored identical evidence from 30 to 72. Two scores it
    really produced for one profile used to give opposite decisions."""
    hunt = HuntResult(iocs=[IOCEnrichment(indicator="45.55.159.241",
                                          verdict=Verdict.MALICIOUS,
                                          abuse_confidence=90)],
                      hypothesis="x" * 20, threat_score=score)
    decision = reporter.recommend_escalation(quiet_triage, hunt, context())
    assert decision["escalate"] is False


def test_no_signal_mentions_the_threat_score(quiet_triage, malicious_hunt):
    decision = reporter.recommend_escalation(quiet_triage, malicious_hunt,
                                             context(successes=3))
    assert not any("threat score" in s for s in decision["triggering"])


def test_the_decision_survives_every_model_failure(make_alert, quiet_triage):
    """Identical across a working model, a documented failure and a crash."""
    alert = make_alert()
    forensics = context(lateral=True, stage=AttackStage.LATERAL_MOVEMENT)

    def working(schema, system, user):
        return (schema(summary="x" * 80, confidence=77),
                {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
                 "cost_usd": 0.0, "model": "stub", "mode": "json_schema"})

    def unavailable(*a, **k):
        raise LLMUnavailable("503")

    def crash(*a, **k):
        raise KeyError("choices")

    saved_call, saved_flag = reporter.structured_call, reporter.llm_available
    reporter.llm_available = lambda: True
    try:
        outcomes = set()
        for behaviour in (working, unavailable, crash):
            reporter.structured_call = behaviour
            _, meta = reporter.report(alert, triage=quiet_triage,
                                      forensics=forensics)
            outcomes.add((meta["escalate"], tuple(meta["signals"])))
        assert len(outcomes) == 1
    finally:
        reporter.structured_call, reporter.llm_available = saved_call, saved_flag


# --- Finding 15: the union, and the disagreement ----------------------------

def test_forensics_escalates_what_triage_would_close(make_alert, quiet_triage):
    """Triage auto-closed all five alerts of a confirmed intrusion."""
    decision = reporter.recommend_escalation(
        quiet_triage, None,
        context(lateral=True, stage=AttackStage.LATERAL_MOVEMENT))
    assert decision["escalate"] is True
    assert decision["overridden_triage"] is True


def test_the_report_states_the_disagreement(make_alert, quiet_triage):
    document, _ = reporter.report(
        make_alert(), triage=quiet_triage,
        forensics=context(lateral=True, stage=AttackStage.LATERAL_MOVEMENT))
    assert "THE AGENTS DISAGREE" in document.markdown
    assert "Triage alone would have auto-closed" in document.markdown
    assert "No verdict in this report was produced by a language model" \
        in document.markdown


@pytest.mark.parametrize("kwargs", [
    {}, {"triage": True}, {"forensics": True}, {"triage": True, "forensics": True},
])
def test_a_report_is_written_whatever_is_missing(make_alert, quiet_triage, kwargs):
    """A report that silently omits a failed input looks exactly like one
    where that input came back clean."""
    arguments = {}
    if kwargs.get("triage"):
        arguments["triage"] = quiet_triage
    if kwargs.get("forensics"):
        arguments["forensics"] = context()
    document, meta = reporter.report(make_alert(), **arguments)
    assert document.char_count > 50
    assert len(meta["missing"]) == 3 - len(arguments)


def test_every_closed_alert_states_a_reason(quiet_triage, malicious_hunt):
    """'Closed, and here is why' must hold for every closed alert."""
    for hunt in (None, malicious_hunt):
        for forensics in (None, context(), context(stage=AttackStage.NOT_APPLICABLE)):
            decision = reporter.recommend_escalation(quiet_triage, hunt, forensics)
            if not decision["escalate"]:
                assert decision["suppressed"]


# --- Finding 17 / 19: the policies -----------------------------------------

@pytest.mark.parametrize("policy,expected", [
    ("any", True), ("corroborate", False), ("triggering", False)])
def test_the_policies_differ_only_on_reputation(quiet_triage, malicious_hunt,
                                                policy, expected):
    decision = reporter.recommend_escalation(quiet_triage, malicious_hunt,
                                             context(), policy=policy)
    assert decision["escalate"] is expected


def test_an_unknown_policy_is_refused(quiet_triage):
    with pytest.raises(ValueError):
        reporter.recommend_escalation(quiet_triage, None, None, policy="vibes")