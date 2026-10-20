"""Findings 10, 12 and 14: scanning is not movement, and a window is not
an incident."""
from __future__ import annotations

import pytest

from core.contracts import AttackStage
from tools import scenarios
from tools.forensics import (GENERIC_ACCOUNTS, _same_actor, infer_attack_stage,
                             investigate, movement_check)


@pytest.mark.parametrize("alert_id,should_be_lateral", [
    ("DEMO-LM-01", True), ("DEMO-LM-02", True), ("DEMO-LM-03", True),
    ("DEMO-LM-04", True), ("DEMO-LM-05", True),
    # TRAPS. A generic account on three hosts is a shared account, and an
    # identity that reached three hosts without a single success is spraying.
    ("DEMO-GA-01", False), ("DEMO-GA-02", False), ("DEMO-GA-03", False),
    ("DEMO-PS-01", False), ("DEMO-PS-02", False), ("DEMO-PS-03", False),
])
def test_lateral_movement_versus_spreading(built_history, alert_id,
                                           should_be_lateral):
    """Finding 10: the first detector flagged 100% of the corpus because it
    conflated scanning with movement."""
    alert = next(a for a in scenarios.all_demo_alerts() if a.id == alert_id)
    result, _ = investigate(alert)
    assert result.lateral_movement is should_be_lateral
    if not should_be_lateral:
        assert result.horizontal_spread is True


def test_the_traps_are_reported_as_spread_with_a_reason(built_history):
    alert = next(a for a in scenarios.all_demo_alerts() if a.id == "DEMO-GA-01")
    _, meta = investigate(alert)
    assert meta["spread_signals"]
    assert meta["account_is_generic"] is True


def test_lateral_movement_requires_a_success(built_history):
    alert = next(a for a in scenarios.all_demo_alerts() if a.id == "DEMO-LM-03")
    result, meta = investigate(alert)
    assert meta["successes"] > 0
    assert result.actor_successes == meta["successes"]
    assert len(result.affected_hosts) >= 2


@pytest.mark.parametrize("account", ["root", "admin", "postgres", "www-data"])
def test_generic_accounts_are_not_identities(account):
    assert account in GENERIC_ACCOUNTS


def test_same_actor_matches_the_address(make_alert):
    alert = make_alert(src_ip="45.55.159.241", user="s.karim")
    assert _same_actor(alert, "45.55.159.241", "someone-else") is True
    assert _same_actor(alert, "8.8.8.8", "s.karim") is True
    assert _same_actor(alert, "8.8.8.8", "someone-else") is False


def test_same_actor_ignores_shared_accounts(make_alert):
    """Two attackers both guessing root are two attackers."""
    alert = make_alert(src_ip=None, user="root")
    assert _same_actor(alert, "8.8.8.8", "root") is False


def test_the_focus_alert_is_always_its_own_actor(built_history, corpus):
    """The bug: an alert with no IP and a generic account failed the actor
    test against its own database row."""
    for alert in corpus[:60]:
        result, _ = investigate(alert)
        focus = [e for e in result.timeline if e.is_focus]
        assert focus, f"{alert.id} is missing from its own timeline"
        assert all(e.same_actor for e in focus)


def test_stage_inference_ignores_full_log(make_alert):
    """Finding 12: this file repeated a mistake already fixed in severity.py,
    and it had already produced one wrong verdict."""
    quiet = make_alert(rule_description="Log file rotated.", full_log=None)
    noisy = make_alert(rule_description="Log file rotated.",
                       full_log="powershell encoded command exfiltration rootkit")
    movement = {"lateral_movement": False}
    assert infer_attack_stage(quiet, movement) == infer_attack_stage(noisy, movement)


@pytest.mark.parametrize("description,stage", [
    ("Log file rotated.", AttackStage.NOT_APPLICABLE),
    ("PAM: Login session closed.", AttackStage.NOT_APPLICABLE),
    ("The CVE-2024-26461 was solved due to a package update",
     AttackStage.NOT_APPLICABLE),
    ("sshd: Attempt to login using a non-existent user",
     AttackStage.INITIAL_ACCESS),
    ("crontab entry changed", AttackStage.PERSISTENCE),
    ("Nothing recognisable at all", AttackStage.UNDETERMINED),
])
def test_stage_keywords(make_alert, description, stage):
    """Finding 13: NotApplicable and Undetermined mean opposite things to
    an analyst, so they must not be collapsed."""
    alert = make_alert(rule_description=description)
    assert infer_attack_stage(alert, {"lateral_movement": False})[0] is stage


@pytest.mark.slow
def test_lateral_movement_is_rare_on_the_real_corpus(built_history, corpus):
    """Finding 10: measured at 0.0%. Asserted as a ceiling - a detector that
    flags a large share of a scanning corpus has broken again."""
    lateral = sum(1 for a in corpus if investigate(a)[0].lateral_movement)
    assert lateral / len(corpus) < 0.10


@pytest.mark.slow
def test_most_window_events_belong_to_other_actors(built_history, corpus):
    """Finding 14: measured at 72.2%. Before the partition, every one of
    those was offered to the model as part of the same story."""
    total = foreign = 0
    for alert in corpus[:120]:
        result, _ = investigate(alert)
        total += len(result.timeline)
        foreign += sum(1 for e in result.timeline if not e.same_actor)
    assert total > 0
    assert foreign / total > 0.3