"""Findings 3, 8, 12 and 13: the rule layer, and the fields it refuses to read."""
from __future__ import annotations

import pytest

from core.contracts import AttackType, Severity
from tools.severity import assign_severity, classify_attack_type


def test_the_rules_are_a_pure_function(make_alert):
    """Finding 8: 500 runs, one result. The reproducible half of the system."""
    alert = make_alert()
    results = {assign_severity(alert).model_dump_json() for _ in range(500)}
    assert len(results) == 1


@pytest.mark.parametrize("description,expected", [
    # Finding 13: non-threats are checked FIRST, or "authentication" in a
    # success would be caught by the brute-force family.
    ("sshd: authentication success", AttackType.NORMAL_ACTIVITY),
    ("PAM: Login session opened.", AttackType.NORMAL_ACTIVITY),
    ("Log file rotated.", AttackType.NORMAL_ACTIVITY),
    # Finding 13: a resolved CVE is a patch, not a vulnerability.
    ("The CVE-2025-24528 that affected libkrb5-3 was solved due to a package update",
     AttackType.NORMAL_ACTIVITY),
    ("sshd: Attempt to login using a non-existent user", AttackType.BRUTE_FORCE),
    ("Web server 400 error code.", AttackType.WEB_ATTACK),
    ("Successful sudo to ROOT executed", AttackType.PRIVILEGE_ESCALATION),
    ("crontab entry changed", AttackType.PERSISTENCE),
])
def test_classification(make_alert, description, expected):
    alert = make_alert(rule_description=description)
    assert classify_attack_type(alert)[0] is expected


def test_full_log_is_never_read(make_alert):
    """Finding 12: raw machine text produced the corpus's only (wrong)
    Execution verdict. The classifier must ignore it entirely."""
    quiet = make_alert(rule_description="Log file rotated.", full_log=None)
    noisy = make_alert(rule_description="Log file rotated.",
                       full_log="powershell encoded command exfiltration "
                                "rootkit malicious brute force sudo to root")
    assert classify_attack_type(quiet) == classify_attack_type(noisy)


@pytest.mark.parametrize("level,severity", [
    (15, Severity.CRITICAL), (12, Severity.CRITICAL),
    (11, Severity.HIGH), (10, Severity.HIGH),
    (9, Severity.MEDIUM), (7, Severity.MEDIUM),
    (6, Severity.LOW), (4, Severity.LOW),
    (3, Severity.INFO), (0, Severity.INFO),
])
def test_severity_bands(make_alert, level, severity):
    alert = make_alert(rule_level=level,
                       rule_description="sshd: brute force attempt")
    assert assign_severity(alert).severity is severity


def test_only_high_and_critical_escalate(make_alert):
    """Finding 3: no corpus alert reaches level 10, so this gate never fires
    on the real data - which is why the reporter cannot rely on it alone."""
    for level in range(0, 10):
        alert = make_alert(rule_level=level,
                           rule_description="sshd: brute force attempt")
        assert assign_severity(alert).escalate_to_tier2 is False
    for level in (10, 12, 15):
        alert = make_alert(rule_level=level,
                           rule_description="sshd: brute force attempt")
        assert assign_severity(alert).escalate_to_tier2 is True


def test_non_threats_are_forced_to_info(make_alert):
    alert = make_alert(rule_level=8, rule_description="sshd: authentication success",
                       src_ip="45.55.159.241")
    result = assign_severity(alert)
    assert result.severity is Severity.INFO
    assert result.score <= 15
    assert "non_threat_event" in result.matched_signals


def test_every_decision_states_its_reason(make_alert):
    result = assign_severity(make_alert())
    assert len(result.rationale) > 40
    assert result.matched_signals