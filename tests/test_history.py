"""Finding 11: a time window must be centred, not merely bounded."""
from __future__ import annotations

import pytest

from tools import history


def test_the_database_is_built(built_history):
    assert built_history > 100


def test_a_window_returns_rows(built_history, corpus):
    """The bug this guards: SQLite's datetime() yields '2025-03-05 00:00:00'
    with a space while we store '...T00:00:00+00:00' with a T, so comparing
    raw strings silently returned nothing."""
    middle = corpus[len(corpus) // 2]
    rows = history.alerts_near(middle.timestamp.isoformat(), window_minutes=60)
    assert rows


def test_the_focus_alert_is_inside_its_own_window(built_history, corpus):
    """A timeline that excludes the event it is about would be absurd."""
    middle = corpus[len(corpus) // 2]
    rows = history.alerts_near(middle.timestamp.isoformat(),
                               window_minutes=60, limit=25)
    assert any(row["id"] == middle.id for row in rows)


def test_rows_come_back_in_time_order(built_history, corpus):
    middle = corpus[len(corpus) // 2]
    rows = history.alerts_near(middle.timestamp.isoformat(), window_minutes=60)
    stamps = [row["timestamp"] for row in rows]
    assert stamps == sorted(stamps)


def test_the_limit_is_respected(built_history, corpus):
    middle = corpus[len(corpus) // 2]
    rows = history.alerts_near(middle.timestamp.isoformat(),
                               window_minutes=1440, limit=7)
    assert len(rows) <= 7


def test_host_queries_exclude_unknown_hosts(built_history, corpus):
    """An unnamed host is not a host you can say someone moved to."""
    for alert in corpus[:200]:
        if not alert.src_ip:
            continue
        rows = history.hosts_for_ip(alert.src_ip, alert.timestamp.isoformat())
        assert all(row["agent_name"] != "unknown-host" for row in rows)


def test_empty_identifiers_query_nothing(built_history):
    assert history.hosts_for_user("", "2030-01-01T00:00:00+00:00") == []
    assert history.hosts_for_ip("", "2030-01-01T00:00:00+00:00") == []


def test_successes_are_counted(built_history):
    """Finding 19: 'attempted' and 'got in' must be distinguishable."""
    rows = history.hosts_for_user("s.karim", "2030-01-15T10:04:31+00:00")
    assert rows
    assert sum(int(r["successes"] or 0) for r in rows) > 0