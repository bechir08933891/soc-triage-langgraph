"""Fixtures shared by the whole suite."""
from __future__ import annotations

import os

# Set BEFORE any project import: no test may spend money or touch the
# network. OFFLINE_MODE makes llm_available() false everywhere, so every
# model call takes its deterministic path.
os.environ.setdefault("SOC_OFFLINE_MODE", "1")
os.environ.setdefault("SOC_A2A_MODE", "0")

import pytest

from core.models import Alert
from core.preprocessor import load_alerts
from tools import history, scenarios


@pytest.fixture(scope="session")
def corpus():
    """The real corpus, loaded ONCE for the whole run."""
    return load_alerts()


@pytest.fixture(scope="session")
def built_history(corpus):
    """The SQLite history, built once, with the demo incidents installed."""
    history.build(corpus)
    scenarios.install()
    return history.row_count()


@pytest.fixture
def make_alert():
    """Build an Alert with sensible defaults, overriding only what matters.

    A test that has to spell out nine fields to change one is a test nobody
    reads.
    """
    def _make(**overrides):
        fields = dict(
            id="TEST-1",
            timestamp="2030-06-01T12:00:00+00:00",
            rule_id="1000",
            rule_level=5,
            rule_description="sshd: Attempt to login using a non-existent user",
            agent_name="test-host",
            raw={},
        )
        fields.update(overrides)
        return Alert(**fields)
    return _make