"""The promise the LLM layer makes, and the nets behind it."""
from __future__ import annotations

import pytest

from core.contracts import AttackStage, ForensicsResult
from core.llm import LLMUnavailable, cost_usd, llm_available
from tools import forensics, hunter, reporter


def test_offline_means_no_model():
    """conftest sets SOC_OFFLINE_MODE=1, so no test can spend money."""
    assert llm_available() is False


def test_cost_is_priced_per_million_tokens():
    assert cost_usd("gpt-6-luna", 1_000_000, 0) == pytest.approx(0.10)
    assert cost_usd("gpt-6-luna", 0, 1_000_000) == pytest.approx(0.50)
    # An unknown model falls back to a default rather than crashing.
    assert cost_usd("a-model-from-the-future", 1_000_000, 0) > 0


@pytest.mark.parametrize("module,attribute", [
    (hunter, "hunt"), (forensics, "narrate"), (reporter, "report"),
])
def test_no_model_failure_escapes(module, attribute, make_alert,
                                  built_history, monkeypatch):
    """Finding from Step 13: the 'only LLMUnavailable escapes' guarantee was
    broken once and killed a running script. Every caller now has a bare
    `except Exception` net as well, and this proves all three still do."""
    def unavailable(*args, **kwargs):
        raise LLMUnavailable("provider returned 503")

    def crash(*args, **kwargs):
        raise KeyError("choices")

    monkeypatch.setattr(module, "llm_available", lambda: True)
    for behaviour in (unavailable, crash):
        monkeypatch.setattr(module, "structured_call", behaviour)
        result = getattr(module, attribute)(make_alert())
        assert result is not None


def test_the_fallback_is_not_visibly_worse(make_alert, built_history):
    """A fallback that says less than the model teaches a reader to
    distrust it. The deterministic text still states the decision."""
    document, meta = reporter.report(
        make_alert(),
        forensics=ForensicsResult(attack_stage=AttackStage.LATERAL_MOVEMENT,
                                  lateral_movement=True, actor_successes=4))
    assert meta["llm_used"] is False
    assert "deterministic template" in document.markdown
    assert "ESCALATE" in document.markdown


def test_a_skipped_model_is_not_a_failed_one(make_alert, built_history):
    """'Skipped deliberately' and 'the provider broke' mean opposite things
    and are recorded in different fields."""
    _, meta = forensics.narrate(make_alert(rule_description="Log file rotated."))
    assert meta["skipped_reason"]
    assert meta["fallback_reason"] is None