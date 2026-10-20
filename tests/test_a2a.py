"""The A2A surface. SKIPPED unless run_agents.py is listening.

    python run_agents.py          (in another window)
    pytest -m a2a
"""
from __future__ import annotations

import json

import pytest

from core.config import A2A_BASE_URL, AGENT_CARD_PATHS

pytestmark = pytest.mark.a2a

AGENTS = ("triage", "hunter", "forensics", "reporter")


@pytest.fixture(scope="module")
def host():
    """Skip the whole module rather than failing it when nothing is hosted.

    A missing server is a missing precondition, not a broken system.
    """
    httpx = pytest.importorskip("httpx")
    try:
        reply = httpx.get(f"{A2A_BASE_URL}/", timeout=3)
        reply.raise_for_status()
    except Exception as error:
        pytest.skip(f"no agent host at {A2A_BASE_URL} ({type(error).__name__}). "
                    f"Start it with: python run_agents.py")
    return reply.json()


def test_every_agent_is_hosted(host):
    assert {agent["name"] for agent in host["agents"]} == set(AGENTS)


@pytest.mark.parametrize("name", AGENTS)
def test_each_agent_publishes_a_card(host, name):
    """An Agent Card is how a caller who knows only the address learns what
    the agent does. A card nobody can read is not discovery."""
    import httpx
    card = httpx.get(f"{A2A_BASE_URL}{AGENT_CARD_PATHS[name]}", timeout=5).json()
    assert card["name"]
    assert card["version"]
    assert card["skills"]
    assert card["supportedInterfaces"][0]["protocolBinding"] == "JSONRPC"


@pytest.mark.parametrize("name", AGENTS)
def test_every_card_example_is_valid_json(host, name):
    """A card whose example cannot be sent is a card nobody can use."""
    import httpx
    card = httpx.get(f"{A2A_BASE_URL}{AGENT_CARD_PATHS[name]}", timeout=5).json()
    for skill in card["skills"]:
        for example in skill.get("examples", []):
            assert isinstance(json.loads(example), dict)


def test_the_transports_agree(host, built_history, monkeypatch):
    """Finding 16: the same alert, both ways, identical rule-derived values.

    Only the token counts may differ, for the reason finding 8 records.
    """
    import asyncio
    import importlib

    from tools import scenarios
    alert = scenarios.lateral_movement_incident()[2]
    results = {}
    for mode in ("1", "0"):
        monkeypatch.setenv("SOC_A2A_MODE", mode)
        import core.config
        importlib.reload(core.config)
        import nodes.triage_node
        importlib.reload(nodes.triage_node)
        from core.state import initial_state
        state = initial_state(alert)
        update = asyncio.run(nodes.triage_node.triage_node(state))
        results[mode] = update["triage_result"].model_dump_json()
    assert results["1"] == results["0"]