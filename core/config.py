"""
core/config.py
==============
Every tunable setting in one place.

Why this file exists: during your defense someone will ask "where does the
port / the timeout / the transport choice come from?". Pointing at one small
file is a much better answer than "it is written in four different modules".

Settings are read from the environment, so you can change behaviour without
editing code:

    set SOC_A2A_MODE=false        (Windows CMD, for this window only)
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Reads a `.env` file if one exists, and puts its values into the environment.
# That is how your OpenAI key will arrive later, without ever being in the code.
load_dotenv()


# Paths, built from this file's own location so the project runs from anywhere.
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)


def _flag(name: str, default: bool = False) -> bool:
    """Read a true/false setting from the environment.

    Environment values are always TEXT, never real booleans. The text "false"
    would be considered true by Python, because any non-empty text is true.
    So we must compare the words ourselves.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# =============================================================================
# THE A2A SWITCH
#
# True  -> nodes call their agents over the A2A protocol (real interoperability)
# False -> nodes call the Python function directly (fast, no server needed)
#
# The graph, the state and the demo interface are IDENTICAL either way. Only
# the transport changes. That is what makes the comparison meaningful.
# =============================================================================

A2A_MODE = _flag("SOC_A2A_MODE", default=True)

A2A_HOST = os.getenv("SOC_A2A_HOST", "127.0.0.1")
A2A_PORT = int(os.getenv("SOC_A2A_PORT", "9001"))

# How long to wait for an agent before giving up. Without a timeout, a hung
# agent would freeze your demo in front of the jury.
A2A_TIMEOUT_S = float(os.getenv("SOC_A2A_TIMEOUT", "30"))

A2A_BASE_URL = f"http://{A2A_HOST}:{A2A_PORT}"

# Where each agent's card lives. We add hunter, forensics and reporter here
# in the coming steps, and nothing else needs to change.
AGENT_CARD_PATHS = {
    "triage": "/triage/.well-known/agent-card.json",
    "hunter": "/hunter/.well-known/agent-card.json",
} 

# =============================================================================
# THREAT INTELLIGENCE
# =============================================================================

# True -> make no outbound calls at all. Use this to rehearse on a venue
# Wi-Fi you do not trust. The system still produces real verdicts from the
# local corpus reputation.
OFFLINE_MODE = _flag("SOC_OFFLINE_MODE", default=False)

# Optional. The system works without them. Never written in code — they
# arrive from the .env file, which Git ignores.
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

INTEL_TIMEOUT_S = float(os.getenv("SOC_INTEL_TIMEOUT", "10"))

# Where answers are remembered, so we never ask the same question twice.
INTEL_CACHE_FILE = DATA_DIR / "intel_cache.json"

# The alert history, as a queryable database. The forensics agent asks it
# "what else happened around this time, and on which hosts?"
HISTORY_DB = DATA_DIR / "soc_history.db"

# =============================================================================
# THE LANGUAGE MODEL
# =============================================================================

OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")

# gpt-4o-mini was deprecated on 2026-10-14 and shuts down on 2027-01-14.
# gpt-6-luna is OpenAI's recommended replacement and is cheaper.
LLM_MODEL = os.getenv("SOC_LLM_MODEL", "gpt-6-luna")

# Temperature 0 means "always pick the most likely next word". It makes the
# model as repeatable as a language model can be, which matters for a demo a
# jury may ask you to run twice.
LLM_TEMPERATURE = float(os.getenv("SOC_LLM_TEMPERATURE", "0"))

LLM_TIMEOUT_S = float(os.getenv("SOC_LLM_TIMEOUT", "45"))
LLM_MAX_RETRIES = int(os.getenv("SOC_LLM_RETRIES", "2"))

def card_url(agent: str) -> str:
    """The card path for one agent. Raises KeyError on a typo, which is good:
    a silent wrong address would be much harder to debug."""
    return AGENT_CARD_PATHS[agent]


def describe() -> str:
    """One line describing the active configuration. Printed at startup so
    you always know which mode you are in."""
    return f"A2A_MODE={A2A_MODE} base={A2A_BASE_URL} timeout={A2A_TIMEOUT_S}s"