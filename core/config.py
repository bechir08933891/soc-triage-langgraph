"""
core/config.py
==============
Every setting in one place, read from the environment.

Two rules this file enforces:
  1. No secret is ever written in code. Keys come from .env, which is
     git-ignored, so a published repository cannot leak one.
  2. Every value has a working default, so the project runs on a fresh
     machine with no .env at all - just with fewer capabilities.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Reads the .env file into the environment. Call it ONCE, here, at import.
load_dotenv()

# `parent.parent` because this file is core/config.py, so one level up is
# core/ and two levels up is the project root. Computing the root from the
# file's own location means the project works from any folder.
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)


def _flag(name: str, default: bool = False) -> bool:
    """Read a true/false setting from the environment.

    Environment variables are always text, so "1", "true", "yes" and "on"
    all have to mean True. Anything else means False.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# =============================================================================
# A2A - the agent-to-agent transport
# =============================================================================

# THE SWITCH. True = agents talk over the network with A2A. False = the same
# functions are called in this process. Identical results either way, which
# is what makes the comparison in the README a measurement and not a claim.
A2A_MODE = _flag("SOC_A2A_MODE", default=True)
A2A_HOST = os.getenv("SOC_A2A_HOST", "127.0.0.1")
A2A_PORT = int(os.getenv("SOC_A2A_PORT", "9001"))
A2A_TIMEOUT_S = float(os.getenv("SOC_A2A_TIMEOUT", "30"))
A2A_BASE_URL = f"http://{A2A_HOST}:{A2A_PORT}"

# Where each agent publishes its Agent Card. ".well-known" is a web
# convention: a fixed location where a service describes itself, so a
# caller who knows only the address can discover what the agent can do.
AGENT_CARD_PATHS = {
    "triage": "/triage/.well-known/agent-card.json",
    "hunter": "/hunter/.well-known/agent-card.json",
    "forensics": "/forensics/.well-known/agent-card.json",
}


# =============================================================================
# THREAT INTELLIGENCE
# =============================================================================

# Turns off every outbound lookup. Useful for a demonstration with no
# internet, and for making a run reproducible.
OFFLINE_MODE = _flag("SOC_OFFLINE_MODE", default=False)
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
INTEL_TIMEOUT_S = float(os.getenv("SOC_INTEL_TIMEOUT", "10"))
INTEL_CACHE_FILE = DATA_DIR / "intel_cache.json"

# The alert history, as a queryable database. The forensics agent asks it
# "what else happened around this time, and on which hosts?"
HISTORY_DB = DATA_DIR / "soc_history.db"


# =============================================================================
# THE LANGUAGE MODEL
# =============================================================================

OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_MODEL = os.getenv("SOC_LLM_MODEL", "gpt-6-luna")
LLM_TEMPERATURE = float(os.getenv("SOC_LLM_TEMPERATURE", "0"))
LLM_TIMEOUT_S = float(os.getenv("SOC_LLM_TIMEOUT", "45"))
LLM_MAX_RETRIES = int(os.getenv("SOC_LLM_RETRIES", "2"))


def card_url(agent: str) -> str:
    """The card path for one agent. Raises KeyError for an unknown name,
    which is better than returning None and failing later with a confusing
    network error."""
    return AGENT_CARD_PATHS[agent]


def describe() -> str:
    """One line for a log or a test header, so a run always records the
    transport it used."""
    return f"A2A_MODE={A2A_MODE} base={A2A_BASE_URL} timeout={A2A_TIMEOUT_S}s"