"""
core/llm.py
===========
One place that talks to the language model.

Four jobs:
  1. build the client, from settings, with the key from .env
  2. force the model's answer into a Pydantic contract
  3. survive provider quirks without crashing the pipeline
  4. count the tokens and the money

TWO LAYERS OF STRUCTURE ENFORCEMENT, deliberately:

  Layer 1  the provider's own `json_schema` mode. The API itself refuses to
           emit anything that does not match the schema.
  Layer 2  if the model or provider does not support layer 1, we put the
           schema into the prompt, read the JSON back ourselves, and validate
           it with Pydantic.

Why both: layer 1 is a provider feature and varies by model. Layer 2 is OUR
guarantee and works everywhere. The contract is enforced at our boundary,
not only by someone else's feature flag.

ONE PROMISE THIS FILE MAKES: the only exception that ever escapes
`structured_call` is LLMUnavailable. A caller catches that one type and
falls back. A fallback that can itself crash is not a fallback.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Callable, TypeVar

from pydantic import BaseModel, ValidationError

from core.config import (
    LLM_MAX_RETRIES,
    LLM_MODEL,
    LLM_TEMPERATURE,
    LLM_TIMEOUT_S,
    OFFLINE_MODE,
    OPENAI_KEY,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "gpt-6-luna": (0.10, 0.50),
    "gpt-6.1-sol": (2.00, 10.00),
    "gpt-6-astra": (10.00, 50.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4o": (2.50, 10.00),
}
DEFAULT_PRICE = (0.10, 0.50)

# Exported so agents can report which model they used in their A2A metadata.
LLM_MODEL_NAME = LLM_MODEL

_TEMPERATURE_PINNED = True


class LLMUnavailable(RuntimeError):
    pass


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    price_in, price_out = PRICES_PER_MTOK.get(model, DEFAULT_PRICE)
    return (input_tokens * price_in + output_tokens * price_out) / 1_000_000


def llm_available() -> bool:
    return bool(OPENAI_KEY) and not OFFLINE_MODE


def temperature_is_pinned() -> bool:
    return _TEMPERATURE_PINNED


@lru_cache(maxsize=2)
def get_llm(pin_temperature: bool = True):
    if not llm_available():
        raise LLMUnavailable(
            "No OPENAI_API_KEY, or SOC_OFFLINE_MODE is on. "
            "Agents will fall back to deterministic synthesis.")
    from langchain_openai import ChatOpenAI

    settings: dict[str, Any] = {
        "model": LLM_MODEL,
        "timeout": LLM_TIMEOUT_S,
        "max_retries": LLM_MAX_RETRIES,
        "api_key": OPENAI_KEY,
    }
    if pin_temperature:
        settings["temperature"] = LLM_TEMPERATURE
    return ChatOpenAI(**settings)


def _is_temperature_error(error: Exception) -> bool:
    text = str(error).lower()
    return "temperature" in text and (
        "not support" in text or "unsupported" in text)


def _run(call: Callable[[Any], Any]) -> Any:
    global _TEMPERATURE_PINNED
    try:
        return call(get_llm(_TEMPERATURE_PINNED))
    except Exception as error:
        if _TEMPERATURE_PINNED and _is_temperature_error(error):
            _TEMPERATURE_PINNED = False
            return call(get_llm(False))
        raise


def _usage_from(raw: Any) -> dict[str, int]:
    usage = getattr(raw, "usage_metadata", None) or {}
    return {"input_tokens": int(usage.get("input_tokens", 0)),
            "output_tokens": int(usage.get("output_tokens", 0))}


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        lines = [l for l in text.splitlines() if not l.strip().startswith("```")]
        text = "\n".join(lines)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("No JSON object found in the model's reply.")
    return json.loads(text[start:end + 1])


def structured_call(schema: type[ModelT], system: str, user: str) -> tuple[ModelT, dict]:
    try:
        llm_ready = get_llm(_TEMPERATURE_PINNED)
    except LLMUnavailable:
        raise
    except Exception as error:
        raise LLMUnavailable(
            f"Could not build the model client: "
            f"{type(error).__name__}: {error}") from error

    primary_error: Exception | None = None

    try:
        def layer_one(llm):
            bound = llm.with_structured_output(schema, method="json_schema",
                                               include_raw=True)
            return bound.invoke([("system", system), ("human", user)])

        answer = _run(layer_one)
        parsed = answer.get("parsed")
        if parsed is not None:
            usage = _usage_from(answer.get("raw"))
            usage.update({"model": LLM_MODEL, "mode": "json_schema",
                          "temperature_pinned": _TEMPERATURE_PINNED})
            return parsed, usage
        primary_error = ValueError("Provider returned no parsed object.")
    except Exception as error:
        primary_error = error

    schema_text = json.dumps(schema.model_json_schema(), indent=2)
    fallback_system = (
        f"{system}\n\n"
        f"Reply with ONE JSON object and nothing else. It must match this "
        f"JSON Schema exactly:\n{schema_text}")

    try:
        raw = _run(lambda llm: llm.invoke(
            [("system", fallback_system), ("human", user)]))
        text = raw.content if isinstance(raw.content, str) else str(raw.content)
        parsed = schema.model_validate(_extract_json(text))
    except Exception as fallback_error:
        raise LLMUnavailable(
            f"Structured output failed both ways. "
            f"primary={type(primary_error).__name__}: {primary_error} | "
            f"fallback={type(fallback_error).__name__}: {fallback_error}"
        ) from fallback_error

    usage = _usage_from(raw)
    usage.update({"model": LLM_MODEL, "mode": "prompted_json",
                  "temperature_pinned": _TEMPERATURE_PINNED})
    return parsed, usage