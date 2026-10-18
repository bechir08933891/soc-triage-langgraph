"""
nodes/a2a_client.py
===================
Speaks A2A. Knows nothing about security, alerts or triage.

This file is deliberately generic: `call_agent("triage", json)` today,
`call_agent("hunter", json)` tomorrow. The A2A plumbing is written ONCE and
reused by every node.

It returns the result AND a list of observations — what was discovered, which
task was created, which states it passed through. Those observations become
the live log lines in your demonstration, which is how you PROVE the protocol
was really used rather than just claiming it.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from a2a.client import ClientConfig, ClientFactory
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

from core.config import A2A_BASE_URL, A2A_TIMEOUT_S, card_url


class A2ACallFailed(RuntimeError):
    """Raised when an A2A call cannot be completed.

    Our own exception type, so a node can catch exactly this and nothing else.
    Catching every possible error would also swallow real bugs.
    """


async def call_agent(agent: str, payload_json: str) -> dict[str, Any]:
    """Send one JSON payload to one A2A agent and return its answer.

    Returns a dictionary holding:
        result_json   - the agent's answer, as JSON text
        task_id       - the A2A task identifier (your proof it happened)
        final_state   - the last task state we saw
        agent_name    - the name from the Agent Card
        agent_version - the version from the Agent Card
        observations  - the step-by-step trace, for the live log
    """
    observations: list[dict[str, str]] = []
    result_text: str | None = None
    task_id: str | None = None
    final_state = "UNKNOWN"

    try:
        # `async with` guarantees the connection is closed afterwards, even
        # if an error happens in the middle.
        async with httpx.AsyncClient(timeout=A2A_TIMEOUT_S) as http:

            # --- 1. DISCOVER -------------------------------------------------
            # We fetch the Agent Card instead of hardcoding an endpoint. This
            # is what makes it interoperability and not just an HTTP call.
            resolver = A2ACardResolver(
                http, A2A_BASE_URL, agent_card_path=card_url(agent)
            )
            card = await resolver.get_agent_card()
            observations.append({
                "stage": "discovered",
                "detail": f"{card.name} v{card.version}",
            })

            # The factory reads the card and builds a client that matches the
            # protocol version and format the agent advertised.
            client = ClientFactory(ClientConfig(httpx_client=http)).create(card)

            # --- 2. SEND -----------------------------------------------------
            message = Message(
                message_id=uuid.uuid4().hex,   # a fresh unique id per message
                role=Role.ROLE_USER,           # we are the caller
                parts=[Part(text=payload_json)],
            )

            # `async for` reads events as they arrive, live, instead of
            # waiting for everything to finish first.
            async for event in client.send_message(SendMessageRequest(message=message)):
                # An event carries exactly one kind of payload. This asks which.
                kind = event.WhichOneof("payload")

                if kind == "task":
                    task_id = event.task.id
                    final_state = TaskState.Name(event.task.status.state)
                    observations.append({
                        "stage": "task_created",
                        "detail": f"{task_id[:8]} {final_state}",
                    })

                elif kind == "status_update":
                    final_state = TaskState.Name(event.status_update.status.state)
                    observations.append({"stage": "status", "detail": final_state})

                elif kind == "artifact_update":
                    artifact = event.artifact_update.artifact
                    for part in artifact.parts:
                        if part.text:
                            result_text = part.text
                    observations.append({
                        "stage": "artifact",
                        "detail": artifact.name or "unnamed",
                    })

    except httpx.ConnectError as error:
        # The most common mistake by far: forgetting to start the server.
        # A clear message here saves you ten minutes of confusion.
        raise A2ACallFailed(
            f"Cannot reach the A2A agent '{agent}' at {A2A_BASE_URL}. "
            f"Is `python run_agents.py` running? ({error})"
        ) from error

    except Exception as error:
        raise A2ACallFailed(
            f"A2A call to '{agent}' failed: {type(error).__name__}: {error}"
        ) from error

    # The call succeeded but the agent sent nothing back. That is a failure
    # too, and we must not pretend otherwise.
    if result_text is None:
        raise A2ACallFailed(
            f"Agent '{agent}' returned no artifact (final state {final_state})."
        )

    return {
        "result_json": result_text,
        "task_id": task_id,
        "final_state": final_state,
        "agent_name": card.name,
        "agent_version": card.version,
        "observations": observations,
    }