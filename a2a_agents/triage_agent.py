"""
a2a_agents/triage_agent.py
==========================
Wraps our deterministic triage logic as a real A2A agent.

Two pieces live here:

  1. TRIAGE_CARD        - the Agent Card. A public description of who this
                          agent is and what it can do. Any A2A client fetches
                          this FIRST, then knows how to talk to us.

  2. TriageAgentExecutor - the worker. A2A hands it a request, it runs our
                          triage function, and it publishes the result back.

Nothing in tools/severity.py changes. We are adding a door, not new logic.
"""

from __future__ import annotations

import json

# --- The A2A server building blocks -----------------------------------------
# AgentExecutor : the base class our worker must inherit from
# RequestContext: holds the incoming message and the task identifiers
# EventQueue    : where we publish progress back to the caller
# TaskUpdater   : a helper that writes well-formed status events for us
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater

# --- The A2A data types ------------------------------------------------------
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Part,
    Task,
    TaskState,
    TaskStatus,
)

# --- Our own code ------------------------------------------------------------
from core.models import Alert
from tools.severity import assign_severity


# =============================================================================
# WHERE THIS AGENT LIVES
#
# 127.0.0.1 means "this computer only". Nothing is exposed to the internet,
# which is exactly what we want while developing.
# =============================================================================

AGENT_HOST = "127.0.0.1"
AGENT_PORT = 9001
AGENT_PATH = "/triage"

BASE_URL = f"http://{AGENT_HOST}:{AGENT_PORT}{AGENT_PATH}"

# The conventional address for an Agent Card. A2A clients look here first.
# We put it under /triage so that later agents (hunter, forensics, reporter)
# can live on the same port with their own cards.
CARD_PATH = f"{AGENT_PATH}/.well-known/agent-card.json"


# =============================================================================
# THE AGENT CARD — the agent's public identity
# =============================================================================

TRIAGE_CARD = AgentCard(
    name="SOC Triage Agent",

    # Be precise. A client reads this to decide whether to call you at all.
    description=(
        "Classifies a Wazuh security alert into an attack family and "
        "assigns a severity. Fully deterministic: the same alert always "
        "produces the same result. No language model is used."
    ),

    version="1.0.0",

    # HOW to reach this agent. "JSONRPC" is the message format; "1.0" is the
    # A2A protocol version, which is the current stable specification.
    supported_interfaces=[
        AgentInterface(
            url=BASE_URL,
            protocol_binding="JSONRPC",
            protocol_version="1.0",
        )
    ],

    # What optional features we support. Streaming means we can send progress
    # updates while we work — that is what will drive your live demo later.
    capabilities=AgentCapabilities(streaming=True),

    # We speak JSON in and JSON out. Not free text.
    default_input_modes=["application/json"],
    default_output_modes=["application/json"],

    # SKILLS: the specific jobs this agent can do. A client can read this list
    # and decide "yes, this agent does what I need".
    skills=[
        AgentSkill(
            id="triage_alert",
            name="Triage a Wazuh alert",
            description=(
                "Send one normalised Wazuh alert as JSON. Returns a "
                "TriageResult as JSON: attack type, severity, score, "
                "confidence, escalation decision and matched signals."
            ),
            tags=["security", "soc", "wazuh", "triage", "deterministic"],
            input_modes=["application/json"],
            output_modes=["application/json"],
            # A real example, so a caller knows exactly what to send.
            examples=[
                '{"id":"alert-001","timestamp":"2026-02-18T10:32:00Z",'
                '"rule_id":"5710","rule_level":10,'
                '"rule_description":"sshd: brute force trying to get access",'
                '"agent_name":"web-server-01","src_ip":"185.220.101.42"}'
            ],
        )
    ],
)


# =============================================================================
# THE EXECUTOR — the worker that actually does the job
# =============================================================================


class TriageAgentExecutor(AgentExecutor):
    """Receives an A2A request, runs our triage, publishes the result."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Handle one triage request.

        An A2A task has a life cycle that the caller watches:
            SUBMITTED  -> we received it
            WORKING    -> we are busy
            COMPLETED  -> here is your answer
        Publishing each stage is what lets a client show live progress.
        """
        # The protocol requires the Task object to EXIST before we send any
        # status update about it. Forgetting this gives the error
        # "Agent should enqueue Task before TaskStatusUpdateEvent event".
        await event_queue.enqueue_event(
            Task(
                id=context.task_id,
                context_id=context.context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
            )
        )

        # TaskUpdater writes correctly-formed events for us.
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        await updater.start_work()

        try:
            # An A2A message is made of "parts". We joined ours into one
            # piece of JSON text on the sending side, so we glue it back here.
            payload = "".join(part.text for part in context.message.parts if part.text)

            # 🔑 THE CONTRACT GUARDS THE DOOR.
            # Anything arriving from outside is untrusted. Pydantic validates
            # it before our logic ever sees it. A malformed alert is rejected
            # here, not deep inside the classifier.
            alert = Alert.model_validate_json(payload)

            # Our ordinary, deterministic function. Unchanged since Step 8.
            result = assign_severity(alert)

            # An "artifact" is a produced result, as opposed to a chat message.
            # We send our TriageResult back as JSON.
            await updater.add_artifact(
                [Part(text=result.model_dump_json())],
                name="triage_result",
                metadata={"alert_id": alert.id, "agent": "triage"},
            )
            await updater.complete()

        except Exception as error:
            # Never let a server crash silently. Tell the caller WHAT went
            # wrong, but do not leak a full stack trace over the network.
            await updater.add_artifact(
                [Part(text=json.dumps({
                    "error": type(error).__name__,
                    "detail": str(error)[:400],
                }))],
                name="triage_error",
            )
            await updater.failed()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """A2A requires this method to exist. Triage finishes in milliseconds,
        so there is nothing meaningful to cancel."""
        raise NotImplementedError("Triage is instant; cancellation is not supported.")