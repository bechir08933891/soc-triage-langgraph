"""
a2a_agents/forensics_agent.py
=============================
The forensics investigator as a real A2A agent. Agent 3 of 5.

Same two pieces as the other agents:

  1. FORENSICS_CARD          - the public Agent Card
  2. ForensicsAgentExecutor  - the worker

WHAT MAKES THIS ONE DIFFERENT: it is the first STATEFUL agent. Triage and
hunter are pure functions of their input. Forensics cannot be, because an
incident is defined by its neighbours in time - so this agent owns a
datastore and must guarantee it exists before answering.

The condition of that datastore is reported in the artifact metadata on
every call. An agent that quietly answered from an empty database would
return an empty timeline, and an empty timeline looks exactly like a quiet
night.
"""

from __future__ import annotations

import json

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
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

from core.contracts import ForensicsRequest
from core.models import Alert
from tools import history
from tools.forensics import narrate


# Same host and port as the other agents, a different path. One process,
# three agents, each with its own card and endpoint.
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 9001
AGENT_PATH = "/forensics"

BASE_URL = f"http://{AGENT_HOST}:{AGENT_PORT}{AGENT_PATH}"
CARD_PATH = f"{AGENT_PATH}/.well-known/agent-card.json"


# =============================================================================
# THE AGENT CARD
# =============================================================================

FORENSICS_CARD = AgentCard(
    name="SOC Forensics Agent",

    # The description states the two things a caller most needs to know
    # before calling: that evidence is partitioned by actor, and that every
    # verdict comes from rules rather than from a model.
    description=(
        "Reconstructs the sequence of events around a Wazuh alert from an "
        "alert history datastore, determines whether the multi-host pattern "
        "is lateral movement or horizontal scanning, and infers the "
        "kill-chain stage. Evidence is partitioned by actor before any "
        "language model sees it, so events belonging to other attackers in "
        "the same time window are never attributed to this one. All "
        "verdicts are produced by deterministic rules; the model contributes "
        "only the narrative and a containment priority."
    ),

    version="1.0.0",
    supported_interfaces=[
        AgentInterface(url=BASE_URL, protocol_binding="JSONRPC",
                       protocol_version="1.0")
    ],
    capabilities=AgentCapabilities(streaming=True),
    default_input_modes=["application/json"],
    default_output_modes=["application/json"],

    skills=[
        AgentSkill(
            id="investigate_alert",
            name="Reconstruct the incident around an alert",
            description=(
                "Send {\"alert\": <Alert as JSON>, \"window_minutes\": <int>}. "
                "Returns a ForensicsResult as JSON: an actor-marked timeline, "
                "affected hosts, lateral_movement and horizontal_spread flags, "
                "the attack stage, and a written analysis."
            ),
            tags=["security", "soc", "forensics", "timeline", "lateral-movement"],
            input_modes=["application/json"],
            output_modes=["application/json"],
            # A real, copy-pasteable example. A card whose example cannot be
            # sent is a card nobody can use.
            examples=[
                '{"alert":{"id":"alert-001","timestamp":"2026-02-18T10:32:00Z",'
                '"rule_id":"5710","rule_level":10,"rule_description":'
                '"sshd: authentication success","agent_name":"web-01",'
                '"src_ip":"185.220.101.42","user":"s.karim"},'
                '"window_minutes":60}'
            ],
        )
    ],
)


# =============================================================================
# THE EXECUTOR
# =============================================================================


class ForensicsAgentExecutor(AgentExecutor):
    """Receives an A2A request, investigates, publishes the result."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        # The Task object must exist before any status update about it, or
        # the SDK refuses with "Agent should enqueue Task before
        # TaskStatusUpdateEvent".
        await event_queue.enqueue_event(
            Task(
                id=context.task_id,
                context_id=context.context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
            )
        )
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        await updater.start_work()

        try:
            # FIRST, before anything else: is the datastore there? This is
            # the stateful part of a stateful agent, and the returned note
            # travels back in the metadata so the caller knows.
            history_note = history.ensure_built()

            payload = "".join(part.text for part in context.message.parts if part.text)

            # TWO contracts guard this door: the wrapper, then the alert
            # inside it. Anything arriving over a network is untrusted.
            request = ForensicsRequest.model_validate_json(payload)
            alert = Alert.model_validate(request.alert)

            result, meta = narrate(alert, window_minutes=request.window_minutes)

            # THE METADATA IS THE AUDIT TRAIL.
            # The work happened in THIS process, but the orchestrator has to
            # report the datastore's condition, the actor split, the tokens
            # and the cost. A2A artifact metadata is how that crosses back.
            #
            # Every value is a string: A2A metadata is string-to-string, so
            # the receiving node converts the numbers back.
            usage = meta.get("usage") or {}
            own = sum(1 for e in result.timeline if e.same_actor)
            metadata = {
                "alert_id": alert.id,
                "agent": "forensics",
                "history": history_note,
                "window_minutes": str(meta["window_minutes"]),
                "timeline_events": str(len(result.timeline)),
                # These two numbers ARE finding 14, reported per call.
                "own_actor_events": str(own),
                "foreign_events": str(len(result.timeline) - own),
                "lateral_movement": str(result.lateral_movement),
                "horizontal_spread": str(result.horizontal_spread),
                "attack_stage": result.attack_stage.value,
                "llm_used": str(meta["llm_used"]),
                "llm_mode": str(usage.get("mode", "none")),
                "llm_model": str(usage.get("model", "none")),
                "input_tokens": str(usage.get("input_tokens", 0)),
                "output_tokens": str(usage.get("output_tokens", 0)),
                # The cost now arrives already computed from core/llm.py,
                # so every agent reports the same figure.
                "cost_usd": f"{float(usage.get('cost_usd', 0.0)):.6f}",
            }
            if meta.get("containment_priority") is not None:
                metadata["containment_priority"] = str(meta["containment_priority"])
            # If the model was not used, say WHY. There are two different
            # reasons and they mean opposite things: "skipped" was our own
            # deliberate choice, "fallback" was a failure.
            if meta.get("fallback_reason"):
                metadata["fallback_reason"] = str(meta["fallback_reason"])[:300]
            if meta.get("skipped_reason"):
                metadata["skipped_reason"] = str(meta["skipped_reason"])[:300]

            await updater.add_artifact(
                [Part(text=result.model_dump_json())],
                name="forensics_result",
                metadata=metadata,
            )
            await updater.complete()

        except Exception as error:
            # Tell the caller what broke, without leaking a stack trace to
            # something on the other side of a network.
            await updater.add_artifact(
                [Part(text=json.dumps({
                    "error": type(error).__name__,
                    "detail": str(error)[:400],
                }))],
                name="forensics_error",
            )
            await updater.failed()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Required by A2A. An investigation is a few database queries, so
        there is nothing worth cancelling."""
        raise NotImplementedError("Investigation is short-lived; cancellation unsupported.")