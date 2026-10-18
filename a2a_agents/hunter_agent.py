"""
a2a_agents/hunter_agent.py
==========================
The threat-hunter as a real A2A agent. Agent 2 of 5.

Same two pieces as the triage agent:

  1. HUNTER_CARD          - the public Agent Card
  2. HunterAgentExecutor  - the worker

One difference worth understanding. Triage needs only the alert. The hunter
also needs `local_hits`, so there is a `HuntRequest` contract wrapping the
alert. See the note in core/contracts.py for why.
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

from core.contracts import HuntRequest
from core.llm import LLM_MODEL_NAME, cost_usd
from core.models import Alert
from tools.hunter import hunt


# Same host and port as the triage agent, a different PATH. One process,
# several agents, each with its own card and endpoint.
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 9001
AGENT_PATH = "/hunter"

BASE_URL = f"http://{AGENT_HOST}:{AGENT_PORT}{AGENT_PATH}"
CARD_PATH = f"{AGENT_PATH}/.well-known/agent-card.json"


# =============================================================================
# THE AGENT CARD
# =============================================================================

HUNTER_CARD = AgentCard(
    name="SOC Threat Hunter Agent",

    # The description states the division of labour explicitly. Any caller
    # reading this card learns, BEFORE calling, that the factual claims come
    # from tools and only the prose comes from a model.
    description=(
        "Enriches a Wazuh alert with threat intelligence. Looks up indicator "
        "reputation across first-party and third-party sources, maps the alert "
        "to MITRE ATT&CK techniques, and produces an analytical hypothesis. "
        "Every factual claim comes from a deterministic tool; the language "
        "model contributes only the prose summary and a 0-100 threat score."
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
            id="enrich_alert",
            name="Enrich an alert with threat intelligence",
            description=(
                "Send {\"alert\": <Alert as JSON>, \"local_hits\": <int>}. "
                "Returns a HuntResult as JSON: enriched indicators with "
                "per-source verdicts, MITRE techniques, a hypothesis and a "
                "threat score."
            ),
            tags=["security", "soc", "threat-intelligence", "mitre", "enrichment"],
            input_modes=["application/json"],
            output_modes=["application/json"],
            examples=[
                '{"alert":{"id":"alert-001","timestamp":"2026-02-18T10:32:00Z",'
                '"rule_id":"5710","rule_level":10,"rule_description":'
                '"sshd: brute force","agent_name":"web-01",'
                '"src_ip":"185.220.101.42"},"local_hits":12}'
            ],
        )
    ],
)


# =============================================================================
# THE EXECUTOR
# =============================================================================


class HunterAgentExecutor(AgentExecutor):
    """Receives an A2A request, runs the hunt, publishes the result."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        # The Task object must EXIST before any status update about it.
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
            payload = "".join(part.text for part in context.message.parts if part.text)

            # TWO contracts guard this door: the wrapper, then the alert
            # inside it. Anything arriving over a network is untrusted.
            request = HuntRequest.model_validate_json(payload)
            alert = Alert.model_validate(request.alert)

            result, meta = hunt(alert, local_hits=request.local_hits)

            # THE METADATA IS THE POINT OF THIS BLOCK.
            # The work happened in THIS process, but the orchestrator needs
            # to report the tokens and the cost in its metrics sidebar. A2A
            # artifact metadata is how that information crosses back.
            #
            # Note every value is a string: A2A metadata is string-to-string,
            # so the receiving side converts them back to numbers.
            usage = meta.get("usage") or {}
            metadata = {
                "alert_id": alert.id,
                "agent": "hunter",
                "llm_used": str(meta["llm_used"]),
                "llm_mode": str(usage.get("mode", "none")),
                "llm_model": str(usage.get("model", "none")),
                "input_tokens": str(usage.get("input_tokens", 0)),
                "output_tokens": str(usage.get("output_tokens", 0)),
                "cost_usd": f"{cost_usd(usage.get('model', LLM_MODEL_NAME), usage.get('input_tokens', 0), usage.get('output_tokens', 0)):.6f}",
            }
            # If the model was NOT used, say why. Silent degradation is the
            # thing we are most careful to avoid.
            if meta.get("fallback_reason"):
                metadata["fallback_reason"] = str(meta["fallback_reason"])[:300]

            await updater.add_artifact(
                [Part(text=result.model_dump_json())],
                name="hunt_result",
                metadata=metadata,
            )
            await updater.complete()

        except Exception as error:
            # Tell the caller what broke, without leaking a stack trace.
            await updater.add_artifact(
                [Part(text=json.dumps({
                    "error": type(error).__name__,
                    "detail": str(error)[:400],
                }))],
                name="hunter_error",
            )
            await updater.failed()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Required by A2A. Enrichment takes about a second, so there is
        nothing worth cancelling."""
        raise NotImplementedError("Enrichment is short-lived; cancellation unsupported.")