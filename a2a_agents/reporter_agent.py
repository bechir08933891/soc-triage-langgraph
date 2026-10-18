"""
a2a_agents/reporter_agent.py
============================
The reporter as a real A2A agent. Agent 4 of 5.

Same two pieces as the other agents:

  1. REPORTER_CARD          - the public Agent Card
  2. ReporterAgentExecutor  - the worker

WHAT MAKES THIS ONE DIFFERENT: it is the only agent whose input is OTHER
AGENTS' OUTPUT. So it validates four contracts at the door, and every one
of the three findings is optional - a missing agent is reported as missing
rather than guessed, because a report that silently omits a failed input
looks exactly like a report where that input came back clean.
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

from core.contracts import (
    ForensicsResult,
    HuntResult,
    ReportRequest,
    TriageResult,
)
from core.models import Alert
from tools.reporter import report


# Same host and port as the other agents, a different path. One process,
# four agents, each with its own card and endpoint.
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 9001
AGENT_PATH = "/reporter"

BASE_URL = f"http://{AGENT_HOST}:{AGENT_PORT}{AGENT_PATH}"
CARD_PATH = f"{AGENT_PATH}/.well-known/agent-card.json"


# =============================================================================
# THE AGENT CARD
# =============================================================================

REPORTER_CARD = AgentCard(
    name="SOC Reporter Agent",

    # The description leads with the escalation rule, because that is the
    # thing a caller most needs to understand before trusting the output.
    description=(
        "Assembles the findings of the triage, hunter and forensics agents "
        "into one incident report, and computes the escalation decision from "
        "the union of their signals rather than from any single agent's "
        "verdict. Where the agents disagree, the report states the "
        "disagreement explicitly instead of reconciling it. Works with "
        "partial input: a missing agent result is recorded as missing, not "
        "guessed. The language model writes only the executive summary and "
        "cannot alter the decision."
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
            id="write_incident_report",
            name="Write the incident report and decide escalation",
            description=(
                "Send {\"alert\": <Alert>, \"triage_result\": <TriageResult|null>, "
                "\"hunt_result\": <HuntResult|null>, \"forensics_result\": "
                "<ForensicsResult|null>}. Returns an IncidentReport as JSON: "
                "a title, a Markdown document, and the generation time."
            ),
            tags=["security", "soc", "reporting", "escalation", "markdown"],
            input_modes=["application/json"],
            output_modes=["application/json"],
            # The example passes nulls on purpose: it documents that partial
            # input is supported, not merely tolerated.
            examples=[
                '{"alert":{"id":"alert-001","timestamp":"2026-02-18T10:32:00Z",'
                '"rule_id":"5710","rule_level":10,"rule_description":'
                '"sshd: brute force","agent_name":"web-01",'
                '"src_ip":"185.220.101.42"},"triage_result":null,'
                '"hunt_result":null,"forensics_result":null}'
            ],
        )
    ],
)


# =============================================================================
# THE EXECUTOR
# =============================================================================


class ReporterAgentExecutor(AgentExecutor):
    """Receives the other agents' findings, writes the report."""

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
            payload = "".join(part.text for part in context.message.parts if part.text)

            # FOUR contracts at this door: the wrapper, then each finding
            # inside it. The `if ... else None` keeps a missing finding
            # missing instead of turning it into an empty object.
            request = ReportRequest.model_validate_json(payload)
            alert = Alert.model_validate(request.alert)
            triage = (TriageResult.model_validate(request.triage_result)
                      if request.triage_result else None)
            hunt = (HuntResult.model_validate(request.hunt_result)
                    if request.hunt_result else None)
            forensics = (ForensicsResult.model_validate(request.forensics_result)
                         if request.forensics_result else None)

            result, meta = report(alert, triage=triage, hunt=hunt,
                                  forensics=forensics)

            # THE METADATA IS THE AUDIT TRAIL - and here it is also the
            # ROUTING DATA. `escalate` travels back as a field so the
            # orchestrator never has to read a Markdown document to find a
            # flag.
            #
            # Every value is a string: A2A metadata is string-to-string, so
            # the receiving node converts them back.
            usage = meta.get("usage") or {}
            metadata = {
                "alert_id": alert.id,
                "agent": "reporter",
                "escalate": str(meta["escalate"]),
                "overridden_triage": str(meta["overridden_triage"]),
                "signals": "; ".join(meta["signals"]) or "none",
                "missing_inputs": ", ".join(meta["missing"]) or "none",
                "report_chars": str(result.char_count),
                "llm_used": str(meta["llm_used"]),
                "llm_mode": str(usage.get("mode", "none")),
                "llm_model": str(usage.get("model", "none")),
                "input_tokens": str(usage.get("input_tokens", 0)),
                "output_tokens": str(usage.get("output_tokens", 0)),
                # The cost arrives already computed from core/llm.py, so
                # every agent reports the same figure.
                "cost_usd": f"{float(usage.get('cost_usd', 0.0)):.6f}",
            }
            if meta.get("confidence") is not None:
                metadata["summary_confidence"] = str(meta["confidence"])
            if meta.get("fallback_reason"):
                metadata["fallback_reason"] = str(meta["fallback_reason"])[:300]

            await updater.add_artifact(
                [Part(text=result.model_dump_json())],
                name="incident_report",
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
                name="reporter_error",
            )
            await updater.failed()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Required by A2A. Writing a report takes milliseconds."""
        raise NotImplementedError("Report writing is short-lived; cancellation unsupported.")