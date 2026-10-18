"""
test_a2a.py
===========
Acts as an A2A CLIENT and calls our triage agent over the protocol.

Run `python run_agents.py` in another window first.

Three stages, which are the three stages of every A2A conversation:
  1. DISCOVER  - fetch the Agent Card and learn what this agent can do
  2. SEND      - send a message, watch the task move through its states
  3. VALIDATE  - check the answer against our own Pydantic contract
"""

import asyncio
import uuid

import httpx

from a2a.client import ClientConfig, ClientFactory
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

from core.contracts import TriageResult
from core.preprocessor import load_alerts

SERVER = "http://127.0.0.1:9001"


async def main() -> None:
    # Take 3 real alerts from the dataset you downloaded.
    alerts = load_alerts(limit=3)

    # `async with` opens the HTTP client and closes it again automatically,
    # even if something goes wrong in the middle.
    async with httpx.AsyncClient(timeout=30) as http:
        print("STEP 1 - DISCOVER THE AGENT")
        card = await A2ACardResolver(
            http, SERVER, agent_card_path="/triage/.well-known/agent-card.json"
        ).get_agent_card()
        print(f"  name     : {card.name}")
        print(f"  version  : {card.version}")
        print(f"  skills   : {[s.id for s in card.skills]}")
        print(f"  endpoint : {card.supported_interfaces[0].url}")

        # The factory reads the card and builds a client that speaks the
        # right protocol version and format. We never hardcode a URL.
        client = ClientFactory(ClientConfig(httpx_client=http)).create(card)

        for alert in alerts:
            print()
            print("=" * 66)
            print(f"STEP 2 - SEND {alert.id}  ({alert.rule_description[:40]})")

            # An A2A message: a unique id, who is speaking, and the content.
            message = Message(
                message_id=uuid.uuid4().hex,
                role=Role.ROLE_USER,
                parts=[Part(text=alert.model_dump_json())],
            )

            result_json = None
            # `async for` reads events as they arrive, live.
            async for event in client.send_message(SendMessageRequest(message=message)):
                # An event carries exactly one kind of payload. This asks which.
                kind = event.WhichOneof("payload")
                if kind == "task":
                    print(f"  task {event.task.id[:12]}... "
                          f"state={TaskState.Name(event.task.status.state)}")
                elif kind == "status_update":
                    print(f"  status -> {TaskState.Name(event.status_update.status.state)}")
                elif kind == "artifact_update":
                    artifact = event.artifact_update.artifact
                    print(f"  artifact '{artifact.name}' received")
                    for part in artifact.parts:
                        if part.text:
                            result_json = part.text

            print("STEP 3 - VALIDATE THE ANSWER AGAINST OUR CONTRACT")
            # The answer came over a network from another process. We do not
            # trust it. Pydantic checks it before we use it.
            result = TriageResult.model_validate_json(result_json)
            print(f"  {result.headline()}")
            print(f"  escalate : {result.escalate_to_tier2}")
            print(f"  signals  : {result.matched_signals}")


# Starts the asynchronous program.
asyncio.run(main())