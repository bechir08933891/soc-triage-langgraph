"""
a2a_agents/server.py
====================
Hosts our A2A agents as one small web server.

Why one process for several agents? Four separate servers would use around
600 MB of memory. One process hosting four agents uses about 150 MB. Each
agent still has its own Agent Card and its own endpoint, so it is genuinely
A2A — just efficiently hosted. Splitting them onto separate machines later
needs no code change, only different addresses in the cards.
"""

from __future__ import annotations

# Starlette is the small web framework the A2A SDK builds on.
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

# DefaultRequestHandler connects an executor to the A2A protocol machinery.
from a2a.server.request_handlers import DefaultRequestHandler

# These two build the web addresses: one serves the card, one receives calls.
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes

# Remembers tasks in memory. Enough for a demo; swap for a database later.
from a2a.server.tasks import InMemoryTaskStore

from a2a_agents.triage_agent import (
    AGENT_HOST,
    AGENT_PATH,
    AGENT_PORT,
    CARD_PATH,
    TRIAGE_CARD,
    TriageAgentExecutor,
)


# The list of agents we host. In Steps 12-14 we add hunter, forensics and
# reporter here, and everything else keeps working unchanged.
AGENTS = [
    {
        "name": "triage",
        "card": TRIAGE_CARD,
        "executor": TriageAgentExecutor(),
        "rpc_url": AGENT_PATH,
        "card_url": CARD_PATH,
    },
]


async def index(request):
    """A friendly page at the root, listing the agents we host.

    Not part of A2A — just useful for you and for a jury member who opens
    the address in a browser and wants to see what is running.
    """
    return JSONResponse({
        "service": "SOC Triage Agent - A2A host",
        "agents": [
            {"name": a["name"], "card": a["card_url"], "endpoint": a["rpc_url"]}
            for a in AGENTS
        ],
    })


def build_app() -> Starlette:
    """Assemble the web application from the agent list."""
    routes: list[Route] = [Route("/", index, methods=["GET"])]

    for agent in AGENTS:
        handler = DefaultRequestHandler(
            agent_executor=agent["executor"],
            task_store=InMemoryTaskStore(),
            agent_card=agent["card"],
        )
        # `+=` on a list adds all the items of another list to it.
        routes += create_agent_card_routes(agent["card"], card_url=agent["card_url"])
        routes += create_jsonrpc_routes(handler, rpc_url=agent["rpc_url"])

    return Starlette(routes=routes)


app = build_app()