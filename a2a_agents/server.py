"""
a2a_agents/server.py
====================
Hosts our A2A agents as one small web server.

Why one process for several agents? Four separate servers would use around
600 MB of memory. One process hosting four agents uses about 150 MB. Each
agent still has its own Agent Card and its own endpoint, so it is genuinely
A2A - just efficiently hosted. Splitting them onto separate machines later
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

# `as FORENSICS_PATH` renames on import. EVERY agent file defines AGENT_PATH
# and CARD_PATH, so without renaming, the later imports would silently
# overwrite the earlier ones - a nasty bug that would send reporter
# requests to triage. Only the triage agent keeps the plain names.
from a2a_agents.forensics_agent import (
    AGENT_PATH as FORENSICS_PATH,
    CARD_PATH as FORENSICS_CARD_PATH,
    FORENSICS_CARD,
    ForensicsAgentExecutor,
)
from a2a_agents.hunter_agent import (
    AGENT_PATH as HUNTER_PATH,
    CARD_PATH as HUNTER_CARD_PATH,
    HUNTER_CARD,
    HunterAgentExecutor,
)
from a2a_agents.reporter_agent import (
    AGENT_PATH as REPORTER_PATH,
    CARD_PATH as REPORTER_CARD_PATH,
    REPORTER_CARD,
    ReporterAgentExecutor,
)
from a2a_agents.triage_agent import (
    AGENT_HOST,
    AGENT_PATH,
    AGENT_PORT,
    CARD_PATH,
    TRIAGE_CARD,
    TriageAgentExecutor,
)


# The list of agents we host. Four of the five; the fifth is the human, who
# does not need a web address. Adding another agent means adding one entry
# here and nothing else.
AGENTS = [
    {
        "name": "triage",
        "card": TRIAGE_CARD,
        "executor": TriageAgentExecutor(),
        "rpc_url": AGENT_PATH,
        "card_url": CARD_PATH,
    },
    {
        "name": "hunter",
        "card": HUNTER_CARD,
        "executor": HunterAgentExecutor(),
        "rpc_url": HUNTER_PATH,
        "card_url": HUNTER_CARD_PATH,
    },
    {
        "name": "forensics",
        "card": FORENSICS_CARD,
        "executor": ForensicsAgentExecutor(),
        "rpc_url": FORENSICS_PATH,
        "card_url": FORENSICS_CARD_PATH,
    },
    {
        "name": "reporter",
        "card": REPORTER_CARD,
        "executor": ReporterAgentExecutor(),
        "rpc_url": REPORTER_PATH,
        "card_url": REPORTER_CARD_PATH,
    },
]


async def index(request):
    """A friendly page at the root, listing the agents we host.

    Not part of A2A - just useful for you and for a jury member who opens
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