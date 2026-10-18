"""
run_agents.py
=============
Starts the A2A agent server.

    python run_agents.py

Leave this window OPEN while you work. It must keep running, the same way a
real service stays running. Press Ctrl+C to stop it.
"""

import uvicorn

from a2a_agents.server import app
from a2a_agents.triage_agent import AGENT_HOST, AGENT_PORT, CARD_PATH

# This `if` means "only run the lines below when this file is started
# directly". If another file imports this one, the server does not start.
if __name__ == "__main__":
    print("=" * 62)
    print("  SOC A2A AGENT HOST")
    print("=" * 62)
    print(f"  Agent card : http://{AGENT_HOST}:{AGENT_PORT}{CARD_PATH}")
    print(f"  Index      : http://{AGENT_HOST}:{AGENT_PORT}/")
    print("  Stop with Ctrl+C")
    print("=" * 62)
    # uvicorn is the web server that runs our application.
    uvicorn.run(app, host=AGENT_HOST, port=AGENT_PORT, log_level="warning")