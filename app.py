"""
app.py
======
The demonstration interface. Five layers:

  1  the agents, live          the audit trail as it happens
  2  what each agent concluded three columns - the disagreement (finding 15)
  3  the evidence              signals, indicators, ATT&CK, the timeline
  4  your decision             the human gate, ONLY when the graph paused
  5  the incident report       the document, downloadable

THREE STREAMLIT FACTS THAT SHAPE THIS FILE:

  A. The whole script RE-RUNS from the top on every interaction. So anything
     expensive goes in @st.cache_resource, and anything that must survive a
     click goes in st.session_state.

  B. The GRAPH must survive reruns. Its checkpointer is what makes
     interrupt() resumable, and a checkpointer rebuilt on every click would
     lose the paused run - the gate would be unable to continue.

  C. Streamlit is synchronous and the graph is async, so each run is driven
     by one asyncio.run(...) call. That is safe here because Streamlit's
     script thread has no running event loop of its own.

ONE RULE ABOUT COLOUR, from finding 20: colour in this interface is
reserved for the three places that genuinely carry a verdict - the
escalation banner, the override warning, and the event kinds in the audit
trail. Counts and scores are rendered in plain, uncoloured captions. An
earlier build showed "+ 4 success(es)" as a green upward delta, two inches
above a red ESCALATE banner reporting the same event.

Run it:
    streamlit run app.py

In A2A mode, run_agents.py must be running in another window.
"""

from __future__ import annotations

import asyncio
import time

import streamlit as st
from langgraph.types import Command

from core.config import (A2A_BASE_URL, A2A_MODE, LLM_MODEL, OFFLINE_MODE,
                         describe)
from core.contracts import Decision
from core.preprocessor import load_alerts
from core.state import initial_state
from graph import build_graph
from tools import history, scenarios
from tools.reporter import POLICY_DEFAULT

# Must be the FIRST Streamlit call in the script, before anything renders.
st.set_page_config(page_title="SOC Triage Agent", page_icon="🛡️",
                   layout="wide")


# One character and one colour per event kind, so a 40-line trail stays
# readable at a glance and a jury member can follow it from across a room.
# This is one of the three places colour is allowed to mean something.
KIND_ICON = {
    "node_start": "▶", "node_end": "■", "tool_call": "·", "llm_call": "~",
    "a2a_call": "@", "a2a_task": " ", "interrupt": "!", "resume": "+",
    "error": "x",
}
KIND_COLOUR = {
    "node_start": "#4c6ef5", "node_end": "#2f9e44", "tool_call": "#868e96",
    "llm_call": "#9775fa", "a2a_call": "#1098ad", "a2a_task": "#adb5bd",
    "interrupt": "#f59f00", "resume": "#2f9e44", "error": "#e03131",
}


# =============================================================================
# SETUP - the expensive things, done once
# =============================================================================


@st.cache_resource(show_spinner="Loading the corpus and building the history…")
def load_everything():
    """Load 738 alerts, build the SQLite history, install the demo incidents.

    @st.cache_resource runs this ONCE per process, not once per click.
    Without it, every button press would re-read a 2.96 MB file and rebuild
    a database - several seconds of waiting on every interaction.
    """
    alerts = load_alerts()
    history.build(alerts)
    scenarios.install()
    return alerts


def get_graph():
    """The graph, kept in session state so its CHECKPOINTER survives reruns.

    This is the one piece that absolutely cannot be rebuilt per click: the
    checkpointer holds the paused run, and a fresh one would have no memory
    of the interrupt, so the gate could never resume.
    """
    if "graph" not in st.session_state:
        st.session_state.graph = build_graph()
    return st.session_state.graph


def reset_run():
    """Forget the previous run. Called when a different alert is picked."""
    for key in ("events", "state", "pause", "thread", "elapsed", "closed"):
        st.session_state.pop(key, None)


def log_html(events: list[dict]) -> str:
    """Render the audit trail as a scrolling monospace block.

    Hand-written HTML rather than st.code because each line needs its own
    colour, and st.code applies one style to everything.
    """
    rows = []
    for event in events:
        icon = KIND_ICON.get(event["kind"], " ")
        colour = KIND_COLOUR.get(event["kind"], "#868e96")
        rows.append(
            f"<div style='font-family:ui-monospace,monospace;font-size:12.5px;"
            f"line-height:1.65;color:{colour};white-space:pre'>"
            f"{icon} [{event['node']:<9}] {event['message'][:96]}</div>")
    return ("<div style='max-height:420px;overflow-y:auto;padding:10px 12px;"
            "border:1px solid rgba(128,128,128,.25);border-radius:8px'>"
            + "".join(rows) + "</div>")


async def drive(graph, payload, config, placeholder, already: int):
    """Run the graph and update the log placeholder as events arrive.

    `stream_mode="values"` yields the WHOLE state after each step. We track
    how many events were already shown (`already`) so the resumed run
    continues the trail instead of repeating it.

    Writing into `placeholder` from inside this async loop is what makes the
    log LIVE: we are still inside the same Streamlit script execution, so the
    placeholder can be rewritten as the graph progresses.
    """
    seen = already
    events: list[dict] = []
    state: dict = {}
    async for chunk in graph.astream(payload, config=config,
                                     stream_mode="values"):
        state = chunk
        events = state.get("events", [])
        if len(events) > seen:
            placeholder.markdown(log_html(events), unsafe_allow_html=True)
            seen = len(events)
    return state, events


# =============================================================================
# SIDEBAR - configuration and the metrics for this run
# =============================================================================

alerts = load_everything()

with st.sidebar:
    st.subheader("Configuration")
    st.markdown(
        f"**Transport** · `{'A2A over JSON-RPC' if A2A_MODE else 'in-process'}`  \n"
        f"**Agents at** · `{A2A_BASE_URL}`  \n"
        f"**Model** · `{LLM_MODEL}`  \n"
        f"**Offline** · `{OFFLINE_MODE}`  \n"
        f"**Gate policy** · `{POLICY_DEFAULT}`")
    st.caption("Change the transport with SOC_A2A_MODE then restart. "
               "In A2A mode run_agents.py must be running.")

    # A live health check, so a failed demo is diagnosed in one click
    # instead of looking like a broken system.
    if st.button("Check the agents", width="stretch"):
        import httpx
        try:
            reply = httpx.get(f"{A2A_BASE_URL}/", timeout=3)
            hosted = reply.json().get("agents", [])
            st.success(f"{len(hosted)} agents hosted")
            for agent in hosted:
                st.caption(f"· {agent['name']} → {agent['endpoint']}")
        except Exception as error:
            st.error(f"No answer: {type(error).__name__}")

    if st.session_state.get("state"):
        st.divider()
        st.subheader("This run")
        state = st.session_state.state
        usage = state.get("token_usage") or []
        tokens = sum(u["total_tokens"] for u in usage)
        st.metric("Tokens", f"{tokens:,}")
        st.metric("Model calls", len(usage))
        if st.session_state.get("elapsed"):
            st.metric("Elapsed", f"{st.session_state.elapsed:,} ms")
        errors = state.get("errors") or []
        st.metric("Errors", len(errors))
        for record in usage:
            st.caption(f"· {record['node']}: {record['total_tokens']} tok")


# =============================================================================
# HEADER AND ALERT PICKER
# =============================================================================

st.title("🛡️ SOC Triage Agent")
st.caption("Four A2A agents, orchestrated by LangGraph, with a human gate. "
           "Rules and tools decide; the language model only writes prose.")

# The synthetic incidents go FIRST and are labelled as such, so nobody can
# mistake a DEMO- alert for corpus evidence.
demo_alerts = scenarios.all_demo_alerts()
choices = [("— labelled synthetic incidents —", None)]
choices += [(f"{a.id}  ·  {a.rule_description[:48]}", a) for a in demo_alerts]
choices += [("— the real corpus —", None)]
choices += [(f"{a.id}  ·  {a.rule_description[:48]}", a) for a in alerts]

# `options=range(len(choices))` with `format_func` lets the list hold real
# Alert objects while the dropdown shows readable text.
picked = st.selectbox("Alert", options=range(len(choices)),
                      format_func=lambda i: choices[i][0], index=3,
                      on_change=reset_run)
alert = choices[picked][1]

if alert is None:
    st.info("Pick an alert, not a separator.")
    st.stop()

left, right = st.columns([3, 1])
with left:
    st.markdown(
        f"**{alert.rule_description}**  \n"
        f"`{alert.id}` · host `{alert.agent_name}` · "
        f"level {alert.rule_level}/15 · "
        f"src `{alert.src_ip or 'none'}` · user `{alert.user or 'none'}`")
with right:
    run = st.button("Run the pipeline", type="primary", width="stretch")

if run:
    reset_run()
    # A fresh thread_id per run, so re-running the same alert starts a clean
    # case rather than resuming the previous one from its checkpoint.
    st.session_state.thread = f"ui-{alert.id}-{int(time.time())}"

st.divider()


# =============================================================================
# LAYER 1 - THE AGENTS, LIVE
# =============================================================================

st.subheader("1 · The agents, live")
log_box = st.empty()

if run:
    graph = get_graph()
    config = {"configurable": {"thread_id": st.session_state.thread}}
    started = time.perf_counter()
    state, events = asyncio.run(
        drive(graph, initial_state(alert), config, log_box, 0))
    st.session_state.elapsed = round((time.perf_counter() - started) * 1000)
    st.session_state.state = state
    st.session_state.events = events
    # `__interrupt__` is present when the graph paused at the gate. Its
    # `.value` is the payload the hitl node passed to interrupt().
    st.session_state.pause = (state["__interrupt__"][0].value
                              if "__interrupt__" in state else None)
    # Rerun so the rest of the page renders from a settled session state
    # rather than half-built mid-run.
    st.rerun()

if st.session_state.get("events"):
    log_box.markdown(log_html(st.session_state.events),
                     unsafe_allow_html=True)
elif not run:
    log_box.info("Press **Run the pipeline**.")

state = st.session_state.get("state") or {}


# =============================================================================
# LAYER 2 - WHAT EACH AGENT CONCLUDED  (finding 15, on screen)
# =============================================================================

if state:
    st.subheader("2 · What each agent concluded")
    triage = state.get("triage_result")
    hunt = state.get("hunt_result")
    forensics = state.get("forensics_result")

    # Three columns, deliberately equal. The layout makes the point that no
    # agent outranks another: the decision is the union of their signals.
    #
    # NO `delta` ARGUMENT ANYWHERE (finding 20). Streamlit renders a delta as
    # a coloured arrow, and an up-arrow is universally "this improved". Four
    # successful authentications by an intruder is the worst number on this
    # screen, and showing it as a green +4 contradicts the red ESCALATE
    # banner directly below. Counts go in captions, which carry no colour
    # and make no claim.
    one, two, three = st.columns(3)
    with one:
        st.markdown("**triage** · rules, one alert")
        if triage:
            st.metric("Severity", triage.severity.value)
            st.caption(f"{triage.attack_type.value} · score "
                       f"{triage.score}/100 · confidence "
                       f"{triage.confidence:.0%}")
            st.caption("**would escalate**" if triage.escalate_to_tier2
                       else "would auto-close")
        else:
            st.warning("no result")
    with two:
        st.markdown("**hunter** · intel + MITRE")
        if hunt:
            st.metric("Worst verdict", hunt.worst_verdict.value)
            st.caption(f"threat score {hunt.threat_score}/100 · "
                       f"{len(hunt.iocs)} indicator(s) · "
                       f"{len(hunt.techniques)} ATT&CK technique(s)")
        else:
            # Skipped by route_after_triage when the alert has no source IP.
            st.warning("skipped or no result")
    with three:
        st.markdown("**forensics** · context, window")
        if forensics:
            pattern = ("lateral movement" if forensics.lateral_movement
                       else "horizontal spread"
                       if forensics.horizontal_spread else "no multi-host pattern")
            st.metric("Attack stage", forensics.attack_stage.value)
            own = sum(1 for e in forensics.timeline if e.same_actor)
            st.caption(f"{pattern} · {forensics.actor_successes} successful "
                       f"authentication(s)")
            st.caption(f"{own}/{len(forensics.timeline)} events in the window "
                       f"are this actor")
        else:
            st.warning("no result")

    signals = state.get("escalation_signals") or []
    if state.get("escalate"):
        st.error("**ESCALATE TO TIER 2** — " + "; ".join(signals))
    else:
        st.success("**AUTO-CLOSED AT TIER 1** — no triggering signal")
    # THE SENTENCE. When this appears, the multi-agent design just earned
    # its keep on screen, in front of whoever is watching.
    if state.get("overridden_triage"):
        st.warning("Triage alone would have auto-closed this alert. The "
                   "decision is the union of all agents' signals.")


# =============================================================================
# LAYER 3 - THE EVIDENCE
# =============================================================================

if state:
    st.subheader("3 · The evidence")
    if triage:
        with st.expander(f"Triage signals — {triage.headline()}"):
            st.write(triage.rationale)
            st.code("\n".join(triage.matched_signals) or "none")
    if hunt and hunt.iocs:
        with st.expander(f"Indicators — worst verdict {hunt.worst_verdict.value}"):
            # The SOURCES column is the point: a verdict with no named
            # source is an assertion, not evidence.
            st.dataframe(
                [{"indicator": i.indicator, "verdict": i.verdict.value,
                  "abuse %": i.abuse_confidence,
                  "sources": ", ".join(i.sources), "detail": i.detail[:70]}
                 for i in hunt.iocs],
                hide_index=True)
    if hunt and hunt.techniques:
        with st.expander(f"MITRE ATT&CK — {len(hunt.techniques)} technique(s)"):
            st.dataframe(
                [{"id": t.technique_id, "name": t.name, "tactic": t.tactic}
                 for t in hunt.techniques],
                hide_index=True)
    if forensics and forensics.timeline:
        own = sum(1 for e in forensics.timeline if e.same_actor)
        with st.expander(
                f"Timeline — {len(forensics.timeline)} events, {own} this actor",
                expanded=True):
            # The legend goes INSIDE the code block, not in a caption. In a
            # caption those markers pass through Markdown on the way to the
            # screen; inside a code block they render exactly as the timeline
            # rows do, which is the whole point of a legend.
            legend = (">> the alert under investigation\n"
                      " ~ a different actor, here by coincidence of timing\n"
                      + "-" * 62)
            st.code(legend + "\n"
                    + "\n".join(e.headline()[:100]
                                for e in forensics.timeline))
            st.write(forensics.analysis)


# =============================================================================
# LAYER 4 - YOUR DECISION  (only when the graph actually paused)
# =============================================================================

pause = st.session_state.get("pause")
if pause and not st.session_state.get("closed"):
    st.subheader("4 · Your decision")
    st.warning(f"The graph is **paused** on `{pause['alert_id']}` and is "
               f"waiting for a human.")
    gate_left, gate_right = st.columns([2, 1])
    with gate_left:
        st.markdown("**Why it escalated**")
        for signal in pause["escalation_signals"]:
            st.markdown(f"- {signal}")
        if pause["overridden_triage"]:
            st.caption("Triage alone would have auto-closed this.")
        note = st.text_input("Note (optional)", key="gate_note")
    with gate_right:
        st.markdown("**Decide**")
        chosen = None
        # The options come FROM the Decision enum, so the interface can
        # never offer a choice the contract would reject.
        for option in pause["options"]:
            if st.button(option.capitalize(), key=f"gate-{option}",
                         width="stretch"):
                chosen = option
    if chosen:
        graph = get_graph()
        config = {"configurable": {"thread_id": st.session_state.thread}}
        # The SAME graph and the SAME thread_id, with a Command instead of a
        # state. LangGraph loads the checkpoint and continues from the pause.
        state, events = asyncio.run(drive(
            graph,
            Command(resume={"decision": chosen, "decided_by": "analyst",
                            "note": st.session_state.get("gate_note", "")}),
            config, st.empty(), len(st.session_state.events)))
        st.session_state.state = state
        st.session_state.events = events
        st.session_state.closed = True
        st.rerun()

decision = state.get("human_decision")
if decision:
    st.subheader("4 · Your decision")
    if decision.decision is Decision.APPROVED:
        st.success(f"Approved — {decision.headline()}")
    elif decision.decision is Decision.REJECTED:
        st.info(f"Rejected — {decision.headline()}")
    else:
        st.error(f"Escalated — {decision.headline()}")
    if decision.note:
        st.caption(f"Note: {decision.note}")


# =============================================================================
# LAYER 5 - THE INCIDENT REPORT
# =============================================================================

if state.get("report"):
    st.subheader("5 · The incident report")
    st.download_button("Download the report (.md)", state["report"],
                       file_name=f"incident-{alert.id}.md",
                       mime="text/markdown")
    # Collapsed while the gate is open, so the decision is not buried under
    # four thousand characters of Markdown.
    with st.expander("Read it", expanded=not pause):
        st.markdown(state["report"])

if state.get("errors"):
    st.subheader("Errors")
    for message in state["errors"]:
        st.error(message)