from __future__ import annotations
from pydantic import BaseModel, Field
from core.contracts import (AttackType, HuntResult, IOCEnrichment,
                            MitreTechnique, Verdict)
from core.llm import LLMUnavailable, llm_available, structured_call
from core.models import Alert
from tools.mitre import map_to_mitre
from tools.severity import assign_severity
from tools.threat_intel import enrich_ioc

SYSTEM_PROMPT = (
    "You are a Tier 1 SOC analyst. You are given VERIFIED FACTS about one "
    "security alert, already gathered by deterministic tools. Your only job "
    "is to write a short analytical hypothesis and a threat score.\n\n"
    "Rules you must follow:\n"
    "- Use ONLY the facts provided. Invent nothing.\n"
    "- Never claim an IP is malicious unless a verdict says so.\n"
    "- If the facts are thin, say so plainly and score low.\n"
    "- The hypothesis must be 2 to 4 sentences, written for a human analyst.\n"
    "- threat_score is 0-100 and must be consistent with the facts."
)


class HuntSynthesis(BaseModel):
    hypothesis: str = Field(min_length=40, max_length=1200)
    threat_score: int = Field(ge=0, le=100)


def gather_evidence(alert: Alert, local_hits: int = 0) -> dict:
    triage = assign_severity(alert)
    techniques = map_to_mitre(alert, triage.attack_type)
    iocs: list[IOCEnrichment] = []
    if alert.src_ip:
        iocs.append(enrich_ioc(alert.src_ip, local_hits=local_hits))
    if alert.dst_ip and alert.dst_ip != alert.src_ip:
        iocs.append(enrich_ioc(alert.dst_ip))
    return {"triage": triage, "techniques": techniques, "iocs": iocs}


def facts_for_prompt(alert: Alert, evidence: dict) -> str:
    triage = evidence["triage"]
    lines = [
        "ALERT",
        f"  id            : {alert.id}",
        f"  time          : {alert.timestamp.isoformat()}",
        f"  host          : {alert.agent_name}",
        f"  wazuh rule    : {alert.rule_id} at level {alert.rule_level}/15",
        f"  description   : {alert.rule_description}",
        f"  source ip     : {alert.src_ip or 'none recorded'}",
        f"  user          : {alert.user or 'none recorded'}",
        "",
        "DETERMINISTIC TRIAGE",
        f"  attack type   : {triage.attack_type.value}",
        f"  severity      : {triage.severity.value} (score {triage.score}/100)",
        f"  signals       : {', '.join(triage.matched_signals)}",
        "",
        "MITRE ATT&CK",
    ]
    if evidence["techniques"]:
        for technique in evidence["techniques"]:
            lines.append(f"  {technique.technique_id} {technique.name} "
                         f"({technique.tactic})")
    else:
        lines.append("  none mapped")

    lines += ["", "INDICATOR REPUTATION"]
    if evidence["iocs"]:
        for ioc in evidence["iocs"]:
            lines.append(f"  {ioc.indicator}: verdict={ioc.verdict.value} "
                         f"confidence={ioc.abuse_confidence} "
                         f"sources={','.join(ioc.sources) or 'none'}")
            if ioc.detail:
                lines.append(f"      {ioc.detail}")
    else:
        lines.append("  no indicators to check")

    if alert.full_log:
        lines += ["", "RAW LOG", f"  {alert.full_log[:300]}"]
    return "\n".join(lines)


def deterministic_synthesis(alert: Alert, evidence: dict) -> HuntSynthesis:
    triage = evidence["triage"]
    iocs = evidence["iocs"]
    worst = Verdict.UNKNOWN
    for level in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.CLEAN):
        if any(i.verdict == level for i in iocs):
            worst = level
            break

    score = triage.score
    if worst is Verdict.MALICIOUS:
        score = min(100, score + 20)
    elif worst is Verdict.SUSPICIOUS:
        score = min(100, score + 10)
    if triage.attack_type in (AttackType.NORMAL_ACTIVITY, AttackType.VULNERABILITY):
        score = min(score, 15)

    technique_text = (", ".join(t.technique_id for t in evidence["techniques"])
                      or "no mapped technique")
    ioc_text = (f"source {iocs[0].indicator} rated {worst.value}"
                if iocs else "no indicator available")

    hypothesis = (
        f"Wazuh rule {alert.rule_id} fired on {alert.agent_name} and was "
        f"classified deterministically as {triage.attack_type.value} at "
        f"{triage.severity.value} severity. Mapped to {technique_text}. "
        f"Indicator reputation reports {ioc_text}. "
        f"Generated without a language model; this is a rule-based summary "
        f"of the gathered facts."
    )
    return HuntSynthesis(hypothesis=hypothesis, threat_score=score)


def hunt(alert: Alert, local_hits: int = 0) -> tuple[HuntResult, dict]:
    evidence = gather_evidence(alert, local_hits=local_hits)
    meta: dict = {"llm_used": False, "usage": None, "fallback_reason": None}

    if llm_available():
        try:
            synthesis, usage = structured_call(
                HuntSynthesis, SYSTEM_PROMPT, facts_for_prompt(alert, evidence))
            meta["llm_used"] = True
            meta["usage"] = usage
        except LLMUnavailable as error:
            synthesis = deterministic_synthesis(alert, evidence)
            meta["fallback_reason"] = str(error)[:300]
        except Exception as error:
            synthesis = deterministic_synthesis(alert, evidence)
            meta["fallback_reason"] = (
                f"Unexpected {type(error).__name__}: {str(error)[:250]}")
    else:
        synthesis = deterministic_synthesis(alert, evidence)
        meta["fallback_reason"] = "No API key, or offline mode is on."

    result = HuntResult(
        iocs=evidence["iocs"],
        techniques=evidence["techniques"],
        similar_alerts=[],
        hypothesis=synthesis.hypothesis,
        threat_score=synthesis.threat_score,
    )
    return result, meta