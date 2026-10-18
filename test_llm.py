"""
test_llm.py
===========
Runs the hunter on three real alerts and reports tokens and cost.

It also lists the models your API key can actually use, so you can confirm
the configured one exists instead of assuming it does.
"""

from core.config import LLM_MODEL, OFFLINE_MODE, OPENAI_KEY
from core.llm import PRICES_PER_MTOK, cost_usd, llm_available
from core.preprocessor import load_alerts
from tools.hunter import facts_for_prompt, gather_evidence, hunt
from tools.threat_intel import count_local_hits

print("=" * 74)
print("CONFIGURATION")
print("=" * 74)
print(f"  OpenAI key    : {'present' if OPENAI_KEY else 'NOT SET'}")
print(f"  Model         : {LLM_MODEL}")
print(f"  Offline mode  : {OFFLINE_MODE}")
print(f"  LLM available : {llm_available()}")

if OPENAI_KEY:
    print()
    print("  Models your key can actually use (chat-capable):")
    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_KEY)
        names = sorted(m.id for m in client.models.list().data)
        # Keep only text/chat models; drop audio, image and embedding ones.
        interesting = [n for n in names
                       if any(k in n for k in ("gpt", "o1", "o3", "o4"))
                       and not any(k in n for k in
                                   ("audio", "tts", "transcribe", "realtime",
                                    "image", "embedding", "moderation", "dall"))]
        for name in interesting[:25]:
            marker = " <-- configured" if name == LLM_MODEL else ""
            print(f"      {name}{marker}")
        if LLM_MODEL not in names:
            print()
            print(f"  WARNING: '{LLM_MODEL}' is not in your account's list.")
            print("  Set SOC_LLM_MODEL in .env to one of the names above.")
    except Exception as error:
        print(f"      could not list models: {type(error).__name__}: {error}")

alerts = load_alerts()
hits = count_local_hits(alerts)


def pick(predicate):
    """Find the first alert matching a condition, busiest attacker first."""
    for alert in sorted(alerts, key=lambda a: -hits.get(a.src_ip or "", 0)):
        if predicate(alert):
            return alert
    return None


chosen = [
    pick(lambda a: hits.get(a.src_ip or "", 0) > 50),
    pick(lambda a: "Web server" in a.rule_description),
    pick(lambda a: "session" in a.rule_description.lower()),
]
chosen = [a for a in chosen if a is not None]

total_cost = 0.0
total_tokens = 0

for alert in chosen:
    local = hits.get(alert.src_ip or "", 0)
    print()
    print("=" * 74)
    print(f"ALERT {alert.id}  |  {alert.rule_description[:46]}")
    print("=" * 74)

    evidence = gather_evidence(alert, local_hits=local)
    print("--- FACTS GATHERED BY TOOLS (this is what the LLM is given) ---")
    print(facts_for_prompt(alert, evidence))

    result, meta = hunt(alert, local_hits=local)
    print()
    print("--- SYNTHESIS ---")
    print(f"  LLM used     : {meta['llm_used']}")
    if meta["fallback_reason"]:
        print(f"  Fallback     : {meta['fallback_reason'][:66]}")
    if meta["usage"]:
        usage = meta["usage"]
        run_cost = cost_usd(usage["model"], usage["input_tokens"],
                            usage["output_tokens"])
        total_cost += run_cost
        total_tokens += usage["input_tokens"] + usage["output_tokens"]
        print(f"  Mode         : {usage['mode']}")
        print(f"  Tokens       : {usage['input_tokens']} in + "
              f"{usage['output_tokens']} out")
        print(f"  Cost         : ${run_cost:.6f}")
    print(f"  Threat score : {result.threat_score}/100")
    print(f"  Worst verdict: {result.worst_verdict.value}")
    print()
    print("  HYPOTHESIS:")
    for line in result.hypothesis.split(". "):
        if line.strip():
            print(f"    {line.strip().rstrip('.')}.")

print()
print("=" * 74)
print("COST SUMMARY")
print("=" * 74)
print(f"  Alerts analysed : {len(chosen)}")
print(f"  Total tokens    : {total_tokens}")
print(f"  Total cost      : ${total_cost:.6f}")
if chosen and total_cost:
    print(f"  Per alert       : ${total_cost/len(chosen):.6f}")
    print(f"  Per 1000 alerts : ${total_cost/len(chosen)*1000:.2f}")
print()
print("  Price table used (USD per 1M tokens, input/output):")
for name, (pin, pout) in PRICES_PER_MTOK.items():
    print(f"      {name:<14} {pin:>6.2f} / {pout:>6.2f}")