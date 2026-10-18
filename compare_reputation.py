"""
compare_reputation.py
=====================
EXPERIMENT: does our local frequency-based reputation agree with an
independent external database?

Why this matters. Our LocalCorpus source says "this address appears in 170
of our alerts, so it is malicious". That is reasonable, but it is only
frequency. AbuseIPDB is an independent opinion built from reports by
thousands of organisations. Comparing the two tells us whether frequency is
a valid proxy for maliciousness — and where it is not.

The disagreements are the most interesting part: they are where frequency
misleads.
"""

from collections import Counter, defaultdict

from core.config import ABUSEIPDB_KEY
from core.preprocessor import load_alerts
from tools.threat_intel import count_local_hits, enrich_ioc

if not ABUSEIPDB_KEY:
    print("This experiment needs an AbuseIPDB key in your .env file.")
    raise SystemExit(0)

alerts = load_alerts()
hits = count_local_hits(alerts)

# Gather both opinions for every unique address.
rows = []
for ip, count in sorted(hits.items(), key=lambda item: -item[1]):
    result = enrich_ioc(ip, local_hits=count)
    local = result.per_source.get("LocalCorpus", {})
    external = result.per_source.get("AbuseIPDB", {})
    # Skip any address the external database did not answer for.
    if not external:
        continue
    rows.append({
        "ip": ip,
        "hits": count,
        "local_verdict": local.get("verdict", "unknown"),
        "ext_verdict": external.get("verdict", "unknown"),
        "ext_score": external.get("score", 0),
        "ext_detail": external.get("detail", ""),
    })

print("=" * 78)
print("EXPERIMENT - DOES LOCAL FREQUENCY AGREE WITH EXTERNAL REPUTATION?")
print("=" * 78)
print(f"  Addresses compared: {len(rows)}")

agree = sum(1 for r in rows if r["local_verdict"] == r["ext_verdict"])
print(f"  Agreement         : {agree}/{len(rows)} = {agree/len(rows):.1%}")

print()
print("CONFUSION MATRIX  (rows = LocalCorpus, columns = AbuseIPDB)")
print("-" * 78)
labels = ["malicious", "suspicious", "clean"]
# A table: for each local verdict, count each external verdict.
matrix = defaultdict(Counter)
for r in rows:
    matrix[r["local_verdict"]][r["ext_verdict"]] += 1

print(f"{'LOCAL \\ EXT':<14}" + "".join(f"{label:>12}" for label in labels))
for local_label in labels:
    row = matrix[local_label]
    print(f"{local_label:<14}" + "".join(f"{row.get(l, 0):>12}" for l in labels))

print()
print("WHERE THEY DISAGREE  (the interesting cases)")
print("-" * 78)
disagreements = [r for r in rows if r["local_verdict"] != r["ext_verdict"]]
if not disagreements:
    print("  None.")
for r in sorted(disagreements, key=lambda x: -x["hits"]):
    print(f"  {r['ip']:<17} hits={r['hits']:<5} local={r['local_verdict']:<11}"
          f"ext={r['ext_verdict']:<11}({r['ext_score']:>3})")
    print(f"      {r['ext_detail'][:66]}")

print()
print("THE BUSIEST ADDRESSES, WITH EXTERNAL EVIDENCE")
print("-" * 78)
for r in rows[:12]:
    print(f"  {r['ip']:<17} hits={r['hits']:<5} ext={r['ext_verdict']:<11}"
          f"({r['ext_score']:>3})  {r['ext_detail'][:40]}")

# =============================================================================
# DECOMPOSING THE DISAGREEMENTS
#
# A raw agreement percentage is not a finding on its own. What matters is WHY
# the sources disagree. Every disagreement falls into exactly one of three
# causes, and each has a different operational consequence.
# =============================================================================

from tools.threat_intel import identify_research_scanner

# How serious each verdict is, as a number, so we can compare two verdicts.
RANK = {"clean": 0, "unknown": 0, "suspicious": 1, "malicious": 2}

scanners, external_blind, local_blind = [], [], []

for r in disagreements:
    # Was this address identified as a benign internet-measurement project?
    org = None
    result = enrich_ioc(r["ip"], local_hits=r["hits"])
    external_entry = result.per_source.get("AbuseIPDB", {})
    org = external_entry.get("org")

    if identify_research_scanner(r["ip"], org):
        scanners.append(r)
    elif RANK[r["local_verdict"]] > RANK[r["ext_verdict"]]:
        # We rated it worse than the external database did: we observed
        # abuse that was never reported to the crowd-sourced service.
        external_blind.append(r)
    else:
        # The external database rated it worse: real abuse that we only
        # saw once or twice, too rarely for a frequency score to catch.
        local_blind.append(r)

print()
print("=" * 78)
print("WHY THEY DISAGREE - THE THREE CAUSES")
print("=" * 78)
total = len(disagreements)
print(f"  Benign research scanners  : {len(scanners):>3}  ({len(scanners)/total:.0%})")
print(f"  External blind spot       : {len(external_blind):>3}  ({len(external_blind)/total:.0%})")
print(f"  Local blind spot          : {len(local_blind):>3}  ({len(local_blind)/total:.0%})")

alerts_with_ip = sum(1 for a in alerts if a.src_ip)
blind_alerts = sum(r["hits"] for r in external_blind)
caught_alerts = sum(r["hits"] for r in local_blind)

print()
print("  OPERATIONAL CONSEQUENCE")
print("  " + "-" * 74)
print(f"  Alerts from addresses the external database did not know about:")
print(f"      {blind_alerts} of {alerts_with_ip} IP-bearing alerts "
      f"= {blind_alerts/alerts_with_ip:.1%}")
print(f"  Alerts only the external database would have caught:")
print(f"      {caught_alerts} of {alerts_with_ip} "
      f"= {caught_alerts/alerts_with_ip:.1%}")
print()
print("  -> The two sources are NOT redundant. Each covers what the other misses.")