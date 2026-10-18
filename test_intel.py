"""
test_intel.py
=============
Runs both hunter tools across the whole corpus and reports the coverage.
"""

from collections import Counter

from core.config import ABUSEIPDB_KEY, OFFLINE_MODE, VIRUSTOTAL_KEY
from core.preprocessor import load_alerts
from tools.mitre import map_to_mitre
from tools.severity import assign_severity
from tools.threat_intel import cache_stats, clear_cache, count_local_hits, enrich_ioc

print("=" * 72)
print("CONFIGURATION")
print("=" * 72)
print(f"  AbuseIPDB key  : {'present' if ABUSEIPDB_KEY else 'NOT SET'}")
print(f"  VirusTotal key : {'present' if VIRUSTOTAL_KEY else 'NOT SET'}")
print(f"  Offline mode   : {OFFLINE_MODE}")
if not ABUSEIPDB_KEY and not VIRUSTOTAL_KEY:
    print("  -> No external keys. The local corpus reputation will be used.")

alerts = load_alerts()

print()
print("=" * 72)
print("PART 1 - HOW MANY UNIQUE IP ADDRESSES ARE THERE?")
print("=" * 72)
hits = count_local_hits(alerts)
with_ip = sum(1 for a in alerts if a.src_ip)
print(f"  Alerts with an IP : {with_ip}")
print(f"  UNIQUE IPs        : {len(hits)}")
if hits:
    saving = 1 - len(hits) / with_ip
    print(f"  Lookups saved by caching: {saving:.1%}")

print()
print("  The busiest addresses:")
for ip, count in sorted(hits.items(), key=lambda item: -item[1])[:8]:
    print(f"    {ip:<18} {count:>5} alerts")

print()
print("=" * 72)
print("PART 2 - ENRICHING EVERY UNIQUE IP")
print("=" * 72)
clear_cache()
print(f"{'IP':<18}{'VERDICT':<12}{'CONF':>6}  SOURCES")
print("-" * 72)
for ip, count in sorted(hits.items(), key=lambda item: -item[1]):
    result = enrich_ioc(ip, local_hits=count)
    print(f"{ip:<18}{result.verdict.value:<12}{result.abuse_confidence:>6}  "
          f"{', '.join(result.sources) or '-'}")
print()
print(f"  Cache after the run: {cache_stats()}")

print()
print("=" * 72)
print("PART 3 - MITRE ATT&CK COVERAGE ACROSS THE WHOLE CORPUS")
print("=" * 72)
techniques = Counter()
tactics = Counter()
for alert in alerts:
    triage = assign_severity(alert)
    for technique in map_to_mitre(alert, triage.attack_type):
        techniques[technique.headline()] += 1
        tactics[technique.tactic] += 1

print(f"{'COUNT':>7}  TECHNIQUE")
print("-" * 72)
for name, count in techniques.most_common():
    print(f"{count:>7}  {name}")

print()
print(f"{'COUNT':>7}  TACTIC")
print("-" * 72)
for name, count in tactics.most_common():
    print(f"{count:>7}  {name}")

unmapped = sum(1 for a in alerts if not map_to_mitre(a, assign_severity(a).attack_type))
print()
print(f"  Alerts with NO technique mapped: {unmapped} / {len(alerts)} "
      f"({unmapped/len(alerts):.1%})")