"""
tools/threat_intel.py
=====================
Ask what is known about an IP address.

THREE sources, merged, worst verdict wins:

  1. LocalCorpus  - how often this address appears in OUR OWN alerts.
                    Always available, needs no key, needs no network.
                    An address seen in 622 brute-force alerts is evidence.
  2. AbuseIPDB    - a public abuse database. Optional, needs a free key.
  3. VirusTotal   - a second opinion. Optional, needs a free key.

Two design rules that matter more than the code:

  CACHING. Our corpus has hundreds of alerts but only a handful of unique
  addresses. Without a cache we would ask the same question hundreds of
  times, burn the free-tier quota, and slow the demo down.

  HONESTY. With no source available we return UNKNOWN. We never report
  "clean" just because we failed to find anything out. In security, "I did
  not check" and "it is safe" are completely different statements.
"""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any

import httpx

from core.config import (
    ABUSEIPDB_KEY,
    DATA_DIR,
    INTEL_CACHE_FILE,
    INTEL_TIMEOUT_S,
    OFFLINE_MODE,
    VIRUSTOTAL_KEY,
)
from core.contracts import IOCEnrichment, Verdict


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Where we draw the lines between verdicts. At the top of the file, so a
# jury can see the policy without reading the logic.
MALICIOUS_THRESHOLD = 75    # confidence 75-100 -> malicious
SUSPICIOUS_THRESHOLD = 25   # confidence 25-74  -> suspicious
#                             confidence  0-24  -> clean

# How many appearances in our own corpus make an address notable.
LOCAL_SUSPICIOUS_HITS = 5
LOCAL_MALICIOUS_HITS = 50


# =============================================================================
# THE CACHE
#
# A module-level dictionary, saved to a file so it survives restarts.
# `_cache` with a leading underscore means "internal, do not touch from
# outside this file" — a Python convention, not a rule.
# =============================================================================

_cache: dict[str, dict[str, Any]] = {}
_cache_loaded = False


def _load_cache() -> None:
    """Read the cache file once, the first time anything needs it."""
    # `global` lets this function change a variable that lives outside it.
    global _cache_loaded
    if _cache_loaded:
        return
    _cache_loaded = True

    if INTEL_CACHE_FILE.exists():
        try:
            _cache.update(json.loads(INTEL_CACHE_FILE.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            # A corrupt cache must never stop the program. We simply start
            # with an empty one.
            pass


def _save_cache() -> None:
    """Write the cache to disk, ignoring failures."""
    try:
        INTEL_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        INTEL_CACHE_FILE.write_text(json.dumps(_cache, indent=2), encoding="utf-8")
    except OSError:
        pass


def cache_stats() -> dict[str, int]:
    """How many answers we are remembering. Shown in your metrics later."""
    _load_cache()
    return {"entries": len(_cache)}


def clear_cache() -> None:
    """Forget everything. Useful when testing."""
    _cache.clear()
    if INTEL_CACHE_FILE.exists():
        INTEL_CACHE_FILE.unlink()


# =============================================================================
# SMALL HELPERS
# =============================================================================


def _score_to_verdict(score: int) -> Verdict:
    """Turn a 0-100 confidence number into one of our verdict words."""
    if score >= MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def _worst(verdicts: list[Verdict]) -> Verdict:
    """The most serious verdict in a list.

    If one source says malicious and two say clean, the answer is malicious.
    In security you act on the worst credible finding, not on the average.
    """
    for level in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.CLEAN):
        if level in verdicts:
            return level
    return Verdict.UNKNOWN


# =============================================================================
# SOURCE 1 - ABUSEIPDB (optional)
# =============================================================================


def _query_abuseipdb(ip: str) -> dict[str, Any] | None:
    """Ask AbuseIPDB about an address. Returns None if unavailable."""
    if not ABUSEIPDB_KEY or OFFLINE_MODE:
        return None

    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    # Try up to 3 times. Free APIs fail occasionally, and one hiccup should
    # not cost us the enrichment.
    for attempt in range(3):
        try:
            response = httpx.get(ABUSEIPDB_URL, headers=headers, params=params,
                                 timeout=INTEL_TIMEOUT_S)

            # 429 means "too many requests". We wait and try again.
            # `2 ** attempt` gives 1, 2, 4 seconds — "exponential backoff",
            # the standard polite way to retry.
            if response.status_code == 429:
                time.sleep(2 ** attempt)
                continue

            response.raise_for_status()
            data = response.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            return {
                "source": "AbuseIPDB",
                "score": score,
                "country": data.get("countryCode"),
                "verdict": _score_to_verdict(score),
                "detail": (f"{data.get('totalReports', 0)} reports, "
                           f"ISP {data.get('isp', 'unknown')}"),
            }
        except (httpx.HTTPError, ValueError, KeyError):
            if attempt == 2:
                return None
            time.sleep(2 ** attempt)
    return None


# =============================================================================
# SOURCE 2 - VIRUSTOTAL (optional)
# =============================================================================


def _query_virustotal(ip: str) -> dict[str, Any] | None:
    """Ask VirusTotal about an address. Returns None if unavailable."""
    if not VIRUSTOTAL_KEY or OFFLINE_MODE:
        return None

    headers = {"x-apikey": VIRUSTOTAL_KEY}
    try:
        response = httpx.get(VIRUSTOTAL_URL.format(ip=ip), headers=headers,
                             timeout=INTEL_TIMEOUT_S)
        response.raise_for_status()

        # VirusTotal reports how many antivirus engines flagged the address.
        # We turn that into a percentage so it is comparable with AbuseIPDB.
        stats = (response.json().get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        # `or 1` avoids dividing by zero if the stats are empty.
        total = sum(int(v) for v in stats.values()) or 1
        score = round((malicious + suspicious) / total * 100)

        return {
            "source": "VirusTotal",
            "score": score,
            "verdict": _score_to_verdict(score),
            "detail": f"{malicious} malicious / {total} engines",
        }
    except (httpx.HTTPError, ValueError, KeyError):
        return None


# =============================================================================
# SOURCE 3 - OUR OWN CORPUS (always available)
# =============================================================================


def _local_reputation(ip: str, hits: int) -> dict[str, Any] | None:
    """Reputation derived from how often this address appears in OUR alerts.

    This is the source that makes the system work with no keys and no
    network. It is also genuinely defensible: an address responsible for 622
    brute-force alerts in your own logs is not a neutral address, whatever
    any external database says.

    We label it "LocalCorpus" so nobody can mistake it for external intel.
    """
    if hits <= 0:
        return None

    if hits >= LOCAL_MALICIOUS_HITS:
        verdict, score = Verdict.MALICIOUS, 90
    elif hits >= LOCAL_SUSPICIOUS_HITS:
        verdict, score = Verdict.SUSPICIOUS, 50
    else:
        verdict, score = Verdict.CLEAN, 5

    return {
        "source": "LocalCorpus",
        "score": score,
        "verdict": verdict,
        "detail": f"{hits} alert(s) from this address in our own corpus",
    }


# =============================================================================
# THE PUBLIC FUNCTION
# =============================================================================


def enrich_ioc(ip: str, local_hits: int = 0, use_cache: bool = True) -> IOCEnrichment:
    """Everything we can find out about one IP address."""
    _load_cache()

    # --- Guard 1: is it even an IP address? ---------------------------------
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return IOCEnrichment(indicator=ip, verdict=Verdict.UNKNOWN,
                             detail="Not a valid IP address.")

    # --- Guard 2: internal addresses need no external lookup ----------------
    # 10.0.1.21 is inside the company. No public database will know it, so
    # asking would waste a request from our daily quota.
    if parsed.is_private or parsed.is_loopback:
        return IOCEnrichment(
            indicator=ip, verdict=Verdict.CLEAN, sources=["internal"],
            detail="Internal address; no external reputation applies.",
        )

    # --- The cache ----------------------------------------------------------
    # The key includes the hit count, so a changed local reputation is not
    # served from a stale entry.
    cache_key = f"{ip}|{local_hits}"
    if use_cache and cache_key in _cache:
        cached = dict(_cache[cache_key])
        # Add "cache" to the sources, so the audit trail shows we did not
        # make a fresh call. Honesty about provenance.
        cached["sources"] = cached.get("sources", []) + ["cache"]
        return IOCEnrichment(**cached)

    # --- Ask every source ---------------------------------------------------
    # The `if f` at the end drops any source that returned None.
    findings = [
        f for f in (
            _local_reputation(ip, local_hits),
            _query_abuseipdb(ip),
            _query_virustotal(ip),
        ) if f
    ]

    if not findings:
        result = IOCEnrichment(indicator=ip, verdict=Verdict.UNKNOWN,
                               detail="No intelligence source available.")
    else:
        result = IOCEnrichment(
            indicator=ip,
            verdict=_worst([f["verdict"] for f in findings]),
            abuse_confidence=max(f["score"] for f in findings),
            # `next(... , None)` takes the first country found, or None.
            country=next((f["country"] for f in findings if f.get("country")), None),
            sources=[f["source"] for f in findings],
            detail=" | ".join(f"{f['source']}: {f['detail']}" for f in findings),
            # Keep every source's own answer, unmerged. This is what makes
            # the comparison experiment possible.
            per_source={
                f["source"]: {
                    "verdict": f["verdict"].value,
                    "score": f["score"],
                    "detail": f["detail"],
                }
                for f in findings
            },
        )

    if use_cache:
        # `mode="json"` converts Enums into plain text so they can be saved.
        _cache[cache_key] = result.model_dump(mode="json")
        _save_cache()

    return result


def count_local_hits(alerts: list) -> dict[str, int]:
    """Count how many alerts came from each IP address.

    Call this once over the whole corpus, then pass the count for one address
    into `enrich_ioc`. That is how the local reputation is built.
    """
    counts: dict[str, int] = {}
    for alert in alerts:
        if alert.src_ip:
            counts[alert.src_ip] = counts.get(alert.src_ip, 0) + 1
    return counts