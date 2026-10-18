"""
core/preprocessor.py
====================
Turn the real Wazuh dataset into validated Alert objects.

Two layers of wrapping have to be removed before we see a real alert:

  LAYER 1 - the training format
      {"instruction": "...", "input": "<the alert as JSON TEXT>", "output": "True Positive"}

  LAYER 2 - the active-response wrapper (63% of this dataset!)
      When Wazuh's firewall blocks an attacker, it writes a NEW alert about
      its own action. The alert that CAUSED the block is buried at
          data -> parameters -> alert
      That inner alert holds the real host name, the real attacker IP and
      the real description. The outer record is just bookkeeping.

We unwrap both, and we record that we did, so nothing is hidden.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Iterable

from pydantic import ValidationError

from core.models import Alert

logger = logging.getLogger(__name__)

DATASET_URL = (
    "https://huggingface.co/datasets/kholil-lil/wazuh-alerts/"
    "resolve/main/wazuh_formatted_alerts.json"
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATASET_FILE = DATA_DIR / "wazuh_formatted_alerts.json"


# =============================================================================
# DOWNLOADING
# =============================================================================


def download_dataset(
    url: str = DATASET_URL,
    destination: Path = DATASET_FILE,
    force: bool = False,
) -> Path:
    """Download the complete dataset file, showing progress."""
    import httpx

    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists() and not force:
        size_mb = destination.stat().st_size / 1_000_000
        print(f"Already downloaded: {destination.name} ({size_mb:.2f} MB)")
        return destination

    print(f"Downloading {url}")
    with httpx.stream("GET", url, follow_redirects=True, timeout=120) as response:
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0))
        done = 0
        with destination.open("wb") as handle:
            for chunk in response.iter_bytes(chunk_size=65536):
                handle.write(chunk)
                done += len(chunk)
                if total:
                    print(f"\r  {done/1_000_000:6.2f} / {total/1_000_000:6.2f} MB "
                          f"({done*100//total:3d}%)", end="")
                else:
                    print(f"\r  {done/1_000_000:6.2f} MB", end="")
    print(f"\nSaved to {destination}")
    return destination


# =============================================================================
# READING THE FILE
# =============================================================================


def _read_json_file(path: Path) -> Any:
    """Read the file, accepting either real JSON or JSON-lines."""
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("[") or text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    return [json.loads(line) for line in text.splitlines() if line.strip()]


# =============================================================================
# LAYER 2 - THE ACTIVE-RESPONSE WRAPPER
# =============================================================================


def _extract_trigger(alert: dict) -> dict | None:
    """Return the alert hidden inside an active-response record, or None.

    The path is data -> parameters -> alert. We check each step is really a
    dictionary before going deeper, because real data is unreliable and a
    missing key would otherwise crash the whole load.
    """
    data = alert.get("data")
    if not isinstance(data, dict):
        return None

    parameters = data.get("parameters")
    if not isinstance(parameters, dict):
        return None

    inner = parameters.get("alert")
    return inner if isinstance(inner, dict) else None


def _enrich_with_trigger(alert: dict) -> dict:
    """Copy the real evidence out of a nested trigger alert into the wrapper.

    We do NOT replace the outer alert. Wazuh really did produce it, and
    deleting it would falsify the record. Instead we ATTACH what we found,
    under names starting with an underscore so it is obvious these came from
    us and not from the SIEM.

    What this recovers: the outer record says host "xxx" (anonymised). The
    inner one says "prod-server" with IP 103.129.149.63. Real evidence.
    """
    trigger = _extract_trigger(alert)
    if trigger is None:
        return alert

    trigger_rule = trigger.get("rule", {})
    trigger_agent = trigger.get("agent", {})
    trigger_data = trigger.get("data", {})

    alert["_trigger_description"] = trigger_rule.get("description")
    alert["_trigger_level"] = trigger_rule.get("level")
    alert["_trigger_rule_id"] = trigger_rule.get("id")
    alert["_trigger_groups"] = trigger_rule.get("groups", [])
    alert["_trigger_host"] = trigger_agent.get("name")
    alert["_trigger_srcip"] = (
        trigger_data.get("srcip") if isinstance(trigger_data, dict) else None
    )
    alert["_trigger_full_log"] = trigger.get("full_log")

    # "add" means the firewall blocked the attacker.
    # "delete" means the block was lifted afterwards.
    data = alert.get("data")
    if isinstance(data, dict):
        alert["_response_command"] = data.get("command")

    return alert


# =============================================================================
# LAYER 1 - THE TRAINING FORMAT
# =============================================================================


def _unwrap_record(record: dict) -> dict | None:
    """Find the real alert inside a training-format record."""
    for key in ("input", "alert", "text"):
        value = record.get(key)

        # Case 1: the alert is JSON stored as TEXT (this dataset's case).
        if isinstance(value, str) and value.strip().startswith("{"):
            try:
                inner = json.loads(value)
            except json.JSONDecodeError:
                continue
            if isinstance(inner, dict):
                if "output" in record:
                    inner["_label"] = record["output"]
                if "instruction" in record:
                    inner["_instruction"] = record["instruction"]
                return _enrich_with_trigger(inner)

        # Case 2: the alert is already a real object.
        if isinstance(value, dict):
            if "output" in record:
                value["_label"] = record["output"]
            return _enrich_with_trigger(value)

    # Case 3: the record IS the alert, with nothing wrapped around it.
    if "rule" in record or "rule_level" in record or "rule_id" in record:
        return _enrich_with_trigger(record)

    return None


def load_raw_records(path: Path = DATASET_FILE) -> list[dict]:
    """Open the dataset file and return a flat list of raw alert dictionaries."""
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {path}. Run download_data.py first."
        )

    payload = _read_json_file(path)

    if isinstance(payload, dict):
        for key in ("data", "alerts", "records", "rows", "train"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            payload = [payload]

    records: list[dict] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        unwrapped = _unwrap_record(item)
        if unwrapped is not None:
            records.append(unwrapped)
    return records


# =============================================================================
# NORMALISING INTO Alert OBJECTS
# =============================================================================

# Syslog lines start "Mon DD HH:MM:SS hostname process[pid]: message".
# Reading the pattern piece by piece:
#   ^[A-Z][a-z]{2}   a three-letter month, e.g. Mar
#   \s+\d{1,2}       the day
#   \s+\d{2}:\d{2}:\d{2}   the clock time
#   \s+(\S+)\s       <- the hostname we want, captured in group 1
SYSLOG_HOST = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s")

# Values that LOOK like a host name but carry no information. The published
# dataset anonymises agent.name to "xxx", so treating it as a real host
# would make every machine appear to be the same machine.
PLACEHOLDER_HOSTS = {"xxx", "unknown", "unknown-host", "-", ""}


def _host_from_syslog(full_log: Any) -> str | None:
    """Recover the host name from a syslog-format log line.

    Why this matters: agent.name is anonymised in this dataset, but the raw
    log line keeps the real host. Without it, lateral-movement detection has
    nothing to compare, because every host is called "xxx".

    Web access logs (nginx, Apache) have no host field, so they return None.
    """
    if not isinstance(full_log, str):
        return None
    match = SYSLOG_HOST.match(full_log)
    return match.group(1) if match else None


def _clean_host(value: Any) -> str | None:
    """Return a usable host name, or None if it is a placeholder."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in PLACEHOLDER_HOSTS else text




def _dig(raw: dict, *candidates: str, default: Any = None) -> Any:
    """Return the first value found among several dotted-path candidates."""
    for path in candidates:
        cursor: Any = raw
        for part in path.split("."):
            cursor = cursor.get(part) if isinstance(cursor, dict) else None
            if cursor is None:
                break
        if cursor not in (None, "", []):
            return cursor
    return default



def _as_int(value: Any, default: int = 0) -> int:
    """Turn a value into a whole number, or use the default if impossible.

    Needed because the nested alerts store the level as TEXT ("5"), while
    the outer ones store it as a number (5). Both must work.
    """
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default

def _resolve_host(raw: dict) -> str:
    """Find the best available host name, treating placeholders as missing.

    Priority order, best evidence first:
      1. the host from a nested active-response alert (real, explicit)
      2. agent.name, if it is not the "xxx" placeholder
      3. the host parsed out of the syslog line
      4. give up honestly
    """
    full_log = _dig(raw, "_trigger_full_log", "full_log", "log", "message")
    candidates = (
        _clean_host(raw.get("_trigger_host")),
        _clean_host(_dig(raw, "agent.name", "agent_name", "host")),
        _clean_host(_host_from_syslog(full_log)),
    )
    for candidate in candidates:
        if candidate:
            return candidate
    return "unknown-host"


def normalize_wazuh_alert(raw: dict, fallback_id: str | None = None) -> Alert:
    """Turn one raw record into a validated Alert.

    Notice the `_trigger_*` names FIRST in three of the lookups below. That
    is the priority rule: if we recovered real evidence from a nested alert,
    prefer it over the anonymised outer value.
    """
    level = _as_int(_dig(raw, "rule.level", "rule_level", "level"), default=0)
    level = max(0, min(15, level))

    return Alert(
        id=str(_dig(raw, "id", "alert_id", "_id", default=fallback_id or "unknown")),
        timestamp=_dig(raw, "timestamp", "@timestamp", "time"),
        rule_id=str(_dig(raw, "rule.id", "rule_id", "ruleid", default="0")),
        rule_level=level,
        rule_description=str(
            _dig(raw, "rule.description", "rule_description", "description",
                 default="(no description)")
        ),
        # Prefer the REAL host name recovered from the nested alert.
        agent_name=_resolve_host(raw),
        agent_id=str(_dig(raw, "agent.id", "agent_id", default="000")),
        # Prefer the REAL attacker IP recovered from the nested alert.
        src_ip=_dig(raw, "_trigger_srcip", "data.srcip", "srcip", "src_ip",
                    "source_ip"),
        dst_ip=_dig(raw, "data.dstip", "dstip", "dst_ip"),
        user=_dig(raw, "data.srcuser", "data.dstuser", "data.user",
                  "srcuser", "dstuser", "user"),
        # Prefer the REAL log line from the nested alert.
        full_log=_dig(raw, "_trigger_full_log", "full_log", "log", "message"),
        raw=raw,
    )


def normalize_many(records: Iterable[dict]) -> tuple[list[Alert], list[str]]:
    """Normalise a batch. Returns (the good alerts, notes about the bad ones)."""
    alerts: list[Alert] = []
    skipped: list[str] = []
    for index, record in enumerate(records):
        try:
            alerts.append(
                normalize_wazuh_alert(record, fallback_id=f"alert-{index:06d}")
            )
        except ValidationError as exc:
            skipped.append(f"record {index}: {exc.error_count()} problem(s)")
    return alerts, skipped


def load_alerts(path: Path = DATASET_FILE, limit: int | None = None) -> list[Alert]:
    """The main entry point: file on disk -> list of validated Alerts."""
    alerts, skipped = normalize_many(load_raw_records(path))
    if skipped:
        logger.warning("Skipped %d malformed records", len(skipped))
    alerts.sort(key=lambda alert: alert.timestamp)
    return alerts[:limit] if limit else alerts