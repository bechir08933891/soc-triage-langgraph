"""
core/preprocessor.py
====================
Turn the real Wazuh dataset into validated Alert objects.

Real data is messy. The same idea appears as `rule.level`, `rule_level` or
`level` depending on who exported it. IP addresses arrive as "-". Some
records are wrapped inside other records.

All of that mess is handled HERE, at the entrance. Everything downstream can
then assume it is holding a clean, validated Alert.

About this dataset specifically: it is published as an AI TRAINING file, so
each row looks like this:

    {
      "instruction": "Classify the following Wazuh alert...",
      "input":       "{ ...the real alert, as JSON TEXT... }",
      "output":      "True Positive"
    }

The alert we want is hidden inside `input` as a string. We unwrap it, and we
keep `output` as `_label`, because that label is a ground truth we will use
later to measure how accurate our agent really is.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable

from pydantic import ValidationError

from core.models import Alert

# A logger lets us record warnings without printing noise into the demo.
logger = logging.getLogger(__name__)


# The single source file of the dataset, straight from Hugging Face.
# "resolve/main/" is the part of the address that serves the raw file.
DATASET_URL = (
    "https://huggingface.co/datasets/kholil-lil/wazuh-alerts/"
    "resolve/main/wazuh_formatted_alerts.json"
)

# Where it will live on your computer.
# `Path(__file__)` is this file. `.resolve()` makes it a full address.
# `.parent.parent` goes up twice: core/ -> the project folder.
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
    """Download the complete dataset file, showing progress.

    `force=False` means: if the file is already here, do not download again.
    """
    import httpx  # imported here so the rest of the file works without network

    # `parents=True` creates the data folder if it is missing.
    # `exist_ok=True` means "do not complain if it already exists".
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists() and not force:
        size_mb = destination.stat().st_size / 1_000_000
        print(f"Already downloaded: {destination.name} ({size_mb:.2f} MB)")
        return destination

    print(f"Downloading {url}")

    # `stream` downloads in small pieces instead of loading everything into
    # memory at once. That matters on a machine with 8 GB of RAM.
    with httpx.stream("GET", url, follow_redirects=True, timeout=120) as response:
        # Raises an error if the server answered with a failure code.
        response.raise_for_status()

        # The server usually tells us the total size, so we can show a percentage.
        total = int(response.headers.get("content-length", 0))
        done = 0

        # `"wb"` means "write, binary" — we write raw bytes, not text.
        with destination.open("wb") as handle:
            for chunk in response.iter_bytes(chunk_size=65536):
                handle.write(chunk)
                done += len(chunk)
                # `\r` returns to the start of the line, so the progress
                # updates in place instead of printing hundreds of lines.
                if total:
                    print(
                        f"\r  {done/1_000_000:6.2f} / {total/1_000_000:6.2f} MB "
                        f"({done*100//total:3d}%)",
                        end="",
                    )
                else:
                    print(f"\r  {done/1_000_000:6.2f} MB", end="")

    print(f"\nSaved to {destination}")
    return destination


# =============================================================================
# READING THE FILE
# =============================================================================


def _read_json_file(path: Path) -> Any:
    """Read the file, accepting either real JSON or JSON-lines.

    JSON        : one big [ ... ] or { ... } covering the whole file
    JSON-lines  : one complete JSON object per line
    Both appear in the wild, so we accept both.
    """
    text = path.read_text(encoding="utf-8").strip()

    if text.startswith("[") or text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # It looked like JSON but was not. Fall through to JSON-lines.
            pass

    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _unwrap_record(record: dict) -> dict | None:
    """Find the real alert inside a training-format record.

    Returns the alert dictionary, or None if this record holds no alert.
    """
    # The alert may hide under any of these keys, as text or as an object.
    for key in ("input", "alert", "text"):
        value = record.get(key)

        # Case 1: the alert is JSON stored as TEXT (this dataset's case).
        if isinstance(value, str) and value.strip().startswith("{"):
            try:
                inner = json.loads(value)
            except json.JSONDecodeError:
                continue
            if isinstance(inner, dict):
                # Keep the ground-truth label. We will measure against it later.
                # The underscore marks it as something WE added, not Wazuh.
                if "output" in record:
                    inner["_label"] = record["output"]
                if "instruction" in record:
                    inner["_instruction"] = record["instruction"]
                return inner

        # Case 2: the alert is already a real object.
        if isinstance(value, dict):
            if "output" in record:
                value["_label"] = record["output"]
            return value

    # Case 3: the record IS the alert, with nothing wrapped around it.
    if "rule" in record or "rule_level" in record or "rule_id" in record:
        return record

    return None


def load_raw_records(path: Path = DATASET_FILE) -> list[dict]:
    """Open the dataset file and return a flat list of raw alert dictionaries."""
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {path}. Run download_data.py first."
        )

    payload = _read_json_file(path)

    # Some files wrap the list inside an object, e.g. {"data": [ ... ]}.
    if isinstance(payload, dict):
        for key in ("data", "alerts", "records", "rows", "train"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            # `else` on a `for` loop runs only if we never hit `break`.
            # So: no known key found, treat the object itself as one record.
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


def _dig(raw: dict, *candidates: str, default: Any = None) -> Any:
    """Return the first value found among several dotted-path candidates.

    `_dig(raw, "rule.level", "rule_level", "level")` tries three spellings
    and returns the first that exists. This is what lets one function handle
    every export format without a pile of if-statements.
    """
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
    """Turn a value into a whole number, or use the default if impossible."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def normalize_wazuh_alert(raw: dict, fallback_id: str | None = None) -> Alert:
    """Turn one raw record into a validated Alert.

    Raises ValidationError if the record cannot be made valid. The caller
    decides whether to skip it. Silently inventing values would poison the
    audit trail, so we never do that.
    """
    level = _as_int(_dig(raw, "rule.level", "rule_level", "level"), default=0)
    # Wazuh guarantees 0-15. We clamp, so hostile or broken input cannot
    # crash the pipeline further down.
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
        agent_name=str(
            _dig(raw, "agent.name", "agent_name", "host", default="unknown-host")
        ),
        agent_id=str(_dig(raw, "agent.id", "agent_id", default="000")),
        src_ip=_dig(raw, "data.srcip", "srcip", "src_ip", "source_ip"),
        dst_ip=_dig(raw, "data.dstip", "dstip", "dst_ip"),
        # This dataset uses `srcuser`; other exports use `dstuser`. Try both.
        user=_dig(raw, "data.srcuser", "data.dstuser", "data.user",
                  "srcuser", "dstuser", "user"),
        full_log=_dig(raw, "full_log", "log", "message"),
        raw=raw,
    )


def normalize_many(records: Iterable[dict]) -> tuple[list[Alert], list[str]]:
    """Normalise a batch. Returns (the good alerts, notes about the bad ones).

    We never throw away a failure silently. Returning the problems means you
    can report honestly: "2,847 of 2,851 records loaded; 4 were malformed."
    """
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
    # Sort by time, because the forensics agent later needs a real timeline.
    alerts.sort(key=lambda alert: alert.timestamp)
    return alerts[:limit] if limit else alerts