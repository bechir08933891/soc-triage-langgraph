"""
tools/history.py
================
The alert history, as a queryable SQLite database.

Why a database and not the JSON file we already load? Three reasons:

  1. The forensics agent asks RANGE questions — "what happened within 60
     minutes of this?" — which a database answers with an index and a flat
     file answers by scanning everything.
  2. It is what a real SOC does. An analyst queries a datastore.
  3. Each query is a visible tool call in the audit trail, which is how the
     demonstration proves the forensics claims rather than asserting them.

The file is rebuilt from the corpus and is git-ignored. Nothing is lost if
it is deleted.
"""

from __future__ import annotations

import sqlite3
# `closing` guarantees the connection is closed even if an error happens.
from contextlib import closing
from pathlib import Path
from typing import Iterable

from core.config import HISTORY_DB
from core.models import Alert


# `IF NOT EXISTS` makes this safe to run repeatedly.
# The indexes are the point of using a database: without them, every
# forensics query would read all 738 rows.
SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id               TEXT PRIMARY KEY,
    timestamp        TEXT    NOT NULL,
    rule_id          TEXT,
    rule_level       INTEGER,
    rule_description TEXT,
    agent_name       TEXT,
    src_ip           TEXT,
    username         TEXT,
    full_log         TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_username  ON alerts(username);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip    ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_host      ON alerts(agent_name);
"""

# Phrases in a rule description that indicate an authentication SUCCEEDED.
# This is the difference between someone knocking and someone getting in,
# and therefore between spraying and lateral movement.
SUCCESS_MARKERS = ("authentication success", "session opened",
                   "logon success", "sudo", "accepted password")


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open the database, creating its folder if needed."""
    path = Path(path or HISTORY_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    # `row_factory` makes rows behave like dictionaries: row["agent_name"]
    # instead of row[5]. Far less error-prone.
    connection.row_factory = sqlite3.Row
    return connection


def build(alerts: Iterable[Alert], path: Path | None = None,
          rebuild: bool = True) -> int:
    """Load the corpus into the database. Returns how many rows were written."""
    path = Path(path or HISTORY_DB)
    if rebuild and path.exists():
        path.unlink()

    with closing(connect(path)) as connection:
        connection.executescript(SCHEMA)
        rows = [(a.id, a.timestamp.isoformat(), a.rule_id, a.rule_level,
                 a.rule_description, a.agent_name, a.src_ip, a.user, a.full_log)
                for a in alerts]
        # `executemany` inserts the whole batch in one transaction. Inserting
        # 738 rows one at a time would be noticeably slower.
        connection.executemany(
            "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?)", rows)
        connection.commit()
        return len(rows)


def is_built(path: Path | None = None) -> bool:
    """Does the database exist and contain our table?"""
    path = Path(path or HISTORY_DB)
    if not path.exists():
        return False
    with closing(connect(path)) as connection:
        found = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
        ).fetchone()
        return found is not None


def row_count(path: Path | None = None) -> int:
    """How many alerts are stored. Shown in the metrics later."""
    if not is_built(path):
        return 0
    with closing(connect(path)) as connection:
        return connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def alerts_near(timestamp_iso: str, window_minutes: int = 60,
                limit: int = 40, path: Path | None = None) -> list[dict]:
    """Every alert within a time window around a moment.

    Note `datetime(timestamp)` on BOTH sides of the comparison. SQLite's
    datetime() returns "2025-03-05 00:00:00" with a SPACE, while we store
    "2025-03-05T00:00:00+00:00" with a T. Comparing the raw strings silently
    returns nothing, because "T" sorts after " ". Converting both sides fixes
    it. This cost me a debugging session.
    """
    with closing(connect(path)) as connection:
        return [dict(r) for r in connection.execute(
            """
            SELECT * FROM alerts
            WHERE datetime(timestamp) BETWEEN datetime(?, ?) AND datetime(?, ?)
            ORDER BY datetime(timestamp)
            LIMIT ?
            """,
            (timestamp_iso, f"-{window_minutes} minutes",
             timestamp_iso, f"+{window_minutes} minutes", limit),
        )]


def _hosts_by(column: str, value: str, timestamp_iso: str,
              window_minutes: int, path: Path | None) -> list[dict]:
    """Hosts where `column = value` within a time window, with success counts.

    The window matters enormously. Asking "has this user ever been on two
    hosts?" across a whole corpus is almost always true and says nothing.
    Asking "within 60 minutes of this alert" is a question about one incident.

    `SUM(CASE WHEN ... THEN 1 ELSE 0 END)` counts matching rows — the SQL way
    of saying "how many of these were successful logins?".
    """
    with closing(connect(path)) as connection:
        return [dict(r) for r in connection.execute(
            f"""
            SELECT agent_name,
                   COUNT(*) AS hits,
                   MIN(timestamp) AS first_seen,
                   MAX(timestamp) AS last_seen,
                   SUM(CASE WHEN {" OR ".join(
                       f"LOWER(rule_description) LIKE '%{m}%'"
                       for m in SUCCESS_MARKERS)}
                       THEN 1 ELSE 0 END) AS successes
            FROM alerts
            WHERE {column} = ?
              AND agent_name != 'unknown-host'
              AND datetime(timestamp) BETWEEN datetime(?, ?) AND datetime(?, ?)
            GROUP BY agent_name
            ORDER BY hits DESC
            """,
            (value, timestamp_iso, f"-{window_minutes} minutes",
             timestamp_iso, f"+{window_minutes} minutes"),
        )]


def hosts_for_user(username: str, timestamp_iso: str,
                   window_minutes: int = 60,
                   path: Path | None = None) -> list[dict]:
    """Which hosts this account touched in the window, and where it succeeded."""
    if not username:
        return []
    return _hosts_by("username", username, timestamp_iso, window_minutes, path)


def hosts_for_ip(src_ip: str, timestamp_iso: str,
                 window_minutes: int = 60,
                 path: Path | None = None) -> list[dict]:
    """Which hosts this address touched in the window."""
    if not src_ip:
        return []
    return _hosts_by("src_ip", src_ip, timestamp_iso, window_minutes, path)