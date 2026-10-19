"""
tools/scenarios.py
==================
Labelled synthetic incidents, used ONLY to prove the forensics detector
fires on the right pattern and stays silent on the wrong ones.

Why these exist: finding 10 showed that 85.8% of the real corpus comes from
a single host, so the real data cannot exercise multi-host detection at all.
Rather than loosen the detector until the real data produced a number, the
detector is validated against cases whose correct answer is known.

Three safeguards keep these from ever being mistaken for evidence:
  1. every id starts with "DEMO-"
  2. every record carries raw={"_synthetic": True}
  3. they are dated 2030, five years clear of the March 2025 corpus, so no
     real alert's 60-minute window can ever reach them

The IP addresses are from RFC 5737 (203.0.113.0/24 and 198.51.100.0/24),
which exist solely for documentation and belong to nobody.

A side effect worth knowing about: Python's `ipaddress` module classifies
those ranges as PRIVATE, so the hunter reports them as "Internal address;
no external reputation applies". That is not a mistake in the scenario - it
is what lateral movement actually looks like. An attacker who landed on
web-01 and then moved to db-01 and file-01 is travelling from INSIDE, and
an internal source with no external reputation is exactly the evidence a
real analyst would see. The scenario is more realistic for it, not less.
"""

from __future__ import annotations

from pathlib import Path

from core.models import Alert
from tools import history


DEMO_PREFIX = "DEMO-"
DEMO_DATE = "2030-01-15"


def _alert(seq: str, clock: str, host: str, level: int, description: str,
           user: str | None, src_ip: str | None) -> Alert:
    """Build one synthetic alert that looks exactly like a real one."""
    return Alert(
        id=f"{DEMO_PREFIX}{seq}",
        timestamp=f"{DEMO_DATE}T{clock}+00:00",
        rule_id="99999",
        rule_level=level,
        rule_description=description,
        agent_name=host,
        agent_id="999",
        src_ip=src_ip,
        user=user,
        full_log=f"Jan 15 {clock} {host} sshd[1000]: {description} "
                 f"for {user} from {src_ip}",
        raw={"_synthetic": True},
    )


def lateral_movement_incident() -> list[Alert]:
    """TRUE lateral movement: a named account that actually got in, twice more.

    The story: one failed attempt, then a success on web-01, then sessions
    opened on db-01 and file-01, then sudo to root. A real identity, real
    successes, three hosts. This MUST be flagged.
    """
    ip = "203.0.113.77"
    user = "s.karim"
    return [
        _alert("LM-01", "09:58:12", "web-01", 5,
               "sshd: Attempt to login using a non-existent user", user, ip),
        _alert("LM-02", "10:00:04", "web-01", 3,
               "sshd: authentication success", user, ip),
        _alert("LM-03", "10:04:31", "db-01", 3,
               "PAM: Login session opened.", user, ip),
        _alert("LM-04", "10:07:55", "file-01", 3,
               "PAM: Login session opened.", user, ip),
        _alert("LM-05", "10:09:40", "db-01", 4,
               "Successful sudo to ROOT executed", user, ip),
    ]


def generic_account_incident() -> list[Alert]:
    """TRAP 1: 'admin' on three hosts. Looks identical to movement.

    It is not: 'admin' exists on every machine, so seeing it in three places
    says nothing about anyone travelling. Correct answer: spread, not lateral.
    """
    ip = "198.51.100.23"
    return [
        _alert("GA-01", "11:00:01", "web-01", 5,
               "sshd: Multiple authentication failures", "admin", ip),
        _alert("GA-02", "11:00:09", "db-01", 5,
               "sshd: Multiple authentication failures", "admin", ip),
        _alert("GA-03", "11:00:17", "file-01", 5,
               "sshd: Multiple authentication failures", "admin", ip),
    ]


def password_spray_incident() -> list[Alert]:
    """TRAP 2: a real-looking account on three hosts, but it NEVER got in.

    Trying three doors and failing at all three is spraying. Correct answer:
    spread, not lateral. This is the case my first detector got wrong.
    """
    ip = "198.51.100.44"
    user = "j.moreau"
    return [
        _alert("PS-01", "12:00:05", "web-01", 5,
               "sshd: Attempt to login using a non-existent user", user, ip),
        _alert("PS-02", "12:00:40", "db-01", 5,
               "sshd: Attempt to login using a non-existent user", user, ip),
        _alert("PS-03", "12:01:22", "file-01", 5,
               "sshd: Attempt to login using a non-existent user", user, ip),
    ]


def all_demo_alerts() -> list[Alert]:
    """All eleven synthetic alerts, in time order."""
    return (lateral_movement_incident()
            + generic_account_incident()
            + password_spray_incident())


def is_demo(alert_id: str) -> bool:
    """True if this id is synthetic. Used so the interface can label it."""
    return str(alert_id).startswith(DEMO_PREFIX)


def install(path: Path | None = None) -> int:
    """Add the synthetic incidents to the history database.

    `rebuild=False` is essential: it ADDS to the database instead of wiping
    it, so the real corpus stays in place beside the demo rows.
    """
    return history.build(all_demo_alerts(), path=path, rebuild=False)