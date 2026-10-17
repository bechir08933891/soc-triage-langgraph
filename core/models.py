"""
core/models.py
==============
This file defines the SHAPE of our data.

Think of it as the quality-control desk at a factory entrance. Nothing gets
inside the system unless it matches one of the shapes described here.

For now there is only one shape: Alert. That is the raw security alert
arriving from Wazuh (our SIEM). Later we will add the shapes produced by
each of the five agents.
"""

# This line must be the first instruction in the file.
# It lets us write modern, simpler type hints (like `dict[str, Any]` instead
# of `Dict[str, Any]`) on every Python version we support.
from __future__ import annotations

# --- Standard library imports (these come with Python, nothing to install) ---

# `ipaddress` knows the rules of real IP addresses. We use it to check
# whether a value like "185.220.101.42" is a genuine IP or just text.
import ipaddress

# `datetime` is Python's date-and-time type.
# `timezone` lets us say "this time is UTC" (the world reference time).
from datetime import datetime, timezone

# `Any` means "a value of any type at all".
# `Optional[str]` means "either a piece of text, or nothing (None)".
from typing import Any, Optional

# --- Third-party import (this is the library we installed with pip) ---

# BaseModel      : the parent class. Inheriting from it gives us validation.
# ConfigDict     : lets us set options on a model (we use it to lock the model).
# Field          : lets us add rules to one single field (min, max, default...).
# field_validator: lets us write our own custom check for a field.
from pydantic import BaseModel, ConfigDict, Field, field_validator


# =============================================================================
# THE ALERT
# =============================================================================

class Alert(BaseModel):
    """One security alert, cleaned and verified. This is what enters the graph.

    `class Alert(BaseModel)` means: "create a new type called Alert, and give
    it all the powers of Pydantic's BaseModel."
    """

    # `frozen=True` makes an Alert READ-ONLY after it is created.
    # Reason: an alert is evidence. In a security investigation, evidence must
    # never be modified while it is being analysed. If some agent later tries
    # to change a value, Python raises an error instead of silently allowing it.
    model_config = ConfigDict(frozen=True)

    # -------------------------------------------------------------------------
    # THE FIELDS
    #
    # Each line follows the pattern:   name: type
    # The type is not a comment — Pydantic really enforces it.
    # A field with no `=` after it is REQUIRED. A field with `=` has a default
    # value and is therefore optional.
    # -------------------------------------------------------------------------

    # A unique name for this alert, for example "alert-001". Must be text.
    id: str

    # When the alert happened. Must be a real date and time.
    timestamp: datetime

    # The number of the Wazuh rule that fired, for example "5710".
    # We keep it as text, not a number, because we never do arithmetic on it.
    rule_id: str

    # Wazuh grades every alert from 0 (harmless) to 15 (critical).
    # `Field(ge=0, le=15)` adds two rules:
    #   ge = "greater than or equal to" 0
    #   le = "less than or equal to" 15
    # A value of 99 is not a severity, it is corrupt data, and Pydantic refuses it.
    rule_level: int = Field(ge=0, le=15, description="Wazuh severity, from 0 to 15")

    # What the rule says in human words.
    rule_description: str

    # The machine where the alert happened, e.g. "web-server-01".
    agent_name: str

    # The Wazuh agent number. `= "000"` is a default: if it is missing,
    # the alert is still accepted and this value is used.
    agent_id: str = "000"

    # The attacker's IP address. `Optional[str]` plus `= None` means:
    # "this may be text, or it may be nothing at all". Many alerts have no IP.
    src_ip: Optional[str] = None

    # The destination IP, when the alert is about network traffic.
    dst_ip: Optional[str] = None

    # The user account involved, e.g. "admin". Also optional.
    user: Optional[str] = None

    # The complete original record, untouched. We keep it so we can always
    # prove what the SIEM really sent us.
    # `default_factory=dict` means "if nothing is given, start with an empty {}".
    # `repr=False` means "do not print this when showing the alert", because
    # it is long and would make the screen unreadable.
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    # -------------------------------------------------------------------------
    # THE VALIDATORS — our own custom checks
    # -------------------------------------------------------------------------

    # `@field_validator(...)` is a decorator. It attaches the function below it
    # to one or more fields. We list two fields, so this one check guards both.
    # `mode="before"` means: run this BEFORE Pydantic checks the type. That is
    # what lets us clean the value first and hand back something acceptable.
    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def _clean_ip(cls, value: Any) -> Optional[str]:
        """Keep real IP addresses. Turn anything else into None.

        Why: later, the hunter agent sends this IP to an external threat
        database. Sending garbage would waste a request and might return a
        confusing answer. Better to have no IP than a fake one.
        """
        # Wazuh writes "-" or an empty string when there is no IP.
        if value in (None, "", "-"):
            return None

        # `try` means "attempt this, and if it fails do not crash".
        try:
            # ip_address() raises an error if the text is not a real IP.
            # str(...) converts the result back into clean text.
            # .strip() removes accidental spaces around the value.
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            # ValueError is the specific error ip_address() raises for bad input.
            # We catch it and return nothing, instead of letting the program die.
            return None

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, value: Any) -> Any:
        """Understand the date format Wazuh actually sends."""
        # `isinstance(value, str)` asks: "is this value a piece of text?"
        # If the value is already a real datetime, we leave it alone.
        if isinstance(value, str):
            # Wazuh writes times like "2026-02-18T10:32:00Z".
            # The "Z" means UTC, but Python's parser prefers "+00:00".
            # .replace() swaps one for the other.
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    # No `mode="before"` here, so this runs AFTER the value is a real datetime.
    @field_validator("timestamp")
    @classmethod
    def _force_utc(cls, value: datetime) -> datetime:
        """Make sure every alert carries a timezone.

        Why this matters: the forensics agent builds an attack timeline by
        sorting alerts by time. Comparing a time that has a timezone with one
        that does not makes Python crash. We remove that risk at the entrance.
        """
        # `.tzinfo` holds the timezone. `is None` means "there is no timezone".
        if value.tzinfo is None:
            # We assume UTC, which is what every SIEM uses by default.
            return value.replace(tzinfo=timezone.utc)
        return value

    # -------------------------------------------------------------------------
    # HELPERS — small conveniences built on top of the data
    # -------------------------------------------------------------------------

    # `@property` lets us use this like a value instead of a function:
    #   alert.is_private_src     (not  alert.is_private_src() )
    @property
    def is_private_src(self) -> bool:
        """True if the source IP is inside the company network.

        Useful later: there is no point asking a public threat database about
        an internal address like 10.0.1.21. It would never be listed.
        """
        if self.src_ip is None:
            return False
        # `.is_private` is given to us for free by the ipaddress library.
        return ipaddress.ip_address(self.src_ip).is_private

    def summary(self) -> str:
        """One short readable line describing this alert.

        We will show this in the dropdown menu of the demo interface.
        """
        # The `f` before the quotes makes it an "f-string": anything inside
        # curly braces { } is replaced by its real value.
        return (
            f"[{self.rule_id}] {self.rule_description} "
            f"(host={self.agent_name}, level={self.rule_level})"
        )