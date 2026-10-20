"""Findings 2, 4 and 9: unwrapping, and the host names hidden in the logs."""
from __future__ import annotations

import pytest

from core.models import Alert
from core.preprocessor import (_host_from_syslog, _resolve_host, _unwrap_record,
                               normalize_wazuh_alert)


@pytest.mark.parametrize("line,expected", [
    ("Mar 05 00:03:44 wazuh-server sshd[3129036]: Invalid user", "wazuh-server"),
    ("Mar 05 02:24:36 staging-environment sshd[70516]: pam_unix", "staging-environment"),
    # nginx access logs have no host field at all - 47 alerts in the corpus
    ('203.0.113.1 - - [05/Mar/2025:00:03:50] "GET / HTTP/1.1" 400', None),
    (None, None),
    ("", None),
])
def test_host_recovered_from_syslog(line, expected):
    assert _host_from_syslog(line) == expected


def test_placeholder_hosts_are_not_host_names():
    """Finding 9: the dataset anonymises agent.name to 'xxx'."""
    assert _resolve_host({"agent": {"name": "xxx"}}) == "unknown-host"
    assert _resolve_host({"agent": {"name": "real-box"}}) == "real-box"


def test_trigger_host_wins_over_the_wrapper():
    raw = {"agent": {"name": "xxx"}, "_trigger_host": "prod-server"}
    assert _resolve_host(raw) == "prod-server"


def test_syslog_is_the_last_resort():
    raw = {"agent": {"name": "xxx"},
           "full_log": "Mar 05 00:03:44 wazuh-server sshd[1]: x"}
    assert _resolve_host(raw) == "wazuh-server"


def test_active_response_wrapper_is_unwrapped():
    """Finding 2: 63% of records hide the alert that matters."""
    record = {"rule": {"id": "651", "level": 3,
                       "description": "Host Blocked by firewall-drop"},
              "data": {"command": "add",
                       "parameters": {"alert": {
                           "rule": {"id": "5710", "level": 5,
                                    "description": "sshd: brute force"},
                           "agent": {"name": "prod-server"},
                           "data": {"srcip": "45.55.159.241"}}}}}
    unwrapped = _unwrap_record(record)
    assert unwrapped["_trigger_description"] == "sshd: brute force"
    assert unwrapped["_trigger_srcip"] == "45.55.159.241"
    assert unwrapped["_trigger_host"] == "prod-server"
    assert unwrapped["_response_command"] == "add"


@pytest.mark.parametrize("value,expected", [
    ("45.55.159.241", "45.55.159.241"),
    ("not-an-address", None),
    ("-", None),
    ("", None),
    (None, None),
])
def test_bad_addresses_become_none(make_alert, value, expected):
    assert make_alert(src_ip=value).src_ip == expected


@pytest.mark.parametrize("stamp", ["2025-03-05T00:03:44.123Z",
                                   "2025-03-05T00:03:44.123+0000",
                                   "2025-03-05T00:03:44+00:00"])
def test_both_timestamp_formats_parse(make_alert, stamp):
    assert make_alert(timestamp=stamp).timestamp.tzinfo is not None


def test_level_is_clamped_to_the_wazuh_range():
    alert = normalize_wazuh_alert({"rule": {"level": 99},
                                   "timestamp": "2030-01-01T00:00:00Z"})
    assert alert.rule_level == 15


@pytest.mark.slow
def test_whole_corpus_validates(corpus):
    """Finding 4: every record survives the contract."""
    assert len(corpus) > 100
    assert all(isinstance(a, Alert) for a in corpus)


@pytest.mark.slow
def test_most_hosts_are_recovered(corpus):
    """Finding 9: measured at 93.6%. Asserted as a floor, not an equality,
    so a dataset update does not fail a test that is still true."""
    real = sum(1 for a in corpus if a.agent_name not in ("xxx", "unknown-host"))
    assert real / len(corpus) > 0.5