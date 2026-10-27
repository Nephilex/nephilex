"""Remote malicious-package feeds are fetched only when one is configured."""

from __future__ import annotations

import pytest

from nephilex.supply_chain import intel


@pytest.fixture
def fetched(monkeypatch) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    def fake_fetch(urls, timeout):
        calls.append(tuple(urls))
        return None

    monkeypatch.setattr(intel, "_fetch_remote", fake_fetch)
    monkeypatch.setattr(intel, "_read_cache", lambda: None)
    monkeypatch.setattr(intel, "_write_cache", lambda index: None)
    monkeypatch.delenv(intel._FEED_ENV, raising=False)
    intel.load_malicious_index.cache_clear()
    yield calls
    intel.load_malicious_index.cache_clear()


def test_no_feed_is_requested_by_default(fetched) -> None:
    index = intel.load_malicious_index(online=True)
    assert fetched == []
    # The bundled list still answers.
    assert ("npm", "flatmap-stream") in index.names()


def test_configured_https_feeds_are_fetched(fetched, monkeypatch) -> None:
    monkeypatch.setenv(
        intel._FEED_ENV,
        " https://intel.example/a.json , http://intel.example/b.json,,https://intel.example/c.json",
    )
    intel.load_malicious_index(online=True)
    assert fetched == [("https://intel.example/a.json", "https://intel.example/c.json")]


def test_configured_feed_is_not_fetched_offline(fetched, monkeypatch) -> None:
    monkeypatch.setenv(intel._FEED_ENV, "https://intel.example/a.json")
    intel.load_malicious_index(online=False)
    assert fetched == []


def test_explicit_feed_url_overrides_the_environment(fetched, monkeypatch) -> None:
    monkeypatch.setenv(intel._FEED_ENV, "https://intel.example/a.json")
    intel.load_malicious_index(online=True, feed_url="https://other.example/x.json")
    assert fetched == [("https://other.example/x.json",)]
