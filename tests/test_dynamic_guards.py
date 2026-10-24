"""SSRF and size guards for the live-target probe (nephilex.dynamic.posture).

All network traffic is served by httpx.MockTransport. The connected peer
address, which a real transport exposes through the ``network_stream``
response extension, is faked per test.
"""

from __future__ import annotations

import httpx
import pytest

from nephilex.dynamic import posture


class _Stream:
    def __init__(self, ip: str, port: int = 443) -> None:
        self._addr = (ip, port)

    def get_extra_info(self, name: str):
        return self._addr if name == "server_addr" else None


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


@pytest.fixture(autouse=True)
def _public_example(monkeypatch):
    """Treat the test origin as public without real DNS; everything else uses the real check."""
    real = posture._hostname_is_public

    def fake(host: str) -> bool:
        return True if host == "app.example.com" else real(host)

    monkeypatch.setattr(posture, "_hostname_is_public", fake)
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(var, raising=False)


def test_public_origin_connected_to_public_peer_is_read():
    def handler(request):
        return httpx.Response(
            200, text="hello", extensions={"network_stream": _Stream("93.184.216.34")}
        )

    s = posture.GuardedSession("https://app.example.com/", client=_client(handler))
    resp = s.get("https://app.example.com/")
    assert resp.status_code == 200 and resp.text == "hello"


def test_dns_rebinding_to_metadata_is_refused():
    # DNS said public, but the socket actually connected to link-local metadata.
    def handler(request):
        return httpx.Response(
            200,
            text="secret-credentials",
            extensions={"network_stream": _Stream("169.254.169.254", 80)},
        )

    s = posture.GuardedSession("http://app.example.com/", client=_client(handler))
    with pytest.raises(ValueError, match="non-public address"):
        s.get("http://app.example.com/latest/meta-data/")


def test_ipv4_mapped_private_peer_is_refused():
    def handler(request):
        return httpx.Response(200, extensions={"network_stream": _Stream("::ffff:10.0.0.5")})

    s = posture.GuardedSession("https://app.example.com/", client=_client(handler))
    with pytest.raises(ValueError):
        s.get("https://app.example.com/")


def test_unknown_peer_fails_closed_for_public_origin():
    def handler(request):
        return httpx.Response(200, text="x")  # no network_stream extension

    s = posture.GuardedSession("https://app.example.com/", client=_client(handler))
    with pytest.raises(ValueError, match="could not verify"):
        s.get("https://app.example.com/")


def test_operator_chosen_local_target_is_allowed():
    def handler(request):
        return httpx.Response(200, text="local app")

    s = posture.GuardedSession("http://127.0.0.1:8080/", client=_client(handler))
    assert s.get("http://127.0.0.1:8080/").text == "local app"


def test_redirect_into_private_space_is_refused():
    def handler(request):
        return httpx.Response(
            302,
            headers={"location": "http://169.254.169.254/"},
            extensions={"network_stream": _Stream("93.184.216.34")},
        )

    s = posture.GuardedSession("https://app.example.com/", client=_client(handler))
    with pytest.raises(ValueError, match="non-public host"):
        s.get("https://app.example.com/")


def test_body_is_capped():
    big = b"a" * 3_000_000

    def handler(request):
        return httpx.Response(
            200, content=big, extensions={"network_stream": _Stream("93.184.216.34")}
        )

    s = posture.GuardedSession("https://app.example.com/", client=_client(handler), max_bytes=1000)
    resp = s.get("https://app.example.com/")
    assert resp.truncated and len(resp.content) == 1000


def test_session_deadline_is_enforced():
    def handler(request):
        return httpx.Response(200, extensions={"network_stream": _Stream("93.184.216.34")})

    s = posture.GuardedSession(
        "https://app.example.com/", client=_client(handler), deadline_seconds=0
    )
    with pytest.raises(TimeoutError):
        s.get("https://app.example.com/")
