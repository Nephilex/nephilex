"""Dashboard hardening: DNS rebinding, CSRF, auth, limits, headers, retention."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlmodel")

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from nephilex.core.models import ScanResult  # noqa: E402
from nephilex.dashboard import app as app_module  # noqa: E402
from nephilex.dashboard import db, store  # noqa: E402

JSON = {"Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setenv("NEPHILEX_DASHBOARD_DB", ":memory:")
    monkeypatch.delenv(app_module.ALLOWED_HOSTS_ENV, raising=False)
    monkeypatch.delenv(app_module.MAX_SCANS_ENV, raising=False)
    db.reset_engine_for_tests()
    monkeypatch.setattr(app_module.settings, "token", None)
    monkeypatch.setattr(app_module.settings, "allowed_hosts", app_module.LOOPBACK_HOSTS)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app_module.app, base_url="http://127.0.0.1:8000")


def _report(target: str = "demo", when: datetime | None = None) -> str:
    when = when or datetime.now(timezone.utc)
    return ScanResult(target=target, started_at=when, finished_at=when).model_dump_json()


def _scan_count() -> int:
    with Session(db.get_engine()) as s:
        return len(s.exec(select(db.Scan)).all())


# --- DNS rebinding -------------------------------------------------------------
@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "[::1]:8000", "localhost"])
def test_loopback_host_headers_are_accepted(client, host):
    assert client.get("/", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("host", ["attacker.example:8000", "127.0.0.1.nip.io", "evil", ""])
def test_rebound_host_headers_are_rejected(client, host):
    r = client.get("/", headers={"Host": host})
    assert r.status_code == 400
    r = client.post("/api/scans", content=_report(), headers={**JSON, "Host": host})
    assert r.status_code == 400
    assert _scan_count() == 0


def test_allowed_hosts_env(monkeypatch):
    monkeypatch.setenv(app_module.ALLOWED_HOSTS_ENV, "nephilex.internal")
    app_module.configure("127.0.0.1")
    c = TestClient(app_module.app, base_url="http://nephilex.internal")
    assert c.get("/").status_code == 200


# --- CSRF --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ctype",
    ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", None],
)
def test_api_ingest_requires_json_content_type(client, ctype):
    headers = {"Content-Type": ctype} if ctype else {}
    r = client.post("/api/scans", content=_report(), headers=headers)
    assert r.status_code == 415
    assert _scan_count() == 0


def test_api_ingest_accepts_json_with_charset(client):
    r = client.post(
        "/api/scans", content=_report(), headers={"Content-Type": "application/json; charset=utf-8"}
    )
    assert r.status_code == 200


@pytest.mark.parametrize("data", [{}, {"csrf_token": "guess"}])
def test_upload_requires_csrf_token(client, data):
    r = client.post(
        "/upload",
        files={"file": ("r.json", _report(), "application/json")},
        data=data,
        follow_redirects=False,
    )
    assert r.status_code == 403
    assert _scan_count() == 0


def test_upload_form_carries_csrf_token(client):
    page = client.get("/upload").text
    assert f'name="csrf_token" value="{app_module.CSRF_TOKEN}"' in page


# --- token auth ----------------------------------------------------------------------
def test_token_required_when_configured(client, monkeypatch):
    monkeypatch.setattr(app_module.settings, "token", "s3cret")
    assert client.get("/").status_code == 401
    r = client.post("/api/scans", content=_report(), headers=JSON)
    assert r.status_code == 401 and r.json()["error"]
    assert client.get("/", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    r = client.post(
        "/api/scans", content=_report(), headers={**JSON, "Authorization": "Bearer s3cret"}
    )
    assert r.status_code == 200


def test_token_login_link_sets_cookie(client, monkeypatch):
    monkeypatch.setattr(app_module.settings, "token", "s3cret")
    r = client.get("/?token=s3cret", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert client.get("/").status_code == 200  # TestClient kept the cookie
    assert client.get("/?token=nope", follow_redirects=False).status_code in (200, 401)


def test_non_loopback_bind_requires_token(monkeypatch):
    monkeypatch.delenv(app_module.TOKEN_ENV, raising=False)
    for host in ("0.0.0.0", "::", "192.168.1.10"):
        with pytest.raises(app_module.DashboardConfigError):
            app_module.configure(host)
    with pytest.raises(SystemExit):
        app_module.serve(host="0.0.0.0", port=0)


def test_non_loopback_bind_with_token(monkeypatch):
    monkeypatch.setenv(app_module.TOKEN_ENV, "t0ken")
    s = app_module.configure("0.0.0.0")
    assert s.allowed_hosts is None and s.token == "t0ken"
    s = app_module.configure("192.168.1.10")
    assert s.allowed_hosts is not None and "192.168.1.10" in s.allowed_hosts
    s = app_module.configure("127.0.0.1")
    assert s.allowed_hosts == app_module.LOOPBACK_HOSTS


# --- forged timestamps ------------------------------------------------------------------
def test_future_dated_report_cannot_stay_latest(client):
    forged = datetime(9999, 1, 1, tzinfo=timezone.utc)
    client.post("/api/scans", content=_report("demo", forged), headers=JSON)
    later = client.post("/api/scans", content=_report("demo"), headers=JSON).json()
    with Session(db.get_engine()) as s:
        scans = store.list_scans(s, store.list_projects(s)[0]["project"].id)
        assert all(sc.created_at.year < 9999 for sc in scans)
        latest = store.list_projects(s)[0]["latest"]
        assert latest.id == later["scan_id"]


# --- size limits and retention -------------------------------------------------------------
def test_streamed_body_is_capped_without_content_length(client, monkeypatch):
    monkeypatch.setattr(app_module, "_MAX_REPORT_BYTES", 64)
    monkeypatch.setattr(app_module, "_MULTIPART_OVERHEAD", 0)

    def chunks():
        for _ in range(10):
            yield b"x" * 50

    r = client.post("/api/scans", content=chunks(), headers=JSON)
    assert r.status_code == 413


def test_oversized_upload_is_refused_before_parsing(client, monkeypatch):
    monkeypatch.setattr(app_module, "_MAX_REPORT_BYTES", 64)
    monkeypatch.setattr(app_module, "_MULTIPART_OVERHEAD", 0)
    called = []
    monkeypatch.setattr(app_module, "_ingest", lambda *a: called.append(a))
    r = client.post(
        "/upload",
        files={"file": ("r.json", b"x" * 5000, "application/json")},
        data={"csrf_token": app_module.CSRF_TOKEN},
        follow_redirects=False,
    )
    assert r.status_code == 413
    assert called == []


def test_ingest_runs_off_the_event_loop(client, monkeypatch):
    used = []
    real = app_module.run_in_threadpool

    async def spy(fn, *args):
        used.append(fn)
        return await real(fn, *args)

    monkeypatch.setattr(app_module, "run_in_threadpool", spy)
    assert client.post("/api/scans", content=_report(), headers=JSON).status_code == 200
    assert used == [app_module._ingest]


def test_retention_cap(client, monkeypatch):
    monkeypatch.setenv(app_module.MAX_SCANS_ENV, "2")
    base = datetime.now(timezone.utc) - timedelta(hours=5)
    for i, name in enumerate(["old", "mid", "new"]):
        r = client.post(
            "/api/scans", content=_report(name, base + timedelta(hours=i)), headers=JSON
        )
        assert r.status_code == 200
    with Session(db.get_engine()) as s:
        names = sorted(p["project"].name for p in store.list_projects(s))
        assert names == ["mid", "new"]  # the oldest scan and its empty project are gone
        assert len(s.exec(select(db.Scan)).all()) == 2


# --- headers and markup ----------------------------------------------------------------------
def test_security_headers_on_every_response(client):
    for path in ("/", "/upload", "/static/app.js", "/scans/999"):
        r = client.get(path)
        csp = r.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp, path
        assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0]
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("referrer-policy") == "no-referrer"


def test_pages_have_no_inline_event_handlers(client):
    client.post("/api/scans", content=_report(), headers=JSON)
    with Session(db.get_engine()) as s:
        slug = store.list_projects(s)[0]["project"].slug
    for path in ("/", f"/projects/{slug}"):
        html = client.get(path).text
        assert "onclick" not in html
        assert "data-href" not in html
    assert f'<a href="/projects/{slug}">' in client.get("/").text
    assert '<a href="/scans/' in client.get(f"/projects/{slug}").text


def test_row_script_never_builds_a_url_from_page_text(client):
    js = client.get("/static/app.js").text
    assert "location" not in js and 'getAttribute("data-href")' not in js
    assert 'querySelector("a[href]")' in js
