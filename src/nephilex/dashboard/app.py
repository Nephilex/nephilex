"""The dashboard web app (FastAPI + server-rendered templates).

Pages: projects overview (``/``), project detail with a risk trend
(``/projects/{slug}``), and a scan's findings (``/scans/{id}``). Reports get in
either by uploading a JSON file (``/upload``) or by POSTing one to ``/api/scans``
with ``Content-Type: application/json``, e.g.
``nephilex scan . -f json | curl -H 'Content-Type: application/json' --data-binary @- .../api/scans``.

The dashboard is local-first, but a browser on the same machine is a way in
for other websites, so every request passes :class:`_GuardMiddleware`:

* **Host check.** On a loopback bind only ``127.0.0.1``, ``localhost`` and
  ``::1`` are accepted as ``Host``, which defeats DNS rebinding (a hostile page
  re-pointing its own name at 127.0.0.1 to read the dashboard). Extra names can
  be allowed with ``NEPHILEX_DASHBOARD_ALLOWED_HOSTS`` (comma-separated).
* **Optional token.** With ``NEPHILEX_DASHBOARD_TOKEN`` set, requests need
  ``Authorization: Bearer <token>`` or the session cookie set by visiting
  ``/?token=<token>`` once. Binding to a non-loopback address without a token
  is refused.
* **CSRF.** ``/api/scans`` only accepts ``application/json`` (a cross-site page
  cannot send that without a CORS preflight, which is never granted) and the
  upload form carries a per-process token.
* **Size limits.** Request bodies are capped while they stream in, before
  multipart parsing spools anything to disk.
* **Security headers.** A strict CSP (no inline script), ``nosniff``, no
  framing and no referrer.
"""

from __future__ import annotations

import contextlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers

from nephilex import __version__
from nephilex.dashboard import charts, store
from nephilex.dashboard.db import get_session

log = logging.getLogger("nephilex.dashboard")

_HERE = Path(__file__).parent
#: Hard cap for uploaded / POSTed JSON reports (bytes). Large enough for real
#: scans; small enough to bound memory and disk when the dashboard is exposed.
_MAX_REPORT_BYTES = 20 * 1024 * 1024
#: Allowance for multipart framing around an uploaded report.
_MULTIPART_OVERHEAD = 64 * 1024
_READ_CHUNK = 64 * 1024

TOKEN_ENV = "NEPHILEX_DASHBOARD_TOKEN"
ALLOWED_HOSTS_ENV = "NEPHILEX_DASHBOARD_ALLOWED_HOSTS"
MAX_SCANS_ENV = "NEPHILEX_DASHBOARD_MAX_SCANS"
DEFAULT_MAX_SCANS = 1000
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_COOKIE = "nephilex_dashboard_token"

#: Per-process CSRF token embedded in the upload form.
CSRF_TOKEN = secrets.token_urlsafe(32)

SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (
        b"content-security-policy",
        b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        b"img-src 'self' data:; object-src 'none'; base-uri 'none'; "
        b"form-action 'self'; frame-ancestors 'none'",
    ),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
)


class DashboardConfigError(RuntimeError):
    """The dashboard cannot be started safely with the given settings."""


@dataclass
class DashboardSettings:
    #: Accepted Host header names; None accepts any (wildcard bind + token).
    allowed_hosts: frozenset[str] | None = LOOPBACK_HOSTS
    #: Bearer token required on every request, if set.
    token: str | None = None


settings = DashboardSettings(token=os.environ.get(TOKEN_ENV) or None)


def _env_hosts() -> frozenset[str]:
    raw = os.environ.get(ALLOWED_HOSTS_ENV, "")
    return frozenset(h.strip().lower().strip("[]") for h in raw.split(",") if h.strip())


def _is_loopback_bind(host: str) -> bool:
    import ipaddress

    h = host.strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def configure(host: str, *, token: str | None = None) -> DashboardSettings:
    """Set the Host allowlist and token for a bind address (used by :func:`serve`).

    Raises :class:`DashboardConfigError` for a non-loopback bind without a token.
    """
    token = token if token is not None else (os.environ.get(TOKEN_ENV) or None)
    bind = host.strip("[]").lower()
    extra = _env_hosts()
    if _is_loopback_bind(host):
        allowed: frozenset[str] | None = LOOPBACK_HOSTS | {bind} | extra
    else:
        if not token:
            raise DashboardConfigError(
                f"refusing to bind the dashboard to {host}: anyone who can reach it "
                f"could read and add scans. Set {TOKEN_ENV} to require a token, or "
                "bind to 127.0.0.1."
            )
        if bind in ("0.0.0.0", "::", ""):
            # Clients use whatever name or address reaches this machine; the
            # token is the protection. Restrict further with the env var.
            allowed = (LOOPBACK_HOSTS | extra) if extra else None
        else:
            allowed = LOOPBACK_HOSTS | {bind} | extra
    settings.allowed_hosts = allowed
    settings.token = token
    return settings


def max_scans() -> int:
    try:
        return max(1, int(os.environ.get(MAX_SCANS_ENV, DEFAULT_MAX_SCANS)))
    except ValueError:
        return DEFAULT_MAX_SCANS


def _host_name(raw: str) -> str:
    raw = raw.strip().lower()
    if raw.startswith("["):
        return raw[1:].split("]", 1)[0]
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    return raw.rstrip(".")


class _BodyTooLarge(Exception):
    pass


class _GuardMiddleware:
    """Host check, token auth, streaming body cap and security headers."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def _respond(
        self,
        send: Any,
        status: int,
        body: bytes,
        *,
        content_type: bytes = b"text/plain; charset=utf-8",
        extra: tuple[tuple[bytes, bytes], ...] = (),
    ) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", content_type),
                    (b"content-length", str(len(body)).encode()),
                    *SECURITY_HEADERS,
                    *extra,
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def _error(
        self,
        scope: dict,
        send: Any,
        status: int,
        message: str,
        extra: tuple[tuple[bytes, bytes], ...] = (),
    ) -> None:
        if scope.get("path", "").startswith("/api/"):
            import json

            await self._respond(
                send,
                status,
                json.dumps({"error": message}).encode(),
                content_type=b"application/json",
                extra=extra,
            )
        else:
            await self._respond(send, status, message.encode(), extra=extra)

    def _authorized(self, headers: Headers) -> bool:
        token = settings.token
        if not token:
            return True
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer ") and hmac.compare_digest(
            auth[7:].strip().encode(), token.encode()
        ):
            return True
        for part in headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == _COOKIE and hmac.compare_digest(value.encode(), token.encode()):
                return True
        return False

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)

        allowed = settings.allowed_hosts
        if allowed is not None and _host_name(headers.get("host", "")) not in allowed:
            await self._error(scope, send, 400, "Invalid host header")
            return

        if not self._authorized(headers):
            query = dict(parse_qsl(scope.get("query_string", b"").decode("latin-1")))
            supplied = query.pop("token", None)
            if (
                supplied
                and settings.token
                and scope.get("method") == "GET"
                and hmac.compare_digest(supplied.encode(), settings.token.encode())
            ):
                # One-time login link: remember the token in a cookie and drop it
                # from the URL so it does not linger in history.
                location = scope.get("path", "/") + (f"?{urlencode(query)}" if query else "")
                cookie = f"{_COOKIE}={settings.token}; Path=/; HttpOnly; SameSite=Strict"
                await self._respond(
                    send,
                    303,
                    b"",
                    extra=(
                        (b"location", location.encode()),
                        (b"set-cookie", cookie.encode()),
                        (b"cache-control", b"no-store"),
                    ),
                )
                return
            await self._error(
                scope,
                send,
                401,
                "Authentication required",
                extra=((b"www-authenticate", b"Bearer"),),
            )
            return

        limit = _MAX_REPORT_BYTES + _MULTIPART_OVERHEAD
        declared = headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > limit:
                    await self._error(
                        scope, send, 413, f"Report exceeds {_MAX_REPORT_BYTES} byte limit"
                    )
                    return
            except ValueError:
                await self._error(scope, send, 400, "Invalid Content-Length")
                return

        state = {"received": 0, "too_large": False, "started": False}

        async def limited_receive() -> dict:
            message = await receive()
            if message["type"] == "http.request":
                state["received"] += len(message.get("body", b""))
                if state["received"] > limit:
                    state["too_large"] = True
                    raise _BodyTooLarge
            return message

        async def guarded_send(message: dict) -> None:
            if state["too_large"]:
                return  # replaced by the 413 below
            if message["type"] == "http.response.start":
                state["started"] = True
                existing = {k.lower() for k, _ in message.get("headers", [])}
                message = dict(message)
                message["headers"] = [
                    *message.get("headers", []),
                    *(h for h in SECURITY_HEADERS if h[0] not in existing),
                ]
            await send(message)

        # The overflow may surface as _BodyTooLarge, or be turned into a 400 by
        # FastAPI's form parsing; either way the response becomes a 413.
        with contextlib.suppress(_BodyTooLarge):
            await self.app(scope, limited_receive, guarded_send)
        if state["too_large"] and not state["started"]:
            await self._error(scope, send, 413, f"Report exceeds {_MAX_REPORT_BYTES} byte limit")


templates = Jinja2Templates(directory=str(_HERE / "templates"))
templates.env.globals.update(
    severity_fill=charts.severity_fill,
    severity_label=store.severity_label,
    severity_order=charts.SEVERITY_ORDER,
    risk_band=charts.risk_band,
    nephilex_version=__version__,
)

app = FastAPI(title="Nephilex Dashboard", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")
app.add_middleware(_GuardMiddleware)


def _too_large() -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=f"Report exceeds {_MAX_REPORT_BYTES} byte limit",
    )


async def _read_body_limited(request: Request) -> str:
    """Read the request body, aborting at ``_MAX_REPORT_BYTES``."""
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > _MAX_REPORT_BYTES:
                raise _too_large()
        except ValueError:
            pass
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > _MAX_REPORT_BYTES:
            raise _too_large()
    return buf.decode("utf-8", "replace")


async def _read_upload_limited(file: UploadFile) -> str:
    """Read an uploaded file, aborting at ``_MAX_REPORT_BYTES``."""
    if file.size is not None and file.size > _MAX_REPORT_BYTES:
        raise _too_large()
    buf = bytearray()
    while True:
        chunk = await file.read(_READ_CHUNK)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > _MAX_REPORT_BYTES:
            raise _too_large()
    return buf.decode("utf-8", "replace")


#: What the client is told when a report cannot be stored. The exception
#: itself goes to the server log only: its text can include parts of the
#: report, file paths or internal details.
_BAD_REPORT = "Not a valid Nephilex JSON report; the dashboard log has the details"


def _ingest(session: Session, raw: str):
    """Store a report and apply the retention cap (runs in a worker thread)."""
    scan = store.ingest_report(session, raw)
    store.enforce_retention(session, max_scans())
    return scan


@app.get("/", response_class=HTMLResponse)
def index(request: Request, session: Session = Depends(get_session)):
    return templates.TemplateResponse(
        request,
        "projects.html",
        {
            "projects": store.list_projects(session),
            "stats": store.overall_stats(session),
        },
    )


@app.get("/projects/{slug}", response_class=HTMLResponse)
def project_detail(slug: str, request: Request, session: Session = Depends(get_session)):
    project = store.get_project(session, slug)
    if project is None or project.id is None:
        raise HTTPException(404, "Project not found")
    return templates.TemplateResponse(
        request,
        "project.html",
        {
            "project": project,
            "scans": store.list_scans(session, project.id),
            "trend": charts.trend_geometry(store.trend(session, project.id)),
        },
    )


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int, request: Request, session: Session = Depends(get_session)):
    scan = store.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return templates.TemplateResponse(
        request,
        "scan.html",
        {
            "scan": scan,
            "project": store.get_project_by_id(session, scan.project_id),
            "findings": store.get_findings(session, scan_id),
            "bar": charts.severity_bar(scan.severity_counts, scan.total_findings),
        },
    )


@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request):
    return templates.TemplateResponse(request, "upload.html", {"csrf_token": CSRF_TOKEN})


@app.post("/upload")
async def upload_submit(
    file: UploadFile, csrf_token: str = Form(""), session: Session = Depends(get_session)
):
    if not hmac.compare_digest(csrf_token.encode(), CSRF_TOKEN.encode()):
        raise HTTPException(403, "Missing or invalid CSRF token; reload the upload page")
    raw = await _read_upload_limited(file)
    try:
        scan = await run_in_threadpool(_ingest, session, raw)
    except Exception as exc:  # bad/incomplete report
        log.warning("Rejected an uploaded report", exc_info=True)
        raise HTTPException(400, _BAD_REPORT) from exc
    return RedirectResponse(f"/scans/{scan.id}", status_code=303)


def _is_json(request: Request) -> bool:
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    return media_type == "application/json"


@app.post("/api/scans")
async def api_ingest(request: Request, session: Session = Depends(get_session)):
    if not _is_json(request):
        # Browsers can send text/plain or form bodies cross-site without a
        # preflight; requiring JSON makes a forged cross-site POST impossible.
        return JSONResponse({"error": "Content-Type must be application/json"}, status_code=415)
    try:
        raw = await _read_body_limited(request)
    except HTTPException as exc:
        if exc.status_code == 413:
            return JSONResponse({"error": exc.detail}, status_code=413)
        raise
    try:
        scan = await run_in_threadpool(_ingest, session, raw)
    except Exception:
        log.warning("Rejected a report posted to /api/scans", exc_info=True)
        return JSONResponse({"error": _BAD_REPORT}, status_code=400)
    return {
        "scan_id": scan.id,
        "url": f"/scans/{scan.id}",
        "risk_score": scan.risk_score,
        "findings": scan.total_findings,
    }


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Launch the dashboard with uvicorn (used by ``nephilex dashboard``).

    Exits with an error for a non-loopback ``host`` unless
    ``NEPHILEX_DASHBOARD_TOKEN`` is set.
    """
    import uvicorn

    try:
        configure(host)
    except DashboardConfigError as exc:
        raise SystemExit(f"Error: {exc}") from None
    if not _is_loopback_bind(host):
        log.warning(
            "Dashboard bound to %s with token authentication. Serve it behind TLS: "
            "the token travels in every request.",
            host,
        )
    uvicorn.run(app, host=host, port=port)
