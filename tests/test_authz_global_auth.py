"""``authz.missing-authentication`` and project-wide authentication.

A route with no auth of its own may be protected by something registered once
for the whole app: an HTTP middleware, app- or router-level dependencies, a
Flask ``before_request`` hook or a Django middleware. Such a route is reported
as an Info note naming the guard instead of a High finding. A guard counts only
when it reads a credential and rejects with 401/403, and a path it skips stays
unprotected.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from nephilex.core.config import Config
from nephilex.core.models import Severity
from nephilex.core.plugin import ScannerContext
from nephilex.core.project import Project
from nephilex.scanners.authz import AuthzScanner

RULE = "authz.missing-authentication"


def _routes(tmp_path: Path, files: dict[str, str]) -> dict[str, Severity]:
    """Severity of the missing-authentication finding per route (one per route)."""
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    out: dict[str, Severity] = {}
    for f in AuthzScanner().scan(ctx):
        if f.rule_id == RULE:
            key = f"{f.location.path.replace(chr(92), '/')}:{f.metadata['route']}"
            assert key not in out or out[key] == f.severity
            out[key] = f.severity
    return out


SETTINGS_ROUTES = """\
    from fastapi import APIRouter

    router = APIRouter()


    @router.get("/settings")
    async def read_settings():
        return {}


    @router.put("/settings")
    async def write_settings(body: dict):
        return body
"""

API_KEY_MIDDLEWARE = """\
    import os
    import secrets

    from fastapi import FastAPI

    from app.api import settings
    from app.errors import error_response

    API_KEY_NAME = "X-API-Key"
    API_TOKEN = os.environ["API_TOKEN"]

    app = FastAPI()


    @app.middleware("http")
    async def guard(request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        key = request.headers.get(API_KEY_NAME)
        if not key or not secrets.compare_digest(key, API_TOKEN):
            return error_response("Unauthorized", None, 401)
        return await call_next(request)


    app.include_router(settings.router)
"""


# --- FastAPI / Starlette ----------------------------------------------------


def test_http_middleware_covers_routes_in_another_module(tmp_path):
    found = _routes(
        tmp_path,
        {"app/main.py": API_KEY_MIDDLEWARE, "app/api/settings.py": SETTINGS_ROUTES},
    )
    assert found == {"app/api/settings.py:/settings": Severity.INFO}


def test_info_note_names_the_guard(tmp_path):
    files = {"app/main.py": API_KEY_MIDDLEWARE, "app/api/settings.py": SETTINGS_ROUTES}
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    notes = [f for f in AuthzScanner().scan(ctx) if f.rule_id == RULE]
    assert len(notes) == 2
    note = notes[0]
    assert note.title == "Sensitive route relies on global authentication: /settings"
    assert note.metadata["global_auth"]["kind"] == "HTTP middleware"
    assert note.metadata["global_auth"]["path"].endswith("main.py")
    assert "global-auth" in note.tags


def test_without_the_middleware_the_routes_are_high(tmp_path):
    found = _routes(tmp_path, {"app/api/settings.py": SETTINGS_ROUTES})
    assert found == {"app/api/settings.py:/settings": Severity.HIGH}


def test_reject_after_pass_through_counts(tmp_path):
    main = """\
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        app = FastAPI()


        @app.middleware("http")
        async def guard(request, call_next):
            token = request.headers.get("Authorization", "")
            if token == f"Bearer {EXPECTED}":
                return await call_next(request)
            return JSONResponse({"detail": "forbidden"}, status_code=403)
    """
    found = _routes(tmp_path, {"main.py": main, "routes.py": SETTINGS_ROUTES})
    assert found == {"routes.py:/settings": Severity.INFO}


def test_add_middleware_class_with_dispatch(tmp_path):
    middleware = """\
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse


        class ApiKeyMiddleware(BaseHTTPMiddleware):
            exempt = ("/health", "/docs")

            async def dispatch(self, request, call_next):
                if request.url.path in self.exempt:
                    return await call_next(request)
                try:
                    claims = decode_jwt(request.cookies["session"])
                except Exception:
                    return JSONResponse({"detail": "unauthorized"}, status_code=401)
                request.state.claims = claims
                return await call_next(request)
    """
    main = """\
        from fastapi import FastAPI

        from security import ApiKeyMiddleware

        app = FastAPI()
        app.add_middleware(ApiKeyMiddleware)
    """
    found = _routes(
        tmp_path,
        {"security.py": middleware, "main.py": main, "routes.py": SETTINGS_ROUTES},
    )
    assert found == {"routes.py:/settings": Severity.INFO}


def test_add_middleware_raising_http_exception(tmp_path):
    middleware = """\
        from fastapi import HTTPException, status
        from starlette.middleware.base import BaseHTTPMiddleware


        class TokenGate(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                auth = request.headers.get("authorization")
                scheme, _, token = (auth or "").partition(" ")
                if scheme.lower() != "bearer" or not is_valid(token):
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
                return await call_next(request)
    """
    main = """\
        from fastapi import FastAPI
        from gate import TokenGate

        app = FastAPI()
        app.add_middleware(TokenGate)
    """
    found = _routes(
        tmp_path, {"gate.py": middleware, "main.py": main, "routes.py": SETTINGS_ROUTES}
    )
    assert found == {"routes.py:/settings": Severity.INFO}


def test_app_level_dependencies(tmp_path):
    main = """\
        from fastapi import Depends, FastAPI

        from deps import verify_api_key

        app = FastAPI(dependencies=[Depends(verify_api_key)])


        @app.get("/admin/users")
        async def list_users():
            return []
    """
    found = _routes(tmp_path, {"main.py": main, "routes.py": SETTINGS_ROUTES})
    assert found == {"main.py:/admin/users": Severity.INFO, "routes.py:/settings": Severity.INFO}


def test_app_dependency_that_is_not_auth_does_not_count(tmp_path):
    main = """\
        from fastapi import Depends, FastAPI

        app = FastAPI(dependencies=[Depends(get_db)])


        def get_db():
            yield None


        @app.get("/admin/users")
        async def list_users():
            return []
    """
    assert _routes(tmp_path, {"main.py": main}) == {"main.py:/admin/users": Severity.HIGH}


def test_include_router_dependencies_cover_only_that_router(tmp_path):
    main = """\
        from fastapi import Depends, FastAPI

        from .api import billing, settings
        from .auth import get_current_user

        app = FastAPI()
        app.include_router(settings.router, dependencies=[Depends(get_current_user)])
        app.include_router(billing.router)
    """
    billing = """\
        from fastapi import APIRouter

        router = APIRouter()


        @router.get("/billing")
        async def invoices():
            return []
    """
    found = _routes(
        tmp_path,
        {
            "svc/__init__.py": "",
            "svc/main.py": main,
            "svc/api/settings.py": SETTINGS_ROUTES,
            "svc/api/billing.py": billing,
        },
    )
    assert found == {
        "svc/api/settings.py:/settings": Severity.INFO,
        "svc/api/billing.py:/billing": Severity.HIGH,
    }


def test_router_level_dependencies_still_drop_the_finding(tmp_path):
    routes = """\
        from fastapi import APIRouter, Depends

        router = APIRouter(dependencies=[Depends(get_current_user)])


        @router.get("/settings")
        async def read_settings():
            return {}
    """
    assert _routes(tmp_path, {"routes.py": routes}) == {}


def test_starlette_middleware_list(tmp_path):
    main = """\
        from fastapi import FastAPI
        from starlette.middleware import Middleware
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import Response


        class KeyCheck(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                if request.headers.get("x-api-key") != KEY:
                    return Response(status_code=401)
                return await call_next(request)


        app = FastAPI(middleware=[Middleware(KeyCheck)])
    """
    found = _routes(tmp_path, {"main.py": main, "routes.py": SETTINGS_ROUTES})
    assert found == {"routes.py:/settings": Severity.INFO}


# --- what is not authentication ---------------------------------------------


def test_middleware_that_checks_nothing_does_not_count(tmp_path):
    main = """\
        import logging
        import time

        from fastapi import FastAPI

        app = FastAPI()
        log = logging.getLogger(__name__)


        @app.middleware("http")
        async def timing(request, call_next):
            start = time.monotonic()
            log.info("auth header present: %s", "authorization" in request.headers)
            response = await call_next(request)
            response.headers["X-Elapsed"] = str(time.monotonic() - start)
            return response
    """
    found = _routes(tmp_path, {"main.py": main, "routes.py": SETTINGS_ROUTES})
    assert found == {"routes.py:/settings": Severity.HIGH}


def test_cors_and_rate_limit_middlewares_do_not_count(tmp_path):
    main = """\
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        app = FastAPI()


        @app.middleware("http")
        async def cors(request, call_next):
            origin = request.headers.get("origin")
            if origin and origin not in ALLOWED_ORIGINS:
                return JSONResponse({"detail": "origin"}, status_code=403)
            response = await call_next(request)
            response.headers["Access-Control-Allow-Origin"] = origin or "*"
            return response


        @app.middleware("http")
        async def rate_limit(request, call_next):
            if hits(request.client.host) > 100:
                return JSONResponse({"detail": "slow down"}, status_code=429)
            return await call_next(request)
    """
    found = _routes(tmp_path, {"main.py": main, "routes.py": SETTINGS_ROUTES})
    assert found == {"routes.py:/settings": Severity.HIGH}


def test_credential_read_without_a_rejection_does_not_count(tmp_path):
    main = """\
        from fastapi import FastAPI

        app = FastAPI()


        @app.middleware("http")
        async def attach_user(request, call_next):
            token = request.headers.get("Authorization")
            if token:
                request.state.user = lookup(token)
            return await call_next(request)
    """
    found = _routes(tmp_path, {"main.py": main, "routes.py": SETTINGS_ROUTES})
    assert found == {"routes.py:/settings": Severity.HIGH}


# --- path exemptions --------------------------------------------------------


def test_exempt_sensitive_path_stays_high(tmp_path):
    main = """\
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        PUBLIC_PATHS = {"/health", "/admin/export"}

        app = FastAPI()


        @app.middleware("http")
        async def guard(request, call_next):
            if request.url.path in PUBLIC_PATHS:
                return await call_next(request)
            if request.headers.get("x-api-key") != API_KEY:
                return JSONResponse({}, status_code=401)
            return await call_next(request)


        @app.get("/admin/export")
        async def export():
            return []


        @app.get("/admin/users")
        async def users():
            return []
    """
    found = _routes(tmp_path, {"main.py": main})
    assert found == {"main.py:/admin/export": Severity.HIGH, "main.py:/admin/users": Severity.INFO}


def test_exempt_prefix_and_router_prefix(tmp_path):
    main = """\
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        app = FastAPI()


        @app.middleware("http")
        async def guard(request, call_next):
            path = request.url.path
            if path == "/health" or path.startswith(("/api/public/", "/docs")):
                return await call_next(request)
            if not request.cookies.get("session"):
                return JSONResponse({}, status_code=401)
            return await call_next(request)
    """
    routes = """\
        from fastapi import APIRouter

        router = APIRouter()


        @router.get("/public/settings")
        async def public_settings():
            return {}


        @router.get("/settings")
        async def settings():
            return {}
    """
    found = _routes(tmp_path, {"main.py": main, "routes.py": routes})
    # The router is mounted under /api, so "/api/public/" also skips
    # "/public/settings" as declared on the router.
    assert found == {
        "routes.py:/public/settings": Severity.HIGH,
        "routes.py:/settings": Severity.INFO,
    }


def test_guard_applied_only_to_a_prefix(tmp_path):
    main = """\
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        app = FastAPI()


        @app.middleware("http")
        async def guard(request, call_next):
            if request.url.path.startswith("/api/"):
                if request.headers.get("authorization") is None:
                    return JSONResponse({}, status_code=401)
            return await call_next(request)


        @app.get("/api/users")
        async def users():
            return []


        @app.get("/admin/users")
        async def admin_users():
            return []
    """
    found = _routes(tmp_path, {"main.py": main})
    assert found == {"main.py:/api/users": Severity.INFO, "main.py:/admin/users": Severity.HIGH}


def test_unreadable_exemption_covers_nothing(tmp_path):
    main = """\
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        app = FastAPI()


        @app.middleware("http")
        async def guard(request, call_next):
            if request.url.path in load_public_paths():
                return await call_next(request)
            if request.headers.get("x-api-key") != API_KEY:
                return JSONResponse({}, status_code=401)
            return await call_next(request)
    """
    found = _routes(tmp_path, {"main.py": main, "routes.py": SETTINGS_ROUTES})
    assert found == {"routes.py:/settings": Severity.HIGH}


def test_guard_on_one_of_several_apps_covers_only_its_file(tmp_path):
    public = """\
        from fastapi import FastAPI

        public_app = FastAPI()


        @public_app.get("/settings")
        async def settings():
            return {}
    """
    found = _routes(tmp_path, {"main.py": API_KEY_MIDDLEWARE, "public.py": public})
    assert found == {"public.py:/settings": Severity.HIGH}


# --- Flask ------------------------------------------------------------------


def test_flask_before_request(tmp_path):
    app = """\
        from flask import Flask, abort, request, session

        app = Flask(__name__)


        @app.before_request
        def require_login():
            if request.endpoint in ("login", "static"):
                return None
            if "user_id" not in session:
                abort(401)
    """
    views = """\
        from flask import jsonify

        from .app import app


        @app.route("/admin/users")
        def list_users():
            return jsonify([])


        @app.route("/settings")
        def login():
            return jsonify({})
    """
    found = _routes(tmp_path, {"web/app.py": app, "web/views.py": views})
    # "/settings" is served by the exempt "login" endpoint.
    assert found == {
        "web/views.py:/admin/users": Severity.INFO,
        "web/views.py:/settings": Severity.HIGH,
    }


def test_flask_before_request_registered_by_call(tmp_path):
    app = """\
        from flask import Flask, request


        def check_token():
            if request.headers.get("X-Auth-Token") != TOKEN:
                return {"error": "unauthorized"}, 401


        app = Flask(__name__)
        app.before_request(check_token)


        @app.route("/admin/users")
        def users():
            return []
    """
    assert _routes(tmp_path, {"app.py": app}) == {"app.py:/admin/users": Severity.INFO}


def test_flask_blueprint_before_request_covers_only_the_blueprint(tmp_path):
    admin = """\
        from flask import Blueprint, abort
        from flask_login import current_user

        blueprint = Blueprint("admin", __name__)


        @blueprint.before_request
        def admin_only():
            if not current_user.is_authenticated:
                abort(403)


        @blueprint.route("/admin/users")
        def users():
            return []
    """
    app = """\
        from flask import Flask

        app = Flask(__name__)


        @app.route("/settings")
        def settings():
            return {}
    """
    found = _routes(tmp_path, {"admin.py": admin, "app.py": app})
    assert found == {"admin.py:/admin/users": Severity.INFO, "app.py:/settings": Severity.HIGH}


def test_flask_before_request_that_only_logs(tmp_path):
    app = """\
        from flask import Flask, request

        app = Flask(__name__)


        @app.before_request
        def log_request():
            app.logger.info("%s %s", request.method, request.path)


        @app.route("/admin/users")
        def users():
            return []
    """
    assert _routes(tmp_path, {"app.py": app}) == {"app.py:/admin/users": Severity.HIGH}


# --- Django -----------------------------------------------------------------

NINJA_API = """\
    from django.contrib.auth.decorators import login_not_required
    from ninja import NinjaAPI

    api = NinjaAPI()


    @api.get("/users")
    def users(request):
        return []


    @login_not_required
    @api.get("/settings")
    def settings(request):
        return {}


    @api.get("/accounts")
    def accounts(request):
        return []
"""


def test_django_login_required_middleware(tmp_path):
    settings = """\
        MIDDLEWARE = [
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django.contrib.auth.middleware.LoginRequiredMiddleware",
        ]
    """
    found = _routes(tmp_path, {"site/settings.py": settings, "site/api.py": NINJA_API})
    assert found == {
        "site/api.py:/users": Severity.INFO,
        "site/api.py:/settings": Severity.HIGH,
        "site/api.py:/accounts": Severity.INFO,
    }


def test_django_custom_middleware(tmp_path):
    settings = """\
        MIDDLEWARE = [
            "django.contrib.sessions.middleware.SessionMiddleware",
            "site.middleware.ApiKeyMiddleware",
        ]
    """
    middleware = """\
        from django.http import HttpResponseForbidden


        class ApiKeyMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response

            def __call__(self, request):
                if request.META.get("HTTP_X_API_KEY") != EXPECTED:
                    return HttpResponseForbidden()
                return self.get_response(request)
    """
    found = _routes(
        tmp_path,
        {
            "site/settings.py": settings,
            "site/middleware.py": middleware,
            "site/api.py": NINJA_API,
        },
    )
    assert found["site/api.py:/users"] == Severity.INFO


def test_django_middleware_without_auth_does_not_count(tmp_path):
    settings = """\
        MIDDLEWARE = [
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ]
    """
    found = _routes(tmp_path, {"site/settings.py": settings, "site/api.py": NINJA_API})
    assert set(found.values()) == {Severity.HIGH}


def test_hostile_python_does_not_break_the_scan(tmp_path):
    deep = "x = " + "(" * 5000 + ")" * 5000 + "\nmiddleware = 1\n"
    found = _routes(
        tmp_path,
        {"deep.py": deep, "broken.py": "@app.middleware('http'\n", "routes.py": SETTINGS_ROUTES},
    )
    assert found == {"routes.py:/settings": Severity.HIGH}


# --- method conditions ------------------------------------------------------


def _by_line(tmp_path: Path, files: dict[str, str]) -> dict[str, tuple[Severity, bool]]:
    """``"file:line"`` of each missing-authentication finding: (severity, fails_open)."""
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    return {
        f"{f.location.path.replace(chr(92), '/')}:{f.location.start_line}": (
            f.severity,
            bool(f.metadata.get("global_auth", {}).get("fails_open")),
        )
        for f in AuthzScanner().scan(ctx)
        if f.rule_id == RULE
    }


GUARDED_APP = """\
from fastapi import FastAPI
from fastapi.responses import JSONResponse

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

app = FastAPI()


@app.middleware("http")
async def guard(request, call_next):
{check}
    return await call_next(request)


@app.get("/settings")
async def read_settings():
    return {{}}


@app.put("/settings")
async def write_settings():
    return {{}}
"""


def _guarded(check: str) -> tuple[str, str, str]:
    """The app with ``check`` as the guard's body, and its GET and PUT route keys."""
    body = textwrap.indent(textwrap.dedent(check), " " * 4)
    text = GUARDED_APP.format(check=body.rstrip("\n"))
    lines = text.splitlines()
    get = lines.index('@app.get("/settings")') + 1
    put = lines.index('@app.put("/settings")') + 1
    return text, f"main.py:{get}", f"main.py:{put}"


def test_writes_only_guard_leaves_get_routes_high(tmp_path):
    text, get, put = _guarded(
        """\
        key = request.headers.get("x-api-key")
        if request.method != "GET" and key != API_KEY:
            return JSONResponse({}, status_code=401)
        """
    )
    found = _by_line(tmp_path, {"main.py": text})
    assert found == {get: (Severity.HIGH, False), put: (Severity.INFO, False)}


def test_guard_nested_under_a_method_constant(tmp_path):
    text, get, put = _guarded(
        """\
        if request.method in WRITE_METHODS:
            if not request.headers.get("authorization"):
                return JSONResponse({}, status_code=401)
        """
    )
    found = _by_line(tmp_path, {"main.py": text})
    assert found == {get: (Severity.HIGH, False), put: (Severity.INFO, False)}


def test_method_bypass_exempts_those_methods(tmp_path):
    text, get, put = _guarded(
        """\
        if request.method in ("GET", "HEAD"):
            return await call_next(request)
        if not request.cookies.get("session"):
            return JSONResponse({}, status_code=403)
        """
    )
    found = _by_line(tmp_path, {"main.py": text})
    assert found == {get: (Severity.HIGH, False), put: (Severity.INFO, False)}


def test_unreadable_method_condition_covers_nothing(tmp_path):
    text, get, put = _guarded(
        """\
        if request.method not in safe_methods() and not request.headers.get("x-api-key"):
            return JSONResponse({}, status_code=401)
        """
    )
    found = _by_line(tmp_path, {"main.py": text})
    assert found == {get: (Severity.HIGH, False), put: (Severity.HIGH, False)}


def test_preflight_bypass_still_covers_the_routes(tmp_path):
    text, get, put = _guarded(
        """\
        if request.method == "OPTIONS":
            return await call_next(request)
        if request.headers.get("x-api-key") != API_KEY:
            return JSONResponse({}, status_code=401)
        """
    )
    found = _by_line(tmp_path, {"main.py": text})
    assert found == {get: (Severity.INFO, False), put: (Severity.INFO, False)}


def test_method_test_that_also_needs_the_credential_is_not_a_skip(tmp_path):
    text, get, put = _guarded(
        """\
        token = request.headers.get("authorization")
        if request.method == "GET" and is_valid(token):
            return await call_next(request)
        if not is_valid(token):
            return JSONResponse({}, status_code=401)
        """
    )
    found = _by_line(tmp_path, {"main.py": text})
    assert found == {get: (Severity.INFO, False), put: (Severity.INFO, False)}


def test_asgi_scope_method(tmp_path):
    main = """\
        from fastapi import FastAPI


        class WriteGuard:
            def __init__(self, app):
                self.app = app

            async def __call__(self, scope, receive, send):
                headers = dict(scope["headers"])
                if scope["method"] not in ("GET", "HEAD") and not check_token(headers):
                    await send({"type": "http.response.start", "status": 401, "headers": []})
                    await send({"type": "http.response.body", "body": b""})
                    return
                await self.app(scope, receive, send)


        app = FastAPI()
        app.add_middleware(WriteGuard)
    """
    routes = """\
        from fastapi import APIRouter

        router = APIRouter()


        @router.get("/settings")
        async def read_settings():
            return {}


        @router.delete("/settings")
        async def reset_settings():
            return {}
    """
    found = _by_line(tmp_path, {"main.py": main, "routes.py": routes})
    assert found == {"routes.py:6": (Severity.HIGH, False), "routes.py:11": (Severity.INFO, False)}


def test_flask_route_methods(tmp_path):
    app = """\
        from flask import Flask, abort, request, session

        app = Flask(__name__)


        @app.before_request
        def writes_need_login():
            if request.method != "GET" and "user_id" not in session:
                abort(401)


        @app.route("/admin/users")
        def list_users():
            return []


        @app.route("/admin/users/new", methods=["POST"])
        def create_user():
            return {}


        @app.route("/admin/settings",
                   methods=["GET", "POST"])
        def admin_settings():
            return {}
    """
    found = _by_line(tmp_path, {"app.py": app})
    assert found == {
        "app.py:12": (Severity.HIGH, False),
        "app.py:17": (Severity.INFO, False),
        "app.py:22": (Severity.HIGH, False),
    }


# --- guards that fail open --------------------------------------------------


def test_guard_that_fails_open_is_flagged_in_the_note(tmp_path):
    text, get, put = _guarded(
        """\
        if not API_TOKEN:
            return await call_next(request)
        if request.headers.get("x-api-key") != API_TOKEN:
            return JSONResponse({}, status_code=401)
        """
    )
    found = _by_line(tmp_path, {"main.py": text})
    assert found == {get: (Severity.INFO, True), put: (Severity.INFO, True)}
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    note = next(f for f in AuthzScanner().scan(ctx) if f.rule_id == RULE)
    assert "allows every request when its credential is not configured" in note.description


def test_helper_that_fails_open(tmp_path):
    main = """\
        import hmac

        from fastapi import FastAPI


        class TokenGuard:
            def __init__(self, app):
                self.app = app

            def _authorized(self, headers):
                token = settings.token
                if not token:
                    return True
                return hmac.compare_digest(headers.get("authorization", ""), token)

            async def __call__(self, scope, receive, send):
                if not self._authorized(Headers(scope=scope)):
                    await send({"type": "http.response.start", "status": 401})
                    return
                await self.app(scope, receive, send)


        app = FastAPI()
        app.add_middleware(TokenGuard)
    """
    found = _by_line(tmp_path, {"main.py": main, "routes.py": SETTINGS_ROUTES})
    assert set(found.values()) == {(Severity.INFO, True)}


def test_auth_switch_counts_as_failing_open(tmp_path):
    text, _, _ = _guarded(
        """\
        if os.environ.get("AUTH_DISABLED") == "1":
            return await call_next(request)
        if request.headers.get("x-api-key") != API_TOKEN:
            return JSONResponse({}, status_code=401)
        """
    )
    found = _by_line(tmp_path, {"main.py": text})
    assert set(found.values()) == {(Severity.INFO, True)}


def test_guard_that_always_checks_does_not_fail_open(tmp_path):
    found = _by_line(
        tmp_path,
        {"app/main.py": API_KEY_MIDDLEWARE, "app/api/settings.py": SETTINGS_ROUTES},
    )
    assert set(found.values()) == {(Severity.INFO, False)}
