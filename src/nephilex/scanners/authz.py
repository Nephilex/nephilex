"""Authentication and authorization analysis (foundation).

Maps route/endpoint definitions to likely auth requirements and flags common
misconfigurations: missing auth on sensitive routes, weak JWT handling, and
routes that accept object IDs without obvious ownership checks nearby.
"""

from __future__ import annotations

import ast
import bisect
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners._text import MAX_SCAN_LINE, snippet_line
from nephilex.scanners.patterns import _is_test_file

_FASTAPI_ROUTE = re.compile(
    r"""@(?:app|router)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""",
)
_FLASK_ROUTE = re.compile(
    r"""@(?:app|blueprint)\.route\(\s*['"]([^'"]+)['"]""",
)
_EXPRESS_ROUTE = re.compile(
    r"""\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""",
)

_AUTH_DECORATORS = re.compile(
    r"@(?:login_required|requires_auth|authenticated|authorize|"
    r"permission_required|roles_required|Depends\([^)]*(?:auth|oauth|jwt|"
    r"get_current_user|Security))",
    re.IGNORECASE,
)
_JWT_WEAK = re.compile(
    r"jwt\.(?:decode|verify)\([^)]*(?:verify\s*=\s*False|algorithms\s*=\s*\[[^\]]*none)",
    re.IGNORECASE,
)
_JWT_NONE_ALG = re.compile(r"['\"]none['\"]", re.IGNORECASE)

_SENSITIVE_PATH = re.compile(
    r"/(?:admin|internal|manage|debug|users?|accounts?|billing|settings|"
    r"delete|export|backup|config|secrets?|tokens?|roles?|permissions?)(?:/|$)",
    re.IGNORECASE,
)
_ID_PARAM = re.compile(
    r"\{(\w*(?:id|uuid|user|account|tenant)\w*)\}|:(\w*(?:id|uuid)\w*)",
    re.IGNORECASE,
)
_OAUTH_STATE_MISSING = re.compile(
    r"(?:oauth|openid)[^;\n]{0,120}(?:callback|redirect)[^;\n]{0,80}(?:state|nonce)",
    re.IGNORECASE,
)
_SESSION_INSECURE = re.compile(
    r"(?:session|cookie)\.(?:set|cookie)\([^)]*(?:secure\s*=\s*False|httponly\s*=\s*False)",
    re.IGNORECASE,
)
# Flask/Werkzeug, Django, Starlette and aiohttp all spell it
# ``response.set_cookie(key, value, ..., secure=..., httponly=...)``.
_SET_COOKIE = re.compile(r"\.set_cookie\s*\(")
_DEF_SET_COOKIE = re.compile(r"\bdef\s+set_cookie\b")
_FLAG_KW = {
    "secure": re.compile(r"(?i)(?<![\w])secure\s*=\s*([\w.]+)"),
    "httponly": re.compile(r"(?i)(?<![\w])httponly\s*=\s*([\w.]+)"),
}
#: Longest call text gathered for one set_cookie(...) across lines.
_MAX_CALL_TEXT = 4000
_OAUTH_TOKEN_IN_URL = re.compile(
    r"https?://[^\s'\"]+(?:\?|&)(?:access_token|id_token|code)=[^&\s'\"]+"
    r"|(?:\?|&)(?:access_token|id_token|code)=[A-Za-z0-9._\-]{8,}",
    re.IGNORECASE,
)
_TOKEN_URL_SUPPRESS = re.compile(
    r"(?i)(?:detail\s*=|message\s*=|description\s*=|Field\(|example|"
    r"HTTPException|raise\s+\w|#|//|invalid|missing|required|error|"
    r"schema|openapi|swagger|\"access_token\"\s*:|'access_token'\s*:)",
)
_PUBLIC_ROUTE = re.compile(
    r"/(?:login|signin|signout|logout|signup|register|forgot|reset|password|"
    r"verification|verify|callback|oauth|refresh|health|docs|openapi|swagger|"
    r"redoc|static|assets|favicon|metrics|probe)(?:/|$)",
    re.IGNORECASE,
)
_ROUTER_CALL = re.compile(r"APIRouter\s*\(", re.IGNORECASE)
_ROUTER_DEPS_KEY = re.compile(r"dependencies\s*=\s*\[", re.IGNORECASE)
_OWNERSHIP_HINT = re.compile(
    r"(owner|tenant|user_id|account_id|current_user|request\.user|"
    r"get_current_user|authorize|permission|forbidden|403)",
    re.IGNORECASE,
)


def _has_router_auth(text: str) -> bool:
    """True if some `APIRouter(` is followed by `dependencies=[` before any `)`,
    with `Depends` appearing before the list's closing `]`.

    This used to be one DOTALL regex over the whole file, which backtracked
    across the rest of the file for every unterminated `APIRouter(` (cubic on a
    hostile file). Here every token is located once and the ordering
    conditions are checked with binary search, so the cost is O(n log n).
    """
    calls = [m.end() for m in _ROUTER_CALL.finditer(text)]
    if not calls:
        return False
    closes = [m.start() for m in re.finditer(r"\)", text)]
    brackets = [m.start() for m in re.finditer(r"\]", text)]
    depends = [m.start() for m in re.finditer(r"(?i)Depends", text)]
    for key in _ROUTER_DEPS_KEY.finditer(text):
        # Nearest preceding APIRouter( call, with no `)` between it and the key.
        ci = bisect.bisect_right(calls, key.start()) - 1
        if ci < 0:
            continue
        pi = bisect.bisect_left(closes, calls[ci])
        if pi < len(closes) and closes[pi] < key.start():
            continue
        # `Depends` before the first `]` after the opening bracket.
        bi = bisect.bisect_left(brackets, key.end())
        limit = brackets[bi] if bi < len(brackets) else len(text)
        di = bisect.bisect_left(depends, key.end())
        if di < len(depends) and depends[di] + len("Depends") <= limit:
            return True
    return False


def _call_text(lines: list[str], idx: int, start: int) -> str:
    """Text of the call starting at ``lines[idx][start:]`` up to its closing ``)``.

    Bounded by :data:`_MAX_CALL_TEXT` characters and 40 lines; parentheses inside
    single-line string literals are ignored. Linear in the text it reads.
    """
    out: list[str] = []
    depth = 0
    seen = 0
    for li in range(idx, min(len(lines), idx + 40)):
        segment = lines[li][start:] if li == idx else lines[li]
        quote = ""
        for ch in segment:
            seen += 1
            if seen > _MAX_CALL_TEXT:
                return "".join(out)
            out.append(ch)
            if quote:
                if ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth <= 0:
                    return "".join(out)
        out.append("\n")
    return "".join(out)


def _top_level_commas(call: str) -> int:
    """Commas between the outer parentheses of ``call``, outside nested brackets/strings."""
    depth = 0
    quote = ""
    count = 0
    for ch in call:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 1:
            count += 1
    return count


def _receiver_start(line: str, pos: int) -> int:
    """Start of the dotted receiver ending at ``pos`` (``resp`` in ``resp.set_cookie``)."""
    while pos > 0 and (line[pos - 1].isalnum() or line[pos - 1] in "_."):
        pos -= 1
    return pos


def _flag_state(value: str | None) -> str:
    """``missing``, ``on``, ``off`` or ``unknown`` for a keyword's source text."""
    if value is None:
        return "missing"
    if value in ("True", "1"):
        return "on"
    if value in ("False", "0", "None"):
        return "off"
    return "unknown"


def _lines(text: str) -> list[str]:
    # Lines are cut to the shared scan limit: the route and JWT checks below
    # run on them and on windows of them, and none needs more than that.
    return [line[:MAX_SCAN_LINE] for line in text.splitlines()]


def _window(lines: list[str], idx: int, before: int = 8, after: int = 12) -> str:
    start = max(0, idx - before)
    end = min(len(lines), idx + after + 1)
    return "\n".join(lines[start:end])


def _route_path(line: str) -> str | None:
    m = _FASTAPI_ROUTE.search(line)
    if m:
        return m.group(2)
    m = _FLASK_ROUTE.search(line)
    if m:
        return m.group(1)
    m = _EXPRESS_ROUTE.search(line)
    if m:
        return m.group(2)
    return None


# --- project-wide authentication -------------------------------------------
#
# A route with no auth of its own is often protected by something registered
# once for the whole application: an HTTP middleware, app- or router-level
# dependencies, a Flask before_request hook, or a Django middleware. The pass
# below finds those guards with the ``ast`` module and decides which routes
# each one covers. A guard counts only if it reads a credential (a credential
# header, a cookie, the session, a token) and rejects with 401 or 403 when the
# check fails; a middleware that logs, sets CORS headers or rate-limits does
# not. Paths the guard skips (``if request.url.path == "/health": ...``) stay
# unprotected, and a guard whose skip list cannot be read covers nothing.

#: Files worth parsing for guard registrations.
_GUARD_TRIGGER = re.compile(
    r"middleware|MIDDLEWARE|before_(?:app_)?request|dependencies\s*=|include_router"
)
_FASTAPI_APP = re.compile(r"\b(?:FastAPI|Starlette)\s*\(")
_FLASK_APP = re.compile(r"\bFlask\s*\(")
_IMPORTS_FASTAPI = re.compile(r"(?m)^\s*(?:from|import)\s+(?:fastapi|starlette)\b")
_IMPORTS_FLASK = re.compile(r"(?m)^\s*(?:from|import)\s+flask\b")
_IMPORTS_DJANGO = re.compile(r"(?m)^\s*(?:from|import)\s+(?:django|ninja|rest_framework)\b")
_ROUTE_RECEIVER = re.compile(r"^\s*@\s*(?:[\w.]+\.)?(\w+)\.\w+\s*\(")
_HANDLER_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")
_LOGIN_NOT_REQUIRED = re.compile(r"@\s*(?:[\w.]+\.)?login_not_required\b")
_AUTH_MIXINS = re.compile(r"\b(?:LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin)\b")

#: Header, cookie and parameter names that carry a credential.
_CRED_LITERAL = re.compile(
    r"(?i)authori[sz]ation|api[-_]?key|x-api|token|session|cookie|bearer|jwt|secret|"
    r"password|credential|\bauth"
)
#: Variable names that hold a credential or a credential header's name.
_CRED_IDENT = re.compile(r"(?i)key|token|auth|secret|session|cookie|credential|header|bearer")
#: Calls that check a credential.
_CRED_CALL = re.compile(
    r"(?i)auth|token|jwt|api_?key|credential|session|login|passw|signature|"
    r"compare_digest|bearer|principal|identity|current_user"
)
#: Dependency callables that look like authentication.
_AUTH_DEP_NAME = re.compile(
    r"(?i)auth|user|token|api_?key|login|jwt|permission|scope|security|guard|session|"
    r"principal|identity|credential|require|protect|admin|bearer|verify"
)
_CRED_ATTRS = frozenset(
    {"cookies", "session", "authorization", "auth", "user", "is_authenticated", "credentials"}
)
#: Request mappings a credential is read from by name (``META`` is Django's).
_CRED_SOURCES = frozenset({"headers", "META", "query_params", "args", "params"})
_REJECT_NAMES = frozenset(
    {
        "HTTP_401_UNAUTHORIZED",
        "HTTP_403_FORBIDDEN",
        "UNAUTHORIZED",
        "FORBIDDEN",
        "Unauthorized",
        "Forbidden",
        "HttpResponseForbidden",
        "PermissionDenied",
        "NotAuthenticated",
        "AuthenticationFailed",
        "HTTPUnauthorized",
        "HTTPForbidden",
    }
)
_PATH_ATTRS = frozenset({"path", "path_info", "endpoint", "url_rule"})
_PATH_MODULES = frozenset({"os", "posixpath", "ntpath", "sys", "pathlib"})
_GUARD_METHODS = ("dispatch", "__call__", "process_request", "process_view")
_MAX_PARSE_CHARS = 2_000_000

_Func = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class _PathRule:
    """Paths a guard skips (``exempt``) or the only paths it checks (``only``)."""

    mode: str
    exact: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()
    endpoints: frozenset[str] = frozenset()

    def matches(self, route: str, handler: str | None) -> bool:
        if handler and any(e == handler or e.endswith("." + handler) for e in self.endpoints):
            return True
        route = route.rstrip("/") or "/"
        loose = self.mode == "exempt"  # err towards reporting
        for value in self.exact:
            value = value.rstrip("/") or "/"
            if value == route or (loose and route != "/" and value.endswith(route)):
                return True
        for prefix in self.prefixes:
            if route.startswith(prefix) or (prefix.rstrip("/") or "/") == route:
                return True
            if loose:
                # The route may be declared relative to a router prefix that
                # the middleware sees: "/api/public" also skips "/public/...".
                parts = [p for p in prefix.split("/") if p]
                for k in range(1, len(parts)):
                    tail = "/" + "/".join(parts[k:])
                    if route.startswith(tail):
                        return True
        return False


@dataclass(frozen=True)
class _Guard:
    """Authentication registered once and applied to many routes."""

    kind: str
    framework: str
    path: str
    line: int
    #: Files whose routes it covers; None for every file of its framework.
    files: frozenset[str] | None = None
    #: Only routes declared on this object (a blueprint or a router).
    receiver: str | None = None
    rules: tuple[_PathRule, ...] = ()

    def covers(self, route: str, handler: str | None) -> bool:
        for rule in self.rules:
            hit = rule.matches(route, handler)
            if rule.mode == "exempt" and hit:
                return False
            if rule.mode == "only" and not hit:
                return False
        return True


def _call_name(node: ast.AST) -> str:
    """``Depends`` for ``Depends(...)`` and ``fastapi.Depends(...)``; ``""`` otherwise."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _str_const(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("latin-1")
    return None


def _name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


class _Index:
    """Parsed non-test Python modules of the project, parsed on first use."""

    def __init__(self, files: Sequence[Any]) -> None:
        self.texts: dict[str, str] = {}
        for f in files:
            text = f.text()
            if text and len(text) <= _MAX_PARSE_CHARS:
                self.texts[f.rel_path.replace("\\", "/")] = text
        self._trees: dict[str, ast.Module | None] = {}

    def tree(self, rel: str) -> ast.Module | None:
        if rel not in self._trees:
            try:
                self._trees[rel] = ast.parse(self.texts[rel])
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                self._trees[rel] = None
        return self._trees[rel]

    def _defs(self, needle: str, kinds: tuple[type, ...], name: str) -> Iterator[tuple[str, Any]]:
        for rel, text in self.texts.items():
            if needle not in text:
                continue
            tree = self.tree(rel)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if isinstance(node, kinds) and getattr(node, "name", None) == name:
                    yield rel, node

    def classes(self, name: str) -> list[tuple[str, ast.ClassDef]]:
        return list(self._defs(f"class {name}", (ast.ClassDef,), name))

    def functions(self, name: str, prefer: str) -> list[tuple[str, _Func]]:
        found = list(self._defs(f"def {name}", (ast.FunctionDef, ast.AsyncFunctionDef), name))
        local = [d for d in found if d[0] == prefer]
        return local or found

    def constant(self, name: str, prefer: str) -> ast.expr | None:
        """The value of a module-level ``NAME = ...``, preferring ``prefer``'s."""
        found: list[ast.expr] = []
        for rel in [prefer] + [r for r in self.texts if r != prefer]:
            if name not in self.texts.get(rel, ""):
                continue
            tree = self.tree(rel)
            if tree is None:
                continue
            for stmt in tree.body:
                targets: list[ast.expr] = []
                value: ast.expr | None = None
                if isinstance(stmt, ast.Assign):
                    targets, value = stmt.targets, stmt.value
                elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                    targets, value = [stmt.target], stmt.value
                if value is not None and any(_name_of(t) == name for t in targets):
                    found.append(value)
            if found and rel == prefer:
                return found[-1]
        return found[0] if len(found) == 1 else None

    def module_files(self, dotted: str) -> list[str]:
        """Project files a dotted module path (``app.api.settings``) may name."""
        tail = dotted.strip(".").replace(".", "/")
        if not tail:
            return []
        out = []
        for rel in self.texts:
            stem = rel[:-3] if rel.endswith(".py") else rel
            stem = stem[: -len("/__init__")] if stem.endswith("/__init__") else stem
            if stem == tail or stem.endswith("/" + tail):
                out.append(rel)
        return out


def _strings(node: ast.AST | None, index: _Index, rel: str, depth: int = 0) -> list[str] | None:
    """String values of a literal collection, a constant or a name bound to one."""
    if node is None or depth > 3:
        return None
    s = _str_const(node)
    if s is not None:
        return [s]
    if isinstance(node, ast.Set | ast.List | ast.Tuple):
        out: list[str] = []
        for elt in node.elts:
            vals = _strings(elt, index, rel, depth + 1)
            if vals is None:
                return None
            out.extend(vals)
        return out
    if isinstance(node, ast.Call) and _call_name(node) in ("frozenset", "set", "tuple", "list"):
        if len(node.args) == 1 and not node.keywords:
            return _strings(node.args[0], index, rel, depth + 1)
        return None
    if isinstance(node, ast.Name | ast.Attribute):
        return _strings(index.constant(_name_of(node), rel), index, rel, depth + 1)
    return None


class _GuardFunction:
    """Reads one middleware or hook function: does it authenticate, and where."""

    def __init__(self, fn: _Func, index: _Index, rel: str, cls: ast.ClassDef | None = None):
        self.fn = fn
        self.index = index
        self.rel = rel
        self.class_consts: dict[str, ast.expr] = {}
        if cls is not None:
            for stmt in cls.body:
                if isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name):
                            self.class_consts[t.id] = stmt.value
        params = [a.arg for a in fn.args.args]
        if params and params[0] == "self":
            params = params[1:]
        #: ``call_next`` in a Starlette middleware.
        self.next_names = {"call_next"} | ({params[1]} if len(params) > 1 else set())
        self.cred_names = self._bound_names(self._reads_credential)
        self.path_names = self._bound_names(self._is_path_expr)

    # -- what the function reads ------------------------------------------

    def _bound_names(self, pred: Any) -> set[str]:
        """Names assigned from an expression for which ``pred`` holds (to a fixpoint)."""
        names: set[str] = set()
        for _ in range(3):
            before = len(names)
            for node in ast.walk(self.fn):
                value: ast.expr | None = None
                targets: list[ast.expr] = []
                if isinstance(node, ast.Assign):
                    value, targets = node.value, node.targets
                elif isinstance(node, ast.AnnAssign | ast.NamedExpr) and node.value is not None:
                    value, targets = node.value, [node.target]
                if value is None or not (pred(value) or self._uses(value, names)):
                    continue
                for t in targets:
                    for sub in ast.walk(t):
                        if isinstance(sub, ast.Name):
                            names.add(sub.id)
            if len(names) == before:
                break
        return names

    @staticmethod
    def _uses(node: ast.AST, names: set[str]) -> bool:
        return bool(names) and any(
            isinstance(n, ast.Name) and n.id in names for n in ast.walk(node)
        )

    def _reads_credential(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and sub.attr in _CRED_ATTRS:
                return True
            if isinstance(sub, ast.Name) and sub.id in ("session", "current_user"):
                return True
            key: ast.AST | None = None
            receiver: ast.AST | None = None
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                if _CRED_CALL.search(sub.func.attr):
                    return True
                if sub.func.attr == "get" and sub.args:
                    key, receiver = sub.args[0], sub.func.value
            elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                if _CRED_CALL.search(sub.func.id):
                    return True
            elif isinstance(sub, ast.Subscript):
                key, receiver = sub.slice, sub.value
            if key is None or receiver is None:
                continue
            literal = _str_const(key)
            from_headers = _name_of(receiver) in _CRED_SOURCES
            if literal is not None and _CRED_LITERAL.search(literal) and from_headers:
                return True
            if literal is None and from_headers and _CRED_IDENT.search(_name_of(key)):
                return True
        return False

    def _credential_test(self, node: ast.AST) -> bool:
        return self._reads_credential(node) or self._uses(node, self.cred_names)

    def _is_path_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # request.url.path.rstrip("/"), request.path.lower()
            if node.func.attr in ("rstrip", "strip", "lower", "casefold"):
                return self._is_path_expr(node.func.value)
            return False
        if isinstance(node, ast.Attribute) and node.attr in _PATH_ATTRS:
            # request.url.path, request.path, request.endpoint; not os.path.
            return not (isinstance(node.value, ast.Name) and node.value.id in _PATH_MODULES)
        if isinstance(node, ast.Subscript) and _str_const(node.slice) == "path":
            return True
        return isinstance(node, ast.Name) and node.id in getattr(self, "path_names", ())

    def _is_endpoint_expr(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Attribute) and node.attr == "endpoint"

    def _mentions_path(self, node: ast.AST) -> bool:
        return any(self._is_path_expr(n) for n in ast.walk(node))

    # -- what the function does -------------------------------------------

    @staticmethod
    def _rejects(stmts: list[ast.stmt]) -> bool:
        """Some statement answers 401/403 and the block leaves (return, raise, abort)."""
        marker = leaves = False
        for stmt in stmts:
            for sub in ast.walk(stmt):
                marker = marker or _is_reject_marker(sub)
                leaves = leaves or isinstance(sub, ast.Return | ast.Raise)
                leaves = leaves or (
                    isinstance(sub, ast.Call) and _call_name(sub) in ("abort", "send")
                )
        return marker and leaves

    def _passes(self, stmts: list[ast.stmt]) -> bool:
        """The block hands the request on: ``call_next``, ``get_response``, or ``return``."""
        for stmt in stmts:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call):
                    name = _call_name(sub)
                    if name in self.next_names or name in ("get_response", "app"):
                        return True
                if isinstance(sub, ast.Return) and (
                    sub.value is None
                    or (isinstance(sub.value, ast.Constant) and sub.value.value is None)
                ):
                    return True
        return False

    def _blocks(self) -> Iterator[list[ast.stmt]]:
        for node in ast.walk(self.fn):
            for field_name in ("body", "orelse", "finalbody"):
                block = getattr(node, field_name, None)
                if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
                    yield block
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    yield handler.body

    def authenticates(self, depth: int = 0) -> bool:
        for block in self._blocks():
            for pos, stmt in enumerate(block):
                if isinstance(stmt, ast.If) and self._credential_test(stmt.test):
                    if self._rejects(stmt.body) or self._rejects(stmt.orelse):
                        return True
                    # if valid: return await call_next(request)
                    # return JSONResponse(status_code=401)
                    if self._passes(stmt.body) and self._rejects(block[pos + 1 :]):
                        return True
                if (
                    isinstance(stmt, ast.Try)
                    and any(self._credential_test(s) for s in stmt.body)
                    and any(self._rejects(h.body) for h in stmt.handlers)
                ):
                    return True
                if depth == 0 and self._calls_auth_helper(stmt):
                    return True
        return False

    def _calls_auth_helper(self, stmt: ast.stmt) -> bool:
        """``await verify_api_key(request)`` where that function rejects itself."""
        if not isinstance(stmt, ast.Expr | ast.Assign):
            return False
        call = stmt.value
        if isinstance(call, ast.Await):
            call = call.value
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            return False
        for rel, fn in self.index.functions(call.func.id, self.rel)[:3]:
            if fn is not self.fn and _GuardFunction(fn, self.index, rel).authenticates(depth=1):
                return True
        return False

    # -- which paths it skips ---------------------------------------------

    def path_rules(self) -> tuple[tuple[_PathRule, ...], bool]:
        """Skip rules from ``if <path test>:`` branches, and whether any was unreadable."""
        rules: list[_PathRule] = []
        unresolved = False
        for node in ast.walk(self.fn):
            if not isinstance(node, ast.If) or not self._mentions_path(node.test):
                continue
            bypass = self._passes(node.body) and not self._rejects(node.body)
            checks = self._rejects(node.body) or any(
                isinstance(s, ast.If) and self._credential_test(s.test)
                for b in node.body
                for s in ast.walk(b)
            )
            if not bypass and not checks:
                continue  # a path test that does something else (logging, metrics)
            pred = self._predicate(node.test)
            if pred is None:
                unresolved = True
                continue
            negated, exact, prefixes, endpoints = pred
            skips_when_true = bypass
            mode = "exempt" if skips_when_true != negated else "only"
            rules.append(_PathRule(mode, frozenset(exact), tuple(prefixes), frozenset(endpoints)))
        return tuple(rules), unresolved

    def _values(self, node: ast.AST) -> list[str] | None:
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and node.attr in self.class_consts
        ):
            return _strings(self.class_consts[node.attr], self.index, self.rel)
        if isinstance(node, ast.Name):
            # A local assignment in the function wins over a module constant.
            for sub in ast.walk(self.fn):
                if isinstance(sub, ast.Assign) and any(_name_of(t) == node.id for t in sub.targets):
                    return _strings(sub.value, self.index, self.rel)
        return _strings(node, self.index, self.rel)

    def _predicate(self, node: ast.AST) -> tuple[bool, list[str], list[str], list[str]] | None:
        """``(negated, exact, prefixes, endpoints)``: the test is "path is one of these"
        (or, when negated, "path is none of these"). None when it cannot be read."""
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            inner = self._predicate(node.operand)
            return None if inner is None else (not inner[0], *inner[1:])
        if isinstance(node, ast.BoolOp):
            parts = [v for v in node.values if self._mentions_path(v)]
            preds = [self._predicate(v) for v in parts]
            if not preds or any(p is None for p in preds):
                return None
            negs = {p[0] for p in preds if p is not None}
            if len(negs) != 1:
                return None
            negated = negs.pop()
            # "a or b" of positives and "not a and not b" both read as one set.
            if len(preds) > 1 and isinstance(node.op, ast.And) != negated:
                return None
            exact: list[str] = []
            prefixes: list[str] = []
            endpoints: list[str] = []
            for p in preds:
                if p is not None:
                    exact += p[1]
                    prefixes += p[2]
                    endpoints += p[3]
            return negated, exact, prefixes, endpoints
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, op, right = node.left, node.ops[0], node.comparators[0]
            if not self._is_path_expr(left):
                if isinstance(op, ast.Eq | ast.NotEq) and self._is_path_expr(right):
                    left, right = right, left
                else:
                    return None
            vals = self._values(right)
            if vals is None:
                return None
            negated = isinstance(op, ast.NotEq | ast.NotIn)
            if not isinstance(op, ast.Eq | ast.NotEq | ast.In | ast.NotIn):
                return None
            if self._is_endpoint_expr(left):
                return negated, [], [], vals
            return negated, vals, [], []
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "startswith" and self._is_path_expr(node.func.value):
                vals = self._values(node.args[0]) if len(node.args) == 1 else None
                return None if vals is None else (False, [], vals, [])
            return None
        if (
            isinstance(node, ast.Call)
            and _call_name(node) == "any"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.GeneratorExp)
        ):
            gen = node.args[0]
            elt, comps = gen.elt, gen.generators
            if (
                len(comps) == 1
                and isinstance(elt, ast.Call)
                and isinstance(elt.func, ast.Attribute)
                and elt.func.attr == "startswith"
                and self._is_path_expr(elt.func.value)
            ):
                vals = self._values(comps[0].iter)
                return None if vals is None else (False, [], vals, [])
        return None


def _guard_from_function(
    fn: _Func,
    index: _Index,
    rel: str,
    cls: ast.ClassDef | None = None,
) -> tuple[_PathRule, ...] | None:
    """Path rules of an authenticating guard function, or None if it is not one."""
    reader = _GuardFunction(fn, index, rel, cls)
    if not reader.authenticates():
        return None
    rules, unresolved = reader.path_rules()
    if unresolved:
        return None  # cannot tell which routes it skips, so it covers none
    return rules


def _guard_from_class(
    name: str, index: _Index, module_hint: str = ""
) -> tuple[_PathRule, ...] | None:
    """Path rules of a middleware class that authenticates, or None."""
    candidates = index.classes(name)
    if module_hint:
        hinted = [c for c in candidates if c[0] in index.module_files(module_hint)]
        candidates = hinted or candidates
    for rel, cls in candidates:
        for stmt in cls.body:
            if (
                isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef)
                and stmt.name in _GUARD_METHODS
            ):
                rules = _guard_from_function(stmt, index, rel, cls)
                if rules is not None:
                    return rules
    return None


def _auth_dependency(node: ast.AST, index: _Index, rel: str) -> bool:
    """``Depends(get_current_user)`` or ``Security(...)`` that looks like authentication."""
    if not isinstance(node, ast.Call):
        return False
    name = _call_name(node)
    if name == "Security":
        return True
    if name != "Depends" or not node.args:
        return False
    target = _name_of(node.args[0])
    if not target:
        return False
    if _AUTH_DEP_NAME.search(target):
        return True
    for frel, fn in index.functions(target, rel)[:3]:
        if _GuardFunction(fn, index, frel).authenticates():
            return True
        for default in [*fn.args.defaults, *fn.args.kw_defaults]:
            if default is not None and _auth_dependency(default, index, frel):
                return True
    return False


def _deps_keyword(call: ast.Call, index: _Index, rel: str) -> bool:
    for kw in call.keywords:
        if kw.arg == "dependencies" and isinstance(kw.value, ast.List | ast.Tuple):
            return any(_auth_dependency(e, index, rel) for e in kw.value.elts)
    return False


def _resolve_router(
    arg: ast.AST, tree: ast.Module, index: _Index, rel: str
) -> tuple[list[str], str]:
    """Files and object name of the router passed to ``include_router``."""
    if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
        module_alias, attr = arg.value.id, arg.attr
    elif isinstance(arg, ast.Name):
        module_alias, attr = "", arg.id
    else:
        return [], ""
    package = rel.split("/")[:-1]
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.ImportFrom):
            base = stmt.module or ""
            if stmt.level:
                parent = package[: len(package) - (stmt.level - 1)] if stmt.level > 1 else package
                base = ".".join([*parent, *([base] if base else [])])
            for alias in stmt.names:
                bound = alias.asname or alias.name
                if module_alias and bound == module_alias:
                    return index.module_files(base + "." + alias.name), attr
                if not module_alias and bound == attr:
                    return index.module_files(base), alias.name
        elif isinstance(stmt, ast.Import) and module_alias:
            for alias in stmt.names:
                if (alias.asname or alias.name) == module_alias:
                    return index.module_files(alias.name), attr
    if not module_alias:
        return [rel], attr  # a router defined in this module
    return [], attr


def _find_guards(files: Sequence[Any]) -> list[_Guard]:
    """Every project-wide authentication guard in the project's Python files."""
    index = _Index(files)
    guards: list[_Guard] = []
    for rel, text in index.texts.items():
        if not _GUARD_TRIGGER.search(text):
            continue
        tree = index.tree(rel)
        if tree is None:
            continue
        blueprints = {
            _name_of(t)
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign) and _call_name(node.value) == "Blueprint"
            for t in node.targets
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                guards.extend(_decorated_guards(node, index, rel, blueprints))
            elif isinstance(node, ast.Call):
                guards.extend(_called_guards(node, tree, index, rel, blueprints))
            elif isinstance(node, ast.Assign | ast.AugAssign):
                guards.extend(_django_guards(node, index, rel))
    return guards


def _decorated_guards(fn: _Func, index: _Index, rel: str, blueprints: set[str]) -> list[_Guard]:
    out: list[_Guard] = []
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if not isinstance(target, ast.Attribute):
            continue
        owner = _name_of(target.value)
        if target.attr == "middleware" and isinstance(dec, ast.Call):
            if not dec.args or _str_const(dec.args[0]) != "http":
                continue
            rules = _guard_from_function(fn, index, rel)
            if rules is not None:
                out.append(_Guard("HTTP middleware", "fastapi", rel, fn.lineno, rules=rules))
        elif target.attr in ("before_request", "before_app_request"):
            rules = _guard_from_function(fn, index, rel)
            if rules is None:
                continue
            if target.attr == "before_request" and owner in blueprints:
                out.append(
                    _Guard(
                        "blueprint before_request hook",
                        "flask",
                        rel,
                        fn.lineno,
                        files=frozenset({rel}),
                        receiver=owner,
                        rules=rules,
                    )
                )
            else:
                out.append(_Guard("before_request hook", "flask", rel, fn.lineno, rules=rules))
    return out


def _called_guards(
    call: ast.Call, tree: ast.Module, index: _Index, rel: str, blueprints: set[str]
) -> list[_Guard]:
    name = _call_name(call)
    line = call.lineno
    if name in ("FastAPI", "Starlette"):
        out = []
        if _deps_keyword(call, index, rel):
            out.append(_Guard("application dependencies", "fastapi", rel, line))
        for kw in call.keywords:
            if kw.arg == "middleware" and isinstance(kw.value, ast.List | ast.Tuple):
                for item in kw.value.elts:
                    if (
                        isinstance(item, ast.Call)
                        and _call_name(item) == "Middleware"
                        and item.args
                    ):
                        rules = _guard_from_class(_name_of(item.args[0]), index)
                        if rules is not None:
                            out.append(
                                _Guard(
                                    "authentication middleware", "fastapi", rel, line, rules=rules
                                )
                            )
        return out
    if name == "add_middleware" and call.args:
        rules = _guard_from_class(_name_of(call.args[0]), index)
        if rules is not None:
            return [_Guard("authentication middleware", "fastapi", rel, line, rules=rules)]
        return []
    if name == "include_router" and call.args and _deps_keyword(call, index, rel):
        files, receiver = _resolve_router(call.args[0], tree, index, rel)
        if files:
            return [
                _Guard(
                    "include_router dependencies",
                    "fastapi",
                    rel,
                    line,
                    files=frozenset(files),
                    receiver=receiver or None,
                )
            ]
        return []
    if name in ("before_request", "before_app_request") and call.args:
        owner = _name_of(call.func.value) if isinstance(call.func, ast.Attribute) else ""
        target = _name_of(call.args[0])
        for frel, fn in index.functions(target, rel)[:1]:
            rules = _guard_from_function(fn, index, frel)
            if rules is None:
                continue
            if name == "before_request" and owner in blueprints:
                return [
                    _Guard(
                        "blueprint before_request hook",
                        "flask",
                        rel,
                        line,
                        files=frozenset({rel}),
                        receiver=owner,
                        rules=rules,
                    )
                ]
            return [_Guard("before_request hook", "flask", rel, line, rules=rules)]
    return []


def _django_guards(node: ast.Assign | ast.AugAssign, index: _Index, rel: str) -> list[_Guard]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    if not any(_name_of(t) in ("MIDDLEWARE", "MIDDLEWARE_CLASSES") for t in targets):
        return []
    entries = _strings(node.value, index, rel) or []
    for dotted in entries:
        module, _, cls_name = dotted.rpartition(".")
        if cls_name == "LoginRequiredMiddleware":
            return [_Guard("LoginRequiredMiddleware", "django", rel, node.lineno)]
        rules = _guard_from_class(cls_name, index, module)
        if rules is not None:
            return [_Guard(f"{cls_name} middleware", "django", rel, node.lineno, rules=rules)]
    return []


class _GlobalAuth:
    """Which routes the project's guards cover."""

    def __init__(self, files: Sequence[Any]) -> None:
        py = [f for f in files if f.suffix == ".py" and not _is_test_file(f.rel_path)]
        self.guards = _find_guards(py) if any(_GUARD_TRIGGER.search(f.text()) for f in py) else []
        self._frameworks: dict[str, set[str]] = {}
        apps = {"fastapi": 0, "flask": 0}
        for f in py:
            text = f.text()
            rel = f.rel_path.replace("\\", "/")
            fw = set()
            if _IMPORTS_FASTAPI.search(text):
                fw.add("fastapi")
            if _IMPORTS_FLASK.search(text):
                fw.add("flask")
            if _IMPORTS_DJANGO.search(text):
                fw.add("django")
            self._frameworks[rel] = fw
            apps["fastapi"] += len(_FASTAPI_APP.findall(text))
            apps["flask"] += len(_FLASK_APP.findall(text))
        #: With several applications, an app-wide guard covers only its own file.
        self._single_app = {fw: n <= 1 for fw, n in apps.items()}
        self._single_app["django"] = True

    def _in_scope(self, guard: _Guard, rel: str) -> bool:
        if guard.files is not None:
            return rel in guard.files
        if guard.framework not in self._frameworks.get(rel, set()):
            return False
        # With several applications, an app-wide guard covers only its own file.
        return self._single_app.get(guard.framework, True) or rel == guard.path

    def guard_for(
        self, rel: str, route: str, handler: str | None, receiver: str | None, decorators: str
    ) -> _Guard | None:
        rel = rel.replace("\\", "/")
        for guard in self.guards:
            if not self._in_scope(guard, rel):
                continue
            if guard.receiver and receiver and receiver != guard.receiver:
                continue
            if guard.framework == "django" and _LOGIN_NOT_REQUIRED.search(decorators):
                continue
            if guard.covers(route, handler):
                return guard
        return None


def _is_reject_marker(node: ast.AST) -> bool:
    """A 401/403 status or a framework's unauthorized/forbidden name."""
    if isinstance(node, ast.Constant):
        return node.value in (401, 403) and not isinstance(node.value, bool)
    return isinstance(node, ast.Name | ast.Attribute) and _name_of(node) in _REJECT_NAMES


def _route_meta(lines: list[str], idx: int) -> tuple[str | None, str | None, str]:
    """The object a route is declared on, its handler's name and its decorator lines."""
    m = _ROUTE_RECEIVER.match(lines[idx])
    receiver = m.group(1) if m else None
    start = idx
    while start > 0 and idx - start < 10 and lines[start - 1].lstrip().startswith("@"):
        start -= 1
    handler = None
    end = idx + 1
    for end in range(idx + 1, min(len(lines), idx + 12)):
        h = _HANDLER_DEF.match(lines[end])
        if h:
            handler = h.group(1)
            break
    return receiver, handler, "\n".join(lines[start:end])


@scanner
class AuthzScanner(Scanner):
    name = "authz"
    category = "auth"
    description = "Analyzes authentication/authorization patterns on routes and JWT usage."

    def applies_to(self, project) -> bool:
        exts = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs")
        return any(f.suffix in exts for f in project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        global_auth = _GlobalAuth(ctx.project.files())
        for f in ctx.project.files():
            if f.suffix not in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"):
                continue
            if _is_test_file(f.rel_path):
                continue
            text = f.text()
            lines = _lines(text)
            file_has_router_auth = _has_router_auth(text)
            for i, line in enumerate(lines):
                for finding in self._check_jwt(f.rel_path, line, i + 1, counter):
                    counter += 1
                    yield finding
                if f.suffix == ".py" and "set_cookie" in line:
                    for finding in self._check_set_cookie(f.rel_path, lines, i, counter):
                        counter += 1
                        yield finding
                for finding in self._check_oauth_session(f.rel_path, line, i + 1, counter):
                    counter += 1
                    yield finding
                for finding in self._check_routes(
                    f.rel_path,
                    lines,
                    i,
                    counter,
                    file_has_router_auth,
                    global_auth if f.suffix == ".py" else None,
                ):
                    counter += 1
                    yield finding

    def _check_oauth_session(
        self,
        path: str,
        line: str,
        line_no: int,
        counter: int,
    ) -> Iterable[Finding]:
        lower = line.lower()
        if (
            ("oauth" in lower or "openid" in lower)
            and re.search(r"callback|redirect", lower)
            and not re.search(r"state|nonce|pkce", lower)
        ):
            yield Finding(
                id=f"authz:oauth-state:{counter + 1}",
                rule_id="authz.oauth-missing-state",
                scanner="authz",
                title="OAuth callback without state/nonce/PKCE hint",
                description="OAuth flows should bind callbacks with state, nonce, or PKCE.",
                location=Location(path=path, start_line=line_no, snippet=snippet_line(line, 200)),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-352"],
                owasp=["A07:2021-Identification and Authentication Failures"],
                why_vulnerable="Missing CSRF binding enables authorization code interception.",
                remediation=Remediation(
                    summary="Use state parameter and PKCE for OAuth/OIDC callbacks.",
                ),
                tags=["auth", "oauth"],
            )
        if _OAUTH_TOKEN_IN_URL.search(line) and not _TOKEN_URL_SUPPRESS.search(line):
            yield Finding(
                id=f"authz:token-url:{counter + 1}",
                rule_id="authz.token-in-url",
                scanner="authz",
                title="Token or authorization code in URL",
                description="Tokens in URLs leak via logs, Referer headers, and browser history.",
                location=Location(path=path, start_line=line_no, snippet=snippet_line(line, 200)),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-598"],
                owasp=["A07:2021-Identification and Authentication Failures"],
                why_vulnerable="URL query parameters are not a secure token channel.",
                remediation=Remediation(
                    summary="Exchange codes server-side; never pass tokens in URLs."
                ),
                tags=["auth", "oauth", "session"],
            )
        if _SESSION_INSECURE.search(line):
            yield Finding(
                id=f"authz:session-cookie:{counter + 1}",
                rule_id="authz.insecure-session-cookie",
                scanner="authz",
                title="Session cookie missing Secure or HttpOnly",
                description="Session cookies should set Secure and HttpOnly flags.",
                location=Location(path=path, start_line=line_no, snippet=snippet_line(line, 200)),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                likelihood=Likelihood.LIKELY,
                cwe=["CWE-614"],
                owasp=["A07:2021-Identification and Authentication Failures"],
                why_vulnerable="Cookies without HttpOnly/Secure are easier to steal or replay.",
                remediation=Remediation(
                    summary="Set Secure=True and HttpOnly=True on session cookies.",
                ),
                tags=["auth", "session"],
            )

    def _check_set_cookie(
        self, path: str, lines: list[str], idx: int, counter: int
    ) -> Iterable[Finding]:
        """``set_cookie(...)`` without ``secure=True`` / ``httponly=True``.

        The call usually spans several lines, so its text is gathered up to the
        closing parenthesis first. A flag set to anything other than a literal
        (``secure=app.config["SECURE"]``) is not judged.
        """
        line = lines[idx]
        m = _SET_COOKIE.search(line)
        if m is None or _DEF_SET_COOKIE.search(line):
            return
        before = line[: m.start()]
        if "#" in before or (before.count('"') + before.count("'")) % 2:
            return  # mentioned in a comment or a string, not called
        call = _call_text(lines, idx, m.start())
        if _top_level_commas(call) == 0 or "**" in call:
            # ``**kwargs`` may carry the flags, so the call cannot be judged.
            # ``jar.set_cookie(cookie)`` (http.cookiejar, requests) takes a ready
            # Cookie object; the web-framework form is set_cookie(key, value, ...).
            return
        flags = {}
        for name, rx in _FLAG_KW.items():
            fm = rx.search(call)
            flags[name] = fm.group(1) if fm else None
        location = Location(
            path=path,
            start_line=idx + 1,
            end_line=idx + 1,
            start_column=_receiver_start(line, m.start()) + 1,
            end_column=m.end() + 1,
            snippet=snippet_line(line),
        )
        secure = _flag_state(flags["secure"])
        if secure in ("off", "missing"):
            explicit = secure == "off"
            yield Finding(
                id=f"authz:session-cookie:{counter + 1}",
                rule_id="authz.insecure-session-cookie",
                scanner="authz",
                title="Cookie set without the Secure flag",
                description=(
                    "set_cookie() is called with secure=False."
                    if explicit
                    else "set_cookie() is called without secure=True (the default is False)."
                ),
                location=location,
                severity=Severity.MEDIUM if explicit else Severity.LOW,
                confidence=Confidence.HIGH if explicit else Confidence.MEDIUM,
                likelihood=Likelihood.LIKELY if explicit else Likelihood.POSSIBLE,
                cwe=["CWE-614"],
                owasp=["A05:2021-Security Misconfiguration"],
                why_vulnerable=(
                    "Without the Secure attribute the browser also sends the cookie over "
                    "plain HTTP, where anyone on the network path can read it."
                ),
                attacker_perspective="Sniff or downgrade one HTTP request to capture the cookie.",
                business_impact="Session hijacking or disclosure of the cookie's value.",
                remediation=Remediation(
                    summary="Pass secure=True (and httponly=True, samesite='Lax') to set_cookie().",
                ),
                tags=["auth", "session", "cookie"],
            )
        httponly = _flag_state(flags["httponly"])
        if httponly in ("off", "missing"):
            explicit = httponly == "off"
            yield Finding(
                id=f"authz:cookie-httponly:{counter + 2}",
                rule_id="authz.cookie-missing-httponly",
                scanner="authz",
                title="Cookie set without the HttpOnly flag",
                description=(
                    "set_cookie() is called with httponly=False."
                    if explicit
                    else "set_cookie() is called without httponly=True (the default is False)."
                ),
                location=location,
                severity=Severity.LOW,
                confidence=Confidence.HIGH if explicit else Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-1004"],
                owasp=["A05:2021-Security Misconfiguration"],
                why_vulnerable=(
                    "Without HttpOnly, script running in the page (for example through "
                    "an XSS bug) can read the cookie."
                ),
                attacker_perspective="Use any script injection to read document.cookie.",
                business_impact="Session theft when combined with cross-site scripting.",
                remediation=Remediation(summary="Pass httponly=True to set_cookie()."),
                tags=["auth", "session", "cookie"],
            )

    def _check_jwt(self, path: str, line: str, line_no: int, counter: int) -> Iterable[Finding]:
        if "jwt" not in line.lower() and "jsonwebtoken" not in line.lower():
            return
        if not (
            _JWT_WEAK.search(line) or ("algorithms" in line.lower() and _JWT_NONE_ALG.search(line))
        ):
            return
        yield Finding(
            id=f"authz:jwt-weak:{counter + 1}",
            rule_id="authz.jwt-weak-validation",
            scanner="authz",
            title="Insecure JWT validation",
            description=(
                "JWT verification is disabled or allows the 'none' algorithm, "
                "enabling token forgery."
            ),
            location=Location(path=path, start_line=line_no, snippet=snippet_line(line, 200)),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            likelihood=Likelihood.LIKELY,
            cwe=["CWE-347"],
            owasp=["A07:2021-Identification and Authentication Failures"],
            why_vulnerable=(
                "Accepting unsigned JWTs or skipping verification lets attackers "
                "forge tokens and impersonate users."
            ),
            attacker_perspective=(
                "Craft a JWT with alg=none or tamper claims after stripping signature verification."
            ),
            business_impact="Full authentication bypass for affected endpoints.",
            remediation=Remediation(
                summary="Verify JWT signatures with an explicit allowlist of algorithms.",
                guidance=(
                    "Use jwt.decode(..., algorithms=['RS256']); never disable signature verification "
                    "in production."
                ),
            ),
            tags=["auth", "jwt"],
        )

    def _check_routes(
        self,
        path: str,
        lines: list[str],
        idx: int,
        counter: int,
        file_has_router_auth: bool = False,
        global_auth: _GlobalAuth | None = None,
    ) -> Iterable[Finding]:
        route_path = _route_path(lines[idx])
        if not route_path or not _SENSITIVE_PATH.search(route_path):
            return
        if _PUBLIC_ROUTE.search(route_path):
            return

        window = _window(lines, idx)
        local_auth = bool(
            file_has_router_auth or _AUTH_DECORATORS.search(window) or _AUTH_MIXINS.search(window)
        )
        guard = None
        if not local_auth and global_auth is not None:
            receiver, handler, decorators = _route_meta(lines, idx)
            guard = global_auth.guard_for(path, route_path, handler, receiver, decorators)
        if local_auth:
            # Still check IDOR hints below when auth is present.
            pass
        elif guard is not None:
            # Covered by a project-wide guard. Kept as an Info note, not dropped:
            # the coverage is inferred (which app serves the route, how the
            # guard's skip list reads), so the reviewer can see what was assumed.
            yield Finding(
                id=f"authz:missing-auth:{counter + 1}",
                rule_id="authz.missing-authentication",
                scanner="authz",
                title=f"Sensitive route relies on global authentication: {route_path}",
                description=(
                    f"Route `{route_path}` has no route-level auth, but the "
                    f"{guard.kind} at {guard.path}:{guard.line} authenticates requests "
                    f"and does not skip this path. Verify that this route is served by "
                    f"that application and is not exempted some other way."
                ),
                location=Location(
                    path=path, start_line=idx + 1, snippet=snippet_line(lines[idx], 200)
                ),
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                likelihood=Likelihood.UNLIKELY,
                cwe=["CWE-306"],
                owasp=["A01:2021-Broken Access Control"],
                why_vulnerable=(
                    "Global authentication protects a route only if the route is mounted "
                    "behind it and not on the guard's skip list."
                ),
                remediation=Remediation(
                    summary="Confirm the global guard covers this route.",
                    guidance=(
                        "Check that the route's router is included in the guarded app and "
                        "that the guard's path exemptions do not match it."
                    ),
                ),
                tags=["auth", "authorization", "global-auth"],
                metadata={
                    "route": route_path,
                    "global_auth": {
                        "kind": guard.kind,
                        "path": guard.path,
                        "line": guard.line,
                    },
                },
            )
        else:
            yield Finding(
                id=f"authz:missing-auth:{counter + 1}",
                rule_id="authz.missing-authentication",
                scanner="authz",
                title=f"Sensitive route may lack authentication: {route_path}",
                description=(
                    f"Route `{route_path}` matches sensitive path patterns and has no "
                    f"obvious auth decorator or Depends() in the surrounding code."
                ),
                location=Location(
                    path=path, start_line=idx + 1, snippet=snippet_line(lines[idx], 200)
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-306"],
                owasp=["A01:2021-Broken Access Control"],
                why_vulnerable=(
                    "Administrative or sensitive endpoints without authentication allow "
                    "unauthenticated access."
                ),
                attacker_perspective="Call the endpoint directly without credentials.",
                business_impact="Unauthorized access to privileged functionality or data.",
                remediation=Remediation(
                    summary="Require authentication on sensitive routes.",
                    guidance=(
                        "Add framework-native auth (Depends(get_current_user), "
                        "@login_required, middleware) before handler logic."
                    ),
                ),
                tags=["auth", "authorization"],
                metadata={"route": route_path},
            )

        window = _window(lines, idx)
        if _ID_PARAM.search(route_path) and not _OWNERSHIP_HINT.search(window):
            yield Finding(
                id=f"authz:idor-hint:{counter + 2}",
                rule_id="authz.idor-hint",
                scanner="authz",
                title=f"Object-ID route without obvious ownership check: {route_path}",
                description=(
                    f"Route `{route_path}` includes an object identifier parameter "
                    f"but no ownership/tenant check is visible nearby (IDOR/BOLA risk)."
                ),
                location=Location(
                    path=path, start_line=idx + 1, snippet=snippet_line(lines[idx], 200)
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-639"],
                owasp=["A01:2021-Broken Access Control"],
                why_vulnerable=(
                    "Endpoints keyed by user-supplied IDs need authorization that the "
                    "caller owns or may access the referenced object."
                ),
                attacker_perspective="Iterate IDs to access other users' records (IDOR/BOLA).",
                business_impact="Cross-account data exposure or unauthorized actions.",
                remediation=Remediation(
                    summary="Verify the authenticated principal may access the requested ID.",
                    guidance=("Compare route/user ID to session tenant; return 403 on mismatch."),
                ),
                tags=["auth", "authorization", "idor"],
                metadata={"route": route_path},
            )
