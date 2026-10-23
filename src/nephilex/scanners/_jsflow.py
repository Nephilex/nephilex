"""Statement-ordered taint engine for JavaScript and TypeScript (tree-sitter).

Used by :mod:`nephilex.scanners.ast_js`. One walk per file, in source order,
tracks where untrusted values go. A value carries one :class:`Taint` per
*flavor* (where it came from) with the set of sink *kinds* it can still harm;
a sanitizer removes only the kinds it protects against.

Flavors and the sinks they are reported at:

* ``request``: HTTP request input (Express/Fastify/Node ``req.*``, Koa ``ctx.*``,
  Next.js ``searchParams`` and ``await request.json()``, h3/Nuxt ``getQuery``,
  Hono ``c.req.*``). Reported at every sink.
* ``dom``: browser input (``location.*``, ``document.URL``/``referrer``/``cookie``,
  ``window.name``) and ``postMessage`` event data. Reported at HTML, redirect
  and code sinks only; SQL, shell, file and SSRF sinks do not run in a browser.
* ``archive``: an entry name read from a tar or zip archive (tar-stream /
  yauzl / unzipper ``on('entry')``, adm-zip ``getEntries()``). Reported at
  file system sinks only (zip slip).
* ``env``: ``process.env`` and ``process.argv``. Reported at SQL sinks only:
  the operator controls them, but SQL text built from them is still fragile.
* ``param``: a parameter of a function. Reported only at shell and ``eval``/
  ``vm`` sinks, and only when the parameter was *built into* a larger command
  or code string together with literal text (``exec('ping ' + host)``), not
  when a wrapper passes it through unchanged (``exec(cmd)``). This is the
  library-API heuristic: an exported function that builds a shell command from
  its argument is command injection for whoever calls it with user input.
  Parameters named like a command or code (``cmd``, ``command``, ``script``,
  ``code``) are not tracked: such a function runs commands by design. The
  ``Function`` constructor is not reported for parameters either, because that
  is how template engines compile templates.

Guards are recognized when a block exits on a failed check (``if (!ok(x))
return``) or when the sink sits inside the passing branch: allowlist
membership (``includes``/``has``/``in``/``Object.hasOwn``), equality with a
literal, an anchored regular expression test, a predicate named like a
validator (``isValid*``, ``isAllowed*``, ``isSafe*``, ``isPathInside``) or
like a blocklist (``isPrivate*``, ``isBlocked*``), and a resolved path checked
with ``startsWith``. A call statement such as ``assertValidHost(h)`` or
``validateName(n)`` is taken to throw on bad input and clears its argument.
String blocklists (``p.includes('..')``) are deliberately not trusted.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nephilex.context import LanguageContext

#: Sink kinds and the CWE each one reports.
KIND_CWE = {
    "sql": "CWE-89",
    "shell": "CWE-78",
    "code": "CWE-95",
    "file": "CWE-22",
    "ssrf": "CWE-918",
    "html": "CWE-79",
    "redirect": "CWE-601",
    "template": "CWE-1336",
}
ALL_KINDS = frozenset(KIND_CWE)
#: Which sink kinds each flavor is reported at.
FLAVOR_KINDS: dict[str, frozenset[str]] = {
    "request": ALL_KINDS,
    # Browser input: the server-side sinks (SQL, shell, files, SSRF) do not exist there.
    "dom": frozenset({"html", "redirect", "code"}),
    "archive": frozenset({"file"}),
    "env": frozenset({"sql"}),
    # Not file: Node code builds paths from parameters everywhere (roots, config dirs),
    # so a parameter-built path is the norm, not a signal.
    "param": frozenset({"shell", "code"}),
}
#: Parameters that name a command or code to run: the function is a runner by design.
_RUNNER_PARAM = re.compile(
    r"(?i)^(?:cmd|cmds|command|commands|commandline|cmdline|script|scripts|code|source|src|"
    r"expr|expression|program|shell|js|javascript|fn|func)$|(?:Cmd|Command|Script|Code)$"
)


class AnalysisBudgetExceeded(RuntimeError):
    """The file needs more analysis work than the per-file budget allows."""


@dataclass(frozen=True)
class Taint:
    flavor: str
    origin: str
    line: int
    kinds: frozenset[str]
    #: Combined into a larger string together with literal text.
    built: bool = False


TaintSet = dict[str, Taint]


def merge(a: TaintSet, b: TaintSet) -> TaintSet:
    if not a:
        return dict(b)
    if not b:
        return dict(a)
    out = dict(a)
    for flavor, t in b.items():
        old = out.get(flavor)
        if old is None:
            out[flavor] = t
        else:
            out[flavor] = replace(old, kinds=old.kinds | t.kinds, built=old.built or t.built)
    return out


def strip(ts: TaintSet, kinds: frozenset[str]) -> TaintSet:
    out: TaintSet = {}
    for flavor, t in ts.items():
        left = t.kinds - kinds
        if left:
            out[flavor] = replace(t, kinds=left) if left != t.kinds else t
    return out


def mark_built(ts: TaintSet) -> TaintSet:
    return {f: (t if t.built else replace(t, built=True)) for f, t in ts.items()}


def unbuilt(ts: TaintSet) -> TaintSet:
    """A container (object, array) is not a command string, whatever its parts are."""
    return {f: (replace(t, built=False) if t.built else t) for f, t in ts.items()}


@dataclass
class Report:
    kind: str
    #: Where the finding is shown: the sink, or the call into a helper that reaches it.
    node: Any
    sink_line: int
    label: str
    taint: Taint
    rule: str = ""


# --- source patterns ---------------------------------------------------------------

_REQ_OBJ = r"(?:req|request|ctx\.request|context\.request|ctx\.req|c\.req|event\.node\.req)"
_REQUEST_MEMBER = re.compile(
    rf"^{_REQ_OBJ}\.(?:query|body|params|headers|header|cookies|signedCookies|url|"
    r"originalUrl|path|hostname|files|file|search|searchParams|nextUrl|href|querystring|"
    r"rawBody|fields)(?:[.\[]|$)"
    r"|^(?:this\.)?(?:ctx|context)\.(?:query|params|headers|header|url|originalUrl|href|path|"
    r"querystring|search|cookies)(?:[.\[]|$)"
)
_DOM_MEMBER = re.compile(
    r"^(?:window\.|document\.|self\.|globalThis\.)?location\.(?:search|hash|href|pathname)"
    r"(?:[.\[]|$)"
    r"|^document\.(?:URL|documentURI|referrer|cookie|baseURI)(?:[.\[]|$)"
    r"|^window\.name$"
)
#: Upload metadata the server generates (multer, express-fileupload): not attacker text.
_UPLOAD_OBJ = re.compile(r"^(?:req|request)\.files?(?:\.|\[|$)")
_SERVER_UPLOAD_FIELDS = {
    "path",
    "tempFilePath",
    "destination",
    "filename",
    "size",
    "buffer",
    "data",
    "truncated",
    "md5",
}
_REQUEST_CALL = re.compile(
    r"^(?:req|ctx\.request)\.(?:json|formData|text|get|header|param)$"
    r"|^request\.(?:json|formData|text|header|param)$"
    r"|^c\.req\.(?:query|queries|param|json|text|parseBody|formData|header)$"
    r"|^(?:this\.)?ctx\.(?:get|cookies\.get)$"
)
#: h3 / Nuxt server-route helpers that read the request (auto-imported in Nuxt).
_H3_SOURCES = {
    "getQuery",
    "readBody",
    "readRawBody",
    "readFormData",
    "readMultipartFormData",
    "getRouterParam",
    "getRouterParams",
    "getRequestURL",
    "getHeader",
    "getHeaders",
    "getRequestHeader",
    "getRequestHeaders",
    "getCookie",
    "parseCookies",
}
#: React / Next.js / React Router hooks that return URL state.
_HOOK_SOURCES = {"useSearchParams", "useParams"}
_ENV_MEMBER = re.compile(r"^process\.(?:env|argv)(?:[.\[]|$)")

# --- modules and sinks ---------------------------------------------------------------

_FS_MODULES = {
    "fs",
    "node:fs",
    "fs/promises",
    "node:fs/promises",
    "fs-extra",
    "graceful-fs",
    "original-fs",
    "mz/fs",
}
_FS_NAMES = {"fs", "fsp", "fse", "fsPromises", "fsExtra"}
_FS_SINKS = {
    "readFile",
    "readFileSync",
    "createReadStream",
    "createWriteStream",
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "open",
    "openSync",
    "readdir",
    "readdirSync",
    "unlink",
    "unlinkSync",
    "rm",
    "rmSync",
    "rmdir",
    "rmdirSync",
    "mkdir",
    "mkdirSync",
    "rename",
    "renameSync",
    "copyFile",
    "copyFileSync",
    "cp",
    "cpSync",
    "symlink",
    "symlinkSync",
    "truncate",
    "truncateSync",
    # fs-extra
    "outputFile",
    "outputFileSync",
    "outputJson",
    "outputJsonSync",
    "readJson",
    "readJsonSync",
    "writeJson",
    "writeJsonSync",
    "remove",
    "removeSync",
    "move",
    "moveSync",
    "copy",
    "copySync",
    "ensureDir",
    "ensureDirSync",
    "ensureFile",
    "ensureFileSync",
}
#: fs functions whose second argument is also a path.
_FS_TWO_PATHS = {
    "rename",
    "renameSync",
    "copyFile",
    "copyFileSync",
    "cp",
    "cpSync",
    "symlink",
    "symlinkSync",
    "move",
    "moveSync",
    "copy",
    "copySync",
}
_CP_MODULES = {"child_process", "node:child_process"}
_CP_NAMES = {"cp", "childProcess", "child_process"}
_CP_EXEC = {"exec", "execSync"}
_CP_SPAWN = {"spawn", "spawnSync", "execFile", "execFileSync"}
_SHELL_BINARIES = re.compile(
    r"^(?:/(?:usr/)?bin/)?(?:sh|bash|zsh|dash|ksh|cmd|cmd\.exe|powershell|powershell\.exe|"
    r"pwsh|pwsh\.exe)$",
    re.IGNORECASE,
)
_SHELL_FLAGS = {"-c", "/c", "/C", "/s", "/S", "-Command", "-command", "-lc", "-ic"}
_VM_MODULES = {"vm", "node:vm"}
_VM_SINKS = {"runInThisContext", "runInNewContext", "runInContext", "compileFunction"}
_HTTP_MODULES = {"http", "https", "node:http", "node:https"}
_HTTP_CLIENTS = {
    "axios",
    "got",
    "node-fetch",
    "undici",
    "superagent",
    "needle",
    "ky",
    "ofetch",
    "cross-fetch",
    "isomorphic-fetch",
    "request",
}
_HTTP_GLOBALS = {"fetch", "$fetch"}
_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
_URL_KEYS = ("url", "uri", "baseURL", "baseUrl", "host", "hostname")
_RES_NAMES = {"res", "response", "resp"}
_REDIRECT_MODULES = re.compile(r"^(?:next/navigation|react-router(?:-dom)?|@remix-run/[\w-]+)$")
_TEMPLATE_HEADS = {
    "ejs": {"render", "compile"},
    "pug": {"render", "compile"},
    "jade": {"render", "compile"},
    "Handlebars": {"compile", "precompile"},
    "handlebars": {"compile", "precompile"},
    "hbs": {"compile"},
    "nunjucks": {"renderString", "compile"},
    "_": {"template"},
    "lodash": {"template"},
    "doT": {"template", "compile"},
    "dot": {"template", "compile"},
}
_TEMPLATE_MODULES = {
    "ejs": {"render", "compile"},
    "pug": {"render", "compile"},
    "handlebars": {"compile", "precompile"},
    "nunjucks": {"renderString", "compile"},
    "lodash": {"template"},
    "lodash.template": {"default", "template"},
    "dot": {"template", "compile"},
}
_SAFE_SQL_TAGS = {"sql", "SQL", "Prisma.sql", "sql.fragment", "dedent"}
_SQL_RECEIVER = re.compile(r"(?i)db|sql|database|conn|pool|client|knex|stmt|sequelize|prisma")

# --- sanitizers ------------------------------------------------------------------------

_NUMERIC = {
    "Number",
    "parseInt",
    "parseFloat",
    "Boolean",
    "isNaN",
    "isFinite",
    "BigInt",
}
_CLEAN_METHODS = {
    "startsWith",
    "endsWith",
    "includes",
    "indexOf",
    "lastIndexOf",
    "test",
    "has",
    "localeCompare",
    "charCodeAt",
    "codePointAt",
    "digest",
    "toFixed",
    "getTime",
    "valueOf",
    "isInteger",
    "isSafeInteger",
}
#: Modules whose default export or functions neutralize a value for these kinds.
_SANITIZER_MODULES: dict[str, frozenset[str]] = {
    "sanitize-filename": frozenset({"file", "shell", "html"}),
    "dompurify": frozenset({"html"}),
    "isomorphic-dompurify": frozenset({"html"}),
    "sanitize-html": frozenset({"html"}),
    "xss": frozenset({"html"}),
    "he": frozenset({"html"}),
    "escape-html": frozenset({"html"}),
    "html-escaper": frozenset({"html"}),
    "lodash.escape": frozenset({"html"}),
    "shell-quote": frozenset({"shell"}),
    "shell-escape": frozenset({"shell"}),
    "shescape": frozenset({"shell"}),
    "sqlstring": frozenset({"sql"}),
    "jsesc": frozenset({"code"}),
    "serialize-javascript": frozenset({"code", "html"}),
    "devalue": frozenset({"code", "html"}),
}
_LEGACY_SANITIZERS: dict[str, frozenset[str]] = {
    "encodeURIComponent": frozenset({"html", "ssrf", "shell", "redirect", "code"}),
    "encodeURI": frozenset({"html"}),
    "escape": frozenset({"html", "sql"}),
    "sanitize": frozenset({"html"}),
    "escapeHtml": frozenset({"html"}),
    "sanitizeHtml": frozenset({"html"}),
    "quote": frozenset({"shell", "sql"}),
    "basename": frozenset({"file"}),
    "filterXSS": frozenset({"html"}),
    "escapeId": frozenset({"sql"}),
    "escapeIdentifier": frozenset({"sql"}),
    "escapeLiteral": frozenset({"sql"}),
}
_NOT_SANITIZER = re.compile(r"(?i)unescape|decode|unsanitiz|unquote")
_SHELL_ESCAPE = re.compile(
    r"(?i)(?:shell|cmd|arg|command).*(?:escape|quote|sanitiz)|"
    r"(?:escape|quote|sanitiz).*(?:shell|cmd|arg|command)"
)
_CODE_ESCAPE = re.compile(
    r"(?i)(?:js|javascript|literal).*escape|escape.*(?:js\b|javascript|literal)"
)
_FILE_SANITIZER = re.compile(
    r"(?i)sanitiz\w*(?:file|path|name)|safe\w*(?:path|file|name|join)|(?:path|file)\w*safe"
)
_URL_SANITIZER = re.compile(r"(?i)sanitiz\w*(?:url|uri|href|link)")
# Not htmlSafe/safeHtml: Ember's htmlSafe() marks a string as trusted HTML, the opposite.
_HTML_ESCAPE = re.compile(r"(?i)escape|sanitiz|encode|purif|xss")
_SQL_ESCAPE = re.compile(
    r"(?i)(?:escape|quote)\w*(?:sql|ident|literal|id\b)|sql\w*(?:escape|quote)"
)
#: Predicates that vouch for their argument when they return true.
_ALLOW_PREDICATE = re.compile(
    r"(?i)^(?:is|has|check|verify|can)?\w*(?:valid|allowed|allow|safe|trusted|permitted|"
    r"whitelist|allowlist|inside|within|contained|subpath|subdir|inroot|sameorigin)\w*$"
)
_DENY_PREDICATE = re.compile(
    r"(?i)^(?:is|has|contains)\w*(?:blocked|denied|deny|forbidden|private|internal|unsafe|"
    r"invalid|malicious|dangerous|traversal|escap|loopback|localhost|reserved|blacklist|"
    r"blocklist|outside)\w*$"
)
#: Call statements taken to throw when their argument is bad.
_VALIDATOR_STMT = re.compile(
    r"(?i)^(?:assert|validate|ensure|check|verify|require|guard)\w*$"
    r"|^\w*(?:valid|safe)\w*(?:or(?:throw|fail)|strict)$"
)
_WEAK_PREFIXES = {"", "/", "./", "http", "https", "http:", "https:", "http://", "https://"}
#: A literal URL prefix that fixes the scheme and host, or a relative URL.
_HOST_PINNED = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/?#{}$\s]+[/?#]|^/(?![/\\])|^\.{1,2}/|^[\w.-]+[/?#]"
)
REST = "\0rest"
#: Functions that build a new object from the fields of their arguments.
_MERGE_FUNCS = {
    "Object.assign",
    "$.extend",
    "jQuery.extend",
    "_.assign",
    "_.extend",
    "_.merge",
    "_.defaults",
    "_.defaultsDeep",
    "Object.freeze",
    "structuredClone",
    "merge",
    "deepmerge",
    "defu",
    "extend",
}
_DIRISH = re.compile(r"(?i)(?:dir|root|base|folder|directory|prefix\w*path|home)\w*$")
_RESOLVERS = {"resolve", "realpath", "realpathSync", "normalize", "join"}

_FUNCTION_TYPES = (
    "function_declaration",
    "function_expression",
    "function",
    "arrow_function",
    "method_definition",
    "generator_function",
    "generator_function_declaration",
)
_ITERATORS = {
    "forEach",
    "map",
    "flatMap",
    "filter",
    "find",
    "findLast",
    "findIndex",
    "some",
    "every",
    "then",
}
_TS_WRAPPERS = (
    "parenthesized_expression",
    "as_expression",
    "satisfies_expression",
    "non_null_expression",
    "type_assertion",
    "await_expression",
)
_NUMERIC_TYPES = {"number", "boolean", "bigint", "never", "void", "undefined", "null"}
_LITERAL_UNION = re.compile(r"^(?:'[^']*'|\"[^\"]*\"|\d+)(?:\s*\|\s*(?:'[^']*'|\"[^\"]*\"|\d+))*$")
#: Work units (expression evaluations) a single file may use.
_BUDGET = 400_000


def walk(root) -> Iterator[Any]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


class JsFlow:
    """Taint analysis of one parsed JS/TS file."""

    def __init__(
        self,
        src: bytes,
        root,
        *,
        context: LanguageContext | None = None,
    ) -> None:
        self.src = src
        self.root = root
        self.ctx = context
        self.imports: dict[str, str] = {}
        self.local_funcs: dict[str, Any] = {}
        self.local_methods: dict[str, Any] = {}
        self.reports: list[Report] = []
        self.resolved: set[str] = set()
        self.relatives: set[str] = set()
        self.url_objects: set[str] = set()
        self.rooted_vars: set[str] = set()
        self.sep_terminated: set[str] = set()
        self.derived: dict[str, str] = {}
        self._seen: set[tuple[str, int]] = set()
        self._done: set[tuple[int, int]] = set()
        self._ret_stack: list[TaintSet] = []
        self._inline_stack: list[str] = []
        self._inline_memo: dict[tuple[Any, ...], TaintSet] = {}
        self._anchor: Any = None
        self._passed: set[tuple[str, str, int]] = set()
        self._loop_depth = 0
        self._work = 0

    # --- entry ----------------------------------------------------------------
    def run(self) -> list[Report]:
        self._collect_imports()
        self._collect_functions()
        self._block(self.root, {})
        return self.reports

    # --- text helpers -----------------------------------------------------------
    def text(self, node) -> str:
        return self.src[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def string(self, node) -> str | None:
        if node is None:
            return None
        if node.type == "string":
            return "".join(self.text(c) for c in node.named_children if c.type == "string_fragment")
        if node.type == "template_string" and not any(
            c.type == "template_substitution" for c in node.named_children
        ):
            return "".join(self.text(c) for c in node.named_children if c.type == "string_fragment")
        return None

    def unwrap(self, node):
        while node is not None and node.type in _TS_WRAPPERS and node.named_children:
            node = node.named_children[0]
        return node

    def key(self, node) -> str | None:
        """A dotted name for an identifier or member path (``req.query.x``), or None."""
        node = self.unwrap(node)
        if node is None:
            return None
        t = node.type
        if t in (
            "identifier",
            "this",
            "shorthand_property_identifier",
            "shorthand_property_identifier_pattern",
            "property_identifier",
        ):
            return self.text(node)
        if t == "member_expression":
            obj = self.key(node.child_by_field_name("object"))
            prop = node.child_by_field_name("property")
            if obj is None or prop is None:
                return None
            return f"{obj}.{self.text(prop)}"
        if t == "subscript_expression":
            obj = self.key(node.child_by_field_name("object"))
            if obj is None:
                return None
            index = node.child_by_field_name("index")
            lit = self.string(index)
            if lit is not None and re.match(r"^[\w$-]+$", lit):
                return f"{obj}.{lit}"
            return f"{obj}[]"
        return None

    def callee_text(self, fn) -> str:
        k = self.key(fn)
        if k is not None:
            return k
        return re.sub(r"\s+", "", self.text(fn)).replace("?.", ".")

    def masked(self, text: str) -> str:
        return self.ctx.mask_trusted(text) if self.ctx is not None else text

    def tick(self, n: int = 1) -> None:
        self._work += n
        if self._work > _BUDGET:
            raise AnalysisBudgetExceeded("analysis budget exceeded")

    # --- imports ---------------------------------------------------------------
    def _require_module(self, node) -> str | None:
        """``m`` for ``require('m')`` / ``import('m')`` (possibly awaited)."""
        node = self.unwrap(node)
        if node is None or node.type != "call_expression":
            return None
        fn = node.child_by_field_name("function")
        if fn is None or self.text(fn) not in ("require", "import"):
            return None
        args = node.child_by_field_name("arguments")
        first = args.named_children[0] if args is not None and args.named_children else None
        return self.string(first)

    def _qualified(self, node) -> str | None:
        """``module#name`` for an expression naming an imported value."""
        node = self.unwrap(node)
        if node is None:
            return None
        if node.type == "identifier":
            return self.imports.get(self.text(node))
        if node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if obj is None or prop is None:
                return None
            mod = self._require_module(obj)
            if mod is None:
                base = self._qualified(obj)
                if base is None or "#" in base:
                    return None
                mod = base
            return f"{mod}#{self.text(prop)}"
        return None

    def _collect_imports(self) -> None:
        for node in walk(self.root):
            if node.type == "import_statement":
                module = self.string(node.child_by_field_name("source"))
                if module is None:
                    continue
                for n in walk(node):
                    if n.type == "import_specifier":
                        name = n.child_by_field_name("name")
                        alias = n.child_by_field_name("alias") or name
                        if name is not None and alias is not None:
                            self.imports[self.text(alias)] = f"{module}#{self.text(name)}"
                    elif n.type == "namespace_import":
                        ident = next((c for c in n.named_children if c.type == "identifier"), None)
                        if ident is not None:
                            self.imports[self.text(ident)] = module
                    elif n.type == "import_clause":
                        for c in n.named_children:
                            if c.type == "identifier":
                                self.imports[self.text(c)] = module
            elif node.type == "variable_declarator":
                value = self.unwrap(node.child_by_field_name("value"))
                name = node.child_by_field_name("name")
                if value is None or name is None:
                    continue
                module = self._require_module(value)
                if module is not None:
                    self._bind_import(name, module)
                    continue
                if value.type == "member_expression" and name.type == "identifier":
                    q = self._qualified(value)
                    if q is not None:
                        self.imports[self.text(name)] = q
                    continue
                if value.type == "call_expression" and name.type == "identifier":
                    fn = value.child_by_field_name("function")
                    args = value.child_by_field_name("arguments")
                    first = (
                        args.named_children[0] if args is not None and args.named_children else None
                    )
                    if fn is not None and self.callee_text(fn).rsplit(".", 1)[-1].startswith(
                        "promisify"
                    ):
                        q = self._qualified(first) if first is not None else None
                        if q is not None:
                            self.imports[self.text(name)] = q

    def _bind_import(self, name, module: str) -> None:
        if name.type == "identifier":
            self.imports[self.text(name)] = module
        elif name.type == "object_pattern":
            for c in name.named_children:
                if c.type == "shorthand_property_identifier_pattern":
                    self.imports[self.text(c)] = f"{module}#{self.text(c)}"
                elif c.type == "pair_pattern":
                    key = c.child_by_field_name("key")
                    val = c.child_by_field_name("value")
                    if key is not None and val is not None and val.type == "identifier":
                        self.imports[self.text(val)] = f"{module}#{self.text(key)}"

    def module_of(self, name: str) -> str:
        return self.imports.get(name, "").split("#", 1)[0]

    def export_of(self, name: str) -> str:
        return self.imports.get(name, "#").split("#", 1)[-1]

    def _collect_functions(self) -> None:
        counts: dict[str, int] = {}
        mcounts: dict[str, int] = {}
        for node in walk(self.root):
            name = None
            fn = None
            if node.type in ("function_declaration", "generator_function_declaration"):
                name_node = node.child_by_field_name("name")
                name, fn = (self.text(name_node) if name_node else None), node
            elif node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                name_node = node.child_by_field_name("name")
                if (
                    value is not None
                    and value.type in _FUNCTION_TYPES
                    and name_node is not None
                    and name_node.type == "identifier"
                ):
                    name, fn = self.text(name_node), value
            elif node.type == "method_definition":
                name_node = node.child_by_field_name("name")
                if name_node is not None:
                    m = self.text(name_node)
                    mcounts[m] = mcounts.get(m, 0) + 1
                    self.local_methods[m] = node
            if name and fn is not None:
                counts[name] = counts.get(name, 0) + 1
                self.local_funcs[name] = fn
        for name, count in counts.items():
            if count > 1:
                del self.local_funcs[name]
        for name, count in mcounts.items():
            if count > 1:
                del self.local_methods[name]

    # --- statements ----------------------------------------------------------------
    def _block(self, node, scope: dict[str, TaintSet]) -> None:
        for stmt in node.named_children:
            self._stmt(stmt, scope)

    def _stmt(self, node, scope: dict[str, TaintSet]) -> None:
        self.tick()
        t = node.type
        if t in ("lexical_declaration", "variable_declaration"):
            for decl in node.named_children:
                if decl.type != "variable_declarator":
                    continue
                value = decl.child_by_field_name("value")
                name = decl.child_by_field_name("name")
                if value is None or name is None:
                    continue
                self._expr(value, scope)
                self._note_derivation(name, value)
                shape = self._shape(value, scope)
                self._bind(name, self._eval(value, scope), scope)
                self._bind_shape(name, shape, scope)
            return
        if t == "expression_statement":
            for child in node.named_children:
                self._expr(child, scope)
                inner = self.unwrap(child)
                if inner is None:
                    continue
                if inner.type in ("assignment_expression", "augmented_assignment_expression"):
                    left = inner.child_by_field_name("left")
                    right = inner.child_by_field_name("right")
                    if left is not None and right is not None:
                        taint = self._eval(right, scope)
                        if inner.type == "augmented_assignment_expression":
                            taint = merge(self._eval(left, scope), taint)
                            if self._stringy(right):
                                taint = mark_built(taint)
                        self._note_derivation(left, right)
                        shape = (
                            self._shape(right, scope)
                            if inner.type == "assignment_expression"
                            else None
                        )
                        self._bind(left, taint, scope)
                        self._bind_shape(left, shape, scope)
                elif inner.type == "call_expression":
                    self._mutation(inner, scope)
                    self._validator_statement(inner, scope)
            return
        if t == "return_statement":
            for child in node.named_children:
                self._expr(child, scope)
            if node.named_children and self._ret_stack:
                value = self._eval(node.named_children[0], scope)
                self._ret_stack[-1] = merge(self._ret_stack[-1], value)
            return
        if t == "if_statement":
            self._if(node, scope)
            return
        if t == "for_in_statement":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if right is not None:
                self._expr(right, scope)
                if left is not None:
                    self._bind(left, self._eval(right, scope), scope)
            body = node.child_by_field_name("body")
            self._loop_depth += 1
            for _ in range(self._passes()):
                if body is not None:
                    self._stmt_or_block(body, scope)
            self._loop_depth -= 1
            return
        if t in ("for_statement", "while_statement", "do_statement"):
            init = node.child_by_field_name("initializer")
            if init is not None:
                if init.type.endswith("declaration"):
                    self._stmt(init, scope)
                else:
                    self._expr(init, scope)
            self._loop_depth += 1
            for _ in range(self._passes()):
                for field_name in ("condition", "increment"):
                    child = node.child_by_field_name(field_name)
                    if child is not None:
                        self._expr(child, scope)
                body = node.child_by_field_name("body")
                if body is not None:
                    self._stmt_or_block(body, scope)
            self._loop_depth -= 1
            return
        if t in _FUNCTION_TYPES:
            self._function(node, scope)
            return
        self._generic(node, scope)

    def _passes(self) -> int:
        return 2 if self._loop_depth <= 2 else 1

    def _stmt_or_block(self, node, scope: dict[str, TaintSet]) -> None:
        if node.type == "statement_block":
            self._block(node, scope)
        else:
            self._stmt(node, scope)

    def _generic(self, node, scope: dict[str, TaintSet]) -> None:
        for child in node.named_children:
            if child.type == "statement_block":
                self._block(child, scope)
            elif child.type.endswith(("_statement", "_declaration")) or child.type in (
                "else_clause",
                "catch_clause",
                "finally_clause",
                "switch_body",
                "switch_case",
                "switch_default",
                "class_body",
                "method_definition",
                "export_clause",
            ):
                self._stmt(child, scope)
            else:
                self._expr(child, scope)

    def _exits(self, node) -> bool:
        if node is None:
            return False
        if node.type in (
            "return_statement",
            "throw_statement",
            "continue_statement",
            "break_statement",
        ):
            return True
        if node.type == "expression_statement":
            inner = self.unwrap(node.named_children[0]) if node.named_children else None
            if inner is not None and inner.type == "call_expression":
                fn = inner.child_by_field_name("function")
                return fn is not None and self.callee_text(fn) == "process.exit"
            return False
        if node.type == "statement_block":
            stmts = [c for c in node.named_children if c.type != "comment"]
            return bool(stmts) and self._exits(stmts[-1])
        return False

    def _if(self, node, scope: dict[str, TaintSet]) -> None:
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        if cond is not None:
            self._expr(cond, scope)
        pos, neg = self._guard(cond, scope) if cond is not None else ({}, {})
        if cons is not None:
            self._stmt_or_block(cons, self._cleared(scope, pos))
        alt_body = None
        if alt is not None:
            alt_body = alt.named_children[0] if alt.named_children else None
            self._generic(alt, self._cleared(scope, neg))
        if cons is not None and self._exits(cons):
            self._apply_clear(scope, neg)
        if alt_body is not None and self._exits(alt_body):
            self._apply_clear(scope, pos)

    def _cleared(self, scope: dict[str, TaintSet], clear: dict[str, frozenset[str]]):
        if not clear:
            return scope
        inner = dict(scope)
        self._apply_clear(inner, clear)
        return inner

    def _apply_clear(self, scope: dict[str, TaintSet], clear: dict[str, frozenset[str]]) -> None:
        for k, kinds in clear.items():
            chain = [k]
            while len(chain) < 4 and chain[-1] in self.derived:
                nxt = self.derived[chain[-1]]
                if nxt in chain:
                    break
                chain.append(nxt)
            for name in chain:
                for key in [
                    s for s in scope if s == name or s.startswith((name + ".", name + REST))
                ]:
                    left = strip(scope[key], kinds)
                    if left:
                        scope[key] = left
                    else:
                        scope.pop(key, None)
                if name not in scope and self._is_source_key(name):
                    # A source read by name (req.query.x) checked here: shadow it.
                    scope[name] = {
                        f: replace(t, kinds=t.kinds - kinds)
                        for f, t in self._source_member(name, self.root).items()
                        if t.kinds - kinds
                    }

    def _note_derivation(self, target, value) -> None:
        """Remember ``u = new URL(x)`` (so a check of ``u`` covers ``x``) and resolved paths."""
        name = self.key(target)
        value = self.unwrap(value)
        if name is None or value is None:
            return
        if value.type == "binary_expression":
            right = self.unwrap(value.child_by_field_name("right"))
            if right is not None and (
                self.text(right) in ("path.sep", "sep", "'/'", '"/"', "'\\\\'", '"\\\\"')
            ):
                self.sep_terminated.add(name)  # base = root + path.sep
        if value.type in ("new_expression", "call_expression"):
            fn = value.child_by_field_name("constructor") or value.child_by_field_name("function")
            args = value.child_by_field_name("arguments")
            first = args.named_children[0] if args is not None and args.named_children else None
            fn_text = self.callee_text(fn) if fn is not None else ""
            last = fn_text.rsplit(".", 1)[-1]
            if last in ("URL", "parse") and first is not None:
                src = self.key(first)
                if src is not None:
                    self.derived[name] = src
            if last == "URL" and value.type == "new_expression":
                self.url_objects.add(name)
            if self._rooted_norm(value):
                self.rooted_vars.add(name)
            if last == "relative" and self._path_module(fn, fn_text) and args is not None:
                # rel = path.relative(base, p): a check of rel is a check of p
                argv = args.named_children
                src = self.key(argv[-1]) if argv else None
                self.relatives.add(name)
                if src is not None:
                    self.derived[name] = src
            if last in _RESOLVERS and self._path_module(fn, fn_text):
                self.resolved.add(name)
                if first is not None and args is not None:
                    # p = path.resolve(base, x): checking p vouches for x too
                    src = self.key(args.named_children[-1])
                    if src is not None and src != name:
                        self.derived.setdefault(name, src)

    def _path_module(self, fn, fn_text: str) -> bool:
        """Whether ``fn`` is a function of ``path`` or ``fs`` (``path.resolve``, ``realpath``)."""
        fn = self.unwrap(fn)
        if fn is None:
            return False
        head = fn_text.split(".", 1)[0]
        mod = self.module_of(fn_text if fn.type == "identifier" else head)
        if mod in ("path", "node:path", "upath", "pathe") or mod in _FS_MODULES:
            return True
        return fn.type == "member_expression" and head in ("path", "fs", "fsp", "upath")

    def _bind(self, target, taint: TaintSet, scope: dict[str, TaintSet]) -> None:
        if target is None:
            return
        t = target.type
        if t in (
            "identifier",
            "member_expression",
            "shorthand_property_identifier_pattern",
            "subscript_expression",
        ):
            key = self.key(target)
            if key is None:
                return
            if t == "subscript_expression" and key.endswith("[]"):
                obj = key[:-2]
                if taint:
                    scope[obj] = merge(scope.get(obj, {}), taint)
                return
            if taint:
                scope[key] = taint
            elif key in scope or self._is_source_key(key):
                scope[key] = {}
            for k in [s for s in scope if s.startswith((key + ".", key + REST))]:
                del scope[k]
            return
        if t == "assignment_pattern":
            self._bind(target.child_by_field_name("left"), taint, scope)
            return
        if t in ("object_pattern", "array_pattern", "rest_pattern"):
            for child in target.named_children:
                if child.type == "pair_pattern":
                    self._bind(child.child_by_field_name("value"), taint, scope)
                elif child.type == "object_assignment_pattern":
                    self._bind(child.child_by_field_name("left"), taint, scope)
                else:
                    self._bind(child, taint, scope)

    def _bind_shape(self, target, shape, scope: dict[str, TaintSet]) -> None:
        """Record per-field taint for an object built from known fields (``{a, b: x}``)."""
        if (
            shape is None
            or target is None
            or target.type not in ("identifier", "member_expression")
        ):
            return
        key = self.key(target)
        if key is None or not scope.get(key):
            return
        fields, rest = shape
        for name, ts in fields.items():
            scope[f"{key}.{name}"] = ts
        scope[key + REST] = rest

    def _shape(self, node, scope: dict[str, TaintSet], depth: int = 0):
        """(field taints, taint of any other field) for an object value, or None if unknown."""
        node = self.unwrap(node)
        if node is None or depth > 4:
            return None
        if node.type == "object":
            fields: dict[str, TaintSet] = {}
            rest: TaintSet = {}
            for c in node.named_children:
                if c.type == "pair":
                    k = c.child_by_field_name("key")
                    v = c.child_by_field_name("value")
                    if k is None or v is None:
                        continue
                    if k.type in ("property_identifier", "string", "number"):
                        fields[self.string(k) or self.text(k)] = self._eval(v, scope)
                    else:
                        rest = merge(rest, self._eval(v, scope))
                elif c.type == "shorthand_property_identifier":
                    fields[self.text(c)] = scope.get(self.text(c), {})
                elif c.type == "spread_element" and c.named_children:
                    inner = self._shape(c.named_children[0], scope, depth + 1)
                    if inner is not None:
                        fields.update(inner[0])
                        rest = merge(rest, inner[1])
                    else:
                        t = self._eval(c.named_children[0], scope)
                        fields = {f: merge(v, t) for f, v in fields.items()}
                        rest = merge(rest, t)
            return fields, rest
        if node.type in ("identifier", "member_expression"):
            key = self.key(node)
            if key is None or key + REST not in scope:
                return None
            prefix = key + "."
            fields = {
                s[len(prefix) :]: v
                for s, v in scope.items()
                if s.startswith(prefix) and "." not in s[len(prefix) :] and REST not in s
            }
            return fields, scope[key + REST]
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is None or self.callee_text(fn) not in _MERGE_FUNCS:
                return None
            args = node.child_by_field_name("arguments")
            fields = {}
            rest = {}
            for a in args.named_children if args is not None else []:
                if a.type in ("true", "false"):
                    continue
                inner = self._shape(a, scope, depth + 1)
                if inner is not None:
                    fields.update(inner[0])
                    rest = merge(rest, inner[1])
                else:
                    t = self._eval(a, scope)
                    fields = {f: merge(v, t) for f, v in fields.items()}
                    rest = merge(rest, t)
            return fields, rest
        return None

    def _is_source_key(self, key: str) -> bool:
        masked = self.masked(key)
        return bool(
            _REQUEST_MEMBER.match(masked) or _DOM_MEMBER.match(masked) or _ENV_MEMBER.match(masked)
        )

    def _mutation(self, call, scope: dict[str, TaintSet]) -> None:
        """``parts.push(x)`` / ``url.searchParams.append(k, x)`` puts ``x`` into the object."""
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return
        prop = fn.child_by_field_name("property")
        obj = fn.child_by_field_name("object")
        if prop is None or obj is None:
            return
        if self.text(prop) not in ("push", "unshift", "add", "set", "append", "splice"):
            return
        key = self.key(obj)
        if key is None:
            return
        args = call.child_by_field_name("arguments")
        taint: TaintSet = {}
        for a in args.named_children if args is not None else []:
            taint = merge(taint, self._eval(a, scope))
        if key.endswith(".searchParams"):
            # A query parameter cannot change the URL's scheme or host.
            key = key[: -len(".searchParams")]
            taint = strip(taint, frozenset({"ssrf", "redirect"}))
        if taint:
            scope[key] = merge(scope.get(key, {}), taint)

    def _validator_statement(self, call, scope: dict[str, TaintSet]) -> None:
        """``assertValidRegion(region)`` as a statement: it throws on bad input."""
        fn = call.child_by_field_name("function")
        if fn is None:
            return
        name = self.callee_text(fn).rsplit(".", 1)[-1]
        if not _VALIDATOR_STMT.match(name):
            return
        args = call.child_by_field_name("arguments")
        clear: dict[str, frozenset[str]] = {}
        for a in args.named_children if args is not None else []:
            k = self.key(a)
            if k is not None:
                clear[k] = ALL_KINDS
        self._apply_clear(scope, clear)

    # --- guards --------------------------------------------------------------------
    def _guard(self, cond, scope: dict[str, TaintSet]):
        """(cleared when the condition is true, cleared when it is false)."""
        cond = self.unwrap(cond)
        empty: dict[str, frozenset[str]] = {}
        if cond is None:
            return empty, empty
        if cond.type == "unary_expression":
            op = cond.child_by_field_name("operator")
            if op is not None and self.text(op) == "!":
                pos, neg = self._guard(cond.child_by_field_name("argument"), scope)
                return neg, pos
            return empty, empty
        if cond.type == "binary_expression":
            op_node = cond.child_by_field_name("operator")
            op = self.text(op_node) if op_node is not None else ""
            left = cond.child_by_field_name("left")
            right = cond.child_by_field_name("right")
            if op in ("&&", "||"):
                lp, ln = self._guard(left, scope)
                rp, rn = self._guard(right, scope)
                if op == "&&":
                    return _union(lp, rp), _intersect(ln, rn)
                return _intersect(lp, rp), _union(ln, rn)
            if op in ("===", "==", "!==", "!="):
                keys: dict[str, frozenset[str]] = {}
                for a, b in ((left, right), (right, left)):
                    if a is None or b is None:
                        continue
                    b = self.unwrap(b)
                    if (
                        b is not None
                        and b.type in ("string", "number", "template_string")
                        and (b.type != "template_string" or self.string(b) is not None)
                    ):
                        keys.update(self._checked(a))
                    elif self._url_part(a) and b is not None and self.key(b) != self.key(a):
                        # u.host === ctx.host, new URL(x).origin === location.origin: a
                        # same-origin check pins the host for redirects and requests
                        for name in self._checked(a):
                            keys[name] = keys.get(name, frozenset()) | frozenset(
                                {"redirect", "ssrf"}
                            )
                    # a call result compared with false/true: isAllowed(x) === false
                    if b is not None and b.type in ("true", "false"):
                        p, n = self._guard(a, scope)
                        truthy = (b.type == "true") == (op in ("===", "=="))
                        return (p, n) if truthy else (n, p)
                if op in ("===", "=="):
                    return keys, empty
                return empty, keys
            if op == "in" and right is not None and not _attacker(self._eval(right, scope)):
                return self._checked(left), empty
            if op in (">", ">=", "<", "<=") and left is not None:
                # path.relative(base, p).indexOf('..') / x.indexOf(...) comparisons: ignore
                return empty, empty
            return empty, empty
        if cond.type == "call_expression":
            return self._guard_call(cond, scope)
        return empty, empty

    def _guard_call(self, call, scope: dict[str, TaintSet]):
        empty: dict[str, frozenset[str]] = {}
        fn = call.child_by_field_name("function")
        args_node = call.child_by_field_name("arguments")
        argv = list(args_node.named_children) if args_node is not None else []
        if fn is None:
            return empty, empty
        fn_text = self.callee_text(fn)
        last = fn_text.rsplit(".", 1)[-1]
        if fn.type == "member_expression":
            obj = self.unwrap(fn.child_by_field_name("object"))
            if obj is None:
                return empty, empty
            if last in ("includes", "has") and not _attacker(self._eval(obj, scope)):
                if obj.type in ("string", "template_string"):
                    return empty, empty  # "abc".includes(x) is a substring test
                out: dict[str, frozenset[str]] = {}
                for a in argv:
                    out.update(self._checked(a))
                return out, empty
            if last in ("hasOwn", "hasOwnProperty") and argv:
                target = argv[-1]
                return self._checked(target), empty
            if last == "test" and obj.type == "regex" and argv:
                pattern = obj.child_by_field_name("pattern")
                ptext = self.text(pattern) if pattern is not None else ""
                checked: dict[str, frozenset[str]] = {}
                for a in argv:
                    checked.update(self._checked(a))
                if ptext.startswith("^") and ptext.endswith("$") and ".*" not in ptext:
                    return checked, empty
                if re.match(r"^\[\^[^\]]*\]$", ptext):
                    return empty, checked  # /[^\w]/.test(x): x has a bad character
                return empty, empty
            if last == "match" and argv and self.unwrap(argv[0]).type == "regex":
                pattern = self.unwrap(argv[0]).child_by_field_name("pattern")
                ptext = self.text(pattern) if pattern is not None else ""
                checked = self._checked(obj)
                if ptext.startswith("^") and ptext.endswith("$") and ".*" not in ptext:
                    return checked, empty
                if re.match(r"^\[\^[^\]]*\]$", ptext):
                    return empty, checked
                return empty, empty
            if last == "startsWith" and argv:
                first = self.unwrap(argv[0])
                while first is not None and first.type == "binary_expression":
                    first = self.unwrap(first.child_by_field_name("left"))
                lit = self.string(first)
                if (
                    lit is not None
                    and lit.startswith("..")
                    and (self.key(obj) or "") in self.relatives
                ):
                    # path.relative(base, p).startsWith('..'): true means p escapes base
                    return empty, {k: frozenset({"file"}) for k in self._checked(obj)}
                return self._prefix_guard(call, obj, argv[0], scope), empty
        if last == "isAbsolute" and argv and (self.key(argv[0]) or "") in self.relatives:
            return empty, {k: frozenset({"file"}) for k in self._checked(argv[0])}
        # Named predicates: isAllowedUrl(u), isPathInside(root, p), isPrivateIp(h)
        if _NOT_SANITIZER.search(last):
            return empty, empty
        if _DENY_PREDICATE.match(last) or _ALLOW_PREDICATE.match(last):
            checked = {}
            for a in argv:
                checked.update(self._checked(a))
            if fn.type == "member_expression" and not argv:
                obj = fn.child_by_field_name("object")
                checked.update(self._checked(obj))
            if _DENY_PREDICATE.match(last):
                return empty, checked
            return checked, empty
        return empty, empty

    def _prefix_guard(self, call, obj, prefix, scope: dict[str, TaintSet]):
        """``p.startsWith(base)``: a containment check for resolved paths and pinned URLs."""
        out: dict[str, frozenset[str]] = {}
        lit = self.string(self.unwrap(prefix))
        checked = self._checked(obj)
        if lit is not None:
            if lit.lower() in _WEAK_PREFIXES or not _HOST_PINNED.match(lit) and "/" not in lit:
                return out
            for k in checked:
                out[k] = frozenset({"ssrf", "redirect", "file"})
            return out
        if _attacker(self._eval(prefix, scope)):
            return out  # comparing against another attacker value proves nothing
        self._weak_prefix_check(call, obj, prefix)
        for k in checked:
            out[k] = frozenset({"file", "ssrf", "redirect"})
        return out

    def _autoescape_off(self, node, fn, fn_text, head, head_mod, last, args) -> None:
        """A template engine configured without HTML escaping (``autoescape: false``)."""
        if fn.type == "identifier":
            mod, last = self.module_of(fn_text), self.export_of(fn_text) or last
        else:
            mod = head_mod or head.lower()
        if mod == "nunjucks" and last in ("configure", "Environment"):
            flag, off = "autoescape", "false"
        elif mod in ("handlebars", "hbs") and last in ("compile", "precompile", "create"):
            flag, off = "noEscape", "true"
        else:
            return
        value = self._options(args).get(flag)
        if value is None or self.unwrap(value).type != off:
            return
        line = node.start_point[0] + 1
        if ("autoescape", line) in self._seen:
            return
        self._seen.add(("autoescape", line))
        self.reports.append(
            Report(
                kind="html",
                node=node,
                sink_line=line,
                label=f"{fn_text}() with {flag}: {off}",
                taint=Taint("config", "template configuration", line, frozenset({"html"})),
                rule="ast-template-autoescape-off",
            )
        )

    def _weak_prefix_check(self, call, obj, prefix) -> None:
        """``resolved.startsWith(rootDir)`` without a trailing separator: /root-evil passes."""
        prefix = self.unwrap(prefix)
        if prefix is None or prefix.type not in ("identifier", "member_expression"):
            return
        name = self.key(prefix) or ""
        if not _DIRISH.search(name.rsplit(".", 1)[-1]) or name in self.sep_terminated:
            return
        target = self.unwrap(obj)
        resolved = False
        if target is not None and target.type == "call_expression":
            fn = target.child_by_field_name("function")
            last = self.callee_text(fn).rsplit(".", 1)[-1] if fn is not None else ""
            resolved = last in _RESOLVERS
        elif target is not None:
            resolved = (self.key(target) or "") in self.resolved
        if not resolved:
            return
        line = call.start_point[0] + 1
        if ("prefix", line) in self._seen:
            return
        self._seen.add(("prefix", line))
        self.reports.append(
            Report(
                kind="file",
                node=call,
                sink_line=line,
                label=f"{self.text(call)[:80]}",
                taint=Taint("check", "a path containment check", line, frozenset({"file"})),
                rule="ast-path-prefix-check",
            )
        )

    def _url_part(self, node) -> bool:
        """``x.host`` / ``x.hostname`` / ``x.origin`` (the parts a same-origin check compares)."""
        node = self.unwrap(node)
        if node is None or node.type != "member_expression":
            return False
        prop = node.child_by_field_name("property")
        return prop is not None and self.text(prop) in ("host", "hostname", "origin")

    def _checked(self, node) -> dict[str, frozenset[str]]:
        """Names an equality/allowlist test on ``node`` vouches for (``u.hostname`` -> ``u``)."""
        node = self.unwrap(node)
        out: dict[str, frozenset[str]] = {}
        if node is None:
            return out
        if node.type == "call_expression":
            # isAllowed(path.resolve(p)), list.includes(x.trim().toLowerCase())
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "member_expression":
                out.update(self._checked(fn.child_by_field_name("object")))
            args = node.child_by_field_name("arguments")
            for a in args.named_children if args is not None else []:
                out.update(self._checked(a))
            return out
        url_part = {
            "hostname": ALL_KINDS,
            "host": ALL_KINDS,
            "origin": ALL_KINDS,
            "href": ALL_KINDS,
            "protocol": frozenset({"html"}),  # a scheme check stops javascript: URLs only
            "pathname": frozenset({"file"}),
        }
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            obj_node = self.unwrap(node.child_by_field_name("object"))
            part = url_part.get(self.text(prop)) if prop is not None else None
            if (
                part is not None
                and obj_node is not None
                and obj_node.type
                in (
                    "new_expression",
                    "call_expression",
                )
            ):
                # new URL(x).hostname, url.parse(x).host: the check covers x
                args = obj_node.child_by_field_name("arguments")
                if args is not None and args.named_children:
                    for name in self._checked(args.named_children[0]):
                        out[name] = part
                return out
        k = self.key(node)
        if k is None:
            return out
        out[k] = ALL_KINDS
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            obj = self.key(node.child_by_field_name("object"))
            part = url_part.get(self.text(prop)) if prop is not None else None
            if part is not None and obj is not None:
                out[obj] = part
        return out

    # --- functions -------------------------------------------------------------------
    def _params(self, fn) -> list[Any]:
        params = fn.child_by_field_name("parameters")
        if params is None:
            single = fn.child_by_field_name("parameter")
            return [single] if single is not None else []
        return [p for p in params.named_children if p.type != "comment"]

    def _param_pattern(self, p):
        if p.type in ("required_parameter", "optional_parameter"):
            return p.child_by_field_name("pattern")
        return p

    def _param_type(self, p) -> str:
        if p.type in ("required_parameter", "optional_parameter"):
            ann = p.child_by_field_name("type")
            if ann is not None:
                return self.text(ann).lstrip(":").strip()
        return ""

    def _names(self, pattern) -> list[str]:
        if pattern is None:
            return []
        if pattern.type == "identifier":
            return [self.text(pattern)]
        names: list[str] = []
        for n in walk(pattern):
            if n.type == "shorthand_property_identifier_pattern":
                names.append(self.text(n))
            elif n.type == "pair_pattern":
                value = n.child_by_field_name("value")
                if value is not None and value.type == "identifier":
                    names.append(self.text(value))
            elif (
                n.type == "identifier"
                and n.parent is not None
                and n.parent.type
                in (
                    "assignment_pattern",
                    "rest_pattern",
                    "array_pattern",
                    "object_assignment_pattern",
                )
            ):
                names.append(self.text(n))
        return names

    def _fn_name(self, fn) -> str:
        name = fn.child_by_field_name("name")
        if name is not None:
            return self.text(name)
        parent = fn.parent
        if parent is not None and parent.type == "variable_declarator":
            n = parent.child_by_field_name("name")
            return self.text(n) if n is not None else "function"
        if parent is not None and parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            return (self.key(left) or "function").rsplit(".", 1)[-1]
        if parent is not None and parent.type == "pair":
            k = parent.child_by_field_name("key")
            return self.text(k) if k is not None else "function"
        return "function"

    def _exported(self, fn) -> bool:
        cur = fn.parent
        while cur is not None and cur.type in ("variable_declarator", "lexical_declaration"):
            cur = cur.parent
        return cur is not None and cur.type == "export_statement"

    def _param_taint(self, fn) -> dict[str, TaintSet]:
        """Parameters of a function analyzed on its own: the library-API heuristic."""
        out: dict[str, TaintSet] = {}
        fname = self._fn_name(fn)
        line = fn.start_point[0] + 1
        exported = self._exported(fn)
        for p in self._params(fn):
            pattern = self._param_pattern(p)
            if pattern is None:
                continue
            if pattern.type == "object_pattern":
                for name in self._names(pattern):
                    if name == "searchParams" or (exported and name in ("params", "query")):
                        out[name] = {"request": Taint("request", f"route {name}", line, ALL_KINDS)}
            ptype = self._param_type(p)
            if ptype in _NUMERIC_TYPES or _LITERAL_UNION.match(ptype):
                continue
            for name in self._names(pattern):
                if name in out or name in ("this", "cb", "callback", "done", "next"):
                    continue
                if _RUNNER_PARAM.search(name):
                    continue
                out[name] = {
                    "param": Taint(
                        "param",
                        f"parameter '{name}' of {fname}()",
                        line,
                        FLAVOR_KINDS["param"],
                    )
                }
        return out

    def _function(
        self,
        fn,
        scope: dict[str, TaintSet],
        tainted: dict[str, TaintSet] | None = None,
    ) -> TaintSet:
        """Walk a function with the enclosing scope (closures); returns its return taint."""
        if tainted is None:
            span = (fn.start_byte, fn.end_byte)
            if span in self._done:
                return {}
            self._done.add(span)
            tainted = self._param_taint(fn)
        inner = dict(scope)
        for p in self._params(fn):
            for name in self._names(self._param_pattern(p)):
                inner.pop(name, None)
                for k in [s for s in inner if s.startswith((name + ".", name + REST))]:
                    del inner[k]
        inner.update(tainted)
        body = fn.child_by_field_name("body")
        if body is None:
            return {}
        self._ret_stack.append({})
        try:
            if body.type == "statement_block":
                self._block(body, inner)
            else:
                self._expr(body, inner)
                self._ret_stack[-1] = merge(self._ret_stack[-1], self._eval(body, inner))
        finally:
            ret = self._ret_stack.pop()
        return ret

    def _callback(self, fn, scope: dict[str, TaintSet]) -> bool:
        """Walk a function literal passed as an argument; True when it was one."""
        args = fn.parent
        if args is None or args.type != "arguments":
            return False
        call = args.parent
        if call is None or call.type not in ("call_expression", "new_expression"):
            return False
        span = (fn.start_byte, fn.end_byte)
        if span in self._done:
            return True
        self._done.add(span)
        tainted: dict[str, TaintSet] = {}
        params = [self._param_pattern(p) for p in self._params(fn)]
        callee = call.child_by_field_name("function")
        argv = list(args.named_children)
        last = self.callee_text(callee).rsplit(".", 1)[-1] if callee is not None else ""
        first_arg = self.string(argv[0]) if argv else None
        line = fn.start_point[0] + 1
        if params and callee is not None and callee.type == "member_expression":
            recv = self._eval(callee.child_by_field_name("object"), scope)
            if last in _ITERATORS and recv:
                for name in self._names(params[0]):
                    tainted[name] = recv
            elif last in ("reduce", "reduceRight") and recv and len(params) > 1:
                for name in self._names(params[1]):
                    tainted[name] = recv
        if params and last in ("on", "once", "addEventListener", "addListener"):
            if first_arg == "message":
                for name in self._names(params[0]):
                    tainted[name] = {"dom": Taint("dom", "postMessage event data", line, ALL_KINDS)}
            elif first_arg == "entry":
                for name in self._names(params[0]):
                    tainted[name] = {
                        "archive": Taint("archive", "an archive entry name", line, ALL_KINDS)
                    }
        self._function(fn, scope, tainted)
        return True

    def _inline(
        self, fn, name: str, call, args: list[Any], scope: dict[str, TaintSet]
    ) -> TaintSet | None:
        """Follow a call to a function defined once in the file; its return taint.

        None when the call is not followed (recursion, depth limit).
        """
        if name in self._inline_stack or len(self._inline_stack) >= 3:
            return None
        callee: dict[str, TaintSet] = {}
        passed: set[tuple[str, str, int]] = set()
        for p, a in zip(self._params(fn), args, strict=False):
            ts = self._eval(a, scope)
            if ts:
                for pname in self._names(self._param_pattern(p)):
                    callee[pname] = ts
                passed.update((t.flavor, t.origin, t.line) for t in ts.values())
        outer = self._anchor is None
        anchor_line = call.start_point[0] + 1 if outer and passed else 0
        key = (
            name,
            fn.start_byte,
            anchor_line,
            tuple(
                sorted(
                    (p, f, t.line, tuple(sorted(t.kinds)), t.built)
                    for p, ts in callee.items()
                    for f, t in ts.items()
                )
            ),
        )
        if key in self._inline_memo:
            return self._inline_memo[key]
        self._inline_memo[key] = {}
        self._inline_stack.append(name)
        saved = (self._anchor, self._passed)
        if outer:
            self._anchor = call
            self._passed = passed
        try:
            ret = self._function(fn, {}, callee)
        finally:
            self._inline_stack.pop()
            self._anchor, self._passed = saved
        self._inline_memo[key] = ret
        return ret

    # --- expressions ------------------------------------------------------------------
    def _expr(self, node, scope: dict[str, TaintSet]) -> None:
        """Check sinks and walk nested functions inside one expression."""
        stack = [node]
        while stack:
            n = stack.pop()
            self.tick()
            t = n.type
            if t in _FUNCTION_TYPES:
                if not self._callback(n, scope):
                    self._function(n, scope)
                continue
            if t in ("class_declaration", "class"):
                body = n.child_by_field_name("body")
                if body is not None:
                    self._generic(body, scope)
                continue
            if t in ("call_expression", "new_expression"):
                self._check_call(n, scope)
                fn = n.child_by_field_name("function")
                if fn is not None and self._local_target(fn) is not None:
                    self._eval_call(n, scope)  # follow the call to report sinks inside
            elif t == "assignment_expression":
                self._check_assignment(n, scope)
            elif t == "jsx_attribute":
                kids = n.named_children
                if kids and self.text(kids[0]) == "dangerouslySetInnerHTML":
                    for pair in walk(n):
                        if pair.type == "pair":
                            k = pair.child_by_field_name("key")
                            if k is not None and self.text(k) == "__html":
                                self._sink(
                                    n,
                                    "html",
                                    pair.child_by_field_name("value"),
                                    "dangerouslySetInnerHTML",
                                    scope,
                                )
            stack.extend(reversed(n.children))

    def _local_target(self, fn):
        fn = self.unwrap(fn)
        if fn is None:
            return None
        if fn.type == "identifier":
            return self.local_funcs.get(self.text(fn))
        if fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            prop = fn.child_by_field_name("property")
            if obj is not None and prop is not None and obj.type == "this":
                return self.local_methods.get(self.text(prop))
        return None

    def _stringy(self, node) -> bool:
        """Whether an expression contains literal string text (a command/code fragment)."""
        node = self.unwrap(node)
        if node is None:
            return False
        if node.type == "string":
            return bool(self.string(node))
        if node.type == "template_string":
            return any(
                c.type == "string_fragment" and self.text(c).strip() for c in node.named_children
            )
        if node.type == "binary_expression":
            op = node.child_by_field_name("operator")
            if op is not None and self.text(op) == "+":
                return self._stringy(node.child_by_field_name("left")) or self._stringy(
                    node.child_by_field_name("right")
                )
        if node.type == "array":
            return any(self._stringy(c) for c in node.named_children)
        return False

    def _source_member(self, key: str, node) -> TaintSet:
        return self._source_or_none(key, node) or {}

    def _source_or_none(self, key: str, node) -> TaintSet | None:
        """The taint of a source read by name; {} for a known-clean field, None otherwise."""
        masked = self.masked(key)
        line = node.start_point[0] + 1
        if _REQUEST_MEMBER.match(masked):
            if _UPLOAD_OBJ.match(masked) and key.rsplit(".", 1)[-1] in _SERVER_UPLOAD_FIELDS:
                return {}
            return {"request": Taint("request", key, line, ALL_KINDS)}
        if _DOM_MEMBER.match(masked):
            return {"dom": Taint("dom", key, line, ALL_KINDS)}
        if _ENV_MEMBER.match(masked):
            return {"env": Taint("env", key, line, ALL_KINDS)}
        return None

    def _eval(self, node, scope: dict[str, TaintSet]) -> TaintSet:
        self.tick()
        if node is None:
            return {}
        t = node.type
        if t in _TS_WRAPPERS or t == "spread_element":
            return self._eval(node.named_children[0], scope) if node.named_children else {}
        if t in (
            "number",
            "true",
            "false",
            "null",
            "undefined",
            "regex",
            "string",
            "this",
            "class",
            "unary_expression",
            "update_expression",
            *_FUNCTION_TYPES,
        ):
            return {}
        if t in ("identifier", "shorthand_property_identifier"):
            return scope.get(self.text(node), {})
        if t in ("member_expression", "subscript_expression"):
            key = self.key(node)
            if key is not None:
                if key in scope:
                    return scope[key]
                src = self._source_or_none(key, node)
                if src is not None:
                    return src
            prop = node.child_by_field_name("property")
            pname = self.text(prop) if prop is not None else ""
            if pname == "length":
                return {}
            obj = node.child_by_field_name("object")
            okey = self.key(obj)
            if okey is not None and okey + REST in scope:
                return scope[okey + REST]  # a field the object literal did not set
            out: TaintSet = self._eval(obj, scope)
            if pname == "pathname" and out:
                inner = self.unwrap(obj)
                if (okey or "") in self.url_objects or (
                    inner is not None
                    and inner.type == "new_expression"
                    and self.callee_text(inner.child_by_field_name("constructor")) == "URL"
                ):
                    out = strip(out, frozenset({"file"}))  # the URL parser removes dot segments
            return out
        if t in ("call_expression", "new_expression"):
            return self._eval_call(node, scope)
        if t == "template_string":
            out = {}
            for child in node.named_children:
                if child.type == "template_substitution":
                    for c in child.named_children:
                        out = merge(out, self._eval(c, scope))
            return mark_built(out) if out and self._stringy(node) else out
        if t == "ternary_expression":
            return merge(
                self._eval(node.child_by_field_name("consequence"), scope),
                self._eval(node.child_by_field_name("alternative"), scope),
            )
        if t == "object":
            out = {}
            for c in node.named_children:
                if c.type == "pair":
                    out = merge(out, self._eval(c.child_by_field_name("value"), scope))
                elif c.type in ("spread_element", "shorthand_property_identifier"):
                    out = merge(out, self._eval(c, scope))
            return unbuilt(out)
        if t == "array":
            out = {}
            for c in node.named_children:
                out = merge(out, self._eval(c, scope))
            return unbuilt(out)
        if t == "binary_expression":
            op = node.child_by_field_name("operator")
            op_text = self.text(op) if op is not None else ""
            if op_text in (
                "===",
                "==",
                "!==",
                "!=",
                "<",
                ">",
                "<=",
                ">=",
                "instanceof",
                "in",
                "-",
                "*",
                "/",
                "%",
                "**",
                "&",
                "|",
                "^",
                "<<",
                ">>",
                ">>>",
            ):
                return {}
            out = merge(
                self._eval(node.child_by_field_name("left"), scope),
                self._eval(node.child_by_field_name("right"), scope),
            )
            if op_text == "+" and out and self._stringy(node):
                out = mark_built(out)
            return out
        if t in ("assignment_expression", "augmented_assignment_expression"):
            return self._eval(node.child_by_field_name("right"), scope)
        if t == "sequence_expression":
            kids = node.named_children
            return self._eval(kids[-1], scope) if kids else {}
        out = {}
        for child in node.named_children:
            out = merge(out, self._eval(child, scope))
        return out

    def _call_source(self, node, fn, fn_text: str) -> TaintSet:
        line = node.start_point[0] + 1
        masked = self.masked(fn_text)
        if self.ctx is not None and self.ctx.is_trusted_call(fn_text):
            return {}
        if _REQUEST_CALL.match(masked):
            return {"request": Taint("request", f"{fn_text}()", line, ALL_KINDS)}
        if fn.type == "identifier":
            mod = self.module_of(fn_text)
            if fn_text in _H3_SOURCES and mod in ("", "h3"):
                return {"request": Taint("request", f"{fn_text}()", line, ALL_KINDS)}
            if fn_text in _HOOK_SOURCES and fn_text not in self.local_funcs:
                return {"dom": Taint("dom", f"{fn_text}()", line, ALL_KINDS)}
        if fn_text.endswith(".getEntries") or fn_text == "getEntries":
            return {"archive": Taint("archive", "archive entries", line, ALL_KINDS)}
        return {}

    def _sanitized(self, fn, fn_text: str, last: str) -> frozenset[str]:
        """Kinds a call to ``fn_text`` neutralizes."""
        kinds: frozenset[str] = frozenset()
        if fn.type == "identifier" and last in _NUMERIC:
            return ALL_KINDS
        if fn_text.startswith("Math."):
            return ALL_KINDS
        head = fn_text.split(".", 1)[0]
        mod = self.module_of(head) if fn.type != "identifier" else self.module_of(fn_text)
        if mod in _SANITIZER_MODULES:
            kinds |= _SANITIZER_MODULES[mod]
        if last in _LEGACY_SANITIZERS:
            kinds |= _LEGACY_SANITIZERS[last]
        if _NOT_SANITIZER.search(last):
            return kinds
        if fn_text in ("path.basename", "posix.basename", "win32.basename") or last == "basename":
            kinds |= frozenset({"file"})
        if fn_text == "JSON.stringify":
            kinds |= frozenset({"code"})
        if _SHELL_ESCAPE.search(last):
            kinds |= frozenset({"shell"})
        if _CODE_ESCAPE.search(last):
            kinds |= frozenset({"code"})
        if _FILE_SANITIZER.search(last):
            kinds |= frozenset({"file"})
        if _URL_SANITIZER.search(last):
            kinds |= frozenset({"html", "redirect"})
        if _SQL_ESCAPE.search(last):
            kinds |= frozenset({"sql"})
        if _HTML_ESCAPE.search(last) and not kinds - {"html"}:
            kinds |= frozenset({"html"})
        if self.ctx is not None:
            for kind, cwe in KIND_CWE.items():
                if self.ctx.clears(fn_text, frozenset({cwe})):
                    kinds |= frozenset({kind})
        return kinds

    def _replace_sanitizes(self, args: list[Any]) -> frozenset[str]:
        """``x.replace(/[^\\w.-]/g, '')`` removes every character a payload needs."""
        if len(args) < 2:
            return frozenset()
        pat = self.unwrap(args[0])
        if pat is None or pat.type != "regex":
            return frozenset()
        pattern = pat.child_by_field_name("pattern")
        flags = pat.child_by_field_name("flags")
        ptext = self.text(pattern) if pattern is not None else ""
        if flags is None or "g" not in self.text(flags):
            return frozenset()
        if (
            re.match(r"^\[\^[^\]]*\][+*]?$", ptext)
            and self.string(self.unwrap(args[1])) is not None
        ):
            return ALL_KINDS
        if "<" in ptext or '"' in ptext:
            return frozenset({"html"})
        return frozenset()

    def _eval_call(self, node, scope: dict[str, TaintSet]) -> TaintSet:
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if fn is None:
            return {}
        fn_text = self.callee_text(fn)
        args_node = node.child_by_field_name("arguments")
        if args_node is not None and args_node.type == "template_string":
            if fn_text in _SAFE_SQL_TAGS:
                return {}
            return self._eval(args_node, scope)
        args = args_node.named_children if args_node is not None else []
        last = fn_text.rsplit(".", 1)[-1]
        src = self._call_source(node, fn, fn_text)
        if src:
            return src
        cleared = self._sanitized(fn, fn_text, last)
        if cleared == ALL_KINDS or self._io_call(fn, fn_text, last):
            return {}
        out: TaintSet = {}
        target = self._local_target(fn)
        inlined = self._inline(target, last, node, list(args), scope) if target else None
        if inlined is not None:
            out = inlined  # the helper's own return value, not a guess from its arguments
        elif fn_text == "URL" and len(args) > 1:
            # new URL(path, request.url): the base is the request's own origin, so it does
            # not make a redirect open (the path argument still can).
            out = merge(
                self._eval(args[0], scope),
                strip(self._eval(args[1], scope), frozenset({"redirect"})),
            )
        else:
            for a in args:
                if a.type in ("arrow_function", "function_expression"):
                    # trySafe(() => decode(x)), useMemo(() => ...): the callback's value
                    body = a.child_by_field_name("body")
                    if body is not None and body.type != "statement_block":
                        out = merge(out, self._eval(body, scope))
                    continue
                out = merge(out, self._eval(a, scope))
        if fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            recv = self._eval(obj, scope)
            if last in _CLEAN_METHODS:
                return {}
            if last == "get" and not self._is_source_key(self.key(obj) or ""):
                # MAP.get(key): the value comes from MAP, not from the key.
                out = recv if recv else {}
            elif last == "replace":
                cleared = cleared | self._replace_sanitizes(list(args))
                if out and (self._stringy(obj) or any(t.built for t in recv.values())):
                    out = mark_built(out)
                out = merge(recv, out)
            elif last in ("resolve", "join", "normalize") and self._path_module(fn, fn_text):
                if last == "join" and len(args) > 1 and inlined is None:
                    # path.join(root, path.normalize('/' + p)): `..` cannot climb above the
                    # root the inner path starts from, so the result stays under root.
                    out = {}
                    for i, a in enumerate(args):
                        ts = self._eval(a, scope)
                        if i and self._rooted_norm(a):
                            ts = strip(ts, frozenset({"file"}))
                        out = merge(out, ts)
                out = mark_built(out) if len(args) > 1 else out
            elif (
                last in ("map", "flatMap")
                and args
                and self.unwrap(args[0]).type in ("identifier", "member_expression")
            ):
                # list.map(escapeShellArg): the named function sanitizes every element
                f = self.unwrap(args[0])
                f_text = self.callee_text(f)
                out = strip(merge(recv, out), self._sanitized(f, f_text, f_text.rsplit(".", 1)[-1]))
            elif last in ("join", "concat"):
                if out or recv:
                    stringy = (obj is not None and self._stringy(obj)) or any(
                        self._stringy(a) for a in args
                    )
                    out = merge(recv, out)
                    if stringy:
                        out = mark_built(out)
            else:
                out = merge(recv, out)
        elif fn_text in ("format", "util.format") and args and self._stringy(args[0]):
            out = mark_built(out)
        if cleared:
            out = strip(out, cleared)
        return out

    def _rooted_norm(self, node) -> bool:
        """``path.join('/', p)`` / ``path.normalize('/' + p)``, or a variable holding one."""
        node = self.unwrap(node)
        if node is None:
            return False
        if node.type in ("identifier", "member_expression"):
            return (self.key(node) or "") in self.rooted_vars
        if node.type != "call_expression":
            return False
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None or not args.named_children:
            return False
        fn_text = self.callee_text(fn)
        last = fn_text.rsplit(".", 1)[-1]
        return (
            last in ("join", "normalize", "resolve")
            and self._path_module(fn, fn_text)
            and self._rooted(args.named_children[0])
        )

    def _rooted(self, node) -> bool:
        """A path argument that is the root itself or starts with it (``'/'``, ``'/' + p``)."""
        node = self.unwrap(node)
        if node is None:
            return False
        lit = self.string(node)
        if lit is not None:
            return lit in ("/", "\\")
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            while left is not None and left.type == "binary_expression":
                left = left.child_by_field_name("left")
            return self.string(left) == "/"
        if node.type == "template_string":
            for c in node.named_children:
                return c.type == "string_fragment" and self.text(c).startswith("/")
        return False

    def _io_call(self, fn, fn_text: str, last: str) -> bool:
        """Calls whose result is data from elsewhere, not their argument (fetch, exec, readFile)."""
        if self._cp_function(fn) is not None:
            return True
        head = fn_text.split(".", 1)[0]
        if self._is_http_call(fn, fn_text, head, self.module_of(head), last):
            return True
        if fn.type == "identifier":
            return self.module_of(fn_text) in _FS_MODULES and self.export_of(fn_text) in _FS_SINKS
        return last in _FS_SINKS and (self.module_of(head) in _FS_MODULES or head in _FS_NAMES)

    # --- sinks ------------------------------------------------------------------------
    def _check_assignment(self, node, scope: dict[str, TaintSet]) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "member_expression":
            return
        prop = left.child_by_field_name("property")
        pname = self.text(prop) if prop is not None else ""
        key = self.key(left) or ""
        if pname in ("innerHTML", "outerHTML", "srcdoc"):
            self._sink(node, "html", right, pname, scope)
        elif key == "ctx.body" and self.unwrap(right).type not in (
            "object",
            "array",
        ):
            self._sink(
                node, "html", right, "ctx.body (Koa sends a string starting with < as HTML)", scope
            )
        elif key in (
            "location.href",
            "window.location.href",
            "window.location",
            "document.location",
        ):
            self._sink(node, "redirect", right, key, scope)

    def _cp_function(self, fn) -> str | None:
        """The child_process / shelljs / execa function a callee names, if any."""
        fn = self.unwrap(fn)
        if fn is None:
            return None
        if fn.type == "identifier":
            q = self.imports.get(self.text(fn), "")
            mod, _, name = q.partition("#")
            if mod in _CP_MODULES and name:
                return name
            if mod == "shelljs" and name == "exec":
                return "exec"
            if mod == "execa" and name in ("execaCommand", "execaCommandSync"):
                return "exec"
            return None
        if fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            prop = fn.child_by_field_name("property")
            if obj is None or prop is None:
                return None
            name = self.text(prop)
            mod = self._require_module(obj) or ""
            head = self.key(obj) or ""
            if not mod:
                mod = self.module_of(head)
            if mod in _CP_MODULES or (not mod and head in _CP_NAMES):
                return name
            if mod == "shelljs" and name == "exec":
                return "exec"
            if mod == "execa" and name in ("command", "commandSync"):
                return "exec"
        return None

    def _is_eval(self, fn) -> bool:
        fn = self.unwrap(fn)
        if fn is None:
            return False
        if fn.type == "identifier":
            return self.text(fn) == "eval"
        if fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            obj = self.key(fn.child_by_field_name("object")) or ""
            return (
                prop is not None
                and self.text(prop) == "eval"
                and obj
                in (
                    "window",
                    "globalThis",
                    "global",
                    "self",
                )
            )
        if fn.type == "subscript_expression":
            obj = self.key(fn.child_by_field_name("object")) or ""
            return (
                obj in ("window", "globalThis", "global", "self")
                and self.string(fn.child_by_field_name("index")) == "eval"
            )
        if fn.type == "parenthesized_expression" or fn.type == "sequence_expression":
            kids = fn.named_children
            return bool(kids) and self._is_eval(kids[-1])
        return False

    def _options(self, args: list[Any]) -> dict[str, Any]:
        for a in args:
            a = self.unwrap(a)
            if a is not None and a.type == "object":
                return self._pairs(a)
        return {}

    def _pairs(self, obj) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for c in obj.named_children:
            if c.type == "pair":
                k = c.child_by_field_name("key")
                v = c.child_by_field_name("value")
                if k is not None and v is not None:
                    out[self.string(k) or self.text(k)] = v
            elif c.type == "shorthand_property_identifier":
                out[self.text(c)] = c
        return out

    def _check_call(self, node, scope: dict[str, TaintSet]) -> None:
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if fn is None:
            return
        args_node = node.child_by_field_name("arguments")
        if args_node is not None and args_node.type == "template_string":
            return
        args = list(args_node.named_children) if args_node is not None else []
        first = args[0] if args else None
        fn_text = self.callee_text(fn)
        last = fn_text.rsplit(".", 1)[-1]
        head = fn_text.split(".", 1)[0]
        head_mod = self.module_of(head)
        is_new = node.type == "new_expression"

        # code
        if self._is_eval(fn):
            self._sink(node, "code", first, "eval()", scope)
            return
        if fn_text in ("Function", "window.Function", "globalThis.Function"):
            for a in args:
                self._sink(node, "code", a, "the Function constructor", scope, no_param=True)
            return
        if (head_mod in _VM_MODULES or head == "vm") and (
            last in _VM_SINKS or (is_new and last == "Script")
        ):
            self._sink(node, "code", first, f"{fn_text}()", scope)
            return
        if fn_text in ("setTimeout", "setInterval") and first is not None:
            inner = self.unwrap(first)
            if inner is not None and inner.type in (
                "string",
                "template_string",
                "binary_expression",
            ):
                self._sink(node, "code", first, f"{fn_text}() with a string", scope)
            return

        # shell
        cp = self._cp_function(fn)
        if cp is not None:
            self._shell_call(node, cp, args, scope)
            return

        # SQL
        if fn.type == "member_expression" and first is not None:
            obj = fn.child_by_field_name("object")
            if last in (
                "query",
                "execute",
                "raw",
                "unsafe",
                "$queryRawUnsafe",
                "$executeRawUnsafe",
            ) or (last == "prepare" and obj is not None and _SQL_RECEIVER.search(self.text(obj))):
                inner = self.unwrap(first)
                if inner is not None and inner.type not in ("object", "array"):
                    self._sink(node, "sql", first, f"{fn_text}()", scope)
                return

        # template engines (server-side template injection)
        if fn.type == "identifier":
            allowed = _TEMPLATE_MODULES.get(self.module_of(fn_text), set())
            name = self.export_of(fn_text) or "default"
        else:
            allowed = _TEMPLATE_MODULES.get(head_mod) or _TEMPLATE_HEADS.get(head, set())
            name = last
        if first is not None and name in allowed:
            self._sink(node, "template", first, f"{fn_text}() template source", scope)
        self._autoescape_off(node, fn, fn_text, head, head_mod, last, args)
        if last in ("SafeString",) and is_new:
            self._sink(node, "html", first, "new SafeString()", scope)
            return
        if last.startswith("bypassSecurityTrust") or last == "unsafeHTML":
            self._sink(node, "html", first, f"{last}()", scope)
            return

        # file system
        fs_fn = None
        if fn.type == "identifier":
            if self.module_of(fn_text) in _FS_MODULES:
                fs_fn = self.export_of(fn_text)
        elif fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            obj_key = self.key(obj) or ""
            root_mod = self.module_of(obj_key.split(".", 1)[0]) or (self._require_module(obj) or "")
            if root_mod in _FS_MODULES or (not root_mod and obj_key.split(".", 1)[0] in _FS_NAMES):
                fs_fn = last
        if fs_fn in _FS_SINKS:
            self._sink(node, "file", first, f"{fn_text}()", scope)
            if fs_fn in _FS_TWO_PATHS and len(args) > 1:
                self._sink(node, "file", args[1], f"{fn_text}()", scope)
            return
        if head in _RES_NAMES and last in ("sendFile", "download", "sendfile"):
            opts = self._options(args[1:])
            if "root" not in opts:
                self._sink(node, "file", first, f"{fn_text}()", scope)
            return
        if fn_text in ("express.static", "serveStatic") or (
            fn.type == "identifier" and self.module_of(fn_text) == "serve-static"
        ):
            self._sink(node, "file", first, f"{fn_text}() root", scope)
            return

        # SSRF
        if self._is_http_call(fn, fn_text, head, head_mod, last):
            target = first
            inner = self.unwrap(first)
            if inner is not None and inner.type == "object":
                pairs = self._pairs(inner)
                for k in _URL_KEYS:
                    if k in pairs:
                        self._sink(node, "ssrf", pairs[k], f"{fn_text}() {k}", scope)
                return
            self._sink(node, "ssrf", target, f"{fn_text}()", scope)
            return

        # redirect
        if last == "redirect" and (
            fn.type == "member_expression"
            or (fn.type == "identifier" and _REDIRECT_MODULES.match(self.module_of(fn_text)))
        ):
            # res/ctx/reply/NextResponse/Response.redirect, Koa's this.redirect: any
            # receiver, since only request or URL input is reported here
            target = args[-1] if args else None
            self._sink(node, "redirect", target, f"{fn_text}()", scope)
            return
        if fn_text in (
            "location.assign",
            "location.replace",
            "window.location.assign",
            "window.location.replace",
            "window.open",
        ):
            self._sink(node, "redirect", first, f"{fn_text}()", scope)
            return
        if (
            head in _RES_NAMES | {"ctx", "reply"}
            and last in ("setHeader", "set", "header")
            and len(args) > 1
        ):
            header = self.string(self.unwrap(args[0]))
            if header is not None and header.lower() == "location":
                self._sink(node, "redirect", args[1], f"{fn_text}('Location')", scope)
            return

        # XSS
        if fn_text in ("document.write", "document.writeln"):
            self._sink(node, "html", first, f"{fn_text}()", scope)
            return
        if last == "insertAdjacentHTML" and len(args) > 1:
            self._sink(node, "html", args[1], "insertAdjacentHTML()", scope)
            return
        if last == "createContextualFragment":
            self._sink(node, "html", first, "createContextualFragment()", scope)
            return
        if (
            fn.type == "member_expression"
            and last == "html"
            and len(args) == 1
            and head
            in (
                "$",
                "jQuery",
            )
        ):
            self._sink(node, "html", first, ".html()", scope)
            return
        if fn.type == "member_expression" and last == "html" and len(args) == 1 and head == "c":
            self._sink(node, "html", first, "c.html()", scope)  # Hono
            return
        if fn_text in ("$", "jQuery") and first is not None and self.unwrap(first).type != "string":
            # $(html) parses markup; $(selector) on a tainted selector only matters when the
            # value is read straight from the URL (the classic $(location.hash)).
            direct = self._source_member(self.key(first) or "", first)
            if self._has_markup(first) or direct:
                self._sink(node, "html", first, f"{fn_text}() with markup", scope)
            return
        if last == "setAttribute" and len(args) > 1:
            attr = (self.string(self.unwrap(args[0])) or "").lower()
            if attr.startswith("on") or attr == "srcdoc":
                self._sink(node, "html", args[1], f"setAttribute('{attr}')", scope)
            return
        if (
            head in _RES_NAMES | {"reply"}
            and last in ("send", "end", "write")
            and first is not None
        ):
            inner = self.unwrap(first)
            if inner is None or inner.type in ("object", "array"):
                return
            ctype = self._content_type(node)
            if ctype is False:
                return
            # Express's res.send() of a string defaults to text/html.
            express_default = last == "send" and head in ("res", "response") and ctype is None
            if express_default or ctype or self._has_markup(first):
                self._sink(node, "html", first, f"{fn_text}() HTML response", scope)
            return
        if is_new and fn_text == "Response" and first is not None and self._html_content_type(node):
            self._sink(node, "html", first, "new Response() with text/html", scope)

    def _shell_call(self, node, cp: str, args: list[Any], scope: dict[str, TaintSet]) -> None:
        first = args[0] if args else None
        label = f"child_process.{cp}()"
        if cp in _CP_EXEC:
            self._sink(node, "shell", first, label, scope)
            return
        if cp not in _CP_SPAWN:
            return
        opts = self._options(args[1:])
        shell = opts.get("shell")
        shell_on = shell is not None and self.unwrap(shell).type not in (
            "false",
            "null",
            "undefined",
        )
        binary = self.string(self.unwrap(first)) if first is not None else None
        argv = self.unwrap(args[1]) if len(args) > 1 else None
        if shell_on:
            self._sink(node, "shell", first, f"{label} with shell: true", scope)
            if argv is not None and argv.type != "object":
                self._sink(node, "shell", argv, f"{label} with shell: true", scope, raw_ok=True)
            return
        if binary is not None and _SHELL_BINARIES.match(binary) and argv is not None:
            flags = [self.string(c) for c in walk(argv) if c.type == "string"]
            if any(f in _SHELL_FLAGS for f in flags):
                self._sink(node, "shell", argv, f"{label} of {binary}", scope, raw_ok=True)

    def _is_http_call(self, fn, fn_text: str, head: str, head_mod: str, last: str) -> bool:
        fn = self.unwrap(fn)
        if fn is None:
            return False
        if fn.type == "identifier":
            if fn_text in _HTTP_GLOBALS and fn_text not in self.local_funcs:
                return True
            mod = self.module_of(fn_text)
            return mod in _HTTP_CLIENTS and self.export_of(fn_text) not in (
                "Agent",
                "create",
                "extend",
            )
        if fn.type == "member_expression":
            if head_mod in _HTTP_MODULES or (not head_mod and head in ("http", "https")):
                return last in ("get", "request")
            if head_mod in _HTTP_CLIENTS or (
                not head_mod and head in ("axios", "got", "superagent")
            ):
                return last in _HTTP_VERBS
        return False

    def _has_markup(self, node) -> bool:
        return any(
            n.type == "string_fragment" and re.search(r"<[A-Za-z/!]", self.text(n))
            for n in walk(node)
        )

    def _html_content_type(self, node) -> bool:
        return self._content_type(node) is True

    def _content_type(self, node) -> bool | None:
        """True when the enclosing function sets an HTML content type, False for another
        explicit type (JSON, text/plain), None when it sets none."""
        cur = node.parent
        while cur is not None and cur.type not in _FUNCTION_TYPES:
            cur = cur.parent
        body = self.text(cur) if cur is not None else self.text(node)
        if re.search(r"text/html|\.type\(\s*['\"]html|\.contentType\(\s*['\"](?:text/)?html", body):
            return True
        if re.search(
            r"(?i)(?:content-type['\"]?\s*[,:]\s*['\"]|\.type\(\s*['\"]|\.contentType\(\s*['\"])"
            r"(?:text/plain|application/|json|text/css|text/csv|image/|text/javascript)",
            body,
        ):
            return False
        return None

    def _sink(
        self,
        node,
        kind: str,
        arg,
        label: str,
        scope: dict[str, TaintSet],
        *,
        raw_ok: bool = False,
        no_param: bool = False,
    ) -> None:
        if arg is None:
            return
        inner = self.unwrap(arg)
        if kind in ("ssrf", "redirect") and inner is not None:
            if inner.type == "ternary_expression":
                # check each branch: `cond ? `/${x}edit` : '/'` is pinned on both sides
                for field_name in ("consequence", "alternative"):
                    branch = inner.child_by_field_name(field_name)
                    self._sink(node, kind, branch, label, scope, raw_ok=raw_ok, no_param=no_param)
                return
            if self._host_pinned(arg):
                return
        for flavor, t in self._eval(arg, scope).items():
            if kind not in t.kinds or kind not in FLAVOR_KINDS.get(flavor, frozenset()):
                continue
            if flavor == "param" and (no_param or not (t.built or raw_ok)):
                continue
            if self._anchor is not None and (t.flavor, t.origin, t.line) not in self._passed:
                continue  # a source inside the helper: reported where the helper is analyzed
            anchor = self._anchor if self._anchor is not None else node
            line = anchor.start_point[0] + 1
            if (kind, line) in self._seen:
                continue
            self._seen.add((kind, line))
            self.reports.append(
                Report(
                    kind=kind, node=anchor, sink_line=node.start_point[0] + 1, label=label, taint=t
                )
            )

    def _host_pinned(self, node) -> bool:
        """A URL whose scheme and host are literal (``https://api.x.com/${id}``) or a local path."""
        node = self.unwrap(node)
        if node is None:
            return False
        if node.type == "template_string":
            text = ""
            for c in node.named_children:
                if c.type == "string_fragment":
                    text += self.text(c)
                else:
                    break
            return bool(_HOST_PINNED.match(text))
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            while left is not None and left.type == "binary_expression":
                left = left.child_by_field_name("left")
            lit = self.string(left) if left is not None else None
            return bool(lit and _HOST_PINNED.match(lit))
        if node.type in ("call_expression", "new_expression"):
            fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            args = node.child_by_field_name("arguments")
            argv = args.named_children if args is not None else []
            if fn is not None and self.callee_text(fn) == "URL" and len(argv) > 1:
                # new URL(path, base) keeps base's host only when path is relative
                return False
        return False


def _attacker(ts: TaintSet) -> bool:
    """Whether a value carries input an attacker controls (not just a parameter)."""
    return any(f in ("request", "dom", "archive") for f in ts)


def _union(a: dict[str, frozenset[str]], b: dict[str, frozenset[str]]):
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, frozenset()) | v
    return out


def _intersect(a: dict[str, frozenset[str]], b: dict[str, frozenset[str]]):
    return {k: a[k] & b[k] for k in a.keys() & b.keys() if a[k] & b[k]}
