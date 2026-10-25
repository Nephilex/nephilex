"""Flow-sensitive taint and constant analysis over a tree-sitter Python tree.

This is the engine behind the ``ast-python`` scanner (and the depth-1
cross-file tier that reuses it). It walks one function at a time, statement by
statement, and keeps an abstract value per variable:

* ``taint``: derived from an untrusted source (``request.args``, ``input()``, ...),
  with the set of CWEs a sanitizer or a guard has already cleared it for.
* ``lit``: derived only from literals, so it can never carry attacker data.
  This is what lets the scanner say "this ``shell=True`` command is constant".
* ``const``: the exact value, when it is a small literal and every path agrees.
  Used to fold conditions such as ``if 7 * 18 + num > 200`` and prune the
  branch that can never run.
* ``weak``: derived from the non-cryptographic ``random`` module.
* a few flags (``path`` for pathlib objects, ``xxe`` for XML parsers with
  external entities enabled, ``reqobj`` for objects built from the request).
* element-wise values for literal dicts, lists and ``configparser`` objects,
  so ``d['a'] = user; x = d['b']`` does not taint ``x``.

Control flow is structured: ``if``/``elif``/``else``, ``match``, loops and
``try`` are analyzed per branch and joined, so a clean reassignment inside one
branch (``if not p: p = ""``) no longer erases the taint the other branch keeps.
A branch whose condition folds to a constant is skipped, and a block that
always returns or raises does not flow into the code after it. Simple guards
refine the state on each side of a condition: an early return when
``'../' in p`` clears ``p`` for path traversal, an allowlist membership test
clears it entirely, and a ``urlparse(u).netloc`` allowlist clears ``u`` for
open redirect.

Everything here is intra-procedural and deliberately simple, except for helper
summaries: a call to a helper defined in the same file, or imported from
another file of the project (through :mod:`nephilex.scanners._pyproject`), is
analyzed through a bounded summary of the helper's body. Python's own
recursion is bounded: statements and expressions nested deeper than a fixed
limit fall back to a flat, conservative scan instead of recursing further, so a
hostile file cannot exhaust the stack.
"""

from __future__ import annotations

import ast as _pyast
import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from nephilex.scanners._pyproject import MAX_XFILE_DEPTH

if TYPE_CHECKING:
    from nephilex.context import LanguageContext

#: Sentinel for "value not known". A plain object: identity comparison only.
NOCONST: Any = object()

MAX_EXPR_DEPTH = 60
MAX_STMT_DEPTH = 60
MAX_ITEMS = 64  # container elements tracked one by one
MAX_STR = 4096  # longest folded constant string
MAX_LITERAL_TEXT = 4096  # longest literal handed to ast.literal_eval
LOOP_ROUNDS = 3
#: Statement visits per run before giving up on a (hostile) file. The scanner
#: reports such a file as skipped instead of spending unbounded time on it.
MAX_STEPS = 400_000


class AnalysisBudgetExceeded(RuntimeError):
    """A file needed more analysis work than :data:`MAX_STEPS` allows."""


CWE_SQL = "CWE-89"
CWE_CMD = "CWE-78"
CWE_PATH = "CWE-22"
CWE_CODE = "CWE-95"
CWE_DESER = "CWE-502"
CWE_XSS = "CWE-79"
CWE_REDIRECT = "CWE-601"
CWE_XXE = "CWE-611"
CWE_LDAP = "CWE-90"
CWE_XPATH = "CWE-643"
CWE_TRUST = "CWE-501"
CWE_WEAKRAND = "CWE-330"
CWE_SSRF = "CWE-918"
CWE_TEMPLATE = "CWE-1336"

#: Sink id -> the CWEs a sanitizer must clear for the value to be safe there.
SINK_CWES: dict[str, frozenset[str]] = {
    "ast-sql-injection": frozenset({CWE_SQL}),
    "ast-sql-string-building": frozenset({CWE_SQL}),
    "ast-command-injection": frozenset({CWE_CMD}),
    "ast-path-traversal": frozenset({CWE_PATH}),
    "ast-archive-extraction": frozenset({CWE_PATH}),
    "ast-code-injection": frozenset({CWE_CODE}),
    "ast-template-injection": frozenset({CWE_TEMPLATE}),
    "ast-unsafe-deserialization": frozenset({CWE_DESER}),
    "ast-xss": frozenset({CWE_XSS}),
    "ast-jinja-autoescape-off": frozenset({CWE_XSS}),
    "ast-open-redirect": frozenset({CWE_REDIRECT}),
    "ast-ssrf": frozenset({CWE_SSRF}),
    "ast-xxe": frozenset({CWE_XXE}),
    "ast-ldap-injection": frozenset({CWE_LDAP}),
    "ast-xpath-injection": frozenset({CWE_XPATH}),
    "ast-trust-boundary": frozenset({CWE_TRUST}),
    "ast-weak-random": frozenset({CWE_WEAKRAND}),
}
#: Sinks that do not depend on a tainted source (excluded from summaries).
NON_TAINT_SINKS = frozenset(
    {"ast-sql-string-building", "ast-weak-random", "ast-jinja-autoescape-off"}
)
TAINT_CWES: frozenset[str] = frozenset(
    c for sid, cwes in SINK_CWES.items() if sid not in NON_TAINT_SINKS for c in cwes
) | frozenset({"CWE-80", "CWE-94"})

#: Where tainted data came from. A value can carry several origins.
ORIGIN_REQUEST = "request"  # HTTP request data, CLI input, environment
ORIGIN_API = "public-api"  # a parameter of a public library function (library mode)
ORIGIN_ARCHIVE = "archive-entry"  # a member name read from a zip or tar archive
#: The command line, the environment or interactive input: controlled by
#: whoever runs the program, so it matters when another program passes
#: untrusted data through them. Reported at low confidence.
ORIGIN_OPERATOR = "operator"
_REQUEST_ORIGIN = frozenset({ORIGIN_REQUEST})
#: Sinks where an operator-controlled value is configuration, not an attack:
#: which server to call (OLLAMA_HOST, --api-url) or where to redirect.
_CONFIGURATION_SINKS = frozenset({"ast-ssrf", "ast-open-redirect"})

#: Library mode: what a value that comes only from a public API parameter must
#: look like before a sink reports it. A public function that hands its own
#: argument to ``open()`` or ``eval()`` usually does so by design (that is the
#: API); the injection the advisories describe is the library placing the
#: caller's value inside a path, command, query, page or expression it builds
#: itself ("embed"), or treating a field of caller-supplied data as code
#: ("part"). Sinks not listed here never report public-API-only flows (HTTP
#: clients, redirects, sessions and XML parsers are expected to receive the
#: caller's URL, target or document).
LIBRARY_SINK_SHAPES: dict[str, frozenset[str]] = {
    "ast-path-traversal": frozenset({"embed"}),
    "ast-xss": frozenset({"embed"}),
    "ast-command-injection": frozenset({"embed"}),
    "ast-sql-injection": frozenset({"embed"}),
    "ast-ldap-injection": frozenset({"embed"}),
    "ast-xpath-injection": frozenset({"embed"}),
    "ast-code-injection": frozenset({"embed", "part"}),
    "ast-template-injection": frozenset({"embed", "part"}),
    "ast-unsafe-deserialization": frozenset({"part"}),
    "ast-archive-extraction": frozenset({"whole", "embed", "part"}),
}

# Untrusted-input sources: an attribute chain or call target matching one of
# these is tainted. ``request.path`` and friends are attacker-controlled too.
SOURCE_RE = re.compile(
    r"\brequest\.(?:args|form|values|json|data|files|cookies|headers|query_params|GET|POST|"
    r"path|full_path|url|base_url|query_string|stream|get_json|get_data|referrer|environ|"
    r"body|path_params|match_info|COOKIES|FILES|META|remote_user)\b"
    r"|\binput\s*\("
    r"|\bsys\.argv\b"
    r"|\bflask\.request\b"
    r"|\bos\.environ\b"
)
#: The operator-controlled part of SOURCE_RE (ORIGIN_OPERATOR).
OPERATOR_SOURCE_RE = re.compile(r"\binput\s*\(|^input$|\bsys\.argv\b|\bos\.environ\b")
#: The request part of SOURCE_RE.
REQUEST_SOURCE_RE = re.compile(
    r"\brequest\.(?:args|form|values|json|data|files|cookies|headers|query_params|GET|POST|"
    r"path|full_path|url|base_url|query_string|stream|get_json|get_data|referrer|environ|"
    r"body|path_params|match_info|COOKIES|FILES|META|remote_user)\b|\bflask\.request\b"
)

# Function-name last components that neutralize taint for every sink (numeric
# coercion, quoting, path basename). Keyed on the final identifier of the target.
UNIVERSAL_SANITIZERS = frozenset(
    {
        "int",
        "float",
        "bool",
        "len",
        "ord",
        "abs",
        "round",
        "complex",
        "secure_filename",
        "basename",
        "quote",
        "safe_join",
        "quote_plus",
        "shlex",
        "url_for",
        "getint",
        "getfloat",
        "getboolean",
        "uuid4",
        "hexdigest",
    }
)
_IMMUTABLE_LITERALS = frozenset(
    {
        "string",
        "concatenated_string",
        "integer",
        "float",
        "true",
        "false",
        "none",
        "tuple",
        "binary_operator",
        "parenthesized_expression",
    }
)
_DICT_CTORS = frozenset(
    {"dict", "OrderedDict", "ConfigParser", "RawConfigParser", "SafeConfigParser"}
)
_LIST_CTORS = frozenset({"list", "deque"})
#: Sanitizers whose result is a number: it cannot carry attacker text at all.
NUMERIC_SANITIZERS = frozenset(
    {"int", "float", "bool", "len", "ord", "abs", "round", "complex", "getint", "getfloat"}
    | {"getboolean", "uuid4", "hexdigest"}
)
_XSS_CLEAN = frozenset({CWE_XSS, "CWE-80"})
_SQL_ESCAPES = frozenset({"escape", "escape_string", "escape_literal", "real_escape_string"})
_LDAP_ESCAPES = frozenset({"escape_filter_chars", "escape_dn_chars", "escape_rdn", "filter_format"})
_XSS_SANITIZER_NAMES = frozenset({"quoteattr", "strip_tags", "sanitize_html", "clean", "linkify"})

# Calls whose result is literal-derived when the receiver and arguments are.
PURE_FUNCTIONS = frozenset(
    {
        "str",
        "repr",
        "format",
        "bytes",
        "bytearray",
        "list",
        "tuple",
        "dict",
        "set",
        "frozenset",
        "sorted",
        "reversed",
        "min",
        "max",
        "sum",
        "chr",
        "hex",
        "oct",
        "bin",
        "b64encode",
        "b64decode",
        "urlsafe_b64encode",
        "urlsafe_b64decode",
        "b32encode",
        "b32decode",
        "b16encode",
        "b16decode",
        "hexlify",
        "unhexlify",
        "unquote",
        "unquote_plus",
        "urlencode",
        "unescape",
        "dumps",
        "loads",
        "join",
        "dirname",
        "splitext",
        "normpath",
        "deepcopy",
        "copy",
        "escape",
    }
)
PURE_METHODS = frozenset(
    {
        "encode",
        "decode",
        "format",
        "join",
        "replace",
        "strip",
        "lstrip",
        "rstrip",
        "upper",
        "lower",
        "title",
        "capitalize",
        "casefold",
        "swapcase",
        "split",
        "rsplit",
        "splitlines",
        "partition",
        "rpartition",
        "zfill",
        "center",
        "ljust",
        "rjust",
        "removeprefix",
        "removesuffix",
        "expandtabs",
        "translate",
        "find",
        "rfind",
        "index",
        "rindex",
        "count",
        "startswith",
        "endswith",
        "copy",
        "get",
        "keys",
        "values",
        "items",
    }
)
_LIT_ATTRS = frozenset(
    {
        "os.name",
        "os.sep",
        "os.linesep",
        "os.pathsep",
        "os.curdir",
        "os.pardir",
        "sys.platform",
        "sys.maxsize",
        "string.ascii_letters",
        "string.ascii_lowercase",
        "string.ascii_uppercase",
        "string.digits",
        "string.hexdigits",
        "string.punctuation",
        "string.printable",
    }
)
_MUTATORS = frozenset(
    {
        "append",
        "appendleft",
        "extend",
        "insert",
        "pop",
        "popleft",
        "remove",
        "clear",
        "set",
        "update",
        "setdefault",
        "add",
        "discard",
        "write",
        "writelines",
        "put",
        "sort",
        "reverse",
    }
)

# --- sink target patterns (matched against the compact call target) ----------
SQL_FN = re.compile(r"(?:^|\.)(?:execute|executemany|executescript)$")
CMD_FN = re.compile(
    r"(?:^|\.)system$|(?:^|\.)popen$|^subprocess\.\w+$|^os\.(?:exec\w*|spawn\w*)$"
    r"|^commands\.getoutput$|^pty\.spawn$"
)
# File APIs whose path argument is a traversal sink. ``x.open()`` on an
# arbitrary object is not included (test clients, browsers, archives all have
# one); pathlib objects are handled through PATH_METHODS.
PATH_FN = re.compile(
    r"^(?:open|io\.open|codecs\.open|os\.open|gzip\.open|bz2\.open|lzma\.open|tarfile\.open)$"
    r"|^aiofiles\.open$|(?:^|\.)FileResponse$"
    r"|(?:^|\.)send_file$|(?:^|\.)send_from_directory$"
    r"|^os\.(?:remove|unlink|rmdir|removedirs|mkdir|makedirs|listdir|scandir|stat|lstat|"
    r"chmod|chown|rename|renames|replace|truncate|utime|access)$"
    r"|^shutil\.(?:copy|copy2|copyfile|copytree|move|rmtree)$"
)
#: Calls whose first two positional arguments are both paths.
TWO_PATH_FN = re.compile(
    r"^os\.(?:rename|renames|replace)$|^shutil\.(?:copy|copy2|copyfile|copytree|move)$"
)
CODE_FN = re.compile(r"^(?:eval|exec|compile)$")
DESER_FN = re.compile(
    r"^(?:c?[Pp]ickle|_pickle|dill|cloudpickle)\.(?:loads?|Unpickler)$|^marshal\.loads?$"
    r"|^jsonpickle\.(?:decode|loads)$|^yaml\.(?:unsafe_load|unsafe_load_all|full_load|full_load_all)$"
)
YAML_LOAD_FN = re.compile(r"^yaml\.(?:load|load_all)$")
SHELL_CMD_FN = re.compile(r"^subprocess\.(?:call|run|Popen|check_output|check_call)$")
#: Command functions that always run their argument through a shell.
_SHELL_FUNCTIONS = frozenset(
    {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
    | {"commands.getoutput"}
)
#: Options after which an interpreter or shell takes code to run.
_CODE_OPTIONS = frozenset(
    {"-c", "-e", "--eval", "--exec", "/c", "/C", "/k", "/K"}
    | {"-Command", "-command", "-EncodedCommand", "--command"}
)
PATH_METHODS = frozenset(
    {
        "exists",
        "is_file",
        "is_dir",
        "open",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "unlink",
        "mkdir",
        "rmdir",
        "iterdir",
        "glob",
        "rglob",
        "stat",
        "touch",
        "rename",
        "replace",
        "chmod",
        "symlink_to",
        "hardlink_to",
    }
)
PATH_CTORS = frozenset({"Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath"})
#: pathlib-only methods: a receiver they are called on is a path object.
PATHLIB_IO = frozenset({"read_text", "read_bytes", "write_text", "write_bytes"})
_PATH_JOINS = frozenset({"os.path.join", "posixpath.join", "ntpath.join", "path.join"})
NORMALIZERS = frozenset(
    {"os.path.realpath", "os.path.abspath", "os.path.normpath", "posixpath.realpath"}
)
LDAP_SEARCH = frozenset({"search", "search_s", "search_st", "search_ext", "search_ext_s"})
XML_PARSE = frozenset({"parseString", "parse", "fromstring", "XML", "iterparse", "XMLID"})
REDIRECT_FNS = frozenset(
    {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse"}
)
MARKUP_FNS = frozenset({"Markup", "mark_safe", "SafeString", "SafeText"})
DJANGO_RESPONSES = frozenset(
    {
        "HttpResponse",
        "HttpResponseBadRequest",
        "HttpResponseNotFound",
        "HttpResponseForbidden",
        "HttpResponseServerError",
    }
)
WEAK_RANDOM_FUNCS = frozenset(
    {
        "random",
        "randint",
        "randrange",
        "choice",
        "choices",
        "getrandbits",
        "randbytes",
        "uniform",
        "normalvariate",
        "gauss",
        "sample",
        "shuffle",
        "triangular",
        "betavariate",
        "expovariate",
        "gammavariate",
        "lognormvariate",
        "vonmisesvariate",
        "paretovariate",
        "weibullvariate",
        "binomialvariate",
    }
)
#: Module-level HTTP client functions whose first argument is the URL
#: (``requests.request`` / ``httpx.request`` take the method first).
HTTP_FN = re.compile(
    r"^(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|request|stream)$"
    r"|^(?:urllib\.request\.)?urlopen$|^urllib3\.request$|^aiohttp\.request$"
)
#: Constructors of HTTP client objects; their request methods take the URL.
HTTP_CLIENT_CTORS = frozenset(
    {
        "requests.Session",
        "requests.session",
        "httpx.Client",
        "httpx.AsyncClient",
        "aiohttp.ClientSession",
        "ClientSession",
        "AsyncClient",
        "urllib3.PoolManager",
        "urllib3.ProxyManager",
        "PoolManager",
        "urllib.request.build_opener",
        "build_opener",
    }
)
HTTP_CLIENT_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
    | {"urlopen", "open", "ws_connect"}
)
#: Client methods whose URL is the second argument (the method comes first).
_HTTP_METHOD_FIRST = frozenset({"request", "urlopen", "stream"})
TAR_CTORS = frozenset({"tarfile.open", "tarfile.TarFile", "TarFile", "tarfile.TarFile.open"})
TAR_CTORS = TAR_CTORS | {"TarFile.open", "tarfile.TarFile.gzopen", "tarfile.TarFile.taropen"}
ZIP_CTORS = frozenset({"zipfile.ZipFile", "ZipFile"})
#: Explicit ``filter=`` values that leave a tar extraction unrestricted.
_UNSAFE_TAR_FILTERS = frozenset(
    {"'fully_trusted'", '"fully_trusted"', "tarfile.fully_trusted_filter", "fully_trusted_filter"}
)
JINJA_ENVS = frozenset({"Environment", "NativeEnvironment"})
JINJA_SANDBOXES = frozenset({"SandboxedEnvironment", "ImmutableSandboxedEnvironment"})
#: FastAPI parameter markers: a parameter with one of these defaults is read
#: from the request (query string, path, body, form, upload, header, cookie).
FASTAPI_PARAMS = frozenset({"Query", "Path", "Body", "Form", "File", "Header", "Cookie"})
#: Annotations that make a parameter the framework's request object.
_REQUEST_TYPES = re.compile(
    r"^(?:(?:fastapi|starlette\.requests|aiohttp\.web|web|django\.http)\.)?"
    r"(?:Request|HttpRequest|WebSocket|HTTPConnection|BaseRequest)$"
)
#: Request-object attributes (and methods) that hold client-controlled data.
REQUEST_ATTRS = frozenset(
    {
        "query_params",
        "path_params",
        "headers",
        "cookies",
        "url",
        "form",
        "json",
        "body",
        "stream",
        "query",
        "rel_url",
        "match_info",
        "post",
        "content",
        "text",
        "read",
        "GET",
        "POST",
        "FILES",
        "COOKIES",
        "META",
        "data",
        "path",
        "path_info",
        "get_full_path",
        "query_string",
    }
)
#: Annotations of values a framework has already parsed into a number, a
#: boolean, a UUID or a date: they cannot carry injected text.
_SAFE_ANNOTATION = re.compile(
    r"^(?:Optional\[)?\s*(?:int|float|bool|complex|Decimal|UUID|uuid\.UUID|datetime|date"
    r"|datetime\.datetime|datetime\.date|timedelta)\s*\]?\s*(?:\|\s*None)?$"
)
_FRAMEWORK_NON_INPUT = re.compile(r"(?:^|\.)(?:Response|BackgroundTasks|Session|AsyncSession)$")
#: Flask/Werkzeug route converters that parse the segment into a number or UUID.
_SAFE_CONVERTERS = frozenset({"int", "float", "uuid", "any"})
_ROUTE_PARAM = re.compile(r"<(?:([A-Za-z_]\w*)(?:\([^)>]*\))?:)?([A-Za-z_]\w*)>")
#: IP address classifications an SSRF guard checks before letting a URL through.
_IP_CLASSIFIERS = re.compile(
    rb"\.is_(?:private|loopback|link_local|reserved|global|multicast|unspecified|site_local)\b"
)
_HTML_TAG = re.compile(r"<(?:[A-Za-z][A-Za-z0-9-]*[\s>/]|/[A-Za-z]|!)")
#: Literal text at the start of a URL that fixes where a redirect can go: a
#: path on this site (``/scans/``, but not ``/`` alone, ``//`` or ``/\``,
#: which a browser reads as another host), or an absolute URL whose host is
#: already closed by ``/``, ``?`` or ``#``. Whatever follows cannot change the
#: destination host.
_FIXED_REDIRECT_START = re.compile(r"/[\w.~%-]|[A-Za-z][A-Za-z0-9+.-]*://[^/\\?#@\s]+[/?#]")
_URL_PARSERS = frozenset({"urlparse", "urlsplit", "URL", "parse_url"})
_AUTOESCAPED_RENDERERS = frozenset(
    {"jsonify", "render_template", "render_template_string", "TemplateResponse"}
)
#: Stored-record lookups: the result is what the database holds for a key, not
#: the key's text (Django managers, Flask-SQLAlchemy and SQLAlchemy getters,
#: and repository methods named get_..._by_id / find_by_... by convention).
_RECORD_GETTERS = frozenset(
    {"get_object_or_404", "get_list_or_404", "get_or_404", "first_or_404", "one_or_404"}
)
_RECORD_LOOKUP_NAME = re.compile(
    r"^(?:get|find|fetch|load|lookup|read|query|select)_(?:\w+_)?by_\w+$"
    r"|^\w+_by_(?:id|pk|uuid|key|slug|name|email|ids)$"
)
_ORM_QUERY_METHODS = frozenset(
    {"get", "filter", "filter_by", "exclude", "first", "one", "one_or_none", "all", "last"}
    | {"get_or_create", "values", "values_list", "only", "order_by", "scalar"}
)
_NUMBER_TYPES = frozenset(
    {"int", "float", "bool", "complex", "Decimal", "decimal.Decimal", "numbers.Number"}
)
#: Methods that read one item out of a container or mapping.
_ITEM_GETTERS = frozenset({"get", "pop", "getlist", "get_all", "getall", "getone"})
_IMPORTS_JINJA_TEMPLATE = re.compile(
    rb"(?m)^\s*from\s+(?:jinja2|mako\.template)\s+import\s+[^\n]*\bTemplate\b"
)
_IMPORTS_JINJA_ENV = re.compile(
    rb"(?m)^\s*from\s+jinja2(?:\.nativetypes)?\s+import\s+[^\n]*\b(?:Native)?Environment\b"
)
SESSION_RE = re.compile(r"(?:^|\.)session$")
#: Names that mark a value as a security token, credential or session secret.
SENSITIVE_RE = re.compile(
    r"(?i)token|secret|passw|pwd|nonce|(?:^|_)salt(?:_|$)|(?:^|_)otp(?:_|$)|csrf|xsrf|"
    r"api_?key|session|cookie|reset_?code|verification_?code|one_?time|captcha|activation"
)
ROUTE_DECORATOR = re.compile(r"(?:^|\.)route\s*\(")
METHOD_DECORATOR = re.compile(r"\.(?:get|post|put|patch|delete)\s*\(")
_ROUTE_RULE = re.compile(r"\(\s*(['\"])([^'\"\n]*)\1")
_REQUEST_PATH = frozenset({"request.path", "flask.request.path"})
_IMPORTS_FLASK = re.compile(rb"(?m)^\s*(?:from|import)\s+(?:flask|quart|bottle)\b")
_IMPORTS_JSON_FRAMEWORK = re.compile(rb"(?m)^\s*(?:from|import)\s+(?:fastapi|starlette)\b")
_IMPORTS_LDAP = re.compile(rb"(?m)^\s*(?:from|import)\s+ldap3?\b")
_IMPORTS_XML = re.compile(rb"(?m)^\s*(?:from|import)\s+(?:lxml|xml\.etree|elementpath)\b")
_FROM_RANDOM = re.compile(rb"(?m)^\s*from\s+random\s+import\s+([^\n#]+)")
_EXTERNAL_ENTITY_FEATURE = re.compile(r"external[-_](?:ges|pes|general|parameter)")


#: One step of a tainted value's history: (start byte, line, byte column,
#: kind, text, extra). ``kind`` is "source" (``extra`` is ``(how, origins)``),
#: "param" (a seeded parameter), "step" (an assignment or a helper call),
#: "guard" (``extra`` is the CWEs the check cleared), "elided" (steps left
#: out) or "opaque" (taint found by the flat fallback scan, origin unknown).
Hop = tuple[int, int, int, str, str, Any]
#: Hops kept per value: the first one (the source) and the most recent ones.
MAX_TRAIL = 16
_ELIDED_HOP: Hop = (-1, 0, 0, "elided", "", None)
_OPAQUE_TRAIL: tuple[Hop, ...] = ((-1, 0, 0, "opaque", "", None),)


def extend_trail(trail: tuple[Hop, ...], hop: Hop) -> tuple[Hop, ...]:
    """``trail`` with ``hop`` appended, capped at :data:`MAX_TRAIL`.

    A hop equal to the last one is not repeated (a loop body runs more than
    once). Past the cap the source and the newest hops are kept, with an
    "elided" marker between them.
    """
    if trail and trail[-1][1:5] == hop[1:5]:
        return trail
    out = (*trail, hop)
    if len(out) > MAX_TRAIL:
        out = (out[0], _ELIDED_HOP, *out[-(MAX_TRAIL - 2) :])
    return out


@dataclass(frozen=True)
class Val:
    """Abstract value of one expression or variable."""

    taint: bool = False
    clean: frozenset[str] = frozenset()
    lit: bool = False
    const: Any = NOCONST
    weak: bool = False
    param: bool = False
    flags: frozenset[str] = frozenset()
    elems: tuple[tuple[Any, Val], ...] | None = None
    seq: tuple[Val, ...] | None = None
    #: Origins of the taint (ORIGIN_*); empty on a tainted value means request.
    src: frozenset[str] = frozenset()
    #: The tainted text sits after content the program supplied itself (a base
    #: directory, a command, an HTML tag, a query): ``base + "/" + name``.
    embed: bool = False
    #: The value is a field or item of a tainted object, not the object itself.
    part: bool = False
    #: Where the taint came from and how it moved (:data:`Hop` entries), for
    #: the evidence shown with a finding. Not part of equality or hashing, so
    #: joins, loop fixed points and caches behave exactly as without it.
    trail: tuple[Hop, ...] = field(default=(), compare=False, repr=False)

    def tainted_for(self, cwes: frozenset[str]) -> bool:
        return self.taint and not (cwes & self.clean)

    @property
    def origins(self) -> frozenset[str]:
        if not self.taint:
            return frozenset()
        return self.src or _REQUEST_ORIGIN

    @property
    def api_only(self) -> bool:
        """Tainted only by a public API parameter (library mode)."""
        return self.taint and self.src == {ORIGIN_API}


UNKNOWN = Val()
LIT = Val(lit=True)
TAINT = Val(taint=True)
API_TAINT = Val(taint=True, param=True, src=frozenset({ORIGIN_API}))
ARCHIVE_TAINT = Val(taint=True, src=frozenset({ORIGIN_ARCHIVE}))
OPERATOR_TAINT = Val(taint=True, src=frozenset({ORIGIN_OPERATOR}))


def combine(vals: Iterable[Val]) -> Val:
    """A value computed from all of ``vals`` (taint if any, literal if all)."""
    taint = weak = param = embed = part = False
    lit = True
    clean: frozenset[str] | None = None
    src: frozenset[str] = frozenset()
    trail: tuple[Hop, ...] = ()
    trail_request = False
    for v in vals:
        if v.taint:
            taint = True
            clean = v.clean if clean is None else clean & v.clean
            src = src | v.origins
            embed = embed or v.embed
            part = part or v.part
            if v.trail and not trail_request and (not trail or ORIGIN_REQUEST in v.origins):
                trail = v.trail
                trail_request = ORIGIN_REQUEST in v.origins
        weak = weak or v.weak
        param = param or v.param
        lit = lit and v.lit
    return Val(
        taint=taint,
        clean=(clean if clean is not None else frozenset()) if taint else frozenset(),
        lit=lit,
        weak=weak,
        param=param,
        src=src,
        embed=embed,
        part=part,
        trail=trail,
    )


def derived(v: Val, **changes: Any) -> Val:
    """A new value computed from ``v`` alone: same taint, origin and literalness."""
    out = Val(
        taint=v.taint,
        clean=v.clean,
        lit=v.lit,
        weak=v.weak,
        param=v.param,
        src=v.src,
        embed=v.embed,
        part=v.part,
        trail=v.trail,
    )
    return replace(out, **changes) if changes else out


def _ordered_embed(vals: Iterable[Val]) -> bool:
    """Whether ``vals`` (in order) place tainted text inside a larger string or path.

    True when a tainted value follows untainted content (``base + name``), or
    when a field of tainted data follows any other content
    (``root / f"{item.name}.txt"``: the item's name becomes a component).
    """
    seen_trusted = seen_any = False
    for v in vals:
        if v.taint:
            if seen_trusted or v.embed or (seen_any and v.part):
                return True
            seen_any = True
        elif not (v.const == "" or v.const is None):
            seen_trusted = seen_any = True
    return False


def _pin_redirect(v: Val, ordered: Sequence[Val]) -> Val:
    """``v`` marked ``pinned`` and cleared for redirects when its start fixes the host.

    ``f"/scans/{scan_id}"`` or ``"https://example.com/" + path`` cannot send the
    browser to another site whatever the tainted part holds. ``ordered`` is the
    string's parts in source order; the first one decides, and a value that is
    itself pinned keeps a longer concatenation pinned.
    """
    if not ordered:
        return v
    first = ordered[0]
    start = first.const
    if not (
        "pinned" in first.flags or (isinstance(start, str) and _FIXED_REDIRECT_START.match(start))
    ):
        return v
    clean = v.clean | {CWE_REDIRECT} if v.taint else v.clean
    return replace(v, clean=clean, flags=v.flags | {"pinned"})


def summary(v: Val) -> Val:
    """``v`` without its constant, flags and element structure."""
    if v.const is NOCONST and not v.flags and v.elems is None and v.seq is None:
        return v
    return derived(v)


def elem_of(v: Val) -> Val:
    """The value of one element when iterating over ``v``."""
    if "archlist" in v.flags or "tar" in v.flags:
        return Val(flags=frozenset({"archmember"}))  # ZipInfo / TarInfo
    if v.seq is not None:
        return combine(v.seq) if v.seq else Val(lit=True)
    if v.elems is not None:
        return Val(lit=True)  # iterating a dict yields its (constant) keys
    return derived(v)


def _same_const(a: Any, b: Any) -> bool:
    if a is NOCONST or b is NOCONST or type(a) is not type(b):
        return False
    try:
        return bool(a == b)
    except Exception:  # pragma: no cover - consts are plain literals
        return False


def join(a: Val, b: Val) -> Val:
    """Least upper bound of two values reaching the same point."""
    if a is b or a == b:
        return a
    if a.taint and b.taint:
        clean = a.clean & b.clean
    elif a.taint:
        clean = a.clean
    elif b.taint:
        clean = b.clean
    else:
        clean = frozenset()
    elems: tuple[tuple[Any, Val], ...] | None = None
    if a.elems is not None and b.elems is not None:
        merged: dict[Any, Val] = {}
        for k, v in a.elems:
            merged[k] = v
        for k, v in b.elems:
            merged[k] = join(merged[k], v) if k in merged else v
        elems = tuple(merged.items())
    seq: tuple[Val, ...] | None = None
    if a.seq is not None and b.seq is not None and len(a.seq) == len(b.seq):
        seq = tuple(join(x, y) for x, y in zip(a.seq, b.seq, strict=True))
    return Val(
        taint=a.taint or b.taint,
        clean=clean,
        lit=a.lit and b.lit,
        const=a.const if _same_const(a.const, b.const) else NOCONST,
        weak=a.weak or b.weak,
        param=a.param or b.param,
        flags=a.flags | b.flags,
        elems=elems,
        seq=seq,
        src=a.origins | b.origins,
        embed=(a.taint and a.embed) or (b.taint and b.embed),
        part=(a.taint and a.part) or (b.taint and b.part),
        trail=_joined_trail(a, b),
    )


def _joined_trail(a: Val, b: Val) -> tuple[Hop, ...]:
    """The trail of whichever joined value is tainted, preferring request data."""
    left = a.trail if a.taint else ()
    right = b.trail if b.taint else ()
    if left and right and ORIGIN_REQUEST not in a.origins and ORIGIN_REQUEST in b.origins:
        return right
    return left or right


class State:
    """Variable -> value at one program point. ``live`` is False after a return."""

    __slots__ = ("vars", "live")

    def __init__(self, vars: dict[str, Val] | None = None, live: bool = True) -> None:
        self.vars: dict[str, Val] = vars if vars is not None else {}
        self.live = live

    def copy(self) -> State:
        return State(dict(self.vars), self.live)

    def get(self, name: str) -> Val:
        return self.vars.get(name, UNKNOWN)


DEAD = State(live=False)


def join_states(states: Iterable[State]) -> State:
    live = [s for s in states if s.live]
    if not live:
        return State(live=False)
    if len(live) == 1:
        return live[0].copy()
    names: set[str] = set()
    for s in live:
        names.update(s.vars)
    out: dict[str, Val] = {}
    for n in names:
        v = live[0].vars.get(n, UNKNOWN)
        for s in live[1:]:
            v = join(v, s.vars.get(n, UNKNOWN))
        out[n] = v
    return State(out)


def truthy(value: Any) -> bool | None:
    if value is NOCONST:
        return None
    try:
        return bool(value)
    except Exception:  # pragma: no cover
        return None


def _fold_binary(op: str, a: Any, b: Any) -> Any:
    if a is NOCONST or b is NOCONST:
        return NOCONST
    num = (int, float)
    both_num = isinstance(a, num) and isinstance(b, num)
    same_text = (isinstance(a, str) and isinstance(b, str)) or (
        isinstance(a, bytes) and isinstance(b, bytes)
    )
    repeat = isinstance(a, str) and isinstance(b, int) and len(a) * max(b, 0) <= MAX_STR
    r: Any = NOCONST
    try:
        if op == "+" and (both_num or same_text):
            r = a + b
        elif op == "-" and both_num:
            r = a - b
        elif op == "*" and (both_num or repeat):
            r = a * b
        elif op in ("//", "%") and both_num and b != 0:
            r = a // b if op == "//" else a % b
        elif op == "/" and both_num and b != 0:
            r = a / b
        elif op == "**" and isinstance(a, int) and isinstance(b, int) and 0 <= b <= 64:
            r = a**b if abs(a) <= 1 << 16 else NOCONST
    except Exception:
        return NOCONST
    if isinstance(r, (str, bytes)) and len(r) > MAX_STR:
        return NOCONST
    if isinstance(r, int) and abs(r) > 1 << 128:
        return NOCONST
    return r


def _fold_compare(op: str, a: Any, b: Any) -> Any:
    try:
        if op == "==":
            return a == b
        if op == "!=":
            return a != b
        if op == "<":
            return a < b
        if op == ">":
            return a > b
        if op == "<=":
            return a <= b
        if op == ">=":
            return a >= b
        if op in ("in", "not in") and isinstance(b, (str, bytes, tuple, list, frozenset)):
            if isinstance(b, (str, bytes)) and not isinstance(a, type(b)):
                return NOCONST
            return (a in b) if op == "in" else (a not in b)
        if op in ("is", "is not") and (a is None or b is None or isinstance(a, bool)):
            return (a is b) if op == "is" else (a is not b)
    except Exception:
        return NOCONST
    return NOCONST


@dataclass
class _Call:
    node: Any
    fn: str
    last: str
    recv: Val | None
    recv_node: Any
    pos: list[Val]
    pos_nodes: list[Any]
    kw: dict[str, Val]
    kw_nodes: dict[str, Any]
    extra: list[Val]

    def arg(self, index: int, *names: str) -> Val | None:
        if index < len(self.pos):
            return self.pos[index]
        for n in names:
            if n in self.kw:
                return self.kw[n]
        return None

    def every_arg(self) -> list[Val]:
        return [*self.pos, *self.kw.values(), *self.extra]


@dataclass
class _FnCtx:
    name: str
    route: bool
    sensitive: bool
    static_path: bool = False
    returns: list[Val] = field(default_factory=list)
    #: Library mode: qualified name of the public function whose parameters
    #: are sources here (inherited by nested functions), else None.
    api_owner: str | None = None
    #: Summary runs only: (returned value, returned expression, state) at
    #: every normal exit of the body.
    exits: list[tuple[Val | None, Any, State]] | None = None


@dataclass(frozen=True)
class LibraryScope:
    """Library mode for one file: public functions' parameters are sources.

    ``module_public`` is False for a module that is not part of the public
    API (a path component starting with an underscore, or a test file).
    """

    module_public: bool = True


@dataclass(frozen=True)
class _RetSummary:
    """What a same-file helper returns when its parameters are tainted."""

    taint: bool
    clean: frozenset[str]
    embed: bool
    part: bool
    lit: bool
    flags: frozenset[str]


@dataclass(frozen=True)
class _Guard:
    """CWEs a same-file validator clears for one parameter.

    ``after``: when the call returns normally (it raises on bad input).
    ``true`` / ``false``: when its result is truthy / falsy.
    """

    after: frozenset[str]
    true: frozenset[str]
    false: frozenset[str]


@dataclass
class _Shared:
    """Per-file index of helpers, shared by a flow and its summary runs."""

    functions: dict[str, Any]
    methods: dict[str, Any]
    returns: dict[str, _RetSummary | None] = field(default_factory=dict)
    guards: dict[tuple[str, str], _Guard | None] = field(default_factory=dict)


@dataclass(frozen=True)
class _HelperRef:
    """A helper a call resolves to, in this file or in another project file."""

    #: Summary cache key in the defining file's tables.
    key: str
    node: Any
    #: The flow over the file that defines the helper (the caller itself for
    #: a helper in the same file).
    host: Flow
    #: The name shown in evidence.
    label: str
    #: ``path:line`` of the definition for a helper in another file, else None.
    where: str | None = None


@dataclass
class ProjectLink:
    """Where a flow's file sits in the project, for cross-file helpers."""

    store: SummaryStore
    path: str


class SummaryStore:
    """Flows over the project's files that hold cross-file helper summaries.

    One store serves one scanner run. A defining file gets one flow per set of
    analysis settings (project context and extra sources), and that flow's
    summary tables are reused by every caller in the scan, so each
    (file, function, mode) is summarized once per settings.
    """

    def __init__(self, project: Any) -> None:
        #: A :class:`nephilex.scanners._pyproject.PythonProject`.
        self.project = project
        self._hosts: dict[tuple[Any, ...], tuple[Flow | None, Any]] = {}

    def host(self, path: str, caller: Flow) -> Flow | None:
        key = (path, id(caller._ctx), caller.source_methods, caller.source_functions)
        hit = self._hosts.get(key)
        if hit is not None:
            return hit[0]
        flow: Flow | None = None
        parsed = self.project.parsed(path)
        if parsed is not None:
            src, root = parsed
            flow = Flow(
                src,
                None,
                context=caller._ctx,
                source_methods=caller.source_methods,
                source_functions=caller.source_functions,
                project=ProjectLink(self, path),
            )
            try:
                flow._ensure_shared(root)
                flow._module_consts = flow._module_constants(root)
            except (AnalysisBudgetExceeded, RecursionError):
                flow = None
        # The context object is kept so its id is not reused during the scan.
        self._hosts[key] = (flow, caller._ctx)
        return flow


#: Flags a helper's return value passes on to its callers.
#: ("html" is not passed on: returned HTML is judged where it is built.)
_RETURN_FLAGS = frozenset({"path", "normalized", "http", "tar", "zip", "jinja", "jinja-sandbox"})
#: Statement visits allowed for summarizing one helper.
SUMMARY_STEPS = 40_000
#: Helper summaries nested inside helper summaries, at most.
MAX_SUMMARY_DEPTH = 2

#: ``emit(sink_id, node, origin=..., owner=...)``: report a finding for
#: ``sink_id`` at ``node``. ``origin`` is ORIGIN_REQUEST, ORIGIN_API or
#: ORIGIN_ARCHIVE; ``owner`` names the public function for ORIGIN_API.
Emit = Callable[..., None]


class Flow:
    """One analysis run over one file (or one function body)."""

    def __init__(
        self,
        src: bytes,
        emit: Emit | None,
        *,
        context: LanguageContext | None = None,
        source_methods: frozenset[str] = frozenset(),
        source_functions: frozenset[str] = frozenset(),
        library: LibraryScope | None = None,
        shared: _Shared | None = None,
        project: ProjectLink | None = None,
    ) -> None:
        self._src = src
        self._emit_cb = emit
        #: Record where taint comes from and how it moves (for finding
        #: evidence). Off for runs that report nothing (helper summaries,
        #: the regex tier's verdicts): there it would only cost time.
        self._trails = emit is not None
        #: The condition or validator call being applied, for "guard" hops.
        self._guard_at: Any = None
        #: ``path:line`` of a validator in another file being applied, if any.
        self._guard_where: str | None = None
        self._ctx = context
        self._cwes: frozenset[str] = TAINT_CWES | (context.cwes if context else frozenset())
        self.source_methods = source_methods
        self.source_functions = source_functions
        self._library = library
        self._exported: frozenset[str] | None = None
        self._fn_stack: list[_FnCtx] = []
        self._class_stack: list[str] = []
        self._loop_stack: list[list[tuple[str, State]]] = []
        self._quiet = 0
        self._steps = 0
        self._step_limit = MAX_STEPS
        self._summary_depth = 0
        #: The file's helper index and summaries. A caller that runs several
        #: flows over one file with the same settings passes it on (``shared``).
        self._shared: _Shared | None = shared
        #: The project around this file, for helpers defined in other files.
        self._project = project
        #: File boundaries crossed by the summary chain this flow runs in.
        self._xdepth = 0
        self._module_consts: dict[str, Val] = {}
        #: (kind, line) -> "tainted" | "literal" | "unknown", for the regex tier.
        self.verdicts: dict[tuple[str, int], str] = {}
        self._flask = bool(_IMPORTS_FLASK.search(src))
        self._json_framework = bool(_IMPORTS_JSON_FRAMEWORK.search(src))
        self._ldap = bool(_IMPORTS_LDAP.search(src))
        self._xml = bool(_IMPORTS_XML.search(src))
        self._jinja_template = bool(_IMPORTS_JINJA_TEMPLATE.search(src))
        self._jinja_env = bool(_IMPORTS_JINJA_ENV.search(src))
        self._random_names: set[str] = set()
        for m in _FROM_RANDOM.finditer(src):
            for part in m.group(1).decode("utf-8", "ignore").replace("(", " ").split(","):
                bits = part.split()
                if bits and bits[0] in WEAK_RANDOM_FUNCS:
                    self._random_names.add(bits[-1])
        self._ev_table: dict[str, Callable[[Any, State, int], Val]] = {
            "identifier": self._ev_identifier,
            "attribute": self._ev_attribute,
            "call": self._ev_call,
            "string": self._ev_string,
            "concatenated_string": self._ev_concat,
            "integer": self._ev_number,
            "float": self._ev_number,
            "true": lambda n, s, d: Val(lit=True, const=True),
            "false": lambda n, s, d: Val(lit=True, const=False),
            "none": lambda n, s, d: Val(lit=True, const=None),
            "ellipsis": lambda n, s, d: LIT,
            "parenthesized_expression": self._ev_paren,
            "binary_operator": self._ev_binary,
            "unary_operator": self._ev_unary,
            "not_operator": self._ev_not,
            "comparison_operator": self._ev_compare,
            "boolean_operator": self._ev_boolean,
            "conditional_expression": self._ev_conditional,
            "subscript": self._ev_subscript,
            "list": self._ev_sequence,
            "tuple": self._ev_sequence,
            "expression_list": self._ev_sequence,
            "set": self._ev_set,
            "dictionary": self._ev_dict,
            "list_comprehension": self._ev_comprehension,
            "set_comprehension": self._ev_comprehension,
            "generator_expression": self._ev_comprehension,
            "dictionary_comprehension": self._ev_comprehension,
            "pair": self._ev_pair,
            "lambda": lambda n, s, d: UNKNOWN,
            "named_expression": self._ev_walrus,
            "keyword_argument": self._ev_keyword,
            "list_splat": self._ev_splat,
            "dictionary_splat": self._ev_splat,
        }

    # --- entry points -------------------------------------------------------
    def run(self, root) -> None:
        self._ensure_shared(root)
        self._module_consts = self._module_constants(root)
        if self._library is not None:
            self._exported = self._module_exports(root)
        self._exec_block(root, State(), 0)

    def _ensure_shared(self, node) -> None:
        """Index the file's helper functions (once), from any node in it."""
        if self._shared is not None:
            return
        root = node
        while root.parent is not None:
            root = root.parent
        functions: dict[str, Any] = {}
        methods: dict[str, Any] = {}
        dups: set[tuple[bool, str]] = set()
        for fn, is_method in iter_functions(root):
            name_node = fn.child_by_field_name("name")
            if name_node is None:
                continue
            name = self.text(name_node)
            table = methods if is_method else functions
            if name in table or (is_method, name) in dups:
                dups.add((is_method, name))
                table.pop(name, None)
                continue
            table[name] = fn
        self._shared = _Shared(functions, methods)

    def _module_constants(self, root) -> dict[str, Val]:
        """Module-level names bound once to an immutable literal (``CMD = "ls"``).

        Functions see these as literal values. A name assigned more than once at
        module level, or declared ``global`` anywhere, is left out. A name bound
        once to a client or template environment (``env = Environment()``,
        ``http = requests.Session()``) is kept as that kind of object, without
        any taint, so its uses inside functions are recognized.
        """
        counts: dict[str, int] = {}
        found: dict[str, Val] = {}
        stmts = list(root.named_children)
        for stmt in list(stmts):
            if stmt.type == "try_statement":  # try: import x; env = X() except ...
                body = stmt.child_by_field_name("body")
                if body is not None:
                    stmts.extend(body.named_children)
        for stmt in stmts:
            if stmt.type != "expression_statement":
                continue
            for ch in stmt.named_children:
                if ch.type not in ("assignment", "augmented_assignment"):
                    continue
                left = ch.child_by_field_name("left")
                right = ch.child_by_field_name("right")
                if left is None or left.type != "identifier":
                    continue
                name = self.text(left)
                counts[name] = counts.get(name, 0) + 1
                if ch.type == "assignment" and right is not None and right.type == "call":
                    v = self._ev_quiet(right, State())
                    kinds = v.flags & _RETURN_FLAGS - {"path", "normalized", "html"}
                    if kinds and not v.taint:
                        found[name] = Val(flags=kinds)
                if (
                    ch.type == "assignment"
                    and right is not None
                    and right.type in _IMMUTABLE_LITERALS
                ):
                    v = self._ev_quiet(right, State())
                    if v.lit and not v.taint and not v.weak:
                        found[name] = v
        if not found:
            return {}
        declared_global: set[str] = set()
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "global_statement":
                declared_global.update(self.text(c) for c in n.named_children)
            stack.extend(n.children)
        return {n: v for n, v in found.items() if counts[n] == 1 and n not in declared_global}

    @property
    def shared(self) -> _Shared | None:
        """The file's helper index and summaries, once built."""
        return self._shared

    def run_body(self, body, seeds: Iterable[str]) -> None:
        self._ensure_shared(body)
        self._exec_block(body, State({n: self._seed(body, n) for n in seeds}), 0)

    def _seed(self, body, name: str) -> Val:
        """A tainted parameter ``name`` of the function whose body is ``body``."""
        fn = body.parent
        params = fn.child_by_field_name("parameters") if fn is not None else None
        if not self._trails or params is None:
            return TAINT
        for p in params.named_children:
            if self._param_parts(p)[0] == name:
                return self._hop(TAINT, p, "param", name)
        return TAINT

    def function_returns_taint(self, fn_node) -> bool:
        """Whether ``fn_node`` returns an untrusted value with nothing seeded."""
        body = fn_node.child_by_field_name("body")
        if body is None:
            return False
        self._ensure_shared(fn_node)
        ctx = _FnCtx(name="", route=False, sensitive=False)
        self._fn_stack.append(ctx)
        try:
            self._exec_block(body, State(), 0)
        finally:
            self._fn_stack.pop()
        return any(v.taint for v in ctx.returns)

    # --- evidence trails -----------------------------------------------------
    def _snip(self, node, limit: int = 80) -> str:
        """``node``'s source text on one line, cut to ``limit`` characters."""
        raw = self._src[node.start_byte : min(node.end_byte, node.start_byte + 4 * limit)]
        text = re.sub(r"\s+", " ", raw.decode("utf-8", "ignore")).strip()
        return text if len(text) <= limit else text[: limit - 3] + "..."

    def _hop(self, v: Val, node, kind: str, text: str, extra: Any = None) -> Val:
        """``v`` with one more step of history at ``node``."""
        row, col = node.start_point
        hop: Hop = (node.start_byte, row + 1, col + 1, kind, text, extra)
        return replace(v, trail=extend_trail(v.trail, hop))

    def _trace(self, v: Val, node) -> Val:
        """Give a tainted value that has no history a source at ``node``.

        Every tainted value is built from another one (which carries its
        trail) or comes from a source, so a value without a trail is the
        source itself: ``request.args``, ``input()``. A source read further
        (``request.args['q']``, ``request.args.get('q')``) is named in full.
        """
        trail = v.trail
        if not trail:
            return self._hop(v, node, "source", self._snip(node), ("expr", v.origins))
        if (
            len(trail) == 1
            and trail[0][3] == "source"
            and trail[0][0] == node.start_byte
            and node.type in ("subscript", "call", "attribute")
        ):
            first = trail[0]
            hop: Hop = (first[0], first[1], first[2], "source", self._snip(node), first[5])
            return replace(v, trail=(hop,))
        return v

    # --- helpers ------------------------------------------------------------
    def text(self, node) -> str:
        return self._src[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def _compact(self, node) -> str:
        return re.sub(r"\s+", "", self.text(node))

    def _path(self, node) -> str | None:
        """Dotted name of an identifier/attribute chain (``a.b.c``), else None."""
        parts: list[str] = []
        cur = node
        while cur is not None and cur.type == "attribute":
            attr = cur.child_by_field_name("attribute")
            if attr is None:
                return None
            parts.append(self.text(attr))
            cur = cur.child_by_field_name("object")
        if cur is None or cur.type != "identifier":
            return None
        parts.append(self.text(cur))
        return ".".join(reversed(parts))

    def _is_source(self, text: str) -> bool:
        if self._ctx is not None:
            text = self._ctx.mask_trusted(text)
        return bool(SOURCE_RE.search(text))

    def _source_val(self, text: str) -> Val:
        """The taint of a matched source: operator-controlled when only argv/env/input match."""
        if self._ctx is not None:
            text = self._ctx.mask_trusted(text)
        if OPERATOR_SOURCE_RE.search(text) and not REQUEST_SOURCE_RE.search(text):
            return OPERATOR_TAINT
        return TAINT

    def _emit(
        self,
        sink_id: str,
        node,
        origin: str = ORIGIN_REQUEST,
        detail: str | None = None,
        trail: tuple[Hop, ...] = (),
    ) -> None:
        if self._emit_cb is None or self._quiet:
            return
        extra: dict[str, Any] = {"detail": detail} if detail else {}
        if trail:
            extra["trail"] = trail
        if origin == ORIGIN_REQUEST:
            self._emit_cb(sink_id, node, **extra)
            return
        owner = self._fn_stack[-1].api_owner if self._fn_stack else None
        self._emit_cb(sink_id, node, origin=origin, owner=owner, **extra)

    def _report(
        self, sink_id: str, node, vals: Iterable[Val | None], detail: str | None = None
    ) -> bool:
        """Emit ``sink_id`` if any of ``vals`` is tainted for it; True if it did.

        The origin reported is the strongest one present: request data, then
        an archive member name, then operator input (command line,
        environment). A flow that comes only from a public API parameter
        (library mode) is reported when its shape is one
        :data:`LIBRARY_SINK_SHAPES` lists for the sink.
        """
        cwes = SINK_CWES[sink_id]
        hits = [v for v in vals if v is not None and v.tainted_for(cwes)]
        if not hits:
            return False
        origins: frozenset[str] = frozenset().union(*(v.origins for v in hits))
        if origins == {ORIGIN_OPERATOR} and sink_id in _CONFIGURATION_SINKS:
            # A server URL or redirect target taken from the environment or the
            # command line is the operator configuring the program.
            return False
        for origin in (ORIGIN_REQUEST, ORIGIN_ARCHIVE, ORIGIN_OPERATOR):
            if origin in origins:
                trail = next((v.trail for v in hits if origin in v.origins and v.trail), ())
                self._emit(sink_id, node, origin, detail, trail)
                return True
        shapes = LIBRARY_SINK_SHAPES.get(sink_id, frozenset())
        for v in hits:
            shape = {name for name, on in (("embed", v.embed), ("part", v.part)) if on}
            if (shape or {"whole"}) & shapes:
                self._emit(sink_id, node, ORIGIN_API, detail, v.trail)
                return True
        return False

    def _ev_quiet(self, node, st: State) -> Val:
        """Evaluate ``node`` again (for a guard) without reporting sinks twice."""
        self._quiet += 1
        try:
            return self.ev(node, st, 0)
        finally:
            self._quiet -= 1

    def _literal(self, node) -> Any:
        text = self.text(node)
        if len(text) > MAX_LITERAL_TEXT:
            return NOCONST
        try:
            value = _pyast.literal_eval(text)
        except Exception:
            return NOCONST
        if isinstance(value, (str, bytes, int, float, bool)) or value is None:
            return value
        return NOCONST

    def _verdict(self, kind: str, node, v: Val | None) -> None:
        if v is None:
            return
        line = node.start_point[0] + 1
        if v.taint:
            new = "tainted"
        elif v.lit:
            new = "literal"
        else:
            new = "unknown"
        rank = {"literal": 0, "unknown": 1, "tainted": 2}
        old = self.verdicts.get((kind, line))
        if old is None or rank[new] > rank[old]:
            self.verdicts[(kind, line)] = new

    # --- statements ---------------------------------------------------------
    def _exec_block(self, block, st: State, depth: int) -> State:
        for stmt in block.named_children:
            if not st.live:
                break
            st = self._exec_stmt(stmt, st, depth)
        return st

    def _exec_stmt(self, node, st: State, depth: int) -> State:
        self._steps += 1
        if self._steps > self._step_limit:
            raise AnalysisBudgetExceeded(f"more than {self._step_limit} statement visits")
        t = node.type
        if depth > MAX_STMT_DEPTH:
            self._flat(node, st)
            return st
        if t == "expression_statement":
            for ch in node.named_children:
                self._exec_expr_stmt(ch, st)
                self._apply_guard_statement(ch, st)
            return st
        if t == "if_statement":
            return self._exec_if(node, st, depth)
        if t == "for_statement":
            return self._exec_for(node, st, depth)
        if t == "while_statement":
            return self._exec_while(node, st, depth)
        if t == "try_statement":
            return self._exec_try(node, st, depth)
        if t == "with_statement":
            return self._exec_with(node, st, depth)
        if t == "match_statement":
            return self._exec_match(node, st, depth)
        if t == "function_definition":
            self._exec_function(node, [], depth, st)
            return st
        if t == "class_definition":
            body = node.child_by_field_name("body")
            name_node = node.child_by_field_name("name")
            if body is not None:
                self._class_stack.append(self.text(name_node) if name_node is not None else "")
                try:
                    self._exec_block(body, State(), depth + 1)
                finally:
                    self._class_stack.pop()
            return st
        if t == "decorated_definition":
            decorators = [self.text(c) for c in node.named_children if c.type == "decorator"]
            defn = node.child_by_field_name("definition")
            if defn is not None and defn.type == "function_definition":
                self._exec_function(defn, decorators, depth, st)
            elif defn is not None:
                self._exec_stmt(defn, st, depth)
            return st
        if t == "return_statement":
            self._exec_return(node, st)
            return State(live=False)
        if t == "raise_statement":
            for ch in node.named_children:
                self.ev(ch, st, 0)
            return State(live=False)
        if t in ("break_statement", "continue_statement"):
            if self._loop_stack:
                kind = "break" if t == "break_statement" else "continue"
                self._loop_stack[-1].append((kind, st.copy()))
            return State(live=False)
        if t == "assert_statement":
            named = node.named_children
            if named:
                self.ev(named[0], st, 0)
                self._refine(named[0], st, True)
            return st
        if t == "block":
            return self._exec_block(node, st, depth + 1)
        if t in (
            "import_statement",
            "import_from_statement",
            "future_import_statement",
            "global_statement",
            "nonlocal_statement",
            "pass_statement",
            "comment",
            "type_alias_statement",
        ):
            return st
        for ch in node.named_children:
            self.ev(ch, st, 0)
        return st

    def _exec_expr_stmt(self, node, st: State) -> None:
        t = node.type
        if t == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            targets = [left] if left is not None else []
            while right is not None and right.type == "assignment":
                nxt = right.child_by_field_name("left")
                if nxt is not None:
                    targets.append(nxt)
                right = right.child_by_field_name("right")
            if right is None:
                return
            val = self.ev(right, st, 0)
            for target in targets:
                self._assign(target, val, st)
            return
        if t == "augmented_assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")
            if left is None or right is None:
                return
            val = self.ev(right, st, 0)
            cur = self.ev(left, st, 0)
            op = self.text(op_node)[:-1] if op_node is not None else "+"
            self._assign(left, self._binop(op, cur, val), st)
            return
        self.ev(node, st, 0)

    def _assign(self, target, val: Val, st: State) -> None:
        t = target.type
        if t == "identifier":
            name = self.text(target)
            if val.weak and SENSITIVE_RE.search(name):
                self._emit("ast-weak-random", target)
            if val.taint and self._trails:
                val = self._hop(val, target, "step", f"assigned to {name[:60]}")
            st.vars[name] = val
            self._kill_prefix(st, name)
            return
        if t == "attribute":
            path = self._path(target)
            attr = target.child_by_field_name("attribute")
            if val.weak and attr is not None and SENSITIVE_RE.search(self.text(attr)):
                self._emit("ast-weak-random", target)
            if path is None:
                obj = target.child_by_field_name("object")
                if obj is not None:
                    self.ev(obj, st, 0)
                return
            if val.taint and self._trails:
                val = self._hop(val, target, "step", f"assigned to {path[:60]}")
            st.vars[path] = val
            self._kill_prefix(st, path)
            return
        if t == "subscript":
            base = target.child_by_field_name("value")
            idx_node = target.child_by_field_name("subscript")
            if base is None:
                return
            idx = self.ev(idx_node, st, 0) if idx_node is not None else UNKNOWN
            base_text = self._compact(base)
            if SESSION_RE.search(base_text):
                self._report("ast-trust-boundary", target, [val, idx])
            if (
                base_text.endswith("headers")
                and isinstance(idx.const, str)
                and idx.const.lower() == "location"
            ):
                self._report("ast-open-redirect", target, [val])  # resp.headers["Location"] = url
            if val.weak and (
                SENSITIVE_RE.search(base_text)
                or (isinstance(idx.const, str) and SENSITIVE_RE.search(idx.const))
            ):
                self._emit("ast-weak-random", target)
            path = self._path(base)
            if path is None:
                self.ev(base, st, 0)
                return
            if val.taint and self._trails:
                val = self._hop(val, target, "step", f"stored in {self._snip(target, 60)}")
            st.vars[path] = self._store_elem(st.get(path), idx, val)
            return
        if t in (
            "pattern_list",
            "tuple_pattern",
            "list_pattern",
            "tuple",
            "list",
            "expression_list",
        ):
            elts = [c for c in target.named_children if c.type != "comment"]
            splat = any(c.type == "list_splat_pattern" for c in elts)
            if val.seq is not None and len(val.seq) == len(elts) and not splat:
                for e, v in zip(elts, val.seq, strict=True):
                    self._assign(e, v, st)
            else:
                each = elem_of(val)
                for e in elts:
                    self._assign(e, each, st)
            return
        if t in ("list_splat_pattern", "parenthesized_expression"):
            for c in target.named_children:
                self._assign(c, summary(val), st)
            return

    @staticmethod
    def _kill_prefix(st: State, name: str) -> None:
        prefix = name + "."
        dead = [k for k in st.vars if k.startswith(prefix)]
        for k in dead:
            del st.vars[k]

    @staticmethod
    def _hashable_const(v: Val) -> bool:
        return v.const is not NOCONST and isinstance(v.const, (str, bytes, int, float, bool, tuple))

    def _store_elem(self, cur: Val, idx: Val, val: Val) -> Val:
        """``cur[idx] = val`` on a tracked container, or a collapsed value."""
        if cur.elems is not None and self._hashable_const(idx):
            items = dict(cur.elems)
            items[idx.const] = val
            if len(items) <= MAX_ITEMS:
                return self._dict_val(items, cur.flags)
        if (
            cur.seq is not None
            and isinstance(idx.const, int)
            and not isinstance(idx.const, bool)
            and -len(cur.seq) <= idx.const < len(cur.seq)
        ):
            seq = list(cur.seq)
            seq[idx.const] = val
            return self._seq_val(seq, cur.flags)
        merged = combine([summary(cur), summary(val)])
        return replace(merged, flags=cur.flags)

    @staticmethod
    def _dict_val(items: dict[Any, Val], flags: frozenset[str] = frozenset()) -> Val:
        base = combine(items.values())
        return replace(base, elems=tuple(items.items()), flags=flags)

    @staticmethod
    def _seq_val(seq: list[Val], flags: frozenset[str] = frozenset()) -> Val:
        base = combine(seq)
        if len(seq) > MAX_ITEMS:
            return replace(base, flags=flags)
        return replace(base, seq=tuple(seq), flags=flags)

    def _exec_if(self, node, st: State, depth: int) -> State:
        chain: list[tuple[Any, Any]] = []
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        if cond is not None and cons is not None:
            chain.append((cond, cons))
        else_body = None
        for i, ch in enumerate(node.children):
            if node.field_name_for_child(i) != "alternative":
                continue
            if ch.type == "elif_clause":
                c = ch.child_by_field_name("condition")
                b = ch.child_by_field_name("consequence")
                if c is not None and b is not None:
                    chain.append((c, b))
            elif ch.type == "else_clause":
                else_body = ch.child_by_field_name("body")
        results: list[State] = []
        pending: State | None = st
        for c, body in chain:
            assert pending is not None
            truth = truthy(self.ev(c, pending, 0).const)
            if truth is not False:
                s_true = pending.copy()
                if truth is None:
                    self._refine(c, s_true, True)
                results.append(self._exec_block(body, s_true, depth + 1))
            if truth is True:
                pending = None
                break
            if truth is None:
                pending = pending.copy()
                self._refine(c, pending, False)
        if pending is not None:
            if else_body is not None:
                results.append(self._exec_block(else_body, pending, depth + 1))
            else:
                results.append(pending)
        return join_states(results)

    def _loop(self, st: State, depth: int, body, bind: Callable[[State], None]) -> State:
        exits: list[tuple[str, State]] = []
        # Nested loops would multiply the rounds (3**depth), so only the two
        # outermost loops iterate towards a fixed point; deeper ones run once.
        rounds = LOOP_ROUNDS if len(self._loop_stack) < 2 else 1
        self._loop_stack.append(exits)
        head = st
        try:
            for _ in range(rounds):
                s = head.copy()
                bind(s)
                out = self._exec_block(body, s, depth + 1)
                conts = [x for k, x in exits if k == "continue"]
                new_head = join_states([head, out, *conts])
                if new_head.live == head.live and new_head.vars == head.vars:
                    break
                head = new_head
        finally:
            self._loop_stack.pop()
        breaks = [x for k, x in exits if k == "break"]
        return join_states([head, *breaks]) if breaks else head

    def _exec_for(self, node, st: State, depth: int) -> State:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        body = node.child_by_field_name("body")
        if body is None:
            return st
        it = self.ev(right, st, 0) if right is not None else UNKNOWN
        elem = elem_of(it)

        def bind(s: State) -> None:
            if left is not None:
                self._assign(left, elem, s)

        after = self._loop(st, depth, body, bind)
        alt = node.child_by_field_name("alternative")
        if alt is not None:
            else_body = alt.child_by_field_name("body")
            if else_body is not None and after.live:
                after = self._exec_block(else_body, after, depth + 1)
        return after

    def _exec_while(self, node, st: State, depth: int) -> State:
        cond = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if cond is None or body is None:
            return st
        truth = truthy(self.ev(cond, st, 0).const)
        if truth is False:
            return st

        def bind(s: State) -> None:
            self.ev(cond, s, 0)
            if truth is None:
                self._refine(cond, s, True)

        after = self._loop(st, depth, body, bind)
        if truth is True:
            # ``while True``: only a break leaves the loop. _loop folded the
            # break states in; without any the code after it is unreachable.
            return after if self._has_break(body) else State(live=False)
        return after

    def _has_break(self, body) -> bool:
        stack = [body]
        while stack:
            n = stack.pop()
            if n.type == "break_statement":
                return True
            if n.type in (
                "for_statement",
                "while_statement",
                "function_definition",
                "class_definition",
            ):
                continue
            stack.extend(n.children)
        return False

    def _exec_try(self, node, st: State, depth: int) -> State:
        body = node.child_by_field_name("body")
        if body is None:
            return st
        out = self._exec_block(body, st.copy(), depth + 1)
        handler_entry = join_states([st, out])
        results: list[State] = []
        normal = out
        finally_block = None
        for ch in node.named_children:
            if ch.type == "else_clause":
                else_body = ch.child_by_field_name("body")
                if else_body is not None and normal.live:
                    normal = self._exec_block(else_body, normal, depth + 1)
            elif ch.type in ("except_clause", "except_group_clause"):
                s = handler_entry.copy()
                block = None
                for sub in ch.named_children:
                    if sub.type == "block":
                        block = sub
                    elif sub.type == "as_pattern":
                        alias = sub.child_by_field_name("alias")
                        if alias is not None:
                            for name in alias.named_children:
                                self._assign(name, UNKNOWN, s)
                if block is not None:
                    results.append(self._exec_block(block, s, depth + 1))
                else:
                    results.append(s)
            elif ch.type == "finally_clause":
                finally_block = next((c for c in ch.named_children if c.type == "block"), None)
        results.insert(0, normal)
        merged = join_states(results)
        if finally_block is not None:
            base = merged if merged.live else handler_entry.copy()
            fin = self._exec_block(finally_block, base, depth + 1)
            return fin if merged.live else State(live=False)
        return merged

    def _exec_with(self, node, st: State, depth: int) -> State:
        for ch in node.named_children:
            if ch.type != "with_clause":
                continue
            for item in ch.named_children:
                value = item.child_by_field_name("value")
                if value is None:
                    continue
                if value.type == "as_pattern":
                    named = value.named_children
                    v = self.ev(named[0], st, 0) if named else UNKNOWN
                    alias = value.child_by_field_name("alias")
                    if alias is not None:
                        for name in alias.named_children:
                            self._assign(name, v, st)
                else:
                    self.ev(value, st, 0)
        body = node.child_by_field_name("body")
        return self._exec_block(body, st, depth + 1) if body is not None else st

    def _exec_match(self, node, st: State, depth: int) -> State:
        subject = node.child_by_field_name("subject")
        body = node.child_by_field_name("body")
        if body is None:
            return st
        sv = self.ev(subject, st, 0) if subject is not None else UNKNOWN
        results: list[State] = []
        exhaustive = False
        for case in body.named_children:
            if case.type != "case_clause":
                continue
            pats = [c for c in case.named_children if c.type == "case_pattern"]
            cons = case.child_by_field_name("consequence")
            guard = case.child_by_field_name("guard")
            decided = self._match_static(pats, sv)
            if decided is False or cons is None:
                continue
            s = st.copy()
            for p in pats:
                for name in self._capture_names(p):
                    s.vars[name] = summary(sv)
            if guard is not None:
                g = guard.named_children[0] if guard.named_children else None
                if g is not None and truthy(self.ev(g, s, 0).const) is False:
                    continue
            results.append(self._exec_block(cons, s, depth + 1))
            if decided is True and guard is None:
                exhaustive = True
                break
        if not exhaustive:
            results.append(st)
        return join_states(results)

    def _match_static(self, pats: list[Any], sv: Val) -> bool | None:
        if len(pats) != 1:
            return None
        p = pats[0]
        named = [c for c in p.named_children if c.type != "comment"]
        if not named:
            return True if self.text(p).strip() == "_" else None
        if len(named) != 1:
            return None
        inner = named[0]
        if inner.type == "identifier":
            return True  # a capture pattern always matches
        options = inner.named_children if inner.type == "union_pattern" else [inner]
        values = []
        for o in options:
            if o.type not in (
                "string",
                "integer",
                "float",
                "true",
                "false",
                "none",
                "concatenated_string",
            ):
                return None
            value = self._literal(o)
            if value is NOCONST:
                return None
            values.append(value)
        if sv.const is NOCONST:
            return None
        return any(_same_const(sv.const, v) for v in values)

    def _capture_names(self, pattern) -> list[str]:
        out: list[str] = []
        stack = [pattern]
        while stack:
            n = stack.pop()
            if (
                n.type == "identifier"
                and n.parent is not None
                and n.parent.type
                in (
                    "case_pattern",
                    "as_pattern_target",
                    "splat_pattern",
                    "keyword_pattern",
                    "list_pattern",
                    "tuple_pattern",
                )
            ):
                name = self.text(n)
                if name != "_":
                    out.append(name)
            stack.extend(n.named_children)
        return out

    def _exec_function(
        self, node, decorators: list[str], depth: int, outer: State | None = None
    ) -> None:
        body = node.child_by_field_name("body")
        name_node = node.child_by_field_name("name")
        if body is None:
            return
        name = self.text(name_node) if name_node is not None else ""
        flask_route = any(ROUTE_DECORATOR.search(d) for d in decorators) or (
            self._flask
            and not self._json_framework
            and any(METHOD_DECORATOR.search(d) for d in decorators)
        )
        # FastAPI / Starlette path operations: @app.get(...), @router.post(...).
        api_route = self._json_framework and any(
            METHOD_DECORATOR.search(d) or ".api_route(" in d or ".websocket(" in d
            for d in decorators
        )
        html_route = api_route and any("HTMLResponse" in d for d in decorators)
        route = flask_route or html_route
        nested = bool(self._fn_stack)
        owner: str | None = None
        if nested:
            owner = self._fn_stack[-1].api_owner
        elif self._is_public(name):
            owner = ".".join([*self._class_stack, name])
        ctx = _FnCtx(
            name=name,
            route=route,
            sensitive=bool(SENSITIVE_RE.search(name)),
            static_path=flask_route and self._static_routes(decorators),
            api_owner=owner,
        )
        self._fn_stack.append(ctx)
        try:
            scope: dict[str, Val] = dict(self._module_consts)
            if nested and outer is not None:
                # A closure sees the enclosing function's variables as they are
                # where it is defined (callbacks, generators, inner helpers).
                scope.update(outer.vars)
            params = self._param_vals(
                node,
                route_rules=decorators if flask_route else None,
                api_route=api_route,
                public=owner is not None and not nested,
            )
            scope.update(params)
            self._exec_block(body, State(scope), depth + 1)
        finally:
            self._fn_stack.pop()

    def _is_public(self, name: str) -> bool:
        """Library mode: a function or method that callers of the package can reach."""
        if self._library is None or not self._library.module_public:
            return False

        def public(n: str) -> bool:
            return not n.startswith("_") or (n.startswith("__") and n.endswith("__"))

        outermost = self._class_stack[0] if self._class_stack else name
        if self._exported is not None and outermost not in self._exported:
            return False
        return public(name) and all(public(c) and not c.startswith("__") for c in self._class_stack)

    def _module_exports(self, root) -> frozenset[str] | None:
        """The names in a literal module-level ``__all__``, or None without one."""
        names: set[str] = set()
        found = False
        for stmt in root.named_children:
            if stmt.type != "expression_statement":
                continue
            for ch in stmt.named_children:
                if ch.type not in ("assignment", "augmented_assignment"):
                    continue
                left = ch.child_by_field_name("left")
                right = ch.child_by_field_name("right")
                if left is None or self.text(left) != "__all__" or right is None:
                    continue
                if right.type not in ("list", "tuple"):
                    return None  # computed: do not guess
                found = True
                for item in right.named_children:
                    value = self._literal(item) if item.type == "string" else NOCONST
                    if isinstance(value, str):
                        names.add(value)
        return frozenset(names) if found else None

    @staticmethod
    def _static_routes(decorators: list[str]) -> bool:
        """Every route rule on the view is a literal path without ``<converters>``.

        Routing only dispatches a request to such a view when its path equals
        one of those literals, so ``request.path`` is not attacker-controlled
        there (its query string and headers still are).
        """
        rules = [d for d in decorators if ROUTE_DECORATOR.search(d) or METHOD_DECORATOR.search(d)]
        if not rules:
            return False
        for d in rules:
            m = _ROUTE_RULE.search(d)
            if m is None or "<" in m.group(2):
                return False
        return True

    def _param_vals(
        self,
        fn_node,
        *,
        route_rules: list[str] | None = None,
        api_route: bool = False,
        public: bool = False,
    ) -> dict[str, Val]:
        """Each parameter (except ``self``/``cls``) as a value of caller origin.

        Parameters the web framework fills from the request are sources: Flask
        route converters (``<path:name>``, except int/float/uuid/any), FastAPI
        parameters (``Query()``, ``Form()``, ``File()``... defaults, and every
        non-dependency parameter of a path operation), ``UploadFile`` uploads.
        A parameter annotated as the framework's request object is marked so
        its client-controlled attributes are sources. In library mode the
        parameters of a public function are sources of origin ORIGIN_API.
        """
        params = fn_node.child_by_field_name("parameters")
        out: dict[str, Val] = {}
        if params is None:
            return out
        converters = self._route_converters(route_rules) if route_rules else {}
        for p in params.named_children:
            name, annotation, default = self._param_parts(p)
            if name is None or name in ("self", "cls"):
                continue
            v = self._param_source(name, annotation, default, converters, api_route, public)
            if v.taint and self._trails:
                v = self._hop(v, p, "source", name, ("param", v.origins))
            out[name] = v
        return out

    def _param_parts(self, p) -> tuple[str | None, str, Any]:
        """(name, annotation text, default node) of one parameter node."""
        t = p.type
        if t == "identifier":
            return self.text(p), "", None
        name_node = p.child_by_field_name("name")
        if name_node is None:
            inner = next((c for c in p.named_children if c.type != "comment"), None)
            if inner is not None and inner.type in (
                "list_splat_pattern",
                "dictionary_splat_pattern",
            ):
                inner = next((c for c in inner.named_children if c.type == "identifier"), None)
            name_node = inner if inner is not None and inner.type == "identifier" else None
        if name_node is None:
            return None, "", None
        ann = p.child_by_field_name("type")
        return (
            self.text(name_node),
            self._compact(ann) if ann is not None else "",
            p.child_by_field_name("value"),
        )

    def _param_source(
        self,
        name: str,
        annotation: str,
        default,
        converters: dict[str, str],
        api_route: bool,
        public: bool,
    ) -> Val:
        marker = ""
        if default is not None and default.type == "call":
            fn = default.child_by_field_name("function")
            marker = self._compact(fn).rsplit(".", 1)[-1] if fn is not None else ""
        if marker in ("Depends", "Security") or "Depends(" in annotation:
            return Val(param=True)
        core = re.sub(r"^Optional\[(.*)\]$|\|None$", r"\1", annotation)
        if core and _REQUEST_TYPES.match(core):
            return Val(param=True, flags=frozenset({"httpreq"}))
        safe = bool(_SAFE_ANNOTATION.match(annotation))
        fastapi_marker = marker in FASTAPI_PARAMS or bool(
            re.search(r"\b(?:Query|Path|Body|Form|File|Header|Cookie)\(", annotation)
        )
        if fastapi_marker or "UploadFile" in annotation:
            return LIT if safe else TAINT
        if name in converters:
            return LIT if converters[name] in _SAFE_CONVERTERS else TAINT
        if api_route and not _FRAMEWORK_NON_INPUT.search(annotation):
            return LIT if safe else TAINT
        if public:
            return Val(lit=True, param=True) if safe else API_TAINT
        return Val(param=True)

    @staticmethod
    def _route_converters(decorators: list[str]) -> dict[str, str]:
        """Route parameter name -> converter (``string`` when none is given)."""
        out: dict[str, str] = {}
        for d in decorators:
            if not (ROUTE_DECORATOR.search(d) or METHOD_DECORATOR.search(d)):
                continue
            m = _ROUTE_RULE.search(d)
            if m is None:
                continue
            for conv, pname in _ROUTE_PARAM.findall(m.group(2)):
                out[pname] = conv or "string"
        return out

    def _exec_return(self, node, st: State) -> None:
        named = node.named_children
        v = self.ev(named[0], st, 0) if named else Val(lit=True, const=None)
        if not self._fn_stack:
            return
        ctx = self._fn_stack[-1]
        ctx.returns.append(v)
        if ctx.exits is not None:
            ctx.exits.append((v, named[0] if named else None, st.copy()))
        if ctx.route and v.tainted_for(SINK_CWES["ast-xss"]):
            self._emit("ast-xss", node, trail=v.trail)
        elif ctx.api_owner is not None and v.api_only and "html" in v.flags:
            # A public function that returns HTML built around its caller's text.
            self._report("ast-xss", node, [v])
        if ctx.sensitive and v.weak:
            self._emit("ast-weak-random", node)

    # --- guards -------------------------------------------------------------
    def _atoms(self, cond, truth: bool, out: list[tuple[Any, bool]], depth: int = 0) -> None:
        """Atomic conditions implied by ``cond`` having the value ``truth``."""
        if depth > 20:
            return
        t = cond.type
        if t == "parenthesized_expression" and cond.named_children:
            self._atoms(cond.named_children[0], truth, out, depth + 1)
            return
        if t == "not_operator":
            arg = cond.child_by_field_name("argument")
            if arg is not None:
                self._atoms(arg, not truth, out, depth + 1)
            return
        if t == "boolean_operator":
            op_node = cond.child_by_field_name("operator")
            op = self.text(op_node) if op_node is not None else ""
            if (op == "and" and truth) or (op == "or" and not truth):
                for side in ("left", "right"):
                    sub = cond.child_by_field_name(side)
                    if sub is not None:
                        self._atoms(sub, truth, out, depth + 1)
                return
            # An "or" that holds (or an "and" that fails) implies no single side;
            # it is passed on whole (``p.startswith(base + os.sep) or p == base``).
        out.append((cond, truth))

    def _refine(self, cond, st: State, truth: bool) -> None:
        # Only guards that are standard, complete mitigations refine a value:
        # allowlists, numeric/identifier checks, host allowlists for redirects
        # and resolved-path containment. Blocklist checks such as
        # ``'../' in p`` or "contains no quote" are deliberately not trusted:
        # they are incomplete in general (absolute paths, other quote styles).
        atoms: list[tuple[Any, bool]] = []
        self._atoms(cond, truth, atoms)
        saved, self._guard_at = self._guard_at, cond
        try:
            self._refine_atoms(atoms, st)
        finally:
            self._guard_at = saved

    def _refine_atoms(self, atoms: list[tuple[Any, bool]], st: State) -> None:
        for node, holds in atoms:
            contained = self._path_contained(node, st, 0) if holds else None
            if contained is None and node.type == "comparison_operator":
                contained = self._commonpath_contained(node, st, holds)
            if contained is not None:
                self._clean(st, contained, frozenset({CWE_PATH}))
            if node.type == "comparison_operator":
                self._refine_compare(node, st, holds)
            elif node.type == "call":
                self._refine_call(node, st, holds)

    def _path_contained(self, node, st: State, depth: int) -> str | None:
        """The resolved path variable ``node`` proves to lie inside a base directory.

        Recognizes ``p.is_relative_to(base)``, ``str(p).startswith(base)``,
        ``p == base``, an ``or`` of such tests on the same ``p`` and
        ``any(<such a test> for base in bases)``, where ``p`` came from
        ``resolve()`` / ``os.path.realpath()`` (so ``..`` is already gone).
        """
        if depth > 8:
            return None
        t = node.type
        if t == "parenthesized_expression" and node.named_children:
            return self._path_contained(node.named_children[0], st, depth + 1)
        if t == "boolean_operator":
            op_node = node.child_by_field_name("operator")
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if op_node is None or self.text(op_node) != "or" or left is None or right is None:
                return None
            a = self._path_contained(left, st, depth + 1)
            return a if a is not None and a == self._path_contained(right, st, depth + 1) else None
        if t == "comparison_operator":
            operands = [c for c in node.named_children if c.type != "comment"]
            ops = [
                c.type
                for i, c in enumerate(node.children)
                if node.field_name_for_child(i) == "operators"
            ]
            if len(operands) == 2 and ops == ["=="]:
                p = self._path(self._unwrap(operands[0]))
                if p is not None and "normalized" in st.get(p).flags:
                    return p
            return None
        if t != "call":
            return None
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None:
            return None
        last = self._compact(fn).rsplit(".", 1)[-1]
        if last == "any" and args is not None and args.type == "generator_expression":
            body = args.child_by_field_name("body")
            return self._path_contained(body, st, depth + 1) if body is not None else None
        if last in ("is_relative_to", "startswith") and fn.type == "attribute":
            recv = fn.child_by_field_name("object")
            p = self._path(self._unwrap(recv)) if recv is not None else None
            if p is not None and "normalized" in st.get(p).flags:
                return p
        return None

    def _commonpath_contained(self, node, st: State, holds: bool) -> str | None:
        """``os.path.commonpath([base, p]) == base`` (or ``!=`` on the false side).

        ``commonpath`` compares whole path components, so a resolved ``p``
        whose common path with ``base`` is ``base`` lies inside ``base``. Like
        the other containment checks, ``p`` must have been normalized first
        (``realpath`` / ``abspath`` / ``resolve()``), or ``..`` would pass.
        """
        operands = [c for c in node.named_children if c.type != "comment"]
        ops = [
            c.type
            for i, c in enumerate(node.children)
            if node.field_name_for_child(i) == "operators"
        ]
        if len(operands) != 2 or ops not in (["=="], ["!="]) or (ops == ["=="]) != holds:
            return None
        for call, other in (operands, operands[::-1]):
            if call.type != "call":
                continue
            fn = call.child_by_field_name("function")
            args = call.child_by_field_name("arguments")
            if fn is None or self._compact(fn).rsplit(".", 1)[-1] != "commonpath" or args is None:
                continue
            items = [a for a in args.named_children if a.type != "comment"]
            if len(items) != 1 or items[0].type not in ("list", "tuple"):
                continue
            elems = [e for e in items[0].named_children if e.type != "comment"]
            base = self._compact(other)
            if len(elems) != 2 or base not in (self._compact(e) for e in elems):
                continue
            cand = elems[1] if self._compact(elems[0]) == base else elems[0]
            p = self._path(self._unwrap(cand))
            if p is not None and "normalized" in st.get(p).flags:
                return p
        return None

    def _unwrap(self, node):
        """``x`` from ``str(x)`` / ``os.fspath(x)`` / ``Path(x)`` / ``(x)``, else ``node``."""
        for _ in range(4):
            if node.type == "parenthesized_expression" and node.named_children:
                node = node.named_children[0]
                continue
            if node.type == "call":
                fn = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")
                if (
                    fn is not None
                    and self._compact(fn)
                    in ("str", "os.fspath", "bytes", "Path", "pathlib.Path", "PurePath")
                    and args is not None
                    and len(args.named_children) == 1
                ):
                    node = args.named_children[0]
                    continue
            break
        return node

    def _refine_compare(self, node, st: State, holds: bool) -> None:
        operands = [c for c in node.named_children if c.type != "comment"]
        ops = [
            c.type
            for i, c in enumerate(node.children)
            if node.field_name_for_child(i) == "operators"
        ]
        if len(operands) != 2 or len(ops) != 1:
            return
        a, b = operands
        op = ops[0]
        if op in ("in", "not in"):
            member_holds = (op == "in") == holds
            if member_holds:
                bv = self._ev_quiet(b, st)
                if bv.lit:
                    path = self._path(a)
                    if path is not None:
                        st.vars[path] = Val(lit=True)
                    self._clean_url_host(a, st)
            return
        if op in ("==", "!="):
            eq_holds = (op == "==") == holds
            if not eq_holds:
                return
            for x, y in ((a, b), (b, a)):
                yv = self._ev_quiet(y, st)
                if yv.lit:
                    path = self._path(x)
                    if path is not None:
                        st.vars[path] = Val(lit=True, const=yv.const)
                    self._clean_url_host(x, st)

    def _clean_url_host(self, node, st: State) -> None:
        """``u.netloc`` / ``u.hostname`` known to be an allowed value.

        The URL ``u`` was parsed from then cannot send a redirect or a
        server-side request anywhere but the allowed hosts.
        """
        cleared = frozenset({CWE_REDIRECT, CWE_SSRF})
        if node.type != "attribute":
            return
        attr = node.child_by_field_name("attribute")
        obj = node.child_by_field_name("object")
        if attr is None or obj is None or self.text(attr) not in ("netloc", "hostname", "host"):
            return
        if obj.type == "call":  # urlparse(target).netloc in ALLOWED
            fn = obj.child_by_field_name("function")
            args = obj.child_by_field_name("arguments")
            if fn is not None and self._compact(fn).rsplit(".", 1)[-1] in _URL_PARSERS:
                first = next(
                    (a for a in (args.named_children if args else []) if a.type != "comment"), None
                )
                target = self._path(first) if first is not None else None
                if target is not None:
                    self._clean(st, target, cleared)
            return
        path = self._path(obj)
        if path is None:
            return
        for flag in st.get(path).flags:
            if flag.startswith("urlof:"):
                self._clean(st, flag[6:], cleared)

    def _host_suffix_check(self, recv, arg_nodes: list[Any], st: State) -> None:
        """``urlparse(u).hostname.endswith(".example.com")``: a host allowlist."""
        if len(arg_nodes) != 1:
            return
        arg = arg_nodes[0]
        options = arg.named_children if arg.type in ("tuple", "parenthesized_expression") else [arg]
        values = [self._literal(o) if o.type == "string" else NOCONST for o in options]
        if values and all(isinstance(v, str) and "." in v.strip(".") for v in values):
            self._clean_url_host(recv, st)

    def _refine_call(
        self,
        node,
        st: State,
        holds: bool,
    ) -> None:
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None:
            return
        last = self._compact(fn).rsplit(".", 1)[-1]
        recv = fn.child_by_field_name("object") if fn.type == "attribute" else None
        arg_nodes = (
            [c for c in args.named_children if c.type != "comment"] if args is not None else []
        )
        saved_where = self._guard_where
        try:
            for path, guard in self._guarded_args(node, st):
                self._clean(st, path, guard.true if holds else guard.false)
        finally:
            self._guard_where = saved_where
        if not holds:
            return
        if recv is None and last == "isinstance" and len(arg_nodes) == 2:
            # isinstance(x, (int, float)): on this branch x is a number, not text.
            p = self._path(arg_nodes[0])
            kinds = [k for k in self._compact(arg_nodes[1]).strip("()").split(",") if k]
            if p is not None and kinds and all(k in _NUMBER_TYPES for k in kinds):
                st.vars[p] = Val(lit=True, weak=st.get(p).weak)
        if recv is not None and last == "endswith":
            self._host_suffix_check(recv, arg_nodes, st)
        if recv is not None:
            rpath = self._path(self._unwrap(recv))
            if rpath is None:
                return
            if last in ("isdigit", "isnumeric", "isdecimal", "isalnum", "isalpha", "isidentifier"):
                v = st.get(rpath)
                st.vars[rpath] = Val(lit=True, weak=v.weak)
            elif last in ("startswith", "is_relative_to") and "normalized" in st.get(rpath).flags:
                self._clean(st, rpath, frozenset({CWE_PATH}))
        safe_url = ("url_has_allowed_host_and_scheme", "is_safe_url", "is_safe_redirect_url")
        if last in safe_url and arg_nodes:
            p = self._path(arg_nodes[0])
            if p is not None:
                self._clean(st, p, frozenset({CWE_REDIRECT}))

    def _clean(self, st: State, path: str, cwes: frozenset[str]) -> None:
        v = st.vars.get(path)
        if v is not None and v.taint:
            v = replace(v, clean=v.clean | cwes)
            if self._trails and self._guard_at is not None and cwes:
                text = self._snip(self._guard_at, 60)
                if self._guard_where is not None:
                    text = f"{text} (defined in {self._guard_where})"
                v = self._hop(v, self._guard_at, "guard", text, cwes)
            st.vars[path] = v

    # --- same-file helpers ----------------------------------------------------
    # A call to a function defined once in this file (``helper(x)``, or
    # ``self.helper(x)`` for a method) is analyzed through a summary of the
    # helper's body instead of assuming its result carries every argument's
    # taint: what it returns when its parameters are tainted (a sanitizing
    # helper returns a cleaned value; one that ignores its argument returns
    # clean data), and which CWEs it validates a parameter for (a helper that
    # raises, or returns False, unless the value passed an allowlist or a
    # resolved-path containment check). Summaries are computed on demand,
    # bounded in depth and steps, and memoized per file.
    def _local_helper(self, fn) -> tuple[str, bool] | None:
        """(name, is_method) when the call target ``fn`` is a helper defined in this file."""
        if self._shared is None or fn is None:
            return None
        if fn.type == "identifier":
            name = self.text(fn)
            return (name, False) if name in self._shared.functions else None
        if fn.type == "attribute":
            obj = fn.child_by_field_name("object")
            attr = fn.child_by_field_name("attribute")
            if (
                obj is not None
                and attr is not None
                and obj.type == "identifier"
                and self.text(obj) in ("self", "cls")
            ):
                name = self.text(attr)
                return (name, True) if name in self._shared.methods else None
        return None

    def _helper_node(self, name: str, method: bool):
        assert self._shared is not None
        return (self._shared.methods if method else self._shared.functions).get(name)

    # A helper imported from another file of the project resolves through the
    # project index (``from .utils import clean``, ``utils.clean(x)``, a static
    # or class method, a method of a module-level instance) and is summarized
    # in its own file, with the caller's settings, by a flow the scan's
    # SummaryStore keeps for that file. Summaries nest at most
    # MAX_SUMMARY_DEPTH deep and cross at most MAX_XFILE_DEPTH file boundaries.
    def _helper_ref(self, fn, st: State | None = None) -> _HelperRef | None:
        """The helper a call target ``fn`` names, in this file or another one."""
        local = self._local_helper(fn)
        if local is not None:
            node = self._helper_node(*local)
            if node is None:
                return None
            key = ("m:" if local[1] else "f:") + local[0]
            return _HelperRef(key, node, self, local[0])
        link = self._project
        if link is None or fn is None or self._xdepth >= MAX_XFILE_DEPTH:
            return None
        dotted = self._path(fn)
        if dotted is None or (st is not None and dotted.split(".", 1)[0] in st.vars):
            return None
        callee = link.store.project.resolve_call(link.path, dotted)
        if callee is None or callee.path == link.path:
            return None
        host = link.store.host(callee.path, self)
        if host is None:
            return None
        label = callee.qualname
        return _HelperRef(
            "x:" + callee.qualname, callee.node, host, label, f"{callee.path}:{callee.line}"
        )

    @contextmanager
    def _visit(self, ref: _HelperRef) -> Iterator[Flow]:
        """``ref``'s defining flow, entered at this flow's depths."""
        host = ref.host
        if host is self:
            yield self
            return
        saved = host._summary_depth, host._xdepth
        host._summary_depth = self._summary_depth
        host._xdepth = self._xdepth + 1
        try:
            yield host
        finally:
            host._summary_depth, host._xdepth = saved

    def _helper_params(self, fn_node) -> list[tuple[str, bool]]:
        """(name, is_splat) for each parameter except ``self``/``cls``."""
        params = fn_node.child_by_field_name("parameters")
        out: list[tuple[str, bool]] = []
        if params is None:
            return out
        for p in params.named_children:
            name, _, _ = self._param_parts(p)
            if name is None or name in ("self", "cls"):
                continue
            splat = p.type in ("list_splat_pattern", "dictionary_splat_pattern") or any(
                c.type in ("list_splat_pattern", "dictionary_splat_pattern")
                for c in p.named_children
            )
            out.append((name, splat))
        return out

    def _call_arg_map(self, call, params: list[tuple[str, bool]]) -> list[tuple[str, Any]]:
        """(parameter name, argument node) pairs for a call to a helper with ``params``."""
        args = call.child_by_field_name("arguments")
        if args is None or args.type == "generator_expression":
            return []
        positional: list[str] = []
        for name, splat in params:
            if splat:
                break
            positional.append(name)
        names = {n for n, splat in params if not splat}
        out: list[tuple[str, Any]] = []
        index = 0
        for a in args.named_children:
            if a.type == "keyword_argument":
                key = a.child_by_field_name("name")
                value = a.child_by_field_name("value")
                if key is not None and value is not None and self.text(key) in names:
                    out.append((self.text(key), value))
            elif a.type in ("list_splat", "dictionary_splat"):
                break
            elif a.type != "comment":
                if index < len(positional):
                    out.append((positional[index], a))
                index += 1
        return out

    def _run_summary(self, fn_node, seeds: dict[str, Val]) -> tuple[Flow, _FnCtx] | None:
        """Run a helper's body once with ``seeds``; its exits are in the context."""
        body = fn_node.child_by_field_name("body")
        if body is None or self._summary_depth >= MAX_SUMMARY_DEPTH:
            return None
        sub = Flow(
            self._src,
            None,
            context=self._ctx,
            source_methods=self.source_methods,
            source_functions=self.source_functions,
        )
        sub._shared = self._shared
        sub._project = self._project
        sub._xdepth = self._xdepth
        sub._module_consts = self._module_consts
        sub._summary_depth = self._summary_depth + 1
        sub._step_limit = SUMMARY_STEPS
        name_node = fn_node.child_by_field_name("name")
        ctx = _FnCtx(
            name=self.text(name_node) if name_node is not None else "",
            route=False,
            sensitive=False,
            exits=[],
        )
        scope = dict(self._module_consts)
        for pname, _ in self._helper_params(fn_node):
            scope[pname] = Val(param=True)
        scope.update(seeds)
        sub._fn_stack.append(ctx)
        try:
            end = sub._exec_block(body, State(scope), 1)
        except (AnalysisBudgetExceeded, RecursionError):
            return None
        assert ctx.exits is not None
        if end.live:
            ctx.exits.append((None, None, end))
        return sub, ctx

    def _return_summary(self, ref: _HelperRef) -> _RetSummary | None:
        with self._visit(ref) as host:
            return host._return_summary_at(ref.key, ref.node)

    def _return_summary_at(self, key: str, node) -> _RetSummary | None:
        """What helper ``node`` of this file returns when its parameters are tainted."""
        assert self._shared is not None
        if key in self._shared.returns:
            return self._shared.returns[key]
        if self._summary_depth >= MAX_SUMMARY_DEPTH:
            return None  # too deep here; do not memoize the gap
        self._shared.returns[key] = None  # recursion guard
        if node is None or _is_generator(node):
            return None
        run = self._run_summary(node, {p: TAINT for p, _ in self._helper_params(node)})
        if run is None:
            return None
        _, ctx = run
        assert ctx.exits is not None
        vals = [v if v is not None else Val(lit=True, const=None) for v, _, _ in ctx.exits]
        if not vals:
            return None  # always raises: keep the default
        joined = vals[0]
        for v in vals[1:]:
            joined = join(joined, v)
        summ = _RetSummary(
            taint=joined.taint,
            clean=joined.clean if joined.taint else frozenset(),
            embed=joined.embed,
            part=joined.part,
            lit=joined.lit,
            flags=joined.flags & _RETURN_FLAGS,
        )
        self._shared.returns[key] = summ
        return summ

    def _guard_summary(self, ref: _HelperRef, pname: str) -> _Guard | None:
        with self._visit(ref) as host:
            return host._guard_summary_at(ref.key, ref.node, pname)

    def _guard_summary_at(self, name: str, node, pname: str) -> _Guard | None:
        """CWEs helper ``node`` of this file validates its parameter ``pname`` for."""
        assert self._shared is not None
        key = (name, pname)
        if key in self._shared.guards:
            return self._shared.guards[key]
        if self._summary_depth >= MAX_SUMMARY_DEPTH:
            return None
        self._shared.guards[key] = None
        if node is None or not _has_rejection(node):
            return None
        run = self._run_summary(node, {pname: TAINT})
        if run is None:
            return None
        sub, ctx = run
        assert ctx.exits is not None
        after: frozenset[str] | None = None
        true: frozenset[str] | None = None
        false: frozenset[str] | None = None
        for v, expr, state in ctx.exits:
            base = _cleared(state.get(pname))
            after = base if after is None else after & base
            truth = False if v is None else truthy(v.const)
            for side, keep in ((True, truth is not False), (False, truth is not True)):
                if not keep:
                    continue
                got = base
                if expr is not None and truth is None:
                    refined = state.copy()
                    sub._quiet += 1
                    try:
                        sub._refine(expr, refined, side)
                    finally:
                        sub._quiet -= 1
                    got = _cleared(refined.get(pname))
                if side:
                    true = got if true is None else true & got
                else:
                    false = got if false is None else false & got
        extra = frozenset({CWE_SSRF}) if self._is_ssrf_guard(node) else frozenset()
        guard = _Guard(
            after=(after or frozenset()) | extra,
            true=(true or frozenset()) | extra,
            false=(false or frozenset()) | extra,
        )
        result = guard if (guard.after or guard.true or guard.false) else None
        self._shared.guards[key] = result
        return result

    def _is_ssrf_guard(self, fn_node) -> bool:
        """A helper that rejects URLs by the class of the address they resolve to.

        Its body (or a same-file helper it calls) tests ``is_private``,
        ``is_loopback``, ``is_link_local``, ``is_reserved``, ``is_global`` and
        similar properties of an ``ipaddress`` / ``netaddr`` address, the
        standard way to keep a server-side request off internal networks.
        """
        text = self._src[fn_node.start_byte : fn_node.end_byte]
        if _IP_CLASSIFIERS.search(text):
            return True
        stack = [fn_node.child_by_field_name("body")]
        while stack:
            n = stack.pop()
            if n is None:
                continue
            if n.type == "call":
                helper = self._local_helper(n.child_by_field_name("function"))
                other = self._helper_node(*helper) if helper is not None else None
                if (
                    other is not None
                    and other is not fn_node
                    and _IP_CLASSIFIERS.search(self._src[other.start_byte : other.end_byte])
                ):
                    return True
            stack.extend(n.children)
        return False

    def _guarded_args(self, call, st: State) -> list[tuple[str, _Guard]]:
        """Tainted variables a call to a validator helper vouches for."""
        fn = call.child_by_field_name("function")
        ref = self._helper_ref(fn, st)
        if ref is None:
            return []
        out: list[tuple[str, _Guard]] = []
        for pname, arg in self._call_arg_map(call, ref.host._helper_params(ref.node)):
            path = self._path(arg)
            if path is None or not st.get(path).taint:
                continue
            guard = self._guard_summary(ref, pname)
            if guard is not None:
                out.append((path, guard))
        if out and ref.where is not None:
            self._guard_where = ref.where
        return out

    def _apply_guard_statement(self, node, st: State) -> None:
        """``validate(x)`` on its own line: past it, ``x`` passed the validation."""
        if node.type == "await" and node.named_children:
            node = node.named_children[0]
        if node.type != "call" or not st.live:
            return
        saved, self._guard_at = self._guard_at, node
        saved_where, self._guard_where = self._guard_where, None
        try:
            for path, guard in self._guarded_args(node, st):
                self._clean(st, path, guard.after)
        finally:
            self._guard_at = saved
            self._guard_where = saved_where

    # --- expressions --------------------------------------------------------
    def ev(self, node, st: State, depth: int) -> Val:
        if node is None:
            return UNKNOWN
        if depth > MAX_EXPR_DEPTH:
            return self._flat(node, st)
        handler = self._ev_table.get(node.type)
        if handler is not None:
            v = handler(node, st, depth + 1)
            return self._trace(v, node) if v.taint and self._trails else v
        if node.type == "comment":
            return LIT
        vals = [self.ev(c, st, depth + 1) for c in node.named_children]
        v = combine(vals)
        return replace(v, lit=False)

    def _ev_identifier(self, node, st: State, depth: int) -> Val:
        return st.vars.get(self.text(node), UNKNOWN)

    def _ev_attribute(self, node, st: State, depth: int) -> Val:
        text = self._compact(node)
        if text in _REQUEST_PATH and self._fn_stack and self._fn_stack[-1].static_path:
            return LIT
        path = self._path(node)
        # Only a plain dotted name (``request.args``) is matched as text: in
        # ``client.get(request.args["u"]).text`` the call must be evaluated, or
        # the sink inside it is never seen.
        if path is not None and self._is_source(text):
            return self._source_val(text)
        if path is not None:
            if path in st.vars:
                return st.vars[path]
            if path in _LIT_ATTRS:
                return LIT
        obj = self.ev(node.child_by_field_name("object"), st, depth)
        flags = obj.flags & {"reqobj"}
        attr = node.child_by_field_name("attribute")
        name = self.text(attr) if attr is not None else ""
        if "httpreq" in obj.flags and name in REQUEST_ATTRS:
            return TAINT  # req.query_params, request.headers, ...
        if "archmember" in obj.flags and name in ("filename", "name", "linkname", "path"):
            return ARCHIVE_TAINT  # the member name stored in the archive
        if name == "parent" and "path" in obj.flags:
            flags = flags | {"path"}
        if obj.taint and obj.src == {ORIGIN_API}:
            return derived(obj, flags=flags, part=True)  # a field of the caller's object
        return derived(obj, flags=flags)

    def _ev_string(self, node, st: State, depth: int) -> Val:
        start = node.children[0] if node.children else None
        prefix = (
            self.text(start).lower() if start is not None and start.type == "string_start" else ""
        )
        interps = [c for c in node.named_children if c.type == "interpolation"]
        html = any(
            c.type == "string_content" and _HTML_TAG.search(self.text(c)) for c in node.children
        )
        tag = frozenset({"html"}) if html else frozenset()
        if "f" in prefix:
            if not interps:
                return Val(lit=True, flags=tag)
            vals: list[Val] = []
            ordered: list[Val] = []  # literal text and values, in source order
            for ch in node.children:
                if ch.type == "string_content" and self.text(ch):
                    ordered.append(Val(lit=True, const=self.text(ch)))
                if ch.type != "interpolation":
                    continue
                expr = ch.child_by_field_name("expression")
                if expr is not None:
                    ev = self.ev(expr, st, depth)
                    vals.append(ev)
                    ordered.append(ev)
                for sub in ch.named_children:
                    if sub.type == "format_specifier":
                        for fe in sub.named_children:
                            e = fe.child_by_field_name("expression")
                            if e is not None:
                                vals.append(self.ev(e, st, depth))
            v = combine(vals)
            flags = (frozenset() if v.lit else frozenset({"dyn"})) | tag
            v = replace(v, flags=flags, embed=v.taint and _ordered_embed(ordered))
            return _pin_redirect(v, ordered)
        return Val(lit=True, const=self._literal(node), flags=tag)

    def _ev_concat(self, node, st: State, depth: int) -> Val:
        parts = [self.ev(c, st, depth) for c in node.named_children]
        v = combine(parts)
        consts = [p.const for p in parts]
        const: Any = NOCONST
        if consts and all(isinstance(c, str) for c in consts):
            const = "".join(consts)
        elif consts and all(isinstance(c, bytes) for c in consts):
            const = b"".join(consts)
        if isinstance(const, (str, bytes)) and len(const) > MAX_STR:
            const = NOCONST
        flags = frozenset() if v.lit else frozenset({"dyn"})
        if any("html" in p.flags for p in parts):
            flags = flags | {"html"}
        v = replace(v, const=const, flags=flags, embed=v.taint and _ordered_embed(parts))
        return _pin_redirect(v, parts)

    def _ev_number(self, node, st: State, depth: int) -> Val:
        text = self.text(node)
        return Val(lit=True, const=self._literal(node) if len(text) < 40 else NOCONST)

    def _ev_paren(self, node, st: State, depth: int) -> Val:
        named = [c for c in node.named_children if c.type != "comment"]
        if len(named) == 1:
            return self.ev(named[0], st, depth)
        return combine(self.ev(c, st, depth) for c in named)

    def _binop(self, op: str, a: Val, b: Val) -> Val:
        v = combine([a, b])
        flags: set[str] = set()
        embed = v.embed
        if op == "/" and (
            "path" in a.flags or isinstance(b.const, str) or ("dyn" in b.flags and not b.lit)
        ):
            # pathlib's ``base / name``: nothing else divides by a string.
            flags.add("path")
            embed = embed or (v.taint and _ordered_embed([a, b]))
        if op in ("%", "+") and not v.lit:
            flags.add("dyn")
        if op in ("%", "+"):
            embed = embed or (v.taint and _ordered_embed([a, b]))
            if "html" in a.flags or "html" in b.flags:
                flags.add("html")
        if op == "+" and a.seq is not None and b.seq is not None:
            return self._seq_val([*a.seq, *b.seq])
        v = replace(
            v, const=_fold_binary(op, a.const, b.const), flags=frozenset(flags), embed=embed
        )
        return _pin_redirect(v, [a, b]) if op == "+" else v

    def _ev_binary(self, node, st: State, depth: int) -> Val:
        a = self.ev(node.child_by_field_name("left"), st, depth)
        b = self.ev(node.child_by_field_name("right"), st, depth)
        op_node = node.child_by_field_name("operator")
        return self._binop(self.text(op_node) if op_node is not None else "", a, b)

    def _ev_unary(self, node, st: State, depth: int) -> Val:
        v = self.ev(node.child_by_field_name("argument"), st, depth)
        op_node = node.child_by_field_name("operator")
        op = self.text(op_node) if op_node is not None else ""
        const: Any = NOCONST
        if isinstance(v.const, (int, float)) and not isinstance(v.const, bool):
            const = {"-": -v.const, "+": +v.const}.get(op, NOCONST)
            if op == "~" and isinstance(v.const, int):
                const = ~v.const
        return derived(v, const=const)

    def _ev_not(self, node, st: State, depth: int) -> Val:
        v = self.ev(node.child_by_field_name("argument"), st, depth)
        t = truthy(v.const)
        return Val(lit=v.lit, const=NOCONST if t is None else not t)

    def _ev_compare(self, node, st: State, depth: int) -> Val:
        operands = [c for c in node.named_children if c.type != "comment"]
        ops = [
            c.type
            for i, c in enumerate(node.children)
            if node.field_name_for_child(i) == "operators"
        ]
        vals = [self.ev(c, st, depth) for c in operands]
        lit = all(v.lit for v in vals)
        result: Any = NOCONST
        if len(ops) == len(vals) - 1 and all(v.const is not NOCONST for v in vals):
            result = True
            for i, op in enumerate(ops):
                r = _fold_compare(op, vals[i].const, vals[i + 1].const)
                if r is NOCONST:
                    result = NOCONST
                    break
                if not r:
                    result = False
                    break
        return Val(lit=lit, const=result)

    def _ev_boolean(self, node, st: State, depth: int) -> Val:
        left = self.ev(node.child_by_field_name("left"), st, depth)
        op_node = node.child_by_field_name("operator")
        op = self.text(op_node) if op_node is not None else ""
        t = truthy(left.const)
        if t is not None:
            if (op == "and" and not t) or (op == "or" and t):
                return left
            return self.ev(node.child_by_field_name("right"), st, depth)
        right = self.ev(node.child_by_field_name("right"), st, depth)
        return combine([left, right])

    def _ev_conditional(self, node, st: State, depth: int) -> Val:
        named = [c for c in node.named_children if c.type != "comment"]
        if len(named) != 3:
            return combine(self.ev(c, st, depth) for c in named)
        a, cond, b = named
        t = truthy(self.ev(cond, st, depth).const)
        if t is True:
            return self.ev(a, st, depth)
        if t is False:
            return self.ev(b, st, depth)
        return join(self.ev(a, st, depth), self.ev(b, st, depth))

    def _ev_subscript(self, node, st: State, depth: int) -> Val:
        v = self._ev_subscript_value(node, st, depth)
        if v.taint and v.src == {ORIGIN_API} and not v.part:
            return replace(v, part=True)  # an item of the caller's container
        return v

    def _ev_subscript_value(self, node, st: State, depth: int) -> Val:
        value = node.child_by_field_name("value")
        subs = [
            c for i, c in enumerate(node.children) if node.field_name_for_child(i) == "subscript"
        ]
        vv = self.ev(value, st, depth)
        if len(subs) != 1:
            for s in subs:
                self.ev(s, st, depth)
            return summary(vv)
        idx_node = subs[0]
        if idx_node.type == "slice":
            slots: list[Any] = [None, None, None]
            known = True
            i = 0
            for ch in idx_node.children:
                if ch.type == ":":
                    i += 1
                elif ch.is_named and i < 3:
                    c = self.ev(ch, st, depth).const
                    if c is None or (isinstance(c, int) and not isinstance(c, bool)):
                        slots[i] = c
                    else:
                        known = False
            if known and isinstance(vv.const, (str, bytes)):
                return Val(lit=vv.lit, const=vv.const[slice(*slots)])
            if known and vv.seq is not None:
                return self._seq_val(list(vv.seq[slice(*slots)]))
            return summary(vv)
        iv = self.ev(idx_node, st, depth)
        if vv.seq is not None and isinstance(iv.const, int) and not isinstance(iv.const, bool):
            if -len(vv.seq) <= iv.const < len(vv.seq):
                return vv.seq[iv.const]
            return summary(vv)
        if vv.elems is not None and self._hashable_const(iv):
            for k, v in vv.elems:
                if _same_const(k, iv.const):
                    return v
            return UNKNOWN
        if (
            isinstance(vv.const, (str, bytes))
            and isinstance(iv.const, int)
            and not isinstance(iv.const, bool)
        ):
            try:
                return Val(lit=True, const=vv.const[iv.const])
            except IndexError:
                return summary(vv)
        return summary(vv)

    def _ev_sequence(self, node, st: State, depth: int) -> Val:
        elts: list[Val] = []
        splat = False
        for c in node.named_children:
            if c.type == "comment":
                continue
            if c.type in ("list_splat", "dictionary_splat", "parenthesized_list_splat"):
                splat = True
            elts.append(self.ev(c, st, depth))
        if splat or len(elts) > MAX_ITEMS:
            return combine(elts)
        return self._seq_val(elts)

    def _ev_set(self, node, st: State, depth: int) -> Val:
        return combine(self.ev(c, st, depth) for c in node.named_children if c.type != "comment")

    def _ev_dict(self, node, st: State, depth: int) -> Val:
        items: dict[Any, Val] = {}
        others: list[Val] = []
        ok = True
        for c in node.named_children:
            if c.type == "pair":
                k = self.ev(c.child_by_field_name("key"), st, depth)
                v = self.ev(c.child_by_field_name("value"), st, depth)
                if self._hashable_const(k):
                    items[k.const] = v
                else:
                    ok = False
                    others.extend([k, v])
            elif c.type != "comment":
                ok = False
                others.append(self.ev(c, st, depth))
        if ok and len(items) <= MAX_ITEMS:
            return self._dict_val(items)
        return combine([*items.values(), *others])

    def _ev_comprehension(self, node, st: State, depth: int) -> Val:
        inner = st.copy()
        iters: list[Val] = []
        for c in node.named_children:
            if c.type == "for_in_clause":
                it = self.ev(c.child_by_field_name("right"), inner, depth)
                iters.append(it)
                left = c.child_by_field_name("left")
                if left is not None:
                    self._assign(left, elem_of(it), inner)
            elif c.type == "if_clause":
                for sub in c.named_children:
                    self.ev(sub, inner, depth)
        body = node.child_by_field_name("body")
        bv = self.ev(body, inner, depth) if body is not None else UNKNOWN
        return derived(bv)

    def _ev_pair(self, node, st: State, depth: int) -> Val:
        return combine(
            [
                self.ev(node.child_by_field_name("key"), st, depth),
                self.ev(node.child_by_field_name("value"), st, depth),
            ]
        )

    def _ev_walrus(self, node, st: State, depth: int) -> Val:
        v = self.ev(node.child_by_field_name("value"), st, depth)
        name = node.child_by_field_name("name")
        if name is not None:
            self._assign(name, v, st)
        return v

    def _ev_keyword(self, node, st: State, depth: int) -> Val:
        return self.ev(node.child_by_field_name("value"), st, depth)

    def _ev_splat(self, node, st: State, depth: int) -> Val:
        named = node.named_children
        return summary(self.ev(named[0], st, depth)) if named else UNKNOWN

    # --- calls --------------------------------------------------------------
    def _ev_call(self, node, st: State, depth: int) -> Val:
        fn = node.child_by_field_name("function")
        argn = node.child_by_field_name("arguments")
        if fn is None:
            return UNKNOWN
        fn_text = self._compact(fn)
        last = fn_text.rsplit(".", 1)[-1]
        recv: Val | None = None
        recv_node = None
        if fn.type == "attribute":
            recv_node = fn.child_by_field_name("object")
            recv = self.ev(recv_node, st, depth)
        elif fn.type != "identifier":
            self.ev(fn, st, depth)
        pos: list[Val] = []
        pos_nodes: list[Any] = []
        kw: dict[str, Val] = {}
        kw_nodes: dict[str, Any] = {}
        extra: list[Val] = []
        if argn is not None:
            if argn.type == "generator_expression":
                pos.append(self.ev(argn, st, depth))
                pos_nodes.append(argn)
            else:
                for a in argn.named_children:
                    if a.type == "keyword_argument":
                        name = a.child_by_field_name("name")
                        value = a.child_by_field_name("value")
                        key = self.text(name) if name is not None else ""
                        kw[key] = self.ev(value, st, depth)
                        kw_nodes[key] = value
                    elif a.type in ("list_splat", "dictionary_splat"):
                        extra.append(self.ev(a, st, depth))
                    elif a.type != "comment":
                        pos.append(self.ev(a, st, depth))
                        pos_nodes.append(a)
        call = _Call(node, fn_text, last, recv, recv_node, pos, pos_nodes, kw, kw_nodes, extra)
        self._check_sinks(call, st)
        result = self._call_result(call, st)
        self._call_effects(call, st)
        return result

    def _is_weak_random(self, c: _Call) -> bool:
        if c.fn.startswith("random.") and c.fn.count(".") == 1 and c.last in WEAK_RANDOM_FUNCS:
            return True
        if c.recv_node is None and c.fn in self._random_names:
            return True
        return c.recv is not None and "weakrng" in c.recv.flags and c.last in WEAK_RANDOM_FUNCS

    def _specific_clean(self, c: _Call) -> frozenset[str]:
        out: set[str] = set()
        low = c.last.lower()
        if "escape" in low or (c.last in _XSS_SANITIZER_NAMES and c.fn.startswith("bleach.")):
            out |= _XSS_CLEAN
        if c.last in ("quoteattr", "strip_tags", "sanitize_html"):
            out |= _XSS_CLEAN
        if c.last in ("format_html", "format_html_join"):
            out |= _XSS_CLEAN  # Django: escapes every argument it formats in
        if c.last in _SQL_ESCAPES:
            out.add(CWE_SQL)
        if c.last in _LDAP_ESCAPES:
            out.add(CWE_LDAP)
        if self._ctx is not None:
            out |= {cwe for cwe in self._cwes if self._ctx.clears(c.fn, frozenset({cwe}))}
        return frozenset(out)

    def _call_result(self, c: _Call, st: State) -> Val:
        args = c.every_arg()
        static_recv = (
            c.recv_node is not None
            and self._compact(c.recv_node) in _REQUEST_PATH
            and bool(self._fn_stack)
            and self._fn_stack[-1].static_path
        )
        # Only a plain dotted target (``request.args.get``) is matched as text; a
        # receiver that is itself an expression was evaluated on its own above.
        dotted = c.recv_node is None or self._path(c.recv_node) is not None
        if dotted and (c.fn == "input" or self._is_source(c.fn)) and not static_recv:
            return self._source_val(c.fn)
        if c.recv is not None and c.last in self.source_methods and "reqobj" in c.recv.flags:
            return TAINT
        if c.last in self.source_functions and (
            c.recv_node is None or (self._path(c.recv_node) or "") not in st.vars
        ):
            return self._helper_source_taint(c.last)
        if self._is_weak_random(c):
            return Val(weak=True)
        if c.fn.endswith("random.Random") or (
            c.recv_node is None and c.fn == "Random" and "Random" in self._random_names
        ):
            return Val(flags=frozenset({"weakrng"}))
        if c.last in UNIVERSAL_SANITIZERS or (
            self._ctx is not None and self._ctx.clears(c.fn, None)
        ):
            numeric = c.last in NUMERIC_SANITIZERS
            return Val(lit=numeric or all(a.lit for a in args), weak=any(a.weak for a in args))
        recv = c.recv
        if recv is not None and "httpreq" in recv.flags and c.last in REQUEST_ATTRS:
            return TAINT  # await request.json(), request.form(), request.body()
        if recv is not None and recv.flags & {"zip", "tar"}:
            if c.last in ("namelist", "getnames"):
                return ARCHIVE_TAINT
            if c.last in ("infolist", "getmembers"):
                return Val(flags=frozenset({"archlist"}))
            if c.last in ("getinfo", "getmember", "next"):
                return Val(flags=frozenset({"archmember"}))
        if c.fn == "compile" and c.recv_node is None:
            # compile(source, filename, mode): only the source becomes code.
            src = c.arg(0, "source")
            return summary(src) if src is not None else UNKNOWN
        if c.fn in TAR_CTORS:
            # An archive object; it carries the taint of where it was read from.
            return replace(summary(combine(args)), flags=frozenset({"tar"}))
        helper = (
            self._helper_ref(c.node.child_by_field_name("function"), st)
            if any(a.taint for a in args)
            else None
        )
        if helper is not None:
            summ = self._return_summary(helper)
            if summ is not None:
                if not summ.taint:
                    return Val(lit=summ.lit, flags=summ.flags)
                base = combine([a for a in args if a.taint])
                out = Val(
                    taint=True,
                    clean=base.clean | summ.clean,
                    src=base.src,
                    embed=base.embed or summ.embed,
                    part=base.part or summ.part,
                    param=base.param,
                    flags=summ.flags,
                    trail=base.trail or _OPAQUE_TRAIL,
                )
                if self._trails:
                    note = f"returned by {helper.label[:40]}()"
                    if helper.where is not None:
                        note += f", defined in {helper.where}"
                    out = self._hop(out, c.node, "step", note)
                return out
        if self._is_record_lookup(c):
            # A row looked up by a key from the request holds stored data, not
            # the key's text.
            return UNKNOWN
        if not args and c.last in _DICT_CTORS:
            return Val(lit=True, elems=())
        if not args and c.last in _LIST_CTORS:
            return Val(lit=True, seq=())
        if self._result_is_not_input(c):
            # A cursor, a process, a file handle or query results: what the
            # sink produced, not the attacker's text.
            return UNKNOWN
        if c.last in REDIRECT_FNS:
            v = combine(args)
            return replace(v, clean=v.clean | _XSS_CLEAN) if v.taint else v
        # Container reads.
        if recv is not None and c.last in ("get", "pop") and c.pos:
            if recv.elems is not None:
                keys = [c.pos[0]] if c.last == "pop" or len(c.pos) == 1 else c.pos[:2]
                found = self._lookup(recv, keys)
                if found is not None:
                    return found
                default = c.pos[1] if len(c.pos) > 1 and len(keys) == 1 else c.kw.get("fallback")
                return summary(default) if default is not None else UNKNOWN
            if recv.seq is not None and c.last == "pop":
                idx = c.pos[0].const
                if (
                    isinstance(idx, int)
                    and not isinstance(idx, bool)
                    and -len(recv.seq) <= idx < len(recv.seq)
                ):
                    return recv.seq[idx]
        if recv is not None and c.last == "pop" and not c.pos and recv.seq:
            return recv.seq[-1]
        if recv is not None and c.last == "copy" and not args:
            return recv
        if recv is not None and c.last in ("values", "items") and recv.elems is not None:
            return summary(recv)
        if recv is not None and c.last == "keys" and recv.elems is not None:
            return Val(lit=True)
        extra_clean = self._specific_clean(c)
        # Flask's render_template(_string), Starlette's Jinja2Templates and
        # Django's TemplateResponse / render render with autoescaping on (the
        # template source of render_template_string is a template-injection sink).
        if c.last in _AUTOESCAPED_RENDERERS or (c.last == "render" and c.fn == "render"):
            v = combine(args)
            return replace(v, clean=v.clean | _XSS_CLEAN) if v.taint else v
        if c.last in ("make_response", "Response") and c.pos:
            body = c.pos[0]
            if body.seq:
                body = body.seq[0]
            return summary(body)
        flags: set[str] = set()
        if c.last in PATH_CTORS:
            flags.add("path")
        if (
            recv is not None
            and "path" in recv.flags
            and c.last
            in (
                "resolve",
                "absolute",
                "joinpath",
                "with_name",
                "with_suffix",
                "expanduser",
            )
        ):
            flags.add("path")
            if c.last in ("resolve", "absolute"):
                flags.add("normalized")
        if c.fn in NORMALIZERS:
            flags.add("normalized")
        if c.last in _URL_PARSERS and c.pos_nodes:
            p = self._path(c.pos_nodes[0])
            if p is not None:
                flags.add("urlof:" + p)
        if c.fn in HTTP_CLIENT_CTORS:
            flags.add("http")
        if c.fn in ZIP_CTORS:
            flags.add("zip")
        if c.last in JINJA_SANDBOXES:
            flags.add("jinja-sandbox")
        elif c.last in JINJA_ENVS and (
            c.fn.startswith("jinja2.") or (c.recv_node is None and self._jinja_env)
        ):
            flags.add("jinja")
        if any(n.type == "identifier" and self.text(n) == "request" for n in c.pos_nodes) or any(
            n is not None and n.type == "identifier" and self.text(n) == "request"
            for n in c.kw_nodes.values()
        ):
            flags.add("reqobj")
        if c.last == "XMLParser" and (
            self._kw_text(c, "resolve_entities") == "True"
            or self._kw_text(c, "no_network") == "False"
        ):
            flags.add("xxe")
        parts = ([recv] if recv is not None else []) + args
        v = combine(parts)
        pure = (c.recv_node is None and c.last in PURE_FUNCTIONS) or (
            c.recv_node is not None and (c.last in PURE_METHODS or c.last in PURE_FUNCTIONS)
        )
        # ``base64.b64decode(x)``: a module (an untracked dotted name) is a
        # namespace, not a value, so it does not make the result non-literal.
        recv_path = self._path(c.recv_node) if c.recv_node is not None else None
        namespace = (
            recv is not None
            and not recv.taint
            and recv_path is not None
            and recv_path.split(".", 1)[0] not in st.vars
        )
        recv_lit = recv is None or recv.lit or (namespace and c.last in PURE_FUNCTIONS)
        lit = pure and recv_lit and all(a.lit for a in args)
        if c.last == "format" and recv is not None and not v.lit:
            flags.add("dyn")
        if c.last in ("format", "join") and recv is not None and "html" in recv.flags:
            flags.add("html")
        const: Any = NOCONST
        if (
            c.fn == "str"
            and len(c.pos) == 1
            and isinstance(c.pos[0].const, (str, int, float, bool))
        ):
            const = str(c.pos[0].const)
        clean = v.clean | extra_clean if v.taint else frozenset()
        embed = v.embed
        if v.taint and not embed:
            # The tainted value is placed after content the program chose.
            if c.fn in _PATH_JOINS or (c.last in PATH_CTORS and len(c.pos) + len(c.extra) > 1):
                embed = _ordered_embed([*c.pos, *c.extra])
            elif c.last in ("joinpath", "format") and recv is not None:
                embed = _ordered_embed([recv, *args])
            elif c.last == "join" and recv is not None and len(c.pos) == 1:
                items = c.pos[0]
                embed = _ordered_embed(list(items.seq)) if items.seq is not None else items.embed
        part = v.part or (
            v.taint
            and (
                (recv is not None and recv.api_only and c.last in _ITEM_GETTERS)
                or (c.fn == "getattr" and bool(c.pos) and c.pos[0].api_only)
            )
        )
        return Val(
            taint=v.taint,
            clean=clean,
            lit=lit,
            weak=v.weak,
            param=v.param,
            flags=frozenset(flags),
            const=const,
            src=v.src,
            embed=embed,
            part=part,
            trail=v.trail,
        )

    def _helper_source_taint(self, name: str) -> Val:
        """Taint returned by a same-file function that reads a source.

        Operator-controlled (ORIGIN_OPERATOR) when its body reads only
        ``sys.argv``, ``os.environ`` or ``input()``; request taint otherwise,
        including for helpers defined in another file.
        """
        node = self._shared.functions.get(name) if self._shared is not None else None
        if node is not None:
            text = self._src[node.start_byte : node.end_byte].decode("utf-8", "ignore")
            if OPERATOR_SOURCE_RE.search(text) and not REQUEST_SOURCE_RE.search(text):
                return OPERATOR_TAINT
        return TAINT

    def _is_record_lookup(self, c: _Call) -> bool:
        """A database lookup by key: Django managers, (Flask-)SQLAlchemy queries,
        ``get_object_or_404`` and repository methods named ``get_..._by_id``.

        Taint is not carried from the key to the record: the record's fields are
        what the application stored. (Stored data that users wrote can still be
        dangerous; this engine does not model stored, second-order flows.)
        """
        if c.recv is not None and c.recv.taint:
            return False
        if c.last in _RECORD_GETTERS or _RECORD_LOOKUP_NAME.match(c.last):
            return True
        if c.recv_node is None or c.last not in _ORM_QUERY_METHODS:
            return False
        chain = self._compact(c.recv_node)
        if ".objects" in chain or re.search(r"\.query(?:\(|\.|$)", chain):
            return True  # Model.objects.get(...), Model.query.get(...), session.query(M).get(...)
        # SQLAlchemy Session.get(Model, key)
        return (
            c.last == "get"
            and len(c.pos) >= 2
            and re.search(r"(?:^|\.)session$", chain) is not None
        )

    def _result_is_not_input(self, c: _Call) -> bool:
        if SQL_FN.search(c.fn) or CMD_FN.search(c.fn) or PATH_FN.search(c.fn):
            return True
        if c.recv is not None and "path" in c.recv.flags and c.last in PATH_METHODS:
            return c.last not in ("resolve", "absolute")
        if self._ldap and c.last in LDAP_SEARCH:
            return True
        return c.last in ("xpath", "XPath") or c.fn in (
            "elementpath.select",
            "elementpath.iter_select",
        )

    def _kw_text(self, c: _Call, name: str) -> str | None:
        node = c.kw_nodes.get(name)
        return self.text(node) if node is not None else None

    @staticmethod
    def _lookup(recv: Val, keys: list[Val]) -> Val | None:
        assert recv.elems is not None
        consts = [k.const for k in keys]
        if any(k is NOCONST for k in consts):
            return None
        wanted: list[Any] = []
        if len(consts) == 2:
            wanted.append(tuple(consts))
        wanted.append(consts[0])
        for w in wanted:
            for k, v in recv.elems:
                if _same_const(k, w):
                    return v
        return None

    def _call_effects(self, c: _Call, st: State) -> None:
        if c.recv_node is None:
            return
        path = self._path(c.recv_node)
        if path is None:
            return
        last = c.last
        if last == "setFeature" and len(c.pos_nodes) >= 2:
            feature = self.text(c.pos_nodes[0])
            enabled = self.text(c.pos_nodes[1]) in ("True", "1")
            if enabled and _EXTERNAL_ENTITY_FEATURE.search(feature):
                cur = st.get(path)
                st.vars[path] = replace(cur, flags=cur.flags | {"xxe"})
            return
        if last not in _MUTATORS:
            return
        known = st.vars.get(path)
        if known is None and not any(a.taint or a.weak for a in c.every_arg()):
            return  # e.g. a module-level list we know nothing about
        st.vars[path] = self._mutate(known if known is not None else UNKNOWN, c)

    def _mutate(self, cur: Val, c: _Call) -> Val:
        last, pos = c.last, c.pos
        if cur.seq is not None:
            seq = list(cur.seq)
            if last == "append" and len(pos) == 1:
                return self._seq_val([*seq, pos[0]], cur.flags)
            if last == "insert" and len(pos) == 2 and isinstance(pos[0].const, int):
                seq.insert(pos[0].const, pos[1])
                return self._seq_val(seq, cur.flags)
            if last == "extend" and len(pos) == 1 and pos[0].seq is not None:
                return self._seq_val([*seq, *pos[0].seq], cur.flags)
            if last == "pop":
                idx = pos[0].const if pos else -1
                if (
                    isinstance(idx, int)
                    and not isinstance(idx, bool)
                    and -len(seq) <= idx < len(seq)
                ):
                    del seq[idx]
                    return self._seq_val(seq, cur.flags)
            if last == "clear":
                return self._seq_val([], cur.flags)
        if cur.elems is not None:
            items = dict(cur.elems)
            if last == "set" and len(pos) in (2, 3):
                keys = pos[:-1]
                if all(self._hashable_const(k) for k in keys):
                    key = keys[0].const if len(keys) == 1 else (keys[0].const, keys[1].const)
                    items[key] = pos[-1]
                    return self._dict_val(items, cur.flags)
            if last == "pop" and pos and self._hashable_const(pos[0]):
                items.pop(pos[0].const, None)
                return self._dict_val(items, cur.flags)
            if last == "setdefault" and pos and self._hashable_const(pos[0]):
                if pos[0].const not in items:
                    items[pos[0].const] = pos[1] if len(pos) > 1 else Val(lit=True, const=None)
                return self._dict_val(items, cur.flags)
            if last == "update" and len(pos) == 1 and pos[0].elems is not None and not c.kw:
                items.update(dict(pos[0].elems))
                return self._dict_val(items, cur.flags)
            if last == "clear":
                return self._dict_val({}, cur.flags)
        if last in ("pop", "popleft", "remove", "discard", "sort", "reverse", "clear"):
            return replace(summary(cur), flags=cur.flags)
        merged = combine([summary(cur), *(summary(a) for a in c.every_arg())])
        return replace(merged, flags=cur.flags)

    # --- sinks --------------------------------------------------------------
    def _check_sinks(self, c: _Call, st: State | None = None) -> None:
        fn, last = c.fn, c.last
        if SQL_FN.search(fn):
            q = c.arg(0, "sql", "query", "operation", "statement")
            if (
                q is not None
                and not self._report("ast-sql-injection", c.node, [q])
                and q.param
                and not q.lit
                and "dyn" in q.flags
            ):
                self._emit("ast-sql-string-building", c.node)
        if CMD_FN.search(fn):
            self._check_command(c, st)
            # The regex tier's shell=True / os.system grading.
            shell_kw = self._kw_text(c, "shell") not in (None, "False")
            if fn in ("os.system", "os.popen") or (SHELL_CMD_FN.search(fn) and shell_kw):
                first = c.arg(0, "args", "cmd", "command")
                self._verdict("shell", c.node, first if first is not None else None)
        if PATH_FN.search(fn):
            if TWO_PATH_FN.search(fn):
                vals = c.pos[:2]
            elif last == "send_from_directory":
                # Flask joins the file name onto the directory with
                # werkzeug.security.safe_join, which refuses to leave it; only
                # a directory taken from input is a traversal risk here.
                vals = c.pos[:1] + [c.kw[k] for k in ("directory",) if k in c.kw]
            else:
                vals = c.pos[:1]
            if last != "send_from_directory":
                vals = vals + [
                    c.kw[k]
                    for k in ("file", "filename", "path", "path_or_file", "name", "src", "dst")
                    if k in c.kw
                ]
            self._report("ast-path-traversal", c.node, vals)
        if c.recv is not None and (
            ("path" in c.recv.flags and last in PATH_METHODS) or last in PATHLIB_IO
        ):
            self._report("ast-path-traversal", c.node, [c.recv])
        self._check_archive(c)
        if CODE_FN.search(fn):
            self._report("ast-code-injection", c.node, [c.arg(0, "source", "object")])
        self._check_template(c)
        if DESER_FN.search(fn) or (YAML_LOAD_FN.search(fn) and self._yaml_unsafe(c)):
            v = c.arg(0, "data", "stream", "file", "s")
            self._verdict("deser", c.node, v)
            self._report("ast-unsafe-deserialization", c.node, [v])
        self._check_ldap(c)
        self._check_xpath(c)
        self._check_ssrf(c)
        if last in XML_PARSE and c.pos:
            data = c.pos[0]
            others = c.pos[1:] + list(c.kw.values())
            enabled = any("xxe" in o.flags for o in others) or (
                c.recv is not None and "xxe" in c.recv.flags
            )
            if enabled:
                self._report("ast-xxe", c.node, [data])
        if last in REDIRECT_FNS:
            self._report(
                "ast-open-redirect", c.node, [c.arg(0, "location", "url", "redirect_to", "to")]
            )
        if last in MARKUP_FNS and c.pos:
            self._report("ast-xss", c.node, [c.pos[0]])
        if last in DJANGO_RESPONSES and c.pos:
            ctype = self._kw_text(c, "content_type")
            if ctype is None or "html" in ctype:
                self._report("ast-xss", c.node, [c.pos[0]])
        if last == "HTMLResponse":  # Starlette / FastAPI
            self._report("ast-xss", c.node, [c.arg(0, "content")])
        jinja_ctor = last in JINJA_ENVS | JINJA_SANDBOXES or (
            last == "Template" and self._is_jinja_template(c)
        )
        if jinja_ctor and self._kw_text(c, "autoescape") == "False":
            self._emit("ast-jinja-autoescape-off", c.node)
        if (
            last in ("update", "setdefault")
            and c.recv_node is not None
            and SESSION_RE.search(self._compact(c.recv_node))
        ):
            self._report("ast-trust-boundary", c.node, c.every_arg())
        if any(v.weak for v in c.every_arg()) and (
            last == "set_cookie"
            or SENSITIVE_RE.search(last)
            or any(SENSITIVE_RE.search(k) and v.weak for k, v in c.kw.items())
        ):
            self._emit("ast-weak-random", c.node)

    def _check_command(self, c: _Call, st: State | None) -> None:
        """OS command injection, told apart by whether a shell parses the command.

        With a shell (``shell=True``, ``os.system``, ``os.popen``,
        ``subprocess.getoutput``) any tainted part of the command string can
        add commands. Without one (an argv list, ``os.exec*``, ``os.spawn*``,
        ``pty.spawn``) there are no metacharacters to inject: a tainted value
        matters only as the program to run (argv[0]) or as the code an
        interpreter or shell runs (the value after ``-c``, ``-e``, ``/c``,
        ``-Command``...). Other argv elements are arguments to a program the
        code chose and are not reported (option injection, CWE-88, is out of
        scope). An argv list whose elements cannot be told apart is reported
        as before, as a possible program choice.
        """
        fn = c.fn
        if fn.startswith(("os.exec", "os.spawn")):
            # os.execv(path, args) / os.execl(path, arg0, ...): the first is the program.
            self._report("ast-command-injection", c.node, c.pos[:1] + c.extra, "argv")
            return
        first = c.arg(0, "args", "cmd", "command")
        shell = fn in _SHELL_FUNCTIONS or self._kw_text(c, "shell") not in (None, "False")
        if shell:
            self._report("ast-command-injection", c.node, [first, *c.extra])
            return
        if first is None:
            self._report("ast-command-injection", c.node, c.extra, "argv")
            return
        elements = self._argv_elements(c, st, first)
        if elements is None:  # a string (the program itself) or an unknown list
            self._report("ast-command-injection", c.node, [first, *c.extra], "argv")
            return
        risky: list[Val] = []
        previous: Any = None
        for i, v in enumerate(elements):
            if i == 0 or (isinstance(previous, str) and previous in _CODE_OPTIONS):
                risky.append(v)
            previous = v.const
        self._report("ast-command-injection", c.node, risky + c.extra, "argv")

    def _argv_elements(self, c: _Call, st: State | None, first: Val) -> list[Val] | None:
        """The elements of an argv list argument, in order, or None when unknown.

        A list or tuple literal is read element by element (a ``*splat`` keeps
        its place as one tainted element); a variable is read from its tracked
        sequence.
        """
        node = c.pos_nodes[0] if c.pos_nodes else c.kw_nodes.get("args")
        if node is not None and node.type in ("list", "tuple") and st is not None:
            out: list[Val] = []
            for ch in node.named_children:
                if ch.type == "comment":
                    continue
                inner = (
                    ch.named_children[0] if ch.type == "list_splat" and ch.named_children else ch
                )
                out.append(self._ev_quiet(inner, st))
            return out
        if first.seq is not None:
            return list(first.seq)
        return None

    def _check_ssrf(self, c: _Call) -> None:
        """An outbound HTTP request to a URL taken from input."""
        url: Val | None = None
        local = c.recv_node is None and self._shared is not None and c.fn in self._shared.functions
        if HTTP_FN.search(c.fn) and not local:
            method_first = c.last == "request" or c.fn in ("urllib3.request", "aiohttp.request")
            url = c.arg(1, "url") if method_first else c.arg(0, "url", "fullurl")
        elif c.recv is not None and "http" in c.recv.flags and c.last in HTTP_CLIENT_METHODS:
            if c.last in _HTTP_METHOD_FIRST:
                url = c.arg(1, "url")
            else:
                url = c.arg(0, "url", "fullurl", "str_or_url")
        if url is not None:
            self._report("ast-ssrf", c.node, [url])

    def _check_archive(self, c: _Call) -> None:
        """A tar archive extracted without a member filter (CWE-22 "tar slip").

        ``TarFile.extractall()`` / ``extract()`` before Python 3.14 writes members
        wherever their names point (``../``, absolute paths, links) unless a
        ``filter=`` other than ``fully_trusted`` (``"data"``, ``"tar"``,
        ``tarfile.data_filter`` or the caller's own filter) or an explicit
        ``members=`` selection is passed. ``shutil.unpack_archive`` takes the same
        ``filter=``. Reported when the archive comes from input.
        """
        flt = self._kw_text(c, "filter")
        if flt is not None and flt not in _UNSAFE_TAR_FILTERS:
            return
        if c.recv is not None and "tar" in c.recv.flags and c.last in ("extractall", "extract"):
            if c.last == "extractall" and ("members" in c.kw or len(c.pos) > 1):
                return
            self._report("ast-archive-extraction", c.node, [c.recv])
        elif c.fn == "shutil.unpack_archive":
            self._report("ast-archive-extraction", c.node, [c.arg(0, "filename")])

    def _is_jinja_template(self, c: _Call) -> bool:
        if c.fn in ("jinja2.Template", "mako.template.Template", "jinja2.environment.Template"):
            return True
        return c.recv_node is None and c.fn == "Template" and self._jinja_template

    def _check_template(self, c: _Call) -> None:
        """A template whose source text comes from input (server-side template injection).

        Rendering attacker-written Jinja2 or Mako source runs expressions with
        access to Python objects, which leads to code execution. Jinja2's
        ``SandboxedEnvironment`` / ``ImmutableSandboxedEnvironment`` restrict
        that, so their ``from_string()`` is not reported.
        """
        src: Val | None = None
        if c.last == "render_template_string":
            src = c.arg(0, "source")
        elif c.last == "Template" and self._is_jinja_template(c):
            src = c.arg(0, "source", "text")
        elif c.last == "from_string" and c.recv is not None and "jinja" in c.recv.flags:
            src = c.arg(0, "source")
        if src is not None:
            self._report("ast-template-injection", c.node, [src])

    def _check_xpath(self, c: _Call) -> None:
        last, fn = c.last, c.fn
        v: Val | None = None
        if last in ("xpath", "XPath") or fn.endswith("etree.XPath"):
            v = c.arg(0, "_path", "path")
        elif fn in ("elementpath.select", "elementpath.iter_select"):
            v = c.arg(1, "path")
        elif fn == "elementpath.Selector" or (
            self._xml
            and last in ("find", "findall", "iterfind", "findtext")
            and c.recv_node is not None
            and self.text(c.recv_node) not in ("re", "regex")
        ):
            v = c.arg(0, "path")
        self._report("ast-xpath-injection", c.node, [v])

    def _check_ldap(self, c: _Call) -> None:
        """ldap3 ``conn.search(base, filter)`` / python-ldap ``search_s(base, scope, filter)``."""
        if not self._ldap or c.last not in LDAP_SEARCH or c.recv_node is None:
            return
        if self.text(c.recv_node) in ("re", "regex"):
            return
        if c.last == "search":
            vals = c.pos[:2] + [c.kw[k] for k in ("search_base", "search_filter") if k in c.kw]
        else:
            vals = [c.pos[i] for i in (0, 2) if i < len(c.pos)]
            vals += [c.kw[k] for k in ("base", "filterstr") if k in c.kw]
        self._report("ast-ldap-injection", c.node, vals)

    def _yaml_unsafe(self, c: _Call) -> bool:
        loader = self._kw_text(c, "Loader")
        if loader is None and len(c.pos_nodes) > 1:
            loader = self.text(c.pos_nodes[1])
        if loader is None:
            return True  # PyYAML < 6 defaults to an unsafe loader; 6+ raises
        return not re.search(r"Safe|BaseLoader", loader)

    # --- conservative fallback ----------------------------------------------
    def _flat(self, node, st: State) -> Val:
        """Taint of ``node`` from a flat scan, also checking simple sinks inside.

        Used past the nesting limits instead of recursing: any source or tainted
        variable anywhere in the subtree taints the whole of it.
        """
        taint = self._is_source(self.text(node))
        api = False
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "identifier":
                v = st.vars.get(self.text(n))
                if v is not None and v.taint:
                    if v.api_only:
                        api = True
                    else:
                        taint = True
            elif n.type == "call":
                self._flat_call(n, st)
            stack.extend(n.children)
        if not taint and api:
            return Val(taint=True, src=frozenset({ORIGIN_API}), trail=_OPAQUE_TRAIL)
        return Val(taint=taint, trail=_OPAQUE_TRAIL if taint else ())

    def _flat_call(self, node, st: State) -> None:
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            return
        fn_text = self._compact(fn)
        if SQL_FN.search(fn_text):
            sink = "ast-sql-injection"
        elif CMD_FN.search(fn_text):
            sink = "ast-command-injection"
        elif PATH_FN.search(fn_text):
            sink = "ast-path-traversal"
        elif CODE_FN.search(fn_text):
            sink = "ast-code-injection"
        elif DESER_FN.search(fn_text):
            sink = "ast-unsafe-deserialization"
        else:
            return
        named = [a for a in args.named_children if a.type != "comment"]
        if sink == "ast-sql-injection":
            named = named[:1]
        for a in named:
            if self._is_source(self.text(a)) or self._flat_ident_taint(a, st):
                self._emit(sink, node)
                return

    def _flat_ident_taint(self, node, st: State) -> bool:
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "identifier":
                v = st.vars.get(self.text(n))
                if v is not None and v.taint and not v.api_only:
                    return True
            stack.extend(n.children)
        return False


#: Every CWE a value can be cleared for.
ALL_CWES: frozenset[str] = TAINT_CWES | frozenset(c for cwes in SINK_CWES.values() for c in cwes)


def _cleared(v: Val) -> frozenset[str]:
    """CWEs ``v`` is safe for: all of them when it no longer carries taint."""
    return v.clean if v.taint else ALL_CWES


def _walk_body(fn_node) -> Iterable[Any]:
    """Nodes of a function's body, not descending into nested functions or lambdas."""
    body = fn_node.child_by_field_name("body")
    stack = [body] if body is not None else []
    while stack:
        n = stack.pop()
        yield n
        for ch in n.children:
            if ch.type not in ("function_definition", "lambda", "class_definition"):
                stack.append(ch)


def _is_generator(fn_node) -> bool:
    return any(n.type == "yield" for n in _walk_body(fn_node))


def _has_rejection(fn_node) -> bool:
    """Whether a function can reject its input: it raises or returns a boolean."""
    for n in _walk_body(fn_node):
        if n.type == "raise_statement":
            return True
        if n.type == "return_statement":
            named = [c for c in n.named_children if c.type != "comment"]
            if len(named) == 1 and named[0].type in ("true", "false"):
                return True
    return False


def iter_functions(root) -> Iterable[tuple[Any, bool]]:
    """Every function definition under ``root`` with whether it is a method."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            parent = node.parent
            if parent is not None and parent.type == "decorated_definition":
                parent = parent.parent
            is_method = (
                parent is not None
                and parent.type == "block"
                and parent.parent is not None
                and parent.parent.type == "class_definition"
            )
            yield node, is_method
        stack.extend(reversed(node.children))


def source_callables(
    src: bytes, root, context: LanguageContext | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Methods and functions in ``root`` that return untrusted input.

    Returns ``(methods, functions)``, each mapping a name to its definition
    node. A method qualifies when one of its ``return`` values is tainted with
    nothing seeded (for example ``return self.request.form.get(name)``): calls
    to it on an object built from the request then count as sources.
    """
    methods: dict[str, Any] = {}
    functions: dict[str, Any] = {}
    flow = Flow(src, None, context=context)
    for fn, is_method in iter_functions(root):
        name_node = fn.child_by_field_name("name")
        if name_node is None:
            continue
        name = flow.text(name_node)
        parent = fn.parent
        if parent is not None and parent.type == "decorated_definition":
            decorators = [flow.text(c) for c in parent.named_children if c.type == "decorator"]
            if any(ROUTE_DECORATOR.search(d) or METHOD_DECORATOR.search(d) for d in decorators):
                continue  # a view returns a response, it is not a helper
        if flow.function_returns_taint(fn):
            (methods if is_method else functions)[name] = fn
    return methods, functions
