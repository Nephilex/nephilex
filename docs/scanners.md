# Scanners & coverage

Nephilex runs a set of scanners over one project view in a single pass. They share a
severity model and a report, so you get one prioritized list, not six. Run
`nephilex scanners` to see which are active in your install.

Each scanner below lists what it detects, what it deliberately does not, and its
current limitations. Stating the limits is intentional: it is how you know where
to still apply human review.

## Secrets

**Detects.** Hardcoded credentials by signature (cloud keys, tokens, private
keys) and by entropy, with common false positives (placeholders, sample values)
filtered out. Optional live verification (`--verify-secrets`) checks whether a
found credential is still active, using read-only endpoints.

**Does not.** Scan git history by default (working tree only), and never stores or
prints a full secret: values are redacted to a short prefix plus length
everywhere.

**Git history (opt-in).** Pass `--secrets-history` to also scan every commit for
secrets that were committed and later deleted, the most dangerous case, since a
credential removed from the current files is still recoverable from history. Each
history finding says plainly: rotate it, deleting it from history is not enough.
Needs a local git repository with full history.

**Limits.** Entropy detection trades recall for low noise. The history scan reads
a bounded amount of diff text (and says so if it truncates on a very large repo).

## Dependencies (SCA)

**Detects.** Known-vulnerable dependencies using live [OSV](https://osv.dev)
data, including transitive packages resolved from lockfiles across PyPI, npm, Go,
Rust, Ruby, and PHP. With `--reachability` (experimental, off by default), a CVE
in a Python or npm package your code never imports is marked lower priority.

**Prioritizes with exploit signals.** Each CVE finding is enriched, best-effort,
with two free feeds: **EPSS** (FIRST.org, the probability the CVE is exploited in
the wild) and the **CISA KEV** catalog (confirmed exploited in the wild). KEV
membership raises a finding's likelihood so "reachable + KEV + high EPSS" sorts to
the top, without ever changing the severity your `--fail-on` gate depends on.
Disable with `exploit_signals: false` under the `dependencies` scanner options.

**Machine-readable exploitability (VEX).** Export an OpenVEX document with
`nephilex scan ... -f vex`. CVEs are `affected` with the fix. When the scan ran with
`--reachability`, a CVE in a package your code never imports is `not_affected`
with the standard `vulnerable_code_not_in_execute_path` justification; without it,
every CVE is `affected`. It pairs with an SBOM for the exposure story enterprises
increasingly request.

**Does not.** Prove exploitability. Reachability is an import-level heuristic, not
a call-graph proof, and EPSS is a probability, not a guarantee.

**Limits.** Coverage is bounded by OSV. Network access is required to refresh
advisories and exploit signals; results are cached on disk with a TTL and degrade
cleanly offline (a missing feed simply means no enrichment, never a failed scan).
Only package names, versions, and CVE ids ever leave your machine.

## SAST (pattern rules)

**Detects.** Dangerous code patterns across many languages: `shell=True`,
`os.system` on dynamic input, unsafe `yaml.load`, weak hashing (including
`hashlib.new("md5")`), insecure deserialization, `Markup()`/`mark_safe()` on a
formatted string, `|safe` and `{% autoescape false %}` in templates, lxml
`resolve_entities=True`, and more, each with a CWE mapping and a concrete fix.

**Graded by data flow (Python).** When the `ast` extra is installed, a few rules
ask the data-flow engine what the payload is before reporting:

| Rule | Payload built only from literals | Unknown origin | Request data |
| --- | --- | --- | --- |
| `python-shell-true`, `python-os-system` | not reported | reported (medium confidence) | reported; the taint tier adds a high-confidence finding |
| `python-pickle-loads` | not reported | reported (low confidence) | reported; the taint tier adds a high-confidence finding |
| `python-yaml-load` (unsafe loader) | reported, low severity and confidence | reported as before | reported, high confidence |

"Built only from literals" includes values that passed a numeric conversion
(`int()`), an allowlist check, or a module-level constant bound once. The
finding's `metadata.dataflow` records the verdict. An unsafe YAML loader is
always reported because it is wrong even when today's input is constant.

**Weak hashes.** `weak-hash-md5-sha1` is not reported when the call passes
`usedforsecurity=False` (Python 3.9+), even when the call spans several lines.
A hash that is evidently a checksum, ETag or cache key (the assigned variable
or the enclosing function is named `etag`, `checksum`, `fingerprint`,
`cache...`, `digest`, `content_hash` and the like) and that names no password,
secret, token, signature, salt, session or HMAC is reported at **low**
severity and confidence with `metadata.hash_purpose: checksum`: a collision
there lets two inputs share a key, it does not forge a credential. Everything
else, password hashing included, keeps medium severity and the KDF guidance
(bcrypt, scrypt or Argon2 for passwords, SHA-256 or better for integrity).

**Does not.** Follow data across functions and files on its own (that is the
taint tier below). Flag every dynamic call, on purpose, to stay low-noise.

**Limits.** Pattern rules are precise but shallow. Long lines are scanned in
bounded, overlapping windows so a regex never sees more than 2000 characters at
once. Findings carry 1-based `start_column`/`end_column` (end exclusive, SARIF
style) and the source line with its indentation as the snippet.

## Taint / data-flow (AST)

**Detects.** Untrusted input flowing into a dangerous sink across function and
file boundaries (injection, SSRF, path traversal, command execution), using
tree-sitter for Python and JavaScript/TypeScript.

**Does not.** Cover every language at this depth. Requires the `ast` extra
(`pip install "nephilex[ast]"`); without it, Nephilex falls back to the
lightweight-taint code scanner and says so.

**Python sinks and rule ids** (`ast-python.*`, and `ast-python-xfile.*` when the
source or the sink is in another file):

| Rule | CWE | Sink |
| --- | --- | --- |
| `ast-sql-injection` | 89 | `execute()`/`executemany()` query argument |
| `ast-sql-string-building` | 89 | query built with `%`, `+`, `.format()` or an f-string from a function parameter (low confidence, no traced source) |
| `ast-command-injection` | 78 | with a shell (`shell=True`, `os.system`, `os.popen`, `subprocess.getoutput`): any tainted part of the command. Without one (an argv list, `os.exec*`, `os.spawn*`, `pty.spawn`): only a tainted program (argv[0]) or the code after an interpreter option such as `-c`, `-e`, `/c`, `-Command` |
| `ast-path-traversal` | 22 | `open`, `io.open`, `codecs.open`, `aiofiles.open`, `os`/`shutil` file operations, `send_file`, Starlette/FastAPI `FileResponse`, the directory of `send_from_directory`, file methods on a `pathlib.Path` built from the value (`Path(x)`, `base / x`, `base / f"{x}.txt"`), and `read_text`/`write_text`/`read_bytes`/`write_bytes` on any tainted path |
| `ast-archive-extraction` | 22 | `TarFile.extractall()`/`extract()` and `shutil.unpack_archive()` on an archive from input, without `filter=` (or with `filter="fully_trusted"`) and without `members=` |
| `ast-code-injection` | 95 | `eval`, `exec`, `compile` (its source argument) |
| `ast-template-injection` | 1336, 94 | template source from input: Flask `render_template_string`, `jinja2.Template`, Mako `Template`, `Environment().from_string()` (a `SandboxedEnvironment` / `ImmutableSandboxedEnvironment` is not reported) |
| `ast-unsafe-deserialization` | 502 | `pickle`/`dill`/`marshal` loads, `yaml.load` without a safe loader, `yaml.unsafe_load` |
| `ast-xss` | 79 | value returned from a Flask/Bottle view (`@app.route`, or `@app.get` in a Flask file) or a FastAPI route declared with `response_class=HTMLResponse`, `Markup()`, `mark_safe()`, Django `HttpResponse`, Starlette `HTMLResponse` |
| `ast-jinja-autoescape-off` | 79 | a Jinja2 `Environment`/`SandboxedEnvironment`/`Template` created with `autoescape=False` (no source needed) |
| `ast-ssrf` | 918 | URL of `requests.*`, `httpx.*`, `urllib.request.urlopen`, `urllib3.request`, `aiohttp.request`, and the request methods of `requests.Session`, `httpx.Client`/`AsyncClient`, `aiohttp.ClientSession`, `urllib3.PoolManager` and `build_opener()` objects |
| `ast-open-redirect` | 601 | `redirect()`, `HttpResponseRedirect`, `RedirectResponse`, `headers["Location"] = ...` |
| `ast-xxe` | 611 | XML parse of the value with a parser that has external entities enabled (`setFeature(feature_external_ges, True)`, lxml `resolve_entities=True`) |
| `ast-ldap-injection` | 90 | ldap3 `search()` base/filter, python-ldap `search_s()` (only in files importing ldap/ldap3) |
| `ast-xpath-injection` | 643 | lxml `xpath()`/`XPath()`, `elementpath.select()`, ElementTree `find*()` in XML files |
| `ast-trust-boundary` | 501 | request data written into `session[...]` (key or value) |
| `ast-weak-random` | 330, 338 | a `random` module value (not `SystemRandom`) stored as a token, password, salt, nonce, session or cookie value, or returned from a function named like one |

**Sources.** Request data (`request.args`, `.form`, `.json`, `.files`,
`.headers`, `.cookies`, `.GET`, `.POST`, `.match_info` and the rest of the
Flask, Django, aiohttp and Starlette request attributes), and parameters the
web framework fills from the request: Flask route converters (`<name>`,
`<path:name>`; not `int`, `float`, `uuid` or `any`), FastAPI parameters with a
`Query()`, `Path()`, `Body()`, `Form()`, `File()`, `Header()` or `Cookie()`
default, every parameter of a FastAPI path operation (`@app.get(...)`) except
`Depends()` dependencies and numeric, boolean, UUID and date annotations,
`UploadFile` uploads (`f.filename`, `await f.read()`), and any parameter
annotated as the request object (`Request`, `HttpRequest`, `WebSocket`), whose
`query_params`, `headers`, `cookies`, `url`, `json()`, `form()` and `body()` are
sources. Member names read from a zip or tar archive (`namelist()`,
`getnames()`, `ZipInfo.filename`, `TarInfo.name`/`linkname`) are sources for
path traversal ("zip slip"), reported at medium confidence with the tag
`archive-entry`. `sys.argv`, `os.environ` and `input()` are controlled by
whoever runs the program: a finding whose only source is one of them (directly
or through a same-file helper that reads them) is reported at low confidence
with the tag `operator-input` (it matters when another program passes
untrusted data through the command line or the environment). For SSRF and
open redirect such a value is not reported at all: a server URL taken from
an environment variable or an option is the operator configuring the program.

**How values are tracked.** The engine is flow-sensitive within a function:
`if`/`elif`/`else`, `match`, loops and `try` are analyzed per branch and joined,
so `if not p: p = ""` keeps the taint of the other branch. Conditions that fold
to a constant (`if 7 * 18 + num > 200`, a `match` on a constant) prune the dead
branch. Literal dicts, lists (`append`, `pop`, indexing) and `configparser`
objects are tracked per key, so storing request data under one key does not
taint a read of another. A method returns request data when it reads the
request (`return self.request.form.get(name)`); calling it on an object built
from the request (`Wrapper(request).get_form_parameter("q")`) is a source, in
the same file (`ast-python`) or across files (`ast-python-xfile`). A nested
function (a callback, a generator) sees the variables of the function it is
defined in. A call to a helper defined once in the same file (`helper(x)`, or
`self.helper(x)` for a method) is analyzed through a summary of the helper's
body instead of assuming the result carries every argument's taint: what it
returns when its parameters are tainted (a sanitizing helper returns a clean
value; one that ignores its argument returns clean data), and which classes it
validates a parameter for when it raises, or returns a boolean, unless the
value passed a check. `validate(x)` on its own line, or `if not
is_safe(x): return`, then clears `x` for those classes. Summaries are computed
on demand, bounded in depth (two helpers deep) and in work, and generators are
not summarized. A record looked up by a key (Django `Model.objects.get()` /
`filter()`, `Model.query.get()`, SQLAlchemy `session.get(Model, key)` and
`session.query(...)`, `get_object_or_404`, and methods named by the
repository convention `get_..._by_id` / `find_by_...`) is stored data, not
the key's text, so a request key does not taint it (stored, second-order
flows are not modeled). Objects created by a known constructor at module level
(`env = Environment()`, `http = requests.Session()`) are recognized inside
functions.

**Guards and sanitizers.** CWE-specific sanitizers clear a value only for their
class: HTML escaping (`html.escape`, `markupsafe.escape`, any `*escape*`,
Django `format_html`) for XSS, `escape_filter_chars` for LDAP. Numeric
conversion, `secure_filename`, `basename`, `safe_join`, `shlex.quote`, `quote`
and `url_for` clear every class. A block that returns or raises when a check
fails refines the value after it, for checks that are complete mitigations: an
allowlist membership test (`x not in (...)`), `x.isdigit()` or
`isinstance(x, (int, float))` clears everything; a host allowlist on the parsed
URL (`urlparse(u).hostname in ALLOWED`, `== "api.example.com"`,
`.endswith(".example.com")`) clears open redirect and SSRF; a helper that
rejects a URL by the class of address it resolves to (`ipaddress` /
`netaddr` `is_private`, `is_loopback`, `is_link_local`, `is_reserved`,
`is_global`) clears SSRF; and a resolved path (`resolve()`,
`os.path.realpath`, `abspath`, `normpath`) checked with `startswith`,
`is_relative_to`, `os.path.commonpath([base, p]) == base`, or an `or` of such
checks, clears path traversal. `send_from_directory` is safe for its file
name (Flask joins it with `werkzeug.security.safe_join`). A tar extraction
with `filter="data"`, `"tar"`, `tarfile.data_filter`, a filter of the
program's own, or an explicit `members=` list is not reported. Flask's
`render_template` and `render_template_string`, Starlette's
`TemplateResponse` and Django's `render()` autoescape their variables.
Blocklist checks (`'../' in p`, "contains no quote") are deliberately not
trusted: an absolute path or another quoting style gets past them.
`request.path` is not a source inside a view whose routes have no
`<converters>`, because routing already fixed it. A known gap: a
`startswith(base)` check whose base does not end in a separator is accepted,
though `/srv/data_evil` passes `startswith("/srv/data")`.

### Library mode

In an application the attacker's input arrives through a request, the command
line or the environment. In a library it arrives as an argument of a public
function, and many advisories are in libraries. In library mode the
parameters of public functions and methods are sources:

- **When.** `library_mode: auto` (the default) turns it on for a project with
  a package manifest (`pyproject.toml`, `setup.py` or `setup.cfg` at the scan
  root) and no web application entry point Nephilex recognizes: a call to
  `Flask()`, `Quart()`, `FastAPI()`, `Starlette()`, `Sanic()`, `Bottle()`,
  `Litestar()`, `FastMCP()`, aiohttp or tornado `Application()`,
  `falcon.App()`, `uvicorn.run()`, `waitress.serve()`,
  `get_wsgi_application()`, `get_asgi_application()` or
  `execute_from_command_line()` outside test, documentation and example
  directories (found with Python's own parser, so a name in a docstring does
  not count). `on` and `off` override the detection; see
  [Configuration](configuration.md). The decision and its reason are in the
  JSON report under `project_summary.library_mode`.
- **Which parameters.** Those of functions and methods that are not
  underscore-prefixed (dunder methods such as `__init__` count), in classes
  that are not underscore-prefixed, listed in `__all__` when the module defines
  one, in modules outside underscore-prefixed packages and outside tests,
  docs, examples, `setup.py` and `__main__.py`. Nested functions are not public
  but see their enclosing function's parameters. Parameters annotated as
  numbers, booleans, UUIDs or dates are not sources.
- **What is reported.** A public function that hands its own argument to
  `open()`, `eval()`, `subprocess.run()` or `Markup()` usually does so by design:
  that is its API. The injection advisories describe the library placing the
  caller's value inside a path, command, query, page or expression it builds
  itself, or treating a field of caller data as code. So a flow whose only
  source is a public parameter is reported when the value is embedded after
  content the library chose (`os.path.join(ROOT, name)`, `"ping " + host`,
  `f'<td class="{value}">'`, `"[" + data + "]"`, `root / f"{item.name}.txt"`)
  for path traversal, command, SQL, LDAP, XPath and XSS sinks (including a
  public function that returns HTML built around its argument), when it is
  embedded or is a field of caller data (`eval(data["type"])`) for code and
  template injection, when it is a field of caller data for deserialization,
  and in any form for tar extraction without a filter. Argv-list commands
  without a shell are not reported from public parameters. SSRF, open
  redirect, session and XML parser sinks are never reported from public
  parameters: fetching, redirecting to or parsing what the caller passes is
  what such APIs are for.
- **How it is reported.** Same rule ids and CWEs, confidence **low**, tags
  `public-api` and `library-mode`, `metadata.source: public-api` and
  `metadata.public_function` (for example `Field.from_dict`), and a
  description saying the value comes from a caller of that public function.
  A request-derived flow to the same sink takes precedence.
- **Gate.** Library-mode findings do **not** count toward `--fail-on` /
  `fail_on` (or the editor hook's blocking threshold); they are still reported
  and still filtered by `min_severity`. Whether they are exploitable depends
  on how code outside the project calls the API, which the scan cannot see,
  and turning library mode on (or `auto` deciding it) must not start failing CI
  for code nobody changed. Gate on them with a policy or review them as a
  report.

**Limits.** Strongest for Python and JS/TS. Interprocedural analysis is bounded
(one call hop across files, plus request wrappers and same-file helper
summaries); extremely dynamic code can defeat static tracing. Guards are
recognized only in the simple forms above. Option injection into an argv list
(CWE-88) is not reported. A file that needs more than a fixed amount of
analysis work, or nests statements deeper than 60 levels, falls back to a
conservative flat scan or is reported as skipped.

## Infrastructure as Code

**Detects.** Misconfiguration in Dockerfiles, Terraform, and Kubernetes
manifests: running as root, privileged containers, exposed services, weak
defaults.

**Does not.** Assess a live cluster (that is the commercial `nephilex-k8s` add-on).

**Limits.** Static file analysis only; it evaluates the declared config, not the
running state.

## LLM / AI application security

**Detects.** The OWASP Top 10 for LLM Apps: insecure model-output handling,
prompt injection, secrets in prompts, over-privileged agent tools, and unsafe
model loading. See [LLM / AI security](llm-security.md).

**Does not.** Test a deployed model or run prompts against it.

**Limits.** A newer domain; rules are evolving. This is the area under the most
active development.

## Authentication and session (authz)

**Detects.** Sensitive routes without an auth decorator, object-id routes with
no visible ownership check, weak JWT validation, OAuth callbacks without
state/PKCE, tokens in URLs, and cookies set without security flags:
`set_cookie(...)` with `secure=False` or without `secure=True` is
`authz.insecure-session-cookie` (CWE-614), and without `httponly=True` is
`authz.cookie-missing-httponly` (CWE-1004). The call is read across lines; an
explicit `False` is high confidence, a missing flag medium.

**Does not.** Judge a flag set from configuration (`secure=app.config[...]`), or
know whether a cookie is a session cookie.

## Agent config

**Detects.** Risky settings in MCP server and coding-agent configuration files
that a teammate or CI agent runs simply by opening the project (`.mcp.json`,
`.claude/settings.json`, `.cursor/mcp.json`, `.vscode/mcp.json`,
`claude_desktop_config.json`, Windsurf `mcp_config.json`, Cline, Roo Code and
Gemini CLI settings):

- `mcp-hardcoded-secret` (OWASP LLM02): a literal credential in a server's
  `env`, `headers` or `args` instead of a variable reference. Uses the secrets
  scanner's signatures; the value is redacted.
- `mcp-unpinned-package` (LLM03): a server started with `npx`, `bunx`,
  `pnpm dlx`, `uvx`, `pipx run` or `docker run` on a package or image without a
  pinned version.
- `mcp-plaintext-http` (LLM03): a remote server reached over plain `http://`
  (loopback excepted).
- `mcp-broad-filesystem-root` (LLM06): a filesystem server or
  `additionalDirectories` entry granted `/`, a drive root or a home directory.
- `agent-auto-approve` (LLM06): tools that run without confirmation (Cline
  `autoApprove`, Roo Code `alwaysAllow`, Gemini CLI `trust: true`, Claude Code
  `enableAllProjectMcpServers`, a bare `Bash` allow rule, `bypassPermissions`).

**Does not.** Start or contact the configured servers, or judge what a pinned
package actually does.

**Limits.** Only the documented file names and keys are read; a client with a
different layout is not covered until it is added.

## Custom rules

**Detects.** Whatever you define. Drop YAML rules in `.nephilex/rules/*.yml` or point
Nephilex at a rules file; no code needed. See [Writing plugins](plugins.md).

**Limits.** Custom rules loaded from a scanned repository are ignored for remote
targets by default, so an untrusted repo cannot define rules that reconfigure the
scanner.
