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

## Supply chain

**Detects.** Dependencies that are dangerous independently of published CVEs:
known-malicious packages, typosquats of popular names, and suspicious npm
lifecycle scripts (`preinstall` / `postinstall` that run a shell, download code,
or read credentials). The malicious-package intelligence is a bundled seed
refreshed, best-effort, from the OSSF `malicious-packages` and OSV feeds.

**Version-aware malicious matching.** A package name on the malicious list is
only flagged at the versions that were actually compromised. The intel stores,
per package, the affected versions as an exact list (OSV `affected[].versions`)
and as `[introduced, fixed)` ranges (OSV `affected[].ranges`), compared with the
right grammar per ecosystem: PEP 440 for PyPI and SemVer for npm and the others.

- When the installed version is in the affected set, the finding is **Critical**,
  high confidence, and names the affected versions.
- When the installed version is pinned and outside the affected set, nothing is
  reported. For example the npm `coa` compromise (Nov 2021) affects versions
  `2.0.3, 2.0.4, 2.1.1, 2.1.3, 3.0.1, 3.1.3`, so a project pinned to the clean
  `coa 2.0.2` is no longer flagged.
- When the installed version cannot be confirmed (unpinned, a range or wildcard
  spec, or unparseable), the name match is still reported, but as "version
  unconfirmed" at **low confidence**, with text saying only some versions are
  affected and that the version could not be confirmed.

An intel entry with no version information keeps the original behaviour and
matches every version. This is the safe default for name-only seed entries and
for any feed record whose affected versions could not be parsed.

**Does not.** Decide that a name-only entry is safe at some version: with no
per-version intel, every version is treated as affected.

**Limits.** Version comparison covers the exact-version and introduced/fixed
shapes the feeds emit, not the full SemVer range grammar (`^`, `~`, `||`). A
package.json range spec (`^2.0.0`, `2.x`, `*`, `latest`) has no single resolved
version without a lockfile, so a malicious name pinned to a range is reported as
version-unconfirmed rather than resolved or dropped; when a lockfile pins the
same package, that exact version is used instead. Set `online_intel: false`
under the `supply-chain` scanner options to use only the bundled seed.

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
not summarized.

Helpers imported from another file of the same project are summarized the
same way, in the file that defines them and with the caller's settings
(project context, sources). What crosses files:

- module functions imported with `from pkg.mod import f`, `from .mod import f`
  (relative), `from pkg.mod import f as g`, `import pkg.mod` then
  `pkg.mod.f(x)`, and `import pkg.mod as m` then `m.f(x)`;
- a name re-exported by a package's `__init__.py` (`from pkg import f` where
  `pkg/__init__.py` has `from .impl import f`), one re-export deep;
- static and class methods called on an imported class (`Paths.clean(x)`), and
  methods called on a module-level instance (`service = Service()` in the
  helper's module, or in the caller's module for an imported class).

Module names come from file paths and package roots (directories with an
`__init__.py`), so `src/` layouts and directories without an `__init__.py`
resolve too. What does not cross files: methods called on any other receiver
(an object passed in, `self` inherited from a base class in another file),
star imports, a name that two modules could provide (two top-level `utils.py`
files that the importing file's location does not tell apart), a name the
importing file also defines itself, and anything outside the scanned project
(installed packages stay opaque). A chain of summaries crosses at most two
file boundaries; past that the call is opaque and its result keeps the
arguments' taint. Each file is parsed once per scan and each helper is
summarized once per scan and settings. When an imported helper passes taint
on, the finding's evidence shows the call with the file and line where the
helper is defined. A validation done by every caller of a function (rather
than inside a helper it calls) is not modeled. A record looked up by a key (Django `Model.objects.get()` /
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

**JavaScript/TypeScript sinks and rule ids** (`ast-js.*`, for `.js`, `.jsx`,
`.mjs`, `.cjs`, `.ts`, `.mts`, `.cts` and `.tsx`):

| Rule | CWE | Sink |
| --- | --- | --- |
| `ast-command-injection` | 78 | `child_process` `exec`/`execSync`, `spawn`/`execFile` with `shell: true` or running `sh -c`/`cmd /c`/`powershell -Command`, shelljs `exec`, execa `execaCommand`; `promisify(exec)` and `require('child_process').exec` bindings are resolved |
| `ast-code-injection` | 95 | `eval` (also `window.eval`, `window['eval']`), the `Function` constructor, `vm.runInThisContext`/`runInNewContext`/`runInContext`/`compileFunction`, `new vm.Script`, `setTimeout`/`setInterval` with a string |
| `ast-path-traversal` | 22 | `fs`, `fs/promises` and `fs-extra` file operations (read, write, open, stream, mkdir, rm, rename, copy), `res.sendFile`/`res.download` without a `root` option, `express.static`/`serve-static` roots |
| `ast-path-prefix-check` | 22 | a resolved path checked with `startsWith(baseDir)` where the base has no trailing separator, so a sibling directory passes (no traced source) |
| `ast-ssrf` | 918 | `fetch`, `$fetch`, `node-fetch`, `undici`, `axios`/`got`/`superagent`/`needle`/`ky` calls and their `url`/`baseURL`/`host` options, `http(s).get`/`request` |
| `ast-xss` | 79 | `innerHTML`/`outerHTML`/`srcdoc` assignment, `document.write`, `insertAdjacentHTML`, `createContextualFragment`, JSX `dangerouslySetInnerHTML`, jQuery `$(html)`/`.html()`, `setAttribute('on*')`, Angular `bypassSecurityTrust*`, Lit `unsafeHTML`, Handlebars `SafeString`; on the server Express `res.send` of a string, `res.end`/`res.write`/`reply.send` with markup or a `text/html` type, Koa `ctx.body`, Hono `c.html` |
| `ast-template-autoescape-off` | 79 | Nunjucks `configure`/`Environment` with `autoescape: false`, Handlebars `compile` with `noEscape: true` (configuration, no traced source) |
| `ast-open-redirect` | 601 | `.redirect()` on a response or context (Express, Koa, Fastify, `NextResponse`), `redirect()` from `next/navigation` or React Router, a `Location` header, `location.href`/`window.location` assignment, `location.assign`/`replace`, `window.open` |
| `ast-template-injection` | 1336 | the template text of `ejs.render`/`compile`, `pug.render`/`compile`, `Handlebars.compile`, `nunjucks.renderString`, `_.template` |
| `ast-sql-injection` | 89 | the query text of `.query()`, `.execute()`, `.raw()`, `$queryRawUnsafe`/`$executeRawUnsafe`, `prepare()` on a database object; bound parameters and `sql`-tagged templates are not flagged |

**JS/TS sources.** Server request input: `req`/`request` `.query`, `.body`,
`.params`, `.headers`, `.cookies`, `.url`, `.originalUrl`, `.path`, `.files`
(not the upload fields the server generates, such as `path` and
`tempFilePath`), `req.get()`/`req.header()`; Koa `ctx.query`, `ctx.params`,
`ctx.request.*`, `ctx.get()`; Next.js `request.nextUrl.searchParams`, `await
request.json()`/`formData()`/`text()` and the `searchParams` page prop; h3/Nuxt
`getQuery`, `readBody`, `getRouterParam`, `getRequestURL`, `getHeader`; Hono
`c.req.*`. Browser input (`location.*`, `document.URL`, `document.referrer`,
`document.cookie`, `window.name`, `postMessage` event data, `useSearchParams`)
is reported at HTML, redirect and code sinks only. Archive entry names
(tar-stream, yauzl and unzipper `on('entry')`, adm-zip `getEntries()`) are
reported at file sinks (zip slip). `process.env` and `process.argv` are
reported at SQL sinks only.

**JS/TS library parameters.** A function parameter that is concatenated or
interpolated into a shell command or an `eval`/`vm` string together with
literal text (`exec('ping ' + host)`) is reported at medium confidence, because
whoever calls the function with user input gets the injection. Passing a
parameter through unchanged (`exec(cmd)`), parameters named like a command or
code (`cmd`, `command`, `script`, `code`), parameters typed `number` or
`boolean`, and the `Function` constructor (how template engines compile) are
not reported. When the command is built in one function and run by a helper
defined in the same file, the finding is shown at the call into the helper.

**How JS/TS values are tracked.** One walk per file in statement order:
assignments, destructuring with defaults, template literals, `+` chains,
`join`/`concat`/`replace`, `await`, optional chaining, TypeScript `as`/`!`/
`satisfies`, `for...of`, array callbacks (`forEach`, `map`, `then`), closures
(nested functions see their enclosing scope) and calls to functions and `this`
methods defined once in the file (followed with the caller's argument taint).
Object literals, spreads and `Object.assign`/`$.extend` keep a taint per field,
so `{ label: 'x', target: req.query.t }.label` is clean. A file system, HTTP or
`exec` call returns fresh data, not its argument.

**JS/TS guards and sanitizers.** Sanitizers clear only their class: HTML
escapers (`escape-html`, `he`, DOMPurify, `sanitize-html`, `xss`, any
`*escape*`/`*sanitize*` name) for XSS, `shell-quote` and `*shellEscape*` names
for commands, `path.basename` and `sanitize-filename` for paths, `jsesc`,
`serialize-javascript`, `devalue` and `JSON.stringify` for code,
`encodeURIComponent` for XSS, SSRF, redirects and commands, and numeric
coercion for everything. `htmlSafe()` is not a sanitizer (it marks HTML as
trusted). A block that returns or throws when a check fails clears the value
after it: allowlist membership (`includes`, `has`, `in`, `Object.hasOwn`),
equality with a literal, an anchored regex test, a predicate named like a
validator (`isValid*`, `isAllowed*`, `isSafe*`, `isPathInside`) or a blocklist
(`isPrivate*`, `isBlocked*`), a URL host compared with an allowlist or with the
request's own host, a resolved path checked with `startsWith(base + path.sep)`
or `path.relative(base, p)` against `..`, and a regex `replace` that removes
everything outside a character class. `p.slice(0, base.length) === base` (or
`substring`/`substr` with the same arguments) is the same test as
`p.startsWith(base)`; it is trusted only when `base` ends with a separator
(`base + path.sep`, or `path.join(dir, '/')`, which keeps the trailing slash),
since otherwise a sibling such as `/srv/www-evil` passes a check for
`/srv/www`. A check of a path also covers a value built from it with a literal
suffix that has no separator and is not only dots (`` `${file}.gz` ``), even
when that value was built before the check. A statement call such as
`assertValidRegion(r)` or `validateName(n)` is taken to throw and clears its
argument. `path.join(root, path.normalize('/' + p))` stays under `root`. Host
pinned URLs (`` `https://api.example.com/${id}` ``) and relative URLs are not
SSRF or open redirect. String blocklists (`p.includes('..')`) are not trusted.
Express's `res.send` of a string is HTML unless the handler sets another
content type.

**JS/TS test and example code.** Findings in test files (`test/`, `tests/`,
`__tests__/`, `spec/`, `fixtures/`) and in example or demo code (`example/`,
`examples/`, `sample/`, `samples/`, `demo/`, `demos/`) are still reported, one
severity step lower and at low confidence, tagged `test-context` or
`example-context`. Such code is not part of what a package runs, but readers
copy examples, so the finding is kept.

**Limits.** Strongest for Python and JS/TS. Interprocedural analysis is bounded
(one call hop across files, plus request wrappers and helper summaries that
cross at most two files); extremely dynamic code can defeat static tracing. Guards are
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

**Global authentication.** Before reporting `authz.missing-authentication`, the
scanner looks for authentication registered once for the whole application:

- FastAPI and Starlette: an `@app.middleware("http")` function; a class passed to
  `app.add_middleware(...)` or `FastAPI(middleware=[Middleware(...)])` whose
  `dispatch` or `__call__` does the check; `FastAPI(dependencies=[...])`; and
  `include_router(router, dependencies=[...])`, which covers only the routes of
  that router's module. `APIRouter(dependencies=[...])` already covered the
  routes in its own file.
- Flask: `@app.before_request` (or `app.before_request(func)`) for the whole app,
  `@blueprint.before_request` for that blueprint's routes, and
  `before_app_request`.
- Django: `LoginRequiredMiddleware` or a project middleware in `MIDDLEWARE`
  whose `__call__`, `process_request` or `process_view` does the check. A route
  marked `@login_not_required` stays reported. `@login_required` and the
  `LoginRequiredMixin`, `PermissionRequiredMixin` and `UserPassesTestMixin`
  classes count as route-level auth.

A middleware or hook counts only if it reads a credential (an `Authorization`,
API-key or token header, a cookie, the session, `request.user`, or a call such
as `verify_token()` or `compare_digest()`) and, when that check fails, returns
or raises 401 or 403 (`abort(401)`, `HTTPException(status_code=401)`,
`HttpResponseForbidden`, `PermissionDenied`). A middleware that only logs, adds
headers, applies CORS or rate-limits is not authentication. Dependencies count
when their callable is named like authentication (`get_current_user`,
`verify_api_key`) or is a function that does the check; `Depends(get_db)` does
not.

Path exemptions are read from the guard: `if request.url.path == "/health"`,
`in PUBLIC_PATHS` (a literal or a module constant), `.startswith(...)`, and
Flask `request.endpoint in (...)`. A route the guard skips is reported as
before.

Method conditions are read the same way. A guard such as
`if request.method != "GET" and not key: return 401`, or a check nested under
`if request.method in ("POST", "PUT"):`, covers only the methods it checks, so
a `GET` route under a writes-only guard stays High while a `PUT` route is
covered. `==`, `!=`, `in` and `not in` against literal methods, tuples or
constants are read on `request.method`, `scope["method"]` and
`scope.get("method")`. The route's method comes from the decorator
(`@router.put`) or Flask's `methods=[...]` (default `GET`); implicit `HEAD` and
`OPTIONS` are not counted, so a CORS preflight bypass still covers the route.
A method test that also requires the credential
(`if request.method == "GET" and token_ok: ...`) is part of the check, not a
skip.

If a path or method condition cannot be read (for example a function call), the
guard covers nothing. With more than one FastAPI or Flask application in the
project, an app-wide guard covers only the routes in its own file.

A covered route is not dropped. It is reported at Info as "Sensitive route
relies on global authentication", naming the guard in `metadata.global_auth`,
so the assumption that the route is mounted behind that guard stays visible
without failing a gate.

A guard that fails open still counts, but the note says so. If the guard, or a
helper its check calls, lets every request through when the expected
credential is not configured (`if not API_TOKEN: return await call_next(...)`,
`if not settings.token: return True`) or when an auth switch is set
(`os.environ.get("AUTH_DISABLED")`), the description says the guard allows all
requests when the credential is not configured, and
`metadata.global_auth.fails_open` is `true`.

**Does not.** Judge a flag set from configuration (`secure=app.config[...]`), or
know whether a cookie is a session cookie. Follow which application a router is
finally mounted on when there are several, or treat a redirect to a login page
as a rejection (only 401 and 403 are).

## Malicious code (malware)

**Detects.** Shapes that point at a backdoor or a compromised repository:
decode-then-exec payloads, `__import__` indirection to a shell, reverse shells,
PHP webshells, cryptominers, remote scripts piped to a shell, encoded
PowerShell, suspicious package lifecycle scripts, and credential or environment
exfiltration.

`malware.data-exfil-env` needs evidence that data leaves the host. A `curl` or
`wget` command is read word by word and reported when one of these holds:

- a data or upload flag (`-d`, `--data*`, `--json`, `-F`, `--form`, `-T`,
  `--upload-file`, wget `--post-data`, `--post-file`, `--body-data`,
  `--body-file`) carries a secret-named variable (`$NPM_TOKEN`,
  `${AWS_SECRET_ACCESS_KEY}`, `%DB_PASSWORD%`, `process.env.API_KEY`), the
  whole environment (`$(env)`, `printenv`, `/proc/*/environ`) or a credential
  file (`~/.aws`, `~/.ssh`, `.env`, `id_rsa`, `/etc/shadow`);
- `env` or `printenv` is piped into the command, a credential file is piped or
  redirected into it, or a secret is piped in and read with `@-`;
- a secret-named variable or the environment appears in the URL, a header
  (`-H`, `--header`), `-u`/`--user` or `--cookie`, except for the
  authenticated API call described below.

A command continued over several lines with a trailing `\` is read as one
command.

A variable counts as a secret when its name contains a word such as `TOKEN`,
`SECRET`, `PASSWORD`, `PASS`, `KEY`, `AUTH`, `SESSION` or `COOKIE`, and does not
end in `URL`, `HOST`, `PORT`, `NAME` or similar. The Python form still reports
`requests`, `httpx` or `urllib` calls on a literal URL with `os.environ`,
`getenv` or `process.env` in the arguments.

**Does not.** Report a request that sends nothing: a readiness loop such as
`curl --fail --max-time 15 "$url" >/dev/null`, `wget --spider "$READY_URL"` or a
download to `-o "$OUT_DIR/file"` is not exfiltration however many variables it
uses.

It also does not report an authenticated API call: a secret in a credential
header (`Authorization`, `Cookie`, `PRIVATE-TOKEN`, or a name containing
`token`, `api-key`, `auth`, `secret` or `session`), in `-u`/`--user`, or in
`--oauth2-bearer`, when every destination is an `https://` URL whose host is
written literally, for example:

```sh
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
```

Variables later in the path or query are fine.
The same header is reported when the destination comes from a variable, uses
plain `http://`, has an IP-literal host, or when the request also has a data
or upload flag carrying a secret or the environment.

**Limits.** A command assembled in a variable or through a function, or a
secret copied into a neutrally named variable first, is not followed. A
credential header sent to a literal `https://` host the attacker controls is
not reported; the scanner cannot tell the intended service from another host.

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
