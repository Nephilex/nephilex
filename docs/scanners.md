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
| `ast-command-injection` | 78 | `os.system`, `os.popen`, `subprocess.*`, `os.exec*`/`os.spawn*` |
| `ast-path-traversal` | 22 | `open`, `io.open`, `codecs.open`, `os`/`shutil` file operations, `send_file`, the file name of `send_from_directory`, and file methods on a `pathlib.Path` built from the value (`Path(x)`, `base / x`) |
| `ast-code-injection` | 95 | `eval`, `exec`, `compile` |
| `ast-unsafe-deserialization` | 502 | `pickle`/`dill`/`marshal` loads, `yaml.load` without a safe loader, `yaml.unsafe_load` |
| `ast-xss` | 79 | value returned from a Flask/Bottle view (`@app.route`, or `@app.get` in a Flask file), `Markup()`, `mark_safe()`, Django `HttpResponse` |
| `ast-open-redirect` | 601 | `redirect()`, `HttpResponseRedirect`, `RedirectResponse`, `headers["Location"] = ...` |
| `ast-xxe` | 611 | XML parse of the value with a parser that has external entities enabled (`setFeature(feature_external_ges, True)`, lxml `resolve_entities=True`) |
| `ast-ldap-injection` | 90 | ldap3 `search()` base/filter, python-ldap `search_s()` (only in files importing ldap/ldap3) |
| `ast-xpath-injection` | 643 | lxml `xpath()`/`XPath()`, `elementpath.select()`, ElementTree `find*()` in XML files |
| `ast-trust-boundary` | 501 | request data written into `session[...]` (key or value) |
| `ast-weak-random` | 330, 338 | a `random` module value (not `SystemRandom`) stored as a token, password, salt, nonce, session or cookie value, or returned from a function named like one |

**How values are tracked.** The engine is flow-sensitive within a function:
`if`/`elif`/`else`, `match`, loops and `try` are analyzed per branch and joined,
so `if not p: p = ""` keeps the taint of the other branch. Conditions that fold
to a constant (`if 7 * 18 + num > 200`, a `match` on a constant) prune the dead
branch. Literal dicts, lists (`append`, `pop`, indexing) and `configparser`
objects are tracked per key, so storing request data under one key does not
taint a read of another. A method returns request data when it reads the
request (`return self.request.form.get(name)`); calling it on an object built
from the request (`Wrapper(request).get_form_parameter("q")`) is a source, in
the same file (`ast-python`) or across files (`ast-python-xfile`).

**Guards and sanitizers.** CWE-specific sanitizers clear a value only for their
class: HTML escaping (`html.escape`, `markupsafe.escape`, any `*escape*`) for
XSS, `escape_filter_chars` for LDAP. Numeric conversion, `secure_filename`,
`basename`, `shlex.quote` and `url_for` clear every class. A block that returns
or raises when a check fails refines the value after it, for checks that are
complete mitigations: an allowlist membership test (`x not in (...)`) or
`x.isdigit()` clears everything, `urlparse(u).netloc` against an allowlist
clears open redirect, and a resolved path (`resolve()`, `os.path.realpath`)
checked with `startswith`/`is_relative_to` clears path traversal. Blocklist
checks (`'../' in p`, "contains no quote") are deliberately not trusted: an
absolute path or another quoting style gets past them. `request.path` is not a
source inside a view whose routes have no `<converters>`, because routing
already fixed it.

**Limits.** Strongest for Python and JS/TS. Interprocedural analysis is bounded
(one call hop, plus request wrappers); extremely dynamic code can defeat static
tracing. Guards are recognized only in the simple forms above. A file that needs
more than a fixed amount of analysis work, or nests statements deeper than 60
levels, falls back to a conservative flat scan or is reported as skipped.

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
  (`-H`, `--header`), `-u`/`--user` or `--cookie`.

A variable counts as a secret when its name contains a word such as `TOKEN`,
`SECRET`, `PASSWORD`, `PASS`, `KEY`, `AUTH`, `SESSION` or `COOKIE`, and does not
end in `URL`, `HOST`, `PORT`, `NAME` or similar. The Python form still reports
`requests`, `httpx` or `urllib` calls on a literal URL with `os.environ`,
`getenv` or `process.env` in the arguments.

**Does not.** Report a request that sends nothing: a readiness loop such as
`curl --fail --max-time 15 "$url" >/dev/null`, `wget --spider "$READY_URL"` or a
download to `-o "$OUT_DIR/file"` is not exfiltration however many variables it
uses.

**Limits.** Line based. A command assembled across lines, or a secret copied
into a neutrally named variable first, is not followed. An authenticated API
call (`-H "Authorization: Bearer $GITHUB_TOKEN"`) is still reported, because the
scanner cannot tell the intended service from an attacker's host.

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
