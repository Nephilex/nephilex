# Changelog

All notable changes to Nephilex are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may
include breaking changes, noted explicitly).

## [Unreleased]

### Added
- **Python taint for path traversal, XSS, SSRF and code injection.** New
  sources (Flask route converters, FastAPI and Starlette parameters and
  requests, uploads, archive member names), sinks (HTTP clients, template
  compilation, tar extraction without a filter, HTML responses, pathlib and
  aiofiles file access) and guards (path containment checks, host allowlists,
  private-address validators, autoescaping renderers). Helpers defined in the
  same file are summarized, so a validator or a wrapper is followed.
- **Library mode** (`library_mode: auto | on | off`). For a Python package
  without a web entry point, parameters of public functions are treated as
  input from callers. These findings are low confidence and do not count
  toward `--fail-on` or the posture gate.
- **JavaScript/TypeScript taint engine.** `ast-js` now follows values
  statement by statement through destructuring, template literals, closures,
  async code and same-file helpers, with sources for Express, Fastify, Koa,
  Next.js, h3, Hono and the browser, and sinks for command execution, code
  evaluation, file access, outgoing requests, HTML output, redirects and
  template compilation. A sanitizer clears only the kinds of sink it protects
  against. Template engines configured without HTML escaping are reported.
- **AI assistant instruction files and MCP tool poisoning.** The
  `agent-config` scanner checks `AGENTS.md`, `CLAUDE.md`, Copilot, Cursor,
  Windsurf, Cline and other instruction files for hidden Unicode, planted
  directives (override, conceal, sabotage, disabling checks, download and
  execute, exfiltration, unreviewed push), untrusted package sources and
  encoded text, and checks MCP server tool descriptions in Python and
  TypeScript for the same.
- Documentation for pinning the GitHub Action by commit SHA, and for giving
  `--open-pr` a least-privilege token on GitHub, GitLab and Bitbucket
  (Bitbucket's `BITBUCKET_TOKEN` was supported but undocumented).

### Changed
- Releases go through a staging phase. A release candidate (`0.12.0rc1`, a
  GitHub pre-release) publishes to TestPyPI and the `rc` image tag; only a
  final version reaches PyPI and `latest`, and the workflows refuse a release
  whose pre-release setting disagrees with its version. A manual Docker build
  publishes `edge` and `sha-<commit>`, never `latest`. See RELEASING.md for the
  phases and the four-week rhythm.
- Routine Dependabot updates are monthly instead of weekly.
- `sys.argv`, `os.environ` and `input()` count as operator input: findings
  from them are low confidence, and a server URL taken from the environment is
  configuration, not SSRF. A command run as an argument list without a shell
  is reported only when the program itself or the code passed to `-c` comes
  from input.
- The weak-hash rule honours `usedforsecurity=False` and reports checksum,
  ETag and cache-key uses at low severity.

### Fixed
- Authorization: routes protected by project-wide authentication (a
  middleware, a global dependency or a before-request guard) are no longer
  reported as missing authorization. A guard covers only the HTTP methods it
  checks, and a guard that fails open is noted on the finding.
- Malware: `data-exfil-env` needs evidence that data leaves the machine, and
  a CI script that sends a token in a credential header to a fixed `https://`
  host is not reported.
- A condition that joins path containment checks with `or` is no longer
  dropped by the Python flow engine.
- JS/TS path traversal: `p.slice(0, base.length) === base` is recognized as a
  containment check when the base ends with a separator (including
  `path.join(dir, '/')`), and the check also covers a path built from the
  checked one with a plain suffix such as `.gz`.

## [0.11.0] - 2026-10-23

### Added
- **Test-verified fixes.** `nephilex fix --verify-with-tests` (with
  `--test-command`, or `autofix.test_command` from a trusted config) runs the
  project's tests in a temporary git worktree before and after the fixes,
  re-scans, and commits only fixes that keep the tests passing. The command
  runs without a shell, with a timeout and capped output, and with tokens and
  keys removed from its environment. Results appear in the summary, the commit,
  the pull request body and the audit log.
- **Agent-security rules.** `llm.indirect-prompt-injection` (external content
  in the prompt of a model whose tools or output can act on it),
  `llm.tool-argument-to-sink`, `llm.untrusted-message-role`,
  `llm.untrusted-tool-selection` and `llm.secret-sent-to-model`, with
  JavaScript/TypeScript coverage for untrusted system prompts and tool handlers.
- **Benchmarks with held-out data.** `benchmarks/heldout/` scores Nephilex,
  Bandit and Semgrep on 201 files from real GitHub advisory fix commits,
  before and after each fix; `benchmarks/agent/` scores the LLM and agent
  rules on a labeled corpus with a held-out split. Both publish raw results.
- Documentation: a quickstart, one finding followed from detection to fix, and
  a "Trust and limits" page with a capability matrix.
- `Scanner.unavailable_reason()` lets a scanner say why it is skipped.

### Changed
- The GitHub Action installs `nephilex[ast]`, so the taint scanners run in CI.
  Earlier versions installed it without the extra and skipped them.
- A scan without the `[ast]` extra says the taint scanners need it, instead of
  calling them "not applicable".
- When two tiers report one weakness with equal confidence and severity, the
  finding with a deterministic fix is kept, then the AST one. The choice no
  longer depends on scanner order, so `scan` and `check` report the same rule
  and `check` keeps the fix an editor applies.
- The weak-hash fix is not applied to a line that hashes a password or other
  secret: SHA-256 is still a fast hash, and passwords need a key-derivation
  function. Such findings keep that guidance instead of a "verified" patch.

### Fixed
- `--format` help on `scan` and `import` now lists `junit`.
- Documentation that did not match the code: the number of report formats,
  `--live-target` described as checking TLS (it checks HTTPS and the redirect),
  and dependency reachability and VEX `not_affected`, which need
  `--reachability`.
- Deeply nested YAML in `.nephilex.yml`, `.nephilex/context.yml`,
  `.nephilex/exceptions.yml`, custom rule files, a scanned project's own config
  (read by the DAST scanner) or the agent config no longer crashes the run with
  a `RecursionError`. Configuration files fail with their normal error, and
  rule or project files are skipped. Found by the new fuzz tests.

### Security
- CI, the release workflow, the container image and the fuzzing build install
  every dependency from hash-locked files (`requirements/`), and Nephilex is
  built without fetching an unpinned build backend.
- Each release carries its signed build provenance (`nephilex-<version>.intoto.jsonl`)
  next to the SBOM, verifiable with
  `gh attestation verify <file> --bundle nephilex-<version>.intoto.jsonl --owner Nephilex`.
- Coverage-guided fuzzing (ClusterFuzzLite with atheris) of the SARIF,
  config and context parsers runs on pull requests and weekly.

## [0.10.0] - 2026-10-23

The first release under the Nephilex name. It contains the 0.9.0 security
hardening, the 0.9.2 fixes, which were never published, and the changes below.

### Breaking changes
- **The project is now Nephilex.** Everything that carries the product name
  changed with it, with no aliases for the earlier names:
  - the PyPI package and the command are `nephilex`, and the import package
    is `nephilex` (plugins import `nephilex.plugin_api` and register under the
    `nephilex.commands` entry-point group);
  - repository config is `.nephilex.yml` and `.nephilex/` (rules, exceptions,
    context, audit log), and the inline suppression comment is
    `nephilex-ignore`;
  - environment variables use the `NEPHILEX_` prefix (for example
    `NEPHILEX_CACHE_DIR`, `NEPHILEX_MCP_ROOTS`, `NEPHILEX_DASHBOARD_TOKEN`);
  - the MCP server is registered as `nephilex`, and its tools are
    `nephilex_scan`, `nephilex_check_files` and so on;
  - SARIF output carries the fingerprint as `nephilexFingerprint`, so baselines
    and code-scanning alerts made by earlier versions need to be regenerated;
  - the GitHub repository is `nephilex/nephilex`, the Action is
    `nephilex/nephilex@<tag>`, and the container image is
    `ghcr.io/nephilex/nephilex`.

  To upgrade, install `nephilex`, rename the config file and directory,
  update inline suppression comments, CI workflows and environment variables,
  and rerun `nephilex init --editor` for editor integrations.

### Added
- **SARIF import.** `nephilex import <file.sarif>` and `nephilex scan --import-sarif`
  read SARIF 2.1.0 from other scanners (CodeQL, Semgrep, Bandit and others),
  map their results onto Nephilex findings, and run them through the same
  baseline, suppression, policy and reporting steps as native findings. The
  input is treated as untrusted: file size, nesting and result count are
  capped, locations outside the project root are dropped, and snippets are
  redacted before anything is stored.
- **Project context file.** `.nephilex/context.yml` declares the project's own
  sanitizers and trusted sources (used by the taint engines), internal-only
  paths, exposure levels and data classification, so findings are ranked
  against how the code is really deployed. Validation is strict, and like the
  rest of repository config it is read only from trusted projects.
- **Audit log.** `.nephilex/audit.log` is an append-only, hash-chained record of
  scans, suppressions (including findings hidden by `--baseline`) and fixes.
  Set `audit_log: false` to turn it off.
- **LLM and agent data flow.** The LLM scanner parses Python with tree-sitter
  to trace model output into dangerous sinks (LLM05), flag agents given
  excessive tools (LLM06) and review system-prompt construction. Findings cite
  OWASP Top 10 for LLM Applications 2025 ids.
- **Agent configuration scanner** (`agent-config`). Reviews MCP server
  definitions and coding-agent settings for hardcoded credentials, servers
  launched from unpinned packages, remote servers over plain HTTP, filesystem
  access to `/` or a home directory, and settings that run tools without
  confirmation. It runs in the `deep` profile.
- **`nephilex check`.** A fast, file-level check for editors and AI assistant
  hooks, with `--hook` output for Claude Code and Cursor and
  `--no-inline-ignores` for strict mode.
- **MCP tools.** The MCP server adds `nephilex_check_files`, `nephilex_check_snippet`,
  `nephilex_check_package` and `nephilex_fix` next to `nephilex_scan`.
- **`nephilex init --editor claude|cursor|vscode`** writes that editor's MCP and
  hook configuration into the project.
- **Public benchmarks.** `benchmarks/public/` runs Nephilex, Bandit and Semgrep
  on OWASP BenchmarkPython and SecurityEval and publishes the raw findings and
  scores; see `docs/benchmarks.md`.
- **Flow-sensitive Python taint engine.** Branches, loops, `match` and `try`
  are analysed separately and joined; constant conditions prune dead code;
  literal containers and simple early-return guards are understood. New
  CWE-mapped sinks cover XSS, open redirect, XXE, LDAP and XPath injection,
  trust-boundary violations, weak randomness for tokens, unsafe
  deserialization and insecure cookies.
- Findings report start and end columns, and snippets keep their indentation,
  so editors can highlight the exact match.
- Logo set and brand assets in `docs/assets/brand/`.

### Changed
- A scan of a git work tree skips untracked files that git ignores (build
  output, virtual environments, local `.env` files).
- Inline `nephilex-ignore` comments are recognised in `--`, `<!-- -->` and `;`
  comment styles as well as `#` and `//`.
- Deterministic fix patches are attached when AI is off, including by
  `nephilex check`, so editors can offer the verified fix in place.
- Reporters, model clients and HTTP libraries are imported on first use, so
  the CLI starts faster.
- The regex tier asks the taint engine about its payload, so `shell=True`,
  `os.system` and `pickle.loads` on literal-only data are no longer reported.

### Fixed
- Imported SARIF findings keep the tool's own fingerprints, so baselines stay
  stable across runs.
- `nephilex mcp --help` lists every MCP tool.
- A fresh `import nephilex.inventory` no longer fails on a circular import.

## 0.9.2 (not released)

Prepared but never published: the PyPI project under the earlier name was
archived before it shipped, and these fixes ship in 0.10.0. The 0.9.0 upload
was rejected by PyPI tooling (see below), and the v0.9.1 tag was created on
the 0.9.0 commit by mistake.

### Fixed
- Packages declare core metadata 2.4 instead of 2.5, and releases upload with
  `pypa/gh-action-pypi-publish` v1.14.3. The upload tooling pinned for 0.9.0
  could not read metadata 2.5 and rejected the distributions.
- The curl-pipe-shell rule no longer fires on text that only names the
  pattern (for example "avoid `curl | bash`" in documentation or a rule's own
  explanation); a real download-and-execute always has an argument between
  the command and the pipe.
- The scan cache now includes a fingerprint of the installed Nephilex code, so
  changing a rule in a source checkout no longer returns stale cached findings.
- The container release workflow refuses to publish when the release tag does
  not match the package version, as the PyPI workflow already did.

## [0.9.1] - 2026-10-22

Tagged on the 0.9.0 commit by mistake. The PyPI release check refused to
publish it, so it is not on PyPI; its container image contains 0.9.0. Use
0.10.0.

## [0.9.0] - 2026-10-22

This release is a security hardening release. Nephilex runs on untrusted code (pull
requests from forks, cloned repositories), and a full review found ways a
hostile repository could execute code, read outside the scan root, hang a
scan, hide its own findings, or make a CI gate pass. All of them are fixed.
Upgrading is recommended for every user.

### Breaking changes
- **Repository config is untrusted by default.** `Config()` now defaults to
  `trust_project_config=False`. A cloned remote's `.nephilex.yml`,
  `.nephilex/rules`, `.nephilex/exceptions.yml` and inline `nephilex-ignore` comments
  are ignored unless you pass `--trust-remote-config`. Library code that builds
  `Config()` directly must set `trust_project_config=True` to honour them.
- **Scanner crashes fail the gate.** When a `fail_on` threshold is set, a
  scanner error now fails the run (a crashed scanner reports nothing, which a
  gate must not read as a pass). Opt out with `--no-fail-on-error` or
  `fail_on_error: false`. `policy check` always fails on scanner errors.
- **Configuration mistakes exit 2.** Wrong types in `.nephilex.yml` (for example
  `exclude_paths: "dist/*"`), unknown `--scanners` names, a selection that
  leaves no scanner, an unknown profile, an invalid severity, invalid policies,
  a malformed `exceptions.yml`, and `policy check` with no policies configured
  now exit 2 instead of being coerced or ignored.
- **Dashboard requests are restricted.** Only loopback Host headers are
  accepted (add names with `NEPHILEX_DASHBOARD_ALLOWED_HOSTS`); `/api/scans`
  requires `Content-Type: application/json`; the upload form requires its CSRF
  token; binding to a non-loopback address requires `NEPHILEX_DASHBOARD_TOKEN`.
- **`nephilex push` refuses `http://`** except for loopback hosts.
- **The MCP server only scans inside its working directory** (or
  `NEPHILEX_MCP_ROOTS`).
- **A DAST URL in the scanned project's own `.nephilex.yml` is ignored.** Use
  `--live-target` or `NEPHILEX_DAST_URL`.
- **`nephilex fix` runs your git commit hooks** and commits with your own git
  identity. It refuses to run when `HEAD` is not the base branch.
- **`watch` state directory names changed**, so the first cycle after
  upgrading records a fresh baseline.

### Security
- Scanning a repository can no longer execute code through its `.git/config`
  (`core.fsmonitor`, `gpg.program`, `diff.external`, textconv); every git call
  runs with hardened config overrides, timeouts and bounded output.
- GitHub Action inputs are passed to the shell through the environment instead
  of being interpolated, closing a command-injection path for workflows that
  forward untrusted event data. On pull requests the Action now reads Nephilex
  config from the base branch (`pr-config-from-base`).
- Regular expressions that a crafted file could drive into minutes of
  backtracking were rewritten to linear forms, and every line-based search is
  bounded.
- Secret values are masked everywhere they appear in a snippet, including
  second tokens on the same line and CI/CD and container findings.
- Dashboard: DNS-rebinding and cross-site request protection, security headers,
  optional token authentication, request size limits, owner-only database
  permissions, and clamped report timestamps.
- DAST and live posture probes verify the connected peer address, refuse
  redirects into private networks, and cap response size.
- Markdown reports, PR review comments and fix PR bodies escape untrusted text,
  links, HTML and @mentions.
- Every prompt sent to a model fences and caps the scanned snippet;
  AI-proposed patches are never marked verified.
- Remote clones are bounded, skip Git LFS downloads, and never leak temporary
  directories on timeout.

### Added
- `--config-from-ref REF` on `scan`, `review`, `policy check` and
  `baseline create`: read Nephilex config from a git ref (the base branch) and
  treat the checked-out tree as untrusted.
- `fix --no-verify` to skip commit hooks explicitly.
- `ai.max_findings` (default 25): only the highest-risk findings are sent to a
  model; the rest get offline reasoning.
- `NEPHILEX_AI_TIMEOUT`, `NEPHILEX_AI_MAX_RETRIES`, `NEPHILEX_GIT_TIMEOUT`,
  `NEPHILEX_MCP_SCAN_TIMEOUT`, `NEPHILEX_DASHBOARD_MAX_SCANS`,
  `NEPHILEX_WATCH_KEEP_SNAPSHOTS` and `NEPHILEX_DAST_URL`.
- New informational findings when part of an analysis could not run:
  `<scanner>.analysis-skipped`, `secrets.history-scan-failed`,
  `secrets.history-scan-incomplete`, `agent.step-failed`, `fim.file-created`,
  `fim.unreadable`, `host.ssh-config-unreadable`, `host.check-failed`.
- Python 3.13 support, CodeQL and dependency review in CI, signed build
  provenance and SBOM attestations for releases and the container image.
- Governance: `GOVERNANCE.md`, `MAINTAINERS.md`, `SUPPORT.md`, a complete
  security policy, the full Contributor Covenant, and DCO sign-off.
- **Versioned plugin API**: `nephilex.plugin_api` is the public import surface for
  scanners, reporters and AI providers, versioned by `PLUGIN_API_VERSION` (1).
  Plugin base classes carry `api_version`; a plugin built for a different
  version is skipped with a logged warning instead of being loaded. See
  "Stability and versioning" in `docs/plugins.md`.

### Changed
- `ScannerContext` is now a dataclass. Construction and attribute access are
  unchanged.
- The CLI is split into one module per command group under
  `nephilex.cli.commands`; commands, options, help text and exit codes are
  unchanged. `nephilex.cli.main:app` remains the entry point.
- All git calls go through one hardened runner, `nephilex.core.gitexec`. The fix
  and review workflow, the dependency diff and `--config-from-ref` now get the
  same config pins, timeouts and output caps as the git-based scanners. Git
  never prompts for credentials (`GIT_TERMINAL_PROMPT=0`).
- The default Anthropic model is `claude-sonnet-5-5` (override with
  `NEPHILEX_AI_MODEL`, `ai.model` or `--ai-model`); model calls default to a 60 s
  timeout and 2 retries; the default `max_tokens` is 4096.
- `nephilex watch` re-reads the target every cycle, keeps running after a failed
  cycle, and prunes old snapshots. The host agent keeps monitoring when a step
  or push fails, and reports the failure.
- The `ci` profile disables the scan cache.
- `--diff` keeps every finding (with a warning) when the diff cannot be
  computed, and works when scanning a subdirectory.
- PR review comments use repository-relative paths and the summary is capped
  at 50 entries.
- The malware scanner reports findings in test files at lower severity
  instead of skipping them, and never skips `conftest.py` or `setup.py`.
- The container image is pinned by digest and installed from the hash-locked
  dependency set.

### Fixed
- `sbom` and `inventory` JSON on stdout is no longer wrapped or stripped.
- `nephilex watch` saw only the first cycle's files.
- The host agent never detected listening ports on Linux and crashed on
  unreadable `sshd_config`; file integrity monitoring missed new files,
  directory contents and unreadable files.
- Packages beyond a fixed count were silently dropped from OSV lookups.
- Deeply nested files or malformed manifests could zero out a whole scanner or
  crash the scan.
- The auth map ranked risks in the wrong order; PostgreSQL was detected from
  "jpg" and "upgrade"; the reachability risk boost and the AWS credential
  attack chain never fired.
- JUnit and SARIF output stay valid for any path or text; GitLab report ids are
  unique.
- The fix applier keeps original line endings, skips non-UTF-8 files, and
  restores the working tree and branch on failure.
- `nephilex dependencies`, `nephilex supply-chain` and `nephilex sbom` exit 2 with a
  message for an unknown or option-like `--diff` ref instead of a traceback.
- `ScanEngine.scan` no longer modifies the `Project` passed in, so its
  `exclude_paths` no longer carry over to a later scan of the same object.

## [0.8.1] - 2026-09-07

### Added
- **`malware` scanner**: backdoors, webshells, obfuscated exec, reverse shells,
  cryptominers, credential exfiltration, suspicious npm install scripts.
- **`lang-sast`**: Go, C#, Kotlin, Swift, shell, and PowerShell rules.

### Fixed
- **Deep profile**: `ast-python-interproc` renamed to `ast-python-xfile` (cross-file taint).
- **Authz precision**: skip test files and public auth routes; detect router-level
  `Depends()`; reduce false positives on token-in-URL heuristics.

## [0.8.0] - 2026-09-07

Platform expansion: supply chain, policy engine, SBOM, infrastructure scanning,
and the `nephilex.commands` entry point for add-on CLI commands.

### Added
- **Supply chain**: malicious package intel, typosquat detection, npm behavior
  metadata, `nephilex supply-chain` command.
- **SBOM**: CycloneDX and SPDX output, SBOM diff via `nephilex sbom --diff`.
- **Policy engine**: `nephilex policy check` with YAML policies.
- **Dependency diff**: `nephilex dependencies --diff` for pull-request review.
- **Infrastructure scanning**: `cicd`, `container`, and `cloud` scanners;
  focused CLI commands `nephilex cicd`, `nephilex container`, `nephilex cloud`.
- **Additional scanners**: authz, API security (OpenAPI), provenance, dependency-diff.
- **Reachability**: npm import reachability and Python symbol-level tier.
- **Docs**: infrastructure scanning guide.
- **Plugin CLI commands**: third-party packages can add `nephilex` subcommands
  through the `nephilex.commands` entry point.

### Fixed
- `os.system` with a constant command (`"df -h"`, `"find ."`) no longer reported
  as command injection.
- `--config` pointing at a missing file is now an error (exit 2) instead of
  silently falling back to defaults and disabling `fail_on` gating.
- JavaScript `eval`/`Function` sink no longer matches names that merely end in
  those words (`retrieval`, `myFunction`); `toString()` is no longer treated as
  a sanitizer.
- OSV advisories that carry only a CVSS v3 vector are scored from the vector
  instead of defaulting to Medium.
- Secret verification treats HTTP 403 as unknown rather than invalid, so a live
  but rate-limited or forbidden credential is never downgraded.

## [0.7.0] - 2026-07-14

The largest release so far: AI-era security coverage, deeper code analysis,
signal-quality features, and frictionless distribution. It also folds in the
JavaScript/TypeScript AST scanner and the web dashboard, which were built but
never released.

### Added
- **AST data-flow (taint) scanner for JavaScript/TypeScript** via tree-sitter:
  follows untrusted input through multiple hops into sinks, and treats
  parameterized queries and sanitized values as safe.
- **Web dashboard** (optional extra `[dashboard]`): a FastAPI and SQLModel app
  with scan history and risk trends, started with `nephilex dashboard`.
- **LLM / AI-application security scanner** (`llm`), mapped to the OWASP Top 10
  for LLM Apps: insecure handling of model output (taint pass into
  `eval`/`exec`/shell/SQL/HTML sinks), prompt injection, secrets in prompts,
  over-privileged agent tools, `trust_remote_code=True`, unsafe `torch.load`
  pickle loading, and HTTP model downloads. Runs only on files that use an
  LLM/agent stack. See `docs/llm-security.md`.
- **Secret verification** (opt-in, `--verify-secrets`): read-only calls confirm
  whether a detected credential is actually **live** (GitHub, Stripe, Slack,
  OpenAI, Google), escalating confirmed ones to Critical and clearing format
  false positives. Local targets only, never in CI templates; the secret is
  never stored in a finding, cache, or report.
- **Live-target posture checks** (`--live-target <url>`, and `nephilex scan <url>`):
  safe, read-only, non-intrusive runtime checks, security headers, cookie
  flags, HTTP-vs-HTTPS transport, version disclosure, and a short allowlist of
  exposed sensitive paths (`/.env`, `/.git/config`, …). A pre-DAST layer, not a
  crawler or fuzzer.
- **Cross-file / inter-procedural taint** (`ast-python-xfile`, needs the `[ast]`
  extra): follows untrusted input one hop across a function, and file,
  boundary into a sink (e.g. a route in `routes.py` passing request data to a
  helper in `db.py` that builds a query). Deliberately high-precision: depth-1
  and requires a direct source at the call site, so a name collision alone never
  fires.
- **Go SAST rules**: SQL injection via `fmt.Sprintf`, command injection via a
  shell, weak hashes (MD5/SHA-1), and SSRF from a dynamic URL.
- **Community rules in YAML** (`scanner_options.patterns.rules`, and the
  convention dir `.nephilex/rules/*.yml`): add SAST rules with only regex + a few
  fields, no Python. Invalid rules are skipped, not fatal. Example in
  `examples/custom-rules/`.
- **GitLab SAST reporter** (`-f gitlab`): emits a GitLab Secure SAST report so
  findings show in the merge-request security widget and Vulnerability Report.
- **Expanded auto-fix**: deterministic rewrites for `trust_remote_code=True` and
  `torch.load(...)` (adds `weights_only=True`), and an explicit **AI-proposed fix
  tier**, model-drafted patches are verified when possible and labeled
  `human-review-required`; only deterministic fixes are ever auto-applied.
- Nephilex now ships its own `.nephilex.yml` and scans itself clean in CI (dogfooding).

### Fixed
- `exclude_paths` now honors real glob patterns (`examples/**`, `*.min.js`, a
  specific file path) as documented; previously only bare directory names were
  matched, so file and subtree globs were silently ignored.

#### Distribution
- **Official GitHub Action** (`action.yml`): one-block CI setup with SARIF
  upload to GitHub Code Scanning and automatic diff-aware baseline scanning on
  pull requests.
- **pre-commit hooks** (`.pre-commit-hooks.yaml`): `nephilex-secrets` (fast,
  secrets-only, made for every commit) and `nephilex` (full static scan).
- **Official Docker image** published to `ghcr.io/nephilex/nephilex`
  (linux/amd64 + linux/arm64) on every release.
- **Reachability analysis (experimental, `--reachability`)**: dependency
  findings for Python projects gain an *imported / not imported* verdict, so a
  CVE in a package your code never imports is visibly lower-priority. First
  tier of the reachability roadmap; Python only for now.
- **Per-file scan caching**: file-local scanners cache findings by file
  content hash, so warm scans re-analyze only changed files. On by default;
  `--no-cache` / `cache: false` disables. Determinism is preserved, cached
  and uncached scans produce byte-identical reports (enforced by tests).
- **Concurrent scanners**: independent scanners now run in a thread pool
  (`parallel: false` to disable), with deterministic result ordering.
- **Benchmark harness** (`benchmarks/`): reproducible finding inventories on
  Juice Shop, DVWA, WebGoat, and (locally) NIST SARD, with commits recorded.
- Published scan-time numbers in `docs/performance.md`.
- Bitbucket Pipelines and expanded GitLab CI documentation.

## [0.6.1] - 2026-07-05

### Fixed
- Rich markup no longer eats bracketed text in CLI tables (e.g. `[ast]`).

## [0.6.0] - 2026-07-05

### Added
- **AST data-flow (taint) scanner for Python** via tree-sitter (optional extra
  `[ast]`), closing SQL-injection and path-traversal detection gaps.

### Changed
- OSV client hardened: batches all packages in one request, caches responses on
  disk, retries transient failures.
- Top-level `--version` / `-V` flag.

## [0.5.0] - 2026-07-04

### Added
- Baseline / diff-aware scanning: report only findings not present in a
  previous JSON report, matched by content-based fingerprint.
- Multi-ecosystem SCA via lockfiles: PyPI (`poetry.lock`, `Pipfile.lock`), npm
  (`package-lock.json`, `yarn.lock`), Go (`go.mod`), Rust (`Cargo.lock`), Ruby
  (`Gemfile.lock`), PHP (`composer.lock`), transitive dependencies included.
- Remote-config hardening: `.nephilex.yml` inside a cloned remote repo is ignored
  unless `--trust-remote-config` is passed.

## [0.2.0] - 2026-07-04

### Added
- Live vulnerability data from [OSV.dev](https://osv.dev) in the dependency
  scanner, with a bundled offline advisory seed as fallback.

## [0.1.1] - 2026-07-04

### Fixed
- False positives found by scanning real-world repositories.

## [0.1.0] - 2026-07-04

Initial release: five-stage pipeline (resolve, analyze, scan, enrich,
report); secrets, dependency, SAST-pattern, and IaC scanners; AI enrichment
with heuristic (offline), Anthropic, OpenAI, and Ollama providers; Attack
Simulation Mode; deterministic verified auto-fix with branch + pull-request
creation (`nephilex fix`); JSON, SARIF, Markdown, HTML, and CSV reporters; plugin
entry-point system for scanners, reporters, and providers.

[Unreleased]: https://github.com/nephilex/nephilex/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/nephilex/nephilex/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/nephilex/nephilex/compare/v0.9.0...v0.10.0
[0.9.1]: https://github.com/nephilex/nephilex/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/nephilex/nephilex/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/nephilex/nephilex/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/nephilex/nephilex/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/nephilex/nephilex/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/nephilex/nephilex/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/nephilex/nephilex/compare/v0.5.1...v0.6.0
[0.2.0]: https://github.com/nephilex/nephilex/releases/tag/v0.2.0
[0.1.0]: https://github.com/nephilex/nephilex/releases/tag/v0.1.0
