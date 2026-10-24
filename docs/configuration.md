# Configuration

Nephilex reads configuration from, in increasing precedence:

1. Built-in defaults.
2. `.nephilex.yml` (or `.nephilex.yaml`) in the project root.
3. A file passed with `--config`.
4. Command-line flags.

Generate a starter file with `nephilex init`.

## Full reference

```yaml
# Scanners to run. Empty = every scanner that applies to the project.
scanners: []            # e.g. ["secrets", "patterns"]

# Scanners to skip (applied after the list above).
exclude_scanners: []    # e.g. ["iac"]

# Extra path globs to ignore, added to the built-in ignore list
# (.git, node_modules, venv, build artifacts, etc.).
exclude_paths: []       # e.g. ["tests/fixtures/*", "*.min.js"]

# In a git work tree, untracked files that .gitignore (or .git/info/exclude)
# ignores are skipped; tracked files are always scanned. true scans the
# ignored files too. CLI: --include-ignored. See "Files that are scanned".
include_ignored: false

# Minimum severity to report: info | low | medium | high | critical
min_severity: info

# Exit non-zero if any finding is at/above this severity. Empty = never fail.
# Use this to gate CI.
fail_on: ""             # e.g. high

# Fail the run when a scanner crashes. Unset (the default) means: fail whenever
# fail_on is set, because a crashed scanner reports nothing and a gate must not
# read that as a pass. CLI: --fail-on-error / --no-fail-on-error.
# fail_on_error: true

# Attack Simulation Mode: safe, sandboxed exploit demonstrations per finding.
attack_simulation: false

# Generate fix patches (and verify the deterministic ones). Nephilex's
# deterministic, verified fixes are attached even with AI enrichment off
# (--no-ai); only model-proposed drafts need a provider.
generate_patches: false

# Reuse cached findings for unchanged files (content-hash keyed; file-local
# scanners only). CLI: --no-cache. See docs/performance.md.
cache: true

# Run scanners concurrently. Reports are deterministic either way.
parallel: true

# Record fixes and suppressions (allowlist entries, exceptions, inline
# nephilex-ignore comments, baselines) in the hash-chained .nephilex/audit.log.
# Trusted local projects only. NEPHILEX_AUDIT_LOG=off also turns it off.
# See docs/audit-log.md.
audit_log: true

# Python library mode: auto | on | off (default auto). In library mode the
# parameters of public functions are taint sources, and their findings are
# reported at low confidence, tagged public-api, and do not count toward
# fail_on. auto turns it on for a project with pyproject.toml, setup.py or
# setup.cfg and no recognized web application entry point. Quote "on" and
# "off" (bare on/off are YAML booleans, which are also accepted).
# See docs/scanners.md, "Library mode".
library_mode: auto

ai:
  # heuristic (offline, default) | anthropic | openai | ollama (local)
  provider: heuristic
  model: ""             # provider-specific; empty uses the provider default
  enabled: true         # false disables all AI enrichment
  temperature: 0.0
  max_tokens: 4096
  max_findings: 25      # only the highest-risk findings go to a model; the rest
                        # get offline reasoning (keeps CI runs bounded)

# Per-scanner options, keyed by scanner name.
scanner_options:
  secrets:
    entropy: true             # enable high-entropy string detection
    entropy_threshold: 4.0    # bits; raise to reduce false positives
    verify: false             # opt-in live check (CLI: --verify-secrets)
  dependencies:
    online: true              # query the OSV database for real, current CVEs
    timeout: 15               # seconds for OSV lookups
    cache: true               # cache OSV records on disk to speed repeat scans
    reachability: false       # experimental: imported/not-imported (Python + npm)
    symbol_reachability: false  # tier-2: Python symbol usage vs OSV hints
  supply-chain:
    online_intel: true        # merge bundled + remote malicious-package feeds
  dependency-diff:
    ref: ""                   # git ref for PR diff (set by --diff / supply-chain)
    behavior: true            # npm registry metadata anomaly checks
    sandbox: auto             # auto | host | docker for metadata fetch
  provenance:
    require_for_releases: false

# Security policies - see docs/policy.md
policies: []
```

## Files that are scanned

Nephilex walks the target directory and skips the directories that are noise for
security analysis (`.git`, `node_modules`, `vendor`, `dist`, `build`, virtual
environments, caches) and anything matching `exclude_paths`.

When the target is inside a git work tree, Nephilex also asks git which
untracked files it ignores (`git ls-files --others --ignored
--exclude-standard`, run with the same hardening as every other git call) and
skips them: build output, local virtual environments, editor and assistant
folders such as `.claude/`, a local `.env`. What is scanned matches what git
would commit:

- **Tracked files are always scanned**, even when a `.gitignore` pattern
  matches them. Ignore rules only apply to untracked files, so a pull request
  cannot hide committed code by adding a pattern to `.gitignore`.
- Untracked files that are not ignored (new files you have not added yet)
  are scanned.
- Outside a git work tree, when git is not installed, or when the target
  directory is itself ignored, every file is walked as before.

`--include-ignored` (or `include_ignored: true`) scans the ignored files too,
as earlier releases did. Files over 2 MB and symlinks that
point outside the project are skipped either way.

## Secret verification (opt-in)

`--verify-secrets` (or `scanner_options.secrets.verify: true`) makes a **single,
read-only** call per detected secret to confirm whether it is actually live,
GitHub, Stripe, Slack, OpenAI, and Google keys are supported; others report as
unverified. A confirmed-live credential is escalated to Critical; a rejected one
is downgraded. This makes authenticated network requests with the candidate
credential, so it is **off by default, restricted to local targets** (never a
cloned remote repo), and deliberately absent from the shipped CI templates. The
secret value is used only for the request, it is never written to a finding,
the cache, or a report.

## Runtime posture checks (`--live-target`)

`--live-target <url>` runs a safe, read-only posture pass against a deployed URL
alongside the static scan (or scan a URL directly with `nephilex scan <url>`): it
checks security headers, cookie flags, HTTP-vs-HTTPS transport, version
disclosure, and a short allowlist of exposed sensitive paths. It is
non-intrusive, only GETs, no payloads or exploitation, but still: **only point
it at systems you are authorized to assess.** It is a pre-DAST layer, not a
crawler or fuzzer.

## Dependency scanning and OSV

The dependency scanner checks your declared packages against the public
[OSV database](https://osv.dev), which covers thousands of advisories across
ecosystems. Only **package names and versions** are sent to OSV, never your
source code, so this preserves Nephilex's offline-first stance. Set
`scanner_options.dependencies.online: false` to use only the small bundled seed
(fully offline); Nephilex also falls back to the seed automatically if OSV is
unreachable.

Lookups are batched (no dependency is silently dropped), retried with backoff on
transient failures, and cached on disk so repeat scans are fast. The cache lives
under `~/.cache/nephilex/osv` by default; override it with the `NEPHILEX_CACHE_DIR`
environment variable, or disable it with `scanner_options.dependencies.cache: false`.

### Reachability (experimental)

Most dependency alerts concern packages your code never even imports. With
`--reachability` (or `scanner_options.dependencies.reachability: true`), Nephilex
annotates each PyPI dependency finding with an **import-level verdict**:
*imported* (first-party code imports the package, treat as actionable) or
*not imported* (no import found, deprioritized to an unlikely likelihood, but
**never suppressed**, since dynamic imports and framework hooks are not traced).
The verdict appears in the finding description and as `reachability` in finding
metadata in JSON/SARIF reports. Supported for **Python and npm** at import level;
add `--symbol-reachability` for Python symbol-level hints when OSV provides them.

See also [policy.md](policy.md) for the policy engine.

## Code scanning: two tiers

Nephilex scans source code with two complementary scanners:

- **`patterns`** (always on), a fast, regex-based pass with a lightweight
  single-hop taint check. Broad language coverage, catches the common cases.
- **`ast-python`** and **`ast-js`** (optional), tree-sitter data-flow analyzers
  for **Python** and **JavaScript/TypeScript** that track tainted values through
  *multiple* variable hops, so they catch injection the regex tier misses
  (e.g. `x = req.query.id`, then `y = x`, then `db.query('... ' + y)`). They also avoid
  the regex tier's common false positives: a **parameterized query**
  (`db.query('... WHERE id = ?', [id])`) and **sanitized** values
  (`DOMPurify.sanitize(...)`, `Number(...)`, `secure_filename(...)`) are treated
  as safe. Enable with:

  ```bash
  pip install "nephilex[ast]"
  ```

  Without the extra, the AST scanners report as not-applicable and Nephilex uses the
  regex tier, nothing breaks. When both tiers run, findings for the same weakness
  are de-duplicated (the higher-confidence AST finding wins), so you never see one
  issue reported twice.

### Library mode (`library_mode`)

| Value | Effect |
| --- | --- |
| `auto` (default) | On when the scan root has `pyproject.toml`, `setup.py` or `setup.cfg` and no web application entry point is found (`Flask()`, `FastAPI()`, `Starlette()`, `get_wsgi_application()` and the others listed in [Scanners](scanners.md#library-mode)); off otherwise |
| `on` | Always on, for example for a library whose repository also ships a demo app |
| `off` | Never on |

Any other value is a configuration error (exit 2), like the other keys. YAML
reads a bare `on`/`off` as `true`/`false`; both forms are accepted. The JSON
report records the decision under `project_summary.library_mode` (`setting`,
`active`, `reason`). Library-mode findings carry the tag `public-api`, are low
confidence and never fail `fail_on`; the reasoning is in
[Scanners](scanners.md#library-mode).

## Common recipes

**Fast secrets-and-deps check, fail the build on High+:**

```yaml
scanners: [secrets, dependencies]
fail_on: high
```

**Everything, with the flagship features, using a local model:**

```yaml
attack_simulation: true
generate_patches: true
ai:
  provider: ollama
  model: llama3.1
```

**Quiet down a noisy entropy scanner:**

```yaml
scanner_options:
  secrets:
    entropy_threshold: 4.5
```

## Environment variables

Credentials for cloud providers and git hosts are read from the environment (see
`.env.example`):

| Variable | Used by |
|----------|---------|
| `ANTHROPIC_API_KEY` | `anthropic` provider |
| `OPENAI_API_KEY` | `openai` provider |
| `OLLAMA_HOST` | `ollama` provider (default `http://localhost:11434`) |
| `GITHUB_TOKEN` / `GITLAB_TOKEN` | opening pull requests with `nephilex fix --open-pr` |
| `NEPHILEX_AI_MODEL` | model override for the configured provider |
| `NEPHILEX_AI_TIMEOUT` / `NEPHILEX_AI_MAX_RETRIES` | per-call model timeout in seconds (default 60) and retries (default 2) |
| `NEPHILEX_GIT_TIMEOUT` | timeout for git commands in seconds (default 300) |
| `NEPHILEX_CACHE_DIR` | cache location for scan results and OSV data |
| `NEPHILEX_DAST_URL` | target for dynamic checks (same as `--live-target`) |
| `NEPHILEX_MCP_ROOTS` / `NEPHILEX_MCP_SCAN_TIMEOUT` | directories the MCP server may scan, and its scan timeout (default 600) |
| `NEPHILEX_DASHBOARD_TOKEN` / `NEPHILEX_DASHBOARD_ALLOWED_HOSTS` / `NEPHILEX_DASHBOARD_MAX_SCANS` | dashboard access control and retention, see [Web dashboard](dashboard.md) |
| `NEPHILEX_WATCH_KEEP_SNAPSHOTS` | number of `nephilex watch` snapshots kept per target (default 50) |

## Which configuration is trusted

The scanned repository is treated as untrusted input, because in CI it is
often a pull request from someone outside your team. Its configuration could
otherwise exclude every path, switch scanners off, or allowlist its own
findings.

| Situation | `.nephilex.yml`, `.nephilex/rules`, `.nephilex/exceptions.yml`, `.nephilex/context.yml`, `nephilex-ignore` comments |
|---|---|
| Local path (`nephilex scan .`) | Honoured |
| Cloned remote (`nephilex scan https://...`) | Ignored unless `--trust-remote-config` |
| `--config-from-ref REF` | `.nephilex.yml` and `.nephilex/context.yml` read from that git ref; the checked-out tree is untrusted, so its rules, exceptions and comments are ignored |
| `--config PATH` | That file is always honoured (you chose it) |
| `nephilex agent`, `nephilex mcp` | The monitored or scanned directory is never trusted |

`.nephilex/context.yml` declares sanitizers and trusted sources that switch
checks off, so it follows the same rule as `.nephilex.yml`; see
[Project context](context.md#trust-rules). The audit log is written only
when the project is trusted and local.

For pull requests, use `--config-from-ref origin/<base-branch>` so the gate uses
the configuration already merged on the base branch. The GitHub Action does
this automatically (`pr-config-from-base`, on by default).

## CLI flags

Every relevant config field has a flag, which overrides the file:

```
nephilex scan TARGET
  -c, --config PATH         path to a .nephilex.yml config file
  -s, --scanners a,b        run only these scanners
      --exclude a,b         skip these scanners
  -f, --format FMT          output format (repeatable): table json sarif markdown html csv
  -o, --output PATH         write reports (a directory writes one file per format)
      --baseline PATH       report only findings not present in a saved JSON report
      --ai-provider NAME    heuristic | anthropic | openai | ollama
      --ai-model ID         model override
      --no-ai               disable AI enrichment
      --include-ignored     also scan untracked files that git ignores
      --attack-sim          enable Attack Simulation Mode
      --patches             generate/verify fix patches (deterministic ones also with --no-ai)
      --min-severity SEV    report findings at/above this severity
      --fail-on SEV         non-zero exit if any finding is at/above this severity
      --[no-]fail-on-error  fail (or not) when a scanner crashes
      --live-target URL     run safe, read-only posture checks against a URL you own
  -b, --branch NAME         branch to clone for remote targets
      --trust-remote-config load .nephilex.yml from a cloned remote repo (off by default)
      --config-from-ref REF read config from a git ref; treat the tree as untrusted
  -q, --quiet               suppress progress output
```
