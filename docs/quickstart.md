# Quickstart

This page takes you from nothing to a scan, two report files, a CI gate and an
editor hook in about five minutes. Every command below was run on Windows 11
with Python 3.11 on 2026-10-23, first with Nephilex 0.10.0 from PyPI and again
with the 0.11.0 code where 0.11.0 changed the output (the `check` example and
the missing `[ast]` messages). The output shown is what it printed. Trimmed
output is marked as trimmed.

All scans here use `--no-ai`, which turns off finding enrichment so the output
is reproducible. You never need an API key: without `--no-ai` Nephilex uses its
offline `heuristic` provider.

## 1. Install

You need Python 3.10 or newer. Install the `[ast]` extra: it adds the
tree-sitter parsers that the data-flow (taint) scanners need.

=== "pipx (recommended for a CLI)"

    ```bash
    pipx install "nephilex[ast]"
    ```

=== "pip in a virtual environment"

    ```bash
    python -m venv .venv
    # Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
    python -m pip install "nephilex[ast]"
    ```

Check it:

```bash
nephilex --version
```

```text
Nephilex v0.11.0
```

## 2. Scan the demo app

The repository ships a small Flask app with deliberate vulnerabilities in
[`examples/vulnerable-app`](https://github.com/nephilex/nephilex/tree/main/examples/vulnerable-app).
Never deploy it.

```bash
git clone --depth 1 https://github.com/nephilex/nephilex.git
nephilex scan nephilex/examples/vulnerable-app --no-ai
```

Expected output (trimmed: 18 of the 20 table rows are left out):

```text
- Analyzing project structure...
- AI enrichment: off
- Skipping scanner 'agent-config' (not applicable).
- Skipping scanner 'api' (not applicable).
- Skipping scanner 'ast-js' (not applicable).
- Skipping scanner 'cicd' (not applicable).
- Skipping scanner 'cloud' (not applicable).
- Skipping scanner 'git-security' (not applicable).
- Skipping scanner 'lang-sast' (not applicable).
- Skipping scanner 'llm' (not applicable).
- Skipping scanner 'provenance' (not applicable).
- Running scanner: dependencies
- Running scanner: patterns
- Running scanner: ast-python
- Running scanner: ast-python-xfile
- Running scanner: authz
- Running scanner: business-logic
- Running scanner: secrets
- Running scanner: container
- Running scanner: container-image
- Running scanner: dast
- Running scanner: dependency-diff
- Running scanner: iac
- Running scanner: malware
- Running scanner: supply-chain
- Done: 20 finding(s), highest severity Critical.
┌────────────────────────────────────────────── Nephilex scan ──────────────────────────────────────────────┐
│ vulnerable-app                                                                                            │
│ Aggregate risk: 99.7/100   Findings: 20                                                                   │
│ Critical: 2 | High: 8 | Medium: 9 | Low: 1 | Info: 0                                                      │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌──────────┬──────┬───────────────────────────────────┬──────────────────┬──────────────────────────────────┐
│ Sev      │ Risk │ Title                             │ Location         │ Rule                             │
├──────────┼──────┼───────────────────────────────────┼──────────────────┼──────────────────────────────────┤
│ High     │ 72.8 │ SQL injection (tainted value      │ app.py:29        │ ast-python.ast-sql-injection     │
│          │      │ reaches a database query)         │                  │                                  │
│ High     │ 70.5 │ Unsafe yaml.load without          │ app.py:45        │ patterns.python-yaml-load        │
│          │      │ SafeLoader                        │                  │                                  │
└──────────┴──────┴───────────────────────────────────┴──────────────────┴──────────────────────────────────┘
┌──────────────────────────────────────────── Security posture ─────────────────────────────────────────────┐
│ Security posture: REVIEW                                                                                  │
│ High-severity issues found; review before release.                                                        │
│                                                                                                           │
│   - Critical: 2, High: 8. No --fail-on gate is active.                                                    │
│   - Add --fail-on high in CI to block merges automatically.                                               │
│   - Aggregate risk 99.7/100 (lower is better; track the trend over time).                                 │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

What to look for:

- `Running scanner: ast-python` confirms the `[ast]` extra is installed. If it
  says `Skipping scanner 'ast-python' (needs the [ast] extra: ...)` instead,
  see [Common problems](#common-problems).
- "Not applicable" means the project has no files that scanner reads (no CI
  workflows, no Terraform, no LLM client code, and so on).
- The five dependency findings come from live [OSV](https://osv.dev) data, so
  the count can change as advisories are published.

The [landing page](index.md) shows the first eight rows; the HTML report below
has all 20. The [example finding](example-finding.md) follows the `yaml.load`
row from detection to fix.

## 3. Write an HTML report

```bash
nephilex scan nephilex/examples/vulnerable-app --no-ai --patches -f html -o report.html
```

Expected output (trimmed: the progress lines are left out):

```text
- Done: 20 finding(s), highest severity Critical.
Wrote report.html
```

`report.html` is a single self-contained file with no scripts. It has one
section per finding with the explanation, the CWE/OWASP mapping and, because
of `--patches`, a suggested patch where Nephilex has a deterministic fix.
When you pass `-f` with a file format, the terminal table is not printed.

## 4. Write a JSON or SARIF report

```bash
nephilex scan nephilex/examples/vulnerable-app --no-ai -f sarif -o results.sarif
nephilex scan nephilex/examples/vulnerable-app --no-ai -f json -o results.json
```

Each prints `Wrote results.sarif` or `Wrote results.json` after the progress
lines. Give `-o` a directory and repeat `-f` to write several formats in one
run:

```bash
nephilex scan nephilex/examples/vulnerable-app --no-ai -f json -f sarif -o reports
```

```text
- Done: 20 finding(s), highest severity Critical.
Wrote reports\nephilex-report.json
Wrote reports\nephilex-report.sarif
```

(Trimmed: the progress lines are left out. The paths use `\` because this ran
on Windows.)

The SARIF file is version 2.1.0 with 20 results. This is the result for the
`yaml.load` finding, copied from `results.sarif`:

```json
{
  "ruleId": "patterns.python-yaml-load",
  "level": "error",
  "message": {
    "text": "Unsafe yaml.load without SafeLoader, Attack: Feed a YAML payload using `!!python/object/apply` tags to execute code., Fix: Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader)."
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "app.py"
        },
        "region": {
          "startLine": 45,
          "endLine": 45,
          "snippet": {
            "text": "    return str(yaml.load(raw))"
          }
        }
      }
    }
  ],
  "partialFingerprints": {
    "nephilexFingerprint": "patterns.python-yaml-load|app.py|ee7664839c3a"
  },
  "properties": {
    "confidence": "High",
    "riskScore": 70.5
  }
}
```

The JSON report holds the full finding objects; the
[example finding](example-finding.md) shows one. Run `nephilex reporters` for
the other formats.

## 5. Fail a build on High findings

`--fail-on high` makes the command exit with status 1 when any finding is High
or Critical. A failed gate is not a crash: it is the signal your CI uses.

```bash
nephilex scan nephilex/examples/vulnerable-app --no-ai --fail-on high
```

Expected output (trimmed: the progress lines and the findings table are left
out):

```text
┌──────────────────────────────────────────── Security posture ─────────────────────────────────────────────┐
│ Security posture: FAIL                                                                                    │
│ Does not meet your High gate; fix before merge or deploy.                                                 │
│                                                                                                           │
│   - Critical: 2, High: 8, Medium: 9, Low: 1.                                                              │
│   - Address Critical and High findings first (secrets, RCE, serious CVEs).                                │
│   - Re-run with the same profile after fixes; exit code 0 means you pass.                                 │
│   - Docs: github.com/nephilex/nephilex/blob/main/docs/understanding-results.md                            │
│                                                                                                           │
│ Gate: --fail-on High  Risk: 99.7/100                                                                      │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
Failing: findings at/above High.
```

Check the exit status:

=== "bash"

    ```bash
    nephilex scan nephilex/examples/vulnerable-app --no-ai --fail-on high --quiet > /dev/null
    echo $?
    ```

    ```text
    Failing: findings at/above High.
    Does not meet your High gate; fix before merge or deploy.
    1
    ```

=== "PowerShell"

    ```powershell
    nephilex scan nephilex/examples/vulnerable-app --no-ai --fail-on high --quiet > $null
    $LASTEXITCODE
    ```

    ```text
    Failing: findings at/above High.
    Does not meet your High gate; fix before merge or deploy.
    1
    ```

With `--quiet` the two gate lines go to stderr, so they stay visible when you
redirect the report. Exit codes and severities are explained in
[Understanding scan results](understanding-results.md#exit-codes).

## 6. Run it in GitHub Actions

This is the workflow from [CI/CD integration](ci-cd.md), which uses the
official Action in this repository (`action.yml`):

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  nephilex:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # full history enables diff-aware PR scanning
      - uses: nephilex/nephilex@v0.12.0
        with:
          fail-on: high      # block merges on newly introduced High+ findings
```

The Action writes SARIF and uploads it to GitHub Code Scanning. On pull
requests it scans the base branch first and gates only on findings the pull
request introduces, and it reads `.nephilex.yml` from the base branch so a pull
request cannot loosen its own gate. The inputs are listed in
[CI/CD integration](ci-cd.md#the-official-action-recommended).

The Action installs `nephilex[ast]`, so the `ast-python`, `ast-python-xfile`
and `ast-js` taint scanners run in CI as they do locally.

This snippet was copied from the docs and `action.yml`; it was not run for
this page.

## 7. Set up your editor

`nephilex init --editor` writes the project files that make an editor or AI
assistant run `nephilex check` on each edited file and register the Nephilex
MCP server. Run it in your project root. The choices are `claude`, `cursor`
and `vscode`.

```bash
nephilex init --editor claude
```

```text
Wrote .mcp.json
Wrote .claude/settings.json
Next: restart the editor, approve the nephilex MCP server when asked, and run the checks in
docs/editors.md.
```

`.claude/settings.json` holds the hook:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "nephilex check --hook claude --no-inline-ignores",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

`--editor cursor` writes `.cursor/mcp.json`, `.cursor/hooks.json` and
`.cursor/rules/nephilex.mdc`. `--editor vscode` writes `.vscode/mcp.json` and
`.vscode/tasks.json` (a "Nephilex: check current file" task with a problem
matcher).

You can run the same check yourself. Here it is on `app.py` from the demo app,
inside a git repository holding a copy of it:

```bash
nephilex check app.py
```

```text
app.py:19  critical  secrets.aws-access-key-id  Hardcoded credential: aws access key id
    Fix: Remove the secret from source and rotate it.
app.py:37  high  ast-python.ast-command-injection  OS command injection (tainted value reaches a shell command)
    Fix: Pass arguments as a list without a shell, and validate/quote input.
app.py:29  high  ast-python.ast-sql-injection  SQL injection (tainted value reaches a database query)
    Fix: Use parameterized queries / bound parameters and never build SQL from input, even across intermediate variables.
app.py:45  high  patterns.python-yaml-load  Unsafe yaml.load without SafeLoader
    Fix: Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader).
app.py:20  high  secrets.high-entropy-string  Possible hardcoded secret in 'API_TOKEN'
    Fix: Remove the secret from source and rotate it.
app.py:19  high  chains.secret-plus-injection  Attack chain: injection foothold beside an exposed credential
    Fix: Break the chain: fixing any one link stops this path, fix all for defense in depth.
app.py:45  medium  ast-python.ast-xss  Cross-site scripting (tainted value returned as HTML)
    Fix: Escape output (markupsafe.escape / html.escape), render through an autoescaping template, or return JSON.
app.py:50  medium  patterns.weak-hash-md5-sha1  Weak hash algorithm (MD5/SHA1)
    Fix: Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/Argon2) for passwords.
app.py:55  medium  patterns.flask-debug-true  Flask app running with debug=True
    Fix: Never enable debug mode in production; gate it behind an environment variable defaulting to off.
9 finding(s) in 1 file (1 critical, 5 high, 3 medium); 6 at or above high.
```

`nephilex check` exits 1 here because findings are at or above its default
gate, `high`. It runs only file-local scanners, so dependency findings are left
to `nephilex scan`. It reports the same rule for a line as `nephilex scan`
does. Hook formats, strict mode and speed are covered in
[Editors & AI assistants](editors.md).

## Common problems

Each of these was reproduced for this page.

**The taint scanners do not run (missing `[ast]` extra).** With a plain
`pip install nephilex`, the scan's progress lines include:

```text
- Skipping scanner 'ast-python' (needs the [ast] extra: pip install "nephilex[ast]").
- Skipping scanner 'ast-js' (not applicable).
- Skipping scanner 'ast-python-xfile' (needs the [ast] extra: pip install "nephilex[ast]").
```

(`ast-js` is "not applicable" here only because the demo app has no
JavaScript.) The scan then reports 19 findings on the demo app instead of 20: SQL injection and
command injection come from the regex rules (`patterns.python-sql-format`,
`patterns.python-shell-true`) instead of the taint rules, the cross-site
scripting finding is missing, and `yaml.load` is reported with Medium instead
of High confidence. Fix: `pip install "nephilex[ast]"`
(or `pipx install --force "nephilex[ast]"`).

**Python is too old.** On Python 3.9, `pip install nephilex` fails with:

```text
ERROR: Ignored the following versions that require a different python version: 0.10.0 Requires-Python >=3.10
ERROR: Could not find a version that satisfies the requirement nephilex (from versions: none)
ERROR: No matching distribution found for nephilex
```

Use Python 3.10 or newer (`python --version`). pipx can be pointed at a
specific interpreter with `pipx install --python <path-to-python> "nephilex[ast]"`.

**`nephilex` is not found after installing (Windows PATH).** A
`pip install --user` puts `nephilex.exe` in a per-user `Scripts` folder that is
not on `PATH`, and pip warns about it (the folder path is replaced with a
placeholder here):

```text
WARNING: The script nephilex.exe is installed in '<your user Scripts folder>' which is not on PATH.
Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
```

Either add that folder to `PATH`, run Nephilex as `python -m nephilex` (same
commands and options), or use pipx. pipx prints a similar note when its own
folder is not on `PATH`, and suggests `pipx ensurepath`. The editor files from
`nephilex init --editor` call `nephilex` by name, so the editor also needs it
on `PATH`.

**Fewer dependency findings without network access.** When OSV cannot be
reached the scan continues with a small bundled advisory list and says so:

```text
OSV lookup for PyPI failed (OSV lookup failed: [WinError 10061] No connection could be made because the target machine actively refused it); falling back to the bundled advisory seed, which covers far fewer packages. Findings may be incomplete.
```

On the demo app that run reported 16 findings instead of 20: three dependency
advisories instead of seven.

**`nephilex init --editor` writes nothing.** It refuses to overwrite existing
files and exits 1:

```text
.mcp.json already exists.
.claude/settings.json already exists.
Nothing written. Use --force to merge the Nephilex entries into them.
```

`--force` keeps your other settings and adds or replaces only the Nephilex
entries.

## Next steps

- [Example finding](example-finding.md): one finding from detection to a
  verified fix.
- [Trust and limits](trust.md): what each scanner covers and how accuracy is
  measured.
- [Triage & baselines](triage.md): adopt Nephilex on an existing codebase
  without drowning in old findings.
- [Configuration](configuration.md): `.nephilex.yml` reference.
