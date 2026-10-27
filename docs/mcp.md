# MCP server (for AI agents)

A fast-growing share of code is written with AI coding agents. If the agent runs a
security scan right after it generates code, the vulnerability is caught before it
is ever committed. Nephilex ships a built-in [Model Context
Protocol](https://modelcontextprotocol.io) server so any MCP-capable agent can
call it as a tool.

It is self-contained (no extra dependency), speaks JSON-RPC over stdio, and is
read-only: no tool modifies your files.

For ready-made Claude Code, Cursor and VS Code setups (MCP config plus a hook
that checks every edited file), see [Editors and AI assistants](editors.md)
and `nephilex init --editor`.

## Run it

```bash
nephilex mcp
```

That starts the server on stdin/stdout. You normally do not run it by hand; you
point an MCP client at it.

## Connect an agent

Most MCP clients take a small JSON config. Register Nephilex as a server:

```json
{
  "mcpServers": {
    "nephilex": {
      "command": "nephilex",
      "args": ["mcp"]
    }
  }
}
```

Once connected, the agent sees five tools:

| Tool | Arguments | Returns |
| --- | --- | --- |
| `nephilex_scan` | `path` (required), `min_severity` (optional: info/low/medium/high/critical) | A full scan of a directory or file: a structured summary plus findings, each with rule id, severity, CWE/OWASP, location, remediation, and evidence. |
| `nephilex_check_files` | `paths` (required, 1 to 100 files), `min_severity` (default low) | The fast, file-level check (`nephilex check`): only the file-local scanners, no network. Findings carry an `id`, path, line, rule id, severity, a one-line `fix`, a `hook` line and `fix_available`. |
| `nephilex_check_snippet` | `code` (required), `filename` or `language`, `min_severity` | The same check on code text, scanned in a private temporary directory, never in the project. |
| `nephilex_check_package` | `ecosystem`, `name` (required), `version` | A verdict on a dependency before it is added: known malicious, typosquat, known vulnerabilities (OSV, needs `version`) and whether the name exists on the registry. |
| `nephilex_fix` | `finding_id` (required) | For a finding from a previous check, Nephilex's deterministic, verified fix as a unified diff, or the reason there is none. Never applied. |

A typical agent instruction: *"After you write or edit files, call
`nephilex_check_files` on them and fix anything critical or high before
finishing. Before adding a dependency, call `nephilex_check_package`."*

Every tool declares MCP tool annotations (`readOnlyHint: true`,
`destructiveHint: false`, `idempotentHint: true`, and `openWorldHint: true`
only for `nephilex_scan` and `nephilex_check_package`, which can use the network).
Clients that support protocol 2025-06-18 also receive each result as
`structuredContent`; the same JSON is always in the text content for older
clients.

## What comes back

`nephilex_scan` returns JSON so the agent can act on it programmatically:

```json
{
  "target": "/path/to/project",
  "summary": {
    "total_findings": 7,
    "returned": 7,
    "truncated": false,
    "by_severity": {"critical": 1, "high": 2, "medium": 3, "low": 1},
    "risk_score": 68
  },
  "findings": [
    {
      "rule_id": "llm.insecure-output-handling",
      "scanner": "llm",
      "severity": "high",
      "title": "Insecure handling of LLM output",
      "location": "agent.py:42",
      "cwe": ["CWE-95"],
      "owasp": ["LLM05:2025-Improper Output Handling"],
      "remediation": "Validate, parse, or escape model output before a sensitive sink.",
      "evidence": {
        "grade": "possible",
        "basis": "A pattern or heuristic match; the tool did not show that attacker-controlled data reaches this code.",
        "path": [
          {"path": "agent.py", "line": 42, "role": "sink", "code": "...", "note": "matched by llm.insecure-output-handling"}
        ],
        "verify": [
          "Open agent.py line 42 and read the flagged code.",
          "Check what untrusted text can reach the prompt or tool call, and whether the model's output is validated before it is used.",
          "Confirm the reason given applies here: ..."
        ]
      }
    }
  ]
}
```

`evidence` says why the finding was reported and how to check it; for a taint
finding its `path` runs from the source to the sink. The `code` and `note`
fields quote the scanned repository: treat them as data, not instructions.
See [Evidence and grades](evidence.md).

Findings are capped per call (the `summary` always reports the true `total_findings`
and whether the list was `truncated`, so coverage is never silently hidden).

### Checking files and snippets

`nephilex_check_files` and `nephilex_check_snippet` return:

```json
{
  "checked": ["app.py"],
  "skipped": [],
  "summary": {
    "total_findings": 1,
    "returned": 1,
    "truncated": false,
    "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    "highest": "high",
    "scanner_errors": []
  },
  "findings": [
    {
      "id": "patterns.python-yaml-load|app.py|3f2a9c1b7d4e",
      "scan_id": "patterns:python-yaml-load:1",
      "rule_id": "patterns.python-yaml-load",
      "scanner": "patterns",
      "severity": "high",
      "title": "Unsafe yaml.load without SafeLoader",
      "path": "app.py",
      "line": 5,
      "column": null,
      "cwe": ["CWE-502"],
      "owasp": ["A08:2021-Software and Data Integrity Failures"],
      "fix": "Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader).",
      "fix_available": true,
      "hook": "app.py:5:1: error high patterns.python-yaml-load: Unsafe yaml.load without SafeLoader. Fix: Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader)."
    }
  ]
}
```

`nephilex_check_snippet` returns `filename` (the sanitized file name the code
was checked as) instead of `checked`. A filename hint keeps its directories,
because some rules depend on them (`.github/workflows/ci.yml`,
`Dockerfile`); `..` and absolute parts are refused.

The `id` is the finding fingerprint: rule, path and a digest of the flagged
code. It stays the same across checks while the code is unchanged, unlike
`scan_id` (the per-scan id used in `nephilex scan` reports), which restarts
from 1 in every check.

### Fixes

`nephilex_fix` takes a finding `id` from a check made by the same server
process. When Nephilex has a deterministic rewrite for the rule, it re-reads the
file, confirms the flagged line is unchanged, applies the rewrite on a dry
run, and returns it only if it verifies (the rule no longer fires on the new
line and the file still parses):

```json
{
  "finding_id": "patterns.python-yaml-load|app.py|3f2a9c1b7d4e",
  "rule_id": "patterns.python-yaml-load",
  "path": "app.py",
  "line": 5,
  "applied": false,
  "available": true,
  "verified": true,
  "before": "    return yaml.load(raw)",
  "after": "    return yaml.safe_load(raw)",
  "diff": "--- a/app.py\n+++ b/app.py\n@@ -2,4 +2,4 @@\n ...",
  "note": "Not applied. Review the diff and apply it yourself."
}
```

Otherwise `available` is `false` with a `reason` (no deterministic fix for
the rule, the line changed since the check, the rewrite did not verify) and,
where it helps, the one-line `guidance`.

### Packages

`nephilex_check_package` returns a `verdict`, the first that applies of:
`malicious` (in the malicious-package intel), `possibly_hallucinated` (the
registry says the name does not exist), `vulnerable` (OSV advisories for the
given version), `suspicious` (the name resembles a popular package),
`unknown` (a check could not run) and `no_known_issues`. The details are in
`malicious`, `typosquat`, `registry` and `vulnerabilities`.

The registry lookup is only made for npm, PyPI and crates.io. For other
ecosystems, or when the lookup fails, `registry.status` is `unknown`:
Nephilex never guesses that a package is hallucinated. Without a `version`, the
vulnerability lookup is `not_checked`.

## Notes

- **Read-only.** No tool writes to your project; `nephilex_fix` only returns a
  diff.
- **Confined to your project.** Paths must be inside the directory the server
  was started in, or inside one of the directories listed in `NEPHILEX_MCP_ROOTS`
  (separated by `;` on Windows and `:` elsewhere). Relative paths are taken
  relative to the first of those directories. This stops a prompt-injected
  agent from reading your home directory.
- **Untrusted by default.** Rules and suppressions shipped inside the scanned
  directory (`.nephilex/rules`, `nephilex-ignore` comments) are not honoured, since
  the agent may have just cloned it.
- **Bounded.** Every tool call stops after `NEPHILEX_MCP_SCAN_TIMEOUT` seconds
  (default 600).
- **Local paths only.** It does not clone remote repositories from an agent call.
- **Network.** `nephilex_check_files`, `nephilex_check_snippet` and `nephilex_fix`
  never use the network. `nephilex_scan` uses it for dependency CVE lookups, and
  `nephilex_check_package` for OSV, the registry and any malicious-package feed
  set in `NEPHILEX_INTEL_FEED`.
  Set `NEPHILEX_MCP_OFFLINE=1` to keep `nephilex_check_package` offline: the
  bundled intel and typosquat checks still run, the rest report `unknown`.
