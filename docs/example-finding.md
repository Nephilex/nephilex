# Example finding: unsafe `yaml.load`

This page follows one real finding from the demo app in
[`examples/vulnerable-app`](https://github.com/nephilex/nephilex/tree/main/examples/vulnerable-app)
from the vulnerable line to a committed fix and a re-scan. It was chosen
because the untrusted input and the dangerous call are both visible, Nephilex
uses data flow to grade it, and Nephilex has a deterministic fix for it.

Everything below was produced by Nephilex 0.11.0 on 2026-10-23 with
`--no-ai` (no AI provider, no API key). The commands are the ones from the
[Quickstart](quickstart.md); outputs are pasted as printed, trimmed only where
marked.

## The vulnerable code

`examples/vulnerable-app/app.py`, lines 41 to 45:

```python linenums="41" hl_lines="4 5"
@app.route("/config")
def load_config():
    # Unsafe deserialization (patterns scanner: CWE-502).
    raw = request.args.get("data")
    return str(yaml.load(raw))
```

Line 44 reads the `data` query parameter, which anyone who can reach `/config`
controls. Line 45 passes it to `yaml.load` without a safe loader, which can
build arbitrary Python objects from the document.

## How Nephilex reports it

The row in the terminal table of `nephilex scan nephilex/examples/vulnerable-app --no-ai`
(trimmed to this one row):

```text
│ High     │ 70.5 │ Unsafe yaml.load without          │ app.py:45        │ patterns.python-yaml-load        │
│          │      │ SafeLoader                        │                  │                                  │
```

The same finding in the Markdown report
(`nephilex scan nephilex/examples/vulnerable-app --no-ai --patches -f json -f markdown -o ex`,
file `ex/nephilex-report.md`, finding 6 of 20):

````markdown
### 6. [HIGH] Unsafe yaml.load without SafeLoader

- **Severity:** High (risk 70.5/100), **Confidence:** High, **Likelihood:** Possible
- **Location:** `app.py:45`
- **Scanner/Rule:** `patterns` / `patterns.python-yaml-load`
- **Mapping:** CWE-502, A08:2021-Software and Data Integrity Failures

```
    return str(yaml.load(raw))
```

**Why it's a vulnerability:** yaml.load with the default loader can construct arbitrary Python objects from the document.

**How an attacker exploits it:** Feed a YAML payload using \`\!\!python/object/apply\` tags to execute code.

**Business impact:** Remote code execution.

**Remediation:** Use yaml.safe\_load, or yaml.load\(..., Loader=yaml.SafeLoader\).

**Suggested patch (verified):**
```diff
--- a/app.py
+++ b/app.py
@@ -45 +45 @@
-    return str(yaml.load(raw))
+    return str(yaml.safe_load(raw))
```
````

And the complete finding object from the JSON report (`ex/nephilex-report.json`):

```json
{
  "id": "patterns:python-yaml-load:3",
  "rule_id": "patterns.python-yaml-load",
  "scanner": "patterns",
  "title": "Unsafe yaml.load without SafeLoader",
  "description": "yaml.load with the default loader can construct arbitrary Python objects from the document.",
  "location": {
    "path": "app.py",
    "start_line": 45,
    "end_line": 45,
    "start_column": 16,
    "end_column": 26,
    "snippet": "    return str(yaml.load(raw))"
  },
  "severity": 3,
  "confidence": 2,
  "likelihood": 2,
  "cwe": [
    "CWE-502"
  ],
  "owasp": [
    "A08:2021-Software and Data Integrity Failures"
  ],
  "why_vulnerable": "yaml.load with the default loader can construct arbitrary Python objects from the document.",
  "attacker_perspective": "Feed a YAML payload using `!!python/object/apply` tags to execute code.",
  "business_impact": "Remote code execution.",
  "remediation": {
    "summary": "Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader).",
    "guidance": "Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader).",
    "patch": "--- a/app.py\n+++ b/app.py\n@@ -45 +45 @@\n-    return str(yaml.load(raw))\n+    return str(yaml.safe_load(raw))\n",
    "references": [
      "https://cwe.mitre.org/data/definitions/502.html"
    ],
    "verified": true
  },
  "exploit": null,
  "tags": [
    "sast"
  ],
  "metadata": {
    "dataflow": "tainted",
    "patch_source": "deterministic",
    "verification": "likely",
    "contextual_risk": 80.5,
    "risk_factors": {
      "base": 70.5,
      "internet_exposed": false,
      "production": false,
      "boost": 10.0
    }
  },
  "detected_at": "2026-10-23T06:57:46.698936Z",
  "docs_url": "https://nephilex.github.io/nephilex/scanners/#sast-pattern-rules"
}
```

### Reading the fields

| Field | Value | Where it comes from |
| --- | --- | --- |
| Rule | `patterns.python-yaml-load` | A rule in the `patterns` scanner, which matches source lines; see [SAST (pattern rules)](scanners.md#sast-pattern-rules). |
| Severity | High (`3`) | The rule's severity: an unsafe YAML loader on input can lead to code execution. |
| Confidence | High (`2`) | Raised from the rule's default because the data-flow engine found that the argument comes from request data (`"dataflow": "tainted"`). |
| Likelihood | Possible (`2`) | The pattern scanner's default. |
| CWE / OWASP | CWE-502, A08:2021 | Deserialization of untrusted data; Software and Data Integrity Failures. |
| Risk | 70.5, contextual 80.5 | The risk score combines severity, confidence and likelihood; the contextual score adds 10 because the severity is High or above. See [Risk score](understanding-results.md#risk-score-0-to-100). |

The JSON stores severity, confidence and likelihood as numbers: severity runs
from 0 (Info) to 4 (Critical), confidence from 0 (Low) to 2 (High), likelihood
from 0 (Rare) to 4 (Almost certain).

The confidence grade depends on the `[ast]` extra. The same scan with a plain
`pip install nephilex` (no tree-sitter) reports this finding with confidence
Medium (`1`), no `dataflow` key, and risk 64.2.

### Source to sink

Nephilex does not print a step-by-step path for this finding. What it records
is the data-flow verdict for the call on line 45, `"dataflow": "tainted"`:
the argument to `yaml.load` was traced back to request data. The source (line
44, `request.args.get`) and the sink (line 45, `yaml.load`) above are read from
the code, not from the report.

Versions after 0.11.0 do record this path: every finding has an `evidence`
block with a grade, the steps from source to sink and how to verify it. For
this finding the path is `request.args.get("data")` (line 44), assigned to
`raw` (line 44), passed to `yaml.load` (line 45), graded `likely`. See
[Evidence and grades](evidence.md).

Two other results point at the same line:

- The taint scanner reports `ast-python.ast-xss` on line 45 (Medium): the
  parsed request data is returned from a Flask view as the response body.
- The taint scanner also traces the request data into `yaml.load` on this
  line. Both tiers report the same weakness, so Nephilex keeps one finding: the
  pattern finding, because it carries the deterministic fix. `nephilex scan`
  and `nephilex check` make the same choice.

## The proposed fix

With `--patches`, the report carries the patch shown above and marks it
`"verified": true`. `nephilex fix` applies such patches to a git repository.
The run below used a fresh git repository holding a copy of the demo app,
because `nephilex fix` creates a branch and commits.

Preview first; `--dry-run` writes nothing:

```bash
nephilex fix --dry-run
```

```text
- Done: 21 finding(s), highest severity Critical.
                     Fixes (dry run)
┌────────┬──────┬───────────────────────────┬──────────┐
│ File   │ Line │ Rule                      │ Verified │
├────────┼──────┼───────────────────────────┼──────────┤
│ app.py │   45 │ patterns.python-yaml-load │   yes    │
│ app.py │   55 │ patterns.flask-debug-true │   yes    │
└────────┴──────┴───────────────────────────┴──────────┘
- would fix 2 finding(s) across 1 file(s) (dry run, no files written)
```

(Trimmed: the progress lines are left out. The count is 21 rather than 20
because inside a git repository the `git-security` scanner also runs and
reports the newly committed `requirements.txt`.)

Then apply:

```bash
nephilex fix -q
```

```text
                          Fixes
┌────────┬──────┬───────────────────────────┬──────────┐
│ File   │ Line │ Rule                      │ Verified │
├────────┼──────┼───────────────────────────┼──────────┤
│ app.py │   45 │ patterns.python-yaml-load │   yes    │
│ app.py │   55 │ patterns.flask-debug-true │   yes    │
└────────┴──────┴───────────────────────────┴──────────┘
- Created branch 'nephilex/security-fixes' at 'master'.
- Committed 2 fix(es) as cb497e04.
- Branch committed locally. Re-run with --open-pr to push and open a pull request.
Fixes committed to the branch. Add --open-pr to push and open a pull request.
```

The commit changes `app.py` (trimmed to the hunk for this finding):

```diff
@@ -42,7 +42,7 @@ def ping():
 def load_config():
     # Unsafe deserialization (CWE-502: patterns; ast-python also traces request data here).
     raw = request.args.get("data")
-    return str(yaml.load(raw))
+    return str(yaml.safe_load(raw))
```

and adds a record to the tamper-evident audit log `.nephilex/audit.log` (one
of two lines shown):

```json
{"action":"fix.applied","actor":"demo <demo@example.com>","details":{"line":45,"verified":true},"fingerprint":"patterns.python-yaml-load|app.py|ee7664839c3a","hash":"c4e252bddef65fff1890a078d926f0f21073c09c7bdb5d7caff6d745ab19f254","kind":null,"path":"app.py","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","reason":"verified deterministic fix","rule":"patterns.python-yaml-load","seq":1,"ts":"2026-10-23T07:42:27.940Z","v":1}
```

Nothing was pushed. `--open-pr` would push the branch and open a pull request;
see [Fixing & pull requests](fixing.md) and [Audit log](audit-log.md).

## Verification status

"Verified" has a narrow, checkable meaning in Nephilex 0.11.0:

1. The rewritten line no longer matches the rule (or matches the rule's
   recognized safe form). This check runs both for `--patches` and for
   `nephilex fix`.
2. `nephilex fix` also re-parses the whole changed file for Python, JSON and
   YAML files, and drops all fixes for a file that would no longer parse.

By default it does not run your tests, start the application, or prove that
the new code behaves the same. `nephilex fix --verify-with-tests` adds that
check: it runs your test command before and after the fixes in a temporary
copy of the repository and commits only fixes that keep the tests passing (see
[Fixing & pull requests](fixing.md)). Either way, review the change as you
would any other pull request.

The re-scan of the fixed branch (`nephilex scan . --no-ai -q`), trimmed to the
summary and the rows for `app.py:45`. The first line is the folder name, which
was `fixrepo` in this run:

```text
┌────────────────────────────────────────────── Nephilex scan ──────────────────────────────────────────────┐
│ fixrepo                                                                                                   │
│ Aggregate risk: 99.7/100   Findings: 19                                                                   │
│ Critical: 2 | High: 7 | Medium: 9 | Low: 1 | Info: 0                                                      │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
│ Medium   │ 44.3 │ Cross-site scripting (tainted     │ app.py:45        │ ast-python.ast-xss               │
│          │      │ value returned as HTML)           │                  │                                  │
```

The `yaml.load` finding is gone, and so is the other fixed finding
(21 before, 19 after). The cross-site scripting finding on the same line is
still there: `safe_load` stops object construction, but the view still returns
request data as HTML. One fixed finding does not make the line safe.

!!! note "Why the weak hash on line 50 is not fixed"
    `hash_password` hashes a password with MD5. Swapping in SHA-256 would make
    the rule stop matching, but SHA-256 is also a fast hash, so stored
    passwords would stay easy to crack. Password storage needs a slow
    key-derivation function (bcrypt, scrypt or Argon2), which a one-line
    rewrite cannot introduce. Nephilex therefore offers no automatic fix for a
    line that hashes a password or secret, and the finding stays with that
    guidance. Treat verified fixes as a correct first step, not the last one.

## Reproduce it

```bash
pipx install "nephilex[ast]"
git clone --depth 1 https://github.com/nephilex/nephilex.git
nephilex scan nephilex/examples/vulnerable-app --no-ai --patches -f json -f markdown -o ex

# nephilex fix needs a git repository of its own:
cp -r nephilex/examples/vulnerable-app demo && cd demo
git init -q && git add -A && git commit -qm "demo app"
nephilex fix --dry-run
nephilex fix -q
nephilex scan . --no-ai -q
```

Commit hashes, timestamps, the base branch name (`master` here, from git's
default) and the audit-log `actor` will differ on your machine, and the
dependency findings follow live OSV data. These steps were re-run in a fresh
folder for this page and gave the same 21 and 18 finding counts.
