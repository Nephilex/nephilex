# Why was this reported? Evidence and grades

Every finding carries an **evidence** block. It answers two questions: why
Nephilex reported the finding, and how you can check it yourself by reading
the code.

Evidence explains a finding. It does not change what is detected: the same
findings, with the same rule, location, severity, confidence and fingerprint,
are reported with or without it.

## What the evidence block contains

| Field | What it holds |
| --- | --- |
| `grade` | `confirmed`, `likely` or `possible`: what kind of proof backs the finding (table below). |
| `basis` | One sentence saying what the grade rests on, for example "Request data reaches the SQL call with no recognized sanitizer on the path." |
| `path` | The lines from where the data comes from to where it is used, in order. Each step has `path` (file), `line`, `column` (when known), `role`, `code` (that source line) and a short `note`. |
| `verify` | Two to four plain steps to confirm or rule out the finding by reading the code. |

A step's `role` is one of:

- `source`: where the data comes from (`request.args['q']`, `req.query.q`).
- `step`: an assignment, a call into a helper, or a parameter that receives the value.
- `guard`: a check Nephilex saw on the way that does **not** cover this kind of
  sink (for example a path containment check before an SQL call).
- `sink`: where the value is used (`cursor.execute`, `child_process.exec()`).
- `elided`: a marker where steps were left out of a long path.

## Grades

The rules live in one place, `src/nephilex/core/evidence.py`. They are
conservative: when a rule does not clearly apply, the weaker grade wins.

| Grade | Meaning | When Nephilex assigns it |
| --- | --- | --- |
| `confirmed` | Proved without guessing. | A secret in a provider's exact key format that the provider accepted as live (only with secret validation on). A dependency whose exact installed version, from a lock file or an `==` pin in `requirements.txt`, is inside an advisory's affected range. A finding that an active check (the dynamic scan, a container image inspection, file integrity monitoring) marked `verified` or `confirmed`. |
| `likely` | Traced, or an exact match. | Taint data flow from an attacker-controlled source (request data, browser input, an archive entry name) to the sink with no recognized sanitizer on the recorded path, at medium or high confidence. A finding that took over such a path because two scanners reported the same weakness (see below). A high-confidence rule of a precise scanner (`patterns`, `lang-sast`, `secrets`, `iac`, `cicd`, `agent-config`, `container`, `cloud`) that matched the exact code. A dependency version required in `go.mod`. |
| `possible` | Worth reading; not shown to be reachable by an attacker. | Everything else: heuristic and pattern matches, low confidence, operator input (command line, environment, console), library-mode findings (`public-api`), test and example code, results imported from another tool's SARIF, dependency versions taken from a range (`package.json`), and data-flow findings whose source was not recorded. |

Checks that make a finding `possible` (test code, operator input, library
mode, low confidence) come before `likely`, so a traced flow inside a test
file is still `possible`. `confirmed` comes first: a live credential is live
wherever it sits.

The grade is separate from confidence. Confidence is each scanner's own
estimate and feeds sorting and risk scores; the grade only says what kind of
proof is behind the finding. Neither `--fail-on` nor any other gate reads the
grade. A `possible` finding is not a false positive: it is one
Nephilex could not back with a traced flow or a check.

## Where the path comes from

- **Python** (`ast-python`): the taint engine records where a value became
  tainted, each assignment it went through, same-file helpers that returned
  it, checks that did not cover the sink, and the sink.
- **Python across files** (`ast-python-xfile`): the source at the call site,
  the call, the parameter that receives the value in the other file, the steps
  inside that function, and the sink there.
- **JavaScript and TypeScript** (`ast-js`): the source, assignments, calls
  into same-file helpers and the sink. For a flow that goes through a helper,
  the finding is shown at the call and the path ends at the sink inside the
  helper.
- **Every other scanner** (patterns, secrets, dependencies, IaC, CI/CD, agent
  configuration, authorization, malware and the rest): one step, the matched
  line, with verification steps written for that kind of finding.

When two scanners report the same weakness a few lines apart, Nephilex keeps
one finding (for example the pattern finding, because it has a deterministic
fix). If the kept finding has no path of its own and the other one traced
attacker-controlled data to the sink, the kept finding shows that path.

A path shows one route the value took. When several routes reach the same
sink, the engine keeps the first it recorded, preferring one that starts at
request data. Paths are capped at 12 steps: the source, an `elided` marker,
and the steps closest to the sink.

## Example: one SQL injection in every format

The code, `app.py`:

```python linenums="1"
import sqlite3
from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    q = request.args['q']
    query = "SELECT * FROM items WHERE name = '" + q + "'"
    cursor = sqlite3.connect('db').cursor()
    cursor.execute(query)
    return 'ok'
```

Everything below was produced by scanning a folder holding only this file
with `--no-ai`. Outputs are pasted as printed, trimmed only where marked.

### Terminal

`nephilex scan . --no-ai` shows the grade in its own column and, for a
finding with a recorded path, the path under the title (in a 160-column
terminal, trimmed to the findings table and the line after it):

```text
┌──────┬──────┬────────┬───────────────────────────────────────────────────────────────────────────────────────────┬───────────┬──────────────────────────────┐
│ Sev  │ Risk │ Grade  │ Title                                                                                     │ Location  │ Rule                         │
├──────┼──────┼────────┼───────────────────────────────────────────────────────────────────────────────────────────┼───────────┼──────────────────────────────┤
│ High │ 72.8 │ likely │ SQL injection (tainted value reaches a database query)                                    │ app.py:10 │ ast-python.ast-sql-injection │
│      │      │        │ request.args['q'] (app.py:7) -> q (app.py:7) -> query (app.py:8) -> cursor.execute        │           │                              │
│      │      │        │ (app.py:10)                                                                               │           │                              │
└──────┴──────┴────────┴───────────────────────────────────────────────────────────────────────────────────────────┴───────────┴──────────────────────────────┘
Grade: confirmed (proved), likely (traced or exact match), possible (heuristic). Full evidence and verify steps: -f html, markdown, json or sarif.
```

### JSON

`-f json`: the finding's `evidence` field.

```json
{
  "grade": "likely",
  "basis": "Request data reaches the SQL call with no recognized sanitizer on the path.",
  "path": [
    {
      "path": "app.py",
      "line": 7,
      "column": 9,
      "role": "source",
      "code": "q = request.args['q']",
      "note": "request.args['q'] is attacker-controlled"
    },
    {
      "path": "app.py",
      "line": 7,
      "column": 5,
      "role": "step",
      "code": "q = request.args['q']",
      "note": "assigned to q"
    },
    {
      "path": "app.py",
      "line": 8,
      "column": 5,
      "role": "step",
      "code": "query = \"SELECT * FROM items WHERE name = '\" + q + \"'\"",
      "note": "assigned to query"
    },
    {
      "path": "app.py",
      "line": 10,
      "column": 5,
      "role": "sink",
      "code": "cursor.execute(query)",
      "note": "passed to cursor.execute"
    }
  ],
  "verify": [
    "Open app.py line 7 and confirm the value read there comes from the request.",
    "Follow it through lines 7 and 8 and check that nothing validates, escapes or converts it before app.py line 10.",
    "Check whether any caller, decorator or middleware validates the value before app.py line 10.",
    "In a test environment you own, pass a value containing a single quote (for example ' OR '1'='1) and check whether the query fails or returns other rows."
  ]
}
```

Older reports have no `evidence` field, and a reader that ignores it keeps
working.

### SARIF

`-f sarif`: the result gets `properties.grade` and a `codeFlows` entry with one
thread flow location per step (trimmed to the first and last of the four
locations). `partialFingerprints` are the same as without evidence, so alerts
in GitHub Code Scanning keep their identity. A finding with a one-step path
gets the grade but no `codeFlows`.

```json
"properties": {
  "confidence": "High",
  "riskScore": 72.8,
  "grade": "likely"
},
"codeFlows": [
  {
    "message": {
      "text": "Request data reaches the SQL call with no recognized sanitizer on the path."
    },
    "threadFlows": [
      {
        "locations": [
          {
            "location": {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "app.py"
                },
                "region": {
                  "startLine": 7,
                  "startColumn": 9,
                  "snippet": {
                    "text": "q = request.args['q']"
                  }
                }
              },
              "message": {
                "text": "source: request.args['q'] is attacker-controlled"
              }
            },
            "properties": {
              "role": "source"
            }
          },
          {
            "location": {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "app.py"
                },
                "region": {
                  "startLine": 10,
                  "startColumn": 5,
                  "snippet": {
                    "text": "cursor.execute(query)"
                  }
                }
              },
              "message": {
                "text": "sink: passed to cursor.execute"
              }
            },
            "properties": {
              "role": "sink"
            }
          }
        ]
      }
    ]
  }
]
```

### HTML

`-f html`: each finding card has a collapsed **Evidence** block with the
grade as a badge, the basis, the numbered steps with each code line, and a
"How to verify" list. Its markup, as written to the report:

```html
<details class="evidence"><summary>Evidence
  <span class="grade" style="background:#8a5a00">likely</span></summary>
  <p class="basis">Request data reaches the SQL call with no recognized sanitizer on the path.</p>
  <ol class="steps"><li><span class="role role-source">source</span> <span class="mono">app.py:7</span> request.args[&#x27;q&#x27;] is attacker-controlled<pre class="code">q = request.args[&#x27;q&#x27;]</pre></li>...</ol>
  <p class="ev-h">How to verify</p><ol><li>Open app.py line 7 and confirm the value read there comes from the request.</li>...</ol>
</details>
```

(Trimmed: `...` stands for the other steps and verify items.)

### Markdown

`-f markdown`: a collapsed block after the finding's explanation.

```markdown
<details><summary>Evidence: likely</summary>

Request data reaches the SQL call with no recognized sanitizer on the path.

1. **source** `app.py:7` request.args\['q'\] is attacker-controlled: `q = request.args['q']`
2. **step** `app.py:7` assigned to q: `q = request.args['q']`
3. **step** `app.py:8` assigned to query: `query = "SELECT * FROM items WHERE name = '" + q + "'"`
4. **sink** `app.py:10` passed to cursor.execute: `cursor.execute(query)`

**How to verify:**

- Open app.py line 7 and confirm the value read there comes from the request.
- Follow it through lines 7 and 8 and check that nothing validates, escapes or converts it before app.py line 10.
- Check whether any caller, decorator or middleware validates the value before app.py line 10.
- In a test environment you own, pass a value containing a single quote \(for example ' OR '1'='1\) and check whether the query fails or returns other rows.

</details>
```

### MCP

The `nephilex_scan` tool of the [MCP server](mcp.md) returns the same block
for each finding as `evidence`, with `grade`, `basis`, `path` (each step's
`path`, `line`, `role`, `code` and `note`) and `verify`.

## How to use `verify`

The `verify` steps are a short review checklist, written so you can settle a
finding without running anything:

1. Open the source line and confirm the value really comes from where the
   note says (a request parameter, a browser URL, an archive entry).
2. Follow the listed lines and look for anything that validates, escapes or
   converts the value before the sink. Nephilex recognizes common sanitizers
   and checks; a project-specific one it does not know shows up here.
3. Check callers, decorators and middleware for validation that happens
   before the code shown.
4. Where a step suggests trying an input, do it only in a test environment
   you own. Nephilex never suggests testing a system you do not own.

If you confirm the finding, fix it. If you rule it out, record why: an inline
`nephilex-ignore` comment, an entry in `.nephilex/exceptions.yml`, or a
baseline (see [Triage & baselines](triage.md)).

## Code from the scanned repository

The `code` and `note` of each step quote the scanned repository, which may be
hostile. Before they are stored, they are reduced to one line, cut to a fixed
length, control, bidirectional and zero-width characters are shown as
`<U+XXXX>`, and secret-looking values are masked, the same way finding
snippets from instruction files are made safe. Each report format escapes
them again for its own syntax (HTML escaping, Markdown code spans, Rich markup
escaping in the terminal). Nephilex never runs this text or puts it in a
shell command.
