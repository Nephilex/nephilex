# Benchmarks & accuracy

A scanner's most important number is how accurate it is, and the most honest thing
a young scanner can do is publish that number with its methodology, and republish
it when it gets worse. Nephilex measures accuracy three ways: a small in-repo
labeled corpus, public labeled datasets scored side by side with Bandit and
Semgrep, and finding inventories on large reference apps.

## Labeled corpus (precision and recall)

A small, fully labeled corpus ships in the repo so the numbers are reproducible on
any machine with one command and no downloads:

```bash
python benchmarks/accuracy.py
```

Every case is a single file that is either **vulnerable** (Nephilex must raise at
least one actionable finding) or **safe** (Nephilex must raise none). From that:

- **Recall** = caught vulnerable cases / all vulnerable cases (did we miss a bug?)
- **Precision** = caught / (caught + findings on safe cases) (did we cry wolf?)

Current results:

| Domain | Recall | Precision | Vulnerable cases | Safe cases | False positives |
| --- | --- | --- | --- | --- | --- |
| secrets | 100% | 100% | 1 | 1 | 0 |
| sast | 100% | 100% | 6 | 7 | 0 |
| taint | 100% | 100% | 16 | 16 | 0 |
| iac | 100% | 100% | 1 | 1 | 0 |
| llm | 100% | 100% | 17 | 17 | 0 |
| mcp | 100% | 100% | 7 | 7 | 0 |
| **overall** | **100%** | **100%** | **48** | **49** | **0** |

!!! warning "Read this number honestly"
    This is a **small sanity-and-regression corpus** (48 vulnerable, 49 safe cases),
    not a claim of 100% real-world accuracy. 100% here means Nephilex classifies
    every case in this set correctly, and the run **exits non-zero if it does
    not**, so a regression fails CI. On independent public datasets the
    numbers are far lower; see the next section.

The **llm** rows are worth calling out: there is no standard public benchmark for
LLM/AI-application vulnerability classes (prompt injection, insecure model-output
handling, unsafe model loading, secrets in prompts, excessive agency). This
labeled set covers OWASP LLM01/02/05/06/08 with a vulnerable and a safe case each,
so the accuracy claim in Nephilex's strongest and least-crowded domain is measurable
and reproducible rather than asserted.

This corpus already earned its keep: building it surfaced two real bugs, both now
fixed and covered by regression tests:

- A false **negative**: `subprocess(..., shell=True)` was being dropped by the
  engine whenever the AST taint tier ran, because that tier does not model a
  taint-independent smell. Command-execution findings now survive.
- A false **positive**: a properly parameterized query
  `execute("... %s", (uid,))` was flagged as SQL injection because a tainted value
  in the bound-parameters argument counted. Bound parameters are now recognized as
  the safe form.

## Public labeled datasets (Nephilex, Bandit, Semgrep)

The in-repo corpus is written by the same people who write the rules, so it
cannot tell you how Nephilex does on code it was not tuned for. For that, Nephilex is
scored on two independent, public, labeled Python datasets, next to Bandit and
Semgrep run on the same files and scored by the same code.

### Reproduce

```bash
pip install -e ".[ast]"                    # Nephilex with the AST tier
pip install bandit semgrep                 # ideally in a separate virtualenv
python benchmarks/public/run.py            # both datasets, all three tools
```

Useful variations:

```bash
python benchmarks/public/run.py --dataset owasp-python --tools nephilex,bandit,semgrep
python benchmarks/public/run.py --offline  # re-score cached outputs, no network, no tool runs
python benchmarks/public/run.py --bandit /path/to/bandit --semgrep /path/to/semgrep
```

`--bandit` and `--semgrep` (or the `NEPHILEX_BENCH_BANDIT` and `NEPHILEX_BENCH_SEMGREP`
environment variables) point at tools installed outside the current environment.
A tool that cannot be found is recorded as `not_run` with the reason; no numbers
are produced for it.

Outputs:

- `benchmarks/results/public/<dataset>.json`: dataset commit and archive hash,
  tool versions, run dates, command lines, the CWE mapping tables used, per-rule
  CWE inventory, and per-category and overall metrics for every tool and mode,
  including the list of false-positive and false-negative case ids.
- `benchmarks/results/public/SUMMARY.md`: generated tables.
- `benchmarks/results/public/findings/<dataset>/<tool>.json`: every finding
  normalized to file, line, rule id and CWEs (no source code), so the scoring
  can be audited or re-run with `--offline` without installing the tools.
- `benchmarks/.corpora/` (git-ignored): the downloaded datasets, the cached
  Semgrep ruleset and each tool's raw JSON output.

### Datasets

| Dataset | Pinned commit | Content | Labels |
| --- | --- | --- | --- |
| [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) v0.1 | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` | 1230 Flask test cases in 14 CWE categories | `expectedresults-0.1.csv`: 452 vulnerable, 778 safe |
| [SecurityEval](https://github.com/s2e-lab/SecurityEval) v2.1 | `6f4fb70f782c6d47b02ea24341e8ef8c1eb04a6a` | 121 short Python samples (`dataset.jsonl`, field `Insecure_code`) | one CWE per sample, 69 CWEs, all vulnerable |

Datasets are downloaded as GitHub archives of the pinned commit. The archive's
SHA-256 is recorded; GitHub does not promise byte-stable archives, so a hash
change is reported as a warning while the commit pin fixes the content.

### Tools and settings

| Tool | Version measured | Configuration |
| --- | --- | --- |
| Nephilex | 0.10.0 (measured on the release code before its version number was set, so the raw results record 0.9.2) | `nephilex scan <root> --no-ai --no-cache -f json`: offline heuristic provider, default scanner set; the harness refuses to run if the `ast-python` tier is missing |
| Bandit | 1.9.4 | `bandit -r <root> -f json`: default plugins, all severities and confidences |
| Semgrep | 1.182.1 (Community Edition) | `semgrep scan --config p/python --metrics=off --no-git-ignore --json`: registry ruleset `p/python`, 151 rules, cached locally with its SHA-256 recorded because registry rulesets are not version-pinned |

Semgrep needs `--no-git-ignore` only because the corpora sit in a git-ignored
directory of this repository; without it Semgrep skips every file. All findings
each tool emits count, at every severity; no tool gets a severity or confidence
filter. Runs were made on Windows 11 with Python 3.11 on 2026-10-22.

### Scoring

**OWASP BenchmarkPython** follows the OWASP Benchmark methodology. A test case is
*flagged* when the tool reports at least one finding in that test case's source
file (`testcode/BenchmarkTestNNNNN.py`) whose CWE matches the case's CWE. Findings
in that file with a different CWE are ignored for that case; findings in helpers
and templates are ignored. Flagged vulnerable case = TP, flagged safe case = FP,
unflagged safe = TN, unflagged vulnerable = FN. Per category and overall:
TPR (recall), FPR, precision, F1 and the OWASP score, TPR - FPR. Overall
numbers are given two ways: *pooled* (counts summed over all 1230 cases, which
weights large categories such as weakrand with 326 cases) and *category average*
(unweighted mean of the per-category TPR, FPR and score, as on the official
OWASP scorecard).

**SecurityEval** has no safe samples, so only recall can be measured. Precision,
FPR and F1 are undefined and are not reported. A sample is detected when the
tool reports a finding in its file with a matching CWE; the `any` mode also
reports how many samples got any finding at all, whatever its CWE.

**CWE matching** comes in two modes, both always published:

- `strict`: one of the tool's own reported CWEs equals the labeled CWE.
- `mapped`: the tool's CWEs, plus documented per-rule overrides, intersect an
  equivalence group containing the label. The groups join parent and child
  CWEs (for example 327/328/916 for weak hashing, 22/23/36/73/99 for path
  traversal, 94/95 for code injection, 330/331/338 for weak randomness). They
  are in `benchmarks/public/mapping.py` and apply to every tool equally.

Manual overrides exist only where a tool reports a generic or wrong CWE for a
rule with a single documented purpose. After auditing the per-rule inventory,
the overrides are: Bandit's XML blacklist rules B313 to B320 and B405 to B410
(reported as CWE-20, mapped to CWE-611), B506 `yaml_load` (CWE-20 to CWE-502),
B102 `exec_used` and B307 `eval` (reported as CWE-78, mapped to CWE-95), and
Semgrep's `python.flask.security.injection.tainted-sql-string` (registry
metadata says CWE-704, mapped to CWE-89). No Nephilex rule needed an override.
Overrides only add CWEs. Note that they cut both ways: Bandit's mapped OWASP
score is *lower* than its strict one, because the overrides credit rules that
also fire on safe cases.

### Results

Measured on 2026-10-22 after the changes listed under "What changed since
0.9.2". Bandit, Semgrep, the datasets and the Semgrep ruleset (same SHA-256) are
unchanged from the 0.9.2 run, and their numbers are identical to it.

!!! warning "How these Nephilex numbers were produced"
    Nephilex's Python rules were revised **with OWASP BenchmarkPython visible**:
    the cases Nephilex got wrong in 0.9.2 were read, and general rules were
    written for the idioms behind them. No OWASP case was held out, so the
    OWASP rows below measure Nephilex on code it was developed against, not on
    unseen code. The checks under "Methodology checks" and the held-out
    benchmark on real fix commits (below) are the evidence on
    generalisation; read them before quoting a number.

OWASP Benchmark for Python v0.1, all 1230 cases:

| Tool | Mode | TP | FP | TN | FN | TPR | FPR | Precision | F1 | Score (pooled) | Score (category avg) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Nephilex | mapped | 447 | 74 | 704 | 5 | 98.9% | 9.5% | 85.8% | 91.9% | +89.4 | +91.3 |
| Nephilex | strict | 356 | 62 | 716 | 96 | 78.8% | 8.0% | 85.2% | 81.8% | +70.8 | +79.6 |
| Nephilex 0.9.2 | mapped | 78 | 30 | 748 | 374 | 17.3% | 3.9% | 72.2% | 27.9% | +13.4 | +6.3 |
| Nephilex 0.9.2 | strict | 37 | 24 | 754 | 415 | 8.2% | 3.1% | 60.7% | 14.4% | +5.1 | +2.4 |
| Bandit | mapped | 130 | 79 | 699 | 322 | 28.8% | 10.2% | 62.2% | 39.3% | +18.6 | +7.5 |
| Bandit | strict | 101 | 25 | 753 | 351 | 22.4% | 3.2% | 80.2% | 34.9% | +19.1 | +8.2 |
| Semgrep | mapped | 73 | 15 | 763 | 379 | 16.2% | 1.9% | 83.0% | 27.0% | +14.2 | +6.0 |
| Semgrep | strict | 18 | 15 | 763 | 434 | 4.0% | 1.9% | 54.5% | 7.4% | +2.1 | -0.8 |

Per category, mapped mode, as TPR / FPR (score):

| Category | CWE | Cases (vuln/safe) | Nephilex | Nephilex 0.9.2 | Bandit | Semgrep |
| --- | --- | --- | --- | --- | --- | --- |
| cmdi | 78 | 13/7 | 100.0% / 14.3% (+85.7) | 53.8% / 100.0% (-46.2) | 100.0% / 100.0% (+0.0) | 53.8% / 100.0% (-46.2) |
| codeinj | 94 | 20/33 | 100.0% / 36.4% (+63.6) | 20.0% / 18.2% (+1.8) | 95.0% / 90.9% (+4.1) | 0.0% / 0.0% (+0.0) |
| deserialization | 502 | 18/36 | 100.0% / 19.4% (+80.6) | 100.0% / 33.3% (+66.7) | 83.3% / 30.6% (+52.8) | 50.0% / 16.7% (+33.3) |
| hash | 328 | 71/80 | 100.0% / 0.0% (+100.0) | 52.1% / 0.0% (+52.1) | 0.0% / 0.0% (+0.0) | 76.1% / 0.0% (+76.1) |
| ldapi | 90 | 16/13 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| pathtraver | 22 | 65/103 | 92.3% / 15.5% (+76.8) | 18.5% / 4.9% (+13.6) | 0.0% / 0.0% (+0.0) | 3.1% / 1.9% (+1.1) |
| redirect | 601 | 13/21 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| securecookie | 614 | 24/15 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| sqli | 89 | 5/11 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 100.0% / 100.0% (+0.0) | 20.0% / 0.0% (+20.0) |
| trustbound | 501 | 18/19 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| weakrand | 330 | 99/227 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 72.7% / 0.0% (+72.7) | 0.0% / 0.0% (+0.0) |
| xpathi | 643 | 51/135 | 100.0% / 28.1% (+71.9) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| xss | 79 | 31/58 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| xxe | 611 | 8/20 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 75.0% / 100.0% (-25.0) | 0.0% / 0.0% (+0.0) |

SecurityEval v2.1, 121 samples, recall only:

| Tool | Mode | Detected | Recall | CWE-average recall | CWEs with a detection |
| --- | --- | --- | --- | --- | --- |
| Nephilex | mapped | 32/121 | 26.5% | 18.4% | 17/69 |
| Nephilex | strict | 26/121 | 21.5% | 13.4% | 13/69 |
| Nephilex | any | 51/121 | 42.1% | 34.4% | 30/69 |
| Nephilex 0.9.2 | mapped | 12/121 | 9.9% | 7.0% | 9/69 |
| Nephilex 0.9.2 | strict | 8/121 | 6.6% | 3.9% | 6/69 |
| Nephilex 0.9.2 | any | 22/121 | 18.2% | 15.5% | 18/69 |
| Bandit | mapped | 32/121 | 26.5% | 23.3% | 21/69 |
| Bandit | strict | 23/121 | 19.0% | 15.9% | 15/69 |
| Bandit | any | 49/121 | 40.5% | 39.6% | 34/69 |
| Semgrep | mapped | 13/121 | 10.7% | 8.1% | 8/69 |
| Semgrep | strict | 10/121 | 8.3% | 5.7% | 6/69 |
| Semgrep | any | 23/121 | 19.0% | 18.2% | 17/69 |

The per-CWE SecurityEval table is in `benchmarks/results/public/SUMMARY.md`.

### Methodology checks

**Corpus-specific keying.** No rule refers to a benchmark file name, test id,
helper module or function (`helpers.*`, the benchmark's request wrapper or
HTML-escape helper), variable name, comment, or the expected-results CSV. An
audit before publishing removed three things that were closer to the
benchmark's own "safe" idioms than to general mitigations: the blocklist
guards `'../' in p` (path traversal) and "contains no quote" (XPath), the
`.replace("'", ...)` XPath sanitizer and the "quoted literal only" check
before `eval`. Those blocklists are incomplete in general (an absolute path or
another quoting style gets past them), so the engine no longer trusts them.
That costs 66 OWASP false positives (16 path traversal, 38 XPath, 12 code
injection), which are in the table above. `os.path.exists` and other
existence checks were also dropped as path sinks after the false-positive
check below, which costs 5 path-traversal true positives. One rule that is
correct but was motivated by the benchmark stays and is documented:
`request.path` is not a source in a Flask view whose routes have no
`<converters>`, because routing has already fixed the path.

**Split halves (not a held-out test).** The OWASP score is stable across
halves, but both halves were visible during development, so this shows the
rules are not keyed to individual cases, not that they generalise:

| Split | Cases | Mapped score (pooled) | Mapped score (category avg) | Strict score (pooled) |
| --- | --- | --- | --- | --- |
| even test numbers | 615 | +89.4 | +92.2 | +71.5 |
| odd test numbers | 615 | +89.4 | +89.0 | +70.1 |
| random half A (seed 20261022) | 611 | +88.8 | +92.7 | +70.9 |
| random half B | 619 | +90.0 | +90.2 | +70.7 |

**SecurityEval (a different corpus).** Mapped recall went from 12/121 (9.9%)
in 0.9.2 to 32/121 (26.5%). Five of the 32 come from rules added after reading
SecurityEval's misses (`compile()` as a code sink, a redirect through
`headers["Location"]`, and lxml `resolve_entities=True`, three samples); the
SQL-from-a-parameter rule was written for a SecurityEval sample named in the
task (`CWE-089_author_1.py`). Without the five post-hoc detections the figure
is 27/121 (22.3%). That is the better estimate of how the OWASP-driven work
transfers to code it was not developed on: a large gain over 0.9.2, still
behind Bandit on CWE-average recall (23.3%) and CWE breadth (21 CWEs).

**False positives on code with no known vulnerabilities.** The SAST, taint and
auth scanners (`ast-python`, `ast-python-xfile`, `patterns`, `authz`) were run
on Flask 3.0.3's tutorial and JavaScript example apps, the Flask 3.0.3 and
Werkzeug 3.0.3 sources, and the installed click, requests, jinja2, rich and
typer packages. Findings at severity low or above, 0.9.2 scanners against
these changes:

| Project | 0.9.2 | Now | New findings |
| --- | --- | --- | --- |
| Flask tutorial app (flaskr) | 0 | 0 | |
| Flask JavaScript example | 0 | 0 | |
| Flask 3.0.3 | 3 | 3 | none (the same 3: `PYTHONSTARTUP` read and executed by `flask shell`, SHA-1 in sessions) |
| Werkzeug 3.0.3 | 6 | 7 | `subprocess.call(args)` re-executing `sys.argv` in the reloader |
| click | 1 | 0 | (0.9.2 flagged the editor launch because its `env=` mapping copies `os.environ`; only the command argument is a sink now) |
| requests | 0 | 0 | |
| jinja2 | 1 | 1 | none |
| rich | 0 | 1 | `pty.spawn(sys.argv[1:])` in a demo entry point |
| typer | 0 | 0 | |

The two new findings come from treating `sys.argv`
as an untrusted source, which Nephilex already did in 0.9.2; the new
engine simply follows those flows further. Earlier drafts of this change were
noisier on these projects (`eval`/`exec` of a function parameter in template
engines, `os.path.exists` on environment paths, `x.open()` on test clients,
`http.cookiejar` `set_cookie(cookie)` and `set_cookie(..., **kwargs)`); those
rules were removed or narrowed before publishing.

### What changed since 0.9.2

Each fix below is a general rule meant to hold on real code. Details per rule
are in [Scanners](scanners.md).

- **Flow-sensitive taint.** Branches, `match`, loops and `try` are analyzed
  separately and joined, so `if not p: p = ""` keeps the taint (the idiom
  behind 41 of the 80 false negatives in 0.9.2). Conditions that fold to a
  constant prune the dead branch. Literal dicts, lists and `configparser`
  objects are tracked per key.
- **Guards.** Early returns on complete mitigations refine the value after
  them: allowlist membership, `isdigit()`-style checks, a
  `urlparse(u).netloc` allowlist, and a resolved-path containment check.
- **Sources.** Methods that return request data (request wrappers) are sources
  when called on an object built from the request, in the same file or across
  files. `request.path` is not a source in a view whose routes have no
  converters.
- **New Python rules.** Reflected XSS from view return values and `Markup`,
  `|safe` in templates, open redirect, XXE with external entities enabled,
  LDAP and XPath injection, trust boundary (session stores), weak randomness
  for tokens and session values, `hashlib.new("md5")`, pathlib file access,
  `compile()` as a code sink, and `set_cookie()` without `secure=True`
  (CWE-614) or `httponly=True` (CWE-1004).
- **Fewer sink-only findings.** `shell=True`, `os.system` and `pickle.loads`
  whose payload is built only from literals are no longer reported.
  `yaml.load` with an unsafe loader is still reported, graded by taint.
- **Function parameters.** SQL built by formatting a function parameter is
  reported at low confidence. The regex tier used to catch some of these, but
  the engine dropped its CWE-89 findings wherever the taint tier ran.

### What the numbers say

- **On OWASP BenchmarkPython Nephilex now scores +89.4 pooled and +91.3 by
  category average (mapped)**, against +18.6 and +7.5 for Bandit and +14.2 and
  +6.0 for Semgrep. Because the rules were developed with this dataset visible
  and it is generated from a small set of templates, read this as "Nephilex
  handles the idioms in this benchmark", not as a real-world detection rate.
- **The 74 false positives** are 66 cases guarded only by blocklist checks that
  Nephilex deliberately does not trust (see above), 5 `yaml.load(...,
  Loader=yaml.Loader)` calls on a constant document (an unsafe loader is still
  reported, at low severity, because it is wrong code even when today's input
  is constant), and 3 payloads that come from a wrapper method in another file
  returning a constant, which the regex tier, grading one file at a time,
  cannot see.
- **Strict mode** (+70.8) is lower mainly because Nephilex reports MD5/SHA-1 as
  CWE-327 against the benchmark's CWE-328 label (71 cases) and `eval`/`exec`
  as CWE-95 against its parent CWE-94 (20 cases); the other 5 misses are the
  path-traversal cases whose only sink is an existence check.
- **On SecurityEval Nephilex ties Bandit on mapped recall (32 samples each)** but
  trails it on CWE-average recall (18.4% vs 23.3%) and CWE breadth (17 vs 21
  CWEs). Without the detections from rules added after reading SecurityEval,
  Nephilex is at 27 samples. SecurityEval covers many classes Nephilex has no Python
  rule for (hard-coded passwords as CWE-259, log injection, temporary files,
  regex DoS, SSRF), and most samples are helper functions with no web request.

### Limitations

- **Labeled-dataset bias.** OWASP BenchmarkPython is synthetic: every case is
  generated from templates, uses Flask, and contains deliberate traps (dead
  branches, constant conditions, overwritten values) that reward or punish
  specific analysis features. Category sizes are uneven (326 weakrand cases,
  16 sqli cases), which dominates the pooled numbers; the category average is
  published for that reason. Real applications look different.
- **SecurityEval has no negatives,** so it cannot measure false positives at all,
  and most CWEs have one to six samples. Many samples are snippets whose input
  is a function parameter rather than a web request, which penalizes tools that
  require a proven untrusted source (the Nephilex taint tier) relative to tools
  that flag sinks unconditionally (Bandit).
- **CWE mapping caveats.** Tools pick different CWEs for the same issue (MD5 is
  CWE-327 in Bandit, Semgrep and Nephilex, but the benchmark label is CWE-328), so
  `strict` understates every tool and `mapped` depends on the committed groups
  and overrides. Both are published; the mapping tables are embedded in each
  results file.
- **Python only.** These datasets measure the Python SAST and taint tiers. They
  say nothing about Nephilex's JavaScript/TypeScript tiers, secrets, dependency,
  IaC, container or LLM-application scanners.
- **Default configurations only.** Semgrep was run with the `p/python` registry
  ruleset on the Community Edition engine (no cross-file Pro analysis); another
  ruleset (for example `p/default`) or Semgrep Pro would give different numbers.
  Nephilex was run without an AI provider (`--no-ai`), so AI triage is not measured.
  Bandit and Semgrep were not tuned for these datasets. Nephilex's rules were
  revised after studying its OWASP misses, with no case held out (see
  "Methodology checks"); no rule refers to a benchmark file, test id,
  helper or generated name.
- **Single run, single machine.** All three tools are deterministic for a fixed
  input, but the runs were made once, on Windows. Nephilex's default scanner set
  includes a dependency scanner that may query OSV for the dataset's
  `requirements.txt`; those findings fall outside the test cases and do not
  affect the scores.

## Held-out benchmark: real fix commits

The public datasets above have a known weakness: Nephilex's Python rules were
revised with OWASP BenchmarkPython visible. This benchmark answers that with
code nobody tuned anything on: real vulnerabilities from real projects, taken
as before/after pairs from the commits that fixed them. This is the frozen v1
set; a development set and a time-split test set use the same rule (see
"Three benchmark sets" below).

### Selection rule

The rule was written down and committed (in `benchmarks/heldout/selection.py`,
with the resulting manifest) before any tool was run on the selected files.
Git history shows the order. In full:

1. **Source.** GitHub Advisory Database, reviewed advisories only, ecosystems
   `pip` and `npm`, published from 2024-01-01 to 2026-09-30, not withdrawn.
2. **CWE.** The advisory lists at least one CWE that Nephilex's Python or
   JavaScript/TypeScript source-code rules report, or a member of the
   equivalence group that contains one (`benchmarks/public/mapping.py`). The
   claimed CWEs, with the scanner modules that report them, are recorded in the
   manifest: 22, 73, 74, 77, 78, 79, 80, 89, 90, 94, 95, 295, 306, 327, 330, 338,
   347, 352, 489, 501, 502, 598, 601, 611, 614, 639, 643, 918, 1004, 1336. With
   their groups the target set adds 23, 36, 88, 99, 297, 328, 331, 564, 776 and
   916. CWEs reported only by configuration, infrastructure, dependency, CI,
   secret, other-language or LLM-misuse rules (for example 200, 250, 732) are
   not claimed here: those rules detect them only in narrow contexts. A case's
   label is the subset of its advisory's CWEs that is in the target set.
3. **Fix commit.** At least one advisory reference is a GitHub commit URL
   (`/commit/<sha>` or `/pull/<n>/commits/<sha>`). All such commits are used.
4. **Files.** From each fix commit, every modified or renamed `.py`, `.js`,
   `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts` or `.tsx` file, except tests
   (`test`/`tests`/`spec`/`__tests__`/`e2e` directories, `test_*.py`,
   `*_test.py`, `test.py`, `tests.py`, `conftest.py`, `*.test.js`, `*.spec.ts`
   and similar),
   documentation and examples (`doc`, `docs`, `example(s)`, `sample(s)`),
   vendored or build output (`vendor`, `third_party`, `node_modules`, `dist`,
   `build`, `coverage`, ...), minified or generated files (`*.min.js`,
   bundles, `*_pb2.py`) and TypeScript declarations (`*.d.ts`). Files the fix
   added or deleted have no before/after pair and are skipped. Within one
   advisory a path is taken once, from the first commit that touches it; a file
   and commit already used by another advisory is not used twice.
5. **Localized fixes.** An advisory whose fix touches more than 5 eligible
   files is dropped as a refactor: most of its changed lines would not be the
   vulnerable code.
6. **Sampling.** Candidate advisories are ordered by SHA-256 of their GHSA id,
   a fixed order nobody chose, and taken until 120 `pip` and 80 `npm` cases
   are reached. Nothing in the order depends on any tool.

A **case** is one file of one advisory. The vulnerable version is the file at
the fix commit's first parent; the patched version is the file at the fix
commit. The manifest (`benchmarks/heldout/manifest.json`) records for each case
the advisory id, CVE, CWEs, repository, parent and fix SHAs, paths, the changed
line ranges on both sides and the SHA-256 of both versions, so anyone can
re-fetch and verify exactly the same files. It also lists every dropped
advisory and file with its reason.

Changed lines come from the fix commit's unified diff: removed lines on the
vulnerable side and added lines on the patched side. A hunk that only inserts
lines marks the two vulnerable-side lines around the insertion point, and a
hunk that only deletes marks the two patched-side lines around the deletion.

### Selection counts

Snapshot taken on 2026-10-23:

| Step | pip | npm |
| --- | --- | --- |
| Reviewed advisories in the window with a target CWE (API filter) | 1882 | 1874 |
| Withdrawn | 88 | 82 |
| No GitHub fix commit reference | 789 | 737 |
| Candidates | 1005 | 1055 |
| Examined in sample order before the budget was reached | 99 | 51 |
| Dropped: fix touches more than 5 source files | 18 | 7 |
| Dropped: no eligible source file in the fix commits | 5 | 2 |
| Dropped: fix commit not retrievable | 0 | 1 |
| Selected advisories | 76 | 41 |
| Selected cases (files) | 120 | 81 |

The 201 cases (117 advisories) are 118 Python, 48 JavaScript and 35 TypeScript files.

**Amendment, made before any score existed.** The first committed selection
missed test modules named `test.py` or `tests.py` (the Django convention):
three of its 202 cases were such files (Weblate `weblate/api/tests.py`,
xml2rfc `test.py`, Taguette `tests.py`). The scan was stopped while Nephilex was
still on its first cases, its partial output was deleted unread, `tests?.py`
and `tests?.js` were added to the test-file rule, and the selection was re-run
on the cached API responses. The same sampling order then added two files from
the next advisories (wlc `wlc/main.py`, picklescan
`src/picklescan/scanner.py`). Both manifests are in git history.

### Scoring

Fixed with the selection rule, before any tool ran:

- **Window.** A finding belongs to a case when it is in the case's file and its
  line is within 3 lines of a changed line on that side. Windows of 0 and 10
  lines are published as a sensitivity check.
- **CWE match.** `mapped` (primary): the finding's CWEs, plus the documented
  rule overrides, intersect the equivalence group of one of the case's label
  CWEs, exactly as in the public benchmark (`benchmarks/public/mapping.py`,
  unchanged). `strict`: a finding CWE equals a label CWE. `any`: any finding in
  the window, whatever its CWE.
- **Detected.** The vulnerable version has a matching finding in the window
  around its changed lines.
- **Flagged after the fix.** The patched version has a matching finding in the
  window around its changed lines. **Still flagged** counts detected cases
  that are also flagged after the fix.
- **Recall** = detected / cases. **Fix-aware recall** = (detected and not
  flagged after the fix) / cases: the tool told the vulnerable version apart
  from the patched one.
- **Precision proxy** = detected / (detected + flagged after the fix), treating
  every match on fixed code as a false positive. Real advisories have no
  labeled safe code, so this is a proxy, not precision (see Limitations).
- Results are given per case (file) and per advisory (an advisory is detected
  when any of its files is), by CWE, language and ecosystem, with raw counts.
  A case with two label CWEs counts once in each CWE row.

### Reproduce

```bash
pip install -e ".[ast]"
pip install bandit semgrep                  # ideally in a separate virtualenv
python benchmarks/heldout/run.py fetch      # files in the manifest, verified by SHA-256
python benchmarks/heldout/run.py scan --bandit /path/to/bandit --semgrep /path/to/semgrep
python benchmarks/heldout/run.py score      # re-score the committed results, no tools, no network
```

`select` re-applies the rule to the live Advisory Database
(`--api-command` or `GITHUB_TOKEN` for authenticated GETs); because GitHub adds,
edits and withdraws advisories, reproducing the published numbers starts at
`fetch`, from the committed manifest. Downloaded files go to
`benchmarks/.corpora/heldout/` (git-ignored); they are scanned as data and never
imported or run.

Outputs, in `benchmarks/results/heldout/`:

- `heldout.json`: Nephilex source commit, manifest hash, tool versions and
  command lines, Semgrep ruleset digests, the CWE mapping tables, and every
  metric for every tool and mode, with the window sensitivity.
- `cases/<case_id>.json`: one file per case with its manifest entry, every
  finding each tool reported on both versions (line, rule id, CWEs; no source
  code) and each tool's outcome. `score` re-scores from these.
- `runs.json` (run metadata) and `SUMMARY.md` (generated tables, including
  the per-CWE breakdown in `any` mode and per ecosystem).

### Tools and settings

| Tool | Version | Configuration |
| --- | --- | --- |
| Nephilex | 0.10.0, source commit `200a227a5424c1e6394643456a4fd71cc164528f` | `nephilex scan <case>/<version> --no-ai --no-cache -f json`, default scanners, one run per case and version (402 runs); the harness refuses to score if `ast-python` (Python cases) or `ast-js` (JS/TS cases) did not run |
| Bandit | 1.9.4 | `bandit -r <root> -f json`, default plugins, all severities and confidences; Python cases only |
| Semgrep | 1.182.1 (Community Edition) | `semgrep scan --config p/python --config p/javascript --metrics=off --no-git-ignore --json`; `p/python` 151 rules, SHA-256 `de5bc79d074c3b4146338a0bf95830406f169bd91ac590a2f1ef111f162e23f5`; `p/javascript` 74 rules, SHA-256 `1bcb61b57b5c9ee521d5e1db2d80062fe90b64fc788650564dc1f1c5243419c2`; both fetched 2026-10-23 |

The Nephilex commit is this benchmark's harness commit; its `src/nephilex` is
identical to the code it was branched from, and nothing under `src/nephilex`
was changed for or after this benchmark. Each Nephilex run sees one file, so
its cross-file analysis can never join two unrelated projects. Bandit and
Semgrep CE analyze one file at a time, so each ran once over the whole tree and
findings were attributed to cases by path. Every finding at every severity
counts for every tool. Each case's file is stored under its last three path
components; a directory name that one of the tools skips by default (`env`,
`target`, ...) gets a trailing underscore. Runs were made on Windows 11 with
Python 3.11 on 2026-10-23.

All 201 selected cases were fetched, verified and scored; none was excluded
at fetch or scan time. Semgrep reported 36 warnings on 22 of the 402 case
versions: 34 rule timeouts (its default per-rule time limit) and 2 reported as
"Other syntax error". A timeout skips only the rule that timed out on that
file. Bandit reported no parse
errors and no Nephilex scanner failed.

### Results

Mapped CWE match, 3-line window (primary):

| Tool | Cases | Detected | Recall | Flagged after fix | Still flagged | Fix-aware detected | Fix-aware recall | Precision proxy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Nephilex | 201 | 4 | 2.0% | 1 | 1 | 3 | 1.5% | 80.0% |
| Bandit (Python only) | 118 | 12 | 10.2% | 5 | 4 | 8 | 6.8% | 70.6% |
| Semgrep | 201 | 4 | 2.0% | 1 | 1 | 3 | 1.5% | 80.0% |

The same, split by language family:

| Tool | Python (118): detected / flagged after fix / fix-aware | JS/TS (83): detected / flagged after fix / fix-aware |
| --- | --- | --- |
| Nephilex | 2 / 1 / 1 | 2 / 0 / 2 |
| Bandit | 12 / 5 / 8 | not applicable |
| Semgrep | 3 / 1 / 2 | 1 / 0 / 1 |

All three modes (detected / flagged after the fix, out of the tool's cases):

| Tool | Cases | Strict | Mapped | Any finding in the changed lines |
| --- | --- | --- | --- | --- |
| Nephilex | 201 | 2 / 1 | 4 / 1 | 6 / 6 |
| Bandit | 118 | 6 / 5 | 12 / 5 | 20 / 10 |
| Semgrep | 201 | 3 / 1 | 4 / 1 | 5 / 1 |

Per advisory (detected when any of its files is), mapped: Nephilex 3 of 117
(2.6%), Bandit 9 of the 75 advisories with a Python case (12.0%), Semgrep 4 of
117 (3.4%).

By CWE, mapped, detected / cases (CWEs with at least 5 cases; the rest are in
`SUMMARY.md`). Bandit's case count is lower where some cases are JS/TS:

| CWE | Cases | Nephilex | Bandit | Semgrep |
| --- | --- | --- | --- | --- |
| 22 path traversal | 40 | 0/40 | 1/29 | 0/40 |
| 79 XSS | 37 | 0/37 | 0/9 | 1/37 |
| 918 SSRF | 25 | 0/25 | 0/19 | 0/25 |
| 94 code injection | 23 | 0/23 | 5/11 | 0/23 |
| 502 deserialization | 13 | 1/13 | 1/13 | 0/13 |
| 601 open redirect | 11 | 0/11 | 0/7 | 0/11 |
| 78 OS command injection | 10 | 0/10 | 2/7 | 2/10 |
| 89 SQL injection | 8 | 1/8 | 2/5 | 1/8 |
| 95 eval injection | 8 | 0/8 | 6/6 | 0/8 |
| 74 injection | 6 | 0/6 | 0/2 | 0/6 |
| 77 command injection | 5 | 2/5 | 0/1 | 0/5 |
| 88 argument injection | 5 | 0/5 | 0/5 | 0/5 |
| 639 authorization bypass | 5 | 0/5 | 0/3 | 0/5 |

No case in the sample carries CWE-611 (XXE).

Window sensitivity, mapped, detected / flagged after the fix:

| Tool | Window 0 | Window 3 | Window 10 |
| --- | --- | --- | --- |
| Nephilex | 4 / 0 | 4 / 1 | 4 / 2 |
| Bandit | 11 / 3 | 12 / 5 | 12 / 5 |
| Semgrep | 4 / 1 | 4 / 1 | 4 / 1 |

With 4 detections in 201 cases, Nephilex's recall has a 95% Wilson interval of
0.8% to 5.0%; Bandit's 12 in 118 gives 5.9% to 16.9%. Differences between
Nephilex and Semgrep here are well inside the noise.

### What the numbers say

- **On real fix commits, all three tools find very little.** Nephilex detects
  4 of 201 cases (2.0%), the same count as Semgrep; Bandit detects 12 of its
  118 Python cases (10.2%). Against the +89.4 OWASP score above, this is the
  number to quote for code Nephilex was not developed on.
- **Bandit's lead comes from flagging sinks without asking where the data
  came from.** Six of its 12 detections are `eval()` (B307, credited to
  CWE-94/95 by the committed override), two are `shell=True` and two are SQL
  built by string formatting. Real library advisories often have a public
  function parameter as the attacker-controlled input, which a sink-only rule
  catches and a source-to-sink taint rule does not.
- **Where Nephilex detected, three of its four detections came from the regex
  `patterns` tier** (`child_process.exec` in two JavaScript files,
  `pickle.loads` in LangChain's FAISS loader); the fourth is the low-confidence
  AST rule for SQL formatted from a non-constant value with no traced source
  (LlamaIndex DuckDB retriever). None of the four is a traced flow from an
  untrusted source to a sink, the analysis behind the OWASP results.
- **Misses worth reading** include Parsl (`%`-formatted SQL from a Flask route
  parameter passed to `pandas.read_sql_query`) and PaddlePaddle (`shell=True`
  with an f-string of a URL parameter), both found by Bandit and Semgrep.
  They are recorded, not fixed: no Nephilex rule was changed because of this
  benchmark.
- **Flagged after the fix** is rare for every tool in mapped mode. Nephilex's
  one case is the LangChain loader, where the fix kept `pickle.loads` behind an
  opt-in flag, so the finding is arguably still correct. In `any` mode,
  Nephilex matches 6 fixed files: besides that one, cookie-flag, OAuth `state`
  and race-hint findings near the changed lines of open-redirect and XSS fixes
  (they name other weaknesses), and a command-injection finding in the patched
  MLflow file of a code-injection advisory.

### Limitations

- **Single-file view.** Each case is only the changed file, not the
  repository. A flow whose source is in another file (a route handler calling
  a helper) is invisible to every tool. This handicaps taint-based analysis
  (Nephilex, Semgrep's taint rules) more than sink-only rules (Bandit).
- **Changed lines are a proxy for the vulnerable lines.** A fix can add a
  check far from the sink, or touch several files of which one holds the bug.
  The window, the 5-file cap and the per-advisory roll-up limit this, they do
  not remove it.
- **The precision proxy is not precision.** A match on the patched lines may
  still be a real issue (as in the LangChain case), and findings outside the
  changed lines are not counted at all, so a tool that reports a lot elsewhere
  in the file pays nothing. There is no labeled safe code in this benchmark.
- **Advisory CWE labels are noisy.** Authors pick broad (CWE-74) or
  neighbouring CWEs; the `any` mode is published for that reason.
- **Small sample.** 201 cases from 117 advisories, with most CWEs under 15
  cases and none for CWE-611. Per-CWE rows are anecdotes, not rates.
- **Snapshot.** The Advisory Database changes; the manifest freezes the
  2026-10-23 selection. The selection rule was amended once before any score
  existed (see "Amendment" above).
- **Default configurations only,** as in the public benchmark: Semgrep CE
  with two registry rulesets, Bandit defaults, Nephilex without AI triage.
  Semgrep timed out on some rules for 22 large case versions.

## Three benchmark sets

The held-out benchmark above is one of three sets built with the same
selection rule and scored by the same harness (`benchmarks/heldout/`, every
command takes `--set`). They exist so that the number quoted for a release
comes from cases nobody looked at while the rules were being written.

| Set | What it is | Who may look at it | Use |
| --- | --- | --- | --- |
| v1 held-out (`benchmarks/heldout/manifest.json`) | 201 cases from advisories published 2024-01-01 to 2026-09-30, selected and scored on 2026-10-23 | Its results are published above and in `benchmarks/results/heldout/`. Rule work should not use its per-case results | Frozen: its manifest and results are not changed or rescored |
| Development (`benchmarks/heldout/sets/dev/manifest.json`) | The same window and rule, minus every advisory v1 examined, in a different sampling order | Anyone, in full: every miss is meant to be read | Studying misses and testing rule changes. Its numbers are development data, not a claim |
| Time-split test (`benchmarks/heldout/sets/timesplit/`) | Advisories published on or after 2026-10-01, up to a freeze date given when it is selected | Nobody, until the detection rules for the release are frozen | The headline number for a release |

**Rule: the headline accuracy number for a release comes from the time-split
set**, selected after the release's detection rules are frozen and scored once
with exactly those rules. Development-set numbers are never quoted as a
claim, and the v1 number stays the number for the release it was published
with.

### Time-split test set (rule only)

The rule is committed (`timesplit_rule` in `benchmarks/heldout/selection.py`,
the guard in `benchmarks/heldout/cli.py`, the description in
`benchmarks/heldout/sets/timesplit/README.md`) but the set has not been
selected. No advisory published on or after 2026-10-01 has been queried,
counted, fetched or scanned for it; the tests use synthetic advisories only.

- **Window.** Reviewed `pip` and `npm` advisories published from 2026-10-01
  up to and including `--until`, which must be before the day of selection
  (UTC) so the window is closed. The API's date filter is re-checked on each
  advisory's `published_at`.
- **Same rule as v1** for CWEs, fix commits, files and the 5-file cap.
- **Exclusions.** Every advisory the v1 or development selection examined,
  any advisory sharing a CVE id with one of them, and any file and commit that
  is already a v1 or development case.
- **Sampling.** SHA-256 of `"timesplit:"` plus the upper-cased GHSA id, up to
  200 `pip` and 150 `npm` cases.
- **Freeze guard.** `select --set timesplit` refuses to run, before any
  request, without `--rules-frozen-at <full commit sha>`, and unless
  `src/nephilex` in the checkout is identical to that commit. The commit, the
  harness commit and the time are recorded in the manifest's `freeze` entry.
  The set is selected once, and `scan --set timesplit` refuses to run if
  `src/nephilex` no longer matches the frozen commit.

```bash
python benchmarks/heldout/run.py select --set timesplit \
    --until YYYY-MM-DD --rules-frozen-at <full commit sha>
```

### Development set

**These are development data, not a claim.** The set exists to be studied:
the people improving detection read every miss, so after the first rule
change its numbers no longer measure code Nephilex was not developed on. The
numbers below are the starting point, before any rule was changed with this
set visible. `benchmarks/results/dev/` now holds a later run; see "After the
Python detection work" at the end of this section.

**Rule.** The v1 rule unchanged (window 2024-01-01 to 2026-09-30, CWE list,
fix-commit, file and 5-file rules), with three differences, all in
`benchmarks/heldout/selection.py` (`DEV_RULE`, `PriorSets`):

- Every advisory the v1 selection examined is skipped before sampling,
  whether it became a v1 case or was dropped: 149 GHSA ids (150 listings,
  one advisory is in both `pip` and `npm`), listed in the manifest under
  `excluded_prior_sets`. The v1 selection before its amendment examined a
  subset of these. Advisories sharing a CVE id with one of them are skipped
  too (none did), and a file and commit that is already a v1 case is never
  used again (14 files).
- Sampling order: SHA-256 of `"dev:"` plus the upper-cased GHSA id.
- Budget: 200 `pip` and 150 `npm` cases.

The rule and the manifest were committed before any file was fetched, and the
content hashes were committed before any tool ran; git history shows the
order.

Selection counts, snapshot taken on 2026-10-23:

| Step | pip | npm |
| --- | --- | --- |
| Reviewed advisories in the window with a target CWE (API filter) | 1882 | 1874 |
| Skipped: examined by the v1 selection | 99 | 51 |
| Withdrawn | 88 | 82 |
| No GitHub fix commit reference | 789 | 737 |
| Candidates | 906 | 1004 |
| Examined in sample order before the budget was reached | 157 | 101 |
| Dropped: fix touches more than 5 source files | 24 | 19 |
| Dropped: no eligible source file in the fix commits | 13 | 5 |
| Dropped: no fix commit retrievable | 4 | 0 |
| Selected advisories | 116 | 77 |
| Selected cases (files) | 201 | 150 |

The listed, withdrawn and no-fix-commit counts equal v1's, and the candidates
plus the skipped advisories equal v1's candidates (1005 and 1055), so the two
selections saw the same population. No advisory fell outside the window on
the client-side date check. The 351 cases (193 advisories) are 193 Python, 51
JavaScript and 107 TypeScript files. All were fetched, verified and scored;
none was excluded.

**Runs.** Nephilex 0.11.0, harness commit
`008261bcc96357539c3160a382a1634f35f89576`, whose `src/nephilex` is identical
to `main` at `0beceec8aac330648d0e3637a46d51b815201d2d` (702 runs, no scanner
failed). Bandit 1.9.4 (no parse errors). Semgrep 1.182.1 CE with `p/python`
(151 rules) and `p/javascript` (74 rules), the same SHA-256 digests as the v1
run; it reported 59 warnings on 31 of the 702 case versions (56 rule
timeouts, 3 syntax errors). Settings are those of the v1 run (see "Tools and
settings" above). Windows 11, Python 3.11, 2026-10-23.

Mapped CWE match, 3-line window:

| Tool | Cases | Detected | Recall | Flagged after fix | Still flagged | Fix-aware detected | Fix-aware recall | Precision proxy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Nephilex | 351 | 12 | 3.4% | 4 | 4 | 8 | 2.3% | 75.0% |
| Bandit (Python only) | 193 | 23 | 11.9% | 11 | 9 | 14 | 7.2% | 67.7% |
| Semgrep | 351 | 3 | 0.9% | 1 | 0 | 3 | 0.9% | 75.0% |

All three modes (detected / flagged after the fix):

| Tool | Cases | Strict | Mapped | Any finding in the changed lines |
| --- | --- | --- | --- | --- |
| Nephilex | 351 | 10 / 4 | 12 / 4 | 20 / 9 |
| Bandit | 193 | 15 / 11 | 23 / 11 | 34 / 25 |
| Semgrep | 351 | 3 / 1 | 3 / 1 | 8 / 5 |

By language, mapped, detected / cases (flagged after the fix):

| Language | Cases | Nephilex | Bandit | Semgrep |
| --- | --- | --- | --- | --- |
| Python | 193 | 10/193 (4) | 23/193 (11) | 3/193 (0) |
| JavaScript | 51 | 1/51 (0) | not applicable | 0/51 (1) |
| TypeScript | 107 | 1/107 (0) | not applicable | 0/107 (0) |

By CWE, mapped, detected / cases (CWEs with at least 5 cases; the rest are in
`benchmarks/results/dev/SUMMARY.md`). Bandit's count covers the Python cases
only:

| CWE | Cases | Nephilex | Bandit | Semgrep |
| --- | --- | --- | --- | --- |
| 22 path traversal | 40 | 0/40 | 2/23 | 0/40 |
| 73 external control of file name | 5 | 0/5 | 0/2 | 0/5 |
| 74 injection | 10 | 0/10 | 0/5 | 0/10 |
| 77 command injection | 16 | 1/16 | 0/9 | 0/16 |
| 78 OS command injection | 28 | 2/28 | 6/15 | 2/28 |
| 79 XSS | 60 | 0/60 | 2/22 | 0/60 |
| 88 argument injection | 8 | 0/8 | 0/6 | 0/8 |
| 89 SQL injection | 18 | 3/18 | 1/13 | 0/18 |
| 94 code injection | 31 | 1/31 | 7/15 | 0/31 |
| 95 eval injection | 8 | 1/8 | 4/4 | 0/8 |
| 295 certificate validation | 5 | 0/5 | 0/3 | 0/5 |
| 306 missing authentication | 7 | 0/7 | 0/5 | 0/7 |
| 347 signature verification | 15 | 0/15 | 0/9 | 0/15 |
| 352 CSRF | 5 | 0/5 | 0/1 | 0/5 |
| 502 deserialization | 13 | 2/13 | 4/13 | 0/13 |
| 601 open redirect | 12 | 2/12 | 0/5 | 0/12 |
| 639 authorization bypass | 17 | 0/17 | 0/10 | 0/17 |
| 918 SSRF | 64 | 0/64 | 0/35 | 0/64 |
| 1336 template injection | 12 | 0/12 | 1/8 | 0/12 |

Per advisory, mapped: Nephilex 10 of 193 (5.2%), Bandit 20 of the 110
advisories with a Python case (18.2%), Semgrep 3 of 193 (1.6%). Window
sensitivity, mapped, detected / flagged after the fix at windows 0, 3 and 10:
Nephilex 8/1, 12/4, 13/6; Bandit 20/6, 23/11, 29/17; Semgrep 3/1, 3/1, 6/3.
95% Wilson intervals for mapped recall: Nephilex 2.0% to 5.9%, Bandit 8.1% to
17.2%, Semgrep 0.3% to 2.5%.

What the development set shows, for the people working on detection:

- **The largest classes are the emptiest.** CWE-918 (64 cases), CWE-79 (60)
  and CWE-22 (40) together are 164 of 351 cases, and Nephilex detects none of
  them in mapped mode; Bandit and Semgrep detect 4 between them. CWE-94 is 1
  of 31 for Nephilex against 7 of 15 for Bandit: 4 of Bandit's 7 are `eval`
  (B307), 1 is Jinja2 autoescape (B701), and 2 are `subprocess` findings in
  cases that also carry CWE-78.
- **Where Nephilex detected,** 7 of its 12 detections are `ast-python` rules
  (code injection, open redirect, SQL string building), 3 are regex
  `patterns` rules (`shell=True`, `pickle.loads`, `child_process.exec`) and 2
  are `llm` rules (`llm.torch-load-pickle`, `llm.tool-handler-exec` in an
  MCP server). Only 2 of the 12 are JavaScript or TypeScript, from 158 such
  cases.
- **Flagged after the fix:** in Nephilex's 4 cases the same rule still fires
  on the patched lines: SQL string building in two LangGraph SQLite
  checkpoint files, open redirect in a Khoj auth router, and `pickle.loads`
  in the pdfminer CMap loader. Whether each is a false positive needs a
  reading of the fix.
- Per-case outcomes for all three tools are in
  `benchmarks/results/dev/SUMMARY.md` ("Per case"), and every finding on both
  versions is in `benchmarks/results/dev/cases/<case>.json`.

The limitations listed for v1 apply unchanged: single-file view, changed
lines as a proxy for the vulnerable lines, a precision proxy that is not
precision, and noisy advisory CWE labels.

```bash
python benchmarks/heldout/run.py fetch --set dev
python benchmarks/heldout/run.py scan --set dev --bandit /path/to/bandit --semgrep /path/to/semgrep
python benchmarks/heldout/run.py score --set dev     # re-score the committed results
# Nephilex only, keeping the recorded Bandit and Semgrep results; a config variant
python benchmarks/heldout/run.py scan --set dev --only nephilex
python benchmarks/heldout/run.py scan --set dev --only nephilex \
    --nephilex-config library-on.yml --variant library-on
python benchmarks/heldout/run.py score --set dev --variant library-on
```

#### After the Python detection work

**Development data, not a claim**, and no longer unseen: the Python rules
for path traversal, XSS, SSRF and code injection, and library mode (see
[Scanners](scanners.md#library-mode)), were written after reading every
Python miss in this set. Nephilex was re-run on the same 351 cases with
`scan --set dev --only nephilex`, which keeps the committed Bandit and
Semgrep results; the Nephilex source is commit
`26011609fa7e31854e0a55dae887054af3d6137d` (recorded in
`benchmarks/results/dev/SUMMARY.md`, `src/nephilex` unmodified; the
library-mode run records `261c48999c9ca36ee4c6992ddc0d792a816341ac`, a
documentation commit with the same `src/nephilex`). The
library-mode run used `--nephilex-config` with `library_mode: "on"` and
`--variant library-on`; its results are in
`benchmarks/results/dev-library-on/`. In the default configuration library
mode stays off on these cases (`auto` needs a package manifest, and each
case is a single file).

Mapped CWE match, 3-line window, Python cases (193), detected / flagged
after the fix:

| Subset | Cases | 0.11.0 baseline | Default (auto) | Library mode on |
| --- | --- | --- | --- | --- |
| All Python | 193 | 10 / 4 | 12 / 4 | 21 / 4 |
| CWE-22 group (22, 23, 36, 73, 99) | 26 | 0 / 0 | 1 / 0 | 4 / 0 |
| CWE-79 group (79, 80) | 22 | 0 / 0 | 0 / 0 | 1 / 0 |
| CWE-918 | 35 | 0 / 0 | 1 / 0 | 1 / 0 |
| CWE-94 group (94, 95) | 19 | 2 / 0 | 2 / 0 | 7 / 0 |
| CWE-1336 | 8 | 0 / 0 | 0 / 0 | 0 / 0 |
| Other CWEs | 87 | 8 / 4 | 8 / 4 | 8 / 4 |

Any finding in the changed lines (CWE-agnostic), Python: baseline 16 / 8,
default 17 / 8, library mode 27 / 8.

All languages, mapped: Nephilex 14 of 351 (4.0%), flagged after the fix 4,
fix-aware 10, against 12 / 4 / 8 at 0.11.0; JavaScript and TypeScript are
unchanged (2 of 158). By CWE over all languages, detected / cases:
CWE-22 1/40 (was 0/40), CWE-79 0/60 (0/60), CWE-918 1/64 (0/64), CWE-94
1/31 (1/31), CWE-95 1/8 (1/8). With library mode on: 23 of 351 (6.6%),
flagged after the fix 4, fix-aware 19; CWE-22 4/40, CWE-79 1/60, CWE-918
1/64, CWE-94 3/31, CWE-95 4/8.

What changed and why the gain is small:

- **New detections, default mode:** an SSRF through a FastAPI `Query()`
  parameter into `aiohttp.ClientSession().get()` (rembg) and a path traversal
  from a FastAPI `UploadFile.filename` into `open()` (libre-chat). Both fixes
  are recognized (a URL validator that checks `is_private` and friends,
  `werkzeug.utils.safe_join`), so neither is flagged after the fix.
- **Library mode adds nine** vulnerable versions, none flagged after the
  fix: `eval` of text a library builds from its caller's data (Amazon
  Redshift driver vector parsing, OpenStack Vitrage query predicates, two
  Agno files reading a type name from a caller's dict, a llama-index
  streaming generator that evaluates server events), path traversal where a
  library joins a caller's name under its own directory (AGiXT `safe_join`,
  Banks prompt registry), a tar archive extracted without a filter (MONAI),
  and Wagtail's `mark_safe` of an f-string in a template tag. Bandit's
  sink-only `eval` rule finds all five of the code-injection cases, which is
  where much of its lead on this set came from.
- **Most target cases are out of reach of a single-file taint engine.** Of
  the 106 Python cases labelled 22, 79, 918, 94, 95 or 1336, most change a
  file that holds neither the source nor the sink: version bumps, settings,
  a validator in a helper module, allowlist or authorization logic, IP
  canonicalization or DNS-rebinding pinning on an existing check, or HTML
  built from data (a parsed APK manifest, an exception, a traceback) that is
  not modeled as untrusted. Others are logic fixes (Weblate and gradio path
  handling, litellm request field checks) that no source-to-sink rule
  describes. Rules keyed to those projects would not generalize, so none
  were written.
- **Findings outside the changed lines.** In the default run, Python
  findings rose from 473 to 505 over both versions (path traversal 22 to 39
  on vulnerable files, open redirect 13 to 14, one new SSRF; XSS fell from 19 to 15 after route
  returns of `jsonify` and `TemplateResponse` stopped counting as HTML).
  Reading them: a zip-slip extraction in Weblate's backup restore (member
  names checked only with `normpath`) and a reflected XSS in a
  changedetection.io Flask route (the very bug of that advisory, but outside
  its changed lines) are real; a flow through an imported `safe_join_path`
  helper (xiaomusic) is most likely a false positive, because a helper in
  another file is not summarized; gradio's file route has its own allowlist
  logic that is not modeled.
- **Flagged after the fix** stays at the baseline's 4 cases: SQL built with
  an f-string in two LangGraph SQLite checkpoint files, an open redirect in
  a Khoj auth router, and `pickle.loads` in the pdfminer CMap loader. None is
  in the CWE classes this work targeted, and the rules that report them did
  not change. Library mode flags the same four.

**False-positive check** (the projects and scanners of "False positives on
code with no known vulnerabilities" above, findings at severity low or
above, same Flask 3.0.3 sources; click 8.5.0, requests 2.34.2, jinja2 3.1.6,
rich 15.0.0 and typer 0.27.3 installed on 2026-10-23):

| Project | 0.11.0 | Now (auto) | Library mode on |
| --- | --- | --- | --- |
| Flask tutorial app (flaskr) | 0 | 0 | 0 (auto keeps it off: `Flask()` entry point) |
| Flask JavaScript example | 0 | 0 | 0 (auto keeps it off) |
| Flask 3.0.3 | 3 | 2 | 7 |
| Werkzeug 3.0.3 | 7 | 7 | 9 |
| click | 0 | 0 | 0 |
| requests | 0 | 0 | 0 |
| jinja2 | 1 | 1 | 6 |
| rich | 1 | 1 | 1 |
| typer | 0 | 0 | 0 |

The installed packages have no manifest in their directories, so `auto`
leaves library mode off on them; the last column forces it on. Flask loses
`flask shell`'s exec of the `PYTHONSTARTUP` file, whose content was counted
as tainted only because its file name was (`compile()` now takes taint from
its source alone). Werkzeug's reloader and rich's `pty.spawn` demo stay, now
at low confidence as operator input. The weak-hash findings that remain all
sit in security code (session signing, the debugger PIN) and keep their
severity. Library mode adds 12 low-confidence `public-api` findings, none
counted by `--fail-on`: Flask's `open_resource`, `open_instance_resource`,
`Config.from_pyfile` and `Config.from_file`, which join a caller's name
under the app's root by design; two HTML fragments in Werkzeug's debugger
`repr` that embed `repr()` text; and in jinja2 the file-system bytecode
cache (names built from a bucket key), `PackageLoader.get_source` (whose
`split_template_path` check is not modeled) and the traceback rewriter's
`exec` of a code object. Reviewers of a library should expect findings of
this kind.

## Public reference apps (finding inventory)

The larger harness scans real, known-vulnerable applications:

```bash
python benchmarks/run_benchmarks.py            # all available corpora
python benchmarks/run_benchmarks.py juice-shop # just one
```

It publishes a **finding inventory** (counts by scanner and severity, plus scan
time) for OWASP Juice Shop, DVWA, WebGoat, and (with a manual download) NIST
SARD/Juliet. An inventory is not precision/recall, it needs a ground-truth
mapping per corpus, which is tracked as a `ground_truth` hook and where
contributions are welcome, but it shows coverage shape and catches per-release
regressions in what Nephilex finds and how fast.

## Methodology and honesty notes

- Runs are deterministic and offline (`--no-ai`, caching disabled) so numbers are
  comparable across machines.
- Numbers that get worse are published anyway. A benchmark that only ever improves
  is marketing, not measurement.
- The labeled corpus is intentionally small and unambiguous. Growing it (more
  languages, more classes, adversarial safe cases) directly improves the quality
  signal, and pull requests that add labeled cases are among the most valuable
  contributions to the project.
