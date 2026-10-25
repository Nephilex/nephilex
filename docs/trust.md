# Trust and limits

This is the page to read before you rely on Nephilex. It covers how accuracy
is measured, what Nephilex does on your machine and on the network, what each
scanner covers and how deeply, and where established tools are stronger.

Facts on this page were checked against Nephilex **0.11.0** on **2026-10-23**,
by running the commands shown and reading the code in `src/nephilex/`.

## How accuracy is measured

Nephilex publishes five kinds of measurement, with methodology and caveats,
on [Benchmarks & accuracy](benchmarks.md) and [LLM / AI security](llm-security.md):

1. **A labeled corpus in the repository.** Small single-file cases, each either
   vulnerable (Nephilex must report it) or safe (Nephilex must stay quiet). It
   runs offline with one command and fails CI on any regression. It is a
   regression guard, not a measure of real-world accuracy.
2. **Public labeled datasets.** OWASP Benchmark for Python and SecurityEval,
   scored for Nephilex, Bandit and Semgrep by the same code, with the dataset
   commits, tool versions and every finding recorded so the scoring can be
   re-run.
3. **A held-out benchmark of real fix commits.** 201 files from 117 GitHub
   advisories (pip and npm, 2024 to 2026), each scanned before and after its
   fix. The selection rule was committed before any tool ran, and no rule was
   changed for it. This is the closest to real-world accuracy, and the result
   is low for every tool: Nephilex 2.0% recall (4 of 201), Semgrep 2.0%, and
   Bandit 10.2% on the Python cases. Each case is a single file, so flows that
   cross files are invisible here.
4. **An LLM and agent-security corpus** of 38 vulnerable and safe pairs, with a
   held-out split scored once after the rules were frozen: 64.3% recall and
   69.2% precision on the held-out cases, against 100% on the cases the rules
   were written for.
5. **Finding inventories on reference apps** (OWASP Juice Shop, DVWA, WebGoat):
   counts by scanner and severity per release. These show coverage shape and
   regressions; they are not precision or recall.

The labeled corpus, run for this page:

```bash
python benchmarks/accuracy.py
```

```text
Nephilex, labeled-corpus accuracy
====================================================
NOTE: This is a small in-repo labeled corpus for regression detection only.
      It is NOT a claim of real-world 100% accuracy on production codebases.
domain       recall   precision   vuln   safe-FP
----------------------------------------------------
iac           100%       100%      1         0
llm           100%       100%     17         0
mcp           100%       100%      7         0
sast          100%       100%      6         0
secrets       100%       100%      1         0
taint         100%       100%     11         0
----------------------------------------------------
OVERALL       100%       100%     43         0
```

Read the benchmark page before quoting any number. In short:

- The Python rules were revised with OWASP Benchmark for Python visible, so
  that dataset is not an independent test. SecurityEval is closer to one, and
  the held-out fix commits are closest; Nephilex's results drop sharply on
  both. Quote the held-out number, not the OWASP one.
- The public datasets measure only the Python SAST and taint scanners. Every
  case in the in-repo `sast` and `taint` domains is Python too. Nothing
  published measures the JavaScript/TypeScript taint scanner, and the secrets,
  IaC and agent-config domains have one to seven cases each.
- All runs use `--no-ai`, so AI enrichment is not measured.

## Checking a finding yourself

Each finding carries evidence: a grade (`confirmed`, `likely` or
`possible`), the path from where the data comes from to where it is used when
a taint engine recorded one, and a few steps to confirm or rule it out by
reading the code. A grade describes the kind of proof behind one finding; it
is not an accuracy figure and is not measured by the benchmarks above. See
[Evidence and grades](evidence.md).

## What runs where

| Activity | When | What leaves your machine |
| --- | --- | --- |
| Static analysis of files | Every scan | Nothing. Files are read locally. |
| Dependency advisories ([OSV](https://osv.dev)), EPSS and CISA KEV | When a dependency manifest is found | Package names, versions and CVE ids. Offline, the scan falls back to a small bundled advisory list and prints a warning. |
| `docker inspect` on base images named in Dockerfiles | When Docker is installed | Nothing; reads local image metadata. |
| Live secret verification | Only with `--verify-secrets`, local targets only | The candidate credential, sent to its issuer (GitHub, Stripe, Slack, OpenAI, Google) in a read-only call. |
| Live posture checks | Only with `--live-target <url>` | Ordinary GET requests to that URL (below). |
| AI enrichment | Default provider `heuristic` is offline; `ollama` is local | Code is sent only if you choose `anthropic` or `openai`. `--no-ai` turns enrichment off. |
| Attack simulation (`--attack-sim`) | Opt-in | Nothing. Scenarios are written, never executed. |

### Static analysis

By default Nephilex is a static analyzer. It reads source, manifests, lock
files and configuration, and never runs the code it scans.

### The `--live-target` checks

With `--live-target https://app.example.com` (or the `NEPHILEX_DAST_URL`
environment variable) Nephilex makes a small, fixed set of GET requests to a
URL you are authorized to test, and reports:

- plain HTTP that does not redirect to HTTPS;
- missing security headers (HSTS, CSP, X-Frame-Options or `frame-ancestors`,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy);
- cookies without Secure, HttpOnly or SameSite;
- `Server` or `X-Powered-By` headers that disclose versions;
- eight well-known paths that should not be public, such as `/.env`,
  `/.git/config` and `/actuator/env`;
- `Access-Control-Allow-Origin: *`;
- whether a harmless marker string, placed in up to five of the URL's existing
  query parameters, comes back in the response.

Redirects are followed with SSRF checks, private and internal addresses are
refused, response bodies are capped, and a URL set in the scanned project's own
`.nephilex.yml` is ignored so a pull request cannot aim your CI runner at
internal services. It does not inspect TLS certificates or protocol versions.
This list was read from `src/nephilex/dynamic/posture.py` and
`src/nephilex/scanners/dast.py`; it was not run against a live site for this
page.

### What Nephilex does not do

- No crawling, no fuzzing, no attack payloads, no authenticated testing.
- No exploitation and no execution of generated exploit code.
- No assessment of running infrastructure: IaC and Kubernetes checks read
  files, not a live cluster.
- No proof of correctness for fixes: "verified" means the rule no longer fires
  on the rewritten line and the file still parses (see the
  [example finding](example-finding.md#verification-status)).

## Capability matrix

Built from `nephilex scanners`, `nephilex reporters` and the scanner modules in
`src/nephilex/scanners/`.

**Nephilex 0.11.0. Last verified 2026-10-23.**

Analysis depth:

- **AST taint**: parses the code with tree-sitter and follows untrusted values
  into dangerous calls. Needs the `[ast]` extra.
- **Pattern**: matches source lines against rules.
- **Configuration**: reads structured files (YAML, JSON, HCL, manifests) and
  checks settings.
- **Lookup**: compares what the project declares against advisory or
  known-bad lists.

Status, as assessed for this page:

- **Stable**: runs by default, its behaviour and limits are documented in
  [Scanners & coverage](scanners.md), and its accuracy is measured in the
  labeled corpus or the public datasets, or its result is a deterministic
  lookup.
- **Experimental**: works and has tests, but no published accuracy
  measurement, or the code describes it as a foundation or heuristic.
- **Planned**: listed in the README roadmap as planned; not in 0.11.0.

### Code

| Scanner | Languages and files | Depth | Status | Accuracy evidence |
| --- | --- | --- | --- | --- |
| `ast-python` | Python | AST taint, flow-sensitive within a function | Stable | Corpus (11 taint cases), public Python datasets |
| `ast-python-xfile` | Python | AST taint, one call hop across functions and files | Stable | Public Python datasets (default scanner set) |
| `ast-js` | JavaScript, TypeScript, TSX | AST taint | Experimental | None published |
| `patterns` | Mostly Python; also JavaScript/TypeScript, Go, HTML templates, and a few checks for any language | Pattern; some Python rules graded by AST data flow when `[ast]` is installed | Stable | Corpus (6 SAST cases), public Python datasets |
| `lang-sast` | Java, PHP, Ruby, Rust, C, C++, Go, C#, Kotlin, Swift, shell, PowerShell | Pattern, one or two rules per file type (22 in total) | Experimental | None published |
| `llm` | Python and JavaScript/TypeScript files that use an LLM or agent library | AST taint (with `[ast]`) and pattern | Stable | Corpus (17 LLM cases) |
| `malware` | Python, JavaScript/TypeScript, PHP, PowerShell, package scripts, any text | Pattern | Experimental | None published |
| `authz` | Python and JavaScript/TypeScript routes, JWT use, cookies | Pattern heuristics ("foundation" in the code) | Experimental | None published |
| `business-logic` | Python, JavaScript, TypeScript, Java, PHP, Ruby | Pattern heuristics | Experimental | None published |
| `secrets` | Any text file | Pattern: 10 token signatures plus entropy; optional live verification and git-history scan | Stable | Corpus (1 case) |

### Dependencies and supply chain

| Scanner | Ecosystems and files | Depth | Status | Accuracy evidence |
| --- | --- | --- | --- | --- |
| `dependencies` | PyPI (`requirements.txt` pins, `poetry.lock`, `Pipfile.lock`), npm (`package.json`, `package-lock.json`, `yarn.lock`), Go (`go.mod`), crates.io (`Cargo.lock`), RubyGems (`Gemfile.lock`), Packagist (`composer.lock`) | Lookup against OSV, plus EPSS and KEV | Stable | Deterministic lookup; bounded by OSV |
| Import-level reachability (`--reachability`) | Python, npm | Heuristic: is the package imported | Experimental (off by default; labeled experimental in the CLI) | None published |
| `supply-chain` | The same manifests | Lookup (bundled known-malicious list) and heuristics (typosquats, npm install scripts) | Experimental | None published |
| `dependency-diff` | Manifests changed in a `--diff` range | Diff of versions | Experimental | None published |
| `provenance` | SLSA / in-toto provenance files | Configuration | Experimental | None published |

### Infrastructure, pipelines and agents

| Scanner | Files | Depth | Status | Accuracy evidence |
| --- | --- | --- | --- | --- |
| `iac` | Dockerfile, Kubernetes manifests, Terraform | Configuration, line rules (10 in total) | Stable | Corpus (1 case) |
| `container` | Docker Compose, Kubernetes manifests, Helm values, Dockerfile | Configuration | Experimental | None published |
| `container-image` | Local images named in `FROM` lines (runs `docker inspect`) | Configuration of image metadata: root user, privileged mode, exposed ports | Experimental | None published |
| `cloud` | Terraform and CloudFormation for AWS, Azure, GCP | Configuration, pattern | Experimental | None published |
| `cicd` | GitHub Actions, GitLab CI, Jenkinsfile, Bitbucket Pipelines, Azure Pipelines, CircleCI | Configuration, pattern | Experimental | None published |
| `api` | OpenAPI / Swagger specs | Configuration | Experimental | None published |
| `agent-config` | MCP and coding-agent config (`.mcp.json`, `.claude/settings.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, and others) | Configuration | Stable | Corpus (7 MCP cases) |
| `git-security` | The scanned folder's git history (only when the scan root holds `.git`) | Git history | Experimental | None published |
| `dast` | A URL you pass with `--live-target` | Live, read-only GET requests | Experimental | None published |

Findings with the rule prefix `chains.` (for example
`chains.secret-plus-injection`) are not a separate scanner: the engine adds
them when findings from different scanners combine into a worse outcome.

### Planned (not in 0.11.0)

From the [README roadmap](https://github.com/nephilex/nephilex#roadmap):

| Capability | Status |
| --- | --- |
| Full dynamic analysis (DAST) beyond the posture checks | Planned |
| Multi-hop cross-file taint | Planned |
| AST analysis for more languages | Planned |
| Richer compliance rule packs | Planned |

### Report formats

`nephilex reporters` in 0.11.0:

| Format | Extension | Description |
| --- | --- | --- |
| `badge` | json | shields.io endpoint JSON for a README security badge. |
| `csv` | csv | Flat one-row-per-finding export for spreadsheets. |
| `gitlab` | json | GitLab SAST report (schema 15.x) for GitLab CI security widgets. |
| `html` | html | Self-contained styled HTML report. |
| `json` | json | Full machine-readable scan result. |
| `junit` | xml | JUnit XML format for CI test result integration. |
| `markdown` | md | Human-readable Markdown report for PRs and issues. |
| `sarif` | sarif | SARIF 2.1.0 for GitHub Code Scanning and enterprise platforms. |
| `vex` | json | OpenVEX document: exploitability status of vulnerable dependencies. |

## Install details that change coverage

- **The `[ast]` extra.** Without it, `ast-python`, `ast-python-xfile` and
  `ast-js` are skipped (the progress line says "not applicable"), the `llm`
  scanner loses its data-flow rules, and pattern findings are not graded by
  data flow. On the demo app that is 19 findings instead of 20; see
  [Common problems](quickstart.md#common-problems).
- **The official GitHub Action** installs `nephilex[ast]` (see `action.yml`),
  so the taint scanners run in CI as they do locally. Releases up to 0.10.0
  installed it without the extra, so pin a later version to get them.

## Security of Nephilex itself

A scanner reads hostile input by design. How Nephilex defends itself (remote
clones, symlinks, parser limits, untrusted repository config, secret
redaction, report escaping) and the residual risks are documented in:

- [Security & threat model](security.md) and the full
  [THREAT_MODEL.md](https://github.com/nephilex/nephilex/blob/main/THREAT_MODEL.md)
- [SECURITY.md](https://github.com/nephilex/nephilex/blob/main/SECURITY.md): how to
  report a vulnerability privately, and which versions get fixes (0.10.x only)

## Where Nephilex is weaker than established tools

Nephilex is early alpha. If one of these is your main need, use a specialist
alongside it or instead of it (see also [How Nephilex compares](comparison.md)):

- **SAST rule breadth.** Outside Python, coverage is thin: `lang-sast` has one
  or two regex rules per file type, and the pattern rules are mostly for
  Python. Semgrep and CodeQL ship larger rule sets per language. In the
  SecurityEval run published on 2026-10-22, Nephilex detected fewer CWE
  classes than Bandit (see [Benchmarks](benchmarks.md)).
- **Data-flow depth.** Taint analysis covers Python and JavaScript/TypeScript
  only, cross-file tracking is Python only and one call hop deep, and the
  JavaScript/TypeScript tier has no published accuracy figures.
- **Secrets.** Ten built-in token signatures plus entropy, and live
  verification for five issuers. Dedicated secret scanners such as
  GitGuardian and TruffleHog cover many more credential types.
- **Dependencies.** Advisory coverage is whatever OSV has. There is no curated
  vulnerability database, and reachability is an opt-in import check, not a
  call graph.
- **Containers and IaC.** No scanning of image layers or OS packages, and a
  small IaC rule set. Trivy, Grype and dedicated IaC policy tools cover these
  areas in more depth.
- **Dynamic testing.** Only the read-only posture checks above. Use a DAST tool
  such as OWASP ZAP for crawling and active testing.
- **Explanations without a model.** With the offline provider, explanations
  come from templates per rule or CWE. For dependency findings that text is
  generic ("An attacker can use the public advisory/exploit for this known
  vulnerability directly against the running application.").
- **Maturity.** Version 0.x, one listed maintainer
  ([MAINTAINERS.md](https://github.com/nephilex/nephilex/blob/main/MAINTAINERS.md)),
  and no enterprise features such as SSO or ticketing.
