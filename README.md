<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/nephilex-wordmark-dark.svg">
  <img src="docs/assets/brand/nephilex-wordmark-light.svg" alt="Nephilex" width="560">
</picture>

**Your open-source AI Security Engineer.** Point it at a codebase or a running app.
It maps the system, runs layered security analysis, explains every finding the way
a senior application-security engineer would, and where it can, it writes the fix
and checks that the fix actually works.

[![PyPI version](https://img.shields.io/pypi/v/nephilex?color=8b5cf6&label=pypi)](https://pypi.org/project/nephilex/)
[![Python](https://img.shields.io/pypi/pyversions/nephilex?color=6ea8fe)](https://pypi.org/project/nephilex/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![CI](https://github.com/nephilex/nephilex/actions/workflows/ci.yml/badge.svg)](https://github.com/nephilex/nephilex/actions/workflows/ci.yml)
[![Self-scan](https://github.com/nephilex/nephilex/actions/workflows/nephilex-scan.yml/badge.svg)](https://github.com/nephilex/nephilex/actions/workflows/nephilex-scan.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Nephilex/nephilex/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Nephilex/nephilex)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-111c33)](https://genai.owasp.org/llm-top-10/)

[Install](#install) | [Quick start](#quick-start) | [How it works](#how-it-works) | [Docs](https://nephilex.github.io/nephilex/) | [Roadmap](#roadmap)

</div>

---

Nephilex is not just another scanner that prints a list. For each finding it tells you
*why* it is a vulnerability, *how* an attacker would exploit it, the *business
impact*, the likelihood and severity, the CWE and OWASP mapping, and concrete
remediation. Then it can generate a patch and confirm the patch closes the issue.

> **Status: early alpha.** The architecture and full pipeline are in place: a working
> CLI, built-in scanners (secrets, dependencies, SAST, IaC, CI/CD, containers, cloud,
> supply chain, LLM/agent), a multi-provider AI layer, cross-file taint analysis, and
> nine report formats. See the [roadmap](#roadmap).

## Why Nephilex

- **Project-aware scanning** - Detects languages and frameworks and builds an architecture map (APIs, auth flows, datastores, third-party services, cloud, containers, CI/CD, dependency manifests) before it scans a single line.
- **Layered analysis** - Secrets, dependency CVEs (live [OSV](https://osv.dev) data, transitive packages from lockfiles across PyPI, npm, Go, Rust, Ruby, PHP), SAST, tree-sitter taint analysis, infrastructure-as-code, CI/CD pipeline, container, and cloud configuration checks, all in one pass.
- **Built for AI-era codebases** - A first-class LLM and agent security scanner mapped to the [OWASP Top 10 for LLM Apps](https://genai.owasp.org/llm-top-10/): insecure model-output handling, prompt injection, secrets in prompts, over-privileged agent tools, and unsafe model loading.
- **Low noise on purpose** - Reachability analysis marks a CVE in a package your code never imports as lower priority. Cross-file taint follows untrusted input across function and file boundaries so real bugs surface and false alarms stay quiet.
- **Your code stays yours** - Offline heuristic provider by default (no key, no network). Ollama runs models fully locally. Anthropic and OpenAI are opt-in for teams that want cloud models.
- **It fixes, not just finds** - Deterministic, self-verified fixes go to a fresh branch and open a pull request. An AI-proposed tier drafts riskier fixes, verifies them, and labels them for human review. Nothing risky is ever auto-applied.
- **CI-native** - Deterministic output, SARIF and GitLab reports, and diff-aware scanning so pull requests are gated only on findings they introduce. One-block GitHub Action, pre-commit hooks, and a Docker image.
- **Plugin-based throughout** - Scanners, reporters, and AI providers are plugins. Add a language, a report format, or even a rule in plain YAML without touching the core.

## Install

```bash
# From PyPI
pip install nephilex

# With cloud model support
pip install "nephilex[anthropic,openai]"

# With the AST data-flow tier (deeper Python/JS taint analysis, via tree-sitter)
pip install "nephilex[ast]"

# With the optional web dashboard (scan history and risk trends)
pip install "nephilex[dashboard]"
```

From source, for development:

```bash
git clone https://github.com/nephilex/nephilex
cd nephilex
pip install -e ".[dev]"
```

Requires Python 3.10+. The installed command is `nephilex`.

## Quick start

```bash
# Scan a local project and print a table
nephilex scan ./my-app

# Turn on the flagship features and write an HTML report
nephilex scan ./my-app --attack-sim --patches -f html -o report.html

# Scan a remote repository (shallow-cloned to a temp dir, then cleaned up)
nephilex scan https://github.com/org/repo

# Apply Nephilex's verified fixes to a branch and open a pull request
nephilex fix ./my-app --open-pr

# Use a local model so code stays on your machine
nephilex scan ./my-app --ai-provider ollama --ai-model llama3.1

# Machine-readable output for CI, failing the build on High and above
nephilex scan ./my-app -f sarif -o results.sarif --fail-on high
```

**What does pass/fail mean?** See [Understanding scan results](docs/understanding-results.md)
for risk scores, severities, exit codes, and how to know you are secure enough.

Explore what is available:

```bash
nephilex scanners     # list scanners
nephilex reporters    # list report formats
nephilex providers    # list AI providers and whether each is usable right now
nephilex init         # write a starter .nephilex.yml
nephilex cicd .       # CI/CD pipeline checks only
nephilex container .  # Docker / Compose / K8s manifests
nephilex cloud .      # Terraform / CloudFormation
nephilex infrastructure .  # all infra scanners
nephilex inventory . -o inventory.json  # static asset map
nephilex drift before.json after.json   # posture drift
nephilex watch . --once                 # continuous local monitoring
nephilex agent --init                   # server agent config
```

## CI in one block

The official GitHub Action uploads findings to GitHub Code Scanning and is
diff-aware on pull requests, so merges are gated only on findings a PR
*introduces*, never on pre-existing ones:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
    with: { fetch-depth: 0 }
  - uses: nephilex/nephilex@v0.12.0
    with:
      fail-on: high
```

You also get [pre-commit hooks](docs/ci-cd.md#pre-commit-hook) that block secrets
before they enter git history, an official Docker image (`ghcr.io/nephilex/nephilex`),
and GitLab CI and Bitbucket Pipelines snippets. See [docs/ci-cd.md](docs/ci-cd.md).

## How it works

```
 target  -->  resolve   -->  analyze    -->  scan      -->  enrich     -->  report
             path/git/     languages,     secrets,       reasoning,      json, sarif,
             url           frameworks,    deps, sast,     attack sim,     gitlab, md,
                           architecture   iac, llm        patches         html, csv
```

The engine never modifies the target. It returns a `ScanResult`, and its only write
is to Nephilex's own cache (`--no-cache` disables even that). Scanners run concurrently
and unchanged files reuse cached findings, so warm scans stay fast
([measured numbers](docs/performance.md)) while reports stay deterministic, byte for
byte. Reporting and any pull-request creation are separate, explicit steps. See
[docs/architecture.md](docs/architecture.md).

## Configuration

Drop a `.nephilex.yml` in your project root (generate one with `nephilex init`):

```yaml
min_severity: low
fail_on: high
attack_simulation: true
generate_patches: true
ai:
  provider: ollama      # heuristic | anthropic | openai | ollama
  model: llama3.1
scanner_options:
  secrets:
    entropy_threshold: 4.2
```

Full reference: [docs/configuration.md](docs/configuration.md).

## Extending Nephilex

Everything is a plugin. Here is a whole scanner:

```python
from nephilex.plugin_api import Finding, Location, Scanner, ScannerContext, Severity, scanner


@scanner
class HelloScanner(Scanner):
    name = "hello"
    category = "example"
    description = "Flags TODO comments as a demo."

    def scan(self, ctx: ScannerContext):
        for f in ctx.project.files():
            for i, line in enumerate(f.lines(), 1):
                if "TODO" in line:
                    yield Finding(
                        id=f"hello:todo:{i}",
                        rule_id="hello.todo",
                        scanner=self.name,
                        title="TODO left in code",
                        description="A TODO marker.",
                        location=Location(path=f.rel_path, start_line=i),
                        severity=Severity.INFO,
                    )
```

Register it via the `nephilex.plugins` entry point in your package and Nephilex picks it up
automatically. Prefer regex over code? You can add a rule in plain
[YAML](docs/plugins.md#community-rules-yaml-no-python) instead. Full guide:
[docs/plugins.md](docs/plugins.md).

## AI providers and data handling

| Provider    | Location | Source leaves your machine? | Needs |
|-------------|----------|-----------------------------|-------|
| `heuristic` | local    | no                          | nothing (default) |
| `ollama`    | local    | no                          | a running Ollama server |
| `anthropic` | cloud    | yes                         | `ANTHROPIC_API_KEY` + `[anthropic]` extra |
| `openai`    | cloud    | yes                         | `OPENAI_API_KEY` + `[openai]` extra |

If a requested provider is unavailable, Nephilex warns and falls back to `heuristic` so a
scan always completes.

## Fixing, not just finding

`nephilex fix` closes the loop. It scans a repository, applies the fixes it can verify
locally to a fresh branch, commits them, and with `--open-pr` opens a pull request.

```bash
nephilex fix ./my-app --dry-run      # preview the changes, write nothing
nephilex fix ./my-app                # apply fixes to a branch and commit locally
nephilex fix ./my-app --open-pr      # also push and open a PR (needs GITHUB_TOKEN)
```

Only deterministic, self-verified fixes are applied by default. Examples: unsafe
`yaml.load` becomes `yaml.safe_load`, weak hashes become SHA-256 (except for
passwords, which need a key-derivation function and get guidance instead), `shell=True` is
removed, `debug=True` becomes `debug=False`, and `torch.load` gains
`weights_only=True`. See [docs/fixing.md](docs/fixing.md).

## Accuracy

Nephilex, Bandit and Semgrep are scored by the same code on the same data, and
the raw findings and scoring scripts are in the repository, so anyone can rerun
them. The most independent test comes first.

| Test | Nephilex | Bandit | Semgrep |
| --- | --- | --- | --- |
| **Held-out: real fix commits**, 201 files from 117 GitHub advisories (2024 to 2026), recall | **2.0%** (4) | 10.2% (12 of 118, Python only) | 2.0% (4) |
| SecurityEval, samples detected out of 121 | 32 | 32 | 13 |
| OWASP BenchmarkPython, score (TPR minus FPR) | +89.4 | +18.6 | +14.2 |

How to read this:

- **The held-out test is the one to quote.** Its cases were chosen by a rule
  committed before any tool ran, and no Nephilex rule was changed for them.
  Every tool finds little there, partly because each case is a single file, so
  flows that cross files are invisible.
- **The OWASP score is not an independent test.** The Python rules were
  developed with that dataset visible; the gap between it and the held-out
  result is the size of that effect.
- SecurityEval sits between the two. Without five detections from rules written
  after reading its misses, Nephilex finds 27 of 121, behind Bandit's 32.

The LLM and agent rules are measured separately on a labeled corpus with a
held-out split: 64.3% recall and 69.2% precision on the held-out cases. See
[docs/benchmarks.md](docs/benchmarks.md) and
[docs/llm-security.md](docs/llm-security.md) for methodology, per-class results
and limits.

## Roadmap

**Implemented.** Project analysis; secrets, dependency, SAST, and IaC scanners; a
first-class LLM and agent security scanner (OWASP LLM Top 10); live OSV vulnerability
data; multi-provider AI enrichment; Attack Simulation Mode; deterministic patch
generation with self-verification; automated fix branches and pull requests
(`nephilex fix`); baseline and diff-aware scanning; dependency reachability analysis;
opt-in secret verification; safe runtime posture checks for a live URL; per-file
caching and parallel scanners; and JSON, SARIF, GitLab, Markdown, HTML, and CSV
reporting.

**Deep code analysis.** AST data-flow scanning ships for Python and
JavaScript/TypeScript (`pip install "nephilex[ast]"`), tree-sitter taint analysis
that follows untrusted input through multiple hops into a sink and treats
parameterized queries and sanitized values as safe. For Python it also includes a
cross-file, inter-procedural tier that follows taint one hop across a function and
file boundary. Go ships SAST rules today, with more languages next.

**Author rules in YAML.** Add SAST rules with only regex and a few fields, no Python,
via `.nephilex/rules/*.yml` or `scanner_options.patterns.rules`. See
[docs/plugins.md](docs/plugins.md#community-rules-yaml-no-python).

**Web dashboard.** Scan history and risk trends ship as an optional extra:
`pip install "nephilex[dashboard]"` then `nephilex dashboard`. See
[docs/dashboard.md](docs/dashboard.md).

**Kubernetes.** The `iac` scanner checks Kubernetes manifests statically as part
of a normal scan. Live-cluster assessment is out of scope for the core; add-on
packages can provide it through the `nephilex.commands` plugin entry point.

**Distribution.** An official GitHub Action, pre-commit hooks, and a published Docker
image. See [docs/ci-cd.md](docs/ci-cd.md).

**Monitoring and drift.** Configuration drift via `nephilex drift`, static asset
inventory via `nephilex inventory`, local continuous monitoring via `nephilex watch`, and
a multi-path host agent via `nephilex agent`.

**Pipelines, containers, cloud.** CI/CD pipeline scanner (GitHub Actions, GitLab
CI, Jenkinsfile), container and Compose checks, and cloud configuration patterns
for AWS, Azure, and GCP in Terraform and CloudFormation.

**Planned.** Full dynamic analysis (DAST) building on the posture layer, deeper taint
depth (multi-hop cross-file), more deep-analysis languages, and richer compliance rule packs.

## Known limitations

Nephilex is early-stage and honest about what it does not yet do, because a security
scanner you cannot trust is worse than none:

- **Primarily static analysis.** It reads code rather than running your app. The
  `--live-target` posture layer adds safe, read-only runtime checks (headers,
  cookies, HTTPS redirect, exposed paths), but it is not full DAST. There is no crawling,
  fuzzing, or exploitation.
- **Deepest for Python and JavaScript/TypeScript.** Other languages are detected and
  covered by the secrets, dependency, LLM, and IaC scanners, and Go has SAST rules,
  but code-level coverage for the rest is limited so far.
- **Code scanning has blind spots.** The default regex tier catches common patterns.
  The optional AST tier follows multi-hop and one-hop cross-file data flows and avoids
  common false positives, but deeper multi-hop cross-file flows can still be missed.
  Treat a clean result as "no known issues found," not a proof of safety.
- **Dependency coverage depends on OSV.** Offline, it falls back to a small bundled
  advisory seed (PyPI and npm) and tells you so.

Treat Nephilex as a strong, fast first line of defense, not a replacement for a manual
security review of critical code.

## Contributing

Contributions are welcome from individuals and organizations alike. The flow is
the standard one:

1. **Fork** this repository.
2. Create a branch (see the naming convention in CONTRIBUTING.md) and make your
   change, with tests.
3. Commit with a `Signed-off-by` line (`git commit -s`) to certify the
   [Developer Certificate of Origin](https://developercertificate.org/).
4. Open a **pull request**. The template will guide you, and CI runs tests, lint,
   type checks, and the accuracy benchmark automatically.

Scanners, language support, compliance rules, and report formats are especially
welcome, and the plugin model means most additions never touch the core.

| Document | Purpose |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, standards, branch and commit conventions |
| [GOVERNANCE.md](GOVERNANCE.md) | Roles, decision making, and how to become a maintainer |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability privately; supported versions |
| [SUPPORT.md](SUPPORT.md) | Where to ask questions and get help |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What Nephilex defends against, and what it does not |

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
